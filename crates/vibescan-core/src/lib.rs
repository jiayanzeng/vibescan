//! Offline scan orchestration and correlation.
//!
//! This crate wires the LocalStatic phases together. It owns configuration,
//! baseline application, generic candidate resolution, correlation,
//! deduplication, statistics, and severity gate policy.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Instant;

use jiff::Timestamp;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use vibescan_git::{WalkOptions, collect_repository};
use vibescan_report::{ReportFormat, TtyStyle, render, render_tty};
use vibescan_secrets::Detector;
use vibescan_supabase::SupabaseClassifier;
use vibescan_types::{
    Category, Confidence, CorrelationRuleId, Evidence, Finding, FindingId, HistoryScope, Location,
    NetworkScope, Provenance, ScanResult, ScanScope, ScanStats, ScopeWarning, SecretCandidate,
    SecretFingerprint, Severity, SupabaseKeyClass,
};

/// Current crate version used in scan results.
pub const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Runtime scan configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScanConfig {
    pub include_working_tree: bool,
    pub include_history: bool,
    pub max_commits: Option<usize>,
    pub max_bytes: usize,
    pub severity_gate: Severity,
    pub path_allowlists: Vec<String>,
    pub baseline_path: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputFormat {
    Json,
    Sarif,
    Tty,
    Html,
}

impl From<OutputFormat> for ReportFormat {
    fn from(value: OutputFormat) -> Self {
        match value {
            OutputFormat::Json => Self::Json,
            OutputFormat::Sarif => Self::Sarif,
            OutputFormat::Tty => Self::Tty,
            OutputFormat::Html => Self::Html,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputStyle {
    Plain,
    Color,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            include_working_tree: true,
            include_history: true,
            max_commits: Some(2_000),
            max_bytes: vibescan_git::DEFAULT_MAX_BYTES,
            severity_gate: Severity::High,
            path_allowlists: Vec::new(),
            baseline_path: None,
        }
    }
}

impl ScanConfig {
    /// Load `vibescan.toml` from `target` if present.
    pub fn load(target: impl AsRef<Path>) -> Result<Self, CoreError> {
        let target = target.as_ref();
        let mut config = Self::default();
        let config_path = target.join("vibescan.toml");

        if config_path.exists() {
            let parsed: FileConfig =
                toml::from_str(&fs::read_to_string(&config_path).map_err(CoreError::Io)?)
                    .map_err(CoreError::Toml)?;
            config.apply_file_config(parsed);
        }

        Ok(config)
    }

    fn apply_file_config(&mut self, parsed: FileConfig) {
        if let Some(scan) = parsed.scan {
            if let Some(value) = scan.working_tree {
                self.include_working_tree = value;
            }
            if let Some(value) = scan.history {
                self.include_history = value;
            }
            if let Some(value) = scan.max_commits {
                self.max_commits = value;
            }
            if let Some(value) = scan.max_bytes {
                self.max_bytes = value;
            }
            if let Some(value) = scan.severity_gate.and_then(parse_severity) {
                self.severity_gate = value;
            }
        }

        if let Some(ignore) = parsed.ignore {
            self.path_allowlists.extend(ignore.paths);
        }

        if let Some(baseline) = parsed.baseline {
            self.baseline_path = baseline.path.map(PathBuf::from);
        }
    }
}

#[derive(Debug, Deserialize)]
struct FileConfig {
    scan: Option<ScanSection>,
    ignore: Option<IgnoreSection>,
    baseline: Option<BaselineSection>,
}

#[derive(Debug, Deserialize)]
struct ScanSection {
    working_tree: Option<bool>,
    history: Option<bool>,
    max_commits: Option<Option<usize>>,
    max_bytes: Option<usize>,
    severity_gate: Option<String>,
}

#[derive(Debug, Deserialize)]
struct IgnoreSection {
    #[serde(default)]
    paths: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct BaselineSection {
    path: Option<String>,
}

/// Run the offline scan pipeline.
pub fn scan(target: impl AsRef<Path>, config: ScanConfig) -> Result<ScanResult, CoreError> {
    let started = Instant::now();
    let started_at = Timestamp::now().to_string();
    let target_path = target.as_ref();
    let baseline = Baseline::load(config.baseline_path.as_ref())?;

    let walk = collect_repository(
        target_path,
        WalkOptions {
            include_working_tree: config.include_working_tree,
            include_history: config.include_history,
            max_commits: config.max_commits,
            max_bytes: config.max_bytes,
            path_allowlists: config.path_allowlists.clone(),
        },
    )
    .map_err(CoreError::Git)?;

    let mut warnings = walk.warnings;
    let units = walk.units;
    let detector = Detector::default_rules().map_err(CoreError::Detector)?;
    let candidates = detector.detect_units(&units);

    let classifier = SupabaseClassifier::new();
    let unit_content = units
        .iter()
        .map(|unit| (unit.path.0.as_str(), unit.content.as_slice()))
        .collect::<BTreeMap<_, _>>();
    let mut findings = candidates
        .iter()
        .filter_map(|candidate| {
            classifier.classify_candidate_with_unit_content(
                candidate,
                unit_content
                    .get(candidate.unit_ref.path.0.as_str())
                    .copied(),
            )
        })
        .collect::<Vec<_>>();
    findings.extend(resolve_generic_candidates(&candidates));
    findings.extend(scan_dependency_integrity(target_path)?);
    findings.extend(correlate_findings(&findings));

    let mut findings = dedup_findings(findings);
    findings.retain(|finding| !baseline.contains(&finding.id));
    sort_findings(&mut findings);

    let stats = compute_stats(&findings, &warnings);
    if !config.include_history {
        warnings.push(ScopeWarning::Other {
            message: "history scanning disabled".to_owned(),
        });
    }

    Ok(ScanResult {
        findings,
        scope: ScanScope {
            target: target_path.display().to_string(),
            working_tree: config.include_working_tree,
            history: history_scope(config.include_history, config.max_commits, &walk.history),
            network: NetworkScope {
                enabled: false,
                tier0_read_probe: false,
                tier1_introspection: false,
            },
            warnings,
        },
        tool_version: TOOL_VERSION.to_owned(),
        started_at,
        duration_ms: started.elapsed().as_millis() as u64,
        stats,
    })
}

pub fn scan_and_render(
    target: impl AsRef<Path>,
    config: ScanConfig,
    format: OutputFormat,
    style: OutputStyle,
) -> Result<(String, i32), CoreError> {
    let result = scan(target, config.clone())?;
    let output = if format == OutputFormat::Tty {
        render_tty(
            &result,
            match style {
                OutputStyle::Plain => TtyStyle::Plain,
                OutputStyle::Color => TtyStyle::Color,
            },
        )
    } else {
        render(&result, format.into()).map_err(CoreError::Json)?
    };
    let code = exit_code(&result, config.severity_gate);
    Ok((output, code))
}

/// Compute whether a result meets the configured severity gate.
pub fn exit_code(result: &ScanResult, gate: Severity) -> i32 {
    result
        .findings
        .iter()
        .any(|finding| finding.severity >= gate)
        .then_some(1)
        .unwrap_or(0)
}

/// Apply the two v1 correlation rules.
pub fn correlate_findings(findings: &[Finding]) -> Vec<Finding> {
    let mut correlations = Vec::new();
    correlations.extend(correlate_exposed_public_key(findings));
    correlations.extend(correlate_elevated_key_moots_rls(findings));
    correlations
}

fn correlate_exposed_public_key(findings: &[Finding]) -> Vec<Finding> {
    let public_keys = findings.iter().filter(|finding| {
        matches!(
            finding.evidence,
            Evidence::SupabaseKey {
                class: SupabaseKeyClass::PublishableNew | SupabaseKeyClass::AnonLegacy,
                ..
            }
        ) && finding.locations.iter().any(|location| {
            location.location_class == vibescan_types::LocationClass::ClientReachable
                || matches!(location.provenance, Provenance::Commit { .. })
        })
    });

    public_keys
        .flat_map(|key_finding| {
            findings.iter().filter_map(move |rls_finding| {
                let same_project =
                    project_url_from_key(key_finding).zip(project_url_from_rls(rls_finding));
                if !matches!(same_project, Some((a, b)) if a == b) {
                    return None;
                }
                let Evidence::RlsProbe {
                    table,
                    endpoint,
                    observed_row_count,
                    ..
                } = &rls_finding.evidence
                else {
                    return None;
                };

                let rule_id = CorrelationRuleId("exposed-public-key-chain".to_owned());
                let id = correlation_id(&rule_id, &[&key_finding.id, &rls_finding.id]);
                Some(Finding {
                    id,
                    category: Category::Correlation,
                    severity: Severity::Critical,
                    title: format!("Public Supabase key can read unprotected table {table}"),
                    detail: "A browser-reachable Supabase public key is present and an API-exposed table on the same project is readable without additional authorization.".to_owned(),
                    locations: key_finding
                        .locations
                        .iter()
                        .cloned()
                        .chain(rls_finding.locations.iter().cloned())
                        .collect(),
                    evidence: Evidence::Correlation {
                        rule_id,
                        reproduction: Some(format!(
                            "{endpoint} returned {observed_row_count} row(s) to the public key"
                        )),
                    },
                    remediation: "Fix RLS policies for the exposed table, then rotate affected keys if exposure is confirmed.".to_owned(),
                    related: vec![key_finding.id.clone(), rls_finding.id.clone()],
                    confidence: Confidence::Confirmed,
                })
            })
        })
        .collect()
}

fn correlate_elevated_key_moots_rls(findings: &[Finding]) -> Vec<Finding> {
    findings
        .iter()
        .filter(|finding| {
            matches!(
                finding.evidence,
                Evidence::SupabaseKey {
                    class: SupabaseKeyClass::SecretNew | SupabaseKeyClass::ServiceRoleLegacy,
                    ..
                }
            ) && finding
                .locations
                .iter()
                .any(|location| matches!(location.provenance, Provenance::Commit { .. }))
        })
        .filter_map(|key_finding| {
            let key_project = project_url_from_key(key_finding)?;
            let related_rls = findings
                .iter()
                .filter(|finding| {
                    project_url_from_rls(finding).is_some_and(|project| project == key_project)
                })
                .map(|finding| finding.id.clone())
                .collect::<Vec<_>>();

            if related_rls.is_empty() {
                return None;
            }

            let mut related = vec![key_finding.id.clone()];
            related.extend(related_rls);
            let rule_id = CorrelationRuleId("elevated-key-in-tree".to_owned());
            let related_refs = related.iter().collect::<Vec<_>>();
            Some(Finding {
                id: correlation_id(&rule_id, &related_refs),
                category: Category::Correlation,
                severity: Severity::Critical,
                title: "Exposed elevated Supabase key bypasses RLS".to_owned(),
                detail: "An elevated Supabase key is committed for this project. RLS findings on the same project are moot until this key is rotated because elevated keys bypass RLS entirely.".to_owned(),
                locations: key_finding.locations.clone(),
                evidence: Evidence::Correlation {
                    rule_id,
                    reproduction: None,
                },
                remediation: "Rotate and remove the elevated key first, then reassess remaining RLS findings.".to_owned(),
                related,
                confidence: Confidence::Likely,
            })
        })
        .collect()
}

fn resolve_generic_candidates(candidates: &[SecretCandidate]) -> Vec<Finding> {
    candidates
        .iter()
        .filter(|candidate| candidate.kind != vibescan_types::CandidateKind::PossibleSupabaseKey)
        .map(generic_candidate_finding)
        .collect()
}

fn generic_candidate_finding(candidate: &SecretCandidate) -> Finding {
    let raw = String::from_utf8_lossy(&candidate.raw_match);
    let fingerprint = fingerprint(&raw);
    let (severity, confidence) = generic_candidate_severity(candidate);
    let location = Location {
        path: candidate.unit_ref.path.clone(),
        span: Some(candidate.span),
        provenance: candidate.unit_ref.provenance.clone(),
        additional_provenance: candidate.unit_ref.additional_provenance.clone(),
        location_class: candidate.unit_ref.location_class,
    };
    let mut hasher = Sha256::new();
    hasher.update(candidate.rule_id.0.as_bytes());
    hasher.update(b"\0");
    hasher.update(fingerprint.0.as_bytes());
    hasher.update(b"\0");
    hasher.update(location.path.0.as_bytes());

    Finding {
        id: FindingId(format!("secret-{}", hex::encode(&hasher.finalize()[..12]))),
        category: Category::SecretExposure,
        severity,
        title: format!("Secret candidate matched {}", candidate.rule_id.0),
        detail: "The generic detector found a credential-shaped value. Review and rotate the value if it is real.".to_owned(),
        locations: vec![location],
        evidence: Evidence::Secret {
            redacted: redact_secret(&raw),
            fingerprint,
        },
        remediation: "Remove the secret from source, rotate it with the provider, and purge committed history if necessary.".to_owned(),
        related: Vec::new(),
        confidence,
    }
}

fn generic_candidate_severity(candidate: &SecretCandidate) -> (Severity, Confidence) {
    match candidate.kind {
        vibescan_types::CandidateKind::ProviderSecret
        | vibescan_types::CandidateKind::PrivateKey => (Severity::High, Confidence::Likely),
        vibescan_types::CandidateKind::GenericHighEntropy => (Severity::Medium, Confidence::Review),
        vibescan_types::CandidateKind::PossibleSupabaseKey => (Severity::Low, Confidence::Review),
        vibescan_types::CandidateKind::Other(_) => (Severity::Medium, Confidence::Review),
    }
}

fn scan_dependency_integrity(target: &Path) -> Result<Vec<Finding>, CoreError> {
    let package_json = target.join("package.json");
    if !package_json.exists() {
        return Ok(Vec::new());
    }

    let content = fs::read_to_string(&package_json).map_err(CoreError::Io)?;
    let value = serde_json::from_str::<serde_json::Value>(&content).map_err(CoreError::Json)?;
    let mut findings = Vec::new();
    for section in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        if let Some(deps) = value.get(section).and_then(serde_json::Value::as_object) {
            for (name, version) in deps {
                if !valid_npm_name(name) {
                    findings.push(dependency_finding(
                        target,
                        name,
                        &format!("invalid npm package name in {section}"),
                        vibescan_types::DependencyIntegrityReason::InvalidPackageName,
                    ));
                }
                if version.as_str().is_some_and(|spec| spec.trim().is_empty()) {
                    findings.push(dependency_finding(
                        target,
                        name,
                        &format!("empty version specifier in {section}"),
                        vibescan_types::DependencyIntegrityReason::EmptyVersionSpecifier,
                    ));
                }
            }
        }
    }
    Ok(findings)
}

fn valid_npm_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 214 || name.starts_with('.') || name.starts_with('_') {
        return false;
    }
    let valid_part = |part: &str| {
        !part.is_empty()
            && part.chars().all(|ch| {
                ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '-' | '_' | '.')
            })
    };
    if let Some(rest) = name.strip_prefix('@') {
        let Some((scope, package)) = rest.split_once('/') else {
            return false;
        };
        valid_part(scope) && valid_part(package)
    } else {
        valid_part(name)
    }
}

fn dependency_finding(
    target: &Path,
    package: &str,
    detail: &str,
    reason: vibescan_types::DependencyIntegrityReason,
) -> Finding {
    let mut hasher = Sha256::new();
    hasher.update(package.as_bytes());
    hasher.update(detail.as_bytes());
    Finding {
        id: FindingId(format!(
            "dependency-{}",
            hex::encode(&hasher.finalize()[..12])
        )),
        category: Category::DependencyIntegrity,
        severity: Severity::High,
        title: format!("Dependency requires review: {package}"),
        detail: detail.to_owned(),
        locations: vec![Location {
            path: vibescan_types::RepoPath(
                target
                    .join("package.json")
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned(),
            ),
            span: None,
            provenance: Provenance::WorkingTree,
            additional_provenance: Vec::new(),
            location_class: vibescan_types::LocationClass::ServerOnly,
        }],
        evidence: Evidence::Dependency {
            package: package.to_owned(),
            manifest_path: vibescan_types::RepoPath("package.json".to_owned()),
            reason,
        },
        remediation: "Correct or remove the dependency before install or deployment.".to_owned(),
        related: Vec::new(),
        confidence: Confidence::Review,
    }
}

fn project_url_from_key(finding: &Finding) -> Option<&str> {
    match &finding.evidence {
        Evidence::SupabaseKey {
            project: Some(project),
            ..
        } => Some(project.url.as_str()),
        _ => None,
    }
}

fn project_url_from_rls(finding: &Finding) -> Option<&str> {
    match &finding.evidence {
        Evidence::RlsProbe { project, .. } => Some(project.url.as_str()),
        _ => None,
    }
}

fn correlation_id(rule_id: &CorrelationRuleId, related: &[&FindingId]) -> FindingId {
    let mut ids = related.iter().map(|id| id.0.as_str()).collect::<Vec<_>>();
    ids.sort_unstable();
    let mut hasher = Sha256::new();
    hasher.update(rule_id.0.as_bytes());
    for id in ids {
        hasher.update(b"\0");
        hasher.update(id.as_bytes());
    }
    FindingId(format!(
        "correlation-{}",
        hex::encode(&hasher.finalize()[..12])
    ))
}

fn dedup_findings(findings: Vec<Finding>) -> Vec<Finding> {
    let mut by_id = BTreeMap::new();
    for finding in findings {
        by_id.entry(finding.id.clone()).or_insert(finding);
    }
    by_id.into_values().collect()
}

fn sort_findings(findings: &mut [Finding]) {
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.category.cmp(&b.category))
            .then_with(|| a.id.cmp(&b.id))
    });
}

fn compute_stats(findings: &[Finding], warnings: &[ScopeWarning]) -> ScanStats {
    let mut stats = ScanStats::default();
    for finding in findings {
        *stats.by_severity.entry(finding.severity).or_default() += 1;
        *stats.by_category.entry(finding.category).or_default() += 1;
    }
    for warning in warnings {
        match warning {
            ScopeWarning::LargeFileSkipped { .. } => stats.skipped_large_files += 1,
            ScopeWarning::BinaryFileSkipped { .. } => stats.skipped_binary_files += 1,
            ScopeWarning::HistoryBudgetHit { .. } => stats.scan_budget_hit = true,
            _ => {}
        }
    }
    stats
}

fn history_scope(
    include_history: bool,
    max_commits: Option<usize>,
    stats: &vibescan_git::HistoryWalkStats,
) -> HistoryScope {
    if !include_history {
        return HistoryScope::Disabled;
    }

    match max_commits {
        Some(max_commits) => HistoryScope::Budgeted {
            max_commits: max_commits as u64,
            scanned_commits: stats.scanned_commits as u64,
            truncated: stats.truncated,
        },
        None => HistoryScope::Exhaustive {
            scanned_commits: stats.scanned_commits as u64,
        },
    }
}

fn parse_severity(value: String) -> Option<Severity> {
    match value.to_ascii_lowercase().as_str() {
        "critical" => Some(Severity::Critical),
        "high" => Some(Severity::High),
        "medium" => Some(Severity::Medium),
        "low" => Some(Severity::Low),
        "info" => Some(Severity::Info),
        _ => None,
    }
}

fn fingerprint(raw: &str) -> SecretFingerprint {
    let mut hasher = Sha256::new();
    hasher.update(raw.as_bytes());
    SecretFingerprint(hex::encode(&hasher.finalize()[..16]))
}

fn redact_secret(raw: &str) -> String {
    let chars = raw.chars().collect::<Vec<_>>();
    if chars.len() <= 12 {
        return "***".to_owned();
    }
    let prefix = chars.iter().take(6).collect::<String>();
    let suffix = chars
        .iter()
        .rev()
        .take(4)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<String>();
    format!("{prefix}...{suffix}")
}

#[derive(Debug, Default)]
struct Baseline {
    ids: BTreeSet<FindingId>,
}

impl Baseline {
    fn load(path: Option<&PathBuf>) -> Result<Self, CoreError> {
        let Some(path) = path else {
            return Ok(Self::default());
        };
        if !path.exists() {
            return Ok(Self::default());
        }

        let content = fs::read_to_string(path).map_err(CoreError::Io)?;
        if let Ok(scan_result) = serde_json::from_str::<ScanResult>(&content) {
            return Ok(Self {
                ids: scan_result
                    .findings
                    .into_iter()
                    .map(|finding| finding.id)
                    .collect(),
            });
        }

        let ids = serde_json::from_str::<Vec<String>>(&content)
            .map_err(CoreError::Json)?
            .into_iter()
            .map(FindingId)
            .collect();
        Ok(Self { ids })
    }

    fn contains(&self, id: &FindingId) -> bool {
        self.ids.contains(id)
    }
}

/// Core pipeline error.
#[derive(Debug)]
pub enum CoreError {
    Detector(vibescan_secrets::DetectorError),
    Git(vibescan_git::GitWalkError),
    Io(io::Error),
    Json(serde_json::Error),
    Toml(toml::de::Error),
}

impl fmt::Display for CoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Detector(source) => write!(formatter, "detector setup failed: {source}"),
            Self::Git(source) => write!(formatter, "git collection failed: {source}"),
            Self::Io(source) => write!(formatter, "filesystem operation failed: {source}"),
            Self::Json(source) => write!(formatter, "JSON parse failed: {source}"),
            Self::Toml(source) => write!(formatter, "configuration TOML parse failed: {source}"),
        }
    }
}

impl std::error::Error for CoreError {}

#[cfg(test)]
mod tests {
    use std::process::Command;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use vibescan_types::{LocationClass, RepoPath, RlsExposure, Span, SupabaseProject, UnitRef};

    use super::*;

    #[test]
    fn offline_pipeline_finds_supabase_and_generic_secrets() {
        let repo = TestRepo::new();
        repo.git(["init"]);
        repo.write(
            "src/app.tsx",
            "const supabase = 'sb_secret_0123456789abcdefghijklmnopqrstuvwxyzABCDEF';\n",
        );
        repo.write(
            "server/stripe.ts",
            "const stripe = 'sk_live_abcdefghijklmnopqrstuvwxyz123456';\n",
        );

        let result = scan(
            repo.path(),
            ScanConfig {
                include_history: false,
                ..ScanConfig::default()
            },
        )
        .expect("scan succeeds");

        assert!(
            result
                .findings
                .iter()
                .any(|finding| finding.category == Category::SecretExposure)
        );
        assert_eq!(result.scope.network.enabled, false);
    }

    #[test]
    fn vibescanignore_suppresses_matching_paths() {
        let repo = TestRepo::new();
        repo.git(["init"]);
        repo.write(".vibescanignore", "ignored.ts\n");
        repo.write(
            "ignored.ts",
            "const key = 'sb_secret_0123456789abcdefghijklmnopqrstuvwxyzABCDEF';\n",
        );

        let config = ScanConfig::load(repo.path()).expect("config loads");
        let result = scan(repo.path(), config).expect("scan succeeds");

        assert!(result.findings.is_empty());
    }

    #[test]
    fn gitignore_suppresses_matching_paths() {
        let repo = TestRepo::new();
        repo.git(["init"]);
        repo.write(".gitignore", "ignored.ts\n");
        repo.write(
            "ignored.ts",
            "const key = 'sb_secret_0123456789abcdefghijklmnopqrstuvwxyzABCDEF';\n",
        );

        let config = ScanConfig::load(repo.path()).expect("config loads");
        let result = scan(repo.path(), config).expect("scan succeeds");

        assert!(result.findings.is_empty());
    }

    #[test]
    fn gitignored_env_secret_is_still_reported() {
        let repo = TestRepo::new();
        repo.git(["init"]);
        repo.write(".gitignore", ".env\n");
        repo.write(
            ".env",
            "SUPABASE_SERVICE_ROLE_KEY=sb_secret_0123456789abcdefghijklmnopqrstuvwxyzABCDEF\n",
        );

        let result = scan(
            repo.path(),
            ScanConfig {
                include_history: false,
                ..ScanConfig::default()
            },
        )
        .expect("scan succeeds");

        assert!(result.findings.iter().any(|finding| {
            finding.category == Category::SecretExposure
                && matches!(finding.severity, Severity::Critical | Severity::High)
                && finding
                    .locations
                    .iter()
                    .any(|location| location.path.0 == ".env")
        }));
    }

    #[test]
    fn scan_associates_new_publishable_key_with_colocated_project_url() {
        let repo = TestRepo::new();
        repo.git(["init"]);
        repo.write(
            "src/app.tsx",
            "const url = 'https://abcdefghijklmnopqrst.supabase.co';\nconst key = 'sb_publishable_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789';\n",
        );

        let result = scan(
            repo.path(),
            ScanConfig {
                include_history: false,
                ..ScanConfig::default()
            },
        )
        .expect("scan succeeds");

        assert!(result.findings.iter().any(|finding| {
            matches!(
                &finding.evidence,
                Evidence::SupabaseKey {
                    class: SupabaseKeyClass::PublishableNew,
                    project: Some(project),
                    ..
                } if project.url == "https://abcdefghijklmnopqrst.supabase.co"
                    && project.ref_id.as_deref() == Some("abcdefghijklmnopqrst")
            )
        }));
    }

    #[test]
    fn config_path_allowlists_suppress_docs_but_cannot_hide_env() {
        let repo = TestRepo::new();
        repo.git(["init"]);
        repo.write("vibescan.toml", "[ignore]\npaths = [\"docs/**\", \"**\"]\n");
        repo.write(
            "docs/secret.ts",
            "const key = 'sb_secret_docs0123456789abcdefghijklmnopqrstuvwxyzABCDEF';\n",
        );
        repo.write(
            ".env",
            "SUPABASE_SERVICE_ROLE_KEY=sb_secret_env0123456789abcdefghijklmnopqrstuvwxyzABCDEF\n",
        );

        let config = ScanConfig::load(repo.path()).expect("config loads");
        let result = scan(repo.path(), config).expect("scan succeeds");

        assert!(result.findings.iter().any(|finding| {
            finding
                .locations
                .iter()
                .any(|location| location.path.0 == ".env")
        }));
        assert!(!result.findings.iter().any(|finding| {
            finding
                .locations
                .iter()
                .any(|location| location.path.0 == "docs/secret.ts")
        }));
    }

    #[test]
    fn dependency_integrity_flags_invalid_package_names() {
        let repo = TestRepo::new();
        repo.git(["init"]);
        repo.write(
            "package.json",
            r#"{"dependencies":{"Bad Package":"1.0.0"}}"#,
        );

        let result = scan(
            repo.path(),
            ScanConfig {
                include_history: false,
                ..ScanConfig::default()
            },
        )
        .expect("scan succeeds");

        assert!(result.findings.iter().any(|finding| {
            finding.category == Category::DependencyIntegrity && finding.severity == Severity::High
        }));
        assert!(result.findings.iter().any(|finding| {
            matches!(
                finding.evidence,
                Evidence::Dependency {
                    reason: vibescan_types::DependencyIntegrityReason::InvalidPackageName,
                    ..
                }
            )
        }));
    }

    #[test]
    fn dependency_integrity_labels_empty_versions_honestly() {
        let repo = TestRepo::new();
        repo.git(["init"]);
        repo.write("package.json", r#"{"dependencies":{"left-pad":""}}"#);

        let result = scan(
            repo.path(),
            ScanConfig {
                include_history: false,
                ..ScanConfig::default()
            },
        )
        .expect("scan succeeds");

        assert!(result.findings.iter().any(|finding| {
            matches!(
                finding.evidence,
                Evidence::Dependency {
                    ref package,
                    reason: vibescan_types::DependencyIntegrityReason::EmptyVersionSpecifier,
                    ..
                } if package == "left-pad"
            )
        }));
    }

    #[test]
    fn baseline_suppresses_existing_findings() {
        let repo = TestRepo::new();
        repo.git(["init"]);
        repo.write(
            "src/app.ts",
            "const stripe = 'sk_live_abcdefghijklmnopqrstuvwxyz123456';\n",
        );

        let first = scan(
            repo.path(),
            ScanConfig {
                include_history: false,
                ..ScanConfig::default()
            },
        )
        .expect("first scan succeeds");
        let ids = first
            .findings
            .iter()
            .map(|finding| finding.id.0.clone())
            .collect::<Vec<_>>();
        repo.write(
            "baseline.json",
            &serde_json::to_string(&ids).expect("ids serialize"),
        );

        let second = scan(
            repo.path(),
            ScanConfig {
                include_history: false,
                baseline_path: Some(repo.path().join("baseline.json")),
                ..ScanConfig::default()
            },
        )
        .expect("second scan succeeds");

        assert!(second.findings.is_empty());
    }

    #[test]
    fn scan_result_started_at_is_rfc3339_timestamp() {
        let repo = TestRepo::new();
        repo.git(["init"]);

        let result = scan(
            repo.path(),
            ScanConfig {
                include_history: false,
                ..ScanConfig::default()
            },
        )
        .expect("scan succeeds");

        assert!(result.started_at.parse::<Timestamp>().is_ok());
        assert_ne!(result.started_at, "local-static");
    }

    #[test]
    fn json_error_message_is_not_baseline_specific() {
        let error = serde_json::from_str::<serde_json::Value>("{")
            .map_err(CoreError::Json)
            .expect_err("invalid JSON fails");

        assert!(error.to_string().starts_with("JSON parse failed:"));
        assert!(!error.to_string().contains("baseline"));
    }

    #[test]
    fn correlates_public_key_with_rls_exposure_on_same_project() {
        let key = public_key_finding();
        let rls = rls_finding();
        let correlations = correlate_findings(&[key.clone(), rls.clone()]);

        assert_eq!(correlations.len(), 1);
        assert_eq!(correlations[0].severity, Severity::Critical);
        assert_eq!(correlations[0].related, vec![key.id, rls.id]);
    }

    #[test]
    fn exit_code_respects_severity_gate() {
        let mut result = empty_result();
        result
            .findings
            .push(generic_candidate_finding(&SecretCandidate {
                rule_id: vibescan_types::RuleId("toy".to_owned()),
                kind: vibescan_types::CandidateKind::ProviderSecret,
                raw_match: b"abcdefghijklmnopqrstuvwxyz123456".to_vec(),
                entropy: 4.0,
                unit_ref: UnitRef {
                    path: RepoPath("src/app.ts".to_owned()),
                    provenance: Provenance::WorkingTree,
                    additional_provenance: Vec::new(),
                    location_class: LocationClass::Unknown,
                },
                span: Span {
                    line: 1,
                    col_start: 1,
                    col_end: 32,
                },
            }));

        assert_eq!(exit_code(&result, Severity::Critical), 0);
        assert_eq!(exit_code(&result, Severity::High), 1);
    }

    #[test]
    fn generic_high_entropy_candidates_are_medium_review() {
        let finding = generic_candidate_finding(&SecretCandidate {
            rule_id: vibescan_types::RuleId("generic-high-entropy-assignment".to_owned()),
            kind: vibescan_types::CandidateKind::GenericHighEntropy,
            raw_match: b"abcdefghijklmnopqrstuvwxyz1234567890".to_vec(),
            entropy: 4.0,
            unit_ref: UnitRef {
                path: RepoPath("src/app.ts".to_owned()),
                provenance: Provenance::WorkingTree,
                additional_provenance: Vec::new(),
                location_class: LocationClass::Unknown,
            },
            span: Span {
                line: 1,
                col_start: 1,
                col_end: 37,
            },
        });

        assert_eq!(finding.severity, Severity::Medium);
        assert_eq!(finding.confidence, Confidence::Review);
    }

    fn public_key_finding() -> Finding {
        Finding {
            id: FindingId("key".to_owned()),
            category: Category::KeyClassification,
            severity: Severity::Info,
            title: "key".to_owned(),
            detail: "key".to_owned(),
            locations: vec![Location {
                path: RepoPath("src/app.tsx".to_owned()),
                span: None,
                provenance: Provenance::WorkingTree,
                additional_provenance: Vec::new(),
                location_class: LocationClass::ClientReachable,
            }],
            evidence: Evidence::SupabaseKey {
                class: SupabaseKeyClass::AnonLegacy,
                redacted: "eyJ...abcd".to_owned(),
                project: Some(project()),
                fingerprint: SecretFingerprint("fp".to_owned()),
            },
            remediation: "fix".to_owned(),
            related: Vec::new(),
            confidence: Confidence::Likely,
        }
    }

    fn rls_finding() -> Finding {
        Finding {
            id: FindingId("rls".to_owned()),
            category: Category::Rls,
            severity: Severity::Critical,
            title: "rls".to_owned(),
            detail: "rls".to_owned(),
            locations: Vec::new(),
            evidence: Evidence::RlsProbe {
                project: project(),
                table: "profiles".to_owned(),
                endpoint: "https://abcdefghijklmnopqrst.supabase.co/rest/v1/profiles?limit=1"
                    .to_owned(),
                observed_row_count: 1,
                exposure: RlsExposure::Exposed,
            },
            remediation: "fix".to_owned(),
            related: Vec::new(),
            confidence: Confidence::Confirmed,
        }
    }

    fn project() -> SupabaseProject {
        SupabaseProject {
            ref_id: Some("abcdefghijklmnopqrst".to_owned()),
            url: "https://abcdefghijklmnopqrst.supabase.co".to_owned(),
        }
    }

    fn empty_result() -> ScanResult {
        ScanResult {
            findings: Vec::new(),
            scope: ScanScope {
                target: ".".to_owned(),
                working_tree: true,
                history: HistoryScope::Disabled,
                network: NetworkScope {
                    enabled: false,
                    tier0_read_probe: false,
                    tier1_introspection: false,
                },
                warnings: Vec::new(),
            },
            tool_version: TOOL_VERSION.to_owned(),
            started_at: "test".to_owned(),
            duration_ms: 0,
            stats: ScanStats::default(),
        }
    }

    struct TestRepo {
        path: PathBuf,
    }

    impl TestRepo {
        fn new() -> Self {
            static NEXT_ID: AtomicU64 = AtomicU64::new(0);
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock works")
                .as_nanos();
            let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "vibescan-core-test-{}-{nonce}-{id}",
                std::process::id()
            ));
            fs::create_dir_all(&path).expect("test repo dir created");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }

        fn write(&self, path: &str, content: &str) {
            let path = self.path.join(path);
            fs::create_dir_all(path.parent().expect("file has parent")).expect("parent created");
            fs::write(path, content).expect("file written");
        }

        fn git<const N: usize>(&self, args: [&str; N]) {
            let status = Command::new("git")
                .args(args)
                .current_dir(&self.path)
                .status()
                .expect("git command runs");
            assert!(status.success(), "git command failed");
        }
    }

    impl Drop for TestRepo {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}
