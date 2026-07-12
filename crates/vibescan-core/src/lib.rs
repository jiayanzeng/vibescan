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
use vibescan_git::{WalkOptions, collect_repository, discover_repository_root};
use vibescan_report::{ReportFormat, TtyStyle, render, render_tty};
use vibescan_secrets::Detector;
use vibescan_supabase::SupabaseClassifier;
#[cfg(feature = "network")]
use vibescan_supabase::Tier0RlsProbeInput;
#[cfg(feature = "network")]
use vibescan_supabase::probe_tier0_read;
use vibescan_types::{
    Category, Confidence, CorrelationRuleId, Evidence, Finding, FindingId, HistoryScope, Location,
    LocationClass, NetworkScope, Provenance, ScanResult, ScanScope, ScanStats, ScannableUnit,
    ScopeWarning, SecretCandidate, SecretFingerprint, Severity, SupabaseKeyClass,
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
    pub tier0_read_probe: bool,
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
            tier0_read_probe: false,
        }
    }
}

impl ScanConfig {
    /// Load `vibescan.toml` from `target` if present.
    pub fn load(target: impl AsRef<Path>) -> Result<Self, CoreError> {
        let target = target.as_ref();
        let mut config = Self::default();
        let config_root = discover_repository_root(target).map_err(CoreError::Git)?;
        let config_path = config_root.join("vibescan.toml");

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

        if let Some(network) = parsed.network {
            if let Some(tier0_read_probe) = network.tier0_read_probe {
                self.tier0_read_probe = tier0_read_probe;
            }
        }
    }
}

#[derive(Debug, Deserialize)]
struct FileConfig {
    scan: Option<ScanSection>,
    ignore: Option<IgnoreSection>,
    baseline: Option<BaselineSection>,
    network: Option<NetworkSection>,
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

#[derive(Debug, Deserialize)]
struct NetworkSection {
    tier0_read_probe: Option<bool>,
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
    let supabase_classifications = candidates
        .iter()
        .filter_map(|candidate| {
            classifier
                .classify_candidate_with_unit_content(
                    candidate,
                    unit_content
                        .get(candidate.unit_ref.path.0.as_str())
                        .copied(),
                )
                .map(|finding| (candidate, finding))
        })
        .collect::<Vec<_>>();
    let mut findings = supabase_classifications
        .iter()
        .map(|(_, finding)| finding.clone())
        .collect::<Vec<_>>();
    findings.extend(resolve_generic_candidates(&candidates));
    findings.extend(scan_dependency_integrity(&walk.repo_root)?);

    if config.tier0_read_probe {
        #[cfg(feature = "network")]
        {
            let table_candidates = harvest_table_names(&units);
            for input in tier0_probe_inputs(&supabase_classifications, &table_candidates) {
                match probe_tier0_read(&input) {
                    Ok(mut output) => {
                        findings.append(&mut output.findings);
                        warnings.extend(output.warnings.into_iter().map(|warning| {
                            ScopeWarning::Other {
                                message: warning.message(),
                            }
                        }));
                    }
                    Err(error) => warnings.push(ScopeWarning::Other {
                        message: format!(
                            "Tier 0 RLS read probe transport/other error for {}: {error}",
                            input.project.url
                        ),
                    }),
                }
            }
        }
        #[cfg(not(feature = "network"))]
        warnings.push(ScopeWarning::Other {
            message: "Tier 0 RLS read probe requested but this binary was built without the network feature".to_owned(),
        });
    }

    let mut findings = coalesce_findings(findings);
    findings.extend(correlate_findings(&findings));

    let mut findings = dedup_findings(findings);
    findings.retain(|finding| !baseline.contains(&finding.id));
    absorb_correlated_constituents(&mut findings);
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
                enabled: config.tier0_read_probe && cfg!(feature = "network"),
                tier0_read_probe: config.tier0_read_probe && cfg!(feature = "network"),
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
    if result
        .findings
        .iter()
        .any(|finding| finding.severity >= gate)
    {
        1
    } else {
        0
    }
}

/// Apply the registered v1 correlation rules.
pub fn correlate_findings(findings: &[Finding]) -> Vec<Finding> {
    CORRELATION_RULES
        .iter()
        .flat_map(|rule| (rule.apply)(rule, findings))
        .collect()
}

#[derive(Clone, Copy)]
struct CorrelationRule {
    id: &'static str,
    absorbs_related_in_summary: bool,
    apply: fn(&CorrelationRule, &[Finding]) -> Vec<Finding>,
}

const CORRELATION_RULES: &[CorrelationRule] = &[
    CorrelationRule {
        id: "exposed-public-key-chain",
        absorbs_related_in_summary: true,
        apply: correlate_exposed_public_key,
    },
    CorrelationRule {
        id: "elevated-key-in-tree",
        absorbs_related_in_summary: false,
        apply: correlate_elevated_key_moots_rls,
    },
];

fn correlate_exposed_public_key(rule: &CorrelationRule, findings: &[Finding]) -> Vec<Finding> {
    let public_keys = findings.iter().filter(|finding| {
        matches!(
            finding.evidence,
            Evidence::SupabaseKey {
                class: SupabaseKeyClass::PublishableNew | SupabaseKeyClass::AnonLegacy,
                ..
            }
        ) && (max_location_class(&finding.locations) == LocationClass::ClientReachable
            || finding
                .locations
                .iter()
                .any(|location| matches!(location.provenance, Provenance::Commit { .. })))
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

                let rule_id = CorrelationRuleId(rule.id.to_owned());
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

fn correlate_elevated_key_moots_rls(rule: &CorrelationRule, findings: &[Finding]) -> Vec<Finding> {
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
            let rule_id = CorrelationRuleId(rule.id.to_owned());
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

fn absorb_correlated_constituents(findings: &mut Vec<Finding>) {
    let absorbed = findings
        .iter()
        .filter_map(|finding| {
            let Evidence::Correlation { rule_id, .. } = &finding.evidence else {
                return None;
            };
            CORRELATION_RULES
                .iter()
                .find(|rule| rule.id == rule_id.0 && rule.absorbs_related_in_summary)
                .map(|_| finding.related.clone())
        })
        .flatten()
        .collect::<BTreeSet<_>>();

    if absorbed.is_empty() {
        return;
    }

    findings.retain(|finding| {
        finding.category == Category::Correlation || !absorbed.contains(&finding.id)
    });
}

fn resolve_generic_candidates(candidates: &[SecretCandidate]) -> Vec<Finding> {
    candidates
        .iter()
        .filter(|candidate| candidate.kind != vibescan_types::CandidateKind::PossibleSupabaseKey)
        .map(generic_candidate_finding)
        .collect()
}

#[cfg(feature = "network")]
fn tier0_probe_inputs(
    classifications: &[(&SecretCandidate, Finding)],
    candidate_tables: &BTreeSet<String>,
) -> Vec<Tier0RlsProbeInput> {
    let mut by_project = BTreeMap::<String, Tier0RlsProbeInput>::new();
    for (candidate, finding) in classifications {
        let Some(input) = (|| {
            let Evidence::SupabaseKey {
                class: SupabaseKeyClass::PublishableNew | SupabaseKeyClass::AnonLegacy,
                project: Some(project),
                ..
            } = &finding.evidence
            else {
                return None;
            };
            let public_key = std::str::from_utf8(&candidate.raw_match).ok()?.to_owned();
            let key_location = finding.locations.first()?.clone();
            Some(Tier0RlsProbeInput {
                project: project.clone(),
                public_key,
                key_location,
                candidate_tables: candidate_tables.clone(),
            })
        })() else {
            continue;
        };
        let key = normalized_project_url(&input.project.url);
        match by_project.entry(key) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(input);
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                if probe_input_is_better(&input, entry.get()) {
                    entry.insert(input);
                }
            }
        }
    }
    by_project.into_values().collect()
}

#[cfg_attr(not(feature = "network"), allow(dead_code))]
fn harvest_table_names(units: &[ScannableUnit]) -> BTreeSet<String> {
    let mut tables = BTreeSet::new();
    for unit in units {
        let Ok(content) = std::str::from_utf8(&unit.content) else {
            continue;
        };
        harvest_quoted_method_names(content, ".from", &mut tables);
        harvest_quoted_method_names(content, ".rpc", &mut tables);
        harvest_rest_paths(content, &mut tables);
    }
    tables
}

#[cfg_attr(not(feature = "network"), allow(dead_code))]
fn harvest_quoted_method_names(content: &str, method: &str, tables: &mut BTreeSet<String>) {
    let mut rest = content;
    while let Some(index) = rest.find(method) {
        rest = &rest[index + method.len()..];
        let trimmed = rest.trim_start();
        let Some(after_paren) = trimmed.strip_prefix('(') else {
            continue;
        };
        let after_space = after_paren.trim_start();
        let Some(quote) = after_space
            .chars()
            .next()
            .filter(|quote| *quote == '\'' || *quote == '"')
        else {
            continue;
        };
        let after_quote = &after_space[quote.len_utf8()..];
        let Some(end) = after_quote.find(quote) else {
            continue;
        };
        insert_table_name(&after_quote[..end], tables);
        rest = &after_quote[end + quote.len_utf8()..];
    }
}

#[cfg_attr(not(feature = "network"), allow(dead_code))]
fn harvest_rest_paths(content: &str, tables: &mut BTreeSet<String>) {
    let mut rest = content;
    const MARKER: &str = "/rest/v1/";
    while let Some(index) = rest.find(MARKER) {
        let after_marker = &rest[index + MARKER.len()..];
        let end = after_marker
            .find(|ch: char| {
                ch.is_whitespace()
                    || matches!(
                        ch,
                        '/' | '?' | '#' | '"' | '\'' | '`' | ')' | ']' | '}' | '&'
                    )
            })
            .unwrap_or(after_marker.len());
        insert_table_name(&after_marker[..end], tables);
        rest = &after_marker[end..];
    }
}

#[cfg_attr(not(feature = "network"), allow(dead_code))]
fn insert_table_name(name: &str, tables: &mut BTreeSet<String>) {
    let name = name.trim();
    if !name.is_empty()
        && name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.'))
    {
        tables.insert(name.to_owned());
    }
}

#[cfg(feature = "network")]
fn probe_input_is_better(candidate: &Tier0RlsProbeInput, current: &Tier0RlsProbeInput) -> bool {
    location_class_rank(candidate.key_location.location_class)
        .cmp(&location_class_rank(current.key_location.location_class))
        .then_with(|| current.key_location.path.cmp(&candidate.key_location.path))
        .is_gt()
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

fn scan_dependency_integrity(repo_root: &Path) -> Result<Vec<Finding>, CoreError> {
    let mut findings = Vec::new();
    for manifest in collect_manifest_paths(repo_root)? {
        match manifest.kind {
            DependencyManifestKind::PackageJson => {
                scan_package_json(repo_root, &manifest.path, &mut findings)?;
            }
            DependencyManifestKind::PackageLock => {
                scan_package_lock(repo_root, &manifest.path, &mut findings)?;
            }
            DependencyManifestKind::Pyproject => {
                scan_pyproject(repo_root, &manifest.path, &mut findings)?;
            }
            DependencyManifestKind::RequirementsTxt => {
                scan_requirements_txt(repo_root, &manifest.path, &mut findings)?;
            }
        }
    }
    Ok(findings)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DependencyManifestKind {
    PackageJson,
    PackageLock,
    Pyproject,
    RequirementsTxt,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DependencyManifest {
    path: PathBuf,
    kind: DependencyManifestKind,
}

fn collect_manifest_paths(repo_root: &Path) -> Result<Vec<DependencyManifest>, CoreError> {
    let mut manifests = Vec::new();
    collect_manifest_paths_in(repo_root, repo_root, &mut manifests)?;
    manifests.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(manifests)
}

fn collect_manifest_paths_in(
    repo_root: &Path,
    dir: &Path,
    manifests: &mut Vec<DependencyManifest>,
) -> Result<(), CoreError> {
    for entry in fs::read_dir(dir).map_err(CoreError::Io)? {
        let entry = entry.map_err(CoreError::Io)?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(CoreError::Io)?;
        if file_type.is_dir() {
            if should_skip_dependency_dir(repo_root, &path) {
                continue;
            }
            collect_manifest_paths_in(repo_root, &path, manifests)?;
            continue;
        }
        if !file_type.is_file() {
            continue;
        }
        let Some(kind) = dependency_manifest_kind(&path) else {
            continue;
        };
        manifests.push(DependencyManifest { path, kind });
    }
    Ok(())
}

fn should_skip_dependency_dir(repo_root: &Path, path: &Path) -> bool {
    let relative = repo_relative_path(repo_root, path);
    relative
        .split('/')
        .any(|component| matches!(component, ".git" | "node_modules" | "target" | ".next"))
}

fn dependency_manifest_kind(path: &Path) -> Option<DependencyManifestKind> {
    match path.file_name().and_then(|name| name.to_str()) {
        Some("package.json") => Some(DependencyManifestKind::PackageJson),
        Some("package-lock.json") => Some(DependencyManifestKind::PackageLock),
        Some("pyproject.toml") => Some(DependencyManifestKind::Pyproject),
        Some("requirements.txt") => Some(DependencyManifestKind::RequirementsTxt),
        _ => None,
    }
}

fn scan_package_json(
    repo_root: &Path,
    manifest_path: &Path,
    findings: &mut Vec<Finding>,
) -> Result<(), CoreError> {
    let value = read_json_manifest(manifest_path)?;
    for section in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        if let Some(deps) = value.get(section).and_then(serde_json::Value::as_object) {
            for (name, version) in deps {
                check_npm_dependency(repo_root, manifest_path, section, name, version, findings);
            }
        }
    }
    Ok(())
}

fn scan_package_lock(
    repo_root: &Path,
    manifest_path: &Path,
    findings: &mut Vec<Finding>,
) -> Result<(), CoreError> {
    let value = read_json_manifest(manifest_path)?;
    if let Some(deps) = value
        .get("dependencies")
        .and_then(serde_json::Value::as_object)
    {
        for (name, metadata) in deps {
            check_npm_dependency(
                repo_root,
                manifest_path,
                "lockfile dependencies",
                name,
                metadata,
                findings,
            );
        }
    }
    if let Some(packages) = value.get("packages").and_then(serde_json::Value::as_object) {
        for (path, metadata) in packages {
            let Some(name) = path.strip_prefix("node_modules/") else {
                continue;
            };
            if name.is_empty() || name.contains("/node_modules/") {
                continue;
            }
            check_npm_dependency(
                repo_root,
                manifest_path,
                "lockfile packages",
                name,
                metadata,
                findings,
            );
        }
    }
    Ok(())
}

fn scan_pyproject(
    repo_root: &Path,
    manifest_path: &Path,
    findings: &mut Vec<Finding>,
) -> Result<(), CoreError> {
    let content = fs::read_to_string(manifest_path).map_err(CoreError::Io)?;
    let value = toml::from_str::<toml::Value>(&content).map_err(CoreError::Toml)?;
    if let Some(deps) = value
        .get("project")
        .and_then(|project| project.get("dependencies"))
        .and_then(toml::Value::as_array)
    {
        for dep in deps.iter().filter_map(toml::Value::as_str) {
            check_python_requirement(
                repo_root,
                manifest_path,
                "project.dependencies",
                dep,
                findings,
            );
        }
    }
    if let Some(deps) = value
        .get("tool")
        .and_then(|tool| tool.get("poetry"))
        .and_then(|poetry| poetry.get("dependencies"))
        .and_then(toml::Value::as_table)
    {
        for (name, version) in deps {
            if name == "python" {
                continue;
            }
            check_python_dependency_name(
                repo_root,
                manifest_path,
                "tool.poetry.dependencies",
                name,
                findings,
            );
            if version.as_str().is_some_and(|spec| spec.trim().is_empty()) {
                findings.push(dependency_finding(
                    repo_root,
                    manifest_path,
                    name,
                    "empty version specifier in tool.poetry.dependencies",
                    vibescan_types::DependencyIntegrityReason::EmptyVersionSpecifier,
                ));
            }
        }
    }
    Ok(())
}

fn scan_requirements_txt(
    repo_root: &Path,
    manifest_path: &Path,
    findings: &mut Vec<Finding>,
) -> Result<(), CoreError> {
    let content = fs::read_to_string(manifest_path).map_err(CoreError::Io)?;
    for line in content.lines() {
        check_python_requirement(repo_root, manifest_path, "requirements.txt", line, findings);
    }
    Ok(())
}

fn read_json_manifest(path: &Path) -> Result<serde_json::Value, CoreError> {
    let content = fs::read_to_string(path).map_err(CoreError::Io)?;
    serde_json::from_str::<serde_json::Value>(&content).map_err(CoreError::Json)
}

fn check_npm_dependency(
    repo_root: &Path,
    manifest_path: &Path,
    section: &str,
    name: &str,
    version: &serde_json::Value,
    findings: &mut Vec<Finding>,
) {
    if !valid_npm_name(name) {
        findings.push(dependency_finding(
            repo_root,
            manifest_path,
            name,
            &format!("invalid npm package name in {section}"),
            vibescan_types::DependencyIntegrityReason::InvalidPackageName,
        ));
    }
    let version = version
        .as_str()
        .or_else(|| version.get("version").and_then(serde_json::Value::as_str));
    if version.is_some_and(|spec| spec.trim().is_empty()) {
        findings.push(dependency_finding(
            repo_root,
            manifest_path,
            name,
            &format!("empty version specifier in {section}"),
            vibescan_types::DependencyIntegrityReason::EmptyVersionSpecifier,
        ));
    }
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

fn check_python_requirement(
    repo_root: &Path,
    manifest_path: &Path,
    section: &str,
    requirement: &str,
    findings: &mut Vec<Finding>,
) {
    let requirement = requirement
        .split_once('#')
        .map_or(requirement, |(before_comment, _)| before_comment)
        .trim();
    if requirement.is_empty()
        || requirement.starts_with('-')
        || requirement.contains("://")
        || requirement.starts_with("git+")
    {
        return;
    }
    let name = python_requirement_name(requirement);
    check_python_dependency_name(repo_root, manifest_path, section, name, findings);
}

fn check_python_dependency_name(
    repo_root: &Path,
    manifest_path: &Path,
    section: &str,
    name: &str,
    findings: &mut Vec<Finding>,
) {
    if !valid_python_package_name(name) {
        findings.push(dependency_finding(
            repo_root,
            manifest_path,
            name,
            &format!("invalid Python package name in {section}"),
            vibescan_types::DependencyIntegrityReason::InvalidPackageName,
        ));
    }
}

fn python_requirement_name(requirement: &str) -> &str {
    let version_start = requirement
        .find(['=', '<', '>', '!', '~'])
        .unwrap_or(requirement.len());
    let extras_start = requirement.find('[').unwrap_or(version_start);
    requirement[..version_start.min(extras_start)].trim()
}

fn valid_python_package_name(name: &str) -> bool {
    let trimmed = name.trim();
    !trimmed.is_empty()
        && trimmed
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
        && trimmed
            .chars()
            .next()
            .is_some_and(|ch| ch.is_ascii_alphanumeric())
        && trimmed
            .chars()
            .last()
            .is_some_and(|ch| ch.is_ascii_alphanumeric())
}

fn dependency_finding(
    repo_root: &Path,
    manifest_path: &Path,
    package: &str,
    detail: &str,
    reason: vibescan_types::DependencyIntegrityReason,
) -> Finding {
    let manifest_path = vibescan_types::RepoPath(repo_relative_path(repo_root, manifest_path));
    let mut hasher = Sha256::new();
    hasher.update(manifest_path.0.as_bytes());
    hasher.update(b"\0");
    hasher.update(package.as_bytes());
    hasher.update(b"\0");
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
            path: manifest_path.clone(),
            span: None,
            provenance: Provenance::WorkingTree,
            additional_provenance: Vec::new(),
            location_class: vibescan_types::LocationClass::ServerOnly,
        }],
        evidence: Evidence::Dependency {
            package: package.to_owned(),
            manifest_path,
            reason,
        },
        remediation: "Correct or remove the dependency before install or deployment.".to_owned(),
        related: Vec::new(),
        confidence: Confidence::Review,
    }
}

fn repo_relative_path(repo_root: &Path, path: &Path) -> String {
    path.strip_prefix(repo_root)
        .unwrap_or(path)
        .components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
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

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct FindingCoalesceKey {
    category: Category,
    rule_or_class: String,
    fingerprint: String,
    project_url: Option<String>,
    severity: Severity,
}

fn coalesce_findings(findings: Vec<Finding>) -> Vec<Finding> {
    let mut coalesced = BTreeMap::<FindingCoalesceKey, Finding>::new();
    let mut passthrough = Vec::new();

    for mut finding in findings {
        let Some(key) = coalesce_key(&finding) else {
            passthrough.push(finding);
            continue;
        };
        finding.id = coalesced_finding_id(&key);
        sort_locations(&mut finding.locations);

        match coalesced.entry(key) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(finding);
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                merge_findings(entry.get_mut(), finding);
            }
        }
    }

    passthrough.extend(coalesced.into_values());
    passthrough
}

fn coalesce_key(finding: &Finding) -> Option<FindingCoalesceKey> {
    match &finding.evidence {
        Evidence::Secret { fingerprint, .. } => Some(FindingCoalesceKey {
            category: finding.category,
            rule_or_class: secret_rule_key(finding).to_owned(),
            fingerprint: fingerprint.0.clone(),
            project_url: None,
            severity: finding.severity,
        }),
        Evidence::SupabaseKey {
            class,
            project,
            fingerprint,
            ..
        } => Some(FindingCoalesceKey {
            category: finding.category,
            rule_or_class: format!("supabase-key:{}", supabase_key_class_key(*class)),
            fingerprint: fingerprint.0.clone(),
            project_url: project
                .as_ref()
                .map(|project| normalized_project_url(&project.url)),
            severity: finding.severity,
        }),
        _ => None,
    }
}

fn coalesced_finding_id(key: &FindingCoalesceKey) -> FindingId {
    let mut hasher = Sha256::new();
    hasher.update(category_key(key.category).as_bytes());
    hasher.update(b"\0");
    hasher.update(key.rule_or_class.as_bytes());
    hasher.update(b"\0");
    hasher.update(key.fingerprint.as_bytes());
    hasher.update(b"\0");
    hasher.update(key.project_url.as_deref().unwrap_or("<none>").as_bytes());
    hasher.update(b"\0");
    hasher.update(severity_key(key.severity).as_bytes());

    let prefix = if key.rule_or_class.starts_with("supabase-key:") {
        "supabase-key"
    } else {
        "secret"
    };
    FindingId(format!(
        "{prefix}-{}",
        hex::encode(&hasher.finalize()[..12])
    ))
}

fn merge_findings(existing: &mut Finding, incoming: Finding) {
    existing.locations.extend(incoming.locations);
    sort_locations(&mut existing.locations);
    existing.related.extend(incoming.related);
    existing.related.sort();
    existing.related.dedup();
}

fn sort_locations(locations: &mut Vec<Location>) {
    locations.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| span_key(&left.span).cmp(&span_key(&right.span)))
            .then_with(|| provenance_key(&left.provenance).cmp(&provenance_key(&right.provenance)))
            .then_with(|| {
                location_class_rank(left.location_class)
                    .cmp(&location_class_rank(right.location_class))
            })
    });
    locations.dedup();
}

fn span_key(span: &Option<vibescan_types::Span>) -> Option<(u32, u32, u32)> {
    span.map(|span| (span.line, span.col_start, span.col_end))
}

fn provenance_key(provenance: &Provenance) -> String {
    match provenance {
        Provenance::WorkingTree => "working_tree".to_owned(),
        Provenance::Commit { sha, author, date } => {
            format!(
                "commit:{}:{}:{}",
                sha,
                author.as_deref().unwrap_or(""),
                date.as_deref().unwrap_or("")
            )
        }
    }
}

fn secret_rule_key(finding: &Finding) -> &str {
    finding
        .title
        .strip_prefix("Secret candidate matched ")
        .unwrap_or(&finding.title)
}

fn category_key(category: Category) -> &'static str {
    match category {
        Category::SecretExposure => "secret_exposure",
        Category::KeyClassification => "key_classification",
        Category::Rls => "rls",
        Category::DependencyIntegrity => "dependency_integrity",
        Category::Correlation => "correlation",
    }
}

fn supabase_key_class_key(class: SupabaseKeyClass) -> &'static str {
    match class {
        SupabaseKeyClass::PublishableNew => "publishable_new",
        SupabaseKeyClass::SecretNew => "secret_new",
        SupabaseKeyClass::AnonLegacy => "anon_legacy",
        SupabaseKeyClass::ServiceRoleLegacy => "service_role_legacy",
        SupabaseKeyClass::Unknown => "unknown",
    }
}

fn severity_key(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}

fn normalized_project_url(url: &str) -> String {
    let trimmed = url.trim_end_matches('/');
    for scheme in ["https://", "http://"] {
        if let Some(rest) = trimmed.strip_prefix(scheme) {
            return if let Some((host, path)) = rest.split_once('/') {
                format!("{scheme}{}/{}", host.to_ascii_lowercase(), path)
            } else {
                format!("{scheme}{}", rest.to_ascii_lowercase())
            };
        }
    }
    trimmed.to_ascii_lowercase()
}

fn max_location_class(locations: &[Location]) -> LocationClass {
    locations
        .iter()
        .map(|location| location.location_class)
        .max_by_key(|class| location_class_rank(*class))
        .unwrap_or(LocationClass::Unknown)
}

fn location_class_rank(location_class: LocationClass) -> u8 {
    match location_class {
        LocationClass::Unknown => 0,
        LocationClass::ServerOnly => 1,
        LocationClass::ClientReachable => 2,
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
        assert!(!result.scope.network.enabled);
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
    fn coalesces_same_secret_across_paths() {
        let repo = TestRepo::new();
        repo.git(["init"]);
        let url = "https://abcdefghijklmnopqrst.supabase.co";
        let key = "sb_publishable_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";
        repo.write(
            "apps/web/.env.local",
            &format!("NEXT_PUBLIC_SUPABASE_URL={url}\nNEXT_PUBLIC_SUPABASE_ANON_KEY={key}\n"),
        );
        repo.write(
            "apps/web/.next/static/chunks/x.js",
            &format!("const url = '{url}';\nconst key = '{key}';\n"),
        );

        let result = scan(
            repo.path(),
            ScanConfig {
                include_history: false,
                severity_gate: Severity::Info,
                ..ScanConfig::default()
            },
        )
        .expect("scan succeeds");
        let findings = publishable_key_findings(&result);

        assert_eq!(findings.len(), 1);
        let finding = findings[0];
        let locations = finding
            .locations
            .iter()
            .map(|location| location.path.0.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            locations,
            vec!["apps/web/.env.local", "apps/web/.next/static/chunks/x.js"]
        );
        assert_eq!(
            max_location_class(&finding.locations),
            LocationClass::ClientReachable
        );
        assert_eq!(result.stats.by_category[&Category::KeyClassification], 1);
    }

    #[test]
    fn identical_content_at_server_and_browser_paths_retains_both_locations() {
        let repo = TestRepo::new();
        repo.git(["init"]);
        let content = "NEXT_PUBLIC_SUPABASE_URL=https://abcdefghijklmnopqrst.supabase.co\nNEXT_PUBLIC_SUPABASE_ANON_KEY=sb_publishable_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789\n";
        repo.write("apps/api/.env.local", content);
        repo.write("apps/web/.next/static/chunks/config.js", content);

        let result = scan(
            repo.path(),
            ScanConfig {
                include_history: false,
                severity_gate: Severity::Info,
                ..ScanConfig::default()
            },
        )
        .expect("scan succeeds");
        let findings = publishable_key_findings(&result);

        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0]
                .locations
                .iter()
                .map(|location| location.path.0.as_str())
                .collect::<Vec<_>>(),
            vec![
                "apps/api/.env.local",
                "apps/web/.next/static/chunks/config.js"
            ]
        );
        assert_eq!(
            max_location_class(&findings[0].locations),
            LocationClass::ClientReachable
        );
    }

    #[test]
    fn coalescing_keeps_different_secrets_at_same_path_separate() {
        let repo = TestRepo::new();
        repo.git(["init"]);
        repo.write(
            "src/app.tsx",
            "const url = 'https://abcdefghijklmnopqrst.supabase.co';\nconst keyA = 'sb_publishable_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789';\nconst keyB = 'sb_publishable_ZyXwVuTsRqPoNmLkJiHgFeDcBa9876543210';\n",
        );

        let result = scan(
            repo.path(),
            ScanConfig {
                include_history: false,
                severity_gate: Severity::Info,
                ..ScanConfig::default()
            },
        )
        .expect("scan succeeds");

        assert_eq!(publishable_key_findings(&result).len(), 2);
    }

    #[test]
    fn coalescing_keeps_same_secret_on_different_projects_separate() {
        let repo = TestRepo::new();
        repo.git(["init"]);
        let key = "sb_publishable_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";
        repo.write(
            "apps/a/src/app.tsx",
            &format!(
                "const url = 'https://abcdefghijklmnopqrst.supabase.co';\nconst key = '{key}';\n"
            ),
        );
        repo.write(
            "apps/b/src/app.tsx",
            &format!(
                "const url = 'https://zyxwvutsrqponmlkjihg.supabase.co';\nconst key = '{key}';\n"
            ),
        );

        let result = scan(
            repo.path(),
            ScanConfig {
                include_history: false,
                severity_gate: Severity::Info,
                ..ScanConfig::default()
            },
        )
        .expect("scan succeeds");
        let project_urls = publishable_key_findings(&result)
            .into_iter()
            .filter_map(|finding| {
                let Evidence::SupabaseKey {
                    project: Some(project),
                    ..
                } = &finding.evidence
                else {
                    return None;
                };
                Some(project.url.as_str())
            })
            .collect::<BTreeSet<_>>();

        assert_eq!(
            project_urls,
            BTreeSet::from([
                "https://abcdefghijklmnopqrst.supabase.co",
                "https://zyxwvutsrqponmlkjihg.supabase.co"
            ])
        );
    }

    #[test]
    fn projectless_copy_joins_single_known_project_for_same_fingerprint() {
        let repo = TestRepo::new();
        repo.git(["init"]);
        let key = "sb_publishable_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";
        repo.write(
            "apps/web/src/config.ts",
            &format!(
                "const url = 'https://abcdefghijklmnopqrst.supabase.co';\nconst key = '{key}';\n"
            ),
        );
        repo.write(
            "apps/web/.next/static/chunks/config.js",
            &format!("window.supabaseKey = '{key}';\n"),
        );

        let result = scan(
            repo.path(),
            ScanConfig {
                include_history: false,
                severity_gate: Severity::Info,
                ..ScanConfig::default()
            },
        )
        .expect("scan succeeds");
        let findings = publishable_key_findings(&result);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].locations.len(), 2);
        assert!(matches!(
            findings[0].evidence,
            Evidence::SupabaseKey {
                project: Some(_),
                ..
            }
        ));
    }

    #[test]
    fn ambiguous_projectless_copy_does_not_join_known_different_projects() {
        let repo = TestRepo::new();
        repo.git(["init"]);
        let key = "sb_publishable_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";
        repo.write(
            "apps/a/src/config.ts",
            &format!(
                "const url = 'https://abcdefghijklmnopqrst.supabase.co';\nconst key = '{key}';\n"
            ),
        );
        repo.write(
            "apps/b/src/config.ts",
            &format!(
                "const url = 'https://zyxwvutsrqponmlkjihg.supabase.co';\nconst key = '{key}';\n"
            ),
        );
        repo.write("shared/config.ts", &format!("const key = '{key}';\n"));

        let result = scan(
            repo.path(),
            ScanConfig {
                include_history: false,
                severity_gate: Severity::Info,
                ..ScanConfig::default()
            },
        )
        .expect("scan succeeds");
        let findings = publishable_key_findings(&result);

        assert_eq!(findings.len(), 3);
        assert_eq!(
            findings
                .iter()
                .filter(|finding| matches!(
                    finding.evidence,
                    Evidence::SupabaseKey { project: None, .. }
                ))
                .count(),
            1
        );
    }

    #[test]
    fn historical_versions_at_same_path_keep_their_own_project_context() {
        let repo = TestRepo::new();
        repo.git(["init"]);
        repo.git(["config", "user.email", "phase0@example.invalid"]);
        repo.git(["config", "user.name", "Phase Zero"]);
        let key = "sb_publishable_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";
        repo.write(
            "src/config.ts",
            &format!(
                "const url = 'https://abcdefghijklmnopqrst.supabase.co';\nconst key = '{key}';\n"
            ),
        );
        repo.git(["add", "src/config.ts"]);
        repo.git(["commit", "-m", "project a"]);
        repo.write(
            "src/config.ts",
            &format!(
                "const url = 'https://zyxwvutsrqponmlkjihg.supabase.co';\nconst key = '{key}';\n"
            ),
        );
        repo.git(["add", "src/config.ts"]);
        repo.git(["commit", "-m", "project b"]);

        let result = scan(
            repo.path(),
            ScanConfig {
                severity_gate: Severity::Info,
                ..ScanConfig::default()
            },
        )
        .expect("scan succeeds");
        let projects = publishable_key_findings(&result)
            .into_iter()
            .filter_map(project_url_from_key)
            .collect::<BTreeSet<_>>();

        assert_eq!(
            projects,
            BTreeSet::from([
                "https://abcdefghijklmnopqrst.supabase.co",
                "https://zyxwvutsrqponmlkjihg.supabase.co"
            ])
        );
    }

    #[cfg(feature = "network")]
    #[test]
    fn tier0_probe_inputs_dedup_same_project_and_prefer_client_location() {
        let server_candidate =
            publishable_candidate("apps/web/.env.local", LocationClass::ServerOnly);
        let client_candidate = publishable_candidate(
            "apps/web/.next/static/chunks/x.js",
            LocationClass::ClientReachable,
        );
        let mut server_finding = public_key_finding_at(
            "server-key",
            "apps/web/.env.local",
            LocationClass::ServerOnly,
        );
        let mut client_finding = public_key_finding_at(
            "client-key",
            "apps/web/.next/static/chunks/x.js",
            LocationClass::ClientReachable,
        );
        if let Evidence::SupabaseKey {
            project: Some(project),
            ..
        } = &mut server_finding.evidence
        {
            project.url = "https://ABCDEFGHIJKLMNOPQRST.supabase.co/".to_owned();
        }
        if let Evidence::SupabaseKey {
            project: Some(project),
            ..
        } = &mut client_finding.evidence
        {
            project.url = "https://abcdefghijklmnopqrst.supabase.co".to_owned();
        }
        let classifications = vec![
            (&server_candidate, server_finding),
            (&client_candidate, client_finding),
        ];
        let candidate_tables = BTreeSet::from(["profiles".to_owned()]);

        let inputs = tier0_probe_inputs(&classifications, &candidate_tables);

        assert_eq!(inputs.len(), 1);
        assert_eq!(
            inputs[0].key_location.path.0,
            "apps/web/.next/static/chunks/x.js"
        );
        assert_eq!(
            inputs[0].key_location.location_class,
            LocationClass::ClientReachable
        );
        assert_eq!(inputs[0].candidate_tables, candidate_tables);
    }

    #[cfg(feature = "network")]
    #[test]
    fn tier0_probe_inputs_keep_harvested_tables_project_local() {
        let candidate_a = publishable_candidate(
            "apps/a/.next/static/chunks/a.js",
            LocationClass::ClientReachable,
        );
        let candidate_b = publishable_candidate(
            "apps/b/.next/static/chunks/b.js",
            LocationClass::ClientReachable,
        );
        let finding_a = public_key_finding_at(
            "key-a",
            "apps/a/.next/static/chunks/a.js",
            LocationClass::ClientReachable,
        );
        let mut finding_b = public_key_finding_at(
            "key-b",
            "apps/b/.next/static/chunks/b.js",
            LocationClass::ClientReachable,
        );
        if let Evidence::SupabaseKey {
            project: Some(project),
            ..
        } = &mut finding_b.evidence
        {
            project.ref_id = Some("zyxwvutsrqponmlkjihg".to_owned());
            project.url = "https://zyxwvutsrqponmlkjihg.supabase.co".to_owned();
        }
        let classifications = vec![(&candidate_a, finding_a), (&candidate_b, finding_b)];
        let harvested = BTreeSet::from(["accounts_a".to_owned(), "accounts_b".to_owned()]);

        let inputs = tier0_probe_inputs(&classifications, &harvested);
        let tables_by_project = inputs
            .into_iter()
            .map(|input| (input.project.url, input.candidate_tables))
            .collect::<BTreeMap<_, _>>();

        assert_eq!(
            tables_by_project["https://abcdefghijklmnopqrst.supabase.co"],
            BTreeSet::from(["accounts_a".to_owned()])
        );
        assert_eq!(
            tables_by_project["https://zyxwvutsrqponmlkjihg.supabase.co"],
            BTreeSet::from(["accounts_b".to_owned()])
        );
    }

    #[cfg(feature = "network")]
    #[test]
    fn tier0_probe_inputs_do_not_cross_probe_ambiguous_harvested_table() {
        let candidate_a = publishable_candidate(
            "apps/a/.next/static/chunks/a.js",
            LocationClass::ClientReachable,
        );
        let candidate_b = publishable_candidate(
            "apps/b/.next/static/chunks/b.js",
            LocationClass::ClientReachable,
        );
        let finding_a = public_key_finding_at(
            "key-a",
            "apps/a/.next/static/chunks/a.js",
            LocationClass::ClientReachable,
        );
        let mut finding_b = public_key_finding_at(
            "key-b",
            "apps/b/.next/static/chunks/b.js",
            LocationClass::ClientReachable,
        );
        if let Evidence::SupabaseKey {
            project: Some(project),
            ..
        } = &mut finding_b.evidence
        {
            project.ref_id = Some("zyxwvutsrqponmlkjihg".to_owned());
            project.url = "https://zyxwvutsrqponmlkjihg.supabase.co".to_owned();
        }
        let classifications = vec![(&candidate_a, finding_a), (&candidate_b, finding_b)];
        let ambiguously_scoped_tables = BTreeSet::from(["shared_profiles".to_owned()]);

        let inputs = tier0_probe_inputs(&classifications, &ambiguously_scoped_tables);

        assert!(
            inputs.iter().all(|input| input.candidate_tables.is_empty()),
            "an ambiguously associated table must not be sent to either project"
        );
    }

    #[test]
    fn harvest_table_names_extracts_localstatic_candidates() {
        let units = vec![ScannableUnit {
            content: br#"
                const profiles = supabase.from('profiles').select('*');
                await client.from("orders").select("id");
                await supabase.rpc('do_x');
                fetch("/rest/v1/widgets?select=*");
            "#
            .to_vec(),
            path: RepoPath("apps/web/.next/static/chunks/x.js".to_owned()),
            provenance: Provenance::WorkingTree,
            additional_provenance: Vec::new(),
            location_class: LocationClass::ClientReachable,
        }];

        assert_eq!(
            harvest_table_names(&units),
            BTreeSet::from([
                "do_x".to_owned(),
                "orders".to_owned(),
                "profiles".to_owned(),
                "widgets".to_owned(),
            ])
        );
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
    fn config_loads_from_repo_root_when_target_is_subdirectory() {
        let repo = TestRepo::new();
        repo.git(["init"]);
        repo.write("vibescan.toml", "[ignore]\npaths = [\"src/**\"]\n");
        repo.write(
            "src/app.ts",
            "const key = 'sb_secret_0123456789abcdefghijklmnopqrstuvwxyzABCDEF';\n",
        );

        let target = repo.path().join("src");
        let config = ScanConfig::load(&target).expect("config loads from repo root");
        let result = scan(&target, config).expect("scan succeeds");

        assert!(result.findings.is_empty());
    }

    #[test]
    fn clean_control_fixture_produces_zero_findings() {
        let repo = TestRepo::new();
        repo.git(["init"]);
        repo.write(
            "package.json",
            r#"{"dependencies":{"@supabase/supabase-js":"2.0.0","next":"15.0.0"}}"#,
        );
        repo.write(
            "src/app/page.tsx",
            "export default function Page() { return <main>clean</main>; }\n",
        );
        repo.write(
            "supabase/functions/ping/index.ts",
            "Deno.serve(() => new Response('ok'));\n",
        );

        let result = scan(
            repo.path(),
            ScanConfig {
                include_history: false,
                severity_gate: Severity::Info,
                ..ScanConfig::default()
            },
        )
        .expect("scan succeeds");

        assert_eq!(result.findings, Vec::new());
    }

    #[test]
    fn elevated_key_committed_then_removed_fixture_is_history_only_critical() {
        let repo = TestRepo::new();
        repo.git(["init"]);
        repo.git(["config", "user.email", "vibescan@example.invalid"]);
        repo.git(["config", "user.name", "vibescan test"]);
        repo.write(
            "src/history.ts",
            "export const key = 'sb_secret_0123456789abcdefghijklmnopqrstuvwxyzABCDEF';\n",
        );
        repo.git(["add", "src/history.ts"]);
        repo.git(["commit", "-m", "add historical secret"]);
        repo.write("src/history.ts", "export const ok = true;\n");
        repo.git(["add", "src/history.ts"]);
        repo.git(["commit", "-m", "remove historical secret"]);

        let result = scan(repo.path(), ScanConfig::default()).expect("scan succeeds");
        let findings = result
            .findings
            .iter()
            .filter(|finding| {
                matches!(
                    finding.evidence,
                    Evidence::SupabaseKey {
                        class: SupabaseKeyClass::SecretNew,
                        ..
                    }
                )
            })
            .collect::<Vec<_>>();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, Category::SecretExposure);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(findings[0].locations.iter().any(|location| {
            location.path.0 == "src/history.ts"
                && matches!(location.provenance, Provenance::Commit { .. })
        }));
    }

    #[test]
    fn gitignored_env_fixture_has_exact_elevated_key_finding() {
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
        let findings = result
            .findings
            .iter()
            .filter(|finding| {
                finding
                    .locations
                    .iter()
                    .any(|location| location.path.0 == ".env")
            })
            .collect::<Vec<_>>();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, Category::SecretExposure);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(matches!(
            findings[0].evidence,
            Evidence::SupabaseKey {
                class: SupabaseKeyClass::SecretNew,
                ..
            }
        ));
    }

    #[test]
    fn next_build_tree_fixture_is_clean_after_ignore_overrides() {
        let repo = TestRepo::new();
        repo.git(["init"]);
        repo.write(".gitignore", ".next/\n");
        repo.write(
            "dashboard/.next/server/vendor-chunks/prop-types.js",
            "var x='abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ';\n",
        );
        repo.write(
            "dashboard/.next/static/chunks/app.js",
            "self.__next_f.push(['clean static bundle']);\n",
        );

        let result = scan(
            repo.path(),
            ScanConfig {
                include_history: false,
                severity_gate: Severity::Info,
                ..ScanConfig::default()
            },
        )
        .expect("scan succeeds");

        assert_eq!(result.findings, Vec::new());
    }

    #[test]
    fn invalid_dependency_fixture_has_exact_integrity_finding() {
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

        assert_eq!(result.findings.len(), 1);
        let finding = &result.findings[0];
        assert_eq!(finding.category, Category::DependencyIntegrity);
        assert_eq!(finding.severity, Severity::High);
        assert!(matches!(
            finding.evidence,
            Evidence::Dependency {
                ref package,
                reason: vibescan_types::DependencyIntegrityReason::InvalidPackageName,
                ..
            } if package == "Bad Package"
        ));
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
    fn dependency_integrity_scans_package_lock() {
        let repo = TestRepo::new();
        repo.git(["init"]);
        repo.write(
            "package-lock.json",
            r#"{"packages":{"node_modules/Bad Package":{"version":"1.0.0"}}}"#,
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
                finding.evidence,
                Evidence::Dependency {
                    ref manifest_path,
                    ref package,
                    reason: vibescan_types::DependencyIntegrityReason::InvalidPackageName,
                } if manifest_path.0 == "package-lock.json" && package == "Bad Package"
            )
        }));
    }

    #[test]
    fn dependency_integrity_scans_python_manifests() {
        let repo = TestRepo::new();
        repo.git(["init"]);
        repo.write(
            "pyproject.toml",
            "[project]\ndependencies = [\"bad package>=1\"]\n",
        );
        repo.write("requirements.txt", "also bad==1\n");

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
                    ref manifest_path,
                    ref package,
                    reason: vibescan_types::DependencyIntegrityReason::InvalidPackageName,
                } if manifest_path.0 == "pyproject.toml" && package == "bad package"
            )
        }));
        assert!(result.findings.iter().any(|finding| {
            matches!(
                finding.evidence,
                Evidence::Dependency {
                    ref manifest_path,
                    ref package,
                    reason: vibescan_types::DependencyIntegrityReason::InvalidPackageName,
                } if manifest_path.0 == "requirements.txt" && package == "also bad"
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
    fn additional_commit_provenance_qualifies_server_public_key_for_correlation() {
        let mut key = public_key_finding();
        key.locations[0].location_class = LocationClass::ServerOnly;
        key.locations[0].additional_provenance = vec![Provenance::Commit {
            sha: "0123456789abcdef".to_owned(),
            author: None,
            date: None,
        }];

        let correlations = correlate_findings(&[key, rls_finding()]);

        assert!(correlations.iter().any(|finding| matches!(
            &finding.evidence,
            Evidence::Correlation { rule_id, .. } if rule_id.0 == "exposed-public-key-chain"
        )));
    }

    #[test]
    fn additional_commit_provenance_qualifies_elevated_key_for_correlation() {
        let mut key = public_key_finding();
        key.id = FindingId("elevated-key".to_owned());
        key.locations[0].location_class = LocationClass::ServerOnly;
        key.locations[0].additional_provenance = vec![Provenance::Commit {
            sha: "fedcba9876543210".to_owned(),
            author: None,
            date: None,
        }];
        if let Evidence::SupabaseKey { class, .. } = &mut key.evidence {
            *class = SupabaseKeyClass::SecretNew;
        }

        let correlations = correlate_findings(&[key, rls_finding()]);

        assert!(correlations.iter().any(|finding| matches!(
            &finding.evidence,
            Evidence::Correlation { rule_id, .. } if rule_id.0 == "elevated-key-in-tree"
        )));
    }

    #[test]
    fn server_only_uncommitted_public_key_remains_outside_correlation() {
        let mut key = public_key_finding();
        key.locations[0].location_class = LocationClass::ServerOnly;

        assert!(correlate_findings(&[key, rls_finding()]).is_empty());
    }

    #[test]
    fn correlation_locations_are_a_deterministic_unique_union() {
        let mut key = public_key_finding();
        key.locations = vec![
            Location {
                path: RepoPath("apps/api/.env.local".to_owned()),
                span: None,
                provenance: Provenance::WorkingTree,
                additional_provenance: Vec::new(),
                location_class: LocationClass::ServerOnly,
            },
            Location {
                path: RepoPath("apps/web/src/config.ts".to_owned()),
                span: None,
                provenance: Provenance::WorkingTree,
                additional_provenance: Vec::new(),
                location_class: LocationClass::ClientReachable,
            },
        ];
        let mut rls = rls_finding();
        rls.locations = vec![key.locations[1].clone()];

        let correlation = correlate_findings(&[key, rls])
            .into_iter()
            .find(|finding| {
                matches!(
                    &finding.evidence,
                    Evidence::Correlation { rule_id, .. } if rule_id.0 == "exposed-public-key-chain"
                )
            })
            .expect("correlation emitted");

        assert_eq!(
            correlation
                .locations
                .iter()
                .map(|location| location.path.0.as_str())
                .collect::<Vec<_>>(),
            vec!["apps/api/.env.local", "apps/web/src/config.ts"]
        );
    }

    #[test]
    fn exposed_public_key_correlation_absorbs_constituents_in_summary() {
        let key = public_key_finding();
        let rls = rls_finding();
        let correlation = correlate_findings(&[key.clone(), rls.clone()])
            .into_iter()
            .next()
            .expect("correlation emitted");
        let mut findings = vec![key, rls, correlation.clone()];

        absorb_correlated_constituents(&mut findings);

        assert_eq!(findings, vec![correlation]);
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

    #[test]
    fn localstatic_dependency_boundary_excludes_network_crates() {
        if cfg!(feature = "network") {
            return;
        }

        let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("workspace root");
        let rustc = Command::new("rustc")
            .arg("-vV")
            .output()
            .expect("rustc version query runs");
        assert!(
            rustc.status.success(),
            "rustc -vV failed: {}",
            String::from_utf8_lossy(&rustc.stderr)
        );
        let rustc_stdout = String::from_utf8(rustc.stdout).expect("rustc output is UTF-8");
        let host = rustc_stdout
            .lines()
            .find_map(|line| line.strip_prefix("host: "))
            .expect("rustc reports host triple");
        let output = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned()))
            .args([
                "metadata",
                "--format-version",
                "1",
                "--locked",
                "--offline",
                "--filter-platform",
                host,
            ])
            .current_dir(workspace_root)
            .output()
            .expect("cargo metadata runs");
        assert!(
            output.status.success(),
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let metadata: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("metadata JSON parses");
        let packages = metadata["packages"]
            .as_array()
            .expect("metadata contains packages");
        let mut names_by_id = BTreeMap::new();
        let mut ids_by_name = BTreeMap::new();
        for package in packages {
            let id = package["id"].as_str().expect("package id").to_owned();
            let name = package["name"].as_str().expect("package name").to_owned();
            names_by_id.insert(id.clone(), name.clone());
            ids_by_name.entry(name).or_insert(id);
        }

        let mut normal_edges = BTreeMap::<String, Vec<String>>::new();
        for node in metadata["resolve"]["nodes"]
            .as_array()
            .expect("metadata contains resolve nodes")
        {
            let id = node["id"].as_str().expect("node id").to_owned();
            let mut deps = Vec::new();
            for dep in node["deps"].as_array().expect("node deps") {
                if dep["dep_kinds"]
                    .as_array()
                    .expect("dependency kinds")
                    .iter()
                    .any(|kind| kind["kind"].is_null() || kind["kind"] == "normal")
                {
                    deps.push(dep["pkg"].as_str().expect("dep package id").to_owned());
                }
            }
            normal_edges.insert(id, deps);
        }

        let localstatic_crates = [
            "vibescan-types",
            "vibescan-git",
            "vibescan-secrets",
            "vibescan-supabase",
            "vibescan-report",
            "vibescan-core",
        ];
        let denied = BTreeSet::from([
            "reqwest",
            "hyper",
            "tokio",
            "ureq",
            "isahc",
            "curl",
            "openssl",
            "native-tls",
            "rustls",
            "gix-protocol",
            "gix-transport",
            "gix-transport-http",
            "gix-transport-http-client",
        ]);

        let mut violations = Vec::new();
        for crate_name in localstatic_crates {
            let root_id = ids_by_name.get(crate_name).expect("local crate present");
            let mut seen = BTreeSet::new();
            let mut stack = vec![root_id.clone()];
            while let Some(id) = stack.pop() {
                if !seen.insert(id.clone()) {
                    continue;
                }
                let name = names_by_id.get(&id).expect("package name");
                if denied.contains(name.as_str()) {
                    violations.push(format!("{crate_name} reaches {name}"));
                }
                if let Some(deps) = normal_edges.get(&id) {
                    stack.extend(deps.iter().cloned());
                }
            }
        }

        assert!(
            violations.is_empty(),
            "LocalStatic network boundary violated: {}",
            violations.join(", ")
        );
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

    fn publishable_key_findings(result: &ScanResult) -> Vec<&Finding> {
        result
            .findings
            .iter()
            .filter(|finding| {
                matches!(
                    finding.evidence,
                    Evidence::SupabaseKey {
                        class: SupabaseKeyClass::PublishableNew,
                        ..
                    }
                )
            })
            .collect()
    }

    #[cfg(feature = "network")]
    fn public_key_finding_at(id: &str, path: &str, location_class: LocationClass) -> Finding {
        let mut finding = public_key_finding();
        finding.id = FindingId(id.to_owned());
        finding.locations = vec![Location {
            path: RepoPath(path.to_owned()),
            span: Some(Span {
                line: 1,
                col_start: 1,
                col_end: 49,
            }),
            provenance: Provenance::WorkingTree,
            additional_provenance: Vec::new(),
            location_class,
        }];
        finding
    }

    #[cfg(feature = "network")]
    fn publishable_candidate(path: &str, location_class: LocationClass) -> SecretCandidate {
        SecretCandidate {
            rule_id: vibescan_types::RuleId("supabase-publishable-key".to_owned()),
            kind: vibescan_types::CandidateKind::PossibleSupabaseKey,
            raw_match: b"sb_publishable_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789".to_vec(),
            entropy: 4.0,
            unit_ref: UnitRef {
                path: RepoPath(path.to_owned()),
                provenance: Provenance::WorkingTree,
                additional_provenance: Vec::new(),
                location_class,
            },
            span: Span {
                line: 1,
                col_start: 1,
                col_end: 55,
            },
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
