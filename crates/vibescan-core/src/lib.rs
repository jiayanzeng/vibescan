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
#[cfg(feature = "registry")]
use vibescan_registry::{RegistryCheckInput, ReqwestRegistrySource, run_registry_checks};
use vibescan_report::{ReportFormat, TtyStyle, render, render_tty};
use vibescan_secrets::Detector;
use vibescan_supabase::SupabaseClassifier;
#[cfg(feature = "network")]
use vibescan_supabase::{Tier0RlsProbeInput, Tier1IntrospectInput};
#[cfg(feature = "network")]
use vibescan_supabase::{introspect_tier1, probe_tier0_read, project_from_db_url};
#[cfg(feature = "network")]
use vibescan_types::RepoPath;
use vibescan_types::{
    Category, Confidence, ContentId, CorrelationRuleId, Ecosystem, Evidence, Finding, FindingId,
    HistoryScope, Location, LocationClass, NetworkActionAudit, NetworkScope, ParsedDependency,
    Provenance, RlsExposure, ScanResult, ScanScope, ScanStats, ScannableUnit, ScopeWarning,
    SecretCandidate, SecretFingerprint, SupabaseKeyClass, SupabaseProject, UnitRef,
};

pub use vibescan_types::Severity;

/// Current crate version used in scan results.
pub const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Env-only source for the Tier 1 database connection string.
pub const TIER1_DB_URL_ENV: &str = "VIBESCAN_SUPABASE_DB_URL";

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
    pub custom_rules_path: Option<PathBuf>,
    pub tier0_read_probe: bool,
    pub tier1_introspection: bool,
    pub registry_checks: bool,
    pub registry_newcomer: bool,
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
            custom_rules_path: None,
            tier0_read_probe: false,
            tier1_introspection: false,
            registry_checks: false,
            registry_newcomer: false,
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
            config.apply_file_config(parsed, &config_root)?;
        }

        Ok(config)
    }

    fn apply_file_config(
        &mut self,
        parsed: FileConfig,
        config_root: &Path,
    ) -> Result<(), CoreError> {
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
            if let Some(value) = scan.severity_gate {
                self.severity_gate = parse_severity(&value)
                    .ok_or_else(|| CoreError::InvalidSeverity(value.clone()))?;
            }
        }

        if let Some(ignore) = parsed.ignore {
            self.path_allowlists.extend(ignore.paths);
        }

        if let Some(baseline) = parsed.baseline {
            self.baseline_path = baseline
                .path
                .map(PathBuf::from)
                .map(|path| resolve_path(config_root, path));
        }

        if let Some(rules) = parsed.rules {
            self.custom_rules_path = rules
                .path
                .map(PathBuf::from)
                .map(|path| resolve_path(config_root, path));
        }

        // Repository config may disable Network work, but only an explicit
        // runtime action may enable it. A configured `true` is intentionally
        // inert until the CLI or another caller confirms the action.
        if let Some(network) = parsed.network {
            if network.tier0_read_probe == Some(false) {
                self.tier0_read_probe = false;
            }
            if network.tier1_introspection == Some(false) {
                self.tier1_introspection = false;
            }
            if network.registry_checks == Some(false) {
                self.registry_checks = false;
            }
            if network.registry_newcomer == Some(false) {
                self.registry_newcomer = false;
            }
        }

        Ok(())
    }
}

/// Resolve a CLI/config path relative to the discovered target repository.
pub fn resolve_repository_path(
    target: impl AsRef<Path>,
    path: impl AsRef<Path>,
) -> Result<PathBuf, CoreError> {
    let path = path.as_ref();
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    let root = discover_repository_root(target.as_ref()).map_err(CoreError::Git)?;
    Ok(root.join(path))
}

fn resolve_path(root: &Path, path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        root.join(path)
    }
}

#[derive(Debug, Deserialize)]
struct FileConfig {
    scan: Option<ScanSection>,
    ignore: Option<IgnoreSection>,
    baseline: Option<BaselineSection>,
    rules: Option<RulesSection>,
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
struct RulesSection {
    path: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NetworkSection {
    tier0_read_probe: Option<bool>,
    tier1_introspection: Option<bool>,
    registry_checks: Option<bool>,
    registry_newcomer: Option<bool>,
}

/// Run the offline scan pipeline.
pub fn scan(target: impl AsRef<Path>, config: ScanConfig) -> Result<ScanResult, CoreError> {
    if config.registry_checks && !cfg!(feature = "registry") {
        return Err(CoreError::RegistryFeatureUnavailable);
    }
    if config.registry_newcomer {
        return Err(CoreError::RegistryNewcomerUnavailable);
    }

    let started = Instant::now();
    let started_at = Timestamp::now().to_string();
    let target_path = target.as_ref();
    let baseline = Baseline::load(config.baseline_path.as_deref())?;
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
    let detector = load_detector(config.custom_rules_path.as_deref())?;
    let candidates = detector.detect_units(&units);

    let classifier = SupabaseClassifier::new();
    let unit_content = units
        .iter()
        .map(|unit| (&unit.content_id, unit.content.as_slice()))
        .collect::<BTreeMap<_, _>>();
    let classified_keys = candidates
        .iter()
        .filter_map(|candidate| {
            classifier
                .classify_candidate_with_unit_content(
                    candidate,
                    unit_content.get(&candidate.unit_ref.content_id).copied(),
                )
                .map(|finding| {
                    let project = project_from_key_finding(&finding).cloned();
                    ClassifiedKeyFact {
                        finding,
                        raw_key: candidate.raw_match.clone(),
                        sources: vec![ClassifiedKeySource {
                            unit_ref: candidate.unit_ref.clone(),
                            project,
                        }],
                    }
                })
        })
        .collect::<Vec<_>>();
    let classified_keys = coalesce_classified_key_facts(classified_keys);
    let mut findings = classified_keys
        .iter()
        .map(|fact| fact.finding.clone())
        .collect::<Vec<_>>();
    #[cfg(any(feature = "network", feature = "registry"))]
    let mut network_actions = Vec::<NetworkActionAudit>::new();
    #[cfg(not(any(feature = "network", feature = "registry")))]
    let network_actions = Vec::<NetworkActionAudit>::new();
    #[cfg(feature = "registry")]
    let mut registry_name_egress = Vec::new();
    #[cfg(not(feature = "registry"))]
    let registry_name_egress = Vec::new();
    findings.extend(resolve_generic_candidates(&candidates));
    let dependency_scan = scan_dependency_integrity(&walk.repo_root)?;
    #[cfg(feature = "registry")]
    let registry_dependencies = registry_eligible_dependencies(
        &dependency_scan.findings,
        dependency_scan.dependencies.clone(),
    );
    findings.extend(dependency_scan.findings);

    if config.registry_checks {
        #[cfg(feature = "registry")]
        {
            let source = ReqwestRegistrySource::new().map_err(CoreError::Registry)?;
            let mut output = run_registry_checks(
                &source,
                &RegistryCheckInput {
                    dependencies: registry_dependencies,
                    private_registry_ecosystems: private_registry_ecosystems(&walk.repo_root)?,
                },
            )
            .map_err(CoreError::Registry)?;
            findings.append(&mut output.findings);
            network_actions.append(&mut output.actions);
            registry_name_egress.append(&mut output.name_egress);
            warnings.extend(
                output
                    .warnings
                    .into_iter()
                    .map(|warning| ScopeWarning::Other {
                        message: warning.message(),
                    }),
            );
        }
    }

    #[cfg(feature = "network")]
    let network_associations = (config.tier0_read_probe || config.tier1_introspection).then(|| {
        let api_references = harvest_api_references(&units);
        associate_api_references(&api_references, &classified_keys)
    });

    if config.tier0_read_probe {
        #[cfg(feature = "network")]
        {
            let associations = network_associations
                .as_ref()
                .expect("network associations computed for Tier 0");
            warnings.extend(associations.warnings.iter().cloned());
            for input in tier0_probe_inputs(&classified_keys, &associations.tables_by_project) {
                match probe_tier0_read(&input) {
                    Ok(mut output) => {
                        findings.append(&mut output.findings);
                        network_actions.append(&mut output.actions);
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

    if config.tier1_introspection {
        #[cfg(feature = "network")]
        {
            let db_url =
                std::env::var(TIER1_DB_URL_ENV).map_err(|_| CoreError::MissingTier1Credential)?;
            let project = project_from_db_url(&db_url).map_err(CoreError::Tier1)?;
            let associations = network_associations
                .as_ref()
                .expect("network associations computed for Tier 1");
            let normalized_project = normalized_project_url(&project.url);
            let input = Tier1IntrospectInput {
                credential_location: tier1_credential_location(),
                candidate_tables: associations
                    .tables_by_project
                    .get(&normalized_project)
                    .cloned()
                    .unwrap_or_default(),
                project,
                db_url,
            };
            let mut output = introspect_tier1(&input).map_err(CoreError::Tier1)?;
            findings.append(&mut output.findings);
            network_actions.append(&mut output.actions);
            warnings.extend(
                output
                    .warnings
                    .into_iter()
                    .map(|warning| ScopeWarning::Other {
                        message: warning.message(),
                    }),
            );
        }
        #[cfg(not(feature = "network"))]
        warnings.push(ScopeWarning::Other {
            message: "Tier 1 RLS introspection requested but this binary was built without the network feature".to_owned(),
        });
    }

    let mut findings = coalesce_findings(findings);
    findings.extend(correlate_findings(&findings));

    let mut findings = dedup_findings(findings);
    findings.retain(|finding| !baseline.contains(&finding.id));
    absorb_correlated_constituents(&mut findings);
    sort_findings(&mut findings);

    let stats = compute_stats(&findings, &warnings, walk.stats, walk.history.truncated);
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
                enabled: ((config.tier0_read_probe || config.tier1_introspection)
                    && cfg!(feature = "network"))
                    || (config.registry_checks && cfg!(feature = "registry")),
                tier0_read_probe: config.tier0_read_probe && cfg!(feature = "network"),
                tier1_introspection: config.tier1_introspection && cfg!(feature = "network"),
                registry_checks: config.registry_checks && cfg!(feature = "registry"),
                registry_newcomer: false,
                registry_name_egress,
                actions: network_actions,
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
            || finding.locations.iter().any(location_has_commit))
    });

    public_keys
        .flat_map(|key_finding| {
            findings.iter().filter_map(move |rls_finding| {
                let same_project =
                    project_url_from_key(key_finding).zip(project_url_from_rls(rls_finding));
                if !matches!(
                    same_project,
                    Some((a, b)) if normalized_project_url(a) == normalized_project_url(b)
                ) {
                    return None;
                }
                let read_exposure = rls_read_exposure(rls_finding)?;

                let rule_id = CorrelationRuleId(rule.id.to_owned());
                let id = correlation_id(&rule_id, &[&key_finding.id, &rls_finding.id]);
                let mut locations = key_finding
                    .locations
                    .iter()
                    .cloned()
                    .chain(rls_finding.locations.iter().cloned())
                    .collect::<Vec<_>>();
                sort_locations(&mut locations);
                Some(Finding {
                    id,
                    category: Category::Correlation,
                    severity: Severity::Critical,
                    title: format!(
                        "Public Supabase key can read unprotected table {}",
                        read_exposure.table
                    ),
                    detail: "A browser-reachable Supabase public key is present and an API-exposed table on the same project is readable without additional authorization.".to_owned(),
                    locations,
                    evidence: Evidence::Correlation {
                        rule_id,
                        reproduction: Some(read_exposure.reproduction),
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
            ) && finding.locations.iter().any(location_has_commit)
        })
        .filter_map(|key_finding| {
            let key_project = project_url_from_key(key_finding)?;
            let related_rls = findings
                .iter()
                .filter(|finding| {
                    finding.category == Category::Rls
                        && project_url_from_rls(finding).is_some_and(|project| {
                            normalized_project_url(project) == normalized_project_url(key_project)
                        })
                })
                .map(|finding| finding.id.clone())
                .collect::<Vec<_>>();

            if related_rls.is_empty() {
                return None;
            }

            let mut related = vec![key_finding.id.clone()];
            related.extend(related_rls);
            related.sort();
            related.dedup();
            let rule_id = CorrelationRuleId(rule.id.to_owned());
            let related_refs = related.iter().collect::<Vec<_>>();
            let mut locations = key_finding.locations.clone();
            sort_locations(&mut locations);
            Some(Finding {
                id: correlation_id(&rule_id, &related_refs),
                category: Category::Correlation,
                severity: Severity::Critical,
                title: "Exposed elevated Supabase key bypasses RLS".to_owned(),
                detail: "An elevated Supabase key is committed for this project. RLS findings on the same project are moot until this key is rotated because elevated keys bypass RLS entirely.".to_owned(),
                locations,
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

struct ClassifiedKeyFact {
    finding: Finding,
    #[cfg_attr(not(feature = "network"), allow(dead_code))]
    raw_key: Vec<u8>,
    sources: Vec<ClassifiedKeySource>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ClassifiedKeySource {
    unit_ref: UnitRef,
    project: Option<SupabaseProject>,
}

fn coalesce_classified_key_facts(facts: Vec<ClassifiedKeyFact>) -> Vec<ClassifiedKeyFact> {
    let mut groups = BTreeMap::<FindingCoalesceBaseKey, Vec<ClassifiedKeyFact>>::new();
    for fact in facts {
        let key = coalesce_key(&fact.finding).expect("classified key has a coalesce key");
        groups.entry(key.base).or_default().push(fact);
    }

    groups
        .into_iter()
        .flat_map(|(base, facts)| coalesce_classified_key_group(base, facts))
        .collect()
}

fn coalesce_classified_key_group(
    base: FindingCoalesceBaseKey,
    facts: Vec<ClassifiedKeyFact>,
) -> Vec<ClassifiedKeyFact> {
    let mut known = BTreeMap::<String, (SupabaseProject, Vec<ClassifiedKeyFact>)>::new();
    let mut projectless = Vec::new();

    for fact in facts {
        if let Some(project) = project_from_key_finding(&fact.finding).cloned() {
            let normalized = normalized_project_url(&project.url);
            known
                .entry(normalized)
                .or_insert_with(|| (project, Vec::new()))
                .1
                .push(fact);
        } else {
            projectless.push(fact);
        }
    }

    if known.len() == 1 {
        let (_, (project, mut facts)) = known.pop_first().expect("one known project");
        facts.append(&mut projectless);
        return vec![merge_classified_key_group(base, Some(project), facts)];
    }

    let mut output = known
        .into_values()
        .map(|(project, facts)| merge_classified_key_group(base.clone(), Some(project), facts))
        .collect::<Vec<_>>();
    if !projectless.is_empty() {
        output.push(merge_classified_key_group(base, None, projectless));
    }
    output
}

fn merge_classified_key_group(
    base: FindingCoalesceBaseKey,
    project: Option<SupabaseProject>,
    mut facts: Vec<ClassifiedKeyFact>,
) -> ClassifiedKeyFact {
    facts.sort_by(|left, right| left.finding.id.cmp(&right.finding.id));
    let mut merged = facts.remove(0);
    sort_locations(&mut merged.finding.locations);
    for fact in facts {
        merge_findings(&mut merged.finding, fact.finding);
        merged.sources.extend(fact.sources);
    }
    merged.sources.sort_by(|left, right| {
        left.unit_ref
            .content_id
            .cmp(&right.unit_ref.content_id)
            .then_with(|| left.unit_ref.locations.cmp(&right.unit_ref.locations))
            .then_with(|| {
                source_project_key(left.project.as_ref())
                    .cmp(&source_project_key(right.project.as_ref()))
            })
    });
    merged.sources.dedup();
    set_key_project(&mut merged.finding, project.as_ref());
    merged.finding.id = coalesced_finding_id(&FindingCoalesceKey {
        base,
        project_url: project
            .as_ref()
            .map(|project| normalized_project_url(&project.url)),
    });
    merged
}

#[cfg(feature = "network")]
fn tier0_probe_inputs(
    classifications: &[ClassifiedKeyFact],
    tables_by_project: &BTreeMap<String, BTreeSet<String>>,
) -> Vec<Tier0RlsProbeInput> {
    let mut by_project = BTreeMap::<String, Tier0RlsProbeInput>::new();
    for fact in classifications {
        let Some(input) = (|| {
            let Evidence::SupabaseKey {
                class: SupabaseKeyClass::PublishableNew | SupabaseKeyClass::AnonLegacy,
                project: Some(project),
                ..
            } = &fact.finding.evidence
            else {
                return None;
            };
            let public_key = std::str::from_utf8(&fact.raw_key).ok()?.to_owned();
            let key_location = best_key_location(&fact.finding.locations)?.clone();
            let normalized_project = normalized_project_url(&project.url);
            Some(Tier0RlsProbeInput {
                project: project.clone(),
                public_key,
                key_location,
                candidate_tables: tables_by_project
                    .get(&normalized_project)
                    .cloned()
                    .unwrap_or_default(),
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

#[cfg(feature = "network")]
fn best_key_location(locations: &[Location]) -> Option<&Location> {
    locations.iter().max_by(|left, right| {
        location_class_rank(left.location_class)
            .cmp(&location_class_rank(right.location_class))
            .then_with(|| right.path.cmp(&left.path))
            .then_with(|| span_key(&right.span).cmp(&span_key(&left.span)))
    })
}

#[cfg(feature = "network")]
fn tier1_credential_location() -> Location {
    Location {
        path: RepoPath("<environment:VIBESCAN_SUPABASE_DB_URL>".to_owned()),
        span: None,
        provenance: Provenance::WorkingTree,
        additional_provenance: Vec::new(),
        location_class: LocationClass::ServerOnly,
    }
}

#[cfg_attr(not(feature = "network"), allow(dead_code))]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum ApiReferenceKind {
    Table,
    Rpc,
}

#[cfg_attr(not(feature = "network"), allow(dead_code))]
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct SourceScope(String);

#[cfg_attr(not(feature = "network"), allow(dead_code))]
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ApiReference {
    kind: ApiReferenceKind,
    content_id: ContentId,
    source_scope: SourceScope,
    name: String,
}

#[cfg_attr(not(feature = "network"), allow(dead_code))]
struct ApiReferenceAssociations {
    tables_by_project: BTreeMap<String, BTreeSet<String>>,
    warnings: Vec<ScopeWarning>,
}

#[cfg_attr(not(feature = "network"), allow(dead_code))]
fn harvest_api_references(units: &[ScannableUnit]) -> Vec<ApiReference> {
    let mut references = BTreeSet::new();
    for unit in units {
        let Ok(content) = std::str::from_utf8(&unit.content) else {
            continue;
        };
        let mut tables = BTreeSet::new();
        let mut rpcs = BTreeSet::new();
        harvest_quoted_method_names(content, ".from", &mut tables);
        harvest_quoted_method_names(content, ".rpc", &mut rpcs);
        harvest_rest_paths(content, &mut tables);
        let scopes = unit
            .locations
            .iter()
            .map(|location| source_scope(&location.path.0))
            .collect::<BTreeSet<_>>();
        for scope in scopes {
            for name in &tables {
                references.insert(ApiReference {
                    kind: ApiReferenceKind::Table,
                    content_id: unit.content_id.clone(),
                    source_scope: scope.clone(),
                    name: name.clone(),
                });
            }
            for name in &rpcs {
                references.insert(ApiReference {
                    kind: ApiReferenceKind::Rpc,
                    content_id: unit.content_id.clone(),
                    source_scope: scope.clone(),
                    name: name.clone(),
                });
            }
        }
    }
    references.into_iter().collect()
}

#[cfg_attr(not(feature = "network"), allow(dead_code))]
fn source_scope(path: &str) -> SourceScope {
    let segments = path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    for (index, segment) in segments.iter().enumerate() {
        if matches!(*segment, "apps" | "packages" | "services") && index + 1 < segments.len() {
            return SourceScope(segments[..=index + 1].join("/"));
        }
    }
    SourceScope(".".to_owned())
}

#[cfg_attr(not(feature = "network"), allow(dead_code))]
fn associate_api_references(
    references: &[ApiReference],
    facts: &[ClassifiedKeyFact],
) -> ApiReferenceAssociations {
    let mut projects_by_content = BTreeMap::<ContentId, BTreeSet<String>>::new();
    let mut projects_by_scope = BTreeMap::<SourceScope, BTreeSet<String>>::new();
    for source in facts.iter().flat_map(|fact| &fact.sources) {
        let Some(project) = &source.project else {
            continue;
        };
        let project_url = normalized_project_url(&project.url);
        projects_by_content
            .entry(source.unit_ref.content_id.clone())
            .or_default()
            .insert(project_url.clone());
        for scope in source
            .unit_ref
            .locations
            .iter()
            .map(|location| source_scope(&location.path.0))
        {
            projects_by_scope
                .entry(scope)
                .or_default()
                .insert(project_url.clone());
        }
    }

    let mut tables_by_project = BTreeMap::<String, BTreeSet<String>>::new();
    let mut warning_messages = BTreeSet::new();
    for reference in references {
        if reference.kind == ApiReferenceKind::Rpc {
            continue;
        }
        match associated_project(reference, &projects_by_content, &projects_by_scope) {
            Ok(project_url) => {
                tables_by_project
                    .entry(project_url)
                    .or_default()
                    .insert(reference.name.clone());
            }
            Err(reason) => {
                warning_messages.insert(format!(
                    "Tier 0 skipped table reference {} from scope {}: {reason}",
                    reference.name, reference.source_scope.0
                ));
            }
        }
    }

    ApiReferenceAssociations {
        tables_by_project,
        warnings: warning_messages
            .into_iter()
            .map(|message| ScopeWarning::Other { message })
            .collect(),
    }
}

#[cfg_attr(not(feature = "network"), allow(dead_code))]
fn associated_project(
    reference: &ApiReference,
    projects_by_content: &BTreeMap<ContentId, BTreeSet<String>>,
    projects_by_scope: &BTreeMap<SourceScope, BTreeSet<String>>,
) -> Result<String, &'static str> {
    if let Some(projects) = projects_by_content.get(&reference.content_id) {
        return unique_project(projects);
    }
    projects_by_scope
        .get(&reference.source_scope)
        .map_or(Err("no associated Supabase project"), unique_project)
}

#[cfg_attr(not(feature = "network"), allow(dead_code))]
fn unique_project(projects: &BTreeSet<String>) -> Result<String, &'static str> {
    if projects.len() == 1 {
        Ok(projects.first().expect("one project").clone())
    } else {
        Err("ambiguous Supabase project association")
    }
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
    let locations = candidate
        .unit_ref
        .locations
        .iter()
        .map(|location| Location {
            path: location.path.clone(),
            span: Some(candidate.span),
            provenance: location.provenance.clone(),
            additional_provenance: location.additional_provenance.clone(),
            location_class: location.location_class,
        })
        .collect::<Vec<_>>();
    let location = locations
        .first()
        .expect("candidates retain a source location");
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
        locations,
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

#[derive(Debug, Default)]
struct DependencyScanOutput {
    findings: Vec<Finding>,
    dependencies: Vec<ParsedDependency>,
}

/// Parse registry-shaped dependencies from manifests under the discovered
/// repository root without performing any egress.
pub fn parse_dependencies(target: impl AsRef<Path>) -> Result<Vec<ParsedDependency>, CoreError> {
    let repo_root = discover_repository_root(target.as_ref()).map_err(CoreError::Git)?;
    Ok(scan_dependency_integrity(&repo_root)?.dependencies)
}

fn scan_dependency_integrity(repo_root: &Path) -> Result<DependencyScanOutput, CoreError> {
    let mut findings = Vec::new();
    let mut dependencies = Vec::new();
    for manifest in collect_manifest_paths(repo_root)? {
        match manifest.kind {
            DependencyManifestKind::PackageJson => {
                scan_package_json(repo_root, &manifest.path, &mut findings, &mut dependencies)?;
            }
            DependencyManifestKind::PackageLock => {
                scan_package_lock(repo_root, &manifest.path, &mut findings, &mut dependencies)?;
            }
            DependencyManifestKind::Pyproject => {
                scan_pyproject(repo_root, &manifest.path, &mut findings, &mut dependencies)?;
            }
            DependencyManifestKind::RequirementsTxt => {
                scan_requirements_txt(repo_root, &manifest.path, &mut findings, &mut dependencies)?;
            }
            DependencyManifestKind::PythonLock => {
                scan_python_lock(repo_root, &manifest.path, &mut dependencies)?;
            }
        }
    }
    dependencies.sort();
    dependencies.dedup();
    Ok(DependencyScanOutput {
        findings,
        dependencies,
    })
}

#[cfg(feature = "registry")]
fn registry_eligible_dependencies(
    structural_findings: &[Finding],
    dependencies: Vec<ParsedDependency>,
) -> Vec<ParsedDependency> {
    let rejected = structural_findings
        .iter()
        .filter_map(|finding| match &finding.evidence {
            Evidence::Dependency {
                package,
                manifest_path,
                reason:
                    vibescan_types::DependencyIntegrityReason::InvalidPackageName
                    | vibescan_types::DependencyIntegrityReason::EmptyVersionSpecifier,
            } => Some((package.clone(), manifest_path.clone())),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    dependencies
        .into_iter()
        .filter(|dependency| {
            !rejected.contains(&(dependency.name.clone(), dependency.manifest_path.clone()))
        })
        .collect()
}

#[cfg(feature = "registry")]
fn private_registry_ecosystems(repo_root: &Path) -> Result<BTreeSet<Ecosystem>, CoreError> {
    let mut ecosystems = BTreeSet::new();
    if std::env::var("NPM_CONFIG_REGISTRY").is_ok_and(|value| npm_registry_is_alternate(&value)) {
        ecosystems.insert(Ecosystem::Npm);
    }
    if std::env::var("PIP_INDEX_URL").is_ok_and(|value| python_registry_is_alternate(&value))
        || std::env::var("PIP_EXTRA_INDEX_URL").is_ok_and(|value| !value.trim().is_empty())
        || std::env::var("UV_INDEX_URL").is_ok_and(|value| python_registry_is_alternate(&value))
    {
        ecosystems.insert(Ecosystem::PyPi);
    }
    let npmrc = repo_root.join(".npmrc");
    if let Ok(content) = fs::read_to_string(&npmrc) {
        if content.lines().any(npmrc_line_is_alternate) {
            ecosystems.insert(Ecosystem::Npm);
        }
    }

    let pip_conf = repo_root.join("pip.conf");
    if fs::read_to_string(&pip_conf)
        .is_ok_and(|content| content.lines().any(is_python_index_configuration))
    {
        ecosystems.insert(Ecosystem::PyPi);
    }

    for manifest in collect_manifest_paths(repo_root)? {
        match manifest.kind {
            DependencyManifestKind::RequirementsTxt => {
                let content = fs::read_to_string(&manifest.path).map_err(CoreError::Io)?;
                if content.lines().any(is_python_index_configuration) {
                    ecosystems.insert(Ecosystem::PyPi);
                }
            }
            DependencyManifestKind::Pyproject => {
                let content = fs::read_to_string(&manifest.path).map_err(CoreError::Io)?;
                let value = toml::from_str::<toml::Value>(&content).map_err(CoreError::Toml)?;
                if pyproject_has_alternate_index(&value) {
                    ecosystems.insert(Ecosystem::PyPi);
                }
            }
            DependencyManifestKind::PackageJson => {
                if let Some(parent) = manifest.path.parent() {
                    if fs::read_to_string(parent.join(".npmrc"))
                        .is_ok_and(|content| content.lines().any(npmrc_line_is_alternate))
                    {
                        ecosystems.insert(Ecosystem::Npm);
                    }
                }
            }
            DependencyManifestKind::PackageLock | DependencyManifestKind::PythonLock => {}
        }
    }
    Ok(ecosystems)
}

#[cfg(feature = "registry")]
fn npmrc_line_is_alternate(line: &str) -> bool {
    line.trim()
        .strip_prefix("registry=")
        .is_some_and(npm_registry_is_alternate)
}

#[cfg(feature = "registry")]
fn npm_registry_is_alternate(value: &str) -> bool {
    let normalized = value.trim().trim_end_matches('/');
    normalized != "https://registry.npmjs.org" && normalized != "http://registry.npmjs.org"
}

#[cfg(feature = "registry")]
fn python_registry_is_alternate(value: &str) -> bool {
    let normalized = value.trim().trim_end_matches('/');
    normalized != "https://pypi.org/simple" && normalized != "http://pypi.org/simple"
}

#[cfg(feature = "registry")]
fn is_python_index_configuration(line: &str) -> bool {
    let line = line.trim();
    line.starts_with("--index-url")
        || line.starts_with("--extra-index-url")
        || line.starts_with("index-url")
        || line.starts_with("extra-index-url")
}

#[cfg(feature = "registry")]
fn pyproject_has_alternate_index(value: &toml::Value) -> bool {
    value
        .get("tool")
        .and_then(|tool| tool.get("poetry"))
        .and_then(|poetry| poetry.get("source"))
        .is_some_and(|source| source.as_array().is_some_and(|items| !items.is_empty()))
        || value
            .get("tool")
            .and_then(|tool| tool.get("uv"))
            .and_then(|uv| uv.get("index"))
            .is_some()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DependencyManifestKind {
    PackageJson,
    PackageLock,
    Pyproject,
    RequirementsTxt,
    PythonLock,
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
        Some("poetry.lock" | "uv.lock") => Some(DependencyManifestKind::PythonLock),
        _ => None,
    }
}

fn scan_package_json(
    repo_root: &Path,
    manifest_path: &Path,
    findings: &mut Vec<Finding>,
    dependencies: &mut Vec<ParsedDependency>,
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
                let version_req = npm_version_req(version);
                dependencies.push(parsed_dependency(
                    repo_root,
                    manifest_path,
                    name,
                    version_req,
                    Ecosystem::Npm,
                    name.starts_with('@'),
                ));
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
    dependencies: &mut Vec<ParsedDependency>,
) -> Result<(), CoreError> {
    let value = read_json_manifest(manifest_path)?;
    let packages = value.get("packages").and_then(serde_json::Value::as_object);
    if packages.is_none() {
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
                dependencies.push(parsed_dependency(
                    repo_root,
                    manifest_path,
                    name,
                    npm_version_req(metadata),
                    Ecosystem::Npm,
                    name.starts_with('@'),
                ));
            }
        }
    }
    if let Some(packages) = packages {
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
            dependencies.push(parsed_dependency(
                repo_root,
                manifest_path,
                name,
                npm_version_req(metadata),
                Ecosystem::Npm,
                name.starts_with('@'),
            ));
        }
    }
    Ok(())
}

fn scan_python_lock(
    repo_root: &Path,
    manifest_path: &Path,
    dependencies: &mut Vec<ParsedDependency>,
) -> Result<(), CoreError> {
    let content = fs::read_to_string(manifest_path).map_err(CoreError::Io)?;
    let value = toml::from_str::<toml::Value>(&content).map_err(CoreError::Toml)?;
    if let Some(packages) = value.get("package").and_then(toml::Value::as_array) {
        for package in packages {
            let Some(name) = package.get("name").and_then(toml::Value::as_str) else {
                continue;
            };
            let Some(version) = package.get("version").and_then(toml::Value::as_str) else {
                continue;
            };
            dependencies.push(parsed_dependency(
                repo_root,
                manifest_path,
                name,
                version,
                Ecosystem::PyPi,
                false,
            ));
        }
    }
    Ok(())
}

fn scan_pyproject(
    repo_root: &Path,
    manifest_path: &Path,
    findings: &mut Vec<Finding>,
    dependencies: &mut Vec<ParsedDependency>,
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
                dependencies,
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
            dependencies.push(parsed_dependency(
                repo_root,
                manifest_path,
                name,
                version.as_str().unwrap_or_default(),
                Ecosystem::PyPi,
                false,
            ));
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
    dependencies: &mut Vec<ParsedDependency>,
) -> Result<(), CoreError> {
    let content = fs::read_to_string(manifest_path).map_err(CoreError::Io)?;
    for line in content.lines() {
        check_python_requirement(
            repo_root,
            manifest_path,
            "requirements.txt",
            line,
            findings,
            dependencies,
        );
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
    dependencies: &mut Vec<ParsedDependency>,
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
    dependencies.push(parsed_dependency(
        repo_root,
        manifest_path,
        name,
        python_version_req(requirement, name),
        Ecosystem::PyPi,
        false,
    ));
}

fn npm_version_req(value: &serde_json::Value) -> &str {
    value
        .as_str()
        .or_else(|| value.get("version").and_then(serde_json::Value::as_str))
        .unwrap_or_default()
}

fn python_version_req<'a>(requirement: &'a str, name: &str) -> &'a str {
    requirement.get(name.len()..).unwrap_or_default().trim()
}

fn parsed_dependency(
    repo_root: &Path,
    manifest_path: &Path,
    name: &str,
    version_req: &str,
    ecosystem: Ecosystem,
    is_scoped: bool,
) -> ParsedDependency {
    ParsedDependency {
        name: name.to_owned(),
        version_req: version_req.to_owned(),
        ecosystem,
        manifest_path: vibescan_types::RepoPath(repo_relative_path(repo_root, manifest_path)),
        is_scoped,
    }
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
        Evidence::RlsProbe { project, .. } | Evidence::RlsPolicy { project, .. } => {
            Some(project.url.as_str())
        }
        _ => None,
    }
}

struct RlsReadExposure<'a> {
    table: &'a str,
    reproduction: String,
}

fn rls_read_exposure(finding: &Finding) -> Option<RlsReadExposure<'_>> {
    if finding.category != Category::Rls {
        return None;
    }

    match &finding.evidence {
        Evidence::RlsProbe {
            table,
            endpoint,
            observed_row_count,
            exposure: RlsExposure::Exposed,
            ..
        } => Some(RlsReadExposure {
            table,
            reproduction: format!(
                "{endpoint} returned {observed_row_count} row(s) to the public key"
            ),
        }),
        Evidence::RlsPolicy {
            table,
            exposure: RlsExposure::RlsDisabled,
            ..
        } => Some(RlsReadExposure {
            table,
            reproduction: format!("table {table} has RLS disabled"),
        }),
        Evidence::RlsPolicy {
            table,
            exposure: RlsExposure::PermissivePolicy,
            ..
        } => Some(RlsReadExposure {
            table,
            reproduction: format!("table {table} has permissive USING (true)"),
        }),
        // TODO(post-tier-e): reconsider SELECT-specific missing-policy evidence only if
        // catalog semantics establish read exposure rather than default-deny behavior.
        Evidence::RlsPolicy {
            exposure: RlsExposure::MissingOperationPolicy | RlsExposure::InferredWriteExposure,
            ..
        } => None,
        _ => None,
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct FindingCoalesceBaseKey {
    category: Category,
    rule_or_class: String,
    fingerprint: String,
    severity: Severity,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct FindingCoalesceKey {
    base: FindingCoalesceBaseKey,
    project_url: Option<String>,
}

fn coalesce_findings(findings: Vec<Finding>) -> Vec<Finding> {
    let mut groups = BTreeMap::<FindingCoalesceBaseKey, Vec<Finding>>::new();
    let mut passthrough = Vec::new();

    for finding in findings {
        let Some(key) = coalesce_key(&finding) else {
            passthrough.push(finding);
            continue;
        };
        groups.entry(key.base).or_default().push(finding);
    }

    for (base, findings) in groups {
        passthrough.extend(coalesce_finding_group(base, findings));
    }
    passthrough
}

fn coalesce_finding_group(base: FindingCoalesceBaseKey, findings: Vec<Finding>) -> Vec<Finding> {
    let mut known = BTreeMap::<String, (SupabaseProject, Vec<Finding>)>::new();
    let mut projectless = Vec::new();

    for finding in findings {
        if let Some(project) = project_from_key_finding(&finding).cloned() {
            let normalized = normalized_project_url(&project.url);
            known
                .entry(normalized)
                .or_insert_with(|| (project, Vec::new()))
                .1
                .push(finding);
        } else {
            projectless.push(finding);
        }
    }

    if known.len() == 1 {
        let (_, (project, mut findings)) = known.pop_first().expect("one known project");
        findings.append(&mut projectless);
        return vec![merge_finding_group(base, Some(project), findings)];
    }

    let mut output = known
        .into_values()
        .map(|(project, findings)| merge_finding_group(base.clone(), Some(project), findings))
        .collect::<Vec<_>>();
    if !projectless.is_empty() {
        output.push(merge_finding_group(base, None, projectless));
    }
    output
}

fn merge_finding_group(
    base: FindingCoalesceBaseKey,
    project: Option<SupabaseProject>,
    mut findings: Vec<Finding>,
) -> Finding {
    findings.sort_by(|left, right| left.id.cmp(&right.id));
    let mut merged = findings.remove(0);
    sort_locations(&mut merged.locations);
    for finding in findings {
        merge_findings(&mut merged, finding);
    }
    set_key_project(&mut merged, project.as_ref());
    let key = FindingCoalesceKey {
        base,
        project_url: project
            .as_ref()
            .map(|project| normalized_project_url(&project.url)),
    };
    merged.id = coalesced_finding_id(&key);
    merged
}

fn coalesce_key(finding: &Finding) -> Option<FindingCoalesceKey> {
    match &finding.evidence {
        Evidence::Secret { fingerprint, .. } => Some(FindingCoalesceKey {
            base: FindingCoalesceBaseKey {
                category: finding.category,
                rule_or_class: secret_rule_key(finding).to_owned(),
                fingerprint: fingerprint.0.clone(),
                severity: finding.severity,
            },
            project_url: None,
        }),
        Evidence::SupabaseKey {
            class,
            project,
            fingerprint,
            ..
        } => Some(FindingCoalesceKey {
            base: FindingCoalesceBaseKey {
                category: finding.category,
                rule_or_class: format!("supabase-key:{}", supabase_key_class_key(*class)),
                fingerprint: fingerprint.0.clone(),
                severity: finding.severity,
            },
            project_url: project
                .as_ref()
                .map(|project| normalized_project_url(&project.url)),
        }),
        _ => None,
    }
}

fn coalesced_finding_id(key: &FindingCoalesceKey) -> FindingId {
    let mut hasher = Sha256::new();
    hasher.update(category_key(key.base.category).as_bytes());
    hasher.update(b"\0");
    hasher.update(key.base.rule_or_class.as_bytes());
    hasher.update(b"\0");
    hasher.update(key.base.fingerprint.as_bytes());
    hasher.update(b"\0");
    hasher.update(key.project_url.as_deref().unwrap_or("<none>").as_bytes());
    hasher.update(b"\0");
    hasher.update(severity_key(key.base.severity).as_bytes());

    let prefix = if key.base.rule_or_class.starts_with("supabase-key:") {
        "supabase-key"
    } else {
        "secret"
    };
    FindingId(format!(
        "{prefix}-{}",
        hex::encode(&hasher.finalize()[..12])
    ))
}

fn project_from_key_finding(finding: &Finding) -> Option<&SupabaseProject> {
    match &finding.evidence {
        Evidence::SupabaseKey {
            project: Some(project),
            ..
        } => Some(project),
        _ => None,
    }
}

fn set_key_project(finding: &mut Finding, project: Option<&SupabaseProject>) {
    if let Evidence::SupabaseKey {
        project: finding_project,
        ..
    } = &mut finding.evidence
    {
        *finding_project = project.cloned();
        if let Some(project) = finding_project {
            project.url = normalized_project_url(&project.url);
        }
    }
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

fn source_project_key(project: Option<&SupabaseProject>) -> (String, Option<String>) {
    project.map_or_else(
        || (String::new(), None),
        |project| (normalized_project_url(&project.url), project.ref_id.clone()),
    )
}

fn max_location_class(locations: &[Location]) -> LocationClass {
    locations
        .iter()
        .map(|location| location.location_class)
        .max_by_key(|class| location_class_rank(*class))
        .unwrap_or(LocationClass::Unknown)
}

fn location_has_commit(location: &Location) -> bool {
    std::iter::once(&location.provenance)
        .chain(location.additional_provenance.iter())
        .any(|provenance| matches!(provenance, Provenance::Commit { .. }))
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

fn compute_stats(
    findings: &[Finding],
    warnings: &[ScopeWarning],
    collection: vibescan_git::WalkStats,
    truncated: bool,
) -> ScanStats {
    let mut stats = ScanStats {
        paths_walked: collection.paths_walked,
        blobs_read: collection.blobs_read,
        unique_contents: collection.unique_contents,
        units_materialized: collection.units_materialized,
        truncated,
        ..ScanStats::default()
    };
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

fn parse_severity(value: &str) -> Option<Severity> {
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
    fn load(path: Option<&Path>) -> Result<Self, CoreError> {
        let Some(path) = path else {
            return Ok(Self::default());
        };
        if !path.exists() {
            return Err(CoreError::ConfiguredPathMissing {
                kind: "baseline",
                path: path.to_path_buf(),
            });
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

fn load_detector(custom_rules_path: Option<&Path>) -> Result<Detector, CoreError> {
    let Some(path) = custom_rules_path else {
        return Detector::default_rules().map_err(CoreError::Detector);
    };
    if !path.exists() {
        return Err(CoreError::ConfiguredPathMissing {
            kind: "custom rules",
            path: path.to_path_buf(),
        });
    }
    let custom = fs::read_to_string(path).map_err(CoreError::Io)?;
    Detector::default_rules_with_custom_toml(&custom).map_err(CoreError::Detector)
}

/// Core pipeline error.
#[derive(Debug)]
pub enum CoreError {
    ConfiguredPathMissing {
        kind: &'static str,
        path: PathBuf,
    },
    Detector(vibescan_secrets::DetectorError),
    Git(vibescan_git::GitWalkError),
    Io(io::Error),
    Json(serde_json::Error),
    Toml(toml::de::Error),
    InvalidSeverity(String),
    MissingTier1Credential,
    Tier1(vibescan_supabase::IntrospectError),
    RegistryFeatureUnavailable,
    RegistryNewcomerUnavailable,
    #[cfg(feature = "registry")]
    Registry(vibescan_registry::RegistryError),
}

impl fmt::Display for CoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConfiguredPathMissing { kind, path } => {
                write!(
                    formatter,
                    "configured {kind} file does not exist: {}",
                    path.display()
                )
            }
            Self::Detector(source) => write!(formatter, "detector setup failed: {source}"),
            Self::Git(source) => write!(formatter, "git collection failed: {source}"),
            Self::Io(source) => write!(formatter, "filesystem operation failed: {source}"),
            Self::Json(source) => write!(formatter, "JSON parse failed: {source}"),
            Self::Toml(source) => write!(formatter, "configuration TOML parse failed: {source}"),
            Self::InvalidSeverity(value) => write!(
                formatter,
                "invalid configured severity {value:?}; expected critical, high, medium, low, or info"
            ),
            Self::MissingTier1Credential => formatter.write_str(
                "Tier 1 introspection requires VIBESCAN_SUPABASE_DB_URL in the local environment",
            ),
            Self::Tier1(source) => write!(formatter, "Tier 1 introspection failed: {source}"),
            Self::RegistryFeatureUnavailable => formatter.write_str(
                "registry checks were requested but this binary was built without registry support",
            ),
            Self::RegistryNewcomerUnavailable => formatter.write_str(
                "the registry newcomer heuristic is deferred and unavailable in Track F",
            ),
            #[cfg(feature = "registry")]
            Self::Registry(source) => write!(formatter, "registry checks failed: {source}"),
        }
    }
}

impl std::error::Error for CoreError {}

#[cfg(test)]
mod tests {
    use std::process::Command;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use vibescan_secrets::working_tree_unit;
    use vibescan_types::{
        ContentId, LocationClass, RepoPath, RlsExposure, Span, SupabaseProject, UnitLocation,
        UnitRef,
    };

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
    fn scan_stats_carries_history_truncation() {
        let repo = TestRepo::new();
        repo.git(["init"]);
        repo.git(["config", "user.email", "a@example.com"]);
        repo.git(["config", "user.name", "A"]);
        repo.write("src/app.ts", "export const version = 1;\n");
        repo.git(["add", "."]);
        repo.git(["commit", "-m", "one"]);
        repo.write("src/app.ts", "export const version = 2;\n");
        repo.git(["add", "."]);
        repo.git(["commit", "-m", "two"]);

        let result = scan(
            repo.path(),
            ScanConfig {
                include_working_tree: false,
                max_commits: Some(1),
                ..ScanConfig::default()
            },
        )
        .expect("budgeted scan succeeds");

        assert!(result.stats.truncated);
        assert!(result.stats.scan_budget_hit);
        assert!(matches!(
            result.scope.history,
            HistoryScope::Budgeted {
                scanned_commits: 1,
                truncated: true,
                ..
            }
        ));
    }

    #[test]
    fn collected_working_tree_units_feed_the_detector() {
        let repo = TestRepo::new();
        repo.git(["init"]);
        repo.write(
            "src/app.tsx",
            "const key = 'sb_publishable_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789';\n",
        );

        let output = collect_repository(
            repo.path(),
            WalkOptions {
                include_history: false,
                ..WalkOptions::default()
            },
        )
        .expect("repo collected");
        let detector = Detector::default_rules().expect("detector compiles");
        let candidates = detector.detect_units(&output.units);

        assert_eq!(output.units.len(), 1);
        assert!(
            candidates
                .iter()
                .any(|candidate| candidate.rule_id.0 == "supabase-publishable-key")
        );
    }

    #[test]
    fn detector_candidates_feed_supabase_classification() {
        let detector = Detector::default_rules().expect("rules compile");
        let unit = working_tree_unit(
            "src/app.tsx",
            "const key = 'sb_secret_0123456789abcdefghijklmnopqrstuvwxyzABCDEF';",
        );
        let candidates = detector.detect_unit(&unit);
        let findings = SupabaseClassifier::new().classify_candidates(&candidates);

        assert!(
            findings
                .iter()
                .any(|finding| finding.category == Category::SecretExposure)
        );
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
    fn project_enrichment_coalescing_is_independent_of_input_order() {
        let known = public_key_finding();
        let mut projectless = known.clone();
        projectless.id = FindingId("projectless".to_owned());
        projectless.locations[0].path = RepoPath("dist/config.js".to_owned());
        if let Evidence::SupabaseKey { project, .. } = &mut projectless.evidence {
            *project = None;
        }

        let forward = coalesce_findings(vec![known.clone(), projectless.clone()]);
        let reverse = coalesce_findings(vec![projectless, known]);

        assert_eq!(forward, reverse);
        assert_eq!(forward.len(), 1);
        assert!(matches!(
            forward[0].evidence,
            Evidence::SupabaseKey {
                project: Some(_),
                ..
            }
        ));
    }

    #[test]
    fn unambiguous_project_enrichment_intentionally_changes_baseline_identity() {
        let known = public_key_finding();
        let mut projectless = known.clone();
        projectless.id = FindingId("projectless".to_owned());
        projectless.locations[0].path = RepoPath("dist/config.js".to_owned());
        if let Evidence::SupabaseKey { project, .. } = &mut projectless.evidence {
            *project = None;
        }

        let projectless_id = coalesce_findings(vec![projectless.clone()])[0].id.clone();
        let known_id = coalesce_findings(vec![known.clone()])[0].id.clone();
        let enriched_id = coalesce_findings(vec![projectless, known])[0].id.clone();

        assert_ne!(projectless_id, enriched_id);
        assert_eq!(enriched_id, known_id);
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
    fn tier1_credential_location_is_the_env_source() {
        let location = tier1_credential_location();

        assert_eq!(
            location.path,
            RepoPath("<environment:VIBESCAN_SUPABASE_DB_URL>".to_owned())
        );
        assert_eq!(location.provenance, Provenance::WorkingTree);
        assert_eq!(location.location_class, LocationClass::ServerOnly);
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
        let classifications = coalesce_classified_key_facts(vec![
            classified_key_fact(&server_candidate, server_finding),
            classified_key_fact(&client_candidate, client_finding),
        ]);
        let candidate_tables = BTreeSet::from(["profiles".to_owned()]);
        let tables_by_project = BTreeMap::from([(
            "https://abcdefghijklmnopqrst.supabase.co".to_owned(),
            candidate_tables.clone(),
        )]);

        let inputs = tier0_probe_inputs(&classifications, &tables_by_project);

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
    fn coalesced_projectless_client_copy_drives_known_project_probe() {
        let server_candidate =
            publishable_candidate("apps/web/.env.local", LocationClass::ServerOnly);
        let client_candidate = publishable_candidate(
            "apps/web/.next/static/chunks/x.js",
            LocationClass::ClientReachable,
        );
        let server_finding = public_key_finding_at(
            "server-key",
            "apps/web/.env.local",
            LocationClass::ServerOnly,
        );
        let mut client_finding = public_key_finding_at(
            "client-key",
            "apps/web/.next/static/chunks/x.js",
            LocationClass::ClientReachable,
        );
        if let Evidence::SupabaseKey { project, .. } = &mut client_finding.evidence {
            *project = None;
        }

        let facts = coalesce_classified_key_facts(vec![
            classified_key_fact(&server_candidate, server_finding),
            classified_key_fact(&client_candidate, client_finding),
        ]);
        let tables_by_project = BTreeMap::from([(
            "https://abcdefghijklmnopqrst.supabase.co".to_owned(),
            BTreeSet::from(["profiles".to_owned()]),
        )]);
        let inputs = tier0_probe_inputs(&facts, &tables_by_project);

        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].finding.locations.len(), 2);
        assert_eq!(facts[0].sources.len(), 2);
        assert_eq!(inputs.len(), 1);
        assert_eq!(
            inputs[0].project.url,
            "https://abcdefghijklmnopqrst.supabase.co"
        );
        assert_eq!(
            inputs[0].key_location.path.0,
            "apps/web/.next/static/chunks/x.js"
        );
    }

    #[cfg(feature = "network")]
    #[test]
    fn tier0_probe_inputs_keep_harvested_tables_project_local() {
        let mut candidate_a = publishable_candidate(
            "apps/a/.next/static/chunks/a.js",
            LocationClass::ClientReachable,
        );
        candidate_a.unit_ref.content_id = ContentId([10; 32]);
        let mut candidate_b = publishable_candidate(
            "apps/b/.next/static/chunks/b.js",
            LocationClass::ClientReachable,
        );
        candidate_b.unit_ref.content_id = ContentId([11; 32]);
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
        let classifications = coalesce_classified_key_facts(vec![
            classified_key_fact(&candidate_a, finding_a),
            classified_key_fact(&candidate_b, finding_b),
        ]);
        let units = vec![
            api_unit(
                ContentId([10; 32]),
                "apps/a/src/data.ts",
                "supabase.from('accounts_a').select('*');",
            ),
            api_unit(
                ContentId([11; 32]),
                "apps/b/src/data.ts",
                "supabase.from('accounts_b').select('*');",
            ),
        ];
        let references = harvest_api_references(&units);
        let associations = associate_api_references(&references, &classifications);

        let inputs = tier0_probe_inputs(&classifications, &associations.tables_by_project);
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
        assert!(associations.warnings.is_empty());
    }

    #[cfg(feature = "network")]
    #[test]
    fn tier0_probe_inputs_do_not_cross_probe_ambiguous_harvested_table() {
        let mut candidate_a = publishable_candidate("src/a-key.ts", LocationClass::ClientReachable);
        candidate_a.unit_ref.content_id = ContentId([20; 32]);
        let mut candidate_b = publishable_candidate("src/b-key.ts", LocationClass::ClientReachable);
        candidate_b.unit_ref.content_id = ContentId([21; 32]);
        let finding_a =
            public_key_finding_at("key-a", "src/a-key.ts", LocationClass::ClientReachable);
        let mut finding_b =
            public_key_finding_at("key-b", "src/b-key.ts", LocationClass::ClientReachable);
        if let Evidence::SupabaseKey {
            project: Some(project),
            ..
        } = &mut finding_b.evidence
        {
            project.ref_id = Some("zyxwvutsrqponmlkjihg".to_owned());
            project.url = "https://zyxwvutsrqponmlkjihg.supabase.co".to_owned();
        }
        let classifications = coalesce_classified_key_facts(vec![
            classified_key_fact(&candidate_a, finding_a),
            classified_key_fact(&candidate_b, finding_b),
        ]);
        let references = harvest_api_references(&[api_unit(
            ContentId([22; 32]),
            "src/shared.ts",
            "supabase.from('shared_profiles').select('*');",
        )]);
        let associations = associate_api_references(&references, &classifications);

        let inputs = tier0_probe_inputs(&classifications, &associations.tables_by_project);

        assert!(
            inputs.iter().all(|input| input.candidate_tables.is_empty()),
            "an ambiguously associated table must not be sent to either project"
        );
        assert!(associations.warnings.iter().any(|warning| matches!(
            warning,
            ScopeWarning::Other { message }
                if message.contains("shared_profiles")
                    && message.contains("ambiguous Supabase project association")
        )));
    }

    #[test]
    fn harvest_api_references_retains_table_and_rpc_kinds() {
        let units = vec![ScannableUnit {
            content_id: ContentId([2; 32]),
            content: br#"
                const profiles = supabase.from('profiles').select('*');
                await client.from("orders").select("id");
                await supabase.rpc('do_x');
                fetch("/rest/v1/widgets?select=*");
            "#
            .to_vec(),
            locations: vec![UnitLocation {
                path: RepoPath("apps/web/.next/static/chunks/x.js".to_owned()),
                provenance: Provenance::WorkingTree,
                additional_provenance: Vec::new(),
                location_class: LocationClass::ClientReachable,
            }],
        }];

        let references = harvest_api_references(&units)
            .into_iter()
            .map(|reference| (reference.kind, reference.name, reference.source_scope.0))
            .collect::<Vec<_>>();

        assert_eq!(
            references,
            vec![
                (
                    ApiReferenceKind::Table,
                    "orders".to_owned(),
                    "apps/web".to_owned()
                ),
                (
                    ApiReferenceKind::Table,
                    "profiles".to_owned(),
                    "apps/web".to_owned()
                ),
                (
                    ApiReferenceKind::Table,
                    "widgets".to_owned(),
                    "apps/web".to_owned()
                ),
                (
                    ApiReferenceKind::Rpc,
                    "do_x".to_owned(),
                    "apps/web".to_owned()
                ),
            ]
        );
    }

    #[test]
    fn rpc_references_remain_typed_and_never_become_table_candidates() {
        let content_id = ContentId([30; 32]);
        let facts = vec![classified_fact_for_source(
            content_id.clone(),
            "apps/web/src/config.ts",
            project(),
        )];
        let references = harvest_api_references(&[api_unit(
            content_id,
            "apps/web/src/data.ts",
            "supabase.from('profiles').select('*'); supabase.rpc('do_x');",
        )]);

        let associations = associate_api_references(&references, &facts);

        assert_eq!(
            associations.tables_by_project,
            BTreeMap::from([(
                "https://abcdefghijklmnopqrst.supabase.co".to_owned(),
                BTreeSet::from(["profiles".to_owned()]),
            )])
        );
        assert!(associations.warnings.is_empty());
        assert!(references.iter().any(|reference| {
            reference.kind == ApiReferenceKind::Rpc && reference.name == "do_x"
        }));
    }

    #[test]
    fn historical_api_references_use_exact_content_project_context() {
        let project_a = project();
        let project_b = SupabaseProject {
            ref_id: Some("zyxwvutsrqponmlkjihg".to_owned()),
            url: "https://zyxwvutsrqponmlkjihg.supabase.co".to_owned(),
        };
        let facts = vec![
            classified_fact_for_source(ContentId([31; 32]), "src/config.ts", project_a.clone()),
            classified_fact_for_source(ContentId([32; 32]), "src/config.ts", project_b.clone()),
        ];
        let references = harvest_api_references(&[
            api_unit(
                ContentId([31; 32]),
                "src/config.ts",
                "supabase.from('accounts_a').select('*');",
            ),
            api_unit(
                ContentId([32; 32]),
                "src/config.ts",
                "supabase.from('accounts_b').select('*');",
            ),
        ]);

        let associations = associate_api_references(&references, &facts);

        assert_eq!(
            associations.tables_by_project[&normalized_project_url(&project_a.url)],
            BTreeSet::from(["accounts_a".to_owned()])
        );
        assert_eq!(
            associations.tables_by_project[&normalized_project_url(&project_b.url)],
            BTreeSet::from(["accounts_b".to_owned()])
        );
        assert!(associations.warnings.is_empty());
    }

    #[test]
    fn unassociated_table_reference_emits_coverage_warning() {
        let references = harvest_api_references(&[api_unit(
            ContentId([33; 32]),
            "shared/data.ts",
            "supabase.from('orphaned_table').select('*');",
        )]);

        let associations = associate_api_references(&references, &[]);

        assert!(associations.tables_by_project.is_empty());
        assert!(matches!(
            associations.warnings.as_slice(),
            [ScopeWarning::Other { message }]
                if message.contains("orphaned_table")
                    && message.contains("no associated Supabase project")
        ));
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
    fn config_preserves_all_localstatic_values_and_resolves_repo_relative_paths() {
        let repo = TestRepo::new();
        repo.git(["init"]);
        repo.write(
            "vibescan.toml",
            r#"
            [scan]
            working_tree = false
            history = false
            max_commits = 17
            max_bytes = 4096
            severity_gate = "info"

            [baseline]
            path = "config/baseline.json"

            [rules]
            path = "config/custom-rules.toml"
            "#,
        );
        repo.write("config/baseline.json", "[]");
        repo.write("config/custom-rules.toml", "");
        repo.write("src/app.ts", "console.log('clean');\n");

        let config = ScanConfig::load(repo.path().join("src")).expect("config loads");

        assert!(!config.include_working_tree);
        assert!(!config.include_history);
        assert_eq!(config.max_commits, Some(17));
        assert_eq!(config.max_bytes, 4096);
        assert_eq!(config.severity_gate, Severity::Info);
        assert_eq!(
            config.baseline_path,
            Some(repo.path().join("config/baseline.json"))
        );
        assert_eq!(
            config.custom_rules_path,
            Some(repo.path().join("config/custom-rules.toml"))
        );
    }

    #[test]
    fn repository_config_cannot_enable_network_without_runtime_confirmation() {
        let repo = TestRepo::new();
        repo.git(["init"]);
        repo.write(
            "vibescan.toml",
            "[network]\ntier0_read_probe = true\ntier1_introspection = true\nregistry_checks = true\nregistry_newcomer = true\n",
        );

        let config = ScanConfig::load(repo.path()).expect("config loads");

        assert!(!config.tier0_read_probe);
        assert!(!config.tier1_introspection);
        assert!(!config.registry_checks);
        assert!(!config.registry_newcomer);
    }

    #[test]
    fn parsed_dependencies_are_deterministic_and_registry_shaped() {
        let repo = TestRepo::new();
        repo.git(["init"]);
        repo.write(
            "package.json",
            r#"{"dependencies":{"@acme/private":"^2.0.0","left-pad":"1.3.0"}}"#,
        );
        repo.write(
            "pyproject.toml",
            "[project]\ndependencies = [\"requests>=2.31\"]\n",
        );

        let first = parse_dependencies(repo.path()).expect("dependencies parse");
        let second = parse_dependencies(repo.path()).expect("dependencies parse twice");

        assert_eq!(first, second);
        assert_eq!(
            first,
            vec![
                ParsedDependency {
                    name: "@acme/private".to_owned(),
                    version_req: "^2.0.0".to_owned(),
                    ecosystem: Ecosystem::Npm,
                    manifest_path: vibescan_types::RepoPath("package.json".to_owned()),
                    is_scoped: true,
                },
                ParsedDependency {
                    name: "left-pad".to_owned(),
                    version_req: "1.3.0".to_owned(),
                    ecosystem: Ecosystem::Npm,
                    manifest_path: vibescan_types::RepoPath("package.json".to_owned()),
                    is_scoped: false,
                },
                ParsedDependency {
                    name: "requests".to_owned(),
                    version_req: ">=2.31".to_owned(),
                    ecosystem: Ecosystem::PyPi,
                    manifest_path: vibescan_types::RepoPath("pyproject.toml".to_owned()),
                    is_scoped: false,
                },
            ]
        );
    }

    #[test]
    fn parsed_dependencies_include_exact_npm_and_python_lock_versions() {
        let repo = TestRepo::new();
        repo.git(["init"]);
        repo.write(
            "package-lock.json",
            r#"{"lockfileVersion":3,"packages":{"":{"name":"fixture"},"node_modules/left-pad":{"version":"1.3.0"}}}"#,
        );
        repo.write(
            "poetry.lock",
            "[[package]]\nname = \"requests\"\nversion = \"2.32.0\"\n",
        );

        let dependencies = parse_dependencies(repo.path()).expect("lockfiles parse");

        assert_eq!(
            dependencies,
            vec![
                ParsedDependency {
                    name: "left-pad".to_owned(),
                    version_req: "1.3.0".to_owned(),
                    ecosystem: Ecosystem::Npm,
                    manifest_path: vibescan_types::RepoPath("package-lock.json".to_owned()),
                    is_scoped: false,
                },
                ParsedDependency {
                    name: "requests".to_owned(),
                    version_req: "2.32.0".to_owned(),
                    ecosystem: Ecosystem::PyPi,
                    manifest_path: vibescan_types::RepoPath("poetry.lock".to_owned()),
                    is_scoped: false,
                },
            ]
        );
    }

    #[cfg(feature = "registry")]
    #[test]
    fn structurally_invalid_dependencies_are_excluded_from_registry_inputs() {
        let repo = TestRepo::new();
        repo.git(["init"]);
        repo.write(
            "package.json",
            r#"{"dependencies":{"INVALID PACKAGE":"1.0.0","empty-version":"","valid-package":"1.0.0"}}"#,
        );

        let scan = scan_dependency_integrity(repo.path()).expect("dependency scan runs");
        let eligible = registry_eligible_dependencies(&scan.findings, scan.dependencies);

        assert_eq!(scan.findings.len(), 2);
        assert!(scan.findings.iter().all(|finding| matches!(
            finding.evidence,
            Evidence::Dependency {
                reason: vibescan_types::DependencyIntegrityReason::InvalidPackageName
                    | vibescan_types::DependencyIntegrityReason::EmptyVersionSpecifier,
                ..
            }
        )));
        assert_eq!(eligible.len(), 1);
        assert_eq!(eligible[0].name, "valid-package");
    }

    #[cfg(feature = "registry")]
    #[test]
    fn invalid_package_is_never_sent_and_remains_one_localstatic_finding() {
        use std::cell::Cell;

        struct CountingRegistry {
            calls: Cell<u64>,
        }

        impl vibescan_registry::RegistrySource for CountingRegistry {
            fn resolves(
                &self,
                _dependency: &ParsedDependency,
            ) -> Result<vibescan_registry::RegistryResolution, vibescan_registry::RegistryError>
            {
                self.calls.set(self.calls.get() + 1);
                Ok(vibescan_registry::RegistryResolution {
                    exists: false,
                    request_made: true,
                })
            }

            fn advisories_for(
                &self,
                ecosystem: Ecosystem,
            ) -> Result<vibescan_registry::AdvisorySet, vibescan_registry::RegistryError>
            {
                self.calls.set(self.calls.get() + 1);
                Ok(vibescan_registry::AdvisorySet::empty(ecosystem))
            }
        }

        let repo = TestRepo::new();
        repo.git(["init"]);
        repo.write(
            "package.json",
            r#"{"dependencies":{"INVALID PACKAGE":"1.0.0"}}"#,
        );
        let scan = scan_dependency_integrity(repo.path()).expect("dependency scan runs");
        let eligible = registry_eligible_dependencies(&scan.findings, scan.dependencies);
        let source = CountingRegistry {
            calls: Cell::new(0),
        };
        let registry_output = run_registry_checks(
            &source,
            &RegistryCheckInput {
                dependencies: eligible,
                private_registry_ecosystems: BTreeSet::new(),
            },
        )
        .expect("empty registry input runs");

        assert_eq!(source.calls.get(), 0);
        assert_eq!(scan.findings.len(), 1);
        assert!(registry_output.findings.is_empty());
        assert!(registry_output.actions.is_empty());
    }

    #[cfg(feature = "registry")]
    #[test]
    fn repository_alternate_registry_configuration_activates_precision_guard() {
        let repo = TestRepo::new();
        repo.git(["init"]);
        repo.write(".npmrc", "registry=https://npm.internal.example/\n");
        repo.write(
            "pyproject.toml",
            "[project]\ndependencies = [\"internal-python==1.0.0\"]\n[[tool.poetry.source]]\nname = \"private\"\nurl = \"https://python.internal.example/simple\"\n",
        );

        let ecosystems =
            private_registry_ecosystems(repo.path()).expect("private registries parse");

        assert_eq!(
            ecosystems,
            BTreeSet::from([Ecosystem::Npm, Ecosystem::PyPi])
        );
    }

    #[cfg(not(feature = "registry"))]
    #[test]
    fn registry_request_without_feature_is_a_clear_operational_error() {
        let repo = TestRepo::new();
        repo.git(["init"]);

        let error = scan(
            repo.path(),
            ScanConfig {
                registry_checks: true,
                ..ScanConfig::default()
            },
        )
        .expect_err("feature-off registry request rejected");

        assert!(matches!(error, CoreError::RegistryFeatureUnavailable));
        assert!(error.to_string().contains("without registry support"));
    }

    #[cfg(feature = "registry")]
    #[test]
    fn registry_runtime_opt_in_is_auditable_and_does_not_enable_rls() {
        let repo = TestRepo::new();
        repo.git(["init"]);

        let result = scan(
            repo.path(),
            ScanConfig {
                include_history: false,
                registry_checks: true,
                ..ScanConfig::default()
            },
        )
        .expect("F1 registry plumbing runs without live egress");

        assert!(result.scope.network.enabled);
        assert!(result.scope.network.registry_checks);
        assert!(!result.scope.network.registry_newcomer);
        assert!(!result.scope.network.tier0_read_probe);
        assert!(!result.scope.network.tier1_introspection);
        assert!(result.scope.network.actions.is_empty());
        assert!(result.scope.network.registry_name_egress.is_empty());
    }

    #[test]
    fn repository_path_resolution_preserves_absolute_paths() {
        let repo = TestRepo::new();
        repo.git(["init"]);
        let absolute = repo.path().join("outside-name.json");

        let resolved = resolve_repository_path(repo.path(), &absolute).expect("path resolves");

        assert_eq!(resolved, absolute);
    }

    #[test]
    fn invalid_configured_severity_is_rejected() {
        let repo = TestRepo::new();
        repo.git(["init"]);
        repo.write("vibescan.toml", "[scan]\nseverity_gate = \"urgent\"\n");

        let error = ScanConfig::load(repo.path()).expect_err("invalid severity rejected");

        assert!(matches!(error, CoreError::InvalidSeverity(value) if value == "urgent"));
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
    fn correlates_public_key_with_critical_rls_disabled_policy_without_probe() {
        let key = public_key_finding();
        let rls = rls_policy_finding(RlsExposure::RlsDisabled, project());
        assert_eq!(rls.severity, Severity::Critical);
        assert!(matches!(rls.evidence, Evidence::RlsPolicy { .. }));

        let correlations = correlate_findings(&[key.clone(), rls.clone()]);

        assert_eq!(rls.severity, Severity::Critical);
        assert_eq!(correlations.len(), 1);
        assert_eq!(correlations[0].severity, Severity::Critical);
        assert_eq!(correlations[0].related, vec![key.id, rls.id]);
        assert!(matches!(
            &correlations[0].evidence,
            Evidence::Correlation {
                reproduction: Some(reproduction),
                ..
            } if reproduction.contains("table profiles has RLS disabled")
        ));
    }

    #[test]
    fn correlates_public_key_with_critical_permissive_policy_without_probe() {
        let key = public_key_finding();
        let rls = rls_policy_finding(RlsExposure::PermissivePolicy, project());
        assert_eq!(rls.severity, Severity::Critical);

        let correlations = correlate_findings(&[key.clone(), rls.clone()]);

        assert_eq!(correlations.len(), 1);
        assert_eq!(correlations[0].related, vec![key.id, rls.id]);
        assert!(matches!(
            &correlations[0].evidence,
            Evidence::Correlation {
                reproduction: Some(reproduction),
                ..
            } if reproduction.contains("table profiles has permissive USING (true)")
        ));
    }

    #[test]
    fn operation_advisory_and_inferred_write_do_not_fire_read_chain() {
        let key = public_key_finding();
        for exposure in [
            RlsExposure::MissingOperationPolicy,
            RlsExposure::InferredWriteExposure,
        ] {
            let rls = rls_policy_finding(exposure, project());
            assert!(
                correlate_findings(&[key.clone(), rls]).is_empty(),
                "{exposure:?} must not prove anonymous read exposure"
            );
        }
    }

    #[test]
    fn tier1_read_exposure_on_different_project_does_not_correlate() {
        let key = public_key_finding();
        let other_project = SupabaseProject {
            ref_id: Some("zyxwvutsrqponmlkjihg".to_owned()),
            url: "https://zyxwvutsrqponmlkjihg.supabase.co/".to_owned(),
        };
        let rls = rls_policy_finding(RlsExposure::RlsDisabled, other_project);

        assert!(correlate_findings(&[key, rls]).is_empty());
    }

    #[test]
    fn committed_elevated_key_moots_tier1_policy_finding() {
        let mut key = public_key_finding();
        key.id = FindingId("elevated-key".to_owned());
        key.category = Category::SecretExposure;
        key.locations[0].provenance = Provenance::Commit {
            sha: "0123456789abcdef".to_owned(),
            author: None,
            date: None,
        };
        if let Evidence::SupabaseKey { class, .. } = &mut key.evidence {
            *class = SupabaseKeyClass::SecretNew;
        }
        let rls = rls_policy_finding(RlsExposure::PermissivePolicy, project());

        let correlation = correlate_findings(&[key.clone(), rls.clone()])
            .into_iter()
            .find(|finding| {
                matches!(
                    &finding.evidence,
                    Evidence::Correlation { rule_id, .. } if rule_id.0 == "elevated-key-in-tree"
                )
            })
            .expect("elevated-key correlation includes Tier 1 RLS evidence");

        assert!(correlation.related.contains(&key.id));
        assert!(correlation.related.contains(&rls.id));
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
                unit_ref: test_unit_ref("src/app.ts", LocationClass::Unknown),
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
            unit_ref: test_unit_ref("src/app.ts", LocationClass::Unknown),
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
    fn generic_finding_retains_all_candidate_source_locations() {
        let mut unit_ref = test_unit_ref("apps/api/.env.local", LocationClass::ServerOnly);
        unit_ref.locations.push(UnitLocation {
            path: RepoPath("apps/web/.next/static/chunks/config.js".to_owned()),
            provenance: Provenance::WorkingTree,
            additional_provenance: Vec::new(),
            location_class: LocationClass::ClientReachable,
        });
        let candidate = SecretCandidate {
            rule_id: vibescan_types::RuleId("toy".to_owned()),
            kind: vibescan_types::CandidateKind::ProviderSecret,
            raw_match: b"abcdefghijklmnopqrstuvwxyz123456".to_vec(),
            entropy: 4.0,
            unit_ref,
            span: Span {
                line: 4,
                col_start: 3,
                col_end: 35,
            },
        };

        let finding = generic_candidate_finding(&candidate);

        assert_eq!(finding.locations.len(), 2);
        assert!(
            finding
                .locations
                .iter()
                .all(|location| location.span == Some(candidate.span))
        );
    }

    #[test]
    fn localstatic_dependency_boundary_excludes_network_crates() {
        if cfg!(feature = "network") || cfg!(feature = "registry") {
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

    fn rls_policy_finding(exposure: RlsExposure, project: SupabaseProject) -> Finding {
        let (id, command, using_expr, rowsecurity, severity) = match exposure {
            RlsExposure::RlsDisabled => ("rls-disabled", "ALL", None, false, Severity::Critical),
            RlsExposure::PermissivePolicy => (
                "rls-permissive",
                "SELECT",
                Some("(true)".to_owned()),
                true,
                Severity::Critical,
            ),
            RlsExposure::MissingOperationPolicy => {
                ("rls-missing", "SELECT", None, true, Severity::Medium)
            }
            RlsExposure::InferredWriteExposure => {
                ("rls-write", "INSERT", None, true, Severity::High)
            }
            other => panic!("unexpected Tier 1 exposure in test helper: {other:?}"),
        };
        Finding {
            id: FindingId(id.to_owned()),
            category: Category::Rls,
            severity,
            title: "Tier 1 RLS policy finding".to_owned(),
            detail: "catalog-derived policy fact".to_owned(),
            locations: vec![Location {
                path: RepoPath("<environment:VIBESCAN_SUPABASE_DB_URL>".to_owned()),
                span: None,
                provenance: Provenance::WorkingTree,
                additional_provenance: Vec::new(),
                location_class: LocationClass::ServerOnly,
            }],
            evidence: Evidence::RlsPolicy {
                project,
                table: "profiles".to_owned(),
                command: command.to_owned(),
                using_expr,
                check_expr: None,
                rowsecurity,
                exposure,
            },
            remediation: "fix policy".to_owned(),
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
            unit_ref: test_unit_ref(path, location_class),
            span: Span {
                line: 1,
                col_start: 1,
                col_end: 55,
            },
        }
    }

    #[cfg(feature = "network")]
    fn classified_key_fact(candidate: &SecretCandidate, finding: Finding) -> ClassifiedKeyFact {
        let project = project_from_key_finding(&finding).cloned();
        ClassifiedKeyFact {
            finding,
            raw_key: candidate.raw_match.clone(),
            sources: vec![ClassifiedKeySource {
                unit_ref: candidate.unit_ref.clone(),
                project,
            }],
        }
    }

    fn project() -> SupabaseProject {
        SupabaseProject {
            ref_id: Some("abcdefghijklmnopqrst".to_owned()),
            url: "https://abcdefghijklmnopqrst.supabase.co".to_owned(),
        }
    }

    fn test_unit_ref(path: &str, location_class: LocationClass) -> UnitRef {
        UnitRef {
            content_id: ContentId([3; 32]),
            locations: vec![UnitLocation {
                path: RepoPath(path.to_owned()),
                provenance: Provenance::WorkingTree,
                additional_provenance: Vec::new(),
                location_class,
            }],
        }
    }

    fn api_unit(content_id: ContentId, path: &str, content: &str) -> ScannableUnit {
        ScannableUnit {
            content_id,
            content: content.as_bytes().to_vec(),
            locations: vec![UnitLocation {
                path: RepoPath(path.to_owned()),
                provenance: Provenance::WorkingTree,
                additional_provenance: Vec::new(),
                location_class: LocationClass::ClientReachable,
            }],
        }
    }

    fn classified_fact_for_source(
        content_id: ContentId,
        path: &str,
        project: SupabaseProject,
    ) -> ClassifiedKeyFact {
        let mut finding = public_key_finding();
        finding.id = FindingId(format!("key-{path}"));
        finding.locations[0].path = RepoPath(path.to_owned());
        if let Evidence::SupabaseKey {
            project: finding_project,
            ..
        } = &mut finding.evidence
        {
            *finding_project = Some(project.clone());
        }
        let unit_ref = UnitRef {
            content_id,
            locations: vec![UnitLocation {
                path: RepoPath(path.to_owned()),
                provenance: Provenance::WorkingTree,
                additional_provenance: Vec::new(),
                location_class: LocationClass::ClientReachable,
            }],
        };
        ClassifiedKeyFact {
            finding,
            raw_key: b"sb_publishable_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789".to_vec(),
            sources: vec![ClassifiedKeySource {
                unit_ref,
                project: Some(project),
            }],
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
                    registry_checks: false,
                    registry_newcomer: false,
                    registry_name_egress: Vec::new(),
                    actions: Vec::new(),
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
