//! Shared vocabulary for the vibescan workspace.
//!
//! This crate intentionally contains only data shapes and light trait contracts.
//! Scanning, IO, formatting, orchestration, and network behavior belong in the
//! higher crates described by the architecture document.

use std::cmp::Ordering;
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// One item of repository content made available to detector phases.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ScannableUnit {
    /// Raw file/blob bytes. Readers apply binary and size skip rules before
    /// constructing scan units.
    pub content: Vec<u8>,
    /// Repository-relative path.
    pub path: RepoPath,
    /// Where this content came from.
    pub provenance: Provenance,
    /// Additional places where identical content appeared after content-hash
    /// deduplication.
    pub additional_provenance: Vec<Provenance>,
    /// Heuristic location class used by later severity decisions.
    pub location_class: LocationClass,
}

/// Repository-relative path text.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct RepoPath(pub String);

/// Origin of a scannable unit or finding location.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Provenance {
    WorkingTree,
    Commit {
        sha: String,
        author: Option<String>,
        date: Option<String>,
    },
}

/// Heuristic judgement about whether a path is client reachable.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocationClass {
    ClientReachable,
    ServerOnly,
    Unknown,
}

/// A raw hit from the generic detection substrate.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SecretCandidate {
    pub rule_id: RuleId,
    pub kind: CandidateKind,
    /// Full matched secret bytes. Report crates must use redacted evidence for
    /// portable formats.
    pub raw_match: Vec<u8>,
    pub entropy: f64,
    pub unit_ref: UnitRef,
    pub span: Span,
}

/// Identifier of the detection rule that emitted a candidate.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct RuleId(pub String);

/// Coarse candidate family emitted by the substrate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateKind {
    PossibleSupabaseKey,
    ProviderSecret,
    PrivateKey,
    GenericHighEntropy,
    Other(String),
}

/// Back-reference to the source unit without retaining full content.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct UnitRef {
    pub path: RepoPath,
    pub provenance: Provenance,
    pub additional_provenance: Vec<Provenance>,
    pub location_class: LocationClass,
}

/// 1-based source span.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Span {
    pub line: u32,
    pub col_start: u32,
    pub col_end: u32,
}

/// A resolved, reportable security result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub id: FindingId,
    pub category: Category,
    pub severity: Severity,
    pub title: String,
    pub detail: String,
    pub locations: Vec<Location>,
    pub evidence: Evidence,
    pub remediation: String,
    pub related: Vec<FindingId>,
    pub confidence: Confidence,
}

/// Stable finding id used for deduplication and baselines.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct FindingId(pub String);

/// Finding category.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    SecretExposure,
    KeyClassification,
    Rls,
    DependencyIntegrity,
    Correlation,
}

/// Severity order used by gates and summary sorting.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub const fn rank(self) -> u8 {
        match self {
            Self::Critical => 5,
            Self::High => 4,
            Self::Medium => 3,
            Self::Low => 2,
            Self::Info => 1,
        }
    }
}

impl Ord for Severity {
    fn cmp(&self, other: &Self) -> Ordering {
        self.rank().cmp(&other.rank())
    }
}

impl PartialOrd for Severity {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Location evidence for one or more source positions.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Location {
    pub path: RepoPath,
    pub span: Option<Span>,
    pub provenance: Provenance,
    pub additional_provenance: Vec<Provenance>,
    pub location_class: LocationClass,
}

/// Evidence attached to a finding.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Evidence {
    Secret {
        redacted: String,
        fingerprint: SecretFingerprint,
    },
    SupabaseKey {
        class: SupabaseKeyClass,
        redacted: String,
        project: Option<SupabaseProject>,
        fingerprint: SecretFingerprint,
    },
    RlsProbe {
        project: SupabaseProject,
        table: String,
        endpoint: String,
        observed_row_count: u64,
        exposure: RlsExposure,
    },
    Dependency {
        package: String,
        manifest_path: RepoPath,
        reason: DependencyIntegrityReason,
    },
    Correlation {
        rule_id: CorrelationRuleId,
        reproduction: Option<String>,
    },
    Note {
        message: String,
    },
}

/// Non-secret fingerprint for grouping the same underlying secret.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct SecretFingerprint(pub String);

/// Supabase project identity derived from a key or supplied config.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct SupabaseProject {
    pub ref_id: Option<String>,
    pub url: String,
}

/// Supabase key class after domain classification.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupabaseKeyClass {
    PublishableNew,
    SecretNew,
    AnonLegacy,
    ServiceRoleLegacy,
    Unknown,
}

/// RLS exposure state emitted by probe/introspection stages.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RlsExposure {
    Protected,
    Exposed,
    RlsDisabled,
    PermissivePolicy,
    MissingOperationPolicy,
    InferredWriteExposure,
}

/// Dependency-integrity finding reason.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyIntegrityReason {
    NonexistentPackage,
    InvalidPackageName,
    EmptyVersionSpecifier,
    SuspiciousNewcomer,
    KnownMalicious,
}

/// Identifier for declarative correlation rules.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct CorrelationRuleId(pub String);

/// Confidence level attached to a finding.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Confirmed,
    Likely,
    Review,
}

/// Whole scan result passed to report renderers.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ScanResult {
    pub findings: Vec<Finding>,
    pub scope: ScanScope,
    pub tool_version: String,
    pub started_at: String,
    pub duration_ms: u64,
    pub stats: ScanStats,
}

/// What the run covered.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ScanScope {
    pub target: String,
    pub working_tree: bool,
    pub history: HistoryScope,
    pub network: NetworkScope,
    pub warnings: Vec<ScopeWarning>,
}

/// History coverage for the run.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum HistoryScope {
    Disabled,
    WorkingTreeOnly,
    Budgeted {
        max_commits: u64,
        scanned_commits: u64,
        truncated: bool,
    },
    Exhaustive {
        scanned_commits: u64,
    },
}

/// Network activity used in the run.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NetworkScope {
    pub enabled: bool,
    pub tier0_read_probe: bool,
    pub tier1_introspection: bool,
}

/// Reportable limitation in scan coverage.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ScopeWarning {
    HistoryBudgetHit { max_commits: u64 },
    ShallowClone,
    SubmoduleSkipped { path: RepoPath },
    MergeCommitFirstParentOnly { sha: String },
    LargeFileSkipped { path: RepoPath, bytes: u64 },
    BinaryFileSkipped { path: RepoPath },
    Other { message: String },
}

/// Precomputed finding totals for reporting.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ScanStats {
    pub by_severity: BTreeMap<Severity, u64>,
    pub by_category: BTreeMap<Category, u64>,
    pub skipped_large_files: u64,
    pub skipped_binary_files: u64,
    pub scan_budget_hit: bool,
}

/// A minimal sink contract for future streaming collectors.
pub trait CandidateSink {
    fn push_candidate(&mut self, candidate: SecretCandidate);
}

/// A minimal sink contract for future finding emitters.
pub trait FindingSink {
    fn push_finding(&mut self, finding: Finding);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_sorts_from_low_to_critical_by_rank() {
        let mut severities = vec![
            Severity::Medium,
            Severity::Info,
            Severity::Critical,
            Severity::Low,
            Severity::High,
        ];

        severities.sort();

        assert_eq!(
            severities,
            vec![
                Severity::Info,
                Severity::Low,
                Severity::Medium,
                Severity::High,
                Severity::Critical
            ]
        );
    }

    #[test]
    fn candidate_round_trips_through_json() {
        let candidate = SecretCandidate {
            rule_id: RuleId("supabase-key-shaped".to_owned()),
            kind: CandidateKind::PossibleSupabaseKey,
            raw_match: b"sb_publishable_example".to_vec(),
            entropy: 3.7,
            unit_ref: UnitRef {
                path: RepoPath("src/app.tsx".to_owned()),
                provenance: Provenance::WorkingTree,
                additional_provenance: Vec::new(),
                location_class: LocationClass::ClientReachable,
            },
            span: Span {
                line: 12,
                col_start: 8,
                col_end: 30,
            },
        };

        let encoded = serde_json::to_string(&candidate).expect("candidate serializes");
        let decoded: SecretCandidate =
            serde_json::from_str(&encoded).expect("candidate deserializes");

        assert_eq!(decoded, candidate);
    }
}
