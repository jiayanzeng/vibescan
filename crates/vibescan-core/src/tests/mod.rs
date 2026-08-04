use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use vibescan_secrets::working_tree_unit;
use vibescan_types::{
    ContentId, LocationClass, RepoPath, RlsExposure, Span, SupabaseProject, UnitLocation, UnitRef,
};

use super::*;

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
        RlsExposure::InferredWriteExposure => ("rls-write", "INSERT", None, true, Severity::High),
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

#[path = "baseline.rs"]
mod baseline_tests;

#[path = "config.rs"]
mod config_tests;

#[path = "correlation.rs"]
mod correlation_tests;

#[path = "dependencies.rs"]
mod dependencies_tests;

#[path = "error.rs"]
mod error_tests;

#[path = "findings.rs"]
mod findings_tests;

#[path = "pipeline.rs"]
mod pipeline_tests;

#[cfg(feature = "registry")]
#[path = "pipeline_registry.rs"]
mod pipeline_registry_tests;
