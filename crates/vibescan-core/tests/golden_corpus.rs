use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use vibescan_core::{ScanConfig, correlate_findings, scan};
use vibescan_types::{
    Category, Confidence, CorrelationRuleId, Evidence, Finding, FindingId, Location, LocationClass,
    Provenance, RepoPath, RlsExposure, ScanResult, SecretFingerprint, Severity, Span,
    SupabaseKeyClass, SupabaseProject,
};

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

const LIVE_FIXTURES: &[GoldenFixture] = &[
    GoldenFixture {
        name: "clean-control",
        history: false,
    },
    GoldenFixture {
        name: "history-only-elevated-key",
        history: true,
    },
    GoldenFixture {
        name: "publishable-client-reachable",
        history: false,
    },
    GoldenFixture {
        name: "vendor-chunks-noise",
        history: false,
    },
    GoldenFixture {
        name: "nested-gitignore",
        history: false,
    },
    GoldenFixture {
        name: "malformed-dependency",
        history: false,
    },
];

#[derive(Clone, Copy, Debug)]
struct GoldenFixture {
    name: &'static str,
    history: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct GoldenManifest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    todo: Option<String>,
    findings: Vec<CanonicalFinding>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct CanonicalFinding {
    stable_key: String,
    rule_id: String,
    category: String,
    severity: String,
    locations: Vec<String>,
    provenance_kind: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    provenance_shas: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    correlation_related: Vec<String>,
    evidence: CanonicalEvidence,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum CanonicalEvidence {
    Secret {
        fingerprint: String,
    },
    SupabaseKey {
        class: String,
        project_ref: Option<String>,
        project_url: Option<String>,
        fingerprint: String,
    },
    RlsProbe {
        project_url: String,
        table: String,
        exposure: String,
    },
    Dependency {
        package: String,
        manifest_path: String,
        reason: String,
    },
    Correlation {
        rule_id: String,
    },
    Note {
        message: String,
    },
}

#[test]
fn golden_corpus_matches_expected_manifests() {
    for fixture in LIVE_FIXTURES {
        let repo = materialize_fixture(fixture);
        let result = scan(
            &repo,
            ScanConfig {
                include_history: fixture.history,
                severity_gate: Severity::Info,
                ..ScanConfig::default()
            },
        )
        .unwrap_or_else(|error| panic!("{} scan failed: {error}", fixture.name));
        let actual = manifest_from_result(&result);
        assert_or_update_manifest(fixture_dir(fixture.name).join("expected.json"), &actual);
    }
}

#[test]
fn golden_corpus_is_deterministic_across_runs() {
    for fixture in LIVE_FIXTURES {
        let first_repo = materialize_fixture(fixture);
        let second_repo = materialize_fixture(fixture);
        let config = ScanConfig {
            include_history: fixture.history,
            severity_gate: Severity::Info,
            ..ScanConfig::default()
        };
        let first = scan(&first_repo, config.clone())
            .unwrap_or_else(|error| panic!("{} first scan failed: {error}", fixture.name));
        let second = scan(&second_repo, config)
            .unwrap_or_else(|error| panic!("{} second scan failed: {error}", fixture.name));

        assert_eq!(
            manifest_from_result(&first),
            manifest_from_result(&second),
            "{} canonical findings changed between runs",
            fixture.name
        );
    }
}

#[test]
fn offline_composite_exposed_public_key_chain_golden() {
    let key = synthetic_public_key_finding();
    let rls = synthetic_rls_finding();
    let correlation = correlate_findings(&[key.clone(), rls.clone()])
        .into_iter()
        .next()
        .expect("correlation emitted");
    assert_eq!(correlation.severity, Severity::Critical);

    let mut findings = vec![key, rls, correlation];
    absorb_exposed_public_key_constituents_for_test(&mut findings);
    assert_eq!(findings.len(), 1, "constituents should be absorbed");
    assert_eq!(findings[0].category, Category::Correlation);

    let manifest = GoldenManifest {
        todo: None,
        findings: canonicalize_findings(&findings),
    };
    assert_or_update_manifest(
        fixture_dir("offline-composite-exposed-public-key-chain").join("expected.json"),
        &manifest,
    );
}

#[test]
#[ignore = "TODO(network): enable when Tier 0 probe fixtures run without live services"]
fn network_exposed_public_key_chain_fixture_is_gated() {
    ignored_network_fixture("exposed-public-key-chain");
}

#[test]
#[ignore = "TODO(network): enable when Tier 0 probe fixtures run without live services"]
fn network_rls_off_table_fixture() {
    ignored_network_fixture("rls-off-table");
}

#[test]
#[ignore = "TODO(network): enable when Tier 0 policy introspection fixtures land"]
fn network_permissive_using_true_policy_fixture() {
    ignored_network_fixture("permissive-using-true-policy");
}

#[test]
#[ignore = "TODO(network): enable when registry-backed dependency checks exist"]
fn network_hallucinated_dependency_fixture() {
    ignored_network_fixture("hallucinated-dependency");
}

fn ignored_network_fixture(name: &str) {
    let manifest = fixture_dir(name).join("expected.json");
    assert!(
        manifest.is_file(),
        "network placeholder fixture {name} must carry expected.json"
    );
}

fn manifest_from_result(result: &ScanResult) -> GoldenManifest {
    GoldenManifest {
        todo: None,
        findings: canonicalize_findings(&result.findings),
    }
}

fn canonicalize_findings(findings: &[Finding]) -> Vec<CanonicalFinding> {
    let mut canonical = findings
        .iter()
        .map(canonicalize_finding)
        .collect::<Vec<_>>();
    canonical.sort_by(|left, right| {
        severity_rank(&left.severity)
            .cmp(&severity_rank(&right.severity))
            .reverse()
            .then_with(|| left.stable_key.cmp(&right.stable_key))
    });
    canonical
}

fn canonicalize_finding(finding: &Finding) -> CanonicalFinding {
    let mut locations = finding
        .locations
        .iter()
        .map(|location| location.path.0.clone())
        .collect::<Vec<_>>();
    locations.sort();
    locations.dedup();

    let mut provenance_kinds = BTreeSet::new();
    let mut provenance_shas = BTreeSet::new();
    for location in &finding.locations {
        collect_provenance(
            &location.provenance,
            &mut provenance_kinds,
            &mut provenance_shas,
        );
        for provenance in &location.additional_provenance {
            collect_provenance(provenance, &mut provenance_kinds, &mut provenance_shas);
        }
    }

    let mut correlation_related = finding
        .related
        .iter()
        .map(|related| related.0.clone())
        .collect::<Vec<_>>();
    correlation_related.sort();

    CanonicalFinding {
        stable_key: finding.id.0.clone(),
        rule_id: rule_id(finding),
        category: enum_string(&finding.category),
        severity: enum_string(&finding.severity),
        locations,
        provenance_kind: if provenance_kinds.contains("commit") {
            "commit".to_owned()
        } else {
            "working_tree".to_owned()
        },
        provenance_shas: provenance_shas.into_iter().collect(),
        correlation_related,
        evidence: canonical_evidence(&finding.evidence),
    }
}

fn collect_provenance(
    provenance: &Provenance,
    kinds: &mut BTreeSet<&'static str>,
    shas: &mut BTreeSet<String>,
) {
    match provenance {
        Provenance::WorkingTree => {
            kinds.insert("working_tree");
        }
        Provenance::Commit { sha, .. } => {
            kinds.insert("commit");
            shas.insert(sha.clone());
        }
    }
}

fn canonical_evidence(evidence: &Evidence) -> CanonicalEvidence {
    match evidence {
        Evidence::Secret { fingerprint, .. } => CanonicalEvidence::Secret {
            fingerprint: fingerprint.0.clone(),
        },
        Evidence::SupabaseKey {
            class,
            project,
            fingerprint,
            ..
        } => CanonicalEvidence::SupabaseKey {
            class: enum_string(class),
            project_ref: project.as_ref().and_then(|project| project.ref_id.clone()),
            project_url: project.as_ref().map(|project| project.url.clone()),
            fingerprint: fingerprint.0.clone(),
        },
        Evidence::RlsProbe {
            project,
            table,
            exposure,
            ..
        } => CanonicalEvidence::RlsProbe {
            project_url: project.url.clone(),
            table: table.clone(),
            exposure: enum_string(exposure),
        },
        Evidence::Dependency {
            package,
            manifest_path,
            reason,
        } => CanonicalEvidence::Dependency {
            package: package.clone(),
            manifest_path: manifest_path.0.clone(),
            reason: enum_string(reason),
        },
        Evidence::Correlation { rule_id, .. } => CanonicalEvidence::Correlation {
            rule_id: rule_id.0.clone(),
        },
        Evidence::Note { message } => CanonicalEvidence::Note {
            message: message.clone(),
        },
    }
}

fn rule_id(finding: &Finding) -> String {
    match &finding.evidence {
        Evidence::Secret { .. } => "generic-secret".to_owned(),
        Evidence::SupabaseKey { class, .. } => format!("supabase-key:{}", enum_string(class)),
        Evidence::RlsProbe { exposure, .. } => format!("rls:{}", enum_string(exposure)),
        Evidence::Dependency { reason, .. } => format!("dependency:{}", enum_string(reason)),
        Evidence::Correlation { rule_id, .. } => rule_id.0.clone(),
        Evidence::Note { .. } => "note".to_owned(),
    }
}

fn enum_string<T: Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .expect("enum serializes")
        .as_str()
        .expect("enum serializes to string")
        .to_owned()
}

fn severity_rank(severity: &str) -> u8 {
    match severity {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        "info" => 1,
        other => panic!("unknown severity {other}"),
    }
}

fn assert_or_update_manifest(path: PathBuf, actual: &GoldenManifest) {
    let update = env::var_os("UPDATE_GOLDEN").is_some_and(|value| value == "1");
    if update {
        let serialized = serde_json::to_string_pretty(actual).expect("golden manifest serializes");
        fs::write(&path, format!("{serialized}\n"))
            .unwrap_or_else(|error| panic!("write {}: {error}", path.display()));
        return;
    }

    let expected_content = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    let expected = serde_json::from_str::<GoldenManifest>(&expected_content)
        .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()));
    assert_eq!(
        &expected,
        actual,
        "golden manifest drifted at {}; rerun with UPDATE_GOLDEN=1 to accept",
        path.display()
    );
}

fn materialize_fixture(fixture: &GoldenFixture) -> PathBuf {
    if fixture.history {
        materialize_history_fixture(fixture.name)
    } else {
        materialize_working_tree_fixture(fixture.name)
    }
}

fn materialize_working_tree_fixture(name: &str) -> PathBuf {
    let source = fixture_dir(name).join("repo");
    let destination = unique_temp_dir(name);
    copy_dir(&source, &destination);
    run_git(&destination, ["init"]);
    destination
}

fn materialize_history_fixture(name: &str) -> PathBuf {
    let destination = unique_temp_dir(name);
    let bundle = fixture_dir(name).join("history.bundle");
    let output = Command::new("git")
        .arg("clone")
        .arg(&bundle)
        .arg(&destination)
        .output()
        .unwrap_or_else(|error| panic!("git clone {} failed: {error}", bundle.display()));
    assert!(
        output.status.success(),
        "git clone {} failed\nstdout:\n{}\nstderr:\n{}",
        bundle.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    destination
}

fn copy_dir(source: &Path, destination: &Path) {
    fs::create_dir_all(destination)
        .unwrap_or_else(|error| panic!("create {}: {error}", destination.display()));
    for entry in fs::read_dir(source)
        .unwrap_or_else(|error| panic!("read fixture source {}: {error}", source.display()))
    {
        let entry = entry.expect("fixture entry is readable");
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let file_type = entry.file_type().expect("fixture entry type is readable");
        if file_type.is_dir() {
            copy_dir(&source_path, &destination_path);
        } else if file_type.is_file() {
            fs::copy(&source_path, &destination_path).unwrap_or_else(|error| {
                panic!(
                    "copy {} to {}: {error}",
                    source_path.display(),
                    destination_path.display()
                )
            });
        }
    }
}

fn run_git<const N: usize>(repo: &Path, args: [&str; N]) {
    let output = Command::new("git")
        .args(args)
        .current_dir(repo)
        .output()
        .expect("git command starts");
    assert!(
        output.status.success(),
        "git failed in {}\nstdout:\n{}\nstderr:\n{}",
        repo.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn unique_temp_dir(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after epoch")
        .as_nanos();
    let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = env::temp_dir().join(format!(
        "vibescan-golden-{name}-{}-{nonce}-{counter}",
        std::process::id()
    ));
    fs::create_dir_all(&path).unwrap_or_else(|error| panic!("create {}: {error}", path.display()));
    path
}

fn fixture_dir(name: &str) -> PathBuf {
    workspace_root().join("tests").join("fixtures").join(name)
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

fn synthetic_public_key_finding() -> Finding {
    Finding {
        id: FindingId("golden-key".to_owned()),
        category: Category::KeyClassification,
        severity: Severity::Info,
        title: "Supabase publishable key found".to_owned(),
        detail: "synthetic public key".to_owned(),
        locations: vec![Location {
            path: RepoPath("src/app/page.tsx".to_owned()),
            span: Some(Span {
                line: 2,
                col_start: 14,
                col_end: 72,
            }),
            provenance: Provenance::WorkingTree,
            additional_provenance: Vec::new(),
            location_class: LocationClass::ClientReachable,
        }],
        evidence: Evidence::SupabaseKey {
            class: SupabaseKeyClass::PublishableNew,
            redacted: "sb_pub...6789".to_owned(),
            project: Some(synthetic_project()),
            fingerprint: SecretFingerprint("golden-public-fingerprint".to_owned()),
        },
        remediation: "fix RLS if exposed".to_owned(),
        related: Vec::new(),
        confidence: Confidence::Likely,
    }
}

fn synthetic_rls_finding() -> Finding {
    Finding {
        id: FindingId("golden-rls".to_owned()),
        category: Category::Rls,
        severity: Severity::Critical,
        title: "Supabase table profiles is readable with the public key".to_owned(),
        detail: "synthetic RLS exposure".to_owned(),
        locations: Vec::new(),
        evidence: Evidence::RlsProbe {
            project: synthetic_project(),
            table: "profiles".to_owned(),
            endpoint: "https://abcdefghijklmnopqrst.supabase.co/rest/v1/profiles?select=*&limit=1"
                .to_owned(),
            observed_row_count: 1,
            exposure: RlsExposure::Exposed,
        },
        remediation: "tighten RLS".to_owned(),
        related: Vec::new(),
        confidence: Confidence::Confirmed,
    }
}

fn synthetic_project() -> SupabaseProject {
    SupabaseProject {
        ref_id: Some("abcdefghijklmnopqrst".to_owned()),
        url: "https://abcdefghijklmnopqrst.supabase.co".to_owned(),
    }
}

fn absorb_exposed_public_key_constituents_for_test(findings: &mut Vec<Finding>) {
    let absorbed = findings
        .iter()
        .filter_map(|finding| {
            let Evidence::Correlation { rule_id, .. } = &finding.evidence else {
                return None;
            };
            if rule_id == &CorrelationRuleId("exposed-public-key-chain".to_owned()) {
                Some(finding.related.clone())
            } else {
                None
            }
        })
        .flatten()
        .collect::<BTreeSet<_>>();

    findings.retain(|finding| {
        finding.category == Category::Correlation || !absorbed.contains(&finding.id)
    });
}
