mod common;

#[cfg(feature = "network")]
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::PathBuf;

#[cfg(feature = "registry")]
use common::registry_fixture_findings;
use common::{
    LIVE_FIXTURES, LiveFixture, fixture_dir, materialize_fixture, offline_composite_findings,
    synthetic_rls_finding,
};
#[cfg(feature = "network")]
use common::{
    TIER1_FIXTURES, absorb_exposed_public_key_constituents_for_test, synthetic_project,
    synthetic_public_key_finding, tier1_fixture_findings,
};
use serde::{Deserialize, Serialize};
use vibescan_core::{ScanConfig, correlate_findings, scan};
#[cfg(feature = "network")]
use vibescan_supabase::{
    RlsHttpClient, RlsHttpResponse, Tier0RlsProbeInput, Tier0RlsProbeWarning,
    probe_tier0_read_with_client,
};
use vibescan_types::{
    Category, CorrelationRuleId, Evidence, Finding, LocationClass, Provenance, ScanResult, Severity,
};

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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    location_classes: Vec<String>,
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
    RlsPolicy {
        project_url: String,
        table: String,
        command: String,
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
        let actual = manifest_from_result(&result, include_location_classes(fixture));
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
            manifest_from_result(&first, include_location_classes(fixture)),
            manifest_from_result(&second, include_location_classes(fixture)),
            "{} canonical findings changed between runs",
            fixture.name
        );
    }
}

#[test]
fn offline_composite_exposed_public_key_chain_golden() {
    let findings = offline_composite_findings();
    assert_eq!(findings.len(), 1, "constituents should be absorbed");
    assert_eq!(findings[0].category, Category::Correlation);
    assert_eq!(findings[0].severity, Severity::Critical);

    let manifest = GoldenManifest {
        todo: None,
        findings: canonicalize_findings(&findings, false),
    };
    assert_or_update_manifest(
        fixture_dir("offline-composite-exposed-public-key-chain").join("expected.json"),
        &manifest,
    );
}

#[test]
#[cfg(feature = "network")]
fn network_exposed_public_key_chain_fixture_is_gated() {
    let key = synthetic_public_key_finding();
    let client = MockPostgrest::new([
        (
            "https://abcdefghijklmnopqrst.supabase.co/rest/v1/",
            RlsHttpResponse {
                status: 403,
                body: r#"{"message":"root forbidden"}"#.to_owned(),
            },
        ),
        (
            "https://abcdefghijklmnopqrst.supabase.co/rest/v1/profiles?select=*&limit=1",
            RlsHttpResponse {
                status: 200,
                body: r#"[{"id":1,"email":"not stored"}]"#.to_owned(),
            },
        ),
    ]);
    let output = probe_tier0_read_with_client(
        &client,
        &Tier0RlsProbeInput {
            project: synthetic_project(),
            public_key: "sb_publishable_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789".to_owned(),
            key_location: key.locations[0].clone(),
            candidate_tables: BTreeSet::from(["profiles".to_owned()]),
        },
    )
    .expect("mocked probe succeeds");
    assert!(matches!(
        output.warnings.as_slice(),
        [Tier0RlsProbeWarning::RootEnumerationUnavailable { status: 403, .. }]
    ));
    assert_eq!(output.findings.len(), 1);

    let rls = output.findings[0].clone();
    let correlation = correlate_findings(&[key.clone(), rls.clone()])
        .into_iter()
        .next()
        .expect("correlation emitted");
    assert_eq!(correlation.severity, Severity::Critical);

    let mut findings = vec![key, rls, correlation];
    absorb_exposed_public_key_constituents_for_test(&mut findings);
    let manifest = GoldenManifest {
        todo: None,
        findings: canonicalize_findings(&findings, false),
    };
    assert_or_update_manifest(
        fixture_dir("exposed-public-key-chain").join("expected.json"),
        &manifest,
    );
}

#[test]
#[cfg(not(feature = "network"))]
#[ignore = "TODO(network): run with --features network to exercise the mocked Tier 0 exposed-chain fixture"]
fn network_exposed_public_key_chain_fixture_is_gated() {
    ignored_feature_fixture("exposed-public-key-chain");
}

#[test]
#[cfg(feature = "network")]
fn network_rls_off_table_fixture() {
    assert_tier1_fixture("rls-off-table");
}

#[test]
#[cfg(not(feature = "network"))]
#[ignore = "TODO(network): run with --features network to exercise the mocked Tier 1 RLS-off fixture"]
fn network_rls_off_table_fixture() {
    ignored_feature_fixture("rls-off-table");
}

#[test]
#[cfg(feature = "network")]
fn network_permissive_using_true_policy_fixture() {
    assert_tier1_fixture("permissive-using-true-policy");
}

#[test]
#[cfg(not(feature = "network"))]
#[ignore = "TODO(network): run with --features network to exercise the mocked Tier 1 permissive-policy fixture"]
fn network_permissive_using_true_policy_fixture() {
    ignored_feature_fixture("permissive-using-true-policy");
}

#[test]
#[cfg(feature = "registry")]
fn network_hallucinated_dependency_fixture() {
    let findings = registry_fixture_findings("hallucinated-dependency");
    let manifest = GoldenManifest {
        todo: None,
        findings: canonicalize_findings(&findings, false),
    };
    assert_or_update_manifest(
        fixture_dir("hallucinated-dependency").join("expected.json"),
        &manifest,
    );
}

#[test]
#[cfg(not(feature = "registry"))]
#[ignore = "feature-off: run with --features registry to exercise the mocked Registry fixture"]
fn network_hallucinated_dependency_fixture() {
    ignored_feature_fixture("hallucinated-dependency");
}

#[test]
fn monorepo_bundle_key_can_drive_exposed_public_key_chain() {
    let fixture = LiveFixture {
        name: "monorepo-layout",
        history: false,
    };
    let repo = materialize_fixture(&fixture);
    let result = scan(
        &repo,
        ScanConfig {
            include_history: false,
            severity_gate: Severity::Info,
            ..ScanConfig::default()
        },
    )
    .expect("monorepo fixture scans");
    let key = result
        .findings
        .iter()
        .find(|finding| matches!(finding.evidence, Evidence::SupabaseKey { .. }))
        .cloned()
        .expect("fixture emits Supabase key finding");

    assert!(key.locations.iter().any(|location| {
        location.path.0 == "apps/web/.next/static/chunks/x.js"
            && location.location_class == LocationClass::ClientReachable
    }));

    let rls = synthetic_rls_finding();
    let correlations = correlate_findings(&[key, rls]);
    let correlation = correlations
        .iter()
        .find(|finding| {
            finding.category == Category::Correlation && finding.severity == Severity::Critical
        })
        .expect("exposed public key chain fires");

    assert!(matches!(
        correlation.evidence,
        Evidence::Correlation { ref rule_id, .. }
            if rule_id == &CorrelationRuleId("exposed-public-key-chain".to_owned())
    ));
}

#[test]
#[cfg(feature = "network")]
fn src_api_client_wrapper_drives_rule_one_without_commit_provenance() {
    let fixture = LiveFixture {
        name: "src-api-client-wrapper",
        history: false,
    };
    let repo = materialize_fixture(&fixture);
    let result = scan(
        &repo,
        ScanConfig {
            include_history: false,
            severity_gate: Severity::Info,
            ..ScanConfig::default()
        },
    )
    .expect("src/api client-wrapper fixture scans");
    let key = result
        .findings
        .iter()
        .find(|finding| matches!(finding.evidence, Evidence::SupabaseKey { .. }))
        .cloned()
        .expect("fixture emits Supabase key finding");

    assert_eq!(key.severity, Severity::Info);
    assert!(key.locations.iter().any(|location| {
        location.path.0 == "src/api/supabase-client.ts"
            && location.location_class == LocationClass::ClientReachable
    }));
    assert!(key.locations.iter().all(|location| {
        matches!(&location.provenance, Provenance::WorkingTree)
            && location
                .additional_provenance
                .iter()
                .all(|provenance| matches!(provenance, Provenance::WorkingTree))
    }));

    let client = MockPostgrest::new([
        (
            "https://abcdefghijklmnopqrst.supabase.co/rest/v1/",
            RlsHttpResponse {
                status: 403,
                body: r#"{"message":"root forbidden"}"#.to_owned(),
            },
        ),
        (
            "https://abcdefghijklmnopqrst.supabase.co/rest/v1/profiles?select=*&limit=1",
            RlsHttpResponse {
                status: 200,
                body: r#"[{}]"#.to_owned(),
            },
        ),
    ]);
    let output = probe_tier0_read_with_client(
        &client,
        &Tier0RlsProbeInput {
            project: synthetic_project(),
            public_key: "sb_publishable_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789".to_owned(),
            key_location: key.locations[0].clone(),
            candidate_tables: BTreeSet::from(["profiles".to_owned()]),
        },
    )
    .expect("mocked probe succeeds");
    assert_eq!(output.findings.len(), 1);
    let rls = output.findings[0].clone();

    let correlation = correlate_findings(&[key.clone(), rls.clone()])
        .into_iter()
        .find(|finding| {
            matches!(
                &finding.evidence,
                Evidence::Correlation { rule_id, .. }
                    if rule_id == &CorrelationRuleId("exposed-public-key-chain".to_owned())
            )
        })
        .expect("client classification fires rule 1 without commit provenance");
    assert_eq!(correlation.severity, Severity::Critical);
    assert_eq!(
        correlation.related.iter().cloned().collect::<BTreeSet<_>>(),
        BTreeSet::from([key.id.clone(), rls.id.clone()])
    );

    let mut findings = vec![key, rls, correlation];
    absorb_exposed_public_key_constituents_for_test(&mut findings);
    assert_eq!(findings.len(), 1, "the composite absorbs both constituents");
    assert_eq!(findings[0].category, Category::Correlation);
}

#[cfg(any(not(feature = "network"), not(feature = "registry")))]
fn ignored_feature_fixture(name: &str) {
    let manifest = fixture_dir(name).join("expected.json");
    assert!(
        manifest.is_file(),
        "feature-gated fixture {name} must carry expected.json"
    );
}

#[cfg(feature = "network")]
fn assert_tier1_fixture(name: &str) {
    assert!(TIER1_FIXTURES.contains(&name));
    let findings = tier1_fixture_findings(name);
    let correlations = findings
        .iter()
        .filter(|finding| finding.category == Category::Correlation)
        .collect::<Vec<_>>();
    assert_eq!(correlations.len(), 1);
    assert_eq!(correlations[0].severity, Severity::Critical);

    let manifest = GoldenManifest {
        todo: None,
        findings: canonicalize_findings(&findings, false),
    };
    assert_or_update_manifest(fixture_dir(name).join("expected.json"), &manifest);
}

fn include_location_classes(fixture: &LiveFixture) -> bool {
    matches!(fixture.name, "monorepo-layout" | "src-api-client-wrapper")
}

fn manifest_from_result(result: &ScanResult, include_location_classes: bool) -> GoldenManifest {
    GoldenManifest {
        todo: None,
        findings: canonicalize_findings(&result.findings, include_location_classes),
    }
}

fn canonicalize_findings(
    findings: &[Finding],
    include_location_classes: bool,
) -> Vec<CanonicalFinding> {
    let mut canonical = findings
        .iter()
        .map(|finding| canonicalize_finding(finding, include_location_classes))
        .collect::<Vec<_>>();
    canonical.sort_by(|left, right| {
        severity_rank(&left.severity)
            .cmp(&severity_rank(&right.severity))
            .reverse()
            .then_with(|| left.stable_key.cmp(&right.stable_key))
    });
    canonical
}

fn canonicalize_finding(finding: &Finding, include_location_classes: bool) -> CanonicalFinding {
    let mut locations = finding
        .locations
        .iter()
        .map(|location| location.path.0.clone())
        .collect::<Vec<_>>();
    locations.sort();
    locations.dedup();
    let mut location_classes = if include_location_classes {
        finding
            .locations
            .iter()
            .map(|location| {
                format!(
                    "{}={}",
                    location.path.0,
                    enum_string(&location.location_class)
                )
            })
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    location_classes.sort();
    location_classes.dedup();

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
        location_classes,
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
        Evidence::RlsPolicy {
            project,
            table,
            command,
            exposure,
            ..
        } => CanonicalEvidence::RlsPolicy {
            project_url: project.url.clone(),
            table: table.clone(),
            command: command.clone(),
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
        Evidence::RlsPolicy { exposure, .. } => format!("rls:{}", enum_string(exposure)),
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

#[cfg(feature = "network")]
struct MockPostgrest {
    responses: BTreeMap<String, RlsHttpResponse>,
}

#[cfg(feature = "network")]
impl MockPostgrest {
    fn new<const N: usize>(responses: [(&str, RlsHttpResponse); N]) -> Self {
        Self {
            responses: responses
                .into_iter()
                .map(|(url, response)| (url.to_owned(), response))
                .collect(),
        }
    }
}

#[cfg(feature = "network")]
impl RlsHttpClient for MockPostgrest {
    fn get(
        &self,
        url: &str,
        headers: &[(String, String)],
    ) -> Result<RlsHttpResponse, vibescan_supabase::RlsProbeError> {
        assert!(
            headers.iter().any(|(name, value)| {
                name == "apikey" && value == "sb_publishable_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
            }),
            "mock request to {url} must include the public key in apikey"
        );
        self.responses
            .get(url)
            .cloned()
            .ok_or_else(|| vibescan_supabase::RlsProbeError::Http {
                url: url.to_owned(),
                status: None,
                source: "missing mock response".to_owned(),
            })
    }
}
