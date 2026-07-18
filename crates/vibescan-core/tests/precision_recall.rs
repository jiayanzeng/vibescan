mod common;

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use common::{
    LIVE_FIXTURES, TIER1_FIXTURES, fixture_dir, materialize_fixture, offline_composite_findings,
    tier1_fixture_findings,
};
use serde::{Deserialize, Serialize};
use vibescan_core::{ScanConfig, scan};
use vibescan_types::{Category, Evidence, Finding, LocationClass, Severity};

const CORPUS_VERSION: &str = "tier-e3-live-v1";
const CLEAN_CONTROL: &str = "clean-control";
const OFFLINE_COMPOSITE: &str = "offline-composite-exposed-public-key-chain";

#[derive(Clone, Debug, Deserialize)]
struct ExpectedManifest {
    findings: Vec<ExpectedFinding>,
}

#[derive(Clone, Debug, Deserialize)]
struct ExpectedFinding {
    rule_id: String,
    evidence: ExpectedEvidence,
    #[serde(default)]
    truth: Option<TruthIdentity>,
}

#[derive(Clone, Debug, Deserialize)]
struct TruthIdentity {
    fingerprint: String,
    #[serde(default)]
    project: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ExpectedEvidence {
    Secret {
        fingerprint: String,
    },
    SupabaseKey {
        project_url: Option<String>,
        fingerprint: String,
    },
    RlsProbe {
        project_url: String,
        table: String,
    },
    RlsPolicy {
        project_url: String,
        table: String,
        command: String,
    },
    Dependency {
        package: String,
    },
    Correlation {
        rule_id: String,
    },
    Note {
        message: String,
    },
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct StableIdentity {
    rule_id: String,
    fingerprint: String,
    project: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
struct MetricsReport {
    corpus_version: String,
    totals: TotalMetrics,
    per_fixture: BTreeMap<String, FixtureMetrics>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
struct TotalMetrics {
    tp: u64,
    fp: u64,
    #[serde(rename = "fn")]
    fn_count: u64,
    precision: f64,
    recall: f64,
    coverage: f64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct FixtureMetrics {
    expected: u64,
    observed: u64,
    tp: u64,
    fp: u64,
    #[serde(rename = "fn")]
    fn_count: u64,
}

#[test]
fn live_corpus_metrics_match_committed_baseline() {
    let report = compute_report();
    assert_eq!(
        report.totals.coverage, 0.75,
        "classification coverage should be exactly 6/8: Tier 1 adds three classified policy advisories while the two Unknown findings remain the intentionally generic src/history.ts and packages/nested/ignored-but-scanned/secret.ts paths"
    );

    let path = baseline_path();
    let baseline_content = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    let baseline = serde_json::from_str::<MetricsReport>(&baseline_content)
        .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()));
    assert_hard_gates(&report, &baseline).unwrap_or_else(|error| panic!("{error}"));

    let actual_content = serialize_report(&report);
    if update_metrics() {
        fs::write(&path, &actual_content)
            .unwrap_or_else(|error| panic!("write {}: {error}", path.display()));
        return;
    }

    assert_eq!(
        report,
        baseline,
        "corpus metrics drifted at {}; rerun with UPDATE_METRICS=1 only for an intentional reviewed change\n\ncommitted baseline:\n{}\ncomputed report:\n{}",
        path.display(),
        baseline_content.trim_end(),
        actual_content.trim_end()
    );
}

#[test]
fn bogus_expected_identity_is_an_fn_and_trips_the_recall_gate() {
    let real = test_identity("real");
    let bogus = test_identity("bogus");
    let fixture = measure_fixture(&[real.clone(), bogus], &[real]);
    assert_eq!(fixture.fn_count, 1);

    let report = test_report("perturbed-fixture", fixture);
    let baseline = test_report(
        "perturbed-fixture",
        FixtureMetrics {
            expected: 2,
            observed: 2,
            tp: 2,
            fp: 0,
            fn_count: 0,
        },
    );
    assert_eq!(report.totals.recall, 0.5);
    let error = assert_hard_gates(&report, &baseline).expect_err("recall regression must fail");
    assert!(
        error.contains("recall decreased"),
        "unexpected error: {error}"
    );
}

#[test]
fn injected_clean_control_fp_fails_independently_of_baseline_rates() {
    let clean = measure_fixture(&[], &[test_identity("injected-fp")]);
    assert_eq!(clean.fp, 1);

    let report = test_report(CLEAN_CONTROL, clean);
    let mut baseline = test_report(
        CLEAN_CONTROL,
        FixtureMetrics {
            expected: 0,
            observed: 0,
            tp: 0,
            fp: 0,
            fn_count: 0,
        },
    );
    baseline.totals.precision = 0.0;
    baseline.totals.recall = 0.0;
    let error =
        assert_hard_gates(&report, &baseline).expect_err("clean-control FP must always fail");
    assert!(
        error.contains("clean-control false positives: expected 0, got 1"),
        "unexpected error: {error}"
    );
}

fn compute_report() -> MetricsReport {
    let mut per_fixture = BTreeMap::new();
    let mut coverage_classified = 0_u64;
    let mut coverage_total = 0_u64;

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
        let expected = read_expected_identities(fixture.name);
        let observed = result
            .findings
            .iter()
            .map(observed_identity)
            .collect::<Vec<_>>();
        let (classified, eligible) = classification_coverage(&result.findings);
        coverage_classified += classified;
        coverage_total += eligible;
        per_fixture.insert(
            fixture.name.to_owned(),
            measure_fixture(&expected, &observed),
        );
    }

    let composite_findings = offline_composite_findings();
    let expected = read_expected_identities(OFFLINE_COMPOSITE);
    let observed = composite_findings
        .iter()
        .map(observed_identity)
        .collect::<Vec<_>>();
    let (classified, eligible) = classification_coverage(&composite_findings);
    coverage_classified += classified;
    coverage_total += eligible;
    per_fixture.insert(
        OFFLINE_COMPOSITE.to_owned(),
        measure_fixture(&expected, &observed),
    );

    for name in TIER1_FIXTURES {
        let findings = tier1_fixture_findings(name);
        let expected = read_expected_identities(name);
        let observed = findings.iter().map(observed_identity).collect::<Vec<_>>();
        let (classified, eligible) = classification_coverage(&findings);
        coverage_classified += classified;
        coverage_total += eligible;
        per_fixture.insert((*name).to_owned(), measure_fixture(&expected, &observed));
    }

    report_from_metrics(per_fixture, ratio(coverage_classified, coverage_total))
}

fn read_expected_identities(name: &str) -> Vec<StableIdentity> {
    let path = fixture_dir(name).join("expected.json");
    let content = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    let manifest = serde_json::from_str::<ExpectedManifest>(&content)
        .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()));
    manifest.findings.iter().map(expected_identity).collect()
}

fn expected_identity(finding: &ExpectedFinding) -> StableIdentity {
    if let Some(truth) = &finding.truth {
        return StableIdentity {
            rule_id: finding.rule_id.clone(),
            fingerprint: truth.fingerprint.clone(),
            project: truth
                .project
                .as_deref()
                .map(normalized_project_url)
                .unwrap_or_default(),
        };
    }

    let (fingerprint, project) = match &finding.evidence {
        ExpectedEvidence::Secret { fingerprint } => (fingerprint.clone(), String::new()),
        ExpectedEvidence::SupabaseKey {
            project_url,
            fingerprint,
        } => (
            fingerprint.clone(),
            project_url
                .as_deref()
                .map(normalized_project_url)
                .unwrap_or_default(),
        ),
        ExpectedEvidence::RlsProbe { project_url, table } => {
            (format!("rls:{table}"), normalized_project_url(project_url))
        }
        ExpectedEvidence::RlsPolicy {
            project_url,
            table,
            command,
        } => (
            format!("rls:{table}:{command}"),
            normalized_project_url(project_url),
        ),
        ExpectedEvidence::Dependency { package } => {
            (format!("dependency:{package}"), String::new())
        }
        ExpectedEvidence::Correlation { rule_id } => {
            (format!("correlation:{rule_id}"), String::new())
        }
        ExpectedEvidence::Note { message } => (format!("note:{message}"), String::new()),
    };
    StableIdentity {
        rule_id: finding.rule_id.clone(),
        fingerprint,
        project,
    }
}

fn observed_identity(finding: &Finding) -> StableIdentity {
    let rule_id = finding_rule_id(finding);
    let (fingerprint, project) = match &finding.evidence {
        Evidence::Secret { fingerprint, .. } => (fingerprint.0.clone(), String::new()),
        Evidence::SupabaseKey {
            project,
            fingerprint,
            ..
        } => (
            fingerprint.0.clone(),
            project
                .as_ref()
                .map(|project| normalized_project_url(&project.url))
                .unwrap_or_default(),
        ),
        Evidence::RlsProbe { project, table, .. } => {
            (format!("rls:{table}"), normalized_project_url(&project.url))
        }
        Evidence::RlsPolicy {
            project,
            table,
            command,
            ..
        } => (
            format!("rls:{table}:{command}"),
            normalized_project_url(&project.url),
        ),
        Evidence::Dependency { package, .. } => (format!("dependency:{package}"), String::new()),
        Evidence::Correlation {
            rule_id,
            reproduction,
        } => correlation_subject(&rule_id.0, reproduction.as_deref()),
        Evidence::Note { message } => (format!("note:{message}"), String::new()),
    };
    StableIdentity {
        rule_id,
        fingerprint,
        project,
    }
}

fn finding_rule_id(finding: &Finding) -> String {
    match &finding.evidence {
        Evidence::Secret { .. } => "generic-secret".to_owned(),
        Evidence::SupabaseKey { class, .. } => {
            format!("supabase-key:{}", enum_string(class))
        }
        Evidence::RlsProbe { exposure, .. } => format!("rls:{}", enum_string(exposure)),
        Evidence::RlsPolicy { exposure, .. } => format!("rls:{}", enum_string(exposure)),
        Evidence::Dependency { reason, .. } => format!("dependency:{}", enum_string(reason)),
        Evidence::Correlation { rule_id, .. } => rule_id.0.clone(),
        Evidence::Note { .. } => "note".to_owned(),
    }
}

fn correlation_subject(rule_id: &str, reproduction: Option<&str>) -> (String, String) {
    if let Some(table) = reproduction
        .and_then(|value| value.strip_prefix("table "))
        .and_then(|value| value.split_once(" has ").map(|parts| parts.0))
    {
        return (format!("correlation:{rule_id}:{table}"), String::new());
    }

    let Some(endpoint) = reproduction.and_then(|value| value.split_once(" returned").map(|v| v.0))
    else {
        return (format!("correlation:{rule_id}"), String::new());
    };
    let Some((project, table_and_query)) = endpoint.split_once("/rest/v1/") else {
        return (format!("correlation:{rule_id}"), String::new());
    };
    let table = table_and_query.split('?').next().unwrap_or(table_and_query);
    (
        format!("correlation:{rule_id}:{table}"),
        normalized_project_url(project),
    )
}

fn measure_fixture(expected: &[StableIdentity], observed: &[StableIdentity]) -> FixtureMetrics {
    let expected_counts = identity_counts(expected);
    let observed_counts = identity_counts(observed);
    let tp = expected_counts
        .iter()
        .map(|(identity, expected_count)| {
            (*expected_count).min(observed_counts.get(identity).copied().unwrap_or(0))
        })
        .sum();
    let expected_total = expected.len() as u64;
    let observed_total = observed.len() as u64;
    FixtureMetrics {
        expected: expected_total,
        observed: observed_total,
        tp,
        fp: observed_total - tp,
        fn_count: expected_total - tp,
    }
}

fn identity_counts(identities: &[StableIdentity]) -> BTreeMap<&StableIdentity, u64> {
    let mut counts = BTreeMap::new();
    for identity in identities {
        *counts.entry(identity).or_insert(0) += 1;
    }
    counts
}

fn classification_coverage(findings: &[Finding]) -> (u64, u64) {
    findings
        .iter()
        .filter(|finding| {
            matches!(
                finding.category,
                Category::SecretExposure | Category::KeyClassification | Category::Rls
            )
        })
        .fold((0, 0), |(classified, total), finding| {
            let has_classified_location = finding
                .locations
                .iter()
                .any(|location| location.location_class != LocationClass::Unknown);
            (classified + u64::from(has_classified_location), total + 1)
        })
}

fn assert_hard_gates(report: &MetricsReport, baseline: &MetricsReport) -> Result<(), String> {
    let clean = report
        .per_fixture
        .get(CLEAN_CONTROL)
        .ok_or_else(|| "clean-control metrics missing".to_owned())?;
    if clean.fp != 0 {
        return Err(format!(
            "clean-control false positives: expected 0, got {}",
            clean.fp
        ));
    }
    if report.totals.precision < baseline.totals.precision {
        return Err(format!(
            "precision decreased from {} to {}",
            baseline.totals.precision, report.totals.precision
        ));
    }
    if report.totals.recall < baseline.totals.recall {
        return Err(format!(
            "recall decreased from {} to {}",
            baseline.totals.recall, report.totals.recall
        ));
    }
    Ok(())
}

fn report_from_metrics(
    per_fixture: BTreeMap<String, FixtureMetrics>,
    coverage: f64,
) -> MetricsReport {
    let tp = per_fixture.values().map(|metrics| metrics.tp).sum();
    let fp = per_fixture.values().map(|metrics| metrics.fp).sum();
    let fn_count = per_fixture.values().map(|metrics| metrics.fn_count).sum();
    MetricsReport {
        corpus_version: CORPUS_VERSION.to_owned(),
        totals: TotalMetrics {
            tp,
            fp,
            fn_count,
            precision: ratio(tp, tp + fp),
            recall: ratio(tp, tp + fn_count),
            coverage,
        },
        per_fixture,
    }
}

fn ratio(numerator: u64, denominator: u64) -> f64 {
    if denominator == 0 {
        1.0
    } else {
        numerator as f64 / denominator as f64
    }
}

fn normalized_project_url(url: &str) -> String {
    let trimmed = url.trim().trim_end_matches('/');
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

fn enum_string<T: Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .expect("enum serializes")
        .as_str()
        .expect("enum serializes to string")
        .to_owned()
}

fn serialize_report(report: &MetricsReport) -> String {
    format!(
        "{}\n",
        serde_json::to_string_pretty(report).expect("metrics report serializes")
    )
}

fn update_metrics() -> bool {
    env::var_os("UPDATE_METRICS").is_some_and(|value| value == "1")
}

fn baseline_path() -> PathBuf {
    workspace_root()
        .join("tests")
        .join("fixtures")
        .join("corpus-metrics-baseline.json")
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

fn test_identity(fingerprint: &str) -> StableIdentity {
    StableIdentity {
        rule_id: "test-rule".to_owned(),
        fingerprint: fingerprint.to_owned(),
        project: String::new(),
    }
}

fn test_report(name: &str, fixture: FixtureMetrics) -> MetricsReport {
    let mut per_fixture = BTreeMap::from([(
        CLEAN_CONTROL.to_owned(),
        FixtureMetrics {
            expected: 0,
            observed: 0,
            tp: 0,
            fp: 0,
            fn_count: 0,
        },
    )]);
    if name == CLEAN_CONTROL {
        per_fixture.insert(CLEAN_CONTROL.to_owned(), fixture);
    } else {
        per_fixture.insert(name.to_owned(), fixture);
    }
    report_from_metrics(per_fixture, 1.0)
}
