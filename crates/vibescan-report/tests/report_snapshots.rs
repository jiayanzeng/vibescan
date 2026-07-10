use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use vibescan_report::{ReportFormat, TtyStyle, render, render_tty};
use vibescan_types::{
    Category, Confidence, Evidence, Finding, FindingId, HistoryScope, Location, LocationClass,
    NetworkScope, Provenance, RepoPath, ScanResult, ScanScope, ScanStats, SecretFingerprint,
    Severity, Span,
};

#[test]
fn report_format_snapshots_match() {
    let result = sample_result();
    assert_or_update_snapshot(
        "json.snapshot",
        &render(&result, ReportFormat::Json).unwrap(),
    );
    assert_or_update_snapshot(
        "sarif.snapshot",
        &render(&result, ReportFormat::Sarif).unwrap(),
    );
    assert_or_update_snapshot(
        "html.snapshot",
        &render(&result, ReportFormat::Html).unwrap(),
    );
    assert_or_update_snapshot("tty.snapshot", &render_tty(&result, TtyStyle::Plain));
}

fn assert_or_update_snapshot(name: &str, actual: &str) {
    let path = snapshot_dir().join(name);
    let update = env::var_os("UPDATE_GOLDEN").is_some_and(|value| value == "1");
    if update {
        fs::write(&path, actual)
            .unwrap_or_else(|error| panic!("write {}: {error}", path.display()));
        return;
    }

    let expected = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    assert_eq!(
        expected,
        actual,
        "report snapshot drifted at {}; rerun with UPDATE_GOLDEN=1 to accept",
        path.display()
    );
}

fn snapshot_dir() -> PathBuf {
    workspace_root()
        .join("tests")
        .join("fixtures")
        .join("report-format-snapshots")
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

fn sample_result() -> ScanResult {
    let finding = Finding {
        id: FindingId("snapshot-secret".to_owned()),
        category: Category::SecretExposure,
        severity: Severity::High,
        title: "Secret candidate matched stripe-secret-key".to_owned(),
        detail: "The generic detector found a credential-shaped value.".to_owned(),
        locations: vec![Location {
            path: RepoPath("src/server/billing.ts".to_owned()),
            span: Some(Span {
                line: 3,
                col_start: 17,
                col_end: 57,
            }),
            provenance: Provenance::WorkingTree,
            additional_provenance: Vec::new(),
            location_class: LocationClass::ServerOnly,
        }],
        evidence: Evidence::Secret {
            redacted: "sk_liv...1234".to_owned(),
            fingerprint: SecretFingerprint("snapshot-fingerprint".to_owned()),
        },
        remediation: "Remove the secret from source and rotate it.".to_owned(),
        related: Vec::new(),
        confidence: Confidence::Likely,
    };

    ScanResult {
        findings: vec![finding],
        scope: ScanScope {
            target: "fixtures/report-format-snapshots".to_owned(),
            working_tree: true,
            history: HistoryScope::WorkingTreeOnly,
            network: NetworkScope {
                enabled: false,
                tier0_read_probe: false,
                tier1_introspection: false,
            },
            warnings: Vec::new(),
        },
        tool_version: "snapshot".to_owned(),
        started_at: "2026-01-01T00:00:00Z".to_owned(),
        duration_ms: 42,
        stats: ScanStats::default(),
    }
}
