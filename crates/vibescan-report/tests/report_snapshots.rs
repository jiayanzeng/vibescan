use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use vibescan_report::{ReportFormat, TtyStyle, render, render_tty};
use vibescan_types::{
    Category, Confidence, Evidence, Finding, FindingId, HistoryScope, Location, LocationClass,
    NetworkActionAudit, NetworkActionIntent, NetworkActionKind, NetworkActionOutcome, NetworkScope,
    Provenance, RepoPath, RlsExposure, ScanResult, ScanScope, ScanStats, SecretFingerprint,
    Severity, Span, SupabaseProject,
};

const REDACTED_SECRET: &str = "sk_liv...1234";

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

#[test]
fn every_format_renders_the_redacted_evidence() {
    let result = sample_result();
    let rendered = [
        ("JSON", render(&result, ReportFormat::Json).unwrap()),
        ("SARIF", render(&result, ReportFormat::Sarif).unwrap()),
        ("HTML", render(&result, ReportFormat::Html).unwrap()),
        ("TTY", render_tty(&result, TtyStyle::Plain)),
    ];

    for (format, output) in rendered {
        assert!(
            output.contains(REDACTED_SECRET),
            "{format} did not render the redacted evidence"
        );
    }
}

#[test]
fn every_format_renders_the_rls_policy_reproduction() {
    let result = sample_result();
    let rendered = [
        ("JSON", render(&result, ReportFormat::Json).unwrap()),
        ("SARIF", render(&result, ReportFormat::Sarif).unwrap()),
        ("HTML", render(&result, ReportFormat::Html).unwrap()),
        ("TTY", render_tty(&result, TtyStyle::Plain)),
    ];

    for (format, output) in rendered {
        assert!(
            output.contains("(true)"),
            "{format} did not render the policy predicate"
        );
        assert!(
            output.to_ascii_lowercase().contains("permissive"),
            "{format} did not render the policy exposure"
        );
    }
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
    let secret_finding = Finding {
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
            redacted: REDACTED_SECRET.to_owned(),
            fingerprint: SecretFingerprint("snapshot-fingerprint".to_owned()),
        },
        remediation: "Remove the secret from source and rotate it.".to_owned(),
        related: Vec::new(),
        confidence: Confidence::Likely,
    };
    let rls_finding = Finding {
        id: FindingId("snapshot-rls-policy".to_owned()),
        category: Category::Rls,
        severity: Severity::Critical,
        title: "Supabase table profiles has a literal-true SELECT policy".to_owned(),
        detail: "Credentialed Tier 1 catalog introspection confirmed a permissive policy whose USING predicate is the literal true.".to_owned(),
        locations: vec![Location {
            path: RepoPath("supabase/policies.sql".to_owned()),
            span: None,
            provenance: Provenance::WorkingTree,
            additional_provenance: Vec::new(),
            location_class: LocationClass::ServerOnly,
        }],
        evidence: Evidence::RlsPolicy {
            project: SupabaseProject {
                ref_id: Some("abcdefghijklmnopqrst".to_owned()),
                url: "https://abcdefghijklmnopqrst.supabase.co".to_owned(),
            },
            table: "profiles".to_owned(),
            command: "SELECT".to_owned(),
            using_expr: Some("(true)".to_owned()),
            check_expr: None,
            rowsecurity: true,
            exposure: RlsExposure::PermissivePolicy,
        },
        remediation: "Replace the literal-true predicate with a least-privilege condition."
            .to_owned(),
        related: Vec::new(),
        confidence: Confidence::Confirmed,
    };

    ScanResult {
        findings: vec![secret_finding, rls_finding],
        scope: ScanScope {
            target: "fixtures/report-format-snapshots".to_owned(),
            working_tree: true,
            history: HistoryScope::WorkingTreeOnly,
            network: NetworkScope {
                enabled: true,
                tier0_read_probe: true,
                tier1_introspection: true,
                actions: vec![
                    NetworkActionAudit {
                        kind: NetworkActionKind::RootEnumeration,
                        intent: NetworkActionIntent::Get,
                        endpoint: "https://abcdefghijklmnopqrst.supabase.co/rest/v1/".to_owned(),
                        table: None,
                        status: Some(200),
                        outcome: NetworkActionOutcome::RootEnumerated,
                        observed_row_count: None,
                    },
                    NetworkActionAudit {
                        kind: NetworkActionKind::TableRead,
                        intent: NetworkActionIntent::Get,
                        endpoint: "https://abcdefghijklmnopqrst.supabase.co/rest/v1/private_profiles?select=*&limit=1".to_owned(),
                        table: Some("private_profiles".to_owned()),
                        status: Some(403),
                        outcome: NetworkActionOutcome::Protected,
                        observed_row_count: None,
                    },
                    NetworkActionAudit {
                        kind: NetworkActionKind::TableRead,
                        intent: NetworkActionIntent::Get,
                        endpoint: "https://abcdefghijklmnopqrst.supabase.co/rest/v1/public_profiles?select=*&limit=1".to_owned(),
                        table: Some("public_profiles".to_owned()),
                        status: Some(200),
                        outcome: NetworkActionOutcome::Exposed,
                        observed_row_count: Some(1),
                    },
                    NetworkActionAudit {
                        kind: NetworkActionKind::CatalogIntrospection,
                        intent: NetworkActionIntent::Select,
                        endpoint: "db.abcdefghijklmnopqrst.supabase.co:5432".to_owned(),
                        table: Some("profiles".to_owned()),
                        status: None,
                        outcome: NetworkActionOutcome::CatalogRead,
                        observed_row_count: None,
                    },
                ],
            },
            warnings: Vec::new(),
        },
        tool_version: "snapshot".to_owned(),
        started_at: "2026-01-01T00:00:00Z".to_owned(),
        duration_ms: 42,
        stats: ScanStats {
            by_severity: BTreeMap::from([(Severity::Critical, 1), (Severity::High, 1)]),
            by_category: BTreeMap::from([
                (Category::SecretExposure, 1),
                (Category::Rls, 1),
            ]),
            paths_walked: 40,
            blobs_read: 40,
            unique_contents: 30,
            units_materialized: 30,
            ..ScanStats::default()
        },
    }
}
