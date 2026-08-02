use std::collections::BTreeMap;

use vibescan_types::{
    FindingId, LocationClass, NetworkActionIntent, NetworkScope, RepoPath, RlsExposure, ScanScope,
    ScanStats, Span, SupabaseProject,
};

use super::*;

#[test]
fn json_render_is_valid_and_redacted() {
    let mut result = sample_result();
    result.scope.network.actions.push(sample_network_action());
    let rendered = render_json(&result).expect("json renders");
    let value: Value = serde_json::from_str(&rendered).expect("json parses");

    assert_eq!(
        value["findings"][0]["evidence"]["redacted"],
        "sb_sec...CDEF"
    );
    assert!(!rendered.contains("full-secret"));
    assert_eq!(
        value["scope"]["network"]["actions"][0]["outcome"],
        "protected"
    );
    assert!(!rendered.contains("public-key"));
}

#[test]
fn sarif_render_contains_results_and_locations() {
    let mut result = sample_result();
    result.scope.network.actions.push(sample_network_action());
    let rendered = render_sarif(&result).expect("sarif renders");
    let value: Value = serde_json::from_str(&rendered).expect("sarif parses");

    assert_eq!(value["version"], "2.1.0");
    assert_eq!(value["runs"][0]["results"][0]["ruleId"], "finding-1");
    assert_eq!(
        value["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        "src/app.tsx"
    );
    assert_eq!(
        value["runs"][0]["invocations"][0]["properties"]["networkActions"][0]["outcome"],
        "protected"
    );
    assert_eq!(
        value["runs"][0]["invocations"][0]["properties"]["scanStats"]["dedupRatioPercent"],
        "25.00"
    );
}

#[test]
fn tty_render_is_human_readable() {
    let mut result = sample_result();
    result.scope.network.actions.push(sample_network_action());
    let output = render_tty(&result, TtyStyle::Plain);

    assert!(output.contains("[critical] Supabase secret key exposed"));
    assert!(output.contains("remediation: Rotate it."));
    assert!(output.contains("GET table read for table profiles"));
    assert!(output.contains("-> protected; HTTP 403"));
    assert!(output.contains("dedup 25.00%"));
}

#[test]
fn tty_render_surfaces_all_locations_and_history_range() {
    let mut result = sample_result();
    result.findings[0].locations.push(Location {
        path: RepoPath("src/other.ts".to_owned()),
        span: None,
        provenance: Provenance::Commit {
            sha: "1111111111111111111111111111111111111111".to_owned(),
            author: None,
            date: Some("10 +0000".to_owned()),
        },
        additional_provenance: vec![Provenance::Commit {
            sha: "2222222222222222222222222222222222222222".to_owned(),
            author: None,
            date: Some("20 +0000".to_owned()),
        }],
        location_class: LocationClass::ServerOnly,
    });

    let output = render_tty(&result, TtyStyle::Plain);

    assert!(output.contains("src/app.tsx"));
    assert!(output.contains("src/other.ts"));
    assert!(output.contains("first seen commit 111111111111; last seen commit 222222222222"));
}

#[test]
fn html_render_escapes_content() {
    let mut result = sample_result();
    result.findings[0].title = "<script>alert(1)</script>".to_owned();
    let mut action = sample_network_action();
    action.table = Some("<private>".to_owned());
    result.scope.network.actions.push(action);
    let output = render_html(&result);

    assert!(output.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    assert!(!output.contains("<script>alert(1)</script>"));
    assert!(output.contains("Network actions"));
    assert!(output.contains("&lt;private&gt;"));
    assert!(output.contains("dedup: 25.00%"));
}

#[test]
fn exit_code_uses_severity_gate() {
    let result = sample_result();

    assert_eq!(exit_code(&result, Severity::Critical), 1);
    assert_eq!(exit_code(&result, Severity::Info), 1);
    assert_eq!(exit_code(&empty_result(), Severity::Info), 0);

    let mut only_scope_evidence = empty_result();
    only_scope_evidence
        .scope
        .network
        .actions
        .push(sample_network_action());
    assert_eq!(only_scope_evidence.stats, ScanStats::default());
    assert_eq!(exit_code(&only_scope_evidence, Severity::Info), 0);
}

#[test]
fn dependency_evidence_names_both_f2_reasons() {
    for (reason, expected) in [
        (
            vibescan_types::DependencyIntegrityReason::KnownMalicious,
            "KnownMalicious",
        ),
        (
            vibescan_types::DependencyIntegrityReason::NonexistentPackage,
            "NonexistentPackage",
        ),
    ] {
        let summary = evidence_summary(&Evidence::Dependency {
            package: "fixture@1.0.0".to_owned(),
            manifest_path: RepoPath("package.json".to_owned()),
            reason,
        });

        assert!(summary.contains(expected));
        assert!(summary.contains("package.json"));
    }
}

fn sample_network_action() -> NetworkActionAudit {
    NetworkActionAudit {
        kind: NetworkActionKind::TableRead,
        intent: NetworkActionIntent::Get,
        endpoint: "https://abcdefghijklmnopqrst.supabase.co/rest/v1/profiles?select=*&limit=1"
            .to_owned(),
        table: Some("profiles".to_owned()),
        package: None,
        status: Some(403),
        outcome: NetworkActionOutcome::Protected,
        observed_row_count: None,
    }
}

fn sample_result() -> ScanResult {
    let finding = Finding {
        id: FindingId("finding-1".to_owned()),
        category: Category::SecretExposure,
        severity: Severity::Critical,
        title: "Supabase secret key exposed".to_owned(),
        detail: "A secret key was found.".to_owned(),
        locations: vec![Location {
            path: RepoPath("src/app.tsx".to_owned()),
            span: Some(Span {
                line: 3,
                col_start: 10,
                col_end: 30,
            }),
            provenance: Provenance::WorkingTree,
            additional_provenance: Vec::new(),
            location_class: LocationClass::ClientReachable,
        }],
        evidence: Evidence::SupabaseKey {
            class: vibescan_types::SupabaseKeyClass::SecretNew,
            redacted: "sb_sec...CDEF".to_owned(),
            project: Some(SupabaseProject {
                ref_id: Some("abcdefghijklmnopqrst".to_owned()),
                url: "https://abcdefghijklmnopqrst.supabase.co".to_owned(),
            }),
            fingerprint: vibescan_types::SecretFingerprint("abc123".to_owned()),
        },
        remediation: "Rotate it.".to_owned(),
        related: Vec::new(),
        confidence: Confidence::Likely,
    };
    let stats = ScanStats {
        by_severity: BTreeMap::from([(Severity::Critical, 1)]),
        by_category: BTreeMap::from([(Category::SecretExposure, 1)]),
        paths_walked: 40,
        blobs_read: 40,
        unique_contents: 30,
        units_materialized: 30,
        ..ScanStats::default()
    };

    ScanResult {
        findings: vec![finding],
        scope: ScanScope {
            target: ".".to_owned(),
            working_tree: true,
            history: HistoryScope::WorkingTreeOnly,
            network: NetworkScope {
                enabled: false,
                tier0_read_probe: false,
                tier1_introspection: false,
                registry_checks: false,
                registry_newcomer: false,
                registry_name_egress: Vec::new(),
                actions: Vec::new(),
            },
            warnings: vec![ScopeWarning::Other {
                message: "fixture warning".to_owned(),
            }],
        },
        tool_version: "0.1.0".to_owned(),
        started_at: "test".to_owned(),
        duration_ms: 12,
        stats,
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
        tool_version: "0.1.0".to_owned(),
        started_at: "test".to_owned(),
        duration_ms: 0,
        stats: ScanStats::default(),
    }
}

#[allow(dead_code)]
fn rls_evidence() -> Evidence {
    Evidence::RlsProbe {
        project: SupabaseProject {
            ref_id: Some("abcdefghijklmnopqrst".to_owned()),
            url: "https://abcdefghijklmnopqrst.supabase.co".to_owned(),
        },
        table: "profiles".to_owned(),
        endpoint: "https://abcdefghijklmnopqrst.supabase.co/rest/v1/profiles?limit=1".to_owned(),
        observed_row_count: 1,
        exposure: RlsExposure::Exposed,
    }
}
