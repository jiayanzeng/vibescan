use std::collections::BTreeMap;

use vibescan_types::{
    FindingId, LocationClass, NetworkActionIntent, NetworkScope, RepoPath, RlsExposure, ScanScope,
    ScanStats, Span, SupabaseProject,
};

use super::*;

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

#[path = "output.rs"]
mod output_tests;

#[path = "presentation.rs"]
mod presentation_tests;

#[path = "sarif.rs"]
mod sarif_tests;

#[path = "summaries.rs"]
mod summaries_tests;
