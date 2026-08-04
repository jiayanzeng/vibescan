use super::*;
use crate::correlation::generic_candidate_finding;

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
