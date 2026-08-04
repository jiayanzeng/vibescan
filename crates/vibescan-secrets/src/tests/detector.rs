use super::*;

#[test]
fn detects_supabase_new_key_shapes() {
    let findings = detect(
        "const url = 'https://x.supabase.co';\n\
             const anon = 'sb_publishable_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789';\n\
             const secret = 'sb_secret_0123456789abcdefghijklmnopqrstuvwxyzABCDEF';\n",
    );

    let rule_ids = findings
        .iter()
        .map(|candidate| candidate.rule_id.0.as_str())
        .collect::<BTreeSet<_>>();

    assert!(rule_ids.contains("supabase-publishable-key"));
    assert!(rule_ids.contains("supabase-secret-key"));
    assert!(
        findings
            .iter()
            .all(|candidate| candidate.kind == CandidateKind::PossibleSupabaseKey)
    );
}

#[test]
fn applies_entropy_gate_to_generic_assignments() {
    let noisy = detect("const token = 'abcdefghijklmnopqrstuvwxyzABCDEFG1234567890';");
    let placeholder = detect("const token = 'example-example-example-example';");

    assert!(
        noisy
            .iter()
            .any(|candidate| candidate.rule_id.0 == "generic-high-entropy-assignment")
    );
    assert!(
        !placeholder
            .iter()
            .any(|candidate| candidate.rule_id.0 == "generic-high-entropy-assignment")
    );
}

#[test]
fn generic_entropy_skips_minified_lines_but_provider_rules_still_fire() {
    let detector = Detector::default_rules().expect("default rules compile");
    let generic_line = format!(
        "var props={};const token='abcdefghijklmnopqrstuvwxyzABCDEFG1234567890';",
        "x".repeat(520)
    );
    let unit = working_tree_unit(".next/static/chunks/prop-types.js", generic_line);

    assert!(
        !detector
            .detect_unit(&unit)
            .iter()
            .any(|candidate| candidate.rule_id.0 == "generic-high-entropy-assignment")
    );

    let provider_line = format!(
        "var bundle={};const stripe='sk_live_abcdefghijklmnopqrstuvwxyz123456';",
        "x".repeat(520)
    );
    let unit = working_tree_unit(".next/static/chunks/app.js", provider_line);

    assert!(
        detector
            .detect_unit(&unit)
            .iter()
            .any(|candidate| candidate.rule_id.0 == "stripe-secret-key")
    );
}

#[test]
fn inline_allow_suppresses_line() {
    let findings =
        detect("const key = 'sk-proj-abcdefghijklmnopqrstuvwxyz1234567890'; // vibescan:allow");

    assert!(findings.is_empty());
}

#[test]
fn path_allowlist_removes_only_the_matching_source_occurrence() {
    let detector = Detector::from_toml(
        r#"
            [[rules]]
            id = "toy"
            kind = "provider_secret"
            regex = '''token = "([A-Za-z0-9_]{8,})"'''
            keywords = ["token"]
            path_allowlist = ["^docs/"]
            "#,
    )
    .expect("ruleset compiles");
    let mut unit = working_tree_unit("docs/example.ts", br#"token = "REAL_TOKEN_VALUE""#.to_vec());
    unit.locations.push(UnitLocation {
        path: RepoPath("src/config.ts".to_owned()),
        provenance: Provenance::WorkingTree,
        additional_provenance: Vec::new(),
        location_class: LocationClass::ServerOnly,
    });

    let candidates = detector.detect_unit(&unit);

    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].unit_ref.locations.len(), 1);
    assert_eq!(candidates[0].unit_ref.locations[0].path.0, "src/config.ts");
}

#[test]
fn commit_allowlist_removes_only_the_matching_source_occurrence() {
    let detector = Detector::from_toml(
        r#"
            [[rules]]
            id = "toy"
            kind = "provider_secret"
            regex = '''token = "([A-Za-z0-9_]{8,})"'''
            keywords = ["token"]

            [[rules.allowlists]]
            commits = ["abc123"]
            "#,
    )
    .expect("ruleset compiles");
    let mut unit = working_tree_unit("src/current.ts", br#"token = "REAL_TOKEN_VALUE""#.to_vec());
    unit.locations.push(UnitLocation {
        path: RepoPath("src/history.ts".to_owned()),
        provenance: Provenance::Commit {
            sha: "abc123".to_owned(),
            author: None,
            date: None,
        },
        additional_provenance: Vec::new(),
        location_class: LocationClass::Unknown,
    });

    let candidates = detector.detect_unit(&unit);

    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].unit_ref.locations.len(), 1);
    assert_eq!(candidates[0].unit_ref.locations[0].path.0, "src/current.ts");
}

#[test]
fn parallel_unit_detection_matches_serial_results() {
    let detector = Detector::default_rules().expect("default rules compile");
    let units = (0..128)
        .map(|index| {
            let content = if index % 2 == 0 {
                format!(
                    "const key{index} = 'sb_secret_{index:04}abcdefghijklmnopqrstuvwxyzABCDEF';\n"
                )
            } else {
                format!("const stripe{index} = 'sk_live_abcdefghijklmnopqrstuvwxyz{index:06}';\n")
            };
            working_tree_unit(format!("src/file-{index}.ts"), content)
        })
        .collect::<Vec<_>>();

    let serial = candidate_snapshot(detector.detect_units_serial(&units));
    let parallel = candidate_snapshot(detector.detect_units(&units));

    assert_eq!(parallel, serial);
}

#[test]
fn reports_one_based_spans() {
    let findings = detect("const key = 'sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890';");
    let anthropic = findings
        .iter()
        .find(|candidate| candidate.rule_id.0 == "anthropic-api-key")
        .expect("anthropic key detected");

    assert_eq!(anthropic.span.line, 1);
    assert!(anthropic.span.col_start > 1);
    assert!(anthropic.span.col_end > anthropic.span.col_start);
}
