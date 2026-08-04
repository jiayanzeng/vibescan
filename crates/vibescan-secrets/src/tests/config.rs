use super::*;

#[test]
fn default_rules_compile() {
    Detector::default_rules().expect("embedded default ruleset compiles");
}

#[test]
fn custom_rules_append_without_replacing_defaults_or_safety_allowlists() {
    let detector = Detector::default_rules_with_custom_toml(
        r#"
            [[rules]]
            id = "custom-service-token"
            kind = "provider_secret"
            regex = '''(custom_[A-Za-z0-9]{24,})'''
            keywords = ["custom_"]
            "#,
    )
    .expect("merged ruleset compiles");

    let unit = working_tree_unit(
        "src/app.ts",
        "const custom = 'custom_abcdefghijklmnopqrstuvwxyz';\nconst supabase = 'sb_secret_0123456789abcdefghijklmnopqrstuvwxyzABCDEF';",
    );
    let candidates = detector.detect_unit(&unit);

    assert!(
        candidates
            .iter()
            .any(|candidate| candidate.rule_id.0 == "custom-service-token")
    );
    assert!(
        candidates
            .iter()
            .any(|candidate| candidate.rule_id.0 == "supabase-secret-key")
    );

    let allowlisted = working_tree_unit(
        ".env.example",
        "const custom = 'custom_abcdefghijklmnopqrstuvwxyz';",
    );
    assert!(detector.detect_unit(&allowlisted).is_empty());
}

#[test]
fn custom_rules_cannot_override_an_embedded_rule_id() {
    let error = Detector::default_rules_with_custom_toml(
        r#"
            [[rules]]
            id = "supabase-secret-key"
            kind = "provider_secret"
            regex = '''(override_[A-Za-z0-9]{24,})'''
            "#,
    )
    .expect_err("duplicate rule id rejected");

    assert!(
        matches!(error, DetectorError::DuplicateRuleId(rule_id) if rule_id == "supabase-secret-key")
    );
}

#[test]
fn configured_allowlist_suppresses_stopword() {
    let detector = Detector::from_toml(
        r#"
            [[rules]]
            id = "toy"
            kind = "provider_secret"
            regex = '''token = "([A-Za-z0-9_]{8,})"'''
            keywords = ["token"]

            [[rules.allowlists]]
            stopwords = ["PLACEHOLDER"]
            "#,
    )
    .expect("ruleset compiles");
    let unit = working_tree_unit("src/app.ts", br#"token = "PLACEHOLDER_TOKEN""#.to_vec());

    assert!(detector.detect_unit(&unit).is_empty());
}

#[test]
fn configured_allowlist_suppresses_commit_id() {
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
    let mut unit = working_tree_unit("src/app.ts", br#"token = "REAL_TOKEN_VALUE""#.to_vec());
    unit.locations[0].provenance = Provenance::Commit {
        sha: "abc123".to_owned(),
        author: None,
        date: None,
    };

    assert!(detector.detect_unit(&unit).is_empty());
}
