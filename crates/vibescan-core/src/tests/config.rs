use super::*;

#[test]
fn config_path_allowlists_suppress_docs_but_cannot_hide_env() {
    let repo = TestRepo::new();
    repo.git(["init"]);
    repo.write("vibescan.toml", "[ignore]\npaths = [\"docs/**\", \"**\"]\n");
    repo.write(
        "docs/secret.ts",
        "const key = 'sb_secret_docs0123456789abcdefghijklmnopqrstuvwxyzABCDEF';\n",
    );
    repo.write(
        ".env",
        "SUPABASE_SERVICE_ROLE_KEY=sb_secret_env0123456789abcdefghijklmnopqrstuvwxyzABCDEF\n",
    );

    let config = ScanConfig::load(repo.path()).expect("config loads");
    let result = scan(repo.path(), config).expect("scan succeeds");

    assert!(result.findings.iter().any(|finding| {
        finding
            .locations
            .iter()
            .any(|location| location.path.0 == ".env")
    }));
    assert!(!result.findings.iter().any(|finding| {
        finding
            .locations
            .iter()
            .any(|location| location.path.0 == "docs/secret.ts")
    }));
}

#[test]
fn config_loads_from_repo_root_when_target_is_subdirectory() {
    let repo = TestRepo::new();
    repo.git(["init"]);
    repo.write("vibescan.toml", "[ignore]\npaths = [\"src/**\"]\n");
    repo.write(
        "src/app.ts",
        "const key = 'sb_secret_0123456789abcdefghijklmnopqrstuvwxyzABCDEF';\n",
    );

    let target = repo.path().join("src");
    let config = ScanConfig::load(&target).expect("config loads from repo root");
    let result = scan(&target, config).expect("scan succeeds");

    assert!(result.findings.is_empty());
}

#[test]
fn config_preserves_all_localstatic_values_and_resolves_repo_relative_paths() {
    let repo = TestRepo::new();
    repo.git(["init"]);
    repo.write(
        "vibescan.toml",
        r#"
        [scan]
        working_tree = false
        history = false
        max_commits = 17
        max_bytes = 4096
        severity_gate = "info"

        [baseline]
        path = "config/baseline.json"

        [rules]
        path = "config/custom-rules.toml"
        "#,
    );
    repo.write("config/baseline.json", "[]");
    repo.write("config/custom-rules.toml", "");
    repo.write("src/app.ts", "console.log('clean');\n");

    let config = ScanConfig::load(repo.path().join("src")).expect("config loads");

    assert!(!config.include_working_tree);
    assert!(!config.include_history);
    assert_eq!(config.max_commits, Some(17));
    assert_eq!(config.max_bytes, 4096);
    assert_eq!(config.severity_gate, Severity::Info);
    assert_eq!(
        config.baseline_path,
        Some(repo.path().join("config/baseline.json"))
    );
    assert_eq!(
        config.custom_rules_path,
        Some(repo.path().join("config/custom-rules.toml"))
    );
}

#[test]
fn repository_config_cannot_enable_network_without_runtime_confirmation() {
    let repo = TestRepo::new();
    repo.git(["init"]);
    repo.write(
        "vibescan.toml",
        "[network]\ntier0_read_probe = true\ntier1_introspection = true\nregistry_checks = true\nregistry_newcomer = true\n",
    );

    let config = ScanConfig::load(repo.path()).expect("config loads");

    assert!(!config.tier0_read_probe);
    assert!(!config.tier1_introspection);
    assert!(!config.registry_checks);
    assert!(!config.registry_newcomer);
}

#[test]
fn repository_path_resolution_preserves_absolute_paths() {
    let repo = TestRepo::new();
    repo.git(["init"]);
    let absolute = repo.path().join("outside-name.json");

    let resolved = resolve_repository_path(repo.path(), &absolute).expect("path resolves");

    assert_eq!(resolved, absolute);
}

#[test]
fn invalid_configured_severity_is_rejected() {
    let repo = TestRepo::new();
    repo.git(["init"]);
    repo.write("vibescan.toml", "[scan]\nseverity_gate = \"urgent\"\n");

    let error = ScanConfig::load(repo.path()).expect_err("invalid severity rejected");

    assert!(matches!(error, CoreError::InvalidSeverity(value) if value == "urgent"));
}
