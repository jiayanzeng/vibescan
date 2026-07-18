use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn absent_cli_scope_flags_preserve_toml_values() {
    let repo = TestRepo::new();
    repo.write("vibescan.toml", "[scan]\nhistory = false\n");

    let output = vibescan(repo.path(), &[]);

    assert!(output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("history disabled"),
        "stdout was: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn explicit_cli_scope_flag_overrides_toml_value() {
    let repo = TestRepo::new();
    repo.write("vibescan.toml", "[scan]\nhistory = true\n");

    let output = vibescan(repo.path(), &["--no-history"]);

    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("history disabled"));
}

#[test]
fn explicit_enable_flags_override_disabled_toml_scopes() {
    let repo = TestRepo::new();
    repo.write(
        "vibescan.toml",
        "[scan]\nhistory = false\nworking_tree = false\n",
    );
    repo.write(
        "src/app.ts",
        "const key = 'sb_secret_0123456789abcdefghijklmnopqrstuvwxyzABCDEF';\n",
    );

    let output = vibescan(repo.path(), &["--history", "--working-tree"]);

    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("history budgeted"), "stdout was: {stdout}");
    assert!(
        stdout.contains("Supabase secret key"),
        "stdout was: {stdout}"
    );
}

#[test]
fn explicit_disable_flag_overrides_enabled_working_tree_config() {
    let repo = TestRepo::new();
    repo.write(
        "vibescan.toml",
        "[scan]\nhistory = false\nworking_tree = true\n",
    );
    repo.write(
        "src/app.ts",
        "const key = 'sb_secret_0123456789abcdefghijklmnopqrstuvwxyzABCDEF';\n",
    );

    let output = vibescan(repo.path(), &["--no-working-tree"]);

    assert!(output.status.success());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("Supabase secret key"));
}

#[test]
fn configured_severity_is_preserved_and_explicit_cli_value_wins() {
    let repo = TestRepo::new();
    repo.write(
        "vibescan.toml",
        "[scan]\nhistory = false\nseverity_gate = \"info\"\n",
    );
    repo.write(
        "src/app.ts",
        "const key = 'sb_publishable_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789';\n",
    );

    let configured = vibescan(repo.path(), &[]);
    let overridden = vibescan(repo.path(), &["--severity-gate", "high"]);

    assert_eq!(configured.status.code(), Some(1));
    assert!(overridden.status.success());
}

#[test]
fn repository_network_config_alone_never_enables_a_request() {
    let repo = TestRepo::new();
    repo.write(
        "vibescan.toml",
        "[scan]\nhistory = false\n[network]\ntier0_read_probe = true\ntier1_introspection = true\nregistry_checks = true\nregistry_newcomer = true\n",
    );

    let output = vibescan(repo.path(), &[]);

    assert!(output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("network: disabled"),
        "stdout was: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[cfg(feature = "registry")]
#[test]
fn registry_flag_does_not_enable_either_rls_tier() {
    let repo = TestRepo::new();
    let output = vibescan(
        repo.path(),
        &["--format", "json", "--registry-checks", "--no-history"],
    );

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"registry_checks\": true"));
    assert!(stdout.contains("\"tier0_read_probe\": false"));
    assert!(stdout.contains("\"tier1_introspection\": false"));
    assert!(stdout.contains("\"registry_name_egress\": []"));
}

#[cfg(not(feature = "registry"))]
#[test]
fn registry_flag_without_feature_is_a_clear_operational_error() {
    let repo = TestRepo::new();
    let output = vibescan(repo.path(), &["--registry-checks"]);

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unexpected argument '--registry-checks'"));
}

#[cfg(feature = "network")]
#[test]
fn tier1_flag_without_env_credential_is_an_operational_error() {
    let repo = TestRepo::new();
    let output = Command::new(env!("CARGO_BIN_EXE_vibescan"))
        .arg(repo.path())
        .arg("--rls-tier1-introspect")
        .env_remove("VIBESCAN_SUPABASE_DB_URL")
        .output()
        .expect("vibescan binary runs");

    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("VIBESCAN_SUPABASE_DB_URL"));
}

#[cfg(feature = "network")]
#[test]
fn tier0_flag_does_not_require_or_enable_tier1() {
    let repo = TestRepo::new();
    let output = Command::new(env!("CARGO_BIN_EXE_vibescan"))
        .arg(repo.path())
        .args(["--format", "json", "--rls-tier0-read-probe"])
        .env_remove("VIBESCAN_SUPABASE_DB_URL")
        .output()
        .expect("vibescan binary runs");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"tier0_read_probe\": true"));
    assert!(stdout.contains("\"tier1_introspection\": false"));
    assert!(stdout.contains("\"registry_checks\": false"));
}

#[test]
fn missing_explicit_baseline_is_an_operational_error() {
    let repo = TestRepo::new();

    let output = vibescan(repo.path(), &["--baseline", "missing-baseline.json"]);

    assert_eq!(output.status.code(), Some(2));
    assert!(!output.stderr.is_empty());
}

#[test]
fn missing_configured_baseline_is_an_operational_error() {
    let repo = TestRepo::new();
    repo.write(
        "vibescan.toml",
        "[baseline]\npath = \"missing-baseline.json\"\n",
    );

    let output = vibescan(repo.path(), &[]);

    assert_eq!(output.status.code(), Some(2));
    assert!(!output.stderr.is_empty());
}

#[test]
fn relative_cli_baseline_suppresses_a_real_synthetic_finding() {
    let repo = TestRepo::new();
    repo.write(
        "src/app.ts",
        "const stripe = 'sk_live_abcdefghijklmnopqrstuvwxyz123456';\n",
    );
    let first = vibescan(repo.path(), &["--format", "json", "--no-history"]);
    assert_eq!(first.status.code(), Some(1));
    repo.write_bytes("baselines/current.json", &first.stdout);

    let suppressed = vibescan(
        repo.path(),
        &[
            "--format",
            "json",
            "--no-history",
            "--baseline",
            "baselines/current.json",
        ],
    );

    assert!(suppressed.status.success());
    let stdout = String::from_utf8_lossy(&suppressed.stdout);
    assert!(stdout.contains("\"findings\": []"), "stdout was: {stdout}");
}

#[test]
fn relative_configured_baseline_suppresses_a_real_synthetic_finding() {
    let repo = TestRepo::new();
    repo.write(
        "src/app.ts",
        "const stripe = 'sk_live_abcdefghijklmnopqrstuvwxyz123456';\n",
    );
    let first = vibescan(repo.path(), &["--format", "json", "--no-history"]);
    assert_eq!(first.status.code(), Some(1));
    repo.write_bytes("config/current-baseline.json", &first.stdout);
    repo.write(
        "vibescan.toml",
        "[scan]\nhistory = false\n[baseline]\npath = \"config/current-baseline.json\"\n",
    );

    let suppressed = vibescan(repo.path(), &["--format", "json"]);

    assert!(suppressed.status.success());
    let stdout = String::from_utf8_lossy(&suppressed.stdout);
    assert!(stdout.contains("\"findings\": []"), "stdout was: {stdout}");
}

#[test]
fn configured_custom_rules_are_repo_relative_and_additive() {
    let repo = TestRepo::new();
    repo.write(
        "vibescan.toml",
        "[scan]\nhistory = false\n[rules]\npath = \"config/custom-rules.toml\"\n",
    );
    repo.write(
        "config/custom-rules.toml",
        r#"
        [[rules]]
        id = "custom-service-token"
        kind = "provider_secret"
        regex = '''(custom_[A-Za-z0-9]{24,})'''
        keywords = ["custom_"]
        "#,
    );
    repo.write(
        "src/app.ts",
        "const custom = 'custom_abcdefghijklmnopqrstuvwxyz';\nconst supabase = 'sb_secret_0123456789abcdefghijklmnopqrstuvwxyzABCDEF';\n",
    );

    let output = vibescan(repo.path(), &["--severity-gate", "info"]);

    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("custom-service-token"),
        "stdout was: {stdout}"
    );
    assert!(
        stdout.contains("Supabase secret key"),
        "stdout was: {stdout}"
    );
}

#[test]
fn missing_configured_custom_rules_are_an_operational_error() {
    let repo = TestRepo::new();
    repo.write(
        "vibescan.toml",
        "[rules]\npath = \"config/missing-rules.toml\"\n",
    );

    let output = vibescan(repo.path(), &[]);

    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("custom rules"));
}

fn vibescan(repo: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_vibescan"))
        .arg(repo)
        .args(args)
        .output()
        .expect("vibescan binary runs")
}

struct TestRepo {
    path: PathBuf,
}

impl TestRepo {
    fn new() -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock works")
            .as_nanos();
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "vibescan-cli-phase0-test-{}-{nonce}-{id}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("test repo dir created");
        let status = Command::new("git")
            .arg("init")
            .arg(&path)
            .status()
            .expect("git init runs");
        assert!(status.success(), "git init failed");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn write(&self, path: &str, content: &str) {
        self.write_bytes(path, content.as_bytes());
    }

    fn write_bytes(&self, path: &str, content: &[u8]) {
        let path = self.path.join(path);
        fs::create_dir_all(path.parent().expect("file has parent")).expect("parent created");
        fs::write(path, content).expect("file written");
    }
}

impl Drop for TestRepo {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
