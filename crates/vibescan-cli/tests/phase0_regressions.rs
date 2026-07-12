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
