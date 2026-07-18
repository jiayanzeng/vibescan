use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use vibescan_core::{OutputFormat, OutputStyle, ScanConfig, scan, scan_and_render};

const RAW_SECRET: &str = "sb_secret_0123456789abcdefghijklmnopqrstuvwxyzABCDEF";
const REDACTED_SECRET: &str = "sb_sec...CDEF";

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[test]
fn raw_secret_stops_at_the_candidate_to_finding_boundary() {
    let repo = RedactionFixture::new();
    let config = ScanConfig {
        include_history: false,
        ..ScanConfig::default()
    };

    for format in [
        OutputFormat::Json,
        OutputFormat::Sarif,
        OutputFormat::Html,
        OutputFormat::Tty,
    ] {
        let (output, _) = scan_and_render(repo.path(), config.clone(), format, OutputStyle::Plain)
            .unwrap_or_else(|error| panic!("{format:?} scan and render failed: {error}"));

        assert!(
            !output.contains(RAW_SECRET),
            "{format:?} leaked the raw secret"
        );
        assert!(
            output.contains(REDACTED_SECRET),
            "{format:?} did not render the redacted evidence"
        );
    }

    let result = scan(repo.path(), config).expect("fixture scan succeeds");
    assert_eq!(result.findings.len(), 1, "fixture must exercise redaction");
    let serialized = serde_json::to_string(&result).expect("ScanResult serializes");
    assert!(
        !serialized.contains(RAW_SECRET),
        "serialized ScanResult leaked the raw secret"
    );
    assert!(serialized.contains(REDACTED_SECRET));
}

struct RedactionFixture {
    path: PathBuf,
}

impl RedactionFixture {
    fn new() -> Self {
        let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = env::temp_dir().join(format!(
            "vibescan-redaction-boundary-{}-{counter}",
            std::process::id()
        ));
        if path.exists() {
            fs::remove_dir_all(&path)
                .unwrap_or_else(|error| panic!("clear {}: {error}", path.display()));
        }
        fs::create_dir_all(path.join("src/server"))
            .unwrap_or_else(|error| panic!("create {}: {error}", path.display()));
        fs::write(
            path.join("src/server/config.ts"),
            format!("export const serviceRoleKey = '{RAW_SECRET}';\n"),
        )
        .unwrap_or_else(|error| panic!("write redaction fixture: {error}"));
        run_git_init(&path);
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for RedactionFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn run_git_init(repo: &Path) {
    let output = Command::new("git")
        .arg("init")
        .current_dir(repo)
        .output()
        .expect("git init starts");
    assert!(
        output.status.success(),
        "git init failed in {}\nstdout:\n{}\nstderr:\n{}",
        repo.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
