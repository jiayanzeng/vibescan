use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use vibescan_core::{ScanConfig, scan};
use vibescan_types::{ScanResult, ScanStats};

const FILE_COUNT: u64 = 40;
const UNIQUE_CONTENT_COUNT: u64 = 30;
const DUPLICATE_FILE_COUNT: u64 = FILE_COUNT - UNIQUE_CONTENT_COUNT;

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CounterSnapshot {
    paths_walked: u64,
    blobs_read: u64,
    unique_contents: u64,
    units_materialized: u64,
    truncated: bool,
}

impl From<&ScanStats> for CounterSnapshot {
    fn from(stats: &ScanStats) -> Self {
        Self {
            paths_walked: stats.paths_walked,
            blobs_read: stats.blobs_read,
            unique_contents: stats.unique_contents,
            units_materialized: stats.units_materialized,
            truncated: stats.truncated,
        }
    }
}

#[test]
fn deterministic_fixture_gates_collection_and_dedup_counters() {
    let first = scan_fixture("first");
    let second = scan_fixture("second");

    assert_expected_counters(&first.stats);
    assert_expected_counters(&second.stats);
    assert_eq!(
        CounterSnapshot::from(&first.stats),
        CounterSnapshot::from(&second.stats),
        "counter gate must be deterministic across independently generated fixtures"
    );

    eprintln!(
        "PERF_COUNTERS duration_ms={} paths={} blobs={} unique={} units={} dedup_ratio={:.2}%",
        first.duration_ms,
        first.stats.paths_walked,
        first.stats.blobs_read,
        first.stats.unique_contents,
        first.stats.units_materialized,
        first.stats.dedup_ratio() * 100.0,
    );
    eprintln!(
        "PERF_COUNTERS duration_ms={} paths={} blobs={} unique={} units={} dedup_ratio={:.2}%",
        second.duration_ms,
        second.stats.paths_walked,
        second.stats.blobs_read,
        second.stats.unique_contents,
        second.stats.units_materialized,
        second.stats.dedup_ratio() * 100.0,
    );
}

#[test]
fn pre_dedup_negative_control_would_count_every_blob_as_unique() {
    let repo = generate_fixture("pre-dedup-negative-control");
    let pre_dedup_unique_contents = fs::read_dir(repo.join("src/generated"))
        .expect("read generated fixture")
        .count() as u64;
    let result = scan_generated_fixture(&repo);

    assert_eq!(pre_dedup_unique_contents, FILE_COUNT);
    assert_eq!(pre_dedup_unique_contents, result.stats.blobs_read);
    assert_ne!(result.stats.unique_contents, pre_dedup_unique_contents);
    assert_eq!(
        result.stats.blobs_read - result.stats.unique_contents,
        DUPLICATE_FILE_COUNT
    );
}

fn assert_expected_counters(stats: &ScanStats) {
    assert_eq!(stats.paths_walked, FILE_COUNT);
    assert_eq!(stats.blobs_read, FILE_COUNT);
    assert_eq!(stats.unique_contents, UNIQUE_CONTENT_COUNT);
    assert_eq!(stats.units_materialized, UNIQUE_CONTENT_COUNT);
    assert_eq!(stats.dedup_ratio(), 0.25);
    assert!(!stats.truncated);
    assert!(!stats.scan_budget_hit);
}

fn scan_fixture(label: &str) -> ScanResult {
    let repo = generate_fixture(label);
    scan_generated_fixture(&repo)
}

fn scan_generated_fixture(repo: &Path) -> ScanResult {
    scan(
        repo,
        ScanConfig {
            include_history: false,
            ..ScanConfig::default()
        },
    )
    .unwrap_or_else(|error| panic!("scan deterministic fixture {}: {error}", repo.display()))
}

fn generate_fixture(label: &str) -> PathBuf {
    let repo = unique_temp_dir(label);
    let generated = repo.join("src/generated");
    fs::create_dir_all(&generated)
        .unwrap_or_else(|error| panic!("create {}: {error}", generated.display()));

    for file_index in 0..FILE_COUNT {
        let content_index = file_index % UNIQUE_CONTENT_COUNT;
        let content =
            format!("export const perf_{content_index:02} = \"fixed-seed-{content_index:02}\";\n");
        let path = generated.join(format!("file-{file_index:02}.ts"));
        fs::write(&path, content)
            .unwrap_or_else(|error| panic!("write {}: {error}", path.display()));
    }

    run_git_init(&repo);
    repo
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

fn unique_temp_dir(label: &str) -> PathBuf {
    let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = env::temp_dir().join(format!(
        "vibescan-perf-{label}-{}-{counter}",
        std::process::id()
    ));
    if path.exists() {
        fs::remove_dir_all(&path)
            .unwrap_or_else(|error| panic!("clear {}: {error}", path.display()));
    }
    fs::create_dir_all(&path).unwrap_or_else(|error| panic!("create {}: {error}", path.display()));
    path
}
