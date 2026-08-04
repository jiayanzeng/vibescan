use std::ffi::OsString;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use super::*;

static GIT_ENV_LOCK: Mutex<()> = Mutex::new(());

fn test_unit(
    content_id: ContentId,
    content: Vec<u8>,
    path: &str,
    location_class: LocationClass,
    provenance: Provenance,
) -> ScannableUnit {
    ScannableUnit {
        content_id,
        content,
        locations: vec![UnitLocation {
            path: RepoPath(path.to_owned()),
            provenance,
            additional_provenance: Vec::new(),
            location_class,
        }],
    }
}

fn commit(sha: &str) -> Provenance {
    Provenance::Commit {
        sha: sha.to_owned(),
        author: None,
        date: None,
    }
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
            "vibescan-git-test-{}-{nonce}-{id}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("test repo dir created");
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

    fn git<const N: usize>(&self, args: [&str; N]) {
        let _guard = GIT_ENV_LOCK.lock().expect("git env lock not poisoned");
        let status = Command::new("git")
            .args(args)
            .current_dir(&self.path)
            .status()
            .expect("git command runs");
        assert!(status.success(), "git command failed");
    }
}

struct PathGuard {
    _guard: MutexGuard<'static, ()>,
    previous: Option<OsString>,
}

impl PathGuard {
    fn empty() -> Self {
        let guard = GIT_ENV_LOCK.lock().expect("git env lock not poisoned");
        let previous = std::env::var_os("PATH");
        unsafe {
            std::env::set_var("PATH", "");
        }
        Self {
            _guard: guard,
            previous,
        }
    }
}

impl Drop for PathGuard {
    fn drop(&mut self) {
        unsafe {
            if let Some(previous) = &self.previous {
                std::env::set_var("PATH", previous);
            } else {
                std::env::remove_var("PATH");
            }
        }
    }
}

fn unit_paths(output: &WalkOutput) -> Vec<String> {
    let mut paths = output
        .units
        .iter()
        .flat_map(|unit| {
            unit.locations
                .iter()
                .map(|location| location.path.0.clone())
        })
        .collect::<Vec<_>>();
    paths.sort();
    paths
}

impl Drop for TestRepo {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[path = "collector.rs"]
mod collector_tests;

#[path = "history.rs"]
mod history_tests;

#[path = "ignore_policy.rs"]
mod ignore_policy_tests;

#[path = "location.rs"]
mod location_tests;
