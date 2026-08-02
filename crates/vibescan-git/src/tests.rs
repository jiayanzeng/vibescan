use std::ffi::OsString;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use super::*;

static GIT_ENV_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn content_dedup_retains_distinct_source_paths_and_classes() {
    let content = b"same bytes".to_vec();
    let id = content_id(&content);
    let mut collector = UnitCollector::new();
    collector.push(test_unit(
        id.clone(),
        content.clone(),
        "apps/api/.env.local",
        LocationClass::ServerOnly,
        Provenance::WorkingTree,
    ));
    collector.push(test_unit(
        id,
        content,
        "apps/web/.next/static/chunks/config.js",
        LocationClass::ClientReachable,
        Provenance::WorkingTree,
    ));

    let stats = collector.stats();
    let units = collector.into_units();

    assert_eq!(stats.unique_contents, 1);
    assert_eq!(stats.units_materialized, 1);
    assert_eq!(units.len(), 1);
    assert_eq!(
        units[0]
            .locations
            .iter()
            .map(|location| (location.path.0.clone(), location.location_class))
            .collect::<Vec<_>>(),
        vec![
            ("apps/api/.env.local".to_owned(), LocationClass::ServerOnly),
            (
                "apps/web/.next/static/chunks/config.js".to_owned(),
                LocationClass::ClientReachable
            )
        ]
    );
}

#[test]
fn same_path_repeated_commits_share_one_location_with_complete_provenance() {
    let content = b"same bytes".to_vec();
    let id = content_id(&content);
    let mut collector = UnitCollector::new();
    collector.push(test_unit(
        id.clone(),
        content.clone(),
        "src/config.ts",
        LocationClass::Unknown,
        commit("bbbb"),
    ));
    collector.push(test_unit(
        id.clone(),
        content.clone(),
        "src/config.ts",
        LocationClass::Unknown,
        Provenance::WorkingTree,
    ));
    collector.push(test_unit(
        id,
        content,
        "src/config.ts",
        LocationClass::Unknown,
        commit("aaaa"),
    ));

    let units = collector.into_units();
    let location = &units[0].locations[0];

    assert_eq!(units.len(), 1);
    assert_eq!(units[0].locations.len(), 1);
    assert_eq!(location.provenance, Provenance::WorkingTree);
    assert_eq!(
        location.additional_provenance,
        vec![commit("aaaa"), commit("bbbb")]
    );
}

#[test]
fn different_historical_contents_at_one_path_remain_distinct_units() {
    let mut collector = UnitCollector::new();
    collector.push(test_unit(
        content_id(b"version a"),
        b"version a".to_vec(),
        "src/config.ts",
        LocationClass::Unknown,
        commit("aaaa"),
    ));
    collector.push(test_unit(
        content_id(b"version b"),
        b"version b".to_vec(),
        "src/config.ts",
        LocationClass::Unknown,
        commit("bbbb"),
    ));

    let units = collector.into_units();

    assert_eq!(units.len(), 2);
    assert_ne!(units[0].content_id, units[1].content_id);
    assert_eq!(units[0].locations[0].path, units[1].locations[0].path);
}

#[test]
fn history_scan_collects_changed_blobs_from_all_refs() {
    let repo = TestRepo::new();
    repo.git(["init", "--initial-branch=main"]);
    repo.git(["config", "user.email", "a@example.com"]);
    repo.git(["config", "user.name", "A"]);
    repo.write("src/app.ts", "console.log('clean');\n");
    repo.git(["add", "."]);
    repo.git(["commit", "-m", "initial"]);
    repo.git(["checkout", "-b", "feature"]);
    repo.write(
        "src/feature.ts",
        "const token = 'sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890';\n",
    );
    repo.git(["add", "."]);
    repo.git(["commit", "-m", "feature secret"]);
    repo.git(["checkout", "main"]);

    let output = collect_repository(
        repo.path(),
        WalkOptions {
            include_working_tree: false,
            max_commits: Some(20),
            ..WalkOptions::default()
        },
    )
    .expect("history collected");

    assert_eq!(output.history.scanned_commits, 2);
    assert!(
        output
            .units
            .iter()
            .any(|unit| unit.locations.iter().any(|location| {
                location.path.0 == "src/feature.ts"
                    && matches!(location.provenance, Provenance::Commit { .. })
            }))
    );
}

#[test]
fn history_budget_sets_scope_warning() {
    let repo = TestRepo::new();
    repo.git(["init"]);
    repo.git(["config", "user.email", "a@example.com"]);
    repo.git(["config", "user.name", "A"]);
    repo.write("a.txt", "one\n");
    repo.git(["add", "."]);
    repo.git(["commit", "-m", "one"]);
    repo.write("a.txt", "two\n");
    repo.git(["add", "."]);
    repo.git(["commit", "-m", "two"]);

    let output = collect_repository(
        repo.path(),
        WalkOptions {
            include_working_tree: false,
            max_commits: Some(1),
            ..WalkOptions::default()
        },
    )
    .expect("history collected");

    assert!(output.history.truncated);
    assert!(matches!(
        output.warnings.as_slice(),
        [ScopeWarning::HistoryBudgetHit { max_commits: 1 }]
    ));
}

#[test]
fn history_scan_does_not_require_git_on_path_after_fixture_setup() {
    let repo = TestRepo::new();
    repo.git(["init"]);
    repo.git(["config", "user.email", "a@example.com"]);
    repo.git(["config", "user.name", "A"]);
    repo.write(
        "src/history.ts",
        "const token = 'sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890';\n",
    );
    repo.git(["add", "."]);
    repo.git(["commit", "-m", "historical secret"]);

    let _guard = PathGuard::empty();
    let output = collect_repository(
        repo.path(),
        WalkOptions {
            include_working_tree: false,
            max_commits: Some(20),
            ..WalkOptions::default()
        },
    )
    .expect("history collected without git on PATH");

    assert_eq!(output.history.scanned_commits, 1);
    assert!(
        output
            .units
            .iter()
            .any(|unit| unit.locations.iter().any(|location| {
                location.path.0 == "src/history.ts"
                    && matches!(location.provenance, Provenance::Commit { .. })
            }))
    );
}

#[test]
fn nested_gitignore_suppresses_matching_paths_without_substrings() {
    let repo = TestRepo::new();
    repo.git(["init"]);
    repo.write("dashboard/.gitignore", "cache\n");
    repo.write("dashboard/cache/app.js", "ignored\n");
    repo.write("dashboard/src/redistribute.ts", "redistribute\n");
    repo.write("dashboard/src/lib/distance.ts", "distance\n");

    let output = collect_repository(
        repo.path(),
        WalkOptions {
            include_history: false,
            ..WalkOptions::default()
        },
    )
    .expect("repo collected");
    let paths = unit_paths(&output);

    assert!(!paths.contains(&"dashboard/cache/app.js".to_owned()));
    assert!(paths.contains(&"dashboard/src/redistribute.ts".to_owned()));
    assert!(paths.contains(&"dashboard/src/lib/distance.ts".to_owned()));
}

#[test]
fn gitignore_negation_rescans_whitelisted_path() {
    let repo = TestRepo::new();
    repo.git(["init"]);
    repo.write(".gitignore", "ignored-dir/*\n!ignored-dir/keep.txt\n");
    repo.write("ignored-dir/drop.txt", "ignored\n");
    repo.write("ignored-dir/keep.txt", "scanned\n");

    let output = collect_repository(
        repo.path(),
        WalkOptions {
            include_history: false,
            ..WalkOptions::default()
        },
    )
    .expect("repo collected");
    let paths = unit_paths(&output);

    assert!(!paths.contains(&"ignored-dir/drop.txt".to_owned()));
    assert!(paths.contains(&"ignored-dir/keep.txt".to_owned()));
}

#[test]
fn gitignored_env_is_scanned_but_examples_are_skipped() {
    let repo = TestRepo::new();
    repo.git(["init"]);
    repo.write(".gitignore", ".env\n.env.*\n");
    repo.write(
        ".env",
        "SUPABASE_SERVICE_ROLE_KEY=sb_secret_0123456789abcdefghijklmnopqrstuvwxyzABCDEF\n",
    );
    repo.write(
        ".env.local",
        "SUPABASE_SERVICE_ROLE_KEY=sb_secret_abcdef0123456789abcdefghijklmnopqrstuvwxyzABCDEF\n",
    );
    repo.write(
        ".env.example",
        "SUPABASE_SERVICE_ROLE_KEY=sb_secret_example0123456789abcdefghijklmnopqrstuvwxyzABCDEF\n",
    );

    let output = collect_repository(
        repo.path(),
        WalkOptions {
            include_history: false,
            ..WalkOptions::default()
        },
    )
    .expect("repo collected");
    let paths = unit_paths(&output);

    assert!(paths.contains(&".env".to_owned()));
    assert!(paths.contains(&".env.local".to_owned()));
    assert!(!paths.contains(&".env.example".to_owned()));
}

#[test]
fn shipped_static_bundle_is_scanned_but_server_vendor_chunks_are_skipped() {
    let repo = TestRepo::new();
    repo.git(["init"]);
    repo.write(".gitignore", ".next/\n");
    repo.write("dashboard/.next/static/chunks/app.js", "scanned\n");
    repo.write(
        "dashboard/.next/server/vendor-chunks/prop-types.js",
        "ignored\n",
    );

    let output = collect_repository(
        repo.path(),
        WalkOptions {
            include_history: false,
            ..WalkOptions::default()
        },
    )
    .expect("repo collected");
    let paths = unit_paths(&output);

    assert!(paths.contains(&"dashboard/.next/static/chunks/app.js".to_owned()));
    assert!(!paths.contains(&"dashboard/.next/server/vendor-chunks/prop-types.js".to_owned()));
}

#[test]
fn config_path_allowlists_skip_paths_but_cannot_hide_env() {
    let repo = TestRepo::new();
    repo.git(["init"]);
    repo.write("docs/secret.txt", "ignored\n");
    repo.write(
        ".env",
        "SUPABASE_SERVICE_ROLE_KEY=sb_secret_0123456789abcdefghijklmnopqrstuvwxyzABCDEF\n",
    );

    let output = collect_repository(
        repo.path(),
        WalkOptions {
            include_history: false,
            path_allowlists: vec!["docs/**".to_owned(), "**".to_owned()],
            ..WalkOptions::default()
        },
    )
    .expect("repo collected");
    let paths = unit_paths(&output);

    assert!(!paths.contains(&"docs/secret.txt".to_owned()));
    assert!(paths.contains(&".env".to_owned()));
}

#[test]
fn history_paths_use_current_ignore_rules() {
    let repo = TestRepo::new();
    repo.git(["init"]);
    repo.git(["config", "user.email", "a@example.com"]);
    repo.git(["config", "user.name", "A"]);
    repo.write("ignored-dir/old.txt", "historical\n");
    repo.git(["add", "."]);
    repo.git(["commit", "-m", "historical file"]);
    repo.write(".vibescanignore", "ignored-dir/*\n");

    let output = collect_repository(
        repo.path(),
        WalkOptions {
            include_working_tree: false,
            include_history: true,
            max_commits: Some(20),
            ..WalkOptions::default()
        },
    )
    .expect("repo collected");
    let paths = unit_paths(&output);

    assert!(!paths.contains(&"ignored-dir/old.txt".to_owned()));
}

#[test]
fn shallow_repositories_emit_scope_warning() {
    let repo = TestRepo::new();
    repo.git(["init"]);
    repo.write(".git/shallow", "0000000000000000000000000000000000000000\n");

    let output = collect_repository(
        repo.path(),
        WalkOptions {
            include_history: false,
            ..WalkOptions::default()
        },
    )
    .expect("repo collected");

    assert!(output.warnings.contains(&ScopeWarning::ShallowClone));
}

#[test]
fn classify_location_matches_monorepo_segment_rules() {
    let cases = [
        (
            "apps/web/.next/static/chunks/x.js",
            "",
            LocationClass::ClientReachable,
        ),
        ("apps/api/.env", "", LocationClass::ServerOnly),
        ("apps/web/.env.local", "", LocationClass::ServerOnly),
        (
            "packages/ui/src/components/Btn.tsx",
            "",
            LocationClass::ClientReachable,
        ),
        ("services/api/index.ts", "", LocationClass::ServerOnly),
        (
            "services/api/src/api/handler.ts",
            "import { NextRequest } from \"next/server\";",
            LocationClass::ServerOnly,
        ),
        (
            "packages/web/src/api/client.ts",
            "export const load = () => fetch('/rest/v1/profiles');",
            LocationClass::ClientReachable,
        ),
        ("apps/web/app/api/route.ts", "", LocationClass::ServerOnly),
        ("apps/web/app/page.tsx", "", LocationClass::ClientReachable),
        (
            "apps/web/.next/server/vendor-chunks/x.js",
            "",
            LocationClass::ServerOnly,
        ),
    ];

    for (path, content, expected) in cases {
        assert_eq!(
            classify_location(path, content.as_bytes()),
            expected,
            "{path}"
        );
    }
}

#[test]
fn classify_location_uses_segments_not_substrings() {
    let cases = [
        ("staticassets/x.js", "", LocationClass::Unknown),
        ("apps/web/src/myenv.ts", "", LocationClass::Unknown),
        ("apps/foo/api-docs/readme.md", "", LocationClass::Unknown),
        (
            "apps/web/app/foo/api/route.ts",
            "",
            LocationClass::ClientReachable,
        ),
    ];

    for (path, content, expected) in cases {
        assert_eq!(
            classify_location(path, content.as_bytes()),
            expected,
            "{path}"
        );
    }
}

#[test]
fn classify_location_preserves_flat_repo_behavior() {
    let cases = [
        ("public/config.js", "", LocationClass::ClientReachable),
        ("app/page.tsx", "", LocationClass::ClientReachable),
        ("pages/index.tsx", "", LocationClass::ClientReachable),
        ("src/app/page.tsx", "", LocationClass::ClientReachable),
        ("src/pages/index.tsx", "", LocationClass::ClientReachable),
        (
            "src/components/Button.tsx",
            "",
            LocationClass::ClientReachable,
        ),
        ("src/client/widget.ts", "", LocationClass::ClientReachable),
        ("src/Button.client.tsx", "", LocationClass::ClientReachable),
        ("dist/bundle.js", "", LocationClass::ClientReachable),
        ("build/assets/app.js", "", LocationClass::ClientReachable),
        (
            ".next/static/chunks/x.js",
            "",
            LocationClass::ClientReachable,
        ),
        (".env", "", LocationClass::ServerOnly),
        (".env.local", "", LocationClass::ServerOnly),
        ("server/index.ts", "", LocationClass::ServerOnly),
        (
            "supabase/functions/ping/index.ts",
            "",
            LocationClass::ServerOnly,
        ),
        ("api/handler.ts", "", LocationClass::ServerOnly),
        (
            "apps/api/index.ts",
            "export const client = true;",
            LocationClass::ServerOnly,
        ),
        (
            "src/api/supabase.ts",
            "export const load = () => fetch('/rest/v1/profiles');",
            LocationClass::ClientReachable,
        ),
        (
            "src/api/handler.ts",
            "import { NextRequest } from \"next/server\";",
            LocationClass::ServerOnly,
        ),
        (
            "src/api/db.ts",
            "import \"node:fs\";",
            LocationClass::ServerOnly,
        ),
        (
            "src/api/actions.ts",
            "'use server';",
            LocationClass::ServerOnly,
        ),
        (
            "src/api/require-db.ts",
            "const crypto = require('node:crypto');",
            LocationClass::ServerOnly,
        ),
        (
            "src/api/env-client.ts",
            "const url = process.env.NEXT_PUBLIC_SUPABASE_URL;",
            LocationClass::ClientReachable,
        ),
        (
            "src/api/node-label.ts",
            "const runtime = 'node:fs';",
            LocationClass::ClientReachable,
        ),
        (
            "src/api/helper.ts",
            "const runtime = myrequire('node:fs');",
            LocationClass::ClientReachable,
        ),
        ("src/lib/util.ts", "", LocationClass::Unknown),
    ];

    for (path, content, expected) in cases {
        assert_eq!(
            classify_location(path, content.as_bytes()),
            expected,
            "{path}"
        );
    }
}

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
