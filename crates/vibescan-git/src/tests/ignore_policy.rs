use super::*;

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
