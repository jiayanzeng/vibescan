use super::*;

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
