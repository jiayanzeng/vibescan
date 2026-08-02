use super::*;

pub(super) fn collect_working_tree(
    repo_root: &Path,
    collector: &mut UnitCollector,
    warnings: &mut Vec<ScopeWarning>,
    options: &WalkOptions,
    ignore_policy: &IgnorePolicy,
) -> Result<(), GitWalkError> {
    let mut seen_paths = BTreeSet::new();
    let mut builder = WalkBuilder::new(repo_root);
    builder
        .hidden(false)
        .parents(true)
        .git_ignore(true)
        .git_global(true)
        .git_exclude(true)
        .add_custom_ignore_filename(".vibescanignore")
        .overrides(ignore_policy.walk_skips.clone());

    for result in builder.build() {
        let entry = result.map_err(GitWalkError::Ignore)?;
        if !is_file_entry(&entry) {
            continue;
        }
        let relative = relative_repo_path(repo_root, entry.path())?;
        if !seen_paths.insert(relative.clone()) {
            continue;
        }
        collector.record_path_walked();
        push_working_tree_file(
            collector,
            warnings,
            entry.path(),
            relative,
            options.max_bytes,
        )?;
    }

    let mut force_builder = WalkBuilder::new(repo_root);
    force_builder
        .hidden(false)
        .parents(false)
        .ignore(false)
        .git_ignore(false)
        .git_global(false)
        .git_exclude(false);

    for result in force_builder.build() {
        let entry = result.map_err(GitWalkError::Ignore)?;
        if !is_file_entry(&entry) {
            continue;
        }
        let relative = relative_repo_path(repo_root, entry.path())?;
        if !ignore_policy.should_force_scan(&relative.0) {
            continue;
        }
        if !seen_paths.insert(relative.clone()) {
            continue;
        }
        collector.record_path_walked();
        push_working_tree_file(
            collector,
            warnings,
            entry.path(),
            relative,
            options.max_bytes,
        )?;
    }
    Ok(())
}

pub(super) fn push_working_tree_file(
    collector: &mut UnitCollector,
    warnings: &mut Vec<ScopeWarning>,
    path: &Path,
    relative: RepoPath,
    max_bytes: usize,
) -> Result<(), GitWalkError> {
    let metadata = fs::metadata(path).map_err(GitWalkError::Io)?;
    if metadata.len() > max_bytes as u64 {
        warnings.push(ScopeWarning::LargeFileSkipped {
            path: relative,
            bytes: metadata.len(),
        });
        return Ok(());
    }
    let content = fs::read(path).map_err(GitWalkError::Io)?;
    collector.record_blob_read();
    push_content(
        collector,
        warnings,
        relative,
        content,
        Provenance::WorkingTree,
        max_bytes,
    );
    Ok(())
}
