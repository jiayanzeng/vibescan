use super::*;

pub const DEFAULT_MAX_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WalkOptions {
    pub include_working_tree: bool,
    pub include_history: bool,
    pub max_commits: Option<usize>,
    pub max_bytes: usize,
    pub path_allowlists: Vec<String>,
}

impl Default for WalkOptions {
    fn default() -> Self {
        Self {
            include_working_tree: true,
            include_history: true,
            max_commits: Some(2_000),
            max_bytes: DEFAULT_MAX_BYTES,
            path_allowlists: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WalkOutput {
    pub repo_root: PathBuf,
    pub units: Vec<ScannableUnit>,
    pub warnings: Vec<ScopeWarning>,
    pub history: HistoryWalkStats,
    pub stats: WalkStats,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HistoryWalkStats {
    pub scanned_commits: usize,
    pub truncated: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WalkStats {
    pub paths_walked: u64,
    pub blobs_read: u64,
    pub unique_contents: u64,
    pub units_materialized: u64,
}

pub fn collect_repository(
    target: impl AsRef<Path>,
    options: WalkOptions,
) -> Result<WalkOutput, GitWalkError> {
    let (git_dir, repo_root) = discover_repository_dirs(target.as_ref())?;

    let mut collector = UnitCollector::new();
    let mut warnings = Vec::new();
    let mut history = HistoryWalkStats::default();
    let ignore_policy = IgnorePolicy::new(&repo_root, &options.path_allowlists)?;
    if git_dir.join("shallow").exists() {
        warnings.push(ScopeWarning::ShallowClone);
    }

    if options.include_working_tree {
        collect_working_tree(
            &repo_root,
            &mut collector,
            &mut warnings,
            &options,
            &ignore_policy,
        )?;
    }
    if options.include_history {
        history = collect_history(
            &git_dir,
            &mut collector,
            &mut warnings,
            &options,
            &ignore_policy,
        )?;
    }

    let stats = collector.stats();
    Ok(WalkOutput {
        repo_root,
        units: collector.into_units(),
        warnings,
        history,
        stats,
    })
}

/// Discover the repository root from a target path.
pub fn discover_repository_root(target: impl AsRef<Path>) -> Result<PathBuf, GitWalkError> {
    discover_repository_dirs(target.as_ref()).map(|(_, repo_root)| repo_root)
}

pub(super) fn discover_repository_dirs(target: &Path) -> Result<(PathBuf, PathBuf), GitWalkError> {
    let (git_dir, worktree_dir) = gix_discover::upwards(target)
        .map_err(|source| GitWalkError::Discover {
            target: target.to_path_buf(),
            source: Box::new(source),
        })?
        .0
        .into_repository_and_work_tree_directories();
    let repo_root =
        worktree_dir.unwrap_or_else(|| git_dir.parent().unwrap_or(&git_dir).to_path_buf());
    Ok((git_dir, repo_root))
}
