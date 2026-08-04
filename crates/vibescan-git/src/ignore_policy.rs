use super::*;

pub(super) fn is_file_entry(entry: &DirEntry) -> bool {
    entry
        .file_type()
        .is_some_and(|file_type| file_type.is_file())
}

pub(super) fn relative_repo_path(root: &Path, path: &Path) -> Result<RepoPath, GitWalkError> {
    let relative = path
        .strip_prefix(root)
        .map_err(|source| GitWalkError::Path {
            path: path.to_path_buf(),
            source,
        })?
        .components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/");
    Ok(RepoPath(relative))
}

#[derive(Clone, Debug)]
pub(super) struct IgnorePolicy {
    repo_root: PathBuf,
    config_skips: Override,
    hard_skips: Override,
    pub(super) walk_skips: Override,
    force_scans: GlobSet,
    history_ignores: Gitignore,
}

impl IgnorePolicy {
    pub(super) fn new(
        repo_root: &Path,
        config_path_allowlists: &[String],
    ) -> Result<Self, GitWalkError> {
        let config_skips = build_ignore_overrides(repo_root, config_path_allowlists)?;
        let hard_skips = build_ignore_overrides(repo_root, ALWAYS_SKIP_PATTERNS)?;
        let walk_skips = build_combined_ignore_overrides(
            repo_root,
            config_path_allowlists,
            ALWAYS_SKIP_PATTERNS,
        )?;
        let force_scans = build_glob_set(ALWAYS_SCAN_PATTERNS)?;
        let history_ignores = build_history_ignores(repo_root)?;
        Ok(Self {
            repo_root: repo_root.to_path_buf(),
            config_skips,
            hard_skips,
            walk_skips,
            force_scans,
            history_ignores,
        })
    }

    pub(super) fn should_scan_history_path(&self, path: &str) -> bool {
        self.should_scan_path(path)
    }

    fn should_scan_path(&self, path: &str) -> bool {
        let path = Path::new(path);
        if matches!(self.hard_skips.matched(path, false), Match::Ignore(_)) {
            return false;
        }
        if self.force_scans.is_match(path) {
            return true;
        }
        if matches!(self.config_skips.matched(path, false), Match::Ignore(_)) {
            return false;
        }

        // Historical object paths are matched against current ignore rules. This
        // is an intentional v1 approximation because per-commit ignore state
        // would require replaying ignore files across history.
        !self
            .history_ignores
            .matched_path_or_any_parents(self.repo_root.join(path), false)
            .is_ignore()
    }

    pub(super) fn should_force_scan(&self, path: &str) -> bool {
        let path = Path::new(path);
        !matches!(self.hard_skips.matched(path, false), Match::Ignore(_))
            && self.force_scans.is_match(path)
    }
}

pub(super) fn build_ignore_overrides(
    repo_root: &Path,
    patterns: &[impl AsRef<str>],
) -> Result<Override, GitWalkError> {
    let mut builder = OverrideBuilder::new(repo_root);

    for pattern in patterns {
        add_override_ignore(&mut builder, pattern.as_ref())?;
    }

    builder.build().map_err(GitWalkError::Override)
}

pub(super) fn build_combined_ignore_overrides(
    repo_root: &Path,
    first: &[String],
    second: &[&str],
) -> Result<Override, GitWalkError> {
    let mut builder = OverrideBuilder::new(repo_root);
    for pattern in first {
        add_override_ignore(&mut builder, pattern)?;
    }
    for pattern in second {
        add_override_ignore(&mut builder, pattern)?;
    }
    builder.build().map_err(GitWalkError::Override)
}

pub(super) fn build_glob_set(patterns: &[&str]) -> Result<GlobSet, GitWalkError> {
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        builder.add(Glob::new(pattern).map_err(GitWalkError::Glob)?);
    }
    builder.build().map_err(GitWalkError::Glob)
}

pub(super) fn add_override_ignore(
    builder: &mut OverrideBuilder,
    pattern: &str,
) -> Result<(), GitWalkError> {
    let pattern = pattern.trim();
    if pattern.is_empty() || pattern.starts_with('#') {
        return Ok(());
    }
    let pattern = if pattern.starts_with('!') {
        pattern.to_owned()
    } else {
        format!("!{pattern}")
    };
    builder
        .add(&pattern)
        .map(|_| ())
        .map_err(GitWalkError::Override)
}

pub(super) fn build_history_ignores(repo_root: &Path) -> Result<Gitignore, GitWalkError> {
    let mut builder = GitignoreBuilder::new(repo_root);
    add_history_ignore_files(repo_root, repo_root, &mut builder)?;
    builder.build().map_err(GitWalkError::Ignore)
}

pub(super) fn add_history_ignore_files(
    repo_root: &Path,
    dir: &Path,
    builder: &mut GitignoreBuilder,
) -> Result<(), GitWalkError> {
    for entry in fs::read_dir(dir).map_err(GitWalkError::Io)? {
        let entry = entry.map_err(GitWalkError::Io)?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(GitWalkError::Io)?;
        let relative = relative_repo_path(repo_root, &path)?;
        if matches!(relative.0.as_str(), ".git" | "target")
            || relative.0.starts_with(".git/")
            || relative.0.starts_with("target/")
        {
            continue;
        }

        if file_type.is_dir() {
            add_history_ignore_files(repo_root, &path, builder)?;
        } else if file_type.is_file()
            && matches!(
                path.file_name().and_then(|name| name.to_str()),
                Some(".gitignore" | ".ignore" | ".vibescanignore")
            )
        {
            if let Some(error) = builder.add(&path) {
                return Err(GitWalkError::Ignore(error));
            }
        }
    }
    Ok(())
}

pub(super) const ALWAYS_SCAN_PATTERNS: &[&str] = &[
    ".env",
    ".env.*",
    "**/.env",
    "**/.env.*",
    "dist/**",
    "**/dist/**",
    "build/**",
    "**/build/**",
    "out/**",
    "**/out/**",
    ".next/static/**",
    "**/.next/static/**",
];

pub(super) const ALWAYS_SKIP_PATTERNS: &[&str] = &[
    "**/node_modules/**",
    "**/vendor-chunks/**",
    "**/.next/cache/**",
    "**/.next/server/**",
    "**/__pycache__/**",
    "**/*.pyc",
    "**/.DS_Store",
    "**/.turbo/**",
    "**/coverage/**",
    ".git/**",
    "target/**",
    ".env.example",
    ".env.sample",
    "**/.env.example",
    "**/.env.sample",
    "*.example",
    "**/*.example",
    "*.sample",
    "**/*.sample",
];
