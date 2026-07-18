//! LocalStatic git history and working tree collector.
//!
//! Repository discovery uses gitoxide's `gix-discover`. Object/history reads use
//! gitoxide's in-process object database APIs; no runtime `git` executable or
//! network client crates are required in this LocalStatic crate.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use gix_hash::ObjectId;
use gix_object::bstr::ByteSlice;
use gix_object::tree::EntryMode;
use gix_object::{FindExt, Kind};
use globset::{Glob, GlobSet, GlobSetBuilder};
use ignore::gitignore::{Gitignore, GitignoreBuilder};
use ignore::overrides::{Override, OverrideBuilder};
use ignore::{DirEntry, Match, WalkBuilder};
use sha2::{Digest, Sha256};
use vibescan_types::{
    ContentId, LocationClass, Provenance, RepoPath, ScannableUnit, ScopeWarning, UnitLocation,
};

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

fn discover_repository_dirs(target: &Path) -> Result<(PathBuf, PathBuf), GitWalkError> {
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

fn collect_working_tree(
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

fn push_working_tree_file(
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

fn collect_history(
    git_dir: &Path,
    collector: &mut UnitCollector,
    warnings: &mut Vec<ScopeWarning>,
    options: &WalkOptions,
    ignore_policy: &IgnorePolicy,
) -> Result<HistoryWalkStats, GitWalkError> {
    let mut stats = HistoryWalkStats::default();
    let objects = gix_odb::at(git_dir.join("objects")).map_err(GitWalkError::Io)?;
    let tips = reachable_ref_tips(git_dir, &objects)?;
    if tips.is_empty() {
        return Ok(stats);
    }

    let limit = options.max_commits.map(|max_commits| max_commits + 1);
    let mut commits = Vec::new();
    let mut queue = Vec::new();
    let mut seen = BTreeSet::new();

    for tip in tips {
        let commit = read_commit(&objects, tip)?;
        queue.push(WalkCandidate {
            id: tip,
            commit_time: commit.commit_time,
        });
    }

    while !queue.is_empty() {
        queue.sort_by(|left, right| {
            right
                .commit_time
                .cmp(&left.commit_time)
                .then_with(|| right.id.cmp(&left.id))
        });
        let candidate = queue.remove(0);
        if !seen.insert(candidate.id) {
            continue;
        }

        let commit = read_commit(&objects, candidate.id)?;
        commits.push(candidate.id);
        if limit.is_some_and(|limit| commits.len() >= limit) {
            break;
        }
        for parent in commit.parents {
            if seen.contains(&parent) {
                continue;
            }
            let parent_commit = read_commit(&objects, parent)?;
            queue.push(WalkCandidate {
                id: parent,
                commit_time: parent_commit.commit_time,
            });
        }
    }

    if let Some(max_commits) = options.max_commits {
        if commits.len() > max_commits {
            commits.truncate(max_commits);
            stats.truncated = true;
            warnings.push(ScopeWarning::HistoryBudgetHit {
                max_commits: max_commits as u64,
            });
        }
    }

    for id in commits {
        let commit = read_commit(&objects, id)?;
        let provenance = commit_provenance(&commit);
        collect_changed_blobs(
            &objects,
            &commit,
            provenance,
            collector,
            warnings,
            options,
            ignore_policy,
        )?;
        stats.scanned_commits += 1;
    }
    Ok(stats)
}

fn collect_changed_blobs(
    objects: &gix_odb::Handle,
    commit: &CommitInfo,
    provenance: Provenance,
    collector: &mut UnitCollector,
    warnings: &mut Vec<ScopeWarning>,
    options: &WalkOptions,
    ignore_policy: &IgnorePolicy,
) -> Result<(), GitWalkError> {
    if commit.parents.len() > 1 {
        warnings.push(ScopeWarning::MergeCommitFirstParentOnly {
            sha: commit.id.to_string(),
        });
    }

    let new_entries = tree_entries(objects, commit.tree_id)?;
    let old_entries = if let Some(parent_id) = commit.parents.first() {
        let parent = read_commit(objects, *parent_id)?;
        tree_entries(objects, parent.tree_id)?
    } else {
        BTreeMap::new()
    };

    for (path, entry) in new_entries {
        if old_entries.get(&path).is_some_and(|old| old == &entry) {
            continue;
        }
        if !ignore_policy.should_scan_history_path(&path) {
            continue;
        }
        if entry.mode.is_commit() {
            warnings.push(ScopeWarning::SubmoduleSkipped {
                path: RepoPath(path.to_owned()),
            });
            continue;
        }
        if !entry.mode.is_blob_or_symlink() {
            continue;
        }

        collector.record_path_walked();
        let mut buffer = Vec::new();
        let blob = objects
            .find_blob(&entry.id, &mut buffer)
            .map_err(|source| GitWalkError::GixObject {
                operation: "read blob",
                source: Box::new(source),
            })?;
        let content = blob.data.to_vec();
        collector.record_blob_read();
        push_content(
            collector,
            warnings,
            RepoPath(path.to_owned()),
            content,
            provenance.clone(),
            options.max_bytes,
        );
    }
    Ok(())
}

fn reachable_ref_tips(
    git_dir: &Path,
    objects: &gix_odb::Handle,
) -> Result<Vec<ObjectId>, GitWalkError> {
    let mut raw_tips = BTreeSet::new();
    collect_loose_refs(&git_dir.join("refs"), &mut raw_tips)?;
    collect_packed_refs(&git_dir.join("packed-refs"), &mut raw_tips)?;

    let mut tips = BTreeSet::new();
    for id in raw_tips {
        if let Some(commit_id) = peel_to_commit(objects, id)? {
            tips.insert(commit_id);
        }
    }
    Ok(tips.into_iter().collect())
}

fn collect_loose_refs(path: &Path, tips: &mut BTreeSet<ObjectId>) -> Result<(), GitWalkError> {
    if !path.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(path).map_err(GitWalkError::Io)? {
        let entry = entry.map_err(GitWalkError::Io)?;
        let path = entry.path();
        if path.is_dir() {
            collect_loose_refs(&path, tips)?;
            continue;
        }
        let content = fs::read_to_string(&path).map_err(GitWalkError::Io)?;
        if let Some(id) = parse_ref_oid(content.trim()) {
            tips.insert(id);
        }
    }
    Ok(())
}

fn collect_packed_refs(path: &Path, tips: &mut BTreeSet<ObjectId>) -> Result<(), GitWalkError> {
    if !path.exists() {
        return Ok(());
    }
    let content = fs::read_to_string(path).map_err(GitWalkError::Io)?;
    for line in content.lines() {
        if line.is_empty() || line.starts_with('#') || line.starts_with('^') {
            continue;
        }
        if let Some(hex) = line.split_whitespace().next() {
            if let Some(id) = parse_ref_oid(hex) {
                tips.insert(id);
            }
        }
    }
    Ok(())
}

fn parse_ref_oid(value: &str) -> Option<ObjectId> {
    ObjectId::from_hex(value.as_bytes()).ok()
}

fn peel_to_commit(
    objects: &gix_odb::Handle,
    mut id: ObjectId,
) -> Result<Option<ObjectId>, GitWalkError> {
    for _ in 0..16 {
        let mut buffer = Vec::new();
        let data = objects
            .find(&id, &mut buffer)
            .map_err(|source| GitWalkError::GixObject {
                operation: "read ref target",
                source: Box::new(source),
            })?;
        match data.kind {
            Kind::Commit => return Ok(Some(id)),
            Kind::Tag => {
                let tag = data.decode().map_err(|source| GitWalkError::GixDecode {
                    operation: "decode tag",
                    source: Box::new(source),
                })?;
                let gix_object::ObjectRef::Tag(tag) = tag else {
                    return Ok(None);
                };
                id = ObjectId::from_hex(tag.target).map_err(|source| GitWalkError::Hash {
                    operation: "parse tag target",
                    source,
                })?;
            }
            _ => return Ok(None),
        }
    }
    Ok(None)
}

fn commit_provenance(commit: &CommitInfo) -> Provenance {
    Provenance::Commit {
        sha: commit.id.to_string(),
        author: commit.author.clone(),
        date: commit.date.clone(),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CommitInfo {
    id: ObjectId,
    tree_id: ObjectId,
    parents: Vec<ObjectId>,
    author: Option<String>,
    date: Option<String>,
    commit_time: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct WalkCandidate {
    id: ObjectId,
    commit_time: i64,
}

fn read_commit(objects: &gix_odb::Handle, id: ObjectId) -> Result<CommitInfo, GitWalkError> {
    let mut tree_buffer = Vec::new();
    let mut commit = objects
        .find_commit_iter(&id, &mut tree_buffer)
        .map_err(|source| GitWalkError::GixObject {
            operation: "read commit",
            source: Box::new(source),
        })?;
    let tree_id = commit.tree_id().map_err(|source| GitWalkError::GixDecode {
        operation: "decode commit tree",
        source: Box::new(source),
    })?;

    let mut parents_buffer = Vec::new();
    let parents = objects
        .find_commit_iter(&id, &mut parents_buffer)
        .map_err(|source| GitWalkError::GixObject {
            operation: "read commit parents",
            source: Box::new(source),
        })?
        .parent_ids()
        .collect();

    let mut author_buffer = Vec::new();
    let author = objects
        .find_commit_iter(&id, &mut author_buffer)
        .map_err(|source| GitWalkError::GixObject {
            operation: "read commit author",
            source: Box::new(source),
        })?
        .author()
        .ok()
        .map(|author| {
            format!(
                "{} <{}>",
                author.name.to_str_lossy(),
                author.email.to_str_lossy()
            )
        });

    let mut committer_buffer = Vec::new();
    let committer = objects
        .find_commit_iter(&id, &mut committer_buffer)
        .map_err(|source| GitWalkError::GixObject {
            operation: "read commit committer",
            source: Box::new(source),
        })?
        .committer()
        .ok();
    let date = committer.map(|signature| signature.time.to_owned());
    let commit_time = date
        .as_deref()
        .and_then(|value| value.split_whitespace().next())
        .and_then(|timestamp| timestamp.parse::<i64>().ok())
        .unwrap_or_default();

    Ok(CommitInfo {
        id,
        tree_id,
        parents,
        author,
        date,
        commit_time,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TreeEntry {
    id: ObjectId,
    mode: EntryMode,
}

fn tree_entries(
    objects: &gix_odb::Handle,
    tree_id: ObjectId,
) -> Result<BTreeMap<String, TreeEntry>, GitWalkError> {
    let mut entries = BTreeMap::new();
    collect_tree_entries(objects, tree_id, String::new(), &mut entries)?;
    Ok(entries)
}

fn collect_tree_entries(
    objects: &gix_odb::Handle,
    tree_id: ObjectId,
    prefix: String,
    entries: &mut BTreeMap<String, TreeEntry>,
) -> Result<(), GitWalkError> {
    let mut buffer = Vec::new();
    let tree = objects
        .find_tree_iter(&tree_id, &mut buffer)
        .map_err(|source| GitWalkError::GixObject {
            operation: "read tree",
            source: Box::new(source),
        })?;
    for entry in tree {
        let entry = entry.map_err(|source| GitWalkError::GixDecode {
            operation: "decode tree entry",
            source: Box::new(source),
        })?;
        let name = entry.filename.to_str_lossy();
        let path = if prefix.is_empty() {
            name.into_owned()
        } else {
            format!("{prefix}/{name}")
        };
        if entry.mode.is_tree() {
            collect_tree_entries(objects, entry.oid.to_owned(), path, entries)?;
        } else {
            entries.insert(
                path,
                TreeEntry {
                    id: entry.oid.to_owned(),
                    mode: entry.mode,
                },
            );
        }
    }
    Ok(())
}

fn push_content(
    collector: &mut UnitCollector,
    warnings: &mut Vec<ScopeWarning>,
    path: RepoPath,
    content: Vec<u8>,
    provenance: Provenance,
    max_bytes: usize,
) {
    if content.len() > max_bytes {
        warnings.push(ScopeWarning::LargeFileSkipped {
            path,
            bytes: content.len() as u64,
        });
        return;
    }
    if content.contains(&0) {
        warnings.push(ScopeWarning::BinaryFileSkipped { path });
        return;
    }

    let content_id = content_id(&content);
    collector.push(ScannableUnit {
        content_id,
        content,
        locations: vec![UnitLocation {
            location_class: classify_location(&path.0),
            path,
            provenance,
            additional_provenance: Vec::new(),
        }],
    });
}

fn classify_location(path: &str) -> LocationClass {
    let lower = path.to_ascii_lowercase();
    let segments = lower
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    let basename = segments.last().copied().unwrap_or_default();

    if basename_is_env(basename)
        || path_has_segments(&segments, &["app", "api"])
        || path_has_segments(&segments, &["pages", "api"])
        || path_has_segments(&segments, &["src", "app", "api"])
        || path_has_segments(&segments, &["src", "pages", "api"])
        || segments.contains(&"server")
        || path_has_segments(&segments, &[".next", "server"])
        || path_has_segments(&segments, &["supabase", "functions"])
        || path_has_package_server_root(&segments)
    {
        return LocationClass::ServerOnly;
    }

    if segments.contains(&"public")
        || segments.contains(&"app")
        || segments.contains(&"pages")
        || path_has_segments(&segments, &["src", "app"])
        || path_has_segments(&segments, &["src", "pages"])
        || path_has_segments(&segments, &["src", "components"])
        || segments.contains(&"dist")
        || segments.contains(&"build")
        || segments.contains(&"out")
        || path_has_segments(&segments, &[".next", "static"])
        || segments.contains(&".svelte-kit")
        || segments.contains(&"client")
        || basename.contains(".client.")
    {
        return LocationClass::ClientReachable;
    }

    LocationClass::Unknown
}

fn basename_is_env(basename: &str) -> bool {
    basename == ".env" || basename.starts_with(".env.")
}

fn path_has_segments(path: &[&str], needle: &[&str]) -> bool {
    !needle.is_empty()
        && needle.len() <= path.len()
        && path.windows(needle.len()).any(|window| window == needle)
}

fn path_has_package_server_root(path: &[&str]) -> bool {
    path.starts_with(&["api"])
        || path.starts_with(&["src", "api"])
        || path.windows(2).any(|window| {
            matches!(window[0], "apps" | "packages" | "services") && window[1] == "api"
        })
        || path.windows(3).any(|window| {
            matches!(window[0], "apps" | "packages" | "services") && window[2] == "api"
        })
        || path.windows(4).any(|window| {
            matches!(window[0], "apps" | "packages" | "services")
                && window[2] == "src"
                && window[3] == "api"
        })
}

fn is_file_entry(entry: &DirEntry) -> bool {
    entry
        .file_type()
        .is_some_and(|file_type| file_type.is_file())
}

fn relative_repo_path(root: &Path, path: &Path) -> Result<RepoPath, GitWalkError> {
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
struct IgnorePolicy {
    repo_root: PathBuf,
    config_skips: Override,
    hard_skips: Override,
    walk_skips: Override,
    force_scans: GlobSet,
    history_ignores: Gitignore,
}

impl IgnorePolicy {
    fn new(repo_root: &Path, config_path_allowlists: &[String]) -> Result<Self, GitWalkError> {
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

    fn should_scan_history_path(&self, path: &str) -> bool {
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

    fn should_force_scan(&self, path: &str) -> bool {
        let path = Path::new(path);
        !matches!(self.hard_skips.matched(path, false), Match::Ignore(_))
            && self.force_scans.is_match(path)
    }
}

fn build_ignore_overrides(
    repo_root: &Path,
    patterns: &[impl AsRef<str>],
) -> Result<Override, GitWalkError> {
    let mut builder = OverrideBuilder::new(repo_root);

    for pattern in patterns {
        add_override_ignore(&mut builder, pattern.as_ref())?;
    }

    builder.build().map_err(GitWalkError::Override)
}

fn build_combined_ignore_overrides(
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

fn build_glob_set(patterns: &[&str]) -> Result<GlobSet, GitWalkError> {
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        builder.add(Glob::new(pattern).map_err(GitWalkError::Glob)?);
    }
    builder.build().map_err(GitWalkError::Glob)
}

fn add_override_ignore(builder: &mut OverrideBuilder, pattern: &str) -> Result<(), GitWalkError> {
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

fn build_history_ignores(repo_root: &Path) -> Result<Gitignore, GitWalkError> {
    let mut builder = GitignoreBuilder::new(repo_root);
    add_history_ignore_files(repo_root, repo_root, &mut builder)?;
    builder.build().map_err(GitWalkError::Ignore)
}

fn add_history_ignore_files(
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

const ALWAYS_SCAN_PATTERNS: &[&str] = &[
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

const ALWAYS_SKIP_PATTERNS: &[&str] = &[
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

#[derive(Debug)]
struct UnitCollector {
    by_content_id: BTreeMap<ContentId, usize>,
    units: Vec<ScannableUnit>,
    paths_walked: u64,
    blobs_read: u64,
}

impl UnitCollector {
    fn new() -> Self {
        Self {
            by_content_id: BTreeMap::new(),
            units: Vec::new(),
            paths_walked: 0,
            blobs_read: 0,
        }
    }

    fn record_path_walked(&mut self) {
        self.paths_walked += 1;
    }

    fn record_blob_read(&mut self) {
        self.blobs_read += 1;
    }

    fn stats(&self) -> WalkStats {
        let materialized = self.units.len() as u64;
        WalkStats {
            paths_walked: self.paths_walked,
            blobs_read: self.blobs_read,
            unique_contents: materialized,
            units_materialized: materialized,
        }
    }

    fn push(&mut self, unit: ScannableUnit) {
        if let Some(existing) = self.by_content_id.get(&unit.content_id).copied() {
            for location in unit.locations {
                merge_unit_location(&mut self.units[existing].locations, location);
            }
            return;
        }
        let index = self.units.len();
        self.by_content_id.insert(unit.content_id.clone(), index);
        self.units.push(unit);
    }

    fn into_units(mut self) -> Vec<ScannableUnit> {
        for unit in &mut self.units {
            for location in &mut unit.locations {
                normalize_provenances(location);
            }
            unit.locations.sort_by(|left, right| {
                left.path
                    .cmp(&right.path)
                    .then_with(|| left.location_class.cmp(&right.location_class))
                    .then_with(|| {
                        provenance_sort_key(&left.provenance)
                            .cmp(&provenance_sort_key(&right.provenance))
                    })
            });
            unit.locations.dedup();
        }
        self.units
    }
}

fn merge_unit_location(locations: &mut Vec<UnitLocation>, incoming: UnitLocation) {
    if let Some(existing) = locations
        .iter_mut()
        .find(|location| location.path == incoming.path)
    {
        existing.additional_provenance.push(incoming.provenance);
        existing
            .additional_provenance
            .extend(incoming.additional_provenance);
        normalize_provenances(existing);
    } else {
        locations.push(incoming);
    }
}

fn normalize_provenances(location: &mut UnitLocation) {
    let mut provenances = std::iter::once(location.provenance.clone())
        .chain(location.additional_provenance.drain(..))
        .collect::<Vec<_>>();
    provenances.sort_by_key(provenance_sort_key);
    provenances.dedup();
    if let Some(primary) = provenances.first().cloned() {
        location.provenance = primary;
        location.additional_provenance = provenances.into_iter().skip(1).collect();
    }
}

fn provenance_sort_key(provenance: &Provenance) -> (u8, String, String, String) {
    match provenance {
        Provenance::WorkingTree => (0, String::new(), String::new(), String::new()),
        Provenance::Commit { sha, author, date } => (
            1,
            sha.clone(),
            author.clone().unwrap_or_default(),
            date.clone().unwrap_or_default(),
        ),
    }
}

fn content_id(content: &[u8]) -> ContentId {
    ContentId(Sha256::digest(content).into())
}

#[derive(Debug)]
pub enum GitWalkError {
    Discover {
        target: PathBuf,
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    GixDecode {
        operation: &'static str,
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    GixObject {
        operation: &'static str,
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    Glob(globset::Error),
    Hash {
        operation: &'static str,
        source: gix_hash::decode::Error,
    },
    Ignore(ignore::Error),
    Io(io::Error),
    Override(ignore::Error),
    Path {
        path: PathBuf,
        source: std::path::StripPrefixError,
    },
}

impl fmt::Display for GitWalkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Discover { target, source } => {
                write!(
                    formatter,
                    "failed to discover git repo at {}: {source}",
                    target.display()
                )
            }
            Self::GixDecode { operation, source } => {
                write!(
                    formatter,
                    "git object decode failed during {operation}: {source}"
                )
            }
            Self::GixObject { operation, source } => {
                write!(
                    formatter,
                    "git object-store operation failed during {operation}: {source}"
                )
            }
            Self::Glob(source) => write!(formatter, "glob setup failed: {source}"),
            Self::Hash { operation, source } => {
                write!(
                    formatter,
                    "git object id parse failed during {operation}: {source}"
                )
            }
            Self::Ignore(source) => write!(formatter, "ignore traversal failed: {source}"),
            Self::Io(source) => write!(formatter, "filesystem traversal failed: {source}"),
            Self::Override(source) => write!(formatter, "ignore override setup failed: {source}"),
            Self::Path { path, source } => {
                write!(
                    formatter,
                    "failed to relativize {}: {source}",
                    path.display()
                )
            }
        }
    }
}

impl std::error::Error for GitWalkError {}

#[cfg(test)]
mod tests {
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
                LocationClass::ClientReachable,
            ),
            ("apps/api/.env", LocationClass::ServerOnly),
            ("apps/web/.env.local", LocationClass::ServerOnly),
            (
                "packages/ui/src/components/Btn.tsx",
                LocationClass::ClientReachable,
            ),
            ("services/api/index.ts", LocationClass::ServerOnly),
            ("services/api/src/api/handler.ts", LocationClass::ServerOnly),
            ("apps/web/app/api/route.ts", LocationClass::ServerOnly),
            ("apps/web/app/page.tsx", LocationClass::ClientReachable),
            (
                "apps/web/.next/server/vendor-chunks/x.js",
                LocationClass::ServerOnly,
            ),
        ];

        for (path, expected) in cases {
            assert_eq!(classify_location(path), expected, "{path}");
        }
    }

    #[test]
    fn classify_location_uses_segments_not_substrings() {
        let cases = [
            ("staticassets/x.js", LocationClass::Unknown),
            ("apps/web/src/myenv.ts", LocationClass::Unknown),
            ("apps/foo/api-docs/readme.md", LocationClass::Unknown),
            (
                "apps/web/app/foo/api/route.ts",
                LocationClass::ClientReachable,
            ),
        ];

        for (path, expected) in cases {
            assert_eq!(classify_location(path), expected, "{path}");
        }
    }

    #[test]
    fn classify_location_preserves_flat_repo_behavior() {
        let cases = [
            ("public/config.js", LocationClass::ClientReachable),
            ("app/page.tsx", LocationClass::ClientReachable),
            ("pages/index.tsx", LocationClass::ClientReachable),
            ("src/app/page.tsx", LocationClass::ClientReachable),
            ("src/pages/index.tsx", LocationClass::ClientReachable),
            ("src/components/Button.tsx", LocationClass::ClientReachable),
            ("src/client/widget.ts", LocationClass::ClientReachable),
            ("src/Button.client.tsx", LocationClass::ClientReachable),
            ("dist/bundle.js", LocationClass::ClientReachable),
            ("build/assets/app.js", LocationClass::ClientReachable),
            (".next/static/chunks/x.js", LocationClass::ClientReachable),
            (".env", LocationClass::ServerOnly),
            (".env.local", LocationClass::ServerOnly),
            ("server/index.ts", LocationClass::ServerOnly),
            (
                "supabase/functions/ping/index.ts",
                LocationClass::ServerOnly,
            ),
            ("api/handler.ts", LocationClass::ServerOnly),
            ("src/api/handler.ts", LocationClass::ServerOnly),
            ("src/lib/util.ts", LocationClass::Unknown),
        ];

        for (path, expected) in cases {
            assert_eq!(classify_location(path), expected, "{path}");
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
}
