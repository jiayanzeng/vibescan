use super::*;

pub(super) fn collect_history(
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

pub(super) fn collect_changed_blobs(
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

pub(super) fn reachable_ref_tips(
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

pub(super) fn collect_loose_refs(
    path: &Path,
    tips: &mut BTreeSet<ObjectId>,
) -> Result<(), GitWalkError> {
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

pub(super) fn collect_packed_refs(
    path: &Path,
    tips: &mut BTreeSet<ObjectId>,
) -> Result<(), GitWalkError> {
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

pub(super) fn parse_ref_oid(value: &str) -> Option<ObjectId> {
    ObjectId::from_hex(value.as_bytes()).ok()
}

pub(super) fn peel_to_commit(
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

pub(super) fn commit_provenance(commit: &CommitInfo) -> Provenance {
    Provenance::Commit {
        sha: commit.id.to_string(),
        author: commit.author.clone(),
        date: commit.date.clone(),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct CommitInfo {
    id: ObjectId,
    tree_id: ObjectId,
    parents: Vec<ObjectId>,
    author: Option<String>,
    date: Option<String>,
    commit_time: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct WalkCandidate {
    id: ObjectId,
    commit_time: i64,
}

pub(super) fn read_commit(
    objects: &gix_odb::Handle,
    id: ObjectId,
) -> Result<CommitInfo, GitWalkError> {
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
pub(super) struct TreeEntry {
    id: ObjectId,
    mode: EntryMode,
}

pub(super) fn tree_entries(
    objects: &gix_odb::Handle,
    tree_id: ObjectId,
) -> Result<BTreeMap<String, TreeEntry>, GitWalkError> {
    let mut entries = BTreeMap::new();
    collect_tree_entries(objects, tree_id, String::new(), &mut entries)?;
    Ok(entries)
}

pub(super) fn collect_tree_entries(
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

pub(super) fn push_content(
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
        locations: vec![UnitLocation {
            location_class: classify_location(&path.0, &content),
            path,
            provenance,
            additional_provenance: Vec::new(),
        }],
        content,
    });
}
