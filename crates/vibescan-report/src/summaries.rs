use super::*;

pub(super) fn location_summary(location: &Location) -> String {
    let span = location
        .span
        .map(|span| format!(":{}:{}-{}", span.line, span.col_start, span.col_end))
        .unwrap_or_default();
    let history = history_range_summary(location)
        .map(|summary| format!("; {summary}"))
        .unwrap_or_default();
    format!(
        "{}{} ({}, {}{})",
        location.path.0,
        span,
        provenance_summary(&location.provenance),
        format!("{:?}", location.location_class).to_ascii_lowercase(),
        history
    )
}

pub(super) fn history_range_summary(location: &Location) -> Option<String> {
    let mut commits = std::iter::once(&location.provenance)
        .chain(location.additional_provenance.iter())
        .filter_map(commit_sort_key)
        .collect::<Vec<_>>();
    if commits.len() < 2 {
        return None;
    }

    commits.sort_by(|left, right| {
        left.timestamp
            .cmp(&right.timestamp)
            .then_with(|| left.sha.cmp(right.sha))
    });
    let first = commits.first()?;
    let last = commits.last()?;
    Some(format!(
        "first seen commit {}; last seen commit {}",
        short_sha(first.sha),
        short_sha(last.sha)
    ))
}

pub(super) struct CommitSortKey<'a> {
    sha: &'a str,
    timestamp: i64,
}

pub(super) fn commit_sort_key(provenance: &Provenance) -> Option<CommitSortKey<'_>> {
    let Provenance::Commit { sha, date, .. } = provenance else {
        return None;
    };
    let timestamp = date
        .as_deref()
        .and_then(|value| value.split_whitespace().next())
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or_default();
    Some(CommitSortKey { sha, timestamp })
}

pub(super) fn short_sha(sha: &str) -> &str {
    sha.get(..12).unwrap_or(sha)
}

pub(super) fn provenance_summary(provenance: &Provenance) -> String {
    match provenance {
        Provenance::WorkingTree => "working tree".to_owned(),
        Provenance::Commit { sha, .. } => format!("commit {sha}"),
    }
}

pub(super) fn warning_summary(warning: &ScopeWarning) -> String {
    match warning {
        ScopeWarning::HistoryBudgetHit { max_commits } => {
            format!("history scan stopped at budget of {max_commits} commits")
        }
        ScopeWarning::ShallowClone => "repository is a shallow clone".to_owned(),
        ScopeWarning::SubmoduleSkipped { path } => format!("submodule skipped at {}", path.0),
        ScopeWarning::MergeCommitFirstParentOnly { sha } => {
            format!("merge commit {sha} diffed against first parent only")
        }
        ScopeWarning::LargeFileSkipped { path, bytes } => {
            format!("large file skipped: {} ({} bytes)", path.0, bytes)
        }
        ScopeWarning::BinaryFileSkipped { path } => format!("binary file skipped: {}", path.0),
        ScopeWarning::Other { message } => message.clone(),
    }
}

pub(super) fn network_action_summary(action: &NetworkActionAudit) -> String {
    let intent = match action.intent {
        NetworkActionIntent::Get => "GET",
        NetworkActionIntent::Select => "SELECT",
    };
    let kind = match action.kind {
        NetworkActionKind::RootEnumeration => "root enumeration",
        NetworkActionKind::TableRead => "table read",
        NetworkActionKind::CatalogIntrospection => "catalog introspection",
        NetworkActionKind::RegistryExistence => "registry existence",
        NetworkActionKind::RegistryAdvisory => "registry advisory",
    };
    let table = action
        .table
        .as_deref()
        .map(|table| format!(" for table {table}"))
        .unwrap_or_default();
    let package = action
        .package
        .as_deref()
        .map(|package| format!(" for package {package}"))
        .unwrap_or_default();
    let status = action
        .status
        .map(|status| format!("; HTTP {status}"))
        .unwrap_or_default();
    let rows = action
        .observed_row_count
        .map(|count| format!("; observed {count} row(s)"))
        .unwrap_or_default();
    format!(
        "{intent} {kind}{table}{package} at {} -> {}{status}{rows}",
        action.endpoint,
        network_action_outcome_name(action.outcome)
    )
}

pub(super) fn network_action_outcome_name(outcome: NetworkActionOutcome) -> &'static str {
    match outcome {
        NetworkActionOutcome::RootEnumerated => "root enumerated",
        NetworkActionOutcome::RootUnavailable => "root unavailable",
        NetworkActionOutcome::Exposed => "exposed",
        NetworkActionOutcome::NoRowsObserved => "no rows observed",
        NetworkActionOutcome::Protected => "protected",
        NetworkActionOutcome::NotFound => "not found",
        NetworkActionOutcome::KeyRejected => "key rejected",
        NetworkActionOutcome::InvalidResponse => "invalid response",
        NetworkActionOutcome::TransportError => "transport error",
        NetworkActionOutcome::CatalogRead => "catalog read",
        NetworkActionOutcome::RegistryResolved => "registry resolved",
        NetworkActionOutcome::AdvisoryFetched => "advisory fetched",
    }
}

pub(super) fn registry_egress_summary(disclosure: &RegistryNameEgress) -> String {
    let ecosystem = match disclosure.ecosystem {
        Ecosystem::Npm => "npm",
        Ecosystem::PyPi => "PyPI",
    };
    format!("{ecosystem} package names sent to {}", disclosure.host)
}

pub(super) fn history_summary(history: &HistoryScope) -> String {
    match history {
        HistoryScope::Disabled => "history disabled".to_owned(),
        HistoryScope::WorkingTreeOnly => "working tree only".to_owned(),
        HistoryScope::Budgeted {
            max_commits,
            scanned_commits,
            truncated,
        } => format!(
            "history budgeted {scanned_commits}/{max_commits} commits{}",
            if *truncated { " truncated" } else { "" }
        ),
        HistoryScope::Exhaustive { scanned_commits } => {
            format!("history exhaustive {scanned_commits} commits")
        }
    }
}
