use super::*;

pub(super) fn repo_relative_path(repo_root: &Path, path: &Path) -> String {
    path.strip_prefix(repo_root)
        .unwrap_or(path)
        .components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

pub(super) fn project_url_from_key(finding: &Finding) -> Option<&str> {
    match &finding.evidence {
        Evidence::SupabaseKey {
            project: Some(project),
            ..
        } => Some(project.url.as_str()),
        _ => None,
    }
}

pub(super) fn project_url_from_rls(finding: &Finding) -> Option<&str> {
    match &finding.evidence {
        Evidence::RlsProbe { project, .. } | Evidence::RlsPolicy { project, .. } => {
            Some(project.url.as_str())
        }
        _ => None,
    }
}

pub(super) struct RlsReadExposure<'a> {
    pub(super) table: &'a str,
    pub(super) reproduction: String,
}

pub(super) fn rls_read_exposure(finding: &Finding) -> Option<RlsReadExposure<'_>> {
    if finding.category != Category::Rls {
        return None;
    }

    match &finding.evidence {
        Evidence::RlsProbe {
            table,
            endpoint,
            observed_row_count,
            exposure: RlsExposure::Exposed,
            ..
        } => Some(RlsReadExposure {
            table,
            reproduction: format!(
                "{endpoint} returned {observed_row_count} row(s) to the public key"
            ),
        }),
        Evidence::RlsPolicy {
            table,
            exposure: RlsExposure::RlsDisabled,
            ..
        } => Some(RlsReadExposure {
            table,
            reproduction: format!("table {table} has RLS disabled"),
        }),
        Evidence::RlsPolicy {
            table,
            exposure: RlsExposure::PermissivePolicy,
            ..
        } => Some(RlsReadExposure {
            table,
            reproduction: format!("table {table} has permissive USING (true)"),
        }),
        // TODO(post-tier-e): reconsider SELECT-specific missing-policy evidence only if
        // catalog semantics establish read exposure rather than default-deny behavior.
        Evidence::RlsPolicy {
            exposure: RlsExposure::MissingOperationPolicy | RlsExposure::InferredWriteExposure,
            ..
        } => None,
        _ => None,
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct FindingCoalesceBaseKey {
    category: Category,
    rule_or_class: String,
    fingerprint: String,
    severity: Severity,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct FindingCoalesceKey {
    pub(super) base: FindingCoalesceBaseKey,
    pub(super) project_url: Option<String>,
}

pub(super) fn coalesce_findings(findings: Vec<Finding>) -> Vec<Finding> {
    let mut groups = BTreeMap::<FindingCoalesceBaseKey, Vec<Finding>>::new();
    let mut passthrough = Vec::new();

    for finding in findings {
        let Some(key) = coalesce_key(&finding) else {
            passthrough.push(finding);
            continue;
        };
        groups.entry(key.base).or_default().push(finding);
    }

    for (base, findings) in groups {
        passthrough.extend(coalesce_finding_group(base, findings));
    }
    passthrough
}

pub(super) fn coalesce_finding_group(
    base: FindingCoalesceBaseKey,
    findings: Vec<Finding>,
) -> Vec<Finding> {
    let mut known = BTreeMap::<String, (SupabaseProject, Vec<Finding>)>::new();
    let mut projectless = Vec::new();

    for finding in findings {
        if let Some(project) = project_from_key_finding(&finding).cloned() {
            let normalized = normalized_project_url(&project.url);
            known
                .entry(normalized)
                .or_insert_with(|| (project, Vec::new()))
                .1
                .push(finding);
        } else {
            projectless.push(finding);
        }
    }

    if known.len() == 1 {
        let (_, (project, mut findings)) = known.pop_first().expect("one known project");
        findings.append(&mut projectless);
        return vec![merge_finding_group(base, Some(project), findings)];
    }

    let mut output = known
        .into_values()
        .map(|(project, findings)| merge_finding_group(base.clone(), Some(project), findings))
        .collect::<Vec<_>>();
    if !projectless.is_empty() {
        output.push(merge_finding_group(base, None, projectless));
    }
    output
}

pub(super) fn merge_finding_group(
    base: FindingCoalesceBaseKey,
    project: Option<SupabaseProject>,
    mut findings: Vec<Finding>,
) -> Finding {
    findings.sort_by(|left, right| left.id.cmp(&right.id));
    let mut merged = findings.remove(0);
    sort_locations(&mut merged.locations);
    for finding in findings {
        merge_findings(&mut merged, finding);
    }
    set_key_project(&mut merged, project.as_ref());
    let key = FindingCoalesceKey {
        base,
        project_url: project
            .as_ref()
            .map(|project| normalized_project_url(&project.url)),
    };
    merged.id = coalesced_finding_id(&key);
    merged
}

pub(super) fn coalesce_key(finding: &Finding) -> Option<FindingCoalesceKey> {
    match &finding.evidence {
        Evidence::Secret { fingerprint, .. } => Some(FindingCoalesceKey {
            base: FindingCoalesceBaseKey {
                category: finding.category,
                rule_or_class: secret_rule_key(finding).to_owned(),
                fingerprint: fingerprint.0.clone(),
                severity: finding.severity,
            },
            project_url: None,
        }),
        Evidence::SupabaseKey {
            class,
            project,
            fingerprint,
            ..
        } => Some(FindingCoalesceKey {
            base: FindingCoalesceBaseKey {
                category: finding.category,
                rule_or_class: format!("supabase-key:{}", supabase_key_class_key(*class)),
                fingerprint: fingerprint.0.clone(),
                severity: finding.severity,
            },
            project_url: project
                .as_ref()
                .map(|project| normalized_project_url(&project.url)),
        }),
        _ => None,
    }
}

pub(super) fn coalesced_finding_id(key: &FindingCoalesceKey) -> FindingId {
    let mut hasher = Sha256::new();
    hasher.update(category_key(key.base.category).as_bytes());
    hasher.update(b"\0");
    hasher.update(key.base.rule_or_class.as_bytes());
    hasher.update(b"\0");
    hasher.update(key.base.fingerprint.as_bytes());
    hasher.update(b"\0");
    hasher.update(key.project_url.as_deref().unwrap_or("<none>").as_bytes());
    hasher.update(b"\0");
    hasher.update(severity_key(key.base.severity).as_bytes());

    let prefix = if key.base.rule_or_class.starts_with("supabase-key:") {
        "supabase-key"
    } else {
        "secret"
    };
    FindingId(format!(
        "{prefix}-{}",
        hex::encode(&hasher.finalize()[..12])
    ))
}

pub(super) fn project_from_key_finding(finding: &Finding) -> Option<&SupabaseProject> {
    match &finding.evidence {
        Evidence::SupabaseKey {
            project: Some(project),
            ..
        } => Some(project),
        _ => None,
    }
}

pub(super) fn set_key_project(finding: &mut Finding, project: Option<&SupabaseProject>) {
    if let Evidence::SupabaseKey {
        project: finding_project,
        ..
    } = &mut finding.evidence
    {
        *finding_project = project.cloned();
        if let Some(project) = finding_project {
            project.url = normalized_project_url(&project.url);
        }
    }
}

pub(super) fn merge_findings(existing: &mut Finding, incoming: Finding) {
    existing.locations.extend(incoming.locations);
    sort_locations(&mut existing.locations);
    existing.related.extend(incoming.related);
    existing.related.sort();
    existing.related.dedup();
}

pub(super) fn sort_locations(locations: &mut Vec<Location>) {
    locations.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| span_key(&left.span).cmp(&span_key(&right.span)))
            .then_with(|| provenance_key(&left.provenance).cmp(&provenance_key(&right.provenance)))
            .then_with(|| {
                location_class_rank(left.location_class)
                    .cmp(&location_class_rank(right.location_class))
            })
    });
    locations.dedup();
}

pub(super) fn span_key(span: &Option<vibescan_types::Span>) -> Option<(u32, u32, u32)> {
    span.map(|span| (span.line, span.col_start, span.col_end))
}

pub(super) fn provenance_key(provenance: &Provenance) -> String {
    match provenance {
        Provenance::WorkingTree => "working_tree".to_owned(),
        Provenance::Commit { sha, author, date } => {
            format!(
                "commit:{}:{}:{}",
                sha,
                author.as_deref().unwrap_or(""),
                date.as_deref().unwrap_or("")
            )
        }
    }
}

pub(super) fn secret_rule_key(finding: &Finding) -> &str {
    finding
        .title
        .strip_prefix("Secret candidate matched ")
        .unwrap_or(&finding.title)
}

pub(super) fn category_key(category: Category) -> &'static str {
    match category {
        Category::SecretExposure => "secret_exposure",
        Category::KeyClassification => "key_classification",
        Category::Rls => "rls",
        Category::DependencyIntegrity => "dependency_integrity",
        Category::Correlation => "correlation",
    }
}

pub(super) fn supabase_key_class_key(class: SupabaseKeyClass) -> &'static str {
    match class {
        SupabaseKeyClass::PublishableNew => "publishable_new",
        SupabaseKeyClass::SecretNew => "secret_new",
        SupabaseKeyClass::AnonLegacy => "anon_legacy",
        SupabaseKeyClass::ServiceRoleLegacy => "service_role_legacy",
        SupabaseKeyClass::Unknown => "unknown",
    }
}

pub(super) fn severity_key(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}

pub(super) fn normalized_project_url(url: &str) -> String {
    let trimmed = url.trim_end_matches('/');
    for scheme in ["https://", "http://"] {
        if let Some(rest) = trimmed.strip_prefix(scheme) {
            return if let Some((host, path)) = rest.split_once('/') {
                format!("{scheme}{}/{}", host.to_ascii_lowercase(), path)
            } else {
                format!("{scheme}{}", rest.to_ascii_lowercase())
            };
        }
    }
    trimmed.to_ascii_lowercase()
}

pub(super) fn source_project_key(project: Option<&SupabaseProject>) -> (String, Option<String>) {
    project.map_or_else(
        || (String::new(), None),
        |project| (normalized_project_url(&project.url), project.ref_id.clone()),
    )
}

pub(super) fn max_location_class(locations: &[Location]) -> LocationClass {
    locations
        .iter()
        .map(|location| location.location_class)
        .max_by_key(|class| location_class_rank(*class))
        .unwrap_or(LocationClass::Unknown)
}

pub(super) fn location_has_commit(location: &Location) -> bool {
    std::iter::once(&location.provenance)
        .chain(location.additional_provenance.iter())
        .any(|provenance| matches!(provenance, Provenance::Commit { .. }))
}

pub(super) fn location_class_rank(location_class: LocationClass) -> u8 {
    match location_class {
        LocationClass::Unknown => 0,
        LocationClass::ServerOnly => 1,
        LocationClass::ClientReachable => 2,
    }
}

pub(super) fn correlation_id(rule_id: &CorrelationRuleId, related: &[&FindingId]) -> FindingId {
    let mut ids = related.iter().map(|id| id.0.as_str()).collect::<Vec<_>>();
    ids.sort_unstable();
    let mut hasher = Sha256::new();
    hasher.update(rule_id.0.as_bytes());
    for id in ids {
        hasher.update(b"\0");
        hasher.update(id.as_bytes());
    }
    FindingId(format!(
        "correlation-{}",
        hex::encode(&hasher.finalize()[..12])
    ))
}

pub(super) fn dedup_findings(findings: Vec<Finding>) -> Vec<Finding> {
    let mut by_id = BTreeMap::new();
    for finding in findings {
        by_id.entry(finding.id.clone()).or_insert(finding);
    }
    by_id.into_values().collect()
}

pub(super) fn sort_findings(findings: &mut [Finding]) {
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.category.cmp(&b.category))
            .then_with(|| a.id.cmp(&b.id))
    });
}

pub(super) fn compute_stats(
    findings: &[Finding],
    warnings: &[ScopeWarning],
    collection: vibescan_git::WalkStats,
    truncated: bool,
) -> ScanStats {
    let mut stats = ScanStats {
        paths_walked: collection.paths_walked,
        blobs_read: collection.blobs_read,
        unique_contents: collection.unique_contents,
        units_materialized: collection.units_materialized,
        truncated,
        ..ScanStats::default()
    };
    for finding in findings {
        *stats.by_severity.entry(finding.severity).or_default() += 1;
        *stats.by_category.entry(finding.category).or_default() += 1;
    }
    for warning in warnings {
        match warning {
            ScopeWarning::LargeFileSkipped { .. } => stats.skipped_large_files += 1,
            ScopeWarning::BinaryFileSkipped { .. } => stats.skipped_binary_files += 1,
            ScopeWarning::HistoryBudgetHit { .. } => stats.scan_budget_hit = true,
            _ => {}
        }
    }
    stats
}

pub(super) fn history_scope(
    include_history: bool,
    max_commits: Option<usize>,
    stats: &vibescan_git::HistoryWalkStats,
) -> HistoryScope {
    if !include_history {
        return HistoryScope::Disabled;
    }

    match max_commits {
        Some(max_commits) => HistoryScope::Budgeted {
            max_commits: max_commits as u64,
            scanned_commits: stats.scanned_commits as u64,
            truncated: stats.truncated,
        },
        None => HistoryScope::Exhaustive {
            scanned_commits: stats.scanned_commits as u64,
        },
    }
}

pub(super) fn parse_severity(value: &str) -> Option<Severity> {
    match value.to_ascii_lowercase().as_str() {
        "critical" => Some(Severity::Critical),
        "high" => Some(Severity::High),
        "medium" => Some(Severity::Medium),
        "low" => Some(Severity::Low),
        "info" => Some(Severity::Info),
        _ => None,
    }
}

pub(super) fn fingerprint(raw: &str) -> SecretFingerprint {
    let mut hasher = Sha256::new();
    hasher.update(raw.as_bytes());
    SecretFingerprint(hex::encode(&hasher.finalize()[..16]))
}

pub(super) fn redact_secret(raw: &str) -> String {
    let chars = raw.chars().collect::<Vec<_>>();
    if chars.len() <= 12 {
        return "***".to_owned();
    }
    let prefix = chars.iter().take(6).collect::<String>();
    let suffix = chars
        .iter()
        .rev()
        .take(4)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<String>();
    format!("{prefix}...{suffix}")
}
