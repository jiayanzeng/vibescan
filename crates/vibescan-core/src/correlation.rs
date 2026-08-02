use super::*;

/// Apply the registered v1 correlation rules.
pub fn correlate_findings(findings: &[Finding]) -> Vec<Finding> {
    CORRELATION_RULES
        .iter()
        .flat_map(|rule| (rule.apply)(rule, findings))
        .collect()
}

#[derive(Clone, Copy)]
pub(super) struct CorrelationRule {
    id: &'static str,
    absorbs_related_in_summary: bool,
    apply: fn(&CorrelationRule, &[Finding]) -> Vec<Finding>,
}

pub(super) const CORRELATION_RULES: &[CorrelationRule] = &[
    CorrelationRule {
        id: "exposed-public-key-chain",
        absorbs_related_in_summary: true,
        apply: correlate_exposed_public_key,
    },
    CorrelationRule {
        id: "elevated-key-in-tree",
        absorbs_related_in_summary: false,
        apply: correlate_elevated_key_moots_rls,
    },
];

pub(super) fn correlate_exposed_public_key(
    rule: &CorrelationRule,
    findings: &[Finding],
) -> Vec<Finding> {
    let public_keys = findings.iter().filter(|finding| {
        matches!(
            finding.evidence,
            Evidence::SupabaseKey {
                class: SupabaseKeyClass::PublishableNew | SupabaseKeyClass::AnonLegacy,
                ..
            }
        ) && (max_location_class(&finding.locations) == LocationClass::ClientReachable
            || finding.locations.iter().any(location_has_commit))
    });

    public_keys
        .flat_map(|key_finding| {
            findings.iter().filter_map(move |rls_finding| {
                let same_project =
                    project_url_from_key(key_finding).zip(project_url_from_rls(rls_finding));
                if !matches!(
                    same_project,
                    Some((a, b)) if normalized_project_url(a) == normalized_project_url(b)
                ) {
                    return None;
                }
                let read_exposure = rls_read_exposure(rls_finding)?;

                let rule_id = CorrelationRuleId(rule.id.to_owned());
                let id = correlation_id(&rule_id, &[&key_finding.id, &rls_finding.id]);
                let mut locations = key_finding
                    .locations
                    .iter()
                    .cloned()
                    .chain(rls_finding.locations.iter().cloned())
                    .collect::<Vec<_>>();
                sort_locations(&mut locations);
                Some(Finding {
                    id,
                    category: Category::Correlation,
                    severity: Severity::Critical,
                    title: format!(
                        "Public Supabase key can read unprotected table {}",
                        read_exposure.table
                    ),
                    detail: "A browser-reachable Supabase public key is present and an API-exposed table on the same project is readable without additional authorization.".to_owned(),
                    locations,
                    evidence: Evidence::Correlation {
                        rule_id,
                        reproduction: Some(read_exposure.reproduction),
                    },
                    remediation: "Fix RLS policies for the exposed table, then rotate affected keys if exposure is confirmed.".to_owned(),
                    related: vec![key_finding.id.clone(), rls_finding.id.clone()],
                    confidence: Confidence::Confirmed,
                })
            })
        })
        .collect()
}

pub(super) fn correlate_elevated_key_moots_rls(
    rule: &CorrelationRule,
    findings: &[Finding],
) -> Vec<Finding> {
    findings
        .iter()
        .filter(|finding| {
            matches!(
                finding.evidence,
                Evidence::SupabaseKey {
                    class: SupabaseKeyClass::SecretNew | SupabaseKeyClass::ServiceRoleLegacy,
                    ..
                }
            ) && finding.locations.iter().any(location_has_commit)
        })
        .filter_map(|key_finding| {
            let key_project = project_url_from_key(key_finding)?;
            let related_rls = findings
                .iter()
                .filter(|finding| {
                    finding.category == Category::Rls
                        && project_url_from_rls(finding).is_some_and(|project| {
                            normalized_project_url(project) == normalized_project_url(key_project)
                        })
                })
                .map(|finding| finding.id.clone())
                .collect::<Vec<_>>();

            if related_rls.is_empty() {
                return None;
            }

            let mut related = vec![key_finding.id.clone()];
            related.extend(related_rls);
            related.sort();
            related.dedup();
            let rule_id = CorrelationRuleId(rule.id.to_owned());
            let related_refs = related.iter().collect::<Vec<_>>();
            let mut locations = key_finding.locations.clone();
            sort_locations(&mut locations);
            Some(Finding {
                id: correlation_id(&rule_id, &related_refs),
                category: Category::Correlation,
                severity: Severity::Critical,
                title: "Exposed elevated Supabase key bypasses RLS".to_owned(),
                detail: "An elevated Supabase key is committed for this project. RLS findings on the same project are moot until this key is rotated because elevated keys bypass RLS entirely.".to_owned(),
                locations,
                evidence: Evidence::Correlation {
                    rule_id,
                    reproduction: None,
                },
                remediation: "Rotate and remove the elevated key first, then reassess remaining RLS findings.".to_owned(),
                related,
                confidence: Confidence::Likely,
            })
        })
        .collect()
}

pub(super) fn absorb_correlated_constituents(findings: &mut Vec<Finding>) {
    let absorbed = findings
        .iter()
        .filter_map(|finding| {
            let Evidence::Correlation { rule_id, .. } = &finding.evidence else {
                return None;
            };
            CORRELATION_RULES
                .iter()
                .find(|rule| rule.id == rule_id.0 && rule.absorbs_related_in_summary)
                .map(|_| finding.related.clone())
        })
        .flatten()
        .collect::<BTreeSet<_>>();

    if absorbed.is_empty() {
        return;
    }

    findings.retain(|finding| {
        finding.category == Category::Correlation || !absorbed.contains(&finding.id)
    });
}

pub(super) fn resolve_generic_candidates(candidates: &[SecretCandidate]) -> Vec<Finding> {
    candidates
        .iter()
        .filter(|candidate| candidate.kind != vibescan_types::CandidateKind::PossibleSupabaseKey)
        .map(generic_candidate_finding)
        .collect()
}

pub(super) struct ClassifiedKeyFact {
    pub(super) finding: Finding,
    #[cfg_attr(not(feature = "network"), allow(dead_code))]
    pub(super) raw_key: Vec<u8>,
    pub(super) sources: Vec<ClassifiedKeySource>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ClassifiedKeySource {
    pub(super) unit_ref: UnitRef,
    pub(super) project: Option<SupabaseProject>,
}

pub(super) fn coalesce_classified_key_facts(
    facts: Vec<ClassifiedKeyFact>,
) -> Vec<ClassifiedKeyFact> {
    let mut groups = BTreeMap::<FindingCoalesceBaseKey, Vec<ClassifiedKeyFact>>::new();
    for fact in facts {
        let key = coalesce_key(&fact.finding).expect("classified key has a coalesce key");
        groups.entry(key.base).or_default().push(fact);
    }

    groups
        .into_iter()
        .flat_map(|(base, facts)| coalesce_classified_key_group(base, facts))
        .collect()
}

pub(super) fn coalesce_classified_key_group(
    base: FindingCoalesceBaseKey,
    facts: Vec<ClassifiedKeyFact>,
) -> Vec<ClassifiedKeyFact> {
    let mut known = BTreeMap::<String, (SupabaseProject, Vec<ClassifiedKeyFact>)>::new();
    let mut projectless = Vec::new();

    for fact in facts {
        if let Some(project) = project_from_key_finding(&fact.finding).cloned() {
            let normalized = normalized_project_url(&project.url);
            known
                .entry(normalized)
                .or_insert_with(|| (project, Vec::new()))
                .1
                .push(fact);
        } else {
            projectless.push(fact);
        }
    }

    if known.len() == 1 {
        let (_, (project, mut facts)) = known.pop_first().expect("one known project");
        facts.append(&mut projectless);
        return vec![merge_classified_key_group(base, Some(project), facts)];
    }

    let mut output = known
        .into_values()
        .map(|(project, facts)| merge_classified_key_group(base.clone(), Some(project), facts))
        .collect::<Vec<_>>();
    if !projectless.is_empty() {
        output.push(merge_classified_key_group(base, None, projectless));
    }
    output
}

pub(super) fn merge_classified_key_group(
    base: FindingCoalesceBaseKey,
    project: Option<SupabaseProject>,
    mut facts: Vec<ClassifiedKeyFact>,
) -> ClassifiedKeyFact {
    facts.sort_by(|left, right| left.finding.id.cmp(&right.finding.id));
    let mut merged = facts.remove(0);
    sort_locations(&mut merged.finding.locations);
    for fact in facts {
        merge_findings(&mut merged.finding, fact.finding);
        merged.sources.extend(fact.sources);
    }
    merged.sources.sort_by(|left, right| {
        left.unit_ref
            .content_id
            .cmp(&right.unit_ref.content_id)
            .then_with(|| left.unit_ref.locations.cmp(&right.unit_ref.locations))
            .then_with(|| {
                source_project_key(left.project.as_ref())
                    .cmp(&source_project_key(right.project.as_ref()))
            })
    });
    merged.sources.dedup();
    set_key_project(&mut merged.finding, project.as_ref());
    merged.finding.id = coalesced_finding_id(&FindingCoalesceKey {
        base,
        project_url: project
            .as_ref()
            .map(|project| normalized_project_url(&project.url)),
    });
    merged
}

#[cfg(feature = "network")]
pub(super) fn tier0_probe_inputs(
    classifications: &[ClassifiedKeyFact],
    tables_by_project: &BTreeMap<String, BTreeSet<String>>,
) -> Vec<Tier0RlsProbeInput> {
    let mut by_project = BTreeMap::<String, Tier0RlsProbeInput>::new();
    for fact in classifications {
        let Some(input) = (|| {
            let Evidence::SupabaseKey {
                class: SupabaseKeyClass::PublishableNew | SupabaseKeyClass::AnonLegacy,
                project: Some(project),
                ..
            } = &fact.finding.evidence
            else {
                return None;
            };
            let public_key = std::str::from_utf8(&fact.raw_key).ok()?.to_owned();
            let key_location = best_key_location(&fact.finding.locations)?.clone();
            let normalized_project = normalized_project_url(&project.url);
            Some(Tier0RlsProbeInput {
                project: project.clone(),
                public_key,
                key_location,
                candidate_tables: tables_by_project
                    .get(&normalized_project)
                    .cloned()
                    .unwrap_or_default(),
            })
        })() else {
            continue;
        };
        let key = normalized_project_url(&input.project.url);
        match by_project.entry(key) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(input);
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                if probe_input_is_better(&input, entry.get()) {
                    entry.insert(input);
                }
            }
        }
    }
    by_project.into_values().collect()
}

#[cfg(feature = "network")]
pub(super) fn best_key_location(locations: &[Location]) -> Option<&Location> {
    locations.iter().max_by(|left, right| {
        location_class_rank(left.location_class)
            .cmp(&location_class_rank(right.location_class))
            .then_with(|| right.path.cmp(&left.path))
            .then_with(|| span_key(&right.span).cmp(&span_key(&left.span)))
    })
}

#[cfg(feature = "network")]
pub(super) fn tier1_credential_location() -> Location {
    Location {
        path: RepoPath("<environment:VIBESCAN_SUPABASE_DB_URL>".to_owned()),
        span: None,
        provenance: Provenance::WorkingTree,
        additional_provenance: Vec::new(),
        location_class: LocationClass::ServerOnly,
    }
}

#[cfg_attr(not(feature = "network"), allow(dead_code))]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) enum ApiReferenceKind {
    Table,
    Rpc,
}

#[cfg_attr(not(feature = "network"), allow(dead_code))]
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct SourceScope(pub(super) String);

#[cfg_attr(not(feature = "network"), allow(dead_code))]
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct ApiReference {
    pub(super) kind: ApiReferenceKind,
    content_id: ContentId,
    pub(super) source_scope: SourceScope,
    pub(super) name: String,
}

#[cfg_attr(not(feature = "network"), allow(dead_code))]
pub(super) struct ApiReferenceAssociations {
    pub(super) tables_by_project: BTreeMap<String, BTreeSet<String>>,
    pub(super) warnings: Vec<ScopeWarning>,
}

#[cfg_attr(not(feature = "network"), allow(dead_code))]
pub(super) fn harvest_api_references(units: &[ScannableUnit]) -> Vec<ApiReference> {
    let mut references = BTreeSet::new();
    for unit in units {
        let Ok(content) = std::str::from_utf8(&unit.content) else {
            continue;
        };
        let mut tables = BTreeSet::new();
        let mut rpcs = BTreeSet::new();
        harvest_quoted_method_names(content, ".from", &mut tables);
        harvest_quoted_method_names(content, ".rpc", &mut rpcs);
        harvest_rest_paths(content, &mut tables);
        let scopes = unit
            .locations
            .iter()
            .map(|location| source_scope(&location.path.0))
            .collect::<BTreeSet<_>>();
        for scope in scopes {
            for name in &tables {
                references.insert(ApiReference {
                    kind: ApiReferenceKind::Table,
                    content_id: unit.content_id.clone(),
                    source_scope: scope.clone(),
                    name: name.clone(),
                });
            }
            for name in &rpcs {
                references.insert(ApiReference {
                    kind: ApiReferenceKind::Rpc,
                    content_id: unit.content_id.clone(),
                    source_scope: scope.clone(),
                    name: name.clone(),
                });
            }
        }
    }
    references.into_iter().collect()
}

#[cfg_attr(not(feature = "network"), allow(dead_code))]
pub(super) fn source_scope(path: &str) -> SourceScope {
    let segments = path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    for (index, segment) in segments.iter().enumerate() {
        if matches!(*segment, "apps" | "packages" | "services") && index + 1 < segments.len() {
            return SourceScope(segments[..=index + 1].join("/"));
        }
    }
    SourceScope(".".to_owned())
}

#[cfg_attr(not(feature = "network"), allow(dead_code))]
pub(super) fn associate_api_references(
    references: &[ApiReference],
    facts: &[ClassifiedKeyFact],
) -> ApiReferenceAssociations {
    let mut projects_by_content = BTreeMap::<ContentId, BTreeSet<String>>::new();
    let mut projects_by_scope = BTreeMap::<SourceScope, BTreeSet<String>>::new();
    for source in facts.iter().flat_map(|fact| &fact.sources) {
        let Some(project) = &source.project else {
            continue;
        };
        let project_url = normalized_project_url(&project.url);
        projects_by_content
            .entry(source.unit_ref.content_id.clone())
            .or_default()
            .insert(project_url.clone());
        for scope in source
            .unit_ref
            .locations
            .iter()
            .map(|location| source_scope(&location.path.0))
        {
            projects_by_scope
                .entry(scope)
                .or_default()
                .insert(project_url.clone());
        }
    }

    let mut tables_by_project = BTreeMap::<String, BTreeSet<String>>::new();
    let mut warning_messages = BTreeSet::new();
    for reference in references {
        if reference.kind == ApiReferenceKind::Rpc {
            continue;
        }
        match associated_project(reference, &projects_by_content, &projects_by_scope) {
            Ok(project_url) => {
                tables_by_project
                    .entry(project_url)
                    .or_default()
                    .insert(reference.name.clone());
            }
            Err(reason) => {
                warning_messages.insert(format!(
                    "Tier 0 skipped table reference {} from scope {}: {reason}",
                    reference.name, reference.source_scope.0
                ));
            }
        }
    }

    ApiReferenceAssociations {
        tables_by_project,
        warnings: warning_messages
            .into_iter()
            .map(|message| ScopeWarning::Other { message })
            .collect(),
    }
}

#[cfg_attr(not(feature = "network"), allow(dead_code))]
pub(super) fn associated_project(
    reference: &ApiReference,
    projects_by_content: &BTreeMap<ContentId, BTreeSet<String>>,
    projects_by_scope: &BTreeMap<SourceScope, BTreeSet<String>>,
) -> Result<String, &'static str> {
    if let Some(projects) = projects_by_content.get(&reference.content_id) {
        return unique_project(projects);
    }
    projects_by_scope
        .get(&reference.source_scope)
        .map_or(Err("no associated Supabase project"), unique_project)
}

#[cfg_attr(not(feature = "network"), allow(dead_code))]
pub(super) fn unique_project(projects: &BTreeSet<String>) -> Result<String, &'static str> {
    if projects.len() == 1 {
        Ok(projects.first().expect("one project").clone())
    } else {
        Err("ambiguous Supabase project association")
    }
}

#[cfg_attr(not(feature = "network"), allow(dead_code))]
pub(super) fn harvest_quoted_method_names(
    content: &str,
    method: &str,
    tables: &mut BTreeSet<String>,
) {
    let mut rest = content;
    while let Some(index) = rest.find(method) {
        rest = &rest[index + method.len()..];
        let trimmed = rest.trim_start();
        let Some(after_paren) = trimmed.strip_prefix('(') else {
            continue;
        };
        let after_space = after_paren.trim_start();
        let Some(quote) = after_space
            .chars()
            .next()
            .filter(|quote| *quote == '\'' || *quote == '"')
        else {
            continue;
        };
        let after_quote = &after_space[quote.len_utf8()..];
        let Some(end) = after_quote.find(quote) else {
            continue;
        };
        insert_table_name(&after_quote[..end], tables);
        rest = &after_quote[end + quote.len_utf8()..];
    }
}

#[cfg_attr(not(feature = "network"), allow(dead_code))]
pub(super) fn harvest_rest_paths(content: &str, tables: &mut BTreeSet<String>) {
    let mut rest = content;
    const MARKER: &str = "/rest/v1/";
    while let Some(index) = rest.find(MARKER) {
        let after_marker = &rest[index + MARKER.len()..];
        let end = after_marker
            .find(|ch: char| {
                ch.is_whitespace()
                    || matches!(
                        ch,
                        '/' | '?' | '#' | '"' | '\'' | '`' | ')' | ']' | '}' | '&'
                    )
            })
            .unwrap_or(after_marker.len());
        insert_table_name(&after_marker[..end], tables);
        rest = &after_marker[end..];
    }
}

#[cfg_attr(not(feature = "network"), allow(dead_code))]
pub(super) fn insert_table_name(name: &str, tables: &mut BTreeSet<String>) {
    let name = name.trim();
    if !name.is_empty()
        && name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.'))
    {
        tables.insert(name.to_owned());
    }
}

#[cfg(feature = "network")]
pub(super) fn probe_input_is_better(
    candidate: &Tier0RlsProbeInput,
    current: &Tier0RlsProbeInput,
) -> bool {
    location_class_rank(candidate.key_location.location_class)
        .cmp(&location_class_rank(current.key_location.location_class))
        .then_with(|| current.key_location.path.cmp(&candidate.key_location.path))
        .is_gt()
}

pub(super) fn generic_candidate_finding(candidate: &SecretCandidate) -> Finding {
    let raw = String::from_utf8_lossy(&candidate.raw_match);
    let fingerprint = fingerprint(&raw);
    let (severity, confidence) = generic_candidate_severity(candidate);
    let locations = candidate
        .unit_ref
        .locations
        .iter()
        .map(|location| Location {
            path: location.path.clone(),
            span: Some(candidate.span),
            provenance: location.provenance.clone(),
            additional_provenance: location.additional_provenance.clone(),
            location_class: location.location_class,
        })
        .collect::<Vec<_>>();
    let location = locations
        .first()
        .expect("candidates retain a source location");
    let mut hasher = Sha256::new();
    hasher.update(candidate.rule_id.0.as_bytes());
    hasher.update(b"\0");
    hasher.update(fingerprint.0.as_bytes());
    hasher.update(b"\0");
    hasher.update(location.path.0.as_bytes());

    Finding {
        id: FindingId(format!("secret-{}", hex::encode(&hasher.finalize()[..12]))),
        category: Category::SecretExposure,
        severity,
        title: format!("Secret candidate matched {}", candidate.rule_id.0),
        detail: "The generic detector found a credential-shaped value. Review and rotate the value if it is real.".to_owned(),
        locations,
        evidence: Evidence::Secret {
            redacted: redact_secret(&raw),
            fingerprint,
        },
        remediation: "Remove the secret from source, rotate it with the provider, and purge committed history if necessary.".to_owned(),
        related: Vec::new(),
        confidence,
    }
}

pub(super) fn generic_candidate_severity(candidate: &SecretCandidate) -> (Severity, Confidence) {
    match candidate.kind {
        vibescan_types::CandidateKind::ProviderSecret
        | vibescan_types::CandidateKind::PrivateKey => (Severity::High, Confidence::Likely),
        vibescan_types::CandidateKind::GenericHighEntropy => (Severity::Medium, Confidence::Review),
        vibescan_types::CandidateKind::PossibleSupabaseKey => (Severity::Low, Confidence::Review),
        vibescan_types::CandidateKind::Other(_) => (Severity::Medium, Confidence::Review),
    }
}
