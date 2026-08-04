use super::*;

#[cfg(feature = "registry")]
pub(super) fn apply_registry_findings<S: RegistrySource>(
    source: &S,
    input: RegistryCheckInput,
    findings: &mut Vec<Finding>,
    network_actions: &mut Vec<NetworkActionAudit>,
    registry_name_egress: &mut Vec<vibescan_types::RegistryNameEgress>,
    warnings: &mut Vec<ScopeWarning>,
) -> Result<(), CoreError> {
    let mut output = run_registry_checks(source, &input).map_err(CoreError::Registry)?;
    findings.append(&mut output.findings);
    network_actions.append(&mut output.actions);
    registry_name_egress.append(&mut output.name_egress);
    warnings.extend(
        output
            .warnings
            .into_iter()
            .map(|warning| ScopeWarning::Other {
                message: warning.message(),
            }),
    );
    Ok(())
}

/// Run the offline scan pipeline.
pub fn scan(target: impl AsRef<Path>, config: ScanConfig) -> Result<ScanResult, CoreError> {
    if config.registry_checks && !cfg!(feature = "registry") {
        return Err(CoreError::RegistryFeatureUnavailable);
    }
    if config.registry_newcomer {
        return Err(CoreError::RegistryNewcomerUnavailable);
    }

    let started = Instant::now();
    let started_at = Timestamp::now().to_string();
    let target_path = target.as_ref();
    let baseline = Baseline::load(config.baseline_path.as_deref())?;
    let walk = collect_repository(
        target_path,
        WalkOptions {
            include_working_tree: config.include_working_tree,
            include_history: config.include_history,
            max_commits: config.max_commits,
            max_bytes: config.max_bytes,
            path_allowlists: config.path_allowlists.clone(),
        },
    )
    .map_err(CoreError::Git)?;

    let mut warnings = walk.warnings;
    let units = walk.units;
    let detector = load_detector(config.custom_rules_path.as_deref())?;
    let candidates = detector.detect_units(&units);

    let classifier = SupabaseClassifier::new();
    let unit_content = units
        .iter()
        .map(|unit| (&unit.content_id, unit.content.as_slice()))
        .collect::<BTreeMap<_, _>>();
    let classified_keys = candidates
        .iter()
        .filter_map(|candidate| {
            classifier
                .classify_candidate_with_unit_content(
                    candidate,
                    unit_content.get(&candidate.unit_ref.content_id).copied(),
                )
                .map(|finding| {
                    let project = project_from_key_finding(&finding).cloned();
                    ClassifiedKeyFact {
                        finding,
                        raw_key: candidate.raw_match.clone(),
                        sources: vec![ClassifiedKeySource {
                            unit_ref: candidate.unit_ref.clone(),
                            project,
                        }],
                    }
                })
        })
        .collect::<Vec<_>>();
    let classified_keys = coalesce_classified_key_facts(classified_keys);
    let mut findings = classified_keys
        .iter()
        .map(|fact| fact.finding.clone())
        .collect::<Vec<_>>();
    #[cfg(any(feature = "network", feature = "registry"))]
    let mut network_actions = Vec::<NetworkActionAudit>::new();
    #[cfg(not(any(feature = "network", feature = "registry")))]
    let network_actions = Vec::<NetworkActionAudit>::new();
    #[cfg(feature = "registry")]
    let mut registry_name_egress = Vec::new();
    #[cfg(not(feature = "registry"))]
    let registry_name_egress = Vec::new();
    findings.extend(resolve_generic_candidates(&candidates));
    let dependency_scan = scan_dependency_integrity(&walk.repo_root)?;
    #[cfg(feature = "registry")]
    let registry_dependencies = registry_eligible_dependencies(
        &dependency_scan.findings,
        dependency_scan.dependencies.clone(),
    );
    findings.extend(dependency_scan.findings);

    if config.registry_checks {
        #[cfg(feature = "registry")]
        {
            let source = ReqwestRegistrySource::new().map_err(CoreError::Registry)?;
            apply_registry_findings(
                &source,
                RegistryCheckInput {
                    dependencies: registry_dependencies,
                    private_registry_ecosystems: private_registry_ecosystems(&walk.repo_root)?,
                },
                &mut findings,
                &mut network_actions,
                &mut registry_name_egress,
                &mut warnings,
            )?;
        }
    }

    #[cfg(feature = "network")]
    let network_associations = (config.tier0_read_probe || config.tier1_introspection).then(|| {
        let api_references = harvest_api_references(&units);
        associate_api_references(&api_references, &classified_keys)
    });

    if config.tier0_read_probe {
        #[cfg(feature = "network")]
        {
            let associations = network_associations
                .as_ref()
                .expect("network associations computed for Tier 0");
            warnings.extend(associations.warnings.iter().cloned());
            for input in tier0_probe_inputs(&classified_keys, &associations.tables_by_project) {
                match probe_tier0_read(&input) {
                    Ok(mut output) => {
                        findings.append(&mut output.findings);
                        network_actions.append(&mut output.actions);
                        warnings.extend(output.warnings.into_iter().map(|warning| {
                            ScopeWarning::Other {
                                message: warning.message(),
                            }
                        }));
                    }
                    Err(error) => warnings.push(ScopeWarning::Other {
                        message: format!(
                            "Tier 0 RLS read probe transport/other error for {}: {error}",
                            input.project.url
                        ),
                    }),
                }
            }
        }
        #[cfg(not(feature = "network"))]
        warnings.push(ScopeWarning::Other {
            message: "Tier 0 RLS read probe requested but this binary was built without the network feature".to_owned(),
        });
    }

    if config.tier1_introspection {
        #[cfg(feature = "network")]
        {
            let db_url =
                std::env::var(TIER1_DB_URL_ENV).map_err(|_| CoreError::MissingTier1Credential)?;
            let project = project_from_db_url(&db_url).map_err(CoreError::Tier1)?;
            let associations = network_associations
                .as_ref()
                .expect("network associations computed for Tier 1");
            let normalized_project = normalized_project_url(&project.url);
            let input = Tier1IntrospectInput {
                credential_location: tier1_credential_location(),
                candidate_tables: associations
                    .tables_by_project
                    .get(&normalized_project)
                    .cloned()
                    .unwrap_or_default(),
                project,
                db_url,
            };
            let mut output = introspect_tier1(&input).map_err(CoreError::Tier1)?;
            findings.append(&mut output.findings);
            network_actions.append(&mut output.actions);
            warnings.extend(
                output
                    .warnings
                    .into_iter()
                    .map(|warning| ScopeWarning::Other {
                        message: warning.message(),
                    }),
            );
        }
        #[cfg(not(feature = "network"))]
        warnings.push(ScopeWarning::Other {
            message: "Tier 1 RLS introspection requested but this binary was built without the network feature".to_owned(),
        });
    }

    let mut findings = coalesce_findings(findings);
    findings.extend(correlate_findings(&findings));

    let mut findings = dedup_findings(findings);
    findings.retain(|finding| !baseline.contains(&finding.id));
    absorb_correlated_constituents(&mut findings);
    sort_findings(&mut findings);

    let stats = compute_stats(&findings, &warnings, walk.stats, walk.history.truncated);
    if !config.include_history {
        warnings.push(ScopeWarning::Other {
            message: "history scanning disabled".to_owned(),
        });
    }

    Ok(ScanResult {
        findings,
        scope: ScanScope {
            target: target_path.display().to_string(),
            working_tree: config.include_working_tree,
            history: history_scope(config.include_history, config.max_commits, &walk.history),
            network: NetworkScope {
                enabled: ((config.tier0_read_probe || config.tier1_introspection)
                    && cfg!(feature = "network"))
                    || (config.registry_checks && cfg!(feature = "registry")),
                tier0_read_probe: config.tier0_read_probe && cfg!(feature = "network"),
                tier1_introspection: config.tier1_introspection && cfg!(feature = "network"),
                registry_checks: config.registry_checks && cfg!(feature = "registry"),
                registry_newcomer: false,
                registry_name_egress,
                actions: network_actions,
            },
            warnings,
        },
        tool_version: TOOL_VERSION.to_owned(),
        started_at,
        duration_ms: started.elapsed().as_millis() as u64,
        stats,
    })
}

pub fn scan_and_render(
    target: impl AsRef<Path>,
    config: ScanConfig,
    format: OutputFormat,
    style: OutputStyle,
) -> Result<(String, i32), CoreError> {
    let result = scan(target, config.clone())?;
    let output = if format == OutputFormat::Tty {
        render_tty(
            &result,
            match style {
                OutputStyle::Plain => TtyStyle::Plain,
                OutputStyle::Color => TtyStyle::Color,
            },
        )
    } else {
        render(&result, format.into()).map_err(CoreError::Json)?
    };
    let code = exit_code(&result, config.severity_gate);
    Ok((output, code))
}

/// Compute whether a result meets the configured severity gate.
pub fn exit_code(result: &ScanResult, gate: Severity) -> i32 {
    if result
        .findings
        .iter()
        .any(|finding| finding.severity >= gate)
    {
        1
    } else {
        0
    }
}
