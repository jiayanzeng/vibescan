use super::*;

#[test]
fn coalesces_same_secret_across_paths() {
    let repo = TestRepo::new();
    repo.git(["init"]);
    let url = "https://abcdefghijklmnopqrst.supabase.co";
    let key = "sb_publishable_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";
    repo.write(
        "apps/web/.env.local",
        &format!("NEXT_PUBLIC_SUPABASE_URL={url}\nNEXT_PUBLIC_SUPABASE_ANON_KEY={key}\n"),
    );
    repo.write(
        "apps/web/.next/static/chunks/x.js",
        &format!("const url = '{url}';\nconst key = '{key}';\n"),
    );

    let result = scan(
        repo.path(),
        ScanConfig {
            include_history: false,
            severity_gate: Severity::Info,
            ..ScanConfig::default()
        },
    )
    .expect("scan succeeds");
    let findings = publishable_key_findings(&result);

    assert_eq!(findings.len(), 1);
    let finding = findings[0];
    let locations = finding
        .locations
        .iter()
        .map(|location| location.path.0.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        locations,
        vec!["apps/web/.env.local", "apps/web/.next/static/chunks/x.js"]
    );
    assert_eq!(
        max_location_class(&finding.locations),
        LocationClass::ClientReachable
    );
    assert_eq!(result.stats.by_category[&Category::KeyClassification], 1);
}

#[test]
fn coalescing_prefers_bundle_over_signal_bearing_src_api_copy() {
    let repo = TestRepo::new();
    repo.git(["init"]);
    let url = "https://abcdefghijklmnopqrst.supabase.co";
    let key = "sb_publishable_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";
    repo.write(
        "src/api/server.ts",
        &format!("\"use server\";\nconst url = '{url}';\nconst key = '{key}';\n"),
    );
    repo.write(
        "dist/bundle.js",
        &format!("const url = '{url}';\nconst key = '{key}';\n"),
    );

    let result = scan(
        repo.path(),
        ScanConfig {
            include_history: false,
            severity_gate: Severity::Info,
            ..ScanConfig::default()
        },
    )
    .expect("scan succeeds");
    let findings = publishable_key_findings(&result);

    assert_eq!(findings.len(), 1);
    let finding = findings[0];
    assert!(finding.locations.iter().any(|location| {
        location.path.0 == "src/api/server.ts"
            && location.location_class == LocationClass::ServerOnly
    }));
    assert!(finding.locations.iter().any(|location| {
        location.path.0 == "dist/bundle.js"
            && location.location_class == LocationClass::ClientReachable
    }));
    assert_eq!(
        max_location_class(&finding.locations),
        LocationClass::ClientReachable
    );
}

#[test]
fn identical_content_at_server_and_browser_paths_retains_both_locations() {
    let repo = TestRepo::new();
    repo.git(["init"]);
    let content = "NEXT_PUBLIC_SUPABASE_URL=https://abcdefghijklmnopqrst.supabase.co\nNEXT_PUBLIC_SUPABASE_ANON_KEY=sb_publishable_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789\n";
    repo.write("apps/api/.env.local", content);
    repo.write("apps/web/.next/static/chunks/config.js", content);

    let result = scan(
        repo.path(),
        ScanConfig {
            include_history: false,
            severity_gate: Severity::Info,
            ..ScanConfig::default()
        },
    )
    .expect("scan succeeds");
    let findings = publishable_key_findings(&result);

    assert_eq!(findings.len(), 1);
    assert_eq!(
        findings[0]
            .locations
            .iter()
            .map(|location| location.path.0.as_str())
            .collect::<Vec<_>>(),
        vec![
            "apps/api/.env.local",
            "apps/web/.next/static/chunks/config.js"
        ]
    );
    assert_eq!(
        max_location_class(&findings[0].locations),
        LocationClass::ClientReachable
    );
}

#[test]
fn coalescing_keeps_different_secrets_at_same_path_separate() {
    let repo = TestRepo::new();
    repo.git(["init"]);
    repo.write(
        "src/app.tsx",
        "const url = 'https://abcdefghijklmnopqrst.supabase.co';\nconst keyA = 'sb_publishable_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789';\nconst keyB = 'sb_publishable_ZyXwVuTsRqPoNmLkJiHgFeDcBa9876543210';\n",
    );

    let result = scan(
        repo.path(),
        ScanConfig {
            include_history: false,
            severity_gate: Severity::Info,
            ..ScanConfig::default()
        },
    )
    .expect("scan succeeds");

    assert_eq!(publishable_key_findings(&result).len(), 2);
}

#[test]
fn coalescing_keeps_same_secret_on_different_projects_separate() {
    let repo = TestRepo::new();
    repo.git(["init"]);
    let key = "sb_publishable_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";
    repo.write(
        "apps/a/src/app.tsx",
        &format!("const url = 'https://abcdefghijklmnopqrst.supabase.co';\nconst key = '{key}';\n"),
    );
    repo.write(
        "apps/b/src/app.tsx",
        &format!("const url = 'https://zyxwvutsrqponmlkjihg.supabase.co';\nconst key = '{key}';\n"),
    );

    let result = scan(
        repo.path(),
        ScanConfig {
            include_history: false,
            severity_gate: Severity::Info,
            ..ScanConfig::default()
        },
    )
    .expect("scan succeeds");
    let project_urls = publishable_key_findings(&result)
        .into_iter()
        .filter_map(|finding| {
            let Evidence::SupabaseKey {
                project: Some(project),
                ..
            } = &finding.evidence
            else {
                return None;
            };
            Some(project.url.as_str())
        })
        .collect::<BTreeSet<_>>();

    assert_eq!(
        project_urls,
        BTreeSet::from([
            "https://abcdefghijklmnopqrst.supabase.co",
            "https://zyxwvutsrqponmlkjihg.supabase.co"
        ])
    );
}

#[test]
fn projectless_copy_joins_single_known_project_for_same_fingerprint() {
    let repo = TestRepo::new();
    repo.git(["init"]);
    let key = "sb_publishable_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";
    repo.write(
        "apps/web/src/config.ts",
        &format!("const url = 'https://abcdefghijklmnopqrst.supabase.co';\nconst key = '{key}';\n"),
    );
    repo.write(
        "apps/web/.next/static/chunks/config.js",
        &format!("window.supabaseKey = '{key}';\n"),
    );

    let result = scan(
        repo.path(),
        ScanConfig {
            include_history: false,
            severity_gate: Severity::Info,
            ..ScanConfig::default()
        },
    )
    .expect("scan succeeds");
    let findings = publishable_key_findings(&result);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].locations.len(), 2);
    assert!(matches!(
        findings[0].evidence,
        Evidence::SupabaseKey {
            project: Some(_),
            ..
        }
    ));
}

#[test]
fn ambiguous_projectless_copy_does_not_join_known_different_projects() {
    let repo = TestRepo::new();
    repo.git(["init"]);
    let key = "sb_publishable_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";
    repo.write(
        "apps/a/src/config.ts",
        &format!("const url = 'https://abcdefghijklmnopqrst.supabase.co';\nconst key = '{key}';\n"),
    );
    repo.write(
        "apps/b/src/config.ts",
        &format!("const url = 'https://zyxwvutsrqponmlkjihg.supabase.co';\nconst key = '{key}';\n"),
    );
    repo.write("shared/config.ts", &format!("const key = '{key}';\n"));

    let result = scan(
        repo.path(),
        ScanConfig {
            include_history: false,
            severity_gate: Severity::Info,
            ..ScanConfig::default()
        },
    )
    .expect("scan succeeds");
    let findings = publishable_key_findings(&result);

    assert_eq!(findings.len(), 3);
    assert_eq!(
        findings
            .iter()
            .filter(|finding| matches!(
                finding.evidence,
                Evidence::SupabaseKey { project: None, .. }
            ))
            .count(),
        1
    );
}

#[test]
fn project_enrichment_coalescing_is_independent_of_input_order() {
    let known = public_key_finding();
    let mut projectless = known.clone();
    projectless.id = FindingId("projectless".to_owned());
    projectless.locations[0].path = RepoPath("dist/config.js".to_owned());
    if let Evidence::SupabaseKey { project, .. } = &mut projectless.evidence {
        *project = None;
    }

    let forward = coalesce_findings(vec![known.clone(), projectless.clone()]);
    let reverse = coalesce_findings(vec![projectless, known]);

    assert_eq!(forward, reverse);
    assert_eq!(forward.len(), 1);
    assert!(matches!(
        forward[0].evidence,
        Evidence::SupabaseKey {
            project: Some(_),
            ..
        }
    ));
}

#[test]
fn unambiguous_project_enrichment_intentionally_changes_baseline_identity() {
    let known = public_key_finding();
    let mut projectless = known.clone();
    projectless.id = FindingId("projectless".to_owned());
    projectless.locations[0].path = RepoPath("dist/config.js".to_owned());
    if let Evidence::SupabaseKey { project, .. } = &mut projectless.evidence {
        *project = None;
    }

    let projectless_id = coalesce_findings(vec![projectless.clone()])[0].id.clone();
    let known_id = coalesce_findings(vec![known.clone()])[0].id.clone();
    let enriched_id = coalesce_findings(vec![projectless, known])[0].id.clone();

    assert_ne!(projectless_id, enriched_id);
    assert_eq!(enriched_id, known_id);
}

#[test]
fn historical_versions_at_same_path_keep_their_own_project_context() {
    let repo = TestRepo::new();
    repo.git(["init"]);
    repo.git(["config", "user.email", "phase0@example.invalid"]);
    repo.git(["config", "user.name", "Phase Zero"]);
    let key = "sb_publishable_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";
    repo.write(
        "src/config.ts",
        &format!("const url = 'https://abcdefghijklmnopqrst.supabase.co';\nconst key = '{key}';\n"),
    );
    repo.git(["add", "src/config.ts"]);
    repo.git(["commit", "-m", "project a"]);
    repo.write(
        "src/config.ts",
        &format!("const url = 'https://zyxwvutsrqponmlkjihg.supabase.co';\nconst key = '{key}';\n"),
    );
    repo.git(["add", "src/config.ts"]);
    repo.git(["commit", "-m", "project b"]);

    let result = scan(
        repo.path(),
        ScanConfig {
            severity_gate: Severity::Info,
            ..ScanConfig::default()
        },
    )
    .expect("scan succeeds");
    let projects = publishable_key_findings(&result)
        .into_iter()
        .filter_map(project_url_from_key)
        .collect::<BTreeSet<_>>();

    assert_eq!(
        projects,
        BTreeSet::from([
            "https://abcdefghijklmnopqrst.supabase.co",
            "https://zyxwvutsrqponmlkjihg.supabase.co"
        ])
    );
}

#[cfg(feature = "network")]
#[test]
fn coalesced_projectless_client_copy_drives_known_project_probe() {
    let server_candidate = publishable_candidate("apps/web/.env.local", LocationClass::ServerOnly);
    let client_candidate = publishable_candidate(
        "apps/web/.next/static/chunks/x.js",
        LocationClass::ClientReachable,
    );
    let server_finding = public_key_finding_at(
        "server-key",
        "apps/web/.env.local",
        LocationClass::ServerOnly,
    );
    let mut client_finding = public_key_finding_at(
        "client-key",
        "apps/web/.next/static/chunks/x.js",
        LocationClass::ClientReachable,
    );
    if let Evidence::SupabaseKey { project, .. } = &mut client_finding.evidence {
        *project = None;
    }

    let facts = coalesce_classified_key_facts(vec![
        classified_key_fact(&server_candidate, server_finding),
        classified_key_fact(&client_candidate, client_finding),
    ]);
    let tables_by_project = BTreeMap::from([(
        "https://abcdefghijklmnopqrst.supabase.co".to_owned(),
        BTreeSet::from(["profiles".to_owned()]),
    )]);
    let inputs = tier0_probe_inputs(&facts, &tables_by_project);

    assert_eq!(facts.len(), 1);
    assert_eq!(facts[0].finding.locations.len(), 2);
    assert_eq!(facts[0].sources.len(), 2);
    assert_eq!(inputs.len(), 1);
    assert_eq!(
        inputs[0].project.url,
        "https://abcdefghijklmnopqrst.supabase.co"
    );
    assert_eq!(
        inputs[0].key_location.path.0,
        "apps/web/.next/static/chunks/x.js"
    );
}

#[test]
fn correlates_public_key_with_rls_exposure_on_same_project() {
    let key = public_key_finding();
    let rls = rls_finding();
    let correlations = correlate_findings(&[key.clone(), rls.clone()]);

    assert_eq!(correlations.len(), 1);
    assert_eq!(correlations[0].severity, Severity::Critical);
    assert_eq!(correlations[0].related, vec![key.id, rls.id]);
}

#[test]
fn correlates_public_key_with_critical_rls_disabled_policy_without_probe() {
    let key = public_key_finding();
    let rls = rls_policy_finding(RlsExposure::RlsDisabled, project());
    assert_eq!(rls.severity, Severity::Critical);
    assert!(matches!(rls.evidence, Evidence::RlsPolicy { .. }));

    let correlations = correlate_findings(&[key.clone(), rls.clone()]);

    assert_eq!(rls.severity, Severity::Critical);
    assert_eq!(correlations.len(), 1);
    assert_eq!(correlations[0].severity, Severity::Critical);
    assert_eq!(correlations[0].related, vec![key.id, rls.id]);
    assert!(matches!(
        &correlations[0].evidence,
        Evidence::Correlation {
            reproduction: Some(reproduction),
            ..
        } if reproduction.contains("table profiles has RLS disabled")
    ));
}

#[test]
fn correlates_public_key_with_critical_permissive_policy_without_probe() {
    let key = public_key_finding();
    let rls = rls_policy_finding(RlsExposure::PermissivePolicy, project());
    assert_eq!(rls.severity, Severity::Critical);

    let correlations = correlate_findings(&[key.clone(), rls.clone()]);

    assert_eq!(correlations.len(), 1);
    assert_eq!(correlations[0].related, vec![key.id, rls.id]);
    assert!(matches!(
        &correlations[0].evidence,
        Evidence::Correlation {
            reproduction: Some(reproduction),
            ..
        } if reproduction.contains("table profiles has permissive USING (true)")
    ));
}

#[test]
fn operation_advisory_and_inferred_write_do_not_fire_read_chain() {
    let key = public_key_finding();
    for exposure in [
        RlsExposure::MissingOperationPolicy,
        RlsExposure::InferredWriteExposure,
    ] {
        let rls = rls_policy_finding(exposure, project());
        assert!(
            correlate_findings(&[key.clone(), rls]).is_empty(),
            "{exposure:?} must not prove anonymous read exposure"
        );
    }
}

#[test]
fn tier1_read_exposure_on_different_project_does_not_correlate() {
    let key = public_key_finding();
    let other_project = SupabaseProject {
        ref_id: Some("zyxwvutsrqponmlkjihg".to_owned()),
        url: "https://zyxwvutsrqponmlkjihg.supabase.co/".to_owned(),
    };
    let rls = rls_policy_finding(RlsExposure::RlsDisabled, other_project);

    assert!(correlate_findings(&[key, rls]).is_empty());
}

#[test]
fn committed_elevated_key_moots_tier1_policy_finding() {
    let mut key = public_key_finding();
    key.id = FindingId("elevated-key".to_owned());
    key.category = Category::SecretExposure;
    key.locations[0].provenance = Provenance::Commit {
        sha: "0123456789abcdef".to_owned(),
        author: None,
        date: None,
    };
    if let Evidence::SupabaseKey { class, .. } = &mut key.evidence {
        *class = SupabaseKeyClass::SecretNew;
    }
    let rls = rls_policy_finding(RlsExposure::PermissivePolicy, project());

    let correlation = correlate_findings(&[key.clone(), rls.clone()])
        .into_iter()
        .find(|finding| {
            matches!(
                &finding.evidence,
                Evidence::Correlation { rule_id, .. } if rule_id.0 == "elevated-key-in-tree"
            )
        })
        .expect("elevated-key correlation includes Tier 1 RLS evidence");

    assert!(correlation.related.contains(&key.id));
    assert!(correlation.related.contains(&rls.id));
}

#[test]
fn additional_commit_provenance_qualifies_server_public_key_for_correlation() {
    let mut key = public_key_finding();
    key.locations[0].location_class = LocationClass::ServerOnly;
    key.locations[0].additional_provenance = vec![Provenance::Commit {
        sha: "0123456789abcdef".to_owned(),
        author: None,
        date: None,
    }];

    let correlations = correlate_findings(&[key, rls_finding()]);

    assert!(correlations.iter().any(|finding| matches!(
        &finding.evidence,
        Evidence::Correlation { rule_id, .. } if rule_id.0 == "exposed-public-key-chain"
    )));
}

#[test]
fn additional_commit_provenance_qualifies_elevated_key_for_correlation() {
    let mut key = public_key_finding();
    key.id = FindingId("elevated-key".to_owned());
    key.locations[0].location_class = LocationClass::ServerOnly;
    key.locations[0].additional_provenance = vec![Provenance::Commit {
        sha: "fedcba9876543210".to_owned(),
        author: None,
        date: None,
    }];
    if let Evidence::SupabaseKey { class, .. } = &mut key.evidence {
        *class = SupabaseKeyClass::SecretNew;
    }

    let correlations = correlate_findings(&[key, rls_finding()]);

    assert!(correlations.iter().any(|finding| matches!(
        &finding.evidence,
        Evidence::Correlation { rule_id, .. } if rule_id.0 == "elevated-key-in-tree"
    )));
}

#[test]
fn server_only_uncommitted_public_key_remains_outside_correlation() {
    let mut key = public_key_finding();
    key.locations[0].location_class = LocationClass::ServerOnly;

    assert!(correlate_findings(&[key, rls_finding()]).is_empty());
}

#[test]
fn correlation_locations_are_a_deterministic_unique_union() {
    let mut key = public_key_finding();
    key.locations = vec![
        Location {
            path: RepoPath("apps/api/.env.local".to_owned()),
            span: None,
            provenance: Provenance::WorkingTree,
            additional_provenance: Vec::new(),
            location_class: LocationClass::ServerOnly,
        },
        Location {
            path: RepoPath("apps/web/src/config.ts".to_owned()),
            span: None,
            provenance: Provenance::WorkingTree,
            additional_provenance: Vec::new(),
            location_class: LocationClass::ClientReachable,
        },
    ];
    let mut rls = rls_finding();
    rls.locations = vec![key.locations[1].clone()];

    let correlation = correlate_findings(&[key, rls])
        .into_iter()
        .find(|finding| {
            matches!(
                &finding.evidence,
                Evidence::Correlation { rule_id, .. } if rule_id.0 == "exposed-public-key-chain"
            )
        })
        .expect("correlation emitted");

    assert_eq!(
        correlation
            .locations
            .iter()
            .map(|location| location.path.0.as_str())
            .collect::<Vec<_>>(),
        vec!["apps/api/.env.local", "apps/web/src/config.ts"]
    );
}

#[test]
fn exposed_public_key_correlation_absorbs_constituents_in_summary() {
    let key = public_key_finding();
    let rls = rls_finding();
    let correlation = correlate_findings(&[key.clone(), rls.clone()])
        .into_iter()
        .next()
        .expect("correlation emitted");
    let mut findings = vec![key, rls, correlation.clone()];

    absorb_correlated_constituents(&mut findings);

    assert_eq!(findings, vec![correlation]);
}
