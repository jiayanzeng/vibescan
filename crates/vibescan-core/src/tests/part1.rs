    use std::process::Command;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use vibescan_secrets::working_tree_unit;
    use vibescan_types::{
        ContentId, LocationClass, RepoPath, RlsExposure, Span, SupabaseProject, UnitLocation,
        UnitRef,
    };

    use super::*;

    #[test]
    fn offline_pipeline_finds_supabase_and_generic_secrets() {
        let repo = TestRepo::new();
        repo.git(["init"]);
        repo.write(
            "src/app.tsx",
            "const supabase = 'sb_secret_0123456789abcdefghijklmnopqrstuvwxyzABCDEF';\n",
        );
        repo.write(
            "server/stripe.ts",
            "const stripe = 'sk_live_abcdefghijklmnopqrstuvwxyz123456';\n",
        );

        let result = scan(
            repo.path(),
            ScanConfig {
                include_history: false,
                ..ScanConfig::default()
            },
        )
        .expect("scan succeeds");

        assert!(
            result
                .findings
                .iter()
                .any(|finding| finding.category == Category::SecretExposure)
        );
        assert!(!result.scope.network.enabled);
    }
    #[test]
    fn scan_stats_carries_history_truncation() {
        let repo = TestRepo::new();
        repo.git(["init"]);
        repo.git(["config", "user.email", "a@example.com"]);
        repo.git(["config", "user.name", "A"]);
        repo.write("src/app.ts", "export const version = 1;\n");
        repo.git(["add", "."]);
        repo.git(["commit", "-m", "one"]);
        repo.write("src/app.ts", "export const version = 2;\n");
        repo.git(["add", "."]);
        repo.git(["commit", "-m", "two"]);

        let result = scan(
            repo.path(),
            ScanConfig {
                include_working_tree: false,
                max_commits: Some(1),
                ..ScanConfig::default()
            },
        )
        .expect("budgeted scan succeeds");

        assert!(result.stats.truncated);
        assert!(result.stats.scan_budget_hit);
        assert!(matches!(
            result.scope.history,
            HistoryScope::Budgeted {
                scanned_commits: 1,
                truncated: true,
                ..
            }
        ));
    }

    #[test]
    fn collected_working_tree_units_feed_the_detector() {
        let repo = TestRepo::new();
        repo.git(["init"]);
        repo.write(
            "src/app.tsx",
            "const key = 'sb_publishable_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789';\n",
        );

        let output = collect_repository(
            repo.path(),
            WalkOptions {
                include_history: false,
                ..WalkOptions::default()
            },
        )
        .expect("repo collected");
        let detector = Detector::default_rules().expect("detector compiles");
        let candidates = detector.detect_units(&output.units);

        assert_eq!(output.units.len(), 1);
        assert!(
            candidates
                .iter()
                .any(|candidate| candidate.rule_id.0 == "supabase-publishable-key")
        );
    }

    #[test]
    fn detector_candidates_feed_supabase_classification() {
        let detector = Detector::default_rules().expect("rules compile");
        let unit = working_tree_unit(
            "src/app.tsx",
            "const key = 'sb_secret_0123456789abcdefghijklmnopqrstuvwxyzABCDEF';",
        );
        let candidates = detector.detect_unit(&unit);
        let findings = SupabaseClassifier::new().classify_candidates(&candidates);

        assert!(
            findings
                .iter()
                .any(|finding| finding.category == Category::SecretExposure)
        );
    }

    #[test]
    fn vibescanignore_suppresses_matching_paths() {
        let repo = TestRepo::new();
        repo.git(["init"]);
        repo.write(".vibescanignore", "ignored.ts\n");
        repo.write(
            "ignored.ts",
            "const key = 'sb_secret_0123456789abcdefghijklmnopqrstuvwxyzABCDEF';\n",
        );

        let config = ScanConfig::load(repo.path()).expect("config loads");
        let result = scan(repo.path(), config).expect("scan succeeds");

        assert!(result.findings.is_empty());
    }

    #[test]
    fn gitignore_suppresses_matching_paths() {
        let repo = TestRepo::new();
        repo.git(["init"]);
        repo.write(".gitignore", "ignored.ts\n");
        repo.write(
            "ignored.ts",
            "const key = 'sb_secret_0123456789abcdefghijklmnopqrstuvwxyzABCDEF';\n",
        );

        let config = ScanConfig::load(repo.path()).expect("config loads");
        let result = scan(repo.path(), config).expect("scan succeeds");

        assert!(result.findings.is_empty());
    }

    #[test]
    fn gitignored_env_secret_is_still_reported() {
        let repo = TestRepo::new();
        repo.git(["init"]);
        repo.write(".gitignore", ".env\n");
        repo.write(
            ".env",
            "SUPABASE_SERVICE_ROLE_KEY=sb_secret_0123456789abcdefghijklmnopqrstuvwxyzABCDEF\n",
        );

        let result = scan(
            repo.path(),
            ScanConfig {
                include_history: false,
                ..ScanConfig::default()
            },
        )
        .expect("scan succeeds");

        assert!(result.findings.iter().any(|finding| {
            finding.category == Category::SecretExposure
                && matches!(finding.severity, Severity::Critical | Severity::High)
                && finding
                    .locations
                    .iter()
                    .any(|location| location.path.0 == ".env")
        }));
    }

    #[test]
    fn scan_associates_new_publishable_key_with_colocated_project_url() {
        let repo = TestRepo::new();
        repo.git(["init"]);
        repo.write(
            "src/app.tsx",
            "const url = 'https://abcdefghijklmnopqrst.supabase.co';\nconst key = 'sb_publishable_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789';\n",
        );

        let result = scan(
            repo.path(),
            ScanConfig {
                include_history: false,
                ..ScanConfig::default()
            },
        )
        .expect("scan succeeds");

        assert!(result.findings.iter().any(|finding| {
            matches!(
                &finding.evidence,
                Evidence::SupabaseKey {
                    class: SupabaseKeyClass::PublishableNew,
                    project: Some(project),
                    ..
                } if project.url == "https://abcdefghijklmnopqrst.supabase.co"
                    && project.ref_id.as_deref() == Some("abcdefghijklmnopqrst")
            )
        }));
    }

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
            &format!(
                "const url = 'https://abcdefghijklmnopqrst.supabase.co';\nconst key = '{key}';\n"
            ),
        );
        repo.write(
            "apps/b/src/app.tsx",
            &format!(
                "const url = 'https://zyxwvutsrqponmlkjihg.supabase.co';\nconst key = '{key}';\n"
            ),
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
            &format!(
                "const url = 'https://abcdefghijklmnopqrst.supabase.co';\nconst key = '{key}';\n"
            ),
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
            &format!(
                "const url = 'https://abcdefghijklmnopqrst.supabase.co';\nconst key = '{key}';\n"
            ),
        );
        repo.write(
            "apps/b/src/config.ts",
            &format!(
                "const url = 'https://zyxwvutsrqponmlkjihg.supabase.co';\nconst key = '{key}';\n"
            ),
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
            &format!(
                "const url = 'https://abcdefghijklmnopqrst.supabase.co';\nconst key = '{key}';\n"
            ),
        );
        repo.git(["add", "src/config.ts"]);
        repo.git(["commit", "-m", "project a"]);
        repo.write(
            "src/config.ts",
            &format!(
                "const url = 'https://zyxwvutsrqponmlkjihg.supabase.co';\nconst key = '{key}';\n"
            ),
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
    fn tier1_credential_location_is_the_env_source() {
        let location = tier1_credential_location();

        assert_eq!(
            location.path,
            RepoPath("<environment:VIBESCAN_SUPABASE_DB_URL>".to_owned())
        );
        assert_eq!(location.provenance, Provenance::WorkingTree);
        assert_eq!(location.location_class, LocationClass::ServerOnly);
    }

    #[cfg(feature = "network")]
    #[test]
    fn tier0_probe_inputs_dedup_same_project_and_prefer_client_location() {
        let server_candidate =
            publishable_candidate("apps/web/.env.local", LocationClass::ServerOnly);
        let client_candidate = publishable_candidate(
            "apps/web/.next/static/chunks/x.js",
            LocationClass::ClientReachable,
        );
        let mut server_finding = public_key_finding_at(
            "server-key",
            "apps/web/.env.local",
            LocationClass::ServerOnly,
        );
        let mut client_finding = public_key_finding_at(
            "client-key",
            "apps/web/.next/static/chunks/x.js",
            LocationClass::ClientReachable,
        );
        if let Evidence::SupabaseKey {
            project: Some(project),
            ..
        } = &mut server_finding.evidence
        {
            project.url = "https://ABCDEFGHIJKLMNOPQRST.supabase.co/".to_owned();
        }
        if let Evidence::SupabaseKey {
            project: Some(project),
            ..
        } = &mut client_finding.evidence
        {
            project.url = "https://abcdefghijklmnopqrst.supabase.co".to_owned();
        }
        let classifications = coalesce_classified_key_facts(vec![
            classified_key_fact(&server_candidate, server_finding),
            classified_key_fact(&client_candidate, client_finding),
        ]);
        let candidate_tables = BTreeSet::from(["profiles".to_owned()]);
        let tables_by_project = BTreeMap::from([(
            "https://abcdefghijklmnopqrst.supabase.co".to_owned(),
            candidate_tables.clone(),
        )]);

        let inputs = tier0_probe_inputs(&classifications, &tables_by_project);

        assert_eq!(inputs.len(), 1);
        assert_eq!(
            inputs[0].key_location.path.0,
            "apps/web/.next/static/chunks/x.js"
        );
        assert_eq!(
            inputs[0].key_location.location_class,
            LocationClass::ClientReachable
        );
        assert_eq!(inputs[0].candidate_tables, candidate_tables);
    }
