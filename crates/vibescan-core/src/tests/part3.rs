    #[test]
    fn clean_control_fixture_produces_zero_findings() {
        let repo = TestRepo::new();
        repo.git(["init"]);
        repo.write(
            "package.json",
            r#"{"dependencies":{"@supabase/supabase-js":"2.0.0","next":"15.0.0"}}"#,
        );
        repo.write(
            "src/app/page.tsx",
            "export default function Page() { return <main>clean</main>; }\n",
        );
        repo.write(
            "supabase/functions/ping/index.ts",
            "Deno.serve(() => new Response('ok'));\n",
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

        assert_eq!(result.findings, Vec::new());
    }
    #[test]
    fn elevated_key_committed_then_removed_fixture_is_history_only_critical() {
        let repo = TestRepo::new();
        repo.git(["init"]);
        repo.git(["config", "user.email", "vibescan@example.invalid"]);
        repo.git(["config", "user.name", "vibescan test"]);
        repo.write(
            "src/history.ts",
            "export const key = 'sb_secret_0123456789abcdefghijklmnopqrstuvwxyzABCDEF';\n",
        );
        repo.git(["add", "src/history.ts"]);
        repo.git(["commit", "-m", "add historical secret"]);
        repo.write("src/history.ts", "export const ok = true;\n");
        repo.git(["add", "src/history.ts"]);
        repo.git(["commit", "-m", "remove historical secret"]);

        let result = scan(repo.path(), ScanConfig::default()).expect("scan succeeds");
        let findings = result
            .findings
            .iter()
            .filter(|finding| {
                matches!(
                    finding.evidence,
                    Evidence::SupabaseKey {
                        class: SupabaseKeyClass::SecretNew,
                        ..
                    }
                )
            })
            .collect::<Vec<_>>();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, Category::SecretExposure);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(findings[0].locations.iter().any(|location| {
            location.path.0 == "src/history.ts"
                && matches!(location.provenance, Provenance::Commit { .. })
        }));
    }

    #[test]
    fn gitignored_env_fixture_has_exact_elevated_key_finding() {
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
        let findings = result
            .findings
            .iter()
            .filter(|finding| {
                finding
                    .locations
                    .iter()
                    .any(|location| location.path.0 == ".env")
            })
            .collect::<Vec<_>>();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, Category::SecretExposure);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(matches!(
            findings[0].evidence,
            Evidence::SupabaseKey {
                class: SupabaseKeyClass::SecretNew,
                ..
            }
        ));
    }

    #[test]
    fn next_build_tree_fixture_is_clean_after_ignore_overrides() {
        let repo = TestRepo::new();
        repo.git(["init"]);
        repo.write(".gitignore", ".next/\n");
        repo.write(
            "dashboard/.next/server/vendor-chunks/prop-types.js",
            "var x='abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ';\n",
        );
        repo.write(
            "dashboard/.next/static/chunks/app.js",
            "self.__next_f.push(['clean static bundle']);\n",
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

        assert_eq!(result.findings, Vec::new());
    }

    #[test]
    fn invalid_dependency_fixture_has_exact_integrity_finding() {
        let repo = TestRepo::new();
        repo.git(["init"]);
        repo.write(
            "package.json",
            r#"{"dependencies":{"Bad Package":"1.0.0"}}"#,
        );

        let result = scan(
            repo.path(),
            ScanConfig {
                include_history: false,
                ..ScanConfig::default()
            },
        )
        .expect("scan succeeds");

        assert_eq!(result.findings.len(), 1);
        let finding = &result.findings[0];
        assert_eq!(finding.category, Category::DependencyIntegrity);
        assert_eq!(finding.severity, Severity::High);
        assert!(matches!(
            finding.evidence,
            Evidence::Dependency {
                ref package,
                reason: vibescan_types::DependencyIntegrityReason::InvalidPackageName,
                ..
            } if package == "Bad Package"
        ));
    }

    #[test]
    fn dependency_integrity_flags_invalid_package_names() {
        let repo = TestRepo::new();
        repo.git(["init"]);
        repo.write(
            "package.json",
            r#"{"dependencies":{"Bad Package":"1.0.0"}}"#,
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
            finding.category == Category::DependencyIntegrity && finding.severity == Severity::High
        }));
        assert!(result.findings.iter().any(|finding| {
            matches!(
                finding.evidence,
                Evidence::Dependency {
                    reason: vibescan_types::DependencyIntegrityReason::InvalidPackageName,
                    ..
                }
            )
        }));
    }

    #[test]
    fn dependency_integrity_labels_empty_versions_honestly() {
        let repo = TestRepo::new();
        repo.git(["init"]);
        repo.write("package.json", r#"{"dependencies":{"left-pad":""}}"#);

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
                finding.evidence,
                Evidence::Dependency {
                    ref package,
                    reason: vibescan_types::DependencyIntegrityReason::EmptyVersionSpecifier,
                    ..
                } if package == "left-pad"
            )
        }));
    }

    #[test]
    fn dependency_integrity_scans_package_lock() {
        let repo = TestRepo::new();
        repo.git(["init"]);
        repo.write(
            "package-lock.json",
            r#"{"packages":{"node_modules/Bad Package":{"version":"1.0.0"}}}"#,
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
                finding.evidence,
                Evidence::Dependency {
                    ref manifest_path,
                    ref package,
                    reason: vibescan_types::DependencyIntegrityReason::InvalidPackageName,
                } if manifest_path.0 == "package-lock.json" && package == "Bad Package"
            )
        }));
    }

    #[test]
    fn dependency_integrity_scans_python_manifests() {
        let repo = TestRepo::new();
        repo.git(["init"]);
        repo.write(
            "pyproject.toml",
            "[project]\ndependencies = [\"bad package>=1\"]\n",
        );
        repo.write("requirements.txt", "also bad==1\n");

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
                finding.evidence,
                Evidence::Dependency {
                    ref manifest_path,
                    ref package,
                    reason: vibescan_types::DependencyIntegrityReason::InvalidPackageName,
                } if manifest_path.0 == "pyproject.toml" && package == "bad package"
            )
        }));
        assert!(result.findings.iter().any(|finding| {
            matches!(
                finding.evidence,
                Evidence::Dependency {
                    ref manifest_path,
                    ref package,
                    reason: vibescan_types::DependencyIntegrityReason::InvalidPackageName,
                } if manifest_path.0 == "requirements.txt" && package == "also bad"
            )
        }));
    }

    #[test]
    fn baseline_suppresses_existing_findings() {
        let repo = TestRepo::new();
        repo.git(["init"]);
        repo.write(
            "src/app.ts",
            "const stripe = 'sk_live_abcdefghijklmnopqrstuvwxyz123456';\n",
        );

        let first = scan(
            repo.path(),
            ScanConfig {
                include_history: false,
                ..ScanConfig::default()
            },
        )
        .expect("first scan succeeds");
        let ids = first
            .findings
            .iter()
            .map(|finding| finding.id.0.clone())
            .collect::<Vec<_>>();
        repo.write(
            "baseline.json",
            &serde_json::to_string(&ids).expect("ids serialize"),
        );

        let second = scan(
            repo.path(),
            ScanConfig {
                include_history: false,
                baseline_path: Some(repo.path().join("baseline.json")),
                ..ScanConfig::default()
            },
        )
        .expect("second scan succeeds");

        assert!(second.findings.is_empty());
    }

    #[test]
    fn scan_result_started_at_is_rfc3339_timestamp() {
        let repo = TestRepo::new();
        repo.git(["init"]);

        let result = scan(
            repo.path(),
            ScanConfig {
                include_history: false,
                ..ScanConfig::default()
            },
        )
        .expect("scan succeeds");

        assert!(result.started_at.parse::<Timestamp>().is_ok());
        assert_ne!(result.started_at, "local-static");
    }

    #[test]
    fn json_error_message_is_not_baseline_specific() {
        let error = serde_json::from_str::<serde_json::Value>("{")
            .map_err(CoreError::Json)
            .expect_err("invalid JSON fails");

        assert!(error.to_string().starts_with("JSON parse failed:"));
        assert!(!error.to_string().contains("baseline"));
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

    #[test]
    fn exit_code_respects_severity_gate() {
        let mut result = empty_result();
        result
            .findings
            .push(generic_candidate_finding(&SecretCandidate {
                rule_id: vibescan_types::RuleId("toy".to_owned()),
                kind: vibescan_types::CandidateKind::ProviderSecret,
                raw_match: b"abcdefghijklmnopqrstuvwxyz123456".to_vec(),
                entropy: 4.0,
                unit_ref: test_unit_ref("src/app.ts", LocationClass::Unknown),
                span: Span {
                    line: 1,
                    col_start: 1,
                    col_end: 32,
                },
            }));

        assert_eq!(exit_code(&result, Severity::Critical), 0);
        assert_eq!(exit_code(&result, Severity::High), 1);
    }

    #[test]
    fn generic_high_entropy_candidates_are_medium_review() {
        let finding = generic_candidate_finding(&SecretCandidate {
            rule_id: vibescan_types::RuleId("generic-high-entropy-assignment".to_owned()),
            kind: vibescan_types::CandidateKind::GenericHighEntropy,
            raw_match: b"abcdefghijklmnopqrstuvwxyz1234567890".to_vec(),
            entropy: 4.0,
            unit_ref: test_unit_ref("src/app.ts", LocationClass::Unknown),
            span: Span {
                line: 1,
                col_start: 1,
                col_end: 37,
            },
        });

        assert_eq!(finding.severity, Severity::Medium);
        assert_eq!(finding.confidence, Confidence::Review);
    }

    #[test]
    fn generic_finding_retains_all_candidate_source_locations() {
        let mut unit_ref = test_unit_ref("apps/api/.env.local", LocationClass::ServerOnly);
        unit_ref.locations.push(UnitLocation {
            path: RepoPath("apps/web/.next/static/chunks/config.js".to_owned()),
            provenance: Provenance::WorkingTree,
            additional_provenance: Vec::new(),
            location_class: LocationClass::ClientReachable,
        });
        let candidate = SecretCandidate {
            rule_id: vibescan_types::RuleId("toy".to_owned()),
            kind: vibescan_types::CandidateKind::ProviderSecret,
            raw_match: b"abcdefghijklmnopqrstuvwxyz123456".to_vec(),
            entropy: 4.0,
            unit_ref,
            span: Span {
                line: 4,
                col_start: 3,
                col_end: 35,
            },
        };

        let finding = generic_candidate_finding(&candidate);

        assert_eq!(finding.locations.len(), 2);
        assert!(
            finding
                .locations
                .iter()
                .all(|location| location.span == Some(candidate.span))
        );
    }
