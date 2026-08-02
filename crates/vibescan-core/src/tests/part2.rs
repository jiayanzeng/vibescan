    #[cfg(feature = "network")]
    #[test]
    fn coalesced_projectless_client_copy_drives_known_project_probe() {
        let server_candidate =
            publishable_candidate("apps/web/.env.local", LocationClass::ServerOnly);
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
    #[cfg(feature = "network")]
    #[test]
    fn tier0_probe_inputs_keep_harvested_tables_project_local() {
        let mut candidate_a = publishable_candidate(
            "apps/a/.next/static/chunks/a.js",
            LocationClass::ClientReachable,
        );
        candidate_a.unit_ref.content_id = ContentId([10; 32]);
        let mut candidate_b = publishable_candidate(
            "apps/b/.next/static/chunks/b.js",
            LocationClass::ClientReachable,
        );
        candidate_b.unit_ref.content_id = ContentId([11; 32]);
        let finding_a = public_key_finding_at(
            "key-a",
            "apps/a/.next/static/chunks/a.js",
            LocationClass::ClientReachable,
        );
        let mut finding_b = public_key_finding_at(
            "key-b",
            "apps/b/.next/static/chunks/b.js",
            LocationClass::ClientReachable,
        );
        if let Evidence::SupabaseKey {
            project: Some(project),
            ..
        } = &mut finding_b.evidence
        {
            project.ref_id = Some("zyxwvutsrqponmlkjihg".to_owned());
            project.url = "https://zyxwvutsrqponmlkjihg.supabase.co".to_owned();
        }
        let classifications = coalesce_classified_key_facts(vec![
            classified_key_fact(&candidate_a, finding_a),
            classified_key_fact(&candidate_b, finding_b),
        ]);
        let units = vec![
            api_unit(
                ContentId([10; 32]),
                "apps/a/src/data.ts",
                "supabase.from('accounts_a').select('*');",
            ),
            api_unit(
                ContentId([11; 32]),
                "apps/b/src/data.ts",
                "supabase.from('accounts_b').select('*');",
            ),
        ];
        let references = harvest_api_references(&units);
        let associations = associate_api_references(&references, &classifications);

        let inputs = tier0_probe_inputs(&classifications, &associations.tables_by_project);
        let tables_by_project = inputs
            .into_iter()
            .map(|input| (input.project.url, input.candidate_tables))
            .collect::<BTreeMap<_, _>>();

        assert_eq!(
            tables_by_project["https://abcdefghijklmnopqrst.supabase.co"],
            BTreeSet::from(["accounts_a".to_owned()])
        );
        assert_eq!(
            tables_by_project["https://zyxwvutsrqponmlkjihg.supabase.co"],
            BTreeSet::from(["accounts_b".to_owned()])
        );
        assert!(associations.warnings.is_empty());
    }

    #[cfg(feature = "network")]
    #[test]
    fn tier0_probe_inputs_do_not_cross_probe_ambiguous_harvested_table() {
        let mut candidate_a = publishable_candidate("src/a-key.ts", LocationClass::ClientReachable);
        candidate_a.unit_ref.content_id = ContentId([20; 32]);
        let mut candidate_b = publishable_candidate("src/b-key.ts", LocationClass::ClientReachable);
        candidate_b.unit_ref.content_id = ContentId([21; 32]);
        let finding_a =
            public_key_finding_at("key-a", "src/a-key.ts", LocationClass::ClientReachable);
        let mut finding_b =
            public_key_finding_at("key-b", "src/b-key.ts", LocationClass::ClientReachable);
        if let Evidence::SupabaseKey {
            project: Some(project),
            ..
        } = &mut finding_b.evidence
        {
            project.ref_id = Some("zyxwvutsrqponmlkjihg".to_owned());
            project.url = "https://zyxwvutsrqponmlkjihg.supabase.co".to_owned();
        }
        let classifications = coalesce_classified_key_facts(vec![
            classified_key_fact(&candidate_a, finding_a),
            classified_key_fact(&candidate_b, finding_b),
        ]);
        let references = harvest_api_references(&[api_unit(
            ContentId([22; 32]),
            "src/shared.ts",
            "supabase.from('shared_profiles').select('*');",
        )]);
        let associations = associate_api_references(&references, &classifications);

        let inputs = tier0_probe_inputs(&classifications, &associations.tables_by_project);

        assert!(
            inputs.iter().all(|input| input.candidate_tables.is_empty()),
            "an ambiguously associated table must not be sent to either project"
        );
        assert!(associations.warnings.iter().any(|warning| matches!(
            warning,
            ScopeWarning::Other { message }
                if message.contains("shared_profiles")
                    && message.contains("ambiguous Supabase project association")
        )));
    }

    #[test]
    fn harvest_api_references_retains_table_and_rpc_kinds() {
        let units = vec![ScannableUnit {
            content_id: ContentId([2; 32]),
            content: br#"
                const profiles = supabase.from('profiles').select('*');
                await client.from("orders").select("id");
                await supabase.rpc('do_x');
                fetch("/rest/v1/widgets?select=*");
            "#
            .to_vec(),
            locations: vec![UnitLocation {
                path: RepoPath("apps/web/.next/static/chunks/x.js".to_owned()),
                provenance: Provenance::WorkingTree,
                additional_provenance: Vec::new(),
                location_class: LocationClass::ClientReachable,
            }],
        }];

        let references = harvest_api_references(&units)
            .into_iter()
            .map(|reference| (reference.kind, reference.name, reference.source_scope.0))
            .collect::<Vec<_>>();

        assert_eq!(
            references,
            vec![
                (
                    ApiReferenceKind::Table,
                    "orders".to_owned(),
                    "apps/web".to_owned()
                ),
                (
                    ApiReferenceKind::Table,
                    "profiles".to_owned(),
                    "apps/web".to_owned()
                ),
                (
                    ApiReferenceKind::Table,
                    "widgets".to_owned(),
                    "apps/web".to_owned()
                ),
                (
                    ApiReferenceKind::Rpc,
                    "do_x".to_owned(),
                    "apps/web".to_owned()
                ),
            ]
        );
    }

    #[test]
    fn rpc_references_remain_typed_and_never_become_table_candidates() {
        let content_id = ContentId([30; 32]);
        let facts = vec![classified_fact_for_source(
            content_id.clone(),
            "apps/web/src/config.ts",
            project(),
        )];
        let references = harvest_api_references(&[api_unit(
            content_id,
            "apps/web/src/data.ts",
            "supabase.from('profiles').select('*'); supabase.rpc('do_x');",
        )]);

        let associations = associate_api_references(&references, &facts);

        assert_eq!(
            associations.tables_by_project,
            BTreeMap::from([(
                "https://abcdefghijklmnopqrst.supabase.co".to_owned(),
                BTreeSet::from(["profiles".to_owned()]),
            )])
        );
        assert!(associations.warnings.is_empty());
        assert!(references.iter().any(|reference| {
            reference.kind == ApiReferenceKind::Rpc && reference.name == "do_x"
        }));
    }

    #[test]
    fn historical_api_references_use_exact_content_project_context() {
        let project_a = project();
        let project_b = SupabaseProject {
            ref_id: Some("zyxwvutsrqponmlkjihg".to_owned()),
            url: "https://zyxwvutsrqponmlkjihg.supabase.co".to_owned(),
        };
        let facts = vec![
            classified_fact_for_source(ContentId([31; 32]), "src/config.ts", project_a.clone()),
            classified_fact_for_source(ContentId([32; 32]), "src/config.ts", project_b.clone()),
        ];
        let references = harvest_api_references(&[
            api_unit(
                ContentId([31; 32]),
                "src/config.ts",
                "supabase.from('accounts_a').select('*');",
            ),
            api_unit(
                ContentId([32; 32]),
                "src/config.ts",
                "supabase.from('accounts_b').select('*');",
            ),
        ]);

        let associations = associate_api_references(&references, &facts);

        assert_eq!(
            associations.tables_by_project[&normalized_project_url(&project_a.url)],
            BTreeSet::from(["accounts_a".to_owned()])
        );
        assert_eq!(
            associations.tables_by_project[&normalized_project_url(&project_b.url)],
            BTreeSet::from(["accounts_b".to_owned()])
        );
        assert!(associations.warnings.is_empty());
    }

    #[test]
    fn unassociated_table_reference_emits_coverage_warning() {
        let references = harvest_api_references(&[api_unit(
            ContentId([33; 32]),
            "shared/data.ts",
            "supabase.from('orphaned_table').select('*');",
        )]);

        let associations = associate_api_references(&references, &[]);

        assert!(associations.tables_by_project.is_empty());
        assert!(matches!(
            associations.warnings.as_slice(),
            [ScopeWarning::Other { message }]
                if message.contains("orphaned_table")
                    && message.contains("no associated Supabase project")
        ));
    }

    #[test]
    fn config_path_allowlists_suppress_docs_but_cannot_hide_env() {
        let repo = TestRepo::new();
        repo.git(["init"]);
        repo.write("vibescan.toml", "[ignore]\npaths = [\"docs/**\", \"**\"]\n");
        repo.write(
            "docs/secret.ts",
            "const key = 'sb_secret_docs0123456789abcdefghijklmnopqrstuvwxyzABCDEF';\n",
        );
        repo.write(
            ".env",
            "SUPABASE_SERVICE_ROLE_KEY=sb_secret_env0123456789abcdefghijklmnopqrstuvwxyzABCDEF\n",
        );

        let config = ScanConfig::load(repo.path()).expect("config loads");
        let result = scan(repo.path(), config).expect("scan succeeds");

        assert!(result.findings.iter().any(|finding| {
            finding
                .locations
                .iter()
                .any(|location| location.path.0 == ".env")
        }));
        assert!(!result.findings.iter().any(|finding| {
            finding
                .locations
                .iter()
                .any(|location| location.path.0 == "docs/secret.ts")
        }));
    }

    #[test]
    fn config_loads_from_repo_root_when_target_is_subdirectory() {
        let repo = TestRepo::new();
        repo.git(["init"]);
        repo.write("vibescan.toml", "[ignore]\npaths = [\"src/**\"]\n");
        repo.write(
            "src/app.ts",
            "const key = 'sb_secret_0123456789abcdefghijklmnopqrstuvwxyzABCDEF';\n",
        );

        let target = repo.path().join("src");
        let config = ScanConfig::load(&target).expect("config loads from repo root");
        let result = scan(&target, config).expect("scan succeeds");

        assert!(result.findings.is_empty());
    }

    #[test]
    fn config_preserves_all_localstatic_values_and_resolves_repo_relative_paths() {
        let repo = TestRepo::new();
        repo.git(["init"]);
        repo.write(
            "vibescan.toml",
            r#"
            [scan]
            working_tree = false
            history = false
            max_commits = 17
            max_bytes = 4096
            severity_gate = "info"

            [baseline]
            path = "config/baseline.json"

            [rules]
            path = "config/custom-rules.toml"
            "#,
        );
        repo.write("config/baseline.json", "[]");
        repo.write("config/custom-rules.toml", "");
        repo.write("src/app.ts", "console.log('clean');\n");

        let config = ScanConfig::load(repo.path().join("src")).expect("config loads");

        assert!(!config.include_working_tree);
        assert!(!config.include_history);
        assert_eq!(config.max_commits, Some(17));
        assert_eq!(config.max_bytes, 4096);
        assert_eq!(config.severity_gate, Severity::Info);
        assert_eq!(
            config.baseline_path,
            Some(repo.path().join("config/baseline.json"))
        );
        assert_eq!(
            config.custom_rules_path,
            Some(repo.path().join("config/custom-rules.toml"))
        );
    }

    #[test]
    fn repository_config_cannot_enable_network_without_runtime_confirmation() {
        let repo = TestRepo::new();
        repo.git(["init"]);
        repo.write(
            "vibescan.toml",
            "[network]\ntier0_read_probe = true\ntier1_introspection = true\nregistry_checks = true\nregistry_newcomer = true\n",
        );

        let config = ScanConfig::load(repo.path()).expect("config loads");

        assert!(!config.tier0_read_probe);
        assert!(!config.tier1_introspection);
        assert!(!config.registry_checks);
        assert!(!config.registry_newcomer);
    }

    #[test]
    fn parsed_dependencies_are_deterministic_and_registry_shaped() {
        let repo = TestRepo::new();
        repo.git(["init"]);
        repo.write(
            "package.json",
            r#"{"dependencies":{"@acme/private":"^2.0.0","left-pad":"1.3.0"}}"#,
        );
        repo.write(
            "pyproject.toml",
            "[project]\ndependencies = [\"requests>=2.31\"]\n",
        );

        let first = parse_dependencies(repo.path()).expect("dependencies parse");
        let second = parse_dependencies(repo.path()).expect("dependencies parse twice");

        assert_eq!(first, second);
        assert_eq!(
            first,
            vec![
                ParsedDependency {
                    name: "@acme/private".to_owned(),
                    version_req: "^2.0.0".to_owned(),
                    ecosystem: Ecosystem::Npm,
                    manifest_path: vibescan_types::RepoPath("package.json".to_owned()),
                    is_scoped: true,
                },
                ParsedDependency {
                    name: "left-pad".to_owned(),
                    version_req: "1.3.0".to_owned(),
                    ecosystem: Ecosystem::Npm,
                    manifest_path: vibescan_types::RepoPath("package.json".to_owned()),
                    is_scoped: false,
                },
                ParsedDependency {
                    name: "requests".to_owned(),
                    version_req: ">=2.31".to_owned(),
                    ecosystem: Ecosystem::PyPi,
                    manifest_path: vibescan_types::RepoPath("pyproject.toml".to_owned()),
                    is_scoped: false,
                },
            ]
        );
    }

    #[test]
    fn parsed_dependencies_include_exact_npm_and_python_lock_versions() {
        let repo = TestRepo::new();
        repo.git(["init"]);
        repo.write(
            "package-lock.json",
            r#"{"lockfileVersion":3,"packages":{"":{"name":"fixture"},"node_modules/left-pad":{"version":"1.3.0"}}}"#,
        );
        repo.write(
            "poetry.lock",
            "[[package]]\nname = \"requests\"\nversion = \"2.32.0\"\n",
        );

        let dependencies = parse_dependencies(repo.path()).expect("lockfiles parse");

        assert_eq!(
            dependencies,
            vec![
                ParsedDependency {
                    name: "left-pad".to_owned(),
                    version_req: "1.3.0".to_owned(),
                    ecosystem: Ecosystem::Npm,
                    manifest_path: vibescan_types::RepoPath("package-lock.json".to_owned()),
                    is_scoped: false,
                },
                ParsedDependency {
                    name: "requests".to_owned(),
                    version_req: "2.32.0".to_owned(),
                    ecosystem: Ecosystem::PyPi,
                    manifest_path: vibescan_types::RepoPath("poetry.lock".to_owned()),
                    is_scoped: false,
                },
            ]
        );
    }

    #[cfg(feature = "registry")]
    #[test]
    fn structurally_invalid_dependencies_are_excluded_from_registry_inputs() {
        let repo = TestRepo::new();
        repo.git(["init"]);
        repo.write(
            "package.json",
            r#"{"dependencies":{"INVALID PACKAGE":"1.0.0","empty-version":"","valid-package":"1.0.0"}}"#,
        );

        let scan = scan_dependency_integrity(repo.path()).expect("dependency scan runs");
        let eligible = registry_eligible_dependencies(&scan.findings, scan.dependencies);

        assert_eq!(scan.findings.len(), 2);
        assert!(scan.findings.iter().all(|finding| matches!(
            finding.evidence,
            Evidence::Dependency {
                reason: vibescan_types::DependencyIntegrityReason::InvalidPackageName
                    | vibescan_types::DependencyIntegrityReason::EmptyVersionSpecifier,
                ..
            }
        )));
        assert_eq!(eligible.len(), 1);
        assert_eq!(eligible[0].name, "valid-package");
    }

    #[cfg(feature = "registry")]
    #[test]
    fn invalid_package_is_never_sent_and_remains_one_localstatic_finding() {
        use std::cell::Cell;

        struct CountingRegistry {
            calls: Cell<u64>,
        }

        impl vibescan_registry::RegistrySource for CountingRegistry {
            fn resolves(
                &self,
                _dependency: &ParsedDependency,
            ) -> Result<vibescan_registry::RegistryResolution, vibescan_registry::RegistryError>
            {
                self.calls.set(self.calls.get() + 1);
                Ok(vibescan_registry::RegistryResolution {
                    exists: false,
                    request_made: true,
                })
            }

            fn advisories_for(
                &self,
                ecosystem: Ecosystem,
            ) -> Result<vibescan_registry::AdvisorySet, vibescan_registry::RegistryError>
            {
                self.calls.set(self.calls.get() + 1);
                Ok(vibescan_registry::AdvisorySet::empty(ecosystem))
            }
        }

        let repo = TestRepo::new();
        repo.git(["init"]);
        repo.write(
            "package.json",
            r#"{"dependencies":{"INVALID PACKAGE":"1.0.0"}}"#,
        );
        let scan = scan_dependency_integrity(repo.path()).expect("dependency scan runs");
        let eligible = registry_eligible_dependencies(&scan.findings, scan.dependencies);
        let source = CountingRegistry {
            calls: Cell::new(0),
        };
        let registry_output = run_registry_checks(
            &source,
            &RegistryCheckInput {
                dependencies: eligible,
                private_registry_ecosystems: BTreeSet::new(),
            },
        )
        .expect("empty registry input runs");

        assert_eq!(source.calls.get(), 0);
        assert_eq!(scan.findings.len(), 1);
        assert!(registry_output.findings.is_empty());
        assert!(registry_output.actions.is_empty());
    }

    #[cfg(feature = "registry")]
    #[test]
    fn repository_alternate_registry_configuration_activates_precision_guard() {
        let repo = TestRepo::new();
        repo.git(["init"]);
        repo.write(".npmrc", "registry=https://npm.internal.example/\n");
        repo.write(
            "pyproject.toml",
            "[project]\ndependencies = [\"internal-python==1.0.0\"]\n[[tool.poetry.source]]\nname = \"private\"\nurl = \"https://python.internal.example/simple\"\n",
        );

        let ecosystems =
            private_registry_ecosystems(repo.path()).expect("private registries parse");

        assert_eq!(
            ecosystems,
            BTreeSet::from([Ecosystem::Npm, Ecosystem::PyPi])
        );
    }

    #[cfg(not(feature = "registry"))]
    #[test]
    fn registry_request_without_feature_is_a_clear_operational_error() {
        let repo = TestRepo::new();
        repo.git(["init"]);

        let error = scan(
            repo.path(),
            ScanConfig {
                registry_checks: true,
                ..ScanConfig::default()
            },
        )
        .expect_err("feature-off registry request rejected");

        assert!(matches!(error, CoreError::RegistryFeatureUnavailable));
        assert!(error.to_string().contains("without registry support"));
    }

    #[cfg(feature = "registry")]
    #[test]
    fn registry_runtime_opt_in_is_auditable_and_does_not_enable_rls() {
        let repo = TestRepo::new();
        repo.git(["init"]);

        let result = scan(
            repo.path(),
            ScanConfig {
                include_history: false,
                registry_checks: true,
                ..ScanConfig::default()
            },
        )
        .expect("F1 registry plumbing runs without live egress");

        assert!(result.scope.network.enabled);
        assert!(result.scope.network.registry_checks);
        assert!(!result.scope.network.registry_newcomer);
        assert!(!result.scope.network.tier0_read_probe);
        assert!(!result.scope.network.tier1_introspection);
        assert!(result.scope.network.actions.is_empty());
        assert!(result.scope.network.registry_name_egress.is_empty());
    }

    #[test]
    fn repository_path_resolution_preserves_absolute_paths() {
        let repo = TestRepo::new();
        repo.git(["init"]);
        let absolute = repo.path().join("outside-name.json");

        let resolved = resolve_repository_path(repo.path(), &absolute).expect("path resolves");

        assert_eq!(resolved, absolute);
    }

    #[test]
    fn invalid_configured_severity_is_rejected() {
        let repo = TestRepo::new();
        repo.git(["init"]);
        repo.write("vibescan.toml", "[scan]\nseverity_gate = \"urgent\"\n");

        let error = ScanConfig::load(repo.path()).expect_err("invalid severity rejected");

        assert!(matches!(error, CoreError::InvalidSeverity(value) if value == "urgent"));
    }
