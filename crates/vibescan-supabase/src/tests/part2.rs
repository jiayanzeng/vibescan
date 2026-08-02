    #[test]
    fn tier1_ignores_catalog_tables_outside_the_local_api_candidates() {
        let source = FakePgCatalog {
            tables: vec![TableRls {
                schema: "public".to_owned(),
                table: "unreferenced_admin_table".to_owned(),
                rowsecurity: false,
            }],
            policies: Vec::new(),
            grants: Vec::new(),
            ..FakePgCatalog::default()
        };

        let output = introspect_tier1_with_source(&source, &tier1_input(tier1_db_url()))
            .expect("mock introspection succeeds");

        assert!(output.findings.is_empty());
    }

    #[test]
    fn tier1_detects_literal_true_permissive_policy() {
        let source = FakePgCatalog {
            policies: vec![policy_row("ALL", Some(" (( TRUE )) "), true)],
            grants: Vec::new(),
            ..FakePgCatalog::default()
        };

        let output = introspect_tier1_with_source(&source, &tier1_input(tier1_db_url()))
            .expect("mock introspection succeeds");

        assert_single_tier1_finding(&output, RlsExposure::PermissivePolicy, "ALL");
        assert_eq!(output.findings[0].severity, Severity::Critical);
        assert_eq!(
            policy_evidence(&output.findings[0]).using_expr,
            Some(" (( TRUE )) ")
        );
    }

    #[test]
    fn tier1_detects_one_missing_select_policy() {
        let source = FakePgCatalog {
            policies: vec![
                policy_row("INSERT", None, true),
                policy_row("UPDATE", Some("auth.uid() = owner_id"), true),
                policy_row("DELETE", Some("auth.uid() = owner_id"), true),
            ],
            grants: Vec::new(),
            ..FakePgCatalog::default()
        };

        let output = introspect_tier1_with_source(&source, &tier1_input(tier1_db_url()))
            .expect("mock introspection succeeds");

        assert_single_tier1_finding(&output, RlsExposure::MissingOperationPolicy, "SELECT");
        assert_eq!(output.findings[0].severity, Severity::Medium);
        assert!(output.findings[0].detail.contains("denied by default"));
        assert!(output.findings[0].detail.contains("anon/authenticated"));
        assert!(!output.findings[0].detail.contains("open"));
        assert!(!output.findings[0].detail.contains("exposed"));
    }

    #[test]
    fn tier1_infers_write_exposure_from_anon_grant_without_policy() {
        let source = FakePgCatalog {
            policies: Vec::new(),
            grants: vec![grant_row("anon", "INSERT")],
            ..FakePgCatalog::default()
        };

        let output = introspect_tier1_with_source(&source, &tier1_input(tier1_db_url()))
            .expect("mock introspection succeeds");

        assert_single_tier1_finding(&output, RlsExposure::InferredWriteExposure, "INSERT");
        assert_eq!(output.findings[0].severity, Severity::High);
        assert!(output.findings[0].detail.contains("inferred"));
        assert!(output.findings[0].detail.contains("no write was attempted"));
        assert!(!output.findings[0].detail.contains("confirmed a write"));
    }

    #[test]
    fn tier1_literal_true_matching_rejects_substrings() {
        for expression in ["is_active = true", "true_flag", "(is_true(value))"] {
            let source = FakePgCatalog {
                policies: vec![policy_row("ALL", Some(expression), true)],
                grants: Vec::new(),
                ..FakePgCatalog::default()
            };

            let output = introspect_tier1_with_source(&source, &tier1_input(tier1_db_url()))
                .expect("mock introspection succeeds");

            assert!(
                output.findings.is_empty(),
                "substring expression was misclassified: {expression}"
            );
        }
    }

    #[test]
    fn tier1_output_contains_policy_reproduction_but_no_credentials_or_row_data() {
        let source = FakePgCatalog {
            policies: vec![PolicyRow {
                policy: "catalog-row-marker".to_owned(),
                roles: vec!["application-row-value".to_owned()],
                ..policy_row("ALL", Some("(true)"), true)
            }],
            grants: Vec::new(),
            ..FakePgCatalog::default()
        };
        let input = tier1_input(
            "postgres://postgres:raw-db-password@db.abcdefghijklmnopqrst.supabase.co/postgres",
        );

        let output =
            introspect_tier1_with_source(&source, &input).expect("mock introspection succeeds");
        let serialized = format!(
            "{}{}{}",
            serde_json::to_string(&output.findings).expect("findings serialize"),
            serde_json::to_string(&output.actions).expect("actions serialize"),
            output
                .warnings
                .iter()
                .map(Tier1IntrospectWarning::message)
                .collect::<Vec<_>>()
                .join("\n")
        );

        assert!(
            serialized.contains("(true)"),
            "policy predicate is evidence"
        );
        for forbidden in [
            "raw-db-password",
            "catalog-row-marker",
            "application-row-value",
            "count",
        ] {
            assert!(
                !serialized.to_ascii_lowercase().contains(forbidden),
                "Tier 1 output leaked {forbidden}"
            );
        }
    }

    #[test]
    fn tier1_metadata_keyed_policy_heuristic_remains_out_of_e2() {
        let source = FakePgCatalog {
            policies: vec![policy_row(
                "ALL",
                Some("(auth.jwt() -> 'user_metadata' ->> 'plan') = 'admin'"),
                true,
            )],
            grants: Vec::new(),
            ..FakePgCatalog::default()
        };

        let output = introspect_tier1_with_source(&source, &tier1_input(tier1_db_url()))
            .expect("mock introspection succeeds");

        assert!(output.findings.is_empty());
    }

    #[test]
    fn tier1_catalog_failure_is_nonfatal_and_sanitized() {
        let source = FakePgCatalog {
            fail: Some(CatalogQueryKind::Policies),
            ..FakePgCatalog::default()
        };
        let input = tier1_input(
            "postgres://postgres:raw-db-password@db.abcdefghijklmnopqrst.supabase.co/postgres",
        );

        let output = introspect_tier1_with_source(&source, &input).expect("query failure degrades");

        assert_eq!(output.warnings.len(), 1);
        assert!(output.warnings[0].message().contains("table policies"));
        assert_eq!(
            output.actions[1].outcome,
            NetworkActionOutcome::TransportError
        );
        assert!(
            output.findings.is_empty(),
            "a failed policy query must not manufacture a policy finding"
        );
        let serialized = serde_json::to_string(&output.actions).expect("actions serialize");
        assert!(!serialized.contains("raw-db-password"));
    }

    #[test]
    fn tier1_refuses_non_supabase_hosts_schemes_ports_and_overrides_before_queries() {
        for db_url in [
            "postgres://postgres:pw@example.com:5432/postgres",
            "https://postgres:pw@db.abcdefghijklmnopqrst.supabase.co:5432/postgres",
            "postgres://postgres:pw@db.abcdefghijklmnopqrst.supabase.co:7777/postgres",
            "postgres://postgres:pw@db.abcdefghijklmnopqrst.supabase.co:5432/postgres?host=example.com",
            "postgres://postgres:pw@db.abcdefghijklmnopqrst.supabase.co:5432/postgres?sslmode=disable",
            "postgres://postgres:pw@aws-0-us-east-1.pooler.supabase.com:5432/postgres",
        ] {
            let source = FakePgCatalog::default();
            let input = tier1_input(db_url);

            let error = introspect_tier1_with_source(&source, &input)
                .expect_err("unsafe destination must be rejected");

            assert!(matches!(error, IntrospectError::InvalidDatabaseUrl { .. }));
            assert!(
                source.calls.borrow().is_empty(),
                "source was queried for {db_url}"
            );
        }
    }

    #[test]
    fn tier1_accepts_supabase_direct_and_pooler_hosts_for_the_same_project() {
        let direct = project_from_db_url(
            "postgresql://postgres:pw@db.abcdefghijklmnopqrst.supabase.co:6543/postgres",
        )
        .expect("dedicated pooler accepted");
        let shared = project_from_db_url(
            "postgres://postgres.abcdefghijklmnopqrst:pw@aws-0-us-east-1.pooler.supabase.com:5432/postgres",
        )
        .expect("shared pooler accepted");

        assert_eq!(direct, shared);
        assert_eq!(direct.ref_id.as_deref(), Some("abcdefghijklmnopqrst"));
    }

    #[test]
    fn tier1_rejects_database_project_mismatch_before_queries() {
        let source = FakePgCatalog::default();
        let input =
            tier1_input("postgres://postgres:pw@db.zyxwvutsrqponmlkjihg.supabase.co:5432/postgres");

        let error = introspect_tier1_with_source(&source, &input)
            .expect_err("known-different project rejected");

        assert!(matches!(error, IntrospectError::ProjectMismatch { .. }));
        assert!(source.calls.borrow().is_empty());
    }

    #[cfg(feature = "network")]
    #[test]
    fn production_catalog_queries_are_select_only() {
        for query in [
            TABLE_RLS_QUERY.to_owned(),
            policies_query("public.profiles"),
            grants_query("public.profiles"),
        ] {
            assert!(catalog_query_is_read_only(&query), "unsafe query: {query}");
        }
        assert!(!catalog_query_is_read_only("SET ROLE postgres"));
        assert!(!catalog_query_is_read_only("DELETE FROM profiles"));
    }

    fn jwt_with_payload(payload: &str) -> String {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(payload.as_bytes());
        let signature = "abcdefghijklmnopqrstuvwxyz1234567890";
        format!("{header}.{payload}.{signature}")
    }

    fn tier0_input() -> Tier0RlsProbeInput {
        tier0_input_with_tables([])
    }

    fn tier0_input_with_tables<const N: usize>(tables: [&str; N]) -> Tier0RlsProbeInput {
        Tier0RlsProbeInput {
            project: SupabaseProject {
                ref_id: Some("abcdefghijklmnopqrst".to_owned()),
                url: "https://abcdefghijklmnopqrst.supabase.co".to_owned(),
            },
            public_key: "sb_publishable_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789".to_owned(),
            key_location: Location {
                path: RepoPath("src/app.tsx".to_owned()),
                span: None,
                provenance: Provenance::WorkingTree,
                additional_provenance: Vec::new(),
                location_class: LocationClass::ClientReachable,
            },
            candidate_tables: tables.into_iter().map(str::to_owned).collect(),
        }
    }

    fn tier1_db_url() -> &'static str {
        "postgres://postgres:pw@db.abcdefghijklmnopqrst.supabase.co/postgres"
    }

    fn tier1_input(db_url: &str) -> Tier1IntrospectInput {
        Tier1IntrospectInput {
            project: SupabaseProject {
                ref_id: Some("abcdefghijklmnopqrst".to_owned()),
                url: "https://abcdefghijklmnopqrst.supabase.co".to_owned(),
            },
            db_url: db_url.to_owned(),
            credential_location: Location {
                path: RepoPath("<environment>".to_owned()),
                span: None,
                provenance: Provenance::WorkingTree,
                additional_provenance: Vec::new(),
                location_class: LocationClass::ServerOnly,
            },
            candidate_tables: BTreeSet::from(["profiles".to_owned()]),
        }
    }

    struct FakePgCatalog {
        calls: RefCell<Vec<(CatalogQueryKind, Option<String>)>>,
        fail: Option<CatalogQueryKind>,
        tables: Vec<TableRls>,
        policies: Vec<PolicyRow>,
        grants: Vec<GrantRow>,
    }

    impl Default for FakePgCatalog {
        fn default() -> Self {
            let mut safe_policy = policy_row("ALL", Some("owner_id = auth.uid()"), true);
            safe_policy.policy = "credential-row-marker".to_owned();
            Self {
                calls: RefCell::new(Vec::new()),
                fail: None,
                tables: vec![table_rls(true)],
                policies: vec![safe_policy],
                grants: vec![grant_row("anon", "SELECT")],
            }
        }
    }

    impl FakePgCatalog {
        fn record(
            &self,
            query: CatalogQueryKind,
            table: Option<&str>,
        ) -> Result<(), IntrospectError> {
            self.calls
                .borrow_mut()
                .push((query, table.map(str::to_owned)));
            if self.fail == Some(query) {
                return Err(IntrospectError::CatalogQueryFailed {
                    query,
                    table: table.map(str::to_owned),
                });
            }
            Ok(())
        }
    }

    impl PgCatalogSource for FakePgCatalog {
        fn tables_with_rowsecurity(&self) -> Result<Vec<TableRls>, IntrospectError> {
            self.record(CatalogQueryKind::TablesWithRowSecurity, None)?;
            Ok(self.tables.clone())
        }

        fn policies_for(&self, table: &str) -> Result<Vec<PolicyRow>, IntrospectError> {
            self.record(CatalogQueryKind::Policies, Some(table))?;
            Ok(self.policies.clone())
        }

        fn grants_for(&self, table: &str) -> Result<Vec<GrantRow>, IntrospectError> {
            self.record(CatalogQueryKind::Grants, Some(table))?;
            Ok(self.grants.clone())
        }
    }

    fn table_rls(rowsecurity: bool) -> TableRls {
        TableRls {
            schema: "public".to_owned(),
            table: "profiles".to_owned(),
            rowsecurity,
        }
    }

    fn policy_row(command: &str, using_expr: Option<&str>, permissive: bool) -> PolicyRow {
        PolicyRow {
            schema: "public".to_owned(),
            table: "profiles".to_owned(),
            policy: format!("{command}-policy"),
            command: command.to_owned(),
            permissive,
            roles: vec!["anon".to_owned()],
            using_expr: using_expr.map(str::to_owned),
            check_expr: None,
        }
    }

    fn grant_row(grantee: &str, privilege: &str) -> GrantRow {
        GrantRow {
            schema: "public".to_owned(),
            table: "profiles".to_owned(),
            grantee: grantee.to_owned(),
            privilege: privilege.to_owned(),
        }
    }

    struct PolicyEvidenceRef<'a> {
        command: &'a str,
        using_expr: Option<&'a str>,
        rowsecurity: bool,
        exposure: RlsExposure,
    }

    fn policy_evidence(finding: &Finding) -> PolicyEvidenceRef<'_> {
        let Evidence::RlsPolicy {
            command,
            using_expr,
            rowsecurity,
            exposure,
            ..
        } = &finding.evidence
        else {
            panic!("expected RLS policy evidence")
        };
        PolicyEvidenceRef {
            command,
            using_expr: using_expr.as_deref(),
            rowsecurity: *rowsecurity,
            exposure: *exposure,
        }
    }

    fn assert_single_tier1_finding(
        output: &Tier1IntrospectOutput,
        exposure: RlsExposure,
        command: &str,
    ) {
        assert_eq!(output.findings.len(), 1, "{:#?}", output.findings);
        let finding = &output.findings[0];
        let evidence = policy_evidence(finding);
        assert_eq!(finding.category, Category::Rls);
        assert_eq!(finding.confidence, Confidence::Confirmed);
        assert_eq!(evidence.exposure, exposure);
        assert_eq!(evidence.command, command);
    }

    #[derive(Default)]
    struct FakeRlsClient {
        responses: BTreeMap<String, RlsHttpResponse>,
        requests: RefCell<Vec<FakeRlsRequest>>,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct FakeRlsRequest {
        url: String,
        headers: Vec<(String, String)>,
    }

    impl FakeRlsClient {
        fn new<const N: usize>(responses: [(&str, RlsHttpResponse); N]) -> Self {
            Self {
                responses: responses
                    .into_iter()
                    .map(|(url, response)| (url.to_owned(), response))
                    .collect(),
                requests: RefCell::new(Vec::new()),
            }
        }

        fn assert_all_requests_include_apikey(&self, public_key: &str) {
            let requests = self.requests.borrow();
            assert!(!requests.is_empty(), "probe should issue requests");
            for request in requests.iter() {
                assert!(
                    request
                        .headers
                        .iter()
                        .any(|(name, value)| name == "apikey" && value == public_key),
                    "{} did not include matching apikey header: {:?}",
                    request.url,
                    request.headers
                );
            }
        }

        fn request_count(&self) -> usize {
            self.requests.borrow().len()
        }
    }

    impl RlsHttpClient for FakeRlsClient {
        fn get(
            &self,
            url: &str,
            headers: &[(String, String)],
        ) -> Result<RlsHttpResponse, RlsProbeError> {
            self.requests.borrow_mut().push(FakeRlsRequest {
                url: url.to_owned(),
                headers: headers.to_vec(),
            });
            self.responses
                .get(url)
                .cloned()
                .ok_or_else(|| RlsProbeError::Http {
                    url: url.to_owned(),
                    status: None,
                    source: "missing fake response".to_owned(),
                })
        }
    }
