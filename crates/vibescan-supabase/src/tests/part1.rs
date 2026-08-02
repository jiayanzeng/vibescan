    use std::cell::RefCell;
    use std::collections::BTreeMap;

    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use vibescan_types::{
        ContentId, LocationClass, Provenance, RepoPath, RuleId, Span, UnitLocation, UnitRef,
    };

    use super::*;

    fn candidate(raw: &str, location_class: LocationClass) -> SecretCandidate {
        SecretCandidate {
            rule_id: RuleId("supabase-key-shaped".to_owned()),
            kind: CandidateKind::PossibleSupabaseKey,
            raw_match: raw.as_bytes().to_vec(),
            entropy: 4.0,
            unit_ref: UnitRef {
                content_id: ContentId([1; 32]),
                locations: vec![UnitLocation {
                    path: RepoPath("src/app.tsx".to_owned()),
                    provenance: Provenance::WorkingTree,
                    additional_provenance: Vec::new(),
                    location_class,
                }],
            },
            span: Span {
                line: 1,
                col_start: 1,
                col_end: raw.len() as u32,
            },
        }
    }

    #[test]
    fn classifies_new_publishable_key_as_info() {
        let finding = SupabaseClassifier::new()
            .classify_candidate(&candidate(
                "sb_publishable_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
                LocationClass::ClientReachable,
            ))
            .expect("finding emitted");

        assert_eq!(finding.category, Category::KeyClassification);
        assert_eq!(finding.severity, Severity::Info);
        assert!(matches!(
            finding.evidence,
            Evidence::SupabaseKey {
                class: SupabaseKeyClass::PublishableNew,
                ..
            }
        ));
    }

    #[test]
    fn finding_retains_every_candidate_source_location_with_the_same_span() {
        let raw = "sb_publishable_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";
        let mut candidate = candidate(raw, LocationClass::ServerOnly);
        candidate.unit_ref.locations.push(UnitLocation {
            path: RepoPath("apps/web/.next/static/chunks/config.js".to_owned()),
            provenance: Provenance::WorkingTree,
            additional_provenance: Vec::new(),
            location_class: LocationClass::ClientReachable,
        });

        let finding = SupabaseClassifier::new()
            .classify_candidate(&candidate)
            .expect("finding emitted");

        assert_eq!(finding.locations.len(), 2);
        assert!(
            finding
                .locations
                .iter()
                .all(|location| location.span == Some(candidate.span))
        );
        assert_eq!(
            finding
                .locations
                .iter()
                .map(|location| location.path.0.as_str())
                .collect::<Vec<_>>(),
            vec!["src/app.tsx", "apps/web/.next/static/chunks/config.js"]
        );
    }

    #[test]
    fn content_id_does_not_change_public_finding_identity() {
        let raw = "sb_publishable_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";
        let first = candidate(raw, LocationClass::ClientReachable);
        let mut second = first.clone();
        second.unit_ref.content_id = ContentId([9; 32]);
        let classifier = SupabaseClassifier::new();

        let first = classifier
            .classify_candidate(&first)
            .expect("first finding emitted");
        let second = classifier
            .classify_candidate(&second)
            .expect("second finding emitted");

        assert_eq!(first.id, second.id);
    }

    #[test]
    fn classifies_new_publishable_key_with_colocated_project_url() {
        let raw = "sb_publishable_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";
        let content = format!(
            "const url = 'https://abcdefghijklmnopqrst.supabase.co';\nconst key = '{raw}';\n"
        );
        let finding = SupabaseClassifier::new()
            .classify_candidate_with_unit_content(
                &candidate(raw, LocationClass::ClientReachable),
                Some(content.as_bytes()),
            )
            .expect("finding emitted");

        let Evidence::SupabaseKey { class, project, .. } = finding.evidence else {
            panic!("expected Supabase evidence");
        };

        assert_eq!(class, SupabaseKeyClass::PublishableNew);
        assert_eq!(finding.severity, Severity::Info);
        let project = project.expect("co-located project URL extracted");
        assert_eq!(project.ref_id.as_deref(), Some("abcdefghijklmnopqrst"));
        assert_eq!(project.url, "https://abcdefghijklmnopqrst.supabase.co");
    }

    #[test]
    fn classifies_new_secret_key_with_colocated_project_url() {
        let raw = "sb_secret_0123456789abcdefghijklmnopqrstuvwxyzABCDEF";
        let content = format!(
            "const url = 'https://abcdefghijklmnopqrst.supabase.co';\nconst key = '{raw}';\n"
        );
        let finding = SupabaseClassifier::new()
            .classify_candidate_with_unit_content(
                &candidate(raw, LocationClass::ServerOnly),
                Some(content.as_bytes()),
            )
            .expect("finding emitted");

        let Evidence::SupabaseKey { class, project, .. } = finding.evidence else {
            panic!("expected Supabase evidence");
        };

        assert_eq!(class, SupabaseKeyClass::SecretNew);
        assert_eq!(finding.severity, Severity::Critical);
        assert_eq!(
            project.expect("co-located project URL extracted").url,
            "https://abcdefghijklmnopqrst.supabase.co"
        );
    }

    #[test]
    fn classifies_new_secret_key_as_critical_when_client_reachable() {
        let finding = SupabaseClassifier::new()
            .classify_candidate(&candidate(
                "sb_secret_0123456789abcdefghijklmnopqrstuvwxyzABCDEF",
                LocationClass::ClientReachable,
            ))
            .expect("finding emitted");

        assert_eq!(finding.category, Category::SecretExposure);
        assert_eq!(finding.severity, Severity::Critical);
    }

    #[test]
    fn classifies_legacy_anon_jwt_and_project_ref() {
        let raw =
            jwt_with_payload(r#"{"iss":"supabase","role":"anon","ref":"abcdefghijklmnopqrst"}"#);
        let finding = SupabaseClassifier::new()
            .classify_candidate(&candidate(&raw, LocationClass::ClientReachable))
            .expect("finding emitted");

        let Evidence::SupabaseKey { class, project, .. } = finding.evidence else {
            panic!("expected Supabase evidence");
        };

        assert_eq!(class, SupabaseKeyClass::AnonLegacy);
        assert_eq!(finding.severity, Severity::Info);
        assert_eq!(
            project.expect("project").url,
            "https://abcdefghijklmnopqrst.supabase.co"
        );
    }

    #[test]
    fn classifies_legacy_service_role_as_elevated() {
        let raw = jwt_with_payload(
            r#"{"iss":"https://abcdefghijklmnopqrst.supabase.co/auth/v1","role":"service_role","ref":"abcdefghijklmnopqrst"}"#,
        );
        let finding = SupabaseClassifier::new()
            .classify_candidate(&candidate(&raw, LocationClass::ServerOnly))
            .expect("finding emitted");

        assert_eq!(finding.severity, Severity::Critical);
        assert!(matches!(
            finding.evidence,
            Evidence::SupabaseKey {
                class: SupabaseKeyClass::ServiceRoleLegacy,
                ..
            }
        ));
    }

    #[test]
    fn classifies_committed_secret_as_critical_even_when_server_only() {
        let mut candidate = candidate(
            "sb_secret_0123456789abcdefghijklmnopqrstuvwxyzABCDEF",
            LocationClass::ServerOnly,
        );
        candidate.unit_ref.locations[0].provenance = Provenance::Commit {
            sha: "abc123".to_owned(),
            author: None,
            date: None,
        };

        let finding = SupabaseClassifier::new()
            .classify_candidate(&candidate)
            .expect("finding emitted");

        assert_eq!(finding.severity, Severity::Critical);
    }

    #[test]
    fn ignores_non_supabase_candidate_kinds() {
        let mut candidate = candidate(
            "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890",
            LocationClass::Unknown,
        );
        candidate.kind = CandidateKind::ProviderSecret;

        assert!(
            SupabaseClassifier::new()
                .classify_candidate(&candidate)
                .is_none()
        );
    }

    #[test]
    fn tier0_read_probe_emits_exposed_table_without_row_data() {
        let client = FakeRlsClient::new([
            (
                "https://abcdefghijklmnopqrst.supabase.co/rest/v1/",
                RlsHttpResponse {
                    status: 200,
                    body: r#"{"paths":{"/profiles":{"get":{}},"/rpc/ping":{"post":{}}}}"#
                        .to_owned(),
                },
            ),
            (
                "https://abcdefghijklmnopqrst.supabase.co/rest/v1/profiles?select=*&limit=1",
                RlsHttpResponse {
                    status: 200,
                    body: r#"[{"id":1,"email":"not included in finding"}]"#.to_owned(),
                },
            ),
        ]);
        let input = tier0_input();

        let output = probe_tier0_read_with_client(&client, &input).expect("probe succeeds");

        client.assert_all_requests_include_apikey(&input.public_key);
        assert_eq!(output.warnings, Vec::new());
        assert_eq!(output.findings.len(), 1);
        assert_eq!(output.actions.len(), client.request_count());
        assert_eq!(
            output.actions[0].outcome,
            NetworkActionOutcome::RootEnumerated
        );
        assert_eq!(output.actions[1].outcome, NetworkActionOutcome::Exposed);
        assert_eq!(output.actions[1].observed_row_count, Some(1));
        assert!(output.actions[0].observed_row_count.is_none());
        let finding = &output.findings[0];
        assert_eq!(finding.category, Category::Rls);
        assert_eq!(finding.severity, Severity::Critical);
        let Evidence::RlsProbe {
            project,
            table,
            endpoint,
            observed_row_count,
            exposure,
        } = &finding.evidence
        else {
            panic!("expected RLS evidence");
        };
        assert_eq!(project.url, "https://abcdefghijklmnopqrst.supabase.co");
        assert_eq!(table, "profiles");
        assert_eq!(
            endpoint,
            "https://abcdefghijklmnopqrst.supabase.co/rest/v1/profiles?select=*&limit=1"
        );
        assert_eq!(*observed_row_count, 1);
        assert_eq!(*exposure, vibescan_types::RlsExposure::Exposed);
        assert!(!format!("{finding:?}").contains("not included in finding"));
        let serialized_actions = serde_json::to_string(&output.actions).expect("actions serialize");
        assert!(!serialized_actions.contains(&input.public_key));
        assert!(!serialized_actions.contains("apikey"));
        assert!(!serialized_actions.contains("not included in finding"));
    }

    #[test]
    fn tier0_read_probe_omits_protected_or_empty_tables() {
        let client = FakeRlsClient::new([
	            (
	                "https://abcdefghijklmnopqrst.supabase.co/rest/v1/",
	                RlsHttpResponse {
	                    status: 200,
	                    body: r#"{"paths":{"/private_table":{"get":{}},"/empty_table":{"get":{}},"/missing_table":{"get":{}}}}"#
	                        .to_owned(),
	                },
	            ),
            (
                "https://abcdefghijklmnopqrst.supabase.co/rest/v1/empty_table?select=*&limit=1",
                RlsHttpResponse {
                    status: 200,
                    body: "[]".to_owned(),
	                },
	            ),
	            (
	                "https://abcdefghijklmnopqrst.supabase.co/rest/v1/missing_table?select=*&limit=1",
	                RlsHttpResponse {
	                    status: 404,
	                    body: r#"{"message":"not found"}"#.to_owned(),
	                },
	            ),
	            (
	                "https://abcdefghijklmnopqrst.supabase.co/rest/v1/private_table?select=*&limit=1",
	                RlsHttpResponse {
                    status: 403,
                    body: r#"{"message":"forbidden"}"#.to_owned(),
                },
            ),
        ]);

        let output = probe_tier0_read_with_client(&client, &tier0_input()).expect("probe succeeds");

        client.assert_all_requests_include_apikey(&tier0_input().public_key);
        assert!(output.findings.is_empty());
        assert_eq!(output.warnings, Vec::new());
        assert_eq!(output.actions.len(), client.request_count());
        assert_eq!(
            output
                .actions
                .iter()
                .map(|action| action.outcome)
                .collect::<Vec<_>>(),
            vec![
                NetworkActionOutcome::RootEnumerated,
                NetworkActionOutcome::NoRowsObserved,
                NetworkActionOutcome::NotFound,
                NetworkActionOutcome::Protected,
            ]
        );
        assert!(
            output
                .actions
                .iter()
                .all(|action| action.observed_row_count.is_none())
        );
    }

    #[test]
    fn tier0_read_probe_audits_invalid_responses_without_response_material() {
        let client = FakeRlsClient::new([
            (
                "https://abcdefghijklmnopqrst.supabase.co/rest/v1/",
                RlsHttpResponse {
                    status: 500,
                    body: "sensitive root response".to_owned(),
                },
            ),
            (
                "https://abcdefghijklmnopqrst.supabase.co/rest/v1/profiles?select=*&limit=1",
                RlsHttpResponse {
                    status: 200,
                    body: r#"{"sensitive":"not an array"}"#.to_owned(),
                },
            ),
        ]);
        let input = tier0_input_with_tables(["profiles"]);

        let output = probe_tier0_read_with_client(&client, &input).expect("probe succeeds");

        assert_eq!(output.actions.len(), client.request_count());
        assert!(
            output
                .actions
                .iter()
                .all(|action| action.outcome == NetworkActionOutcome::InvalidResponse)
        );
        let serialized_actions = serde_json::to_string(&output.actions).expect("actions serialize");
        assert!(!serialized_actions.contains("sensitive"));
        assert!(!serialized_actions.contains(&input.public_key));
    }

    #[test]
    fn tier0_read_probe_audits_transport_errors_for_each_attempt() {
        let client = FakeRlsClient::default();
        let input = tier0_input_with_tables(["profiles"]);

        let output = probe_tier0_read_with_client(&client, &input).expect("probe succeeds");

        assert_eq!(output.actions.len(), 2);
        assert_eq!(output.actions.len(), client.request_count());
        assert!(output.actions.iter().all(|action| {
            action.status.is_none() && action.outcome == NetworkActionOutcome::TransportError
        }));
    }

    #[test]
    fn tier0_read_probe_continues_after_root_unavailable_with_harvested_tables() {
        let client = FakeRlsClient::new([
            (
                "https://abcdefghijklmnopqrst.supabase.co/rest/v1/",
                RlsHttpResponse {
                    status: 403,
                    body: r#"{"message":"forbidden"}"#.to_owned(),
                },
            ),
            (
                "https://abcdefghijklmnopqrst.supabase.co/rest/v1/profiles?select=*&limit=1",
                RlsHttpResponse {
                    status: 200,
                    body: r#"[{"id":1}]"#.to_owned(),
                },
            ),
        ]);
        let input = tier0_input_with_tables(["profiles"]);

        let output = probe_tier0_read_with_client(&client, &input).expect("probe succeeds");

        client.assert_all_requests_include_apikey(&input.public_key);
        assert_eq!(output.findings.len(), 1);
        assert_eq!(output.actions.len(), client.request_count());
        assert_eq!(
            output.actions[0].outcome,
            NetworkActionOutcome::RootUnavailable
        );
        assert_eq!(output.actions[0].status, Some(403));
        assert_eq!(output.actions[1].outcome, NetworkActionOutcome::Exposed);
        assert!(matches!(
            output.warnings.as_slice(),
            [Tier0RlsProbeWarning::RootEnumerationUnavailable { status: 403, .. }]
        ));
        assert!(
            output.warnings[0]
                .message()
                .contains("root enumeration unavailable with public key")
        );
    }

    #[test]
    fn tier0_read_probe_reserves_key_rejected_for_table_request() {
        let client = FakeRlsClient::new([
            (
                "https://abcdefghijklmnopqrst.supabase.co/rest/v1/",
                RlsHttpResponse {
                    status: 200,
                    body: r#"{"paths":{"/profiles":{"get":{}}}}"#.to_owned(),
                },
            ),
            (
                "https://abcdefghijklmnopqrst.supabase.co/rest/v1/profiles?select=*&limit=1",
                RlsHttpResponse {
                    status: 401,
                    body: r#"{"message":"invalid api key"}"#.to_owned(),
                },
            ),
        ]);
        let input = tier0_input_with_tables(["profiles"]);

        let output = probe_tier0_read_with_client(&client, &input).expect("probe succeeds");

        client.assert_all_requests_include_apikey(&input.public_key);
        assert!(output.findings.is_empty());
        assert_eq!(output.actions.len(), client.request_count());
        assert_eq!(output.actions[1].outcome, NetworkActionOutcome::KeyRejected);
        assert_eq!(output.actions[1].status, Some(401));
        assert!(matches!(
            output.warnings.as_slice(),
            [Tier0RlsProbeWarning::KeyRejected { .. }]
        ));
    }

    #[test]
    fn root_unauthorized_but_table_readable_is_not_reported_as_key_rejection() {
        let client = FakeRlsClient::new([
            (
                "https://abcdefghijklmnopqrst.supabase.co/rest/v1/",
                RlsHttpResponse {
                    status: 401,
                    body: r#"{"message":"root enumeration unavailable"}"#.to_owned(),
                },
            ),
            (
                "https://abcdefghijklmnopqrst.supabase.co/rest/v1/profiles?select=*&limit=1",
                RlsHttpResponse {
                    status: 200,
                    body: r#"[{"id":1}]"#.to_owned(),
                },
            ),
        ]);
        let input = tier0_input_with_tables(["profiles"]);

        let output = probe_tier0_read_with_client(&client, &input).expect("probe succeeds");

        client.assert_all_requests_include_apikey(&input.public_key);
        assert_eq!(output.findings.len(), 1);
        assert!(output.warnings.iter().any(|warning| matches!(
            warning,
            Tier0RlsProbeWarning::RootEnumerationUnavailable { status: 401, .. }
        )));
        assert!(
            !output
                .warnings
                .iter()
                .any(|warning| matches!(warning, Tier0RlsProbeWarning::KeyRejected { .. }))
        );
    }

    #[test]
    fn root_unauthorized_and_table_unauthorized_report_distinct_outcomes() {
        let client = FakeRlsClient::new([
            (
                "https://abcdefghijklmnopqrst.supabase.co/rest/v1/",
                RlsHttpResponse {
                    status: 401,
                    body: r#"{"message":"root enumeration unavailable"}"#.to_owned(),
                },
            ),
            (
                "https://abcdefghijklmnopqrst.supabase.co/rest/v1/profiles?select=*&limit=1",
                RlsHttpResponse {
                    status: 401,
                    body: r#"{"message":"invalid api key"}"#.to_owned(),
                },
            ),
        ]);
        let input = tier0_input_with_tables(["profiles"]);

        let output = probe_tier0_read_with_client(&client, &input).expect("probe succeeds");

        client.assert_all_requests_include_apikey(&input.public_key);
        assert!(output.findings.is_empty());
        assert!(output.warnings.iter().any(|warning| matches!(
            warning,
            Tier0RlsProbeWarning::RootEnumerationUnavailable { status: 401, .. }
        )));
        assert!(
            output
                .warnings
                .iter()
                .any(|warning| matches!(warning, Tier0RlsProbeWarning::KeyRejected { .. }))
        );
    }

    #[test]
    fn tier0_read_probe_warns_when_there_are_no_candidate_tables() {
        let client = FakeRlsClient::new([(
            "https://abcdefghijklmnopqrst.supabase.co/rest/v1/",
            RlsHttpResponse {
                status: 403,
                body: r#"{"message":"forbidden"}"#.to_owned(),
            },
        )]);
        let input = tier0_input();

        let output = probe_tier0_read_with_client(&client, &input).expect("probe succeeds");

        assert!(output.findings.is_empty());
        assert_eq!(output.warnings.len(), 2);
        assert!(output.warnings.iter().any(|warning| matches!(
            warning,
            Tier0RlsProbeWarning::RootEnumerationUnavailable { status: 403, .. }
        )));
        assert!(
            output
                .warnings
                .iter()
                .any(|warning| matches!(warning, Tier0RlsProbeWarning::NoCandidateTables { .. }))
        );
    }

    #[test]
    fn tier0_read_probe_refuses_non_supabase_urls() {
        let client = FakeRlsClient::default();
        let mut input = tier0_input();
        input.project.url = "https://example.com".to_owned();

        let error =
            probe_tier0_read_with_client(&client, &input).expect_err("invalid URL rejected");

        assert!(matches!(error, RlsProbeError::InvalidProjectUrl(_)));
    }

    #[test]
    fn tier1_mock_catalog_is_read_only_auditable_and_redacted() {
        let source = FakePgCatalog::default();
        let input = tier1_input(
            "postgresql://postgres:raw-db-password@db.abcdefghijklmnopqrst.supabase.co:5432/postgres",
        );
        assert!(!format!("{input:?}").contains("raw-db-password"));

        let output =
            introspect_tier1_with_source(&source, &input).expect("mock introspection succeeds");

        assert!(
            output.findings.is_empty(),
            "the safe mock catalog should not emit Tier 1 findings"
        );
        assert!(output.warnings.is_empty());
        assert_eq!(
            source.calls.borrow().as_slice(),
            [
                (CatalogQueryKind::TablesWithRowSecurity, None),
                (CatalogQueryKind::Policies, Some("profiles".to_owned())),
                (CatalogQueryKind::Grants, Some("profiles".to_owned())),
            ]
        );
        assert_eq!(output.actions.len(), 3);
        assert!(output.actions.iter().all(|action| {
            action.kind == NetworkActionKind::CatalogIntrospection
                && action.intent == NetworkActionIntent::Select
                && action.endpoint == "db.abcdefghijklmnopqrst.supabase.co:5432"
                && action.outcome == NetworkActionOutcome::CatalogRead
                && action.status.is_none()
                && action.observed_row_count.is_none()
        }));

        let serialized = serde_json::to_string(&output.actions).expect("actions serialize");
        for forbidden in [
            "raw-db-password",
            "credential-row-marker",
            "owner_id = auth.uid()",
        ] {
            assert!(
                !serialized.contains(forbidden),
                "actions leaked {forbidden}"
            );
        }
    }

    #[test]
    fn tier1_detects_rls_disabled_candidate() {
        let source = FakePgCatalog {
            tables: vec![table_rls(false)],
            policies: Vec::new(),
            grants: Vec::new(),
            ..FakePgCatalog::default()
        };

        let output = introspect_tier1_with_source(&source, &tier1_input(tier1_db_url()))
            .expect("mock introspection succeeds");

        assert_single_tier1_finding(&output, RlsExposure::RlsDisabled, "ALL");
        assert_eq!(output.findings[0].severity, Severity::Critical);
        assert!(!policy_evidence(&output.findings[0]).rowsecurity);
    }
