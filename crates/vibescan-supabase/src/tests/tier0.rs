use super::*;

#[test]
fn tier0_read_probe_emits_exposed_table_without_row_data() {
    let client = FakeRlsClient::new([
        (
            "https://abcdefghijklmnopqrst.supabase.co/rest/v1/",
            RlsHttpResponse {
                status: 200,
                body: r#"{"paths":{"/profiles":{"get":{}},"/rpc/ping":{"post":{}}}}"#.to_owned(),
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

    let error = probe_tier0_read_with_client(&client, &input).expect_err("invalid URL rejected");

    assert!(matches!(error, RlsProbeError::InvalidProjectUrl(_)));
}
