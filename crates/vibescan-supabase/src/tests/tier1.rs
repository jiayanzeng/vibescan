use super::*;

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
