use super::*;

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
    let content =
        format!("const url = 'https://abcdefghijklmnopqrst.supabase.co';\nconst key = '{raw}';\n");
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
    let content =
        format!("const url = 'https://abcdefghijklmnopqrst.supabase.co';\nconst key = '{raw}';\n");
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
    let raw = jwt_with_payload(r#"{"iss":"supabase","role":"anon","ref":"abcdefghijklmnopqrst"}"#);
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
