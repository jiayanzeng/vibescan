use super::*;

#[test]
fn known_malicious_is_critical_confirmed_and_has_no_name_egress() {
    let mut advisories = AdvisorySet::empty(Ecosystem::Npm);
    advisories.insert("left-pad", "1.3.0");
    let source = MockRegistry {
        advisories: BTreeMap::from([(Ecosystem::Npm, advisories)]),
        ..MockRegistry::default()
    };

    let output = run_registry_checks(
        &source,
        &input(vec![
            dependency("left-pad", "1.3.0", Ecosystem::Npm, false),
            dependency("left-pad", "^1.0.0", Ecosystem::Npm, false),
        ]),
    )
    .expect("registry checks run");

    assert!(source.resolve_calls.borrow().is_empty());
    assert!(output.actions.is_empty());
    assert!(output.name_egress.is_empty());
    assert_eq!(output.findings.len(), 1);
    assert_eq!(output.findings[0].severity, Severity::Critical);
    assert_eq!(output.findings[0].confidence, Confidence::Confirmed);
    assert!(matches!(
        output.findings[0].evidence,
        Evidence::Dependency {
            reason: DependencyIntegrityReason::KnownMalicious,
            ..
        }
    ));
}

#[test]
fn public_404_is_high_confirmed_and_disclosed_once() {
    let source = MockRegistry {
        resolutions: BTreeMap::from([(
            "vibescan-hallucination".to_owned(),
            Ok(RegistryResolution {
                exists: false,
                request_made: true,
            }),
        )]),
        ..MockRegistry::default()
    };

    let output = run_registry_checks(
        &source,
        &input(vec![dependency(
            "vibescan-hallucination",
            "9.9.9",
            Ecosystem::Npm,
            false,
        )]),
    )
    .expect("registry checks run");

    assert_eq!(
        source.resolve_calls.borrow().as_slice(),
        ["vibescan-hallucination"]
    );
    assert_eq!(output.findings.len(), 1);
    assert_eq!(output.findings[0].severity, Severity::High);
    assert_eq!(output.findings[0].confidence, Confidence::Confirmed);
    assert!(matches!(
        output.findings[0].evidence,
        Evidence::Dependency {
            reason: DependencyIntegrityReason::NonexistentPackage,
            ..
        }
    ));
    assert_eq!(output.actions.len(), 1);
    assert_eq!(output.actions[0].kind, NetworkActionKind::RegistryExistence);
    assert_eq!(output.actions[0].status, Some(404));
    assert_eq!(output.actions[0].outcome, NetworkActionOutcome::NotFound);
    assert_eq!(
        output.actions[0].package.as_deref(),
        Some("vibescan-hallucination@9.9.9")
    );
    assert_eq!(
        output.name_egress,
        vec![RegistryNameEgress {
            ecosystem: Ecosystem::Npm,
            host: "registry.npmjs.org".to_owned(),
        }]
    );
}

#[test]
fn resolvable_advisory_free_dependency_has_no_finding() {
    let source = MockRegistry::default();

    let output = run_registry_checks(
        &source,
        &input(vec![dependency("serde", "1.0.0", Ecosystem::Npm, false)]),
    )
    .expect("registry checks run");

    assert!(output.findings.is_empty());
    assert_eq!(output.actions.len(), 1);
    assert_eq!(
        output.actions[0].outcome,
        NetworkActionOutcome::RegistryResolved
    );
}

#[test]
fn scoped_and_private_registry_names_never_become_nonexistent_findings() {
    let source = MockRegistry {
        resolutions: BTreeMap::from([
            (
                "@acme/private".to_owned(),
                Ok(RegistryResolution {
                    exists: false,
                    request_made: true,
                }),
            ),
            (
                "internal-python".to_owned(),
                Ok(RegistryResolution {
                    exists: false,
                    request_made: true,
                }),
            ),
        ]),
        ..MockRegistry::default()
    };
    let mut check_input = input(vec![
        dependency("@acme/private", "1.0.0", Ecosystem::Npm, true),
        dependency("internal-python", "1.0.0", Ecosystem::PyPi, false),
    ]);
    check_input
        .private_registry_ecosystems
        .insert(Ecosystem::PyPi);

    let output = run_registry_checks(&source, &check_input).expect("registry checks run");

    assert!(output.findings.is_empty());
    assert!(output.actions.is_empty());
    assert!(output.name_egress.is_empty());
    assert!(source.resolve_calls.borrow().is_empty());
}

#[test]
fn outage_is_a_warning_never_a_nonexistent_finding() {
    let source = MockRegistry {
        resolutions: BTreeMap::from([(
            "left-pad".to_owned(),
            Err(RegistryError::RegistryUnavailable {
                host: "registry.npmjs.org".to_owned(),
            }),
        )]),
        ..MockRegistry::default()
    };

    let output = run_registry_checks(
        &source,
        &input(vec![dependency("left-pad", "1.3.0", Ecosystem::Npm, false)]),
    )
    .expect("registry failure is non-fatal");

    assert!(output.findings.is_empty());
    assert_eq!(
        output.warnings,
        vec![RegistryWarning::RegistryUnavailable {
            host: "registry.npmjs.org".to_owned(),
        }]
    );
    assert_eq!(
        output.actions[0].outcome,
        NetworkActionOutcome::TransportError
    );
}

#[test]
fn osv_failure_is_explicit_and_does_not_erase_existence_results() {
    let source = MockRegistry {
        advisory_failures: BTreeSet::from([Ecosystem::Npm]),
        ..MockRegistry::default()
    };

    let output = run_registry_checks(
        &source,
        &input(vec![dependency("left-pad", "1.3.0", Ecosystem::Npm, false)]),
    )
    .expect("OSV failure is non-fatal");

    assert!(output.findings.is_empty());
    assert_eq!(
        output.warnings,
        vec![RegistryWarning::OsvSnapshotUnavailable {
            ecosystem: Ecosystem::Npm,
        }]
    );
    assert_eq!(output.actions.len(), 1);
    assert_eq!(
        output.actions[0].outcome,
        NetworkActionOutcome::RegistryResolved
    );
}

#[test]
fn cache_hit_result_emits_no_name_egress_audit() {
    let source = MockRegistry {
        resolutions: BTreeMap::from([(
            "left-pad".to_owned(),
            Ok(RegistryResolution {
                exists: true,
                request_made: false,
            }),
        )]),
        ..MockRegistry::default()
    };

    let output = run_registry_checks(
        &source,
        &input(vec![dependency("left-pad", "1.3.0", Ecosystem::Npm, false)]),
    )
    .expect("cached registry check runs");

    assert!(output.findings.is_empty());
    assert!(output.actions.is_empty());
    assert!(output.name_egress.is_empty());
}

#[test]
fn credential_shaped_coordinate_never_reaches_audit_or_finding() {
    let source = MockRegistry::default();
    let raw = "sb_secret_0123456789abcdefghijklmnopqrstuvwxyz";

    let output = run_registry_checks(
        &source,
        &input(vec![dependency(raw, "1.0.0", Ecosystem::Npm, false)]),
    )
    .expect("credential-shaped coordinate is suppressed");
    let serialized_actions = serde_json::to_string(&output.actions).expect("actions serialize");

    assert!(source.resolve_calls.borrow().is_empty());
    assert!(output.findings.is_empty());
    assert!(output.actions.is_empty());
    assert!(output.name_egress.is_empty());
    assert!(!serialized_actions.contains(raw));
    assert_eq!(
        output.warnings,
        vec![RegistryWarning::SensitiveCoordinateSuppressed]
    );
}

#[test]
fn duplicate_declarations_coalesce_into_one_finding_with_all_locations() {
    let source = MockRegistry {
        resolutions: BTreeMap::from([(
            "missing".to_owned(),
            Ok(RegistryResolution {
                exists: false,
                request_made: true,
            }),
        )]),
        ..MockRegistry::default()
    };
    let first = dependency("missing", "1.0.0", Ecosystem::Npm, false);
    let mut second = first.clone();
    second.manifest_path = RepoPath("apps/web/package.json".to_owned());

    let output =
        run_registry_checks(&source, &input(vec![first, second])).expect("registry checks run");

    assert_eq!(output.findings.len(), 1);
    assert_eq!(output.findings[0].locations.len(), 2);
    assert_eq!(source.resolve_calls.borrow().as_slice(), ["missing"]);
}

#[test]
fn loose_version_ranges_are_not_misreported_as_confirmed_osv_matches() {
    let mut advisories = AdvisorySet::empty(Ecosystem::Npm);
    advisories.insert("left-pad", "1.3.0");
    let source = MockRegistry {
        advisories: BTreeMap::from([(Ecosystem::Npm, advisories)]),
        ..MockRegistry::default()
    };

    let output = run_registry_checks(
        &source,
        &input(vec![dependency(
            "left-pad",
            "^1.3.0",
            Ecosystem::Npm,
            false,
        )]),
    )
    .expect("registry checks run");

    assert!(output.findings.is_empty());
    assert_eq!(source.resolve_calls.borrow().as_slice(), ["left-pad"]);
}
