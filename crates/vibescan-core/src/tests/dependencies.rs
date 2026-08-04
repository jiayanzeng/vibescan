use super::*;

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
        ) -> Result<vibescan_registry::AdvisorySet, vibescan_registry::RegistryError> {
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

    let ecosystems = private_registry_ecosystems(repo.path()).expect("private registries parse");

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
