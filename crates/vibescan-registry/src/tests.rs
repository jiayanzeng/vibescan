#[cfg(feature = "transport")]
use std::cell::Cell;
use std::cell::RefCell;

use super::*;

#[derive(Default)]
struct MockRegistry {
    advisories: BTreeMap<Ecosystem, AdvisorySet>,
    advisory_failures: BTreeSet<Ecosystem>,
    resolutions: BTreeMap<String, Result<RegistryResolution, RegistryError>>,
    resolve_calls: RefCell<Vec<String>>,
    advisory_calls: RefCell<Vec<Ecosystem>>,
}

impl RegistrySource for MockRegistry {
    fn resolves(&self, dependency: &ParsedDependency) -> Result<RegistryResolution, RegistryError> {
        self.resolve_calls
            .borrow_mut()
            .push(dependency.name.clone());
        self.resolutions
            .get(&dependency.name)
            .cloned()
            .unwrap_or(Ok(RegistryResolution {
                exists: true,
                request_made: true,
            }))
    }

    fn advisories_for(&self, ecosystem: Ecosystem) -> Result<AdvisorySet, RegistryError> {
        self.advisory_calls.borrow_mut().push(ecosystem);
        if self.advisory_failures.contains(&ecosystem) {
            return Err(RegistryError::OsvSnapshotUnavailable { ecosystem });
        }
        Ok(self
            .advisories
            .get(&ecosystem)
            .cloned()
            .unwrap_or_else(|| AdvisorySet::empty(ecosystem)))
    }
}

fn dependency(
    name: &str,
    version_req: &str,
    ecosystem: Ecosystem,
    is_scoped: bool,
) -> ParsedDependency {
    ParsedDependency {
        name: name.to_owned(),
        version_req: version_req.to_owned(),
        ecosystem,
        manifest_path: RepoPath(match ecosystem {
            Ecosystem::Npm => "package.json".to_owned(),
            Ecosystem::PyPi => "pyproject.toml".to_owned(),
        }),
        is_scoped,
    }
}

fn input(dependencies: Vec<ParsedDependency>) -> RegistryCheckInput {
    RegistryCheckInput {
        dependencies,
        private_registry_ecosystems: BTreeSet::new(),
    }
}

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

#[test]
fn warning_messages_disclose_only_public_host_and_ecosystem() {
    assert_eq!(
        RegistryWarning::RegistryUnavailable {
            host: "registry.npmjs.org".to_owned()
        }
        .message(),
        "package registry unavailable at registry.npmjs.org"
    );
    assert!(
        RegistryWarning::OsvSnapshotUnavailable {
            ecosystem: Ecosystem::PyPi
        }
        .message()
        .contains("PyPi")
    );
}

#[cfg(feature = "transport")]
#[test]
fn production_source_constructs_without_opening_a_connection() {
    let _source = ReqwestRegistrySource::new().expect("rustls client constructs");
}

#[cfg(feature = "transport")]
#[test]
fn existence_cache_avoids_a_second_request() {
    let temp = TestDir::new("existence-cache");
    let cache = RegistryCache::new(temp.path.clone(), Duration::from_secs(24 * 60 * 60));
    let dependency = dependency("left-pad", "1.3.0", Ecosystem::Npm, false);
    let calls = Cell::new(0_u64);

    let first = resolve_with_cache(&cache, &dependency, || {
        calls.set(calls.get() + 1);
        Ok(true)
    })
    .expect("first lookup succeeds");
    let second = resolve_with_cache(&cache, &dependency, || {
        calls.set(calls.get() + 1);
        Ok(false)
    })
    .expect("cached lookup succeeds");

    assert_eq!(calls.get(), 1);
    assert_eq!(
        first,
        RegistryResolution {
            exists: true,
            request_made: true,
        }
    );
    assert_eq!(
        second,
        RegistryResolution {
            exists: true,
            request_made: false,
        }
    );
}

#[cfg(feature = "transport")]
#[test]
fn expired_existence_cache_is_refreshed() {
    let temp = TestDir::new("existence-cache-expired");
    let cache = RegistryCache::new(temp.path.clone(), Duration::from_secs(24 * 60 * 60));
    let dependency = dependency("left-pad", "1.3.0", Ecosystem::Npm, false);
    let calls = Cell::new(0_u64);

    resolve_with_cache(&cache, &dependency, || {
        calls.set(calls.get() + 1);
        Ok(true)
    })
    .expect("first lookup succeeds");
    let cache_path = cache.existence_path(&dependency);
    let mut entry =
        serde_json::from_slice::<ExistenceCacheEntry>(&fs::read(&cache_path).expect("cache reads"))
            .expect("cache entry parses");
    entry.fetched_at = 0;
    fs::write(
        cache_path,
        serde_json::to_vec(&entry).expect("cache serializes"),
    )
    .expect("expired cache writes");

    let refreshed = resolve_with_cache(&cache, &dependency, || {
        calls.set(calls.get() + 1);
        Ok(false)
    })
    .expect("expired lookup refreshes");

    assert_eq!(calls.get(), 2);
    assert_eq!(
        refreshed,
        RegistryResolution {
            exists: false,
            request_made: true,
        }
    );
}

#[cfg(feature = "transport")]
#[test]
fn osv_snapshot_cache_fetches_once_and_matches_locally() {
    let temp = TestDir::new("osv-cache");
    let cache = RegistryCache::new(temp.path.clone(), Duration::from_secs(24 * 60 * 60));
    let archive = osv_archive(
        "GHSA-fixture.json",
        r#"{"affected":[{"package":{"ecosystem":"npm","name":"left-pad"},"versions":["1.3.0"]}]}"#,
    );
    let calls = Cell::new(0_u64);

    let first = advisories_with_cache(&cache, Ecosystem::Npm, || {
        calls.set(calls.get() + 1);
        Ok(archive.clone())
    })
    .expect("snapshot parses");
    let second = advisories_with_cache(&cache, Ecosystem::Npm, || {
        calls.set(calls.get() + 1);
        Err(RegistryError::OsvSnapshotUnavailable {
            ecosystem: Ecosystem::Npm,
        })
    })
    .expect("cached snapshot parses");

    assert_eq!(calls.get(), 1);
    assert_eq!(first, second);
    assert!(first.contains(&dependency("left-pad", "1.3.0", Ecosystem::Npm, false,)));
}

#[cfg(feature = "transport")]
#[test]
fn second_full_check_uses_both_caches_and_issues_zero_requests() {
    struct CachedMockRegistry<'a> {
        cache: &'a RegistryCache,
        archive: Vec<u8>,
        existence_requests: Cell<u64>,
        snapshot_requests: Cell<u64>,
    }

    impl RegistrySource for CachedMockRegistry<'_> {
        fn resolves(
            &self,
            dependency: &ParsedDependency,
        ) -> Result<RegistryResolution, RegistryError> {
            resolve_with_cache(self.cache, dependency, || {
                self.existence_requests
                    .set(self.existence_requests.get() + 1);
                Ok(true)
            })
        }

        fn advisories_for(&self, ecosystem: Ecosystem) -> Result<AdvisorySet, RegistryError> {
            advisories_with_cache(self.cache, ecosystem, || {
                self.snapshot_requests.set(self.snapshot_requests.get() + 1);
                Ok(self.archive.clone())
            })
        }
    }

    let temp = TestDir::new("full-cache");
    let cache = RegistryCache::new(temp.path.clone(), Duration::from_secs(24 * 60 * 60));
    let source = CachedMockRegistry {
        cache: &cache,
        archive: osv_archive("empty.json", r#"{"affected":[]}"#),
        existence_requests: Cell::new(0),
        snapshot_requests: Cell::new(0),
    };
    let check_input = input(vec![dependency("left-pad", "1.3.0", Ecosystem::Npm, false)]);

    let first = run_registry_checks(&source, &check_input).expect("first check runs");
    let second = run_registry_checks(&source, &check_input).expect("cached check runs");

    assert_eq!(source.snapshot_requests.get(), 1);
    assert_eq!(source.existence_requests.get(), 1);
    assert_eq!(first.actions.len(), 1);
    assert!(second.actions.is_empty());
    assert!(second.name_egress.is_empty());
}

#[cfg(feature = "transport")]
fn osv_archive(name: &str, json: &str) -> Vec<u8> {
    use std::io::Write;

    let mut bytes = Cursor::new(Vec::new());
    {
        let mut writer = zip::ZipWriter::new(&mut bytes);
        writer
            .start_file(name, zip::write::SimpleFileOptions::default())
            .expect("zip entry starts");
        writer.write_all(json.as_bytes()).expect("zip entry writes");
        writer.finish().expect("zip finishes");
    }
    bytes.into_inner()
}

#[cfg(feature = "transport")]
struct TestDir {
    path: PathBuf,
}

#[cfg(feature = "transport")]
impl TestDir {
    fn new(label: &str) -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "vibescan-registry-{label}-{}-{}",
            std::process::id(),
            NEXT_ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).expect("test cache directory creates");
        Self { path }
    }
}

#[cfg(feature = "transport")]
impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
