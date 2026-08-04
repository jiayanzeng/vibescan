use super::*;

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
