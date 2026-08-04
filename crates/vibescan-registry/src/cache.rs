use super::*;

#[cfg(feature = "transport")]
#[derive(Clone, Debug)]
pub(super) struct RegistryCache {
    root: PathBuf,
    ttl: Duration,
}

#[cfg(feature = "transport")]
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub(super) struct ExistenceCacheEntry {
    pub(super) fetched_at: u64,
    exists: bool,
}

#[cfg(feature = "transport")]
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub(super) struct SnapshotCacheEntry {
    fetched_at: u64,
}

#[cfg(feature = "transport")]
impl RegistryCache {
    pub(super) fn new(root: PathBuf, ttl: Duration) -> Self {
        Self { root, ttl }
    }

    fn now_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn is_fresh(&self, fetched_at: u64) -> bool {
        self.now_secs().saturating_sub(fetched_at) <= self.ttl.as_secs()
    }

    pub(super) fn existence_path(&self, dependency: &ParsedDependency) -> PathBuf {
        let mut hasher = Sha256::new();
        hasher.update(format!("{:?}", dependency.ecosystem).as_bytes());
        hasher.update(b"\0");
        hasher.update(normalize_package_name(dependency.ecosystem, &dependency.name).as_bytes());
        self.root
            .join("existence")
            .join(format!("{}.json", hex::encode(hasher.finalize())))
    }

    fn read_existence(&self, dependency: &ParsedDependency) -> Option<bool> {
        let bytes = fs::read(self.existence_path(dependency)).ok()?;
        let entry = serde_json::from_slice::<ExistenceCacheEntry>(&bytes).ok()?;
        self.is_fresh(entry.fetched_at).then_some(entry.exists)
    }

    fn write_existence(&self, dependency: &ParsedDependency, exists: bool) {
        let path = self.existence_path(dependency);
        let entry = ExistenceCacheEntry {
            fetched_at: self.now_secs(),
            exists,
        };
        if let Ok(bytes) = serde_json::to_vec(&entry) {
            let _ = atomic_write(&path, &bytes);
        }
    }

    fn snapshot_paths(&self, ecosystem: Ecosystem) -> (PathBuf, PathBuf) {
        let name = match ecosystem {
            Ecosystem::Npm => "npm",
            Ecosystem::PyPi => "pypi",
        };
        (
            self.root.join("osv").join(format!("{name}.zip")),
            self.root.join("osv").join(format!("{name}.json")),
        )
    }

    fn read_snapshot(&self, ecosystem: Ecosystem) -> Option<Vec<u8>> {
        let (archive_path, metadata_path) = self.snapshot_paths(ecosystem);
        let metadata = fs::read(metadata_path).ok()?;
        let entry = serde_json::from_slice::<SnapshotCacheEntry>(&metadata).ok()?;
        self.is_fresh(entry.fetched_at)
            .then(|| fs::read(archive_path).ok())
            .flatten()
    }

    fn write_snapshot(&self, ecosystem: Ecosystem, bytes: &[u8]) {
        let (archive_path, metadata_path) = self.snapshot_paths(ecosystem);
        let entry = SnapshotCacheEntry {
            fetched_at: self.now_secs(),
        };
        if atomic_write(&archive_path, bytes).is_ok() {
            if let Ok(metadata) = serde_json::to_vec(&entry) {
                let _ = atomic_write(&metadata_path, &metadata);
            }
        }
    }
}

#[cfg(feature = "transport")]
pub(super) fn default_cache_dir() -> PathBuf {
    if let Some(path) = std::env::var_os("VIBESCAN_CACHE_DIR") {
        return PathBuf::from(path).join("registry");
    }
    #[cfg(target_os = "windows")]
    if let Some(path) = std::env::var_os("LOCALAPPDATA") {
        return PathBuf::from(path).join("vibescan").join("registry");
    }
    #[cfg(target_os = "macos")]
    if let Some(path) = std::env::var_os("HOME") {
        return PathBuf::from(path)
            .join("Library")
            .join("Caches")
            .join("vibescan")
            .join("registry");
    }
    if let Some(path) = std::env::var_os("XDG_CACHE_HOME") {
        return PathBuf::from(path).join("vibescan").join("registry");
    }
    if let Some(path) = std::env::var_os("HOME") {
        return PathBuf::from(path)
            .join(".cache")
            .join("vibescan")
            .join("registry");
    }
    std::env::temp_dir().join("vibescan-cache").join("registry")
}

#[cfg(feature = "transport")]
pub(super) fn resolve_with_cache(
    cache: &RegistryCache,
    dependency: &ParsedDependency,
    fetch: impl FnOnce() -> Result<bool, RegistryError>,
) -> Result<RegistryResolution, RegistryError> {
    if let Some(exists) = cache.read_existence(dependency) {
        return Ok(RegistryResolution {
            exists,
            request_made: false,
        });
    }
    let exists = fetch()?;
    cache.write_existence(dependency, exists);
    Ok(RegistryResolution {
        exists,
        request_made: true,
    })
}

#[cfg(feature = "transport")]
pub(super) fn advisories_with_cache(
    cache: &RegistryCache,
    ecosystem: Ecosystem,
    fetch: impl FnOnce() -> Result<Vec<u8>, RegistryError>,
) -> Result<AdvisorySet, RegistryError> {
    if let Some(bytes) = cache.read_snapshot(ecosystem) {
        if let Ok(advisories) = parse_osv_snapshot(ecosystem, &bytes) {
            return Ok(advisories);
        }
    }
    let bytes = fetch()?;
    let advisories = parse_osv_snapshot(ecosystem, &bytes)?;
    cache.write_snapshot(ecosystem, &bytes);
    Ok(advisories)
}

#[cfg(feature = "transport")]
pub(super) fn parse_osv_snapshot(
    ecosystem: Ecosystem,
    bytes: &[u8],
) -> Result<AdvisorySet, RegistryError> {
    const MAX_OSV_ENTRY_BYTES: u64 = 16 * 1024 * 1024;
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes))
        .map_err(|_| RegistryError::OsvSnapshotUnavailable { ecosystem })?;
    let mut advisories = AdvisorySet::empty(ecosystem);
    for index in 0..archive.len() {
        let mut file = archive
            .by_index(index)
            .map_err(|_| RegistryError::OsvSnapshotUnavailable { ecosystem })?;
        if file.is_dir() || !file.name().ends_with(".json") {
            continue;
        }
        if file.size() > MAX_OSV_ENTRY_BYTES {
            return Err(RegistryError::OsvSnapshotUnavailable { ecosystem });
        }
        let mut json = String::new();
        file.read_to_string(&mut json)
            .map_err(|_| RegistryError::OsvSnapshotUnavailable { ecosystem })?;
        let value = serde_json::from_str::<serde_json::Value>(&json)
            .map_err(|_| RegistryError::OsvSnapshotUnavailable { ecosystem })?;
        let Some(affected) = value.get("affected").and_then(serde_json::Value::as_array) else {
            continue;
        };
        for item in affected {
            let Some(package) = item.get("package") else {
                continue;
            };
            let Some(package_ecosystem) =
                package.get("ecosystem").and_then(serde_json::Value::as_str)
            else {
                continue;
            };
            if !osv_ecosystem_matches(ecosystem, package_ecosystem) {
                continue;
            }
            let Some(name) = package.get("name").and_then(serde_json::Value::as_str) else {
                continue;
            };
            for version in item
                .get("versions")
                .and_then(serde_json::Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(serde_json::Value::as_str)
            {
                advisories.insert(name, version);
            }
        }
    }
    Ok(advisories)
}

#[cfg(feature = "transport")]
pub(super) fn osv_ecosystem_matches(ecosystem: Ecosystem, value: &str) -> bool {
    match ecosystem {
        Ecosystem::Npm => value.eq_ignore_ascii_case("npm"),
        Ecosystem::PyPi => value.eq_ignore_ascii_case("PyPI"),
    }
}

#[cfg(feature = "transport")]
pub(super) fn atomic_write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);
    let Some(parent) = path.parent() else {
        return Err(std::io::Error::other("cache path has no parent"));
    };
    fs::create_dir_all(parent)?;
    let temp_path = parent.join(format!(
        ".vibescan-cache-{}-{}.tmp",
        std::process::id(),
        NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed)
    ));
    fs::write(&temp_path, bytes)?;
    match fs::rename(&temp_path, path) {
        Ok(()) => Ok(()),
        Err(error) => {
            let _ = fs::remove_file(&temp_path);
            Err(error)
        }
    }
}
