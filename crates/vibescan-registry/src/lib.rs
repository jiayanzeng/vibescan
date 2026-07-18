//! Opt-in public package-registry intelligence for vibescan.
//!
//! Track F implements the two high-confidence registry checks: local OSV
//! snapshot matching and public-package existence resolution. The newcomer
//! heuristic remains deliberately deferred.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
#[cfg(feature = "transport")]
use std::fs;
#[cfg(feature = "transport")]
use std::io::{Cursor, Read};
#[cfg(feature = "transport")]
use std::path::{Path, PathBuf};
#[cfg(feature = "transport")]
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(feature = "transport")]
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(feature = "transport")]
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use vibescan_types::{
    Category, Confidence, DependencyIntegrityReason, Ecosystem, Evidence, Finding, FindingId,
    Location, LocationClass, NetworkActionAudit, NetworkActionIntent, NetworkActionKind,
    NetworkActionOutcome, ParsedDependency, Provenance, RegistryNameEgress, RepoPath, Severity,
};

/// Parsed manifest inputs eligible for opt-in registry checks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistryCheckInput {
    pub dependencies: Vec<ParsedDependency>,
    /// Ecosystems whose public default registry is replaced by repository-local
    /// configuration. Their names must not drive a public-registry 404 finding.
    pub private_registry_ecosystems: BTreeSet<Ecosystem>,
}

/// Findings and shareable audit material produced by registry checks.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RegistryCheckOutput {
    pub findings: Vec<Finding>,
    pub warnings: Vec<RegistryWarning>,
    pub actions: Vec<NetworkActionAudit>,
    pub name_egress: Vec<RegistryNameEgress>,
}

/// Locally usable advisory identities grouped by package and affected version.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdvisorySet {
    pub ecosystem: Ecosystem,
    pub affected_versions: BTreeMap<String, BTreeSet<String>>,
}

impl AdvisorySet {
    pub fn empty(ecosystem: Ecosystem) -> Self {
        Self {
            ecosystem,
            affected_versions: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, package: impl Into<String>, version: impl Into<String>) {
        self.affected_versions
            .entry(normalize_package_name(self.ecosystem, &package.into()))
            .or_default()
            .insert(version.into());
    }

    fn contains(&self, dependency: &ParsedDependency) -> bool {
        let Some(version) = exact_version(dependency) else {
            return false;
        };
        self.affected_versions
            .get(&normalize_package_name(
                dependency.ecosystem,
                &dependency.name,
            ))
            .is_some_and(|versions| versions.contains(version))
    }
}

/// Result of one existence lookup, including whether this run actually sent
/// the package name. Cache hits therefore do not manufacture egress audits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistryResolution {
    pub exists: bool,
    pub request_made: bool,
}

/// Injectable registry/OSV source. Automated tests implement this trait and
/// never open sockets.
pub trait RegistrySource {
    fn resolves(&self, dependency: &ParsedDependency) -> Result<RegistryResolution, RegistryError>;

    fn advisories_for(&self, ecosystem: Ecosystem) -> Result<AdvisorySet, RegistryError>;
}

/// Non-fatal warning categories surfaced in scan scope by F2.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegistryWarning {
    OsvSnapshotUnavailable { ecosystem: Ecosystem },
    RegistryUnavailable { host: String },
    RateLimited { host: String },
    InvalidResponse { host: String },
    SensitiveCoordinateSuppressed,
    NonRegistryCoordinateSuppressed,
}

impl RegistryWarning {
    pub fn message(&self) -> String {
        match self {
            Self::OsvSnapshotUnavailable { ecosystem } => {
                format!("OSV snapshot unavailable for {ecosystem:?}")
            }
            Self::RegistryUnavailable { host } => {
                format!("package registry unavailable at {host}")
            }
            Self::RateLimited { host } => format!("package registry rate limited at {host}"),
            Self::InvalidResponse { host } => {
                format!("package registry returned an invalid response at {host}")
            }
            Self::SensitiveCoordinateSuppressed => {
                "registry check suppressed a credential-shaped package coordinate".to_owned()
            }
            Self::NonRegistryCoordinateSuppressed => {
                "registry check skipped a non-registry dependency source".to_owned()
            }
        }
    }
}

/// Sanitized error returned by a registry source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegistryError {
    RegistryUnavailable { host: String },
    RateLimited { host: String },
    InvalidResponse { host: String, status: Option<u16> },
    OsvSnapshotUnavailable { ecosystem: Ecosystem },
}

impl fmt::Display for RegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RegistryUnavailable { host } => {
                write!(formatter, "package registry unavailable at {host}")
            }
            Self::RateLimited { host } => {
                write!(formatter, "package registry rate limited at {host}")
            }
            Self::InvalidResponse { host, status } => match status {
                Some(status) => write!(
                    formatter,
                    "package registry returned HTTP {status} at {host}"
                ),
                None => write!(
                    formatter,
                    "package registry returned invalid data at {host}"
                ),
            },
            Self::OsvSnapshotUnavailable { ecosystem } => {
                write!(formatter, "OSV snapshot unavailable for {ecosystem:?}")
            }
        }
    }
}

impl std::error::Error for RegistryError {}

/// Run the high-confidence registry checks through an injected source.
///
/// OSV matches are evaluated before public existence requests. A confirmed
/// advisory therefore emits one Critical finding without leaking the package
/// name merely to prove that an already-known package exists.
pub fn run_registry_checks(
    source: &impl RegistrySource,
    input: &RegistryCheckInput,
) -> Result<RegistryCheckOutput, RegistryError> {
    let dependencies = grouped_dependencies(&input.dependencies);
    let mut advisory_sets = BTreeMap::new();
    let mut output = RegistryCheckOutput::default();
    let mut checkable = Vec::new();

    for (key, declarations) in dependencies {
        let dependency = ParsedDependency {
            name: key.name.clone(),
            version_req: key.version_req.clone(),
            ecosystem: key.ecosystem,
            manifest_path: declarations[0].clone(),
            is_scoped: key.is_scoped,
        };
        if coordinate_may_contain_secret(&dependency) {
            output
                .warnings
                .push(RegistryWarning::SensitiveCoordinateSuppressed);
            continue;
        }
        if !is_registry_version_requirement(&dependency.version_req) {
            output
                .warnings
                .push(RegistryWarning::NonRegistryCoordinateSuppressed);
            continue;
        }
        checkable.push((dependency, declarations));
    }

    for ecosystem in checkable
        .iter()
        .map(|(dependency, _)| dependency.ecosystem)
        .collect::<BTreeSet<_>>()
    {
        match source.advisories_for(ecosystem) {
            Ok(advisories) => {
                advisory_sets.insert(ecosystem, advisories);
            }
            Err(_) => output
                .warnings
                .push(RegistryWarning::OsvSnapshotUnavailable { ecosystem }),
        }
    }

    let mut malicious_names = BTreeSet::new();
    for (dependency, declarations) in &checkable {
        if advisory_sets
            .get(&dependency.ecosystem)
            .is_some_and(|advisories| advisories.contains(dependency))
        {
            malicious_names.insert(PackageKey::from(dependency));
            output.findings.push(dependency_finding(
                dependency,
                declarations,
                DependencyIntegrityReason::KnownMalicious,
            ));
        }
    }

    let mut existence_checks = BTreeMap::<PackageKey, (ParsedDependency, Vec<RepoPath>)>::new();
    for (dependency, declarations) in checkable {
        let package_key = PackageKey::from(&dependency);
        if malicious_names.contains(&package_key) {
            continue;
        }
        if dependency.is_scoped
            || input
                .private_registry_ecosystems
                .contains(&dependency.ecosystem)
        {
            continue;
        }
        let entry = existence_checks
            .entry(package_key)
            .or_insert_with(|| (dependency.clone(), Vec::new()));
        entry.1.extend(declarations);
        entry.1.sort();
        entry.1.dedup();
    }

    for (_, (dependency, declarations)) in existence_checks {
        let host = registry_host(dependency.ecosystem);
        match source.resolves(&dependency) {
            Ok(resolution) => {
                if resolution.request_made {
                    output.actions.push(existence_action(
                        &dependency,
                        host,
                        if resolution.exists {
                            Some(200)
                        } else {
                            Some(404)
                        },
                        if resolution.exists {
                            NetworkActionOutcome::RegistryResolved
                        } else {
                            NetworkActionOutcome::NotFound
                        },
                    ));
                    output.name_egress.push(RegistryNameEgress {
                        ecosystem: dependency.ecosystem,
                        host: host.to_owned(),
                    });
                }
                if !resolution.exists {
                    output.findings.push(dependency_finding(
                        &dependency,
                        &declarations,
                        DependencyIntegrityReason::NonexistentPackage,
                    ));
                }
            }
            Err(error) => {
                output.actions.push(existence_action(
                    &dependency,
                    host,
                    error_status(&error),
                    error_outcome(&error),
                ));
                output.name_egress.push(RegistryNameEgress {
                    ecosystem: dependency.ecosystem,
                    host: host.to_owned(),
                });
                output.warnings.push(warning_from_error(error, host));
            }
        }
    }

    output
        .findings
        .sort_by(|left, right| left.id.cmp(&right.id));
    output.warnings.sort_by_key(RegistryWarning::message);
    output.warnings.dedup();
    output.actions.sort_by(|left, right| {
        (&left.endpoint, &left.package, left.status).cmp(&(
            &right.endpoint,
            &right.package,
            right.status,
        ))
    });
    output.actions.dedup();
    output.name_egress.sort();
    output.name_egress.dedup();
    Ok(output)
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct DependencyKey {
    ecosystem: Ecosystem,
    name: String,
    version_req: String,
    is_scoped: bool,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct PackageKey {
    ecosystem: Ecosystem,
    normalized_name: String,
}

impl From<&ParsedDependency> for PackageKey {
    fn from(dependency: &ParsedDependency) -> Self {
        Self {
            ecosystem: dependency.ecosystem,
            normalized_name: normalize_package_name(dependency.ecosystem, &dependency.name),
        }
    }
}

fn grouped_dependencies(
    dependencies: &[ParsedDependency],
) -> BTreeMap<DependencyKey, Vec<RepoPath>> {
    let mut grouped = BTreeMap::<DependencyKey, Vec<RepoPath>>::new();
    for dependency in dependencies {
        grouped
            .entry(DependencyKey {
                ecosystem: dependency.ecosystem,
                name: dependency.name.clone(),
                version_req: dependency.version_req.clone(),
                is_scoped: dependency.is_scoped,
            })
            .or_default()
            .push(dependency.manifest_path.clone());
    }
    for paths in grouped.values_mut() {
        paths.sort();
        paths.dedup();
    }
    grouped
}

fn exact_version(dependency: &ParsedDependency) -> Option<&str> {
    let value = dependency.version_req.trim();
    let value = match dependency.ecosystem {
        Ecosystem::Npm => value.strip_prefix('=').unwrap_or(value),
        Ecosystem::PyPi => value.strip_prefix("==").unwrap_or(value),
    };
    (!value.is_empty()
        && value.chars().next().is_some_and(|ch| ch.is_ascii_digit())
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '+')))
    .then_some(value)
}

fn normalize_package_name(ecosystem: Ecosystem, package: &str) -> String {
    match ecosystem {
        Ecosystem::Npm => package.to_owned(),
        Ecosystem::PyPi => {
            let mut normalized = String::new();
            let mut separator = false;
            for ch in package.chars() {
                if matches!(ch, '-' | '_' | '.') {
                    if !separator {
                        normalized.push('-');
                    }
                    separator = true;
                } else {
                    normalized.extend(ch.to_lowercase());
                    separator = false;
                }
            }
            normalized
        }
    }
}

fn registry_host(ecosystem: Ecosystem) -> &'static str {
    match ecosystem {
        Ecosystem::Npm => "registry.npmjs.org",
        Ecosystem::PyPi => "pypi.org",
    }
}

fn package_coordinate(dependency: &ParsedDependency) -> String {
    format!("{}@{}", dependency.name, dependency.version_req)
}

fn coordinate_may_contain_secret(dependency: &ParsedDependency) -> bool {
    let coordinate = package_coordinate(dependency).to_ascii_lowercase();
    [
        "sb_secret_",
        "service_role",
        "sk_live_",
        "sk-proj-",
        "github_pat_",
        "ghp_",
        "-----begin",
    ]
    .iter()
    .any(|marker| coordinate.contains(marker))
        || coordinate
            .split(|ch: char| !ch.is_ascii_alphanumeric())
            .any(|part| part.len() >= 20 && part.starts_with("akia"))
}

fn is_registry_version_requirement(version_req: &str) -> bool {
    let value = version_req.trim().to_ascii_lowercase();
    !value.is_empty()
        && !value.contains("://")
        && ![
            "git+",
            "git:",
            "file:",
            "link:",
            "workspace:",
            "github:",
            "http:",
            "https:",
        ]
        .iter()
        .any(|prefix| value.starts_with(prefix))
}

fn existence_action(
    dependency: &ParsedDependency,
    host: &str,
    status: Option<u16>,
    outcome: NetworkActionOutcome,
) -> NetworkActionAudit {
    NetworkActionAudit {
        kind: NetworkActionKind::RegistryExistence,
        intent: NetworkActionIntent::Get,
        endpoint: host.to_owned(),
        table: None,
        package: Some(package_coordinate(dependency)),
        status,
        outcome,
        observed_row_count: None,
    }
}

fn error_status(error: &RegistryError) -> Option<u16> {
    match error {
        RegistryError::RateLimited { .. } => Some(429),
        RegistryError::InvalidResponse { status, .. } => *status,
        RegistryError::RegistryUnavailable { .. }
        | RegistryError::OsvSnapshotUnavailable { .. } => None,
    }
}

fn error_outcome(error: &RegistryError) -> NetworkActionOutcome {
    match error {
        RegistryError::RegistryUnavailable { .. } => NetworkActionOutcome::TransportError,
        RegistryError::RateLimited { .. }
        | RegistryError::InvalidResponse { .. }
        | RegistryError::OsvSnapshotUnavailable { .. } => NetworkActionOutcome::InvalidResponse,
    }
}

fn warning_from_error(error: RegistryError, fallback_host: &str) -> RegistryWarning {
    match error {
        RegistryError::RegistryUnavailable { host } => {
            RegistryWarning::RegistryUnavailable { host }
        }
        RegistryError::RateLimited { host } => RegistryWarning::RateLimited { host },
        RegistryError::InvalidResponse { host, .. } => RegistryWarning::InvalidResponse { host },
        RegistryError::OsvSnapshotUnavailable { .. } => RegistryWarning::InvalidResponse {
            host: fallback_host.to_owned(),
        },
    }
}

fn dependency_finding(
    dependency: &ParsedDependency,
    manifest_paths: &[RepoPath],
    reason: DependencyIntegrityReason,
) -> Finding {
    let mut hasher = Sha256::new();
    hasher.update(format!("{:?}", dependency.ecosystem).as_bytes());
    hasher.update(b"\0");
    hasher.update(dependency.name.as_bytes());
    hasher.update(b"\0");
    hasher.update(dependency.version_req.as_bytes());
    hasher.update(b"\0");
    hasher.update(format!("{reason:?}").as_bytes());
    let (severity, title, detail, remediation) = match reason {
        DependencyIntegrityReason::KnownMalicious => (
            Severity::Critical,
            format!("Known-malicious dependency: {}", dependency.name),
            format!(
                "{}@{} matches the locally cached OSV advisory snapshot.",
                dependency.name, dependency.version_req
            ),
            "Remove or upgrade the dependency to a version not affected by the advisory, then regenerate and review the lockfile.".to_owned(),
        ),
        DependencyIntegrityReason::NonexistentPackage => (
            Severity::High,
            format!("Package does not resolve publicly: {}", dependency.name),
            format!(
                "{}@{} returned not found from the public {:?} registry and may be hallucinated or vulnerable to slopsquatting.",
                dependency.name, dependency.version_req, dependency.ecosystem
            ),
            "Verify the intended public package name before install; correct or remove the declaration and regenerate the lockfile.".to_owned(),
        ),
        _ => unreachable!("registry engine emits only F2 reasons"),
    };
    let mut locations = manifest_paths
        .iter()
        .map(|path| Location {
            path: path.clone(),
            span: None,
            provenance: Provenance::WorkingTree,
            additional_provenance: Vec::new(),
            location_class: LocationClass::ServerOnly,
        })
        .collect::<Vec<_>>();
    locations.sort_by(|left, right| left.path.cmp(&right.path));
    Finding {
        id: FindingId(format!(
            "dependency-{}",
            hex::encode(&hasher.finalize()[..12])
        )),
        category: Category::DependencyIntegrity,
        severity,
        title,
        detail,
        locations,
        evidence: Evidence::Dependency {
            package: package_coordinate(dependency),
            manifest_path: manifest_paths[0].clone(),
            reason,
        },
        remediation,
        related: Vec::new(),
        confidence: Confidence::Confirmed,
    }
}

/// Production sync/rustls HTTP source. Construction does not perform egress.
#[cfg(feature = "transport")]
#[derive(Clone, Debug)]
pub struct ReqwestRegistrySource {
    client: reqwest::blocking::Client,
    cache: RegistryCache,
}

#[cfg(feature = "transport")]
impl ReqwestRegistrySource {
    pub fn new() -> Result<Self, RegistryError> {
        let client = reqwest::blocking::Client::builder().build().map_err(|_| {
            RegistryError::InvalidResponse {
                host: "registry transport".to_owned(),
                status: None,
            }
        })?;
        Ok(Self {
            client,
            cache: RegistryCache::new(default_cache_dir(), Duration::from_secs(24 * 60 * 60)),
        })
    }

    fn registry_url(
        dependency: &ParsedDependency,
    ) -> Result<(reqwest::Url, &'static str), RegistryError> {
        let (base, host) = match dependency.ecosystem {
            Ecosystem::Npm => ("https://registry.npmjs.org/", "registry.npmjs.org"),
            Ecosystem::PyPi => ("https://pypi.org/pypi/", "pypi.org"),
        };
        let mut url = reqwest::Url::parse(base).map_err(|_| RegistryError::InvalidResponse {
            host: host.to_owned(),
            status: None,
        })?;
        url.path_segments_mut()
            .map_err(|_| RegistryError::InvalidResponse {
                host: host.to_owned(),
                status: None,
            })?
            .push(&dependency.name);
        if dependency.ecosystem == Ecosystem::PyPi {
            url.path_segments_mut()
                .map_err(|_| RegistryError::InvalidResponse {
                    host: host.to_owned(),
                    status: None,
                })?
                .push("json");
        }
        Ok((url, host))
    }

    fn resolve_uncached(&self, dependency: &ParsedDependency) -> Result<bool, RegistryError> {
        let (url, host) = Self::registry_url(dependency)?;
        let response =
            self.client
                .get(url)
                .send()
                .map_err(|_| RegistryError::RegistryUnavailable {
                    host: host.to_owned(),
                })?;
        match response.status() {
            status if status.is_success() => Ok(true),
            reqwest::StatusCode::NOT_FOUND => Ok(false),
            reqwest::StatusCode::TOO_MANY_REQUESTS => Err(RegistryError::RateLimited {
                host: host.to_owned(),
            }),
            status => Err(RegistryError::InvalidResponse {
                host: host.to_owned(),
                status: Some(status.as_u16()),
            }),
        }
    }

    fn fetch_osv_snapshot(&self, ecosystem: Ecosystem) -> Result<Vec<u8>, RegistryError> {
        const MAX_OSV_SNAPSHOT_BYTES: usize = 512 * 1024 * 1024;
        let host = "osv-vulnerabilities.storage.googleapis.com";
        let ecosystem_path = match ecosystem {
            Ecosystem::Npm => "npm",
            Ecosystem::PyPi => "PyPI",
        };
        let url = format!("https://{host}/{ecosystem_path}/all.zip");
        let response = self
            .client
            .get(url)
            .send()
            .map_err(|_| RegistryError::OsvSnapshotUnavailable { ecosystem })?;
        if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Err(RegistryError::RateLimited {
                host: host.to_owned(),
            });
        }
        if !response.status().is_success() {
            return Err(RegistryError::InvalidResponse {
                host: host.to_owned(),
                status: Some(response.status().as_u16()),
            });
        }
        if response
            .content_length()
            .is_some_and(|size| size > MAX_OSV_SNAPSHOT_BYTES as u64)
        {
            return Err(RegistryError::InvalidResponse {
                host: host.to_owned(),
                status: Some(200),
            });
        }
        let bytes = response
            .bytes()
            .map_err(|_| RegistryError::InvalidResponse {
                host: host.to_owned(),
                status: Some(200),
            })?;
        if bytes.len() > MAX_OSV_SNAPSHOT_BYTES {
            return Err(RegistryError::InvalidResponse {
                host: host.to_owned(),
                status: Some(200),
            });
        }
        Ok(bytes.to_vec())
    }
}

#[cfg(feature = "transport")]
impl RegistrySource for ReqwestRegistrySource {
    fn resolves(&self, dependency: &ParsedDependency) -> Result<RegistryResolution, RegistryError> {
        resolve_with_cache(&self.cache, dependency, || {
            self.resolve_uncached(dependency)
        })
    }

    fn advisories_for(&self, ecosystem: Ecosystem) -> Result<AdvisorySet, RegistryError> {
        advisories_with_cache(&self.cache, ecosystem, || {
            self.fetch_osv_snapshot(ecosystem)
        })
    }
}

#[cfg(feature = "transport")]
#[derive(Clone, Debug)]
struct RegistryCache {
    root: PathBuf,
    ttl: Duration,
}

#[cfg(feature = "transport")]
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
struct ExistenceCacheEntry {
    fetched_at: u64,
    exists: bool,
}

#[cfg(feature = "transport")]
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
struct SnapshotCacheEntry {
    fetched_at: u64,
}

#[cfg(feature = "transport")]
impl RegistryCache {
    fn new(root: PathBuf, ttl: Duration) -> Self {
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

    fn existence_path(&self, dependency: &ParsedDependency) -> PathBuf {
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
fn default_cache_dir() -> PathBuf {
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
fn resolve_with_cache(
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
fn advisories_with_cache(
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
fn parse_osv_snapshot(ecosystem: Ecosystem, bytes: &[u8]) -> Result<AdvisorySet, RegistryError> {
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
fn osv_ecosystem_matches(ecosystem: Ecosystem, value: &str) -> bool {
    match ecosystem {
        Ecosystem::Npm => value.eq_ignore_ascii_case("npm"),
        Ecosystem::PyPi => value.eq_ignore_ascii_case("PyPI"),
    }
}

#[cfg(feature = "transport")]
fn atomic_write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
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

#[cfg(test)]
mod tests {
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
        fn resolves(
            &self,
            dependency: &ParsedDependency,
        ) -> Result<RegistryResolution, RegistryError> {
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
        let mut entry = serde_json::from_slice::<ExistenceCacheEntry>(
            &fs::read(&cache_path).expect("cache reads"),
        )
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
}
