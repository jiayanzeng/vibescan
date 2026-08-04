use super::*;

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

    pub(super) fn contains(&self, dependency: &ParsedDependency) -> bool {
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
