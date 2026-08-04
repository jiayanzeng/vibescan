use super::*;

/// Core pipeline error.
#[derive(Debug)]
pub enum CoreError {
    ConfiguredPathMissing {
        kind: &'static str,
        path: PathBuf,
    },
    Detector(vibescan_secrets::DetectorError),
    Git(vibescan_git::GitWalkError),
    Io(io::Error),
    Json(serde_json::Error),
    Toml(toml::de::Error),
    InvalidSeverity(String),
    MissingTier1Credential,
    Tier1(vibescan_supabase::IntrospectError),
    RegistryFeatureUnavailable,
    RegistryNewcomerUnavailable,
    #[cfg(feature = "registry")]
    Registry(vibescan_registry::RegistryError),
}

impl fmt::Display for CoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConfiguredPathMissing { kind, path } => {
                write!(
                    formatter,
                    "configured {kind} file does not exist: {}",
                    path.display()
                )
            }
            Self::Detector(source) => write!(formatter, "detector setup failed: {source}"),
            Self::Git(source) => write!(formatter, "git collection failed: {source}"),
            Self::Io(source) => write!(formatter, "filesystem operation failed: {source}"),
            Self::Json(source) => write!(formatter, "JSON parse failed: {source}"),
            Self::Toml(source) => write!(formatter, "configuration TOML parse failed: {source}"),
            Self::InvalidSeverity(value) => write!(
                formatter,
                "invalid configured severity {value:?}; expected critical, high, medium, low, or info"
            ),
            Self::MissingTier1Credential => formatter.write_str(
                "Tier 1 introspection requires VIBESCAN_SUPABASE_DB_URL in the local environment",
            ),
            Self::Tier1(source) => write!(formatter, "Tier 1 introspection failed: {source}"),
            Self::RegistryFeatureUnavailable => formatter.write_str(
                "registry checks were requested but this binary was built without registry support",
            ),
            Self::RegistryNewcomerUnavailable => formatter.write_str(
                "the registry newcomer heuristic is deferred and unavailable in Track F",
            ),
            #[cfg(feature = "registry")]
            Self::Registry(source) => write!(formatter, "registry checks failed: {source}"),
        }
    }
}

impl std::error::Error for CoreError {}
