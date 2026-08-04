use super::*;

/// Current crate version used in scan results.
pub const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Env-only source for the Tier 1 database connection string.
pub const TIER1_DB_URL_ENV: &str = "VIBESCAN_SUPABASE_DB_URL";

/// Runtime scan configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScanConfig {
    pub include_working_tree: bool,
    pub include_history: bool,
    pub max_commits: Option<usize>,
    pub max_bytes: usize,
    pub severity_gate: Severity,
    pub path_allowlists: Vec<String>,
    pub baseline_path: Option<PathBuf>,
    pub custom_rules_path: Option<PathBuf>,
    pub tier0_read_probe: bool,
    pub tier1_introspection: bool,
    pub registry_checks: bool,
    pub registry_newcomer: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputFormat {
    Json,
    Sarif,
    Tty,
    Html,
}

impl From<OutputFormat> for ReportFormat {
    fn from(value: OutputFormat) -> Self {
        match value {
            OutputFormat::Json => Self::Json,
            OutputFormat::Sarif => Self::Sarif,
            OutputFormat::Tty => Self::Tty,
            OutputFormat::Html => Self::Html,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputStyle {
    Plain,
    Color,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            include_working_tree: true,
            include_history: true,
            max_commits: Some(2_000),
            max_bytes: vibescan_git::DEFAULT_MAX_BYTES,
            severity_gate: Severity::High,
            path_allowlists: Vec::new(),
            baseline_path: None,
            custom_rules_path: None,
            tier0_read_probe: false,
            tier1_introspection: false,
            registry_checks: false,
            registry_newcomer: false,
        }
    }
}

impl ScanConfig {
    /// Load `vibescan.toml` from `target` if present.
    pub fn load(target: impl AsRef<Path>) -> Result<Self, CoreError> {
        let target = target.as_ref();
        let mut config = Self::default();
        let config_root = discover_repository_root(target).map_err(CoreError::Git)?;
        let config_path = config_root.join("vibescan.toml");

        if config_path.exists() {
            let parsed: FileConfig =
                toml::from_str(&fs::read_to_string(&config_path).map_err(CoreError::Io)?)
                    .map_err(CoreError::Toml)?;
            config.apply_file_config(parsed, &config_root)?;
        }

        Ok(config)
    }

    fn apply_file_config(
        &mut self,
        parsed: FileConfig,
        config_root: &Path,
    ) -> Result<(), CoreError> {
        if let Some(scan) = parsed.scan {
            if let Some(value) = scan.working_tree {
                self.include_working_tree = value;
            }
            if let Some(value) = scan.history {
                self.include_history = value;
            }
            if let Some(value) = scan.max_commits {
                self.max_commits = value;
            }
            if let Some(value) = scan.max_bytes {
                self.max_bytes = value;
            }
            if let Some(value) = scan.severity_gate {
                self.severity_gate = parse_severity(&value)
                    .ok_or_else(|| CoreError::InvalidSeverity(value.clone()))?;
            }
        }

        if let Some(ignore) = parsed.ignore {
            self.path_allowlists.extend(ignore.paths);
        }

        if let Some(baseline) = parsed.baseline {
            self.baseline_path = baseline
                .path
                .map(PathBuf::from)
                .map(|path| resolve_path(config_root, path));
        }

        if let Some(rules) = parsed.rules {
            self.custom_rules_path = rules
                .path
                .map(PathBuf::from)
                .map(|path| resolve_path(config_root, path));
        }

        // Repository config may disable Network work, but only an explicit
        // runtime action may enable it. A configured `true` is intentionally
        // inert until the CLI or another caller confirms the action.
        if let Some(network) = parsed.network {
            if network.tier0_read_probe == Some(false) {
                self.tier0_read_probe = false;
            }
            if network.tier1_introspection == Some(false) {
                self.tier1_introspection = false;
            }
            if network.registry_checks == Some(false) {
                self.registry_checks = false;
            }
            if network.registry_newcomer == Some(false) {
                self.registry_newcomer = false;
            }
        }

        Ok(())
    }
}

/// Resolve a CLI/config path relative to the discovered target repository.
pub fn resolve_repository_path(
    target: impl AsRef<Path>,
    path: impl AsRef<Path>,
) -> Result<PathBuf, CoreError> {
    let path = path.as_ref();
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    let root = discover_repository_root(target.as_ref()).map_err(CoreError::Git)?;
    Ok(root.join(path))
}

pub(super) fn resolve_path(root: &Path, path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        root.join(path)
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct FileConfig {
    scan: Option<ScanSection>,
    ignore: Option<IgnoreSection>,
    baseline: Option<BaselineSection>,
    rules: Option<RulesSection>,
    network: Option<NetworkSection>,
}

#[derive(Debug, Deserialize)]
pub(super) struct ScanSection {
    working_tree: Option<bool>,
    history: Option<bool>,
    max_commits: Option<Option<usize>>,
    max_bytes: Option<usize>,
    severity_gate: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct IgnoreSection {
    #[serde(default)]
    paths: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct BaselineSection {
    path: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct RulesSection {
    path: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct NetworkSection {
    tier0_read_probe: Option<bool>,
    tier1_introspection: Option<bool>,
    registry_checks: Option<bool>,
    registry_newcomer: Option<bool>,
}
