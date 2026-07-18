use std::path::PathBuf;
use std::process::ExitCode;

use clap::{ArgAction, Parser, ValueEnum};
#[cfg(feature = "network")]
use vibescan_core::TIER1_DB_URL_ENV;
use vibescan_core::{
    OutputFormat as CoreOutputFormat, OutputStyle, ScanConfig, Severity, resolve_repository_path,
    scan_and_render,
};

#[derive(Debug, Parser)]
#[command(
    name = "vibescan",
    version,
    about = "Scan local Supabase + Next.js apps for correlated secret and RLS risk.",
    long_about = "vibescan runs local-first scans by default: working tree/history collection, secret detection, Supabase key classification, offline correlation, and local reporting. Tier 0 RLS reads and Tier 1 credentialed catalog introspection require the network feature and separate opt-ins. Public package-registry checks require the independent registry feature and --registry-checks."
)]
struct Cli {
    /// Target repository path.
    #[arg(default_value = ".")]
    target: PathBuf,

    /// Output format.
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Tty)]
    format: OutputFormat,

    /// Explicitly enable git history scanning, overriding repository config.
    #[arg(long, action = ArgAction::SetTrue, conflicts_with = "no_history")]
    history: bool,

    /// Explicitly disable git history scanning, overriding repository config.
    #[arg(long, action = ArgAction::SetTrue, conflicts_with = "history")]
    no_history: bool,

    /// Explicitly enable working tree scanning, overriding repository config.
    #[arg(long, action = ArgAction::SetTrue, conflicts_with = "no_working_tree")]
    working_tree: bool,

    /// Explicitly disable working tree scanning, overriding repository config.
    #[arg(long, action = ArgAction::SetTrue, conflicts_with = "working_tree")]
    no_working_tree: bool,

    /// Maximum commits to scan from all refs. Use --exhaustive-history to remove the cap.
    #[arg(long, conflicts_with = "exhaustive_history")]
    max_commits: Option<usize>,

    /// Scan history without a commit cap.
    #[arg(long, action = ArgAction::SetTrue, conflicts_with = "max_commits")]
    exhaustive_history: bool,

    /// Maximum file/blob bytes to scan.
    #[arg(long)]
    max_bytes: Option<usize>,

    /// Baseline file, resolved from the target repository unless absolute.
    #[arg(long)]
    baseline: Option<PathBuf>,

    /// Severity gate for the process exit code.
    #[arg(long, value_enum)]
    severity_gate: Option<SeverityArg>,

    /// Print ANSI colors in TTY output.
    #[arg(long)]
    color: bool,

    /// Opt in to read-only Supabase Tier 0 RLS probing for discovered public keys.
    #[cfg(feature = "network")]
    #[arg(long)]
    rls_tier0_read_probe: bool,

    /// Opt in to read-only Supabase Tier 1 catalog introspection. The database URL is read from VIBESCAN_SUPABASE_DB_URL.
    #[cfg(feature = "network")]
    #[arg(long)]
    rls_tier1_introspect: bool,

    /// Opt in to public package-registry checks. Package names may leave the machine and are disclosed in scan scope.
    #[cfg(feature = "registry")]
    #[arg(long)]
    registry_checks: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum OutputFormat {
    Json,
    Sarif,
    Tty,
    Html,
}

impl From<OutputFormat> for CoreOutputFormat {
    fn from(value: OutputFormat) -> Self {
        match value {
            OutputFormat::Json => Self::Json,
            OutputFormat::Sarif => Self::Sarif,
            OutputFormat::Tty => Self::Tty,
            OutputFormat::Html => Self::Html,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum SeverityArg {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl From<SeverityArg> for Severity {
    fn from(value: SeverityArg) -> Self {
        match value {
            SeverityArg::Critical => Self::Critical,
            SeverityArg::High => Self::High,
            SeverityArg::Medium => Self::Medium,
            SeverityArg::Low => Self::Low,
            SeverityArg::Info => Self::Info,
        }
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("vibescan: {error}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<u8, Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let mut config = ScanConfig::load(&cli.target)?;

    if cli.history {
        config.include_history = true;
    } else if cli.no_history {
        config.include_history = false;
    }
    if cli.working_tree {
        config.include_working_tree = true;
    } else if cli.no_working_tree {
        config.include_working_tree = false;
    }
    if let Some(max_commits) = cli.max_commits {
        config.max_commits = Some(max_commits);
    }
    if cli.exhaustive_history {
        config.max_commits = None;
    }
    if let Some(max_bytes) = cli.max_bytes {
        config.max_bytes = max_bytes;
    }
    if let Some(baseline) = cli.baseline {
        config.baseline_path = Some(resolve_repository_path(&cli.target, baseline)?);
    }
    config.tier0_read_probe = false;
    config.tier1_introspection = false;
    config.registry_checks = false;
    config.registry_newcomer = false;
    #[cfg(feature = "network")]
    {
        apply_network_runtime_options(
            &mut config,
            cli.rls_tier0_read_probe,
            cli.rls_tier1_introspect,
            std::env::var_os(TIER1_DB_URL_ENV).is_some(),
        )
        .map_err(|message| std::io::Error::new(std::io::ErrorKind::InvalidInput, message))?;
    }
    #[cfg(feature = "registry")]
    apply_registry_runtime_options(&mut config, cli.registry_checks);
    if let Some(severity_gate) = cli.severity_gate {
        config.severity_gate = severity_gate.into();
    }

    let (output, code) = scan_and_render(
        &cli.target,
        config,
        cli.format.into(),
        if cli.color {
            OutputStyle::Color
        } else {
            OutputStyle::Plain
        },
    )?;
    print!("{output}");

    Ok(code as u8)
}

#[cfg(feature = "registry")]
fn apply_registry_runtime_options(config: &mut ScanConfig, registry_checks: bool) {
    config.registry_checks = registry_checks;
    config.registry_newcomer = false;
}

#[cfg(feature = "network")]
fn apply_network_runtime_options(
    config: &mut ScanConfig,
    tier0_read_probe: bool,
    tier1_introspection: bool,
    tier1_credential_present: bool,
) -> Result<(), &'static str> {
    if tier1_introspection && !tier1_credential_present {
        return Err(
            "--rls-tier1-introspect requires VIBESCAN_SUPABASE_DB_URL in the local environment",
        );
    }
    config.tier0_read_probe = tier0_read_probe;
    config.tier1_introspection = tier1_introspection;
    Ok(())
}

#[cfg(all(test, feature = "network"))]
mod tests {
    use super::*;

    #[test]
    fn tier0_and_tier1_runtime_opt_ins_are_independent() {
        let mut tier0 = ScanConfig::default();
        apply_network_runtime_options(&mut tier0, true, false, false)
            .expect("Tier 0 does not require a DB credential");
        assert!(tier0.tier0_read_probe);
        assert!(!tier0.tier1_introspection);
        assert!(!tier0.registry_checks);

        let mut tier1 = ScanConfig::default();
        apply_network_runtime_options(&mut tier1, false, true, true)
            .expect("Tier 1 option applies");
        assert!(!tier1.tier0_read_probe);
        assert!(tier1.tier1_introspection);
        assert!(!tier1.registry_checks);
    }

    #[test]
    fn tier1_runtime_opt_in_requires_env_credential_value() {
        let error = apply_network_runtime_options(&mut ScanConfig::default(), false, true, false)
            .expect_err("missing credential rejected");

        assert!(error.contains(TIER1_DB_URL_ENV));
    }
}

#[cfg(all(test, feature = "registry"))]
mod registry_tests {
    use super::*;

    #[test]
    fn registry_runtime_opt_in_is_independent_of_both_rls_tiers() {
        let mut config = ScanConfig::default();

        apply_registry_runtime_options(&mut config, true);

        assert!(config.registry_checks);
        assert!(!config.registry_newcomer);
        assert!(!config.tier0_read_probe);
        assert!(!config.tier1_introspection);
    }
}
