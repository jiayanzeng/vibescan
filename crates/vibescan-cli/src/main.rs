use std::path::PathBuf;
use std::process::ExitCode;

use clap::{ArgAction, Parser, ValueEnum};
use vibescan_core::{
    OutputFormat as CoreOutputFormat, OutputStyle, ScanConfig, Severity, resolve_repository_path,
    scan_and_render,
};

#[derive(Debug, Parser)]
#[command(
    name = "vibescan",
    version,
    about = "Scan local Supabase + Next.js apps for correlated secret and RLS risk.",
    long_about = "vibescan runs local-first scans by default: working tree/history collection, secret detection, Supabase key classification, offline correlation, and local reporting. Tier 0 RLS read probes are available only in builds compiled with the network feature and require an explicit opt-in flag."
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
    #[cfg(feature = "network")]
    {
        config.tier0_read_probe = cli.rls_tier0_read_probe;
    }
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
