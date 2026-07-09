use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, ValueEnum};
use vibescan_core::{OutputFormat as CoreOutputFormat, OutputStyle, ScanConfig, scan_and_render};
use vibescan_types::Severity;

#[derive(Debug, Parser)]
#[command(
    name = "vibescan",
    version,
    about = "Scan local Supabase + Next.js apps for correlated secret and RLS risk.",
    long_about = "vibescan runs the free local tier: working tree/history collection, secret detection, Supabase key classification, offline correlation, and local reporting. Network RLS probes are intentionally not wired in this tier yet."
)]
struct Cli {
    /// Target repository path.
    #[arg(default_value = ".")]
    target: PathBuf,

    /// Output format.
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Tty)]
    format: OutputFormat,

    /// Disable git history scanning.
    #[arg(long)]
    no_history: bool,

    /// Disable working tree scanning.
    #[arg(long)]
    no_working_tree: bool,

    /// Maximum commits to scan from all refs. Use --exhaustive-history to remove the cap.
    #[arg(long)]
    max_commits: Option<usize>,

    /// Scan history without a commit cap.
    #[arg(long)]
    exhaustive_history: bool,

    /// Maximum file/blob bytes to scan.
    #[arg(long)]
    max_bytes: Option<usize>,

    /// Baseline file: either a prior ScanResult JSON or a JSON array of finding IDs.
    #[arg(long)]
    baseline: Option<PathBuf>,

    /// Severity gate for the process exit code.
    #[arg(long, value_enum, default_value_t = SeverityArg::High)]
    severity_gate: SeverityArg,

    /// Print ANSI colors in TTY output.
    #[arg(long)]
    color: bool,
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

    config.include_history = !cli.no_history;
    config.include_working_tree = !cli.no_working_tree;
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
        config.baseline_path = Some(baseline);
    }
    config.severity_gate = cli.severity_gate.into();

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
