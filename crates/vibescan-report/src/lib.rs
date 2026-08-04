//! Report renderers for `ScanResult`.
//!
//! This crate is rendering-only. It does not decide findings, run scans, or
//! reach the network.

use serde_json::{Value, json};
use vibescan_types::{
    Category, Confidence, Ecosystem, Evidence, Finding, HistoryScope, Location, NetworkActionAudit,
    NetworkActionIntent, NetworkActionKind, NetworkActionOutcome, Provenance, RegistryNameEgress,
    ScanResult, ScanStats, ScopeWarning, Severity,
};

mod output;
mod presentation;
mod sarif;
mod summaries;

use presentation::*;
use sarif::*;
use summaries::*;

pub use output::{
    ReportFormat, TtyStyle, exit_code, render, render_html, render_json, render_sarif, render_tty,
};

#[cfg(test)]
mod tests;
