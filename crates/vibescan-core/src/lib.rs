//! Offline scan orchestration and correlation.
//!
//! This crate wires the LocalStatic phases together. It owns configuration,
//! baseline application, generic candidate resolution, correlation,
//! deduplication, statistics, and severity gate policy.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Instant;

use jiff::Timestamp;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use vibescan_git::{WalkOptions, collect_repository, discover_repository_root};
#[cfg(feature = "registry")]
use vibescan_registry::{
    RegistryCheckInput, RegistrySource, ReqwestRegistrySource, run_registry_checks,
};
use vibescan_report::{ReportFormat, TtyStyle, render, render_tty};
use vibescan_secrets::Detector;
use vibescan_supabase::SupabaseClassifier;
#[cfg(feature = "network")]
use vibescan_supabase::{Tier0RlsProbeInput, Tier1IntrospectInput};
#[cfg(feature = "network")]
use vibescan_supabase::{introspect_tier1, probe_tier0_read, project_from_db_url};
#[cfg(feature = "network")]
use vibescan_types::RepoPath;
use vibescan_types::{
    Category, Confidence, ContentId, CorrelationRuleId, Ecosystem, Evidence, Finding, FindingId,
    HistoryScope, Location, LocationClass, NetworkActionAudit, NetworkScope, ParsedDependency,
    Provenance, RlsExposure, ScanResult, ScanScope, ScanStats, ScannableUnit, ScopeWarning,
    SecretCandidate, SecretFingerprint, SupabaseKeyClass, SupabaseProject, UnitRef,
};

pub use vibescan_types::Severity;

mod baseline;
mod config;
mod correlation;
mod dependencies;
mod error;
mod findings;
mod pipeline;

use baseline::*;
use correlation::{
    ClassifiedKeyFact, ClassifiedKeySource, absorb_correlated_constituents,
    coalesce_classified_key_facts, resolve_generic_candidates,
};
#[cfg(feature = "network")]
use correlation::{
    associate_api_references, harvest_api_references, tier0_probe_inputs, tier1_credential_location,
};
use dependencies::scan_dependency_integrity;
#[cfg(feature = "registry")]
use dependencies::{private_registry_ecosystems, registry_eligible_dependencies};
use findings::*;

pub use config::{
    OutputFormat, OutputStyle, ScanConfig, TIER1_DB_URL_ENV, TOOL_VERSION, resolve_repository_path,
};
pub use correlation::correlate_findings;
pub use dependencies::parse_dependencies;
pub use error::CoreError;
pub use pipeline::{exit_code, scan, scan_and_render};

#[cfg(test)]
mod tests;
