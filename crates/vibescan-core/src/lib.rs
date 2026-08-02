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
use correlation::*;
use dependencies::*;
use findings::*;

pub use config::*;
pub use correlation::*;
pub use dependencies::*;
pub use error::*;
pub use pipeline::*;

#[cfg(all(test, feature = "registry"))]
mod registry_failure_tests;

#[cfg(test)]
mod tests;
