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

#[cfg(feature = "transport")]
mod cache;
mod checks;
mod model;
#[cfg(feature = "transport")]
mod transport;

#[cfg(feature = "transport")]
use cache::*;
#[cfg(test)]
use checks::*;

pub use checks::*;
pub use model::*;
#[cfg(feature = "transport")]
pub use transport::*;

#[cfg(test)]
mod tests;
