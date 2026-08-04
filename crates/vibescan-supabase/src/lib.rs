//! Supabase domain intelligence.
//!
//! By default this crate is LocalStatic only: it classifies Supabase key
//! candidates and emits linkable findings. Tier 0 reads and Tier 1 catalog
//! introspection are compiled only with the `network` feature and must be
//! explicitly enabled by callers.

use std::collections::BTreeSet;
use std::fmt;
#[cfg(feature = "network")]
use std::sync::Mutex;
#[cfg(feature = "network")]
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::Value;
use sha2::{Digest, Sha256};
use url::Url;
use vibescan_types::{
    CandidateKind, Category, Confidence, Evidence, Finding, FindingId, Location,
    NetworkActionAudit, NetworkActionIntent, NetworkActionKind, NetworkActionOutcome, RlsExposure,
    SecretCandidate, SecretFingerprint, Severity, SupabaseKeyClass, SupabaseProject,
};

#[cfg(feature = "network")]
mod catalog;
mod classifier;
mod tier0;
mod tier1;

#[cfg(test)]
#[cfg(feature = "network")]
use catalog::*;
use classifier::{SUPABASE_URL_SUFFIX, is_valid_project_ref};
#[cfg(feature = "network")]
use tier1::*;

#[cfg(feature = "network")]
pub use catalog::{PostgresPgCatalogSource, introspect_tier1};
pub use classifier::SupabaseClassifier;
#[cfg(feature = "network")]
pub use tier0::{ReqwestRlsHttpClient, probe_tier0_read};
pub use tier0::{
    RlsHttpClient, RlsHttpResponse, RlsProbeError, Tier0RlsProbeInput, Tier0RlsProbeOutput,
    Tier0RlsProbeWarning, probe_tier0_read_with_client,
};
pub use tier1::{
    CatalogQueryKind, GrantRow, IntrospectError, PgCatalogSource, PolicyRow, TableRls,
    Tier1IntrospectInput, Tier1IntrospectOutput, Tier1IntrospectWarning,
    introspect_tier1_with_source, project_from_db_url,
};

#[cfg(test)]
mod tests;
