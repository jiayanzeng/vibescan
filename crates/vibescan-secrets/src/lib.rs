//! LocalStatic secret detection substrate.
//!
//! This crate owns pattern matching, keyword pre-filtering, entropy gates, and
//! allowlist suppression. Supabase semantics are intentionally deferred to
//! `vibescan-supabase`; Supabase-shaped hits are emitted only as
//! `PossibleSupabaseKey` candidates.

use std::collections::BTreeSet;
use std::fmt;

use rayon::prelude::*;
use regex::Regex;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use vibescan_types::{
    CandidateKind, ContentId, LocationClass, Provenance, RepoPath, RuleId, ScannableUnit,
    SecretCandidate, Span, UnitLocation, UnitRef,
};

mod config;
mod content;
mod detector;
mod error;

use content::{byte_to_one_based_col, compile_regexes, normalize_keywords};
use detector::{CompiledAllowlist, CompiledRule};

pub use config::{AllowlistConfig, CandidateKindConfig, ContentPolicy, RuleConfig, RulesetConfig};
pub use content::{is_binary, shannon_entropy, working_tree_unit};
pub use detector::{DEFAULT_RULESET_TOML, Detector};
pub use error::DetectorError;

#[cfg(test)]
mod tests;
