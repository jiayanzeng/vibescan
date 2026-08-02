//! LocalStatic git history and working tree collector.
//!
//! Repository discovery uses gitoxide's `gix-discover`. Object/history reads use
//! gitoxide's in-process object database APIs; no runtime `git` executable or
//! network client crates are required in this LocalStatic crate.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use gix_hash::ObjectId;
use gix_object::bstr::ByteSlice;
use gix_object::tree::EntryMode;
use gix_object::{FindExt, Kind};
use globset::{Glob, GlobSet, GlobSetBuilder};
use ignore::gitignore::{Gitignore, GitignoreBuilder};
use ignore::overrides::{Override, OverrideBuilder};
use ignore::{DirEntry, Match, WalkBuilder};
use sha2::{Digest, Sha256};
use vibescan_types::{
    ContentId, LocationClass, Provenance, RepoPath, ScannableUnit, ScopeWarning, UnitLocation,
};

mod collector;
mod error;
mod history;
mod ignore_policy;
mod location;
mod repository;
mod working_tree;

use collector::*;
use history::*;
use ignore_policy::*;
use location::*;
use working_tree::*;

pub use error::*;
pub use repository::*;

#[cfg(test)]
mod tests;
