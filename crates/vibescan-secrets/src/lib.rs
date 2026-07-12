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

const INLINE_ALLOW_MARKER: &str = "vibescan:allow";
const MINIFIED_GENERIC_LINE_THRESHOLD: usize = 500;

/// Embedded default ruleset. The generic corpus is intentionally conservative
/// in v1; deeper breadth can come from configured rules without changing the
/// Supabase moat.
pub const DEFAULT_RULESET_TOML: &str = include_str!("rules/default-rules.toml");

/// Detection engine ready to scan `ScannableUnit`s.
#[derive(Debug)]
pub struct Detector {
    rules: Vec<CompiledRule>,
    global_allowlists: Vec<CompiledAllowlist>,
}

impl Detector {
    /// Build a detector from the embedded default ruleset.
    pub fn default_rules() -> Result<Self, DetectorError> {
        RulesetConfig::from_toml(DEFAULT_RULESET_TOML)?.compile()
    }

    /// Build a detector from TOML using the gitleaks-style surface supported by
    /// this crate.
    pub fn from_toml(input: &str) -> Result<Self, DetectorError> {
        RulesetConfig::from_toml(input)?.compile()
    }

    /// Scan all supplied units and return raw candidates.
    pub fn detect_units<'a>(
        &self,
        units: impl IntoIterator<Item = &'a ScannableUnit>,
    ) -> Vec<SecretCandidate> {
        let units = units.into_iter().collect::<Vec<_>>();
        units
            .par_iter()
            .flat_map(|unit| self.detect_unit(unit))
            .collect()
    }

    #[cfg(test)]
    fn detect_units_serial<'a>(
        &self,
        units: impl IntoIterator<Item = &'a ScannableUnit>,
    ) -> Vec<SecretCandidate> {
        units
            .into_iter()
            .flat_map(|unit| self.detect_unit(unit))
            .collect()
    }

    /// Scan one unit and return raw candidates.
    pub fn detect_unit(&self, unit: &ScannableUnit) -> Vec<SecretCandidate> {
        if is_binary(&unit.content) {
            return Vec::new();
        }

        let Ok(content) = std::str::from_utf8(&unit.content) else {
            return Vec::new();
        };

        content
            .lines()
            .enumerate()
            .flat_map(|(line_index, line)| self.detect_line(unit, line, line_index as u32 + 1))
            .collect()
    }

    fn detect_line(
        &self,
        unit: &ScannableUnit,
        line: &str,
        line_number: u32,
    ) -> Vec<SecretCandidate> {
        if line.contains(INLINE_ALLOW_MARKER) {
            return Vec::new();
        }

        self.rules
            .iter()
            .filter(|rule| rule.keyword_prefilter(line))
            .flat_map(|rule| rule.detect(line, line_number, unit, &self.global_allowlists))
            .collect()
    }
}

impl Default for Detector {
    fn default() -> Self {
        Self::default_rules().expect("embedded vibescan default ruleset compiles")
    }
}

#[derive(Debug)]
struct CompiledRule {
    id: String,
    kind: CandidateKind,
    regex: Regex,
    secret_group: usize,
    keywords: Vec<String>,
    entropy: Option<f64>,
    path_allowlist: Vec<Regex>,
    allowlists: Vec<CompiledAllowlist>,
}

impl CompiledRule {
    fn applies_to_path(&self, path: &str) -> bool {
        !self
            .path_allowlist
            .iter()
            .any(|allowlist| allowlist.is_match(path))
    }

    fn keyword_prefilter(&self, line: &str) -> bool {
        self.keywords.is_empty()
            || self
                .keywords
                .iter()
                .any(|keyword| line.to_ascii_lowercase().contains(keyword))
    }

    fn detect(
        &self,
        line: &str,
        line_number: u32,
        unit: &ScannableUnit,
        global_allowlists: &[CompiledAllowlist],
    ) -> Vec<SecretCandidate> {
        if self.kind == CandidateKind::GenericHighEntropy
            && line.len() > MINIFIED_GENERIC_LINE_THRESHOLD
        {
            return Vec::new();
        }

        self.regex
            .captures_iter(line)
            .filter_map(|captures| {
                let secret = captures.get(self.secret_group)?;
                let entropy = shannon_entropy(secret.as_str().as_bytes());
                if self.entropy.is_some_and(|threshold| entropy < threshold) {
                    return None;
                }

                let locations = unit
                    .locations
                    .iter()
                    .filter(|location| self.applies_to_path(&location.path.0))
                    .filter(|location| {
                        let context = AllowlistContext {
                            path: &location.path.0,
                            secret: secret.as_str(),
                            line,
                            provenance: &location.provenance,
                            additional_provenance: &location.additional_provenance,
                        };
                        !self
                            .allowlists
                            .iter()
                            .any(|allowlist| allowlist.matches(context))
                            && !global_allowlists
                                .iter()
                                .any(|allowlist| allowlist.matches(context))
                    })
                    .cloned()
                    .collect::<Vec<_>>();
                if locations.is_empty() {
                    return None;
                }

                Some(SecretCandidate {
                    rule_id: RuleId(self.id.clone()),
                    kind: self.kind.clone(),
                    raw_match: secret.as_str().as_bytes().to_vec(),
                    entropy,
                    unit_ref: UnitRef {
                        content_id: unit.content_id.clone(),
                        locations,
                    },
                    span: Span {
                        line: line_number,
                        col_start: byte_to_one_based_col(line, secret.start()),
                        col_end: byte_to_one_based_col(line, secret.end()),
                    },
                })
            })
            .collect()
    }
}

#[derive(Clone, Copy)]
struct AllowlistContext<'a> {
    path: &'a str,
    secret: &'a str,
    line: &'a str,
    provenance: &'a Provenance,
    additional_provenance: &'a [Provenance],
}

#[derive(Debug)]
struct CompiledAllowlist {
    paths: Vec<Regex>,
    regexes: Vec<Regex>,
    commits: BTreeSet<String>,
    stopwords: BTreeSet<String>,
}

impl CompiledAllowlist {
    fn matches(&self, context: AllowlistContext<'_>) -> bool {
        self.paths.iter().any(|path| path.is_match(context.path))
            || self
                .regexes
                .iter()
                .any(|regex| regex.is_match(context.line))
            || self.matches_commit(context.provenance)
            || context
                .additional_provenance
                .iter()
                .any(|provenance| self.matches_commit(provenance))
            || self
                .stopwords
                .iter()
                .any(|stopword| context.secret.contains(stopword))
    }

    fn matches_commit(&self, provenance: &Provenance) -> bool {
        let Provenance::Commit { sha, .. } = provenance else {
            return false;
        };
        self.commits.contains(sha)
    }
}

/// Parsed ruleset surface.
#[derive(Debug, Deserialize)]
pub struct RulesetConfig {
    #[serde(default)]
    pub rules: Vec<RuleConfig>,
    #[serde(default)]
    pub allowlists: Vec<AllowlistConfig>,
}

impl RulesetConfig {
    pub fn from_toml(input: &str) -> Result<Self, DetectorError> {
        toml::from_str(input).map_err(DetectorError::Toml)
    }

    pub fn compile(self) -> Result<Detector, DetectorError> {
        let rules = self
            .rules
            .into_iter()
            .map(RuleConfig::compile)
            .collect::<Result<Vec<_>, _>>()?;
        let global_allowlists = self
            .allowlists
            .into_iter()
            .map(AllowlistConfig::compile)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Detector {
            rules,
            global_allowlists,
        })
    }
}

/// One configured detection rule.
#[derive(Debug, Deserialize)]
pub struct RuleConfig {
    pub id: String,
    #[serde(default)]
    pub kind: CandidateKindConfig,
    pub regex: String,
    #[serde(default = "default_secret_group")]
    pub secret_group: usize,
    #[serde(default)]
    pub keywords: Vec<String>,
    pub entropy: Option<f64>,
    #[serde(default)]
    pub path_allowlist: Vec<String>,
    #[serde(default)]
    pub allowlists: Vec<AllowlistConfig>,
}

impl RuleConfig {
    fn compile(self) -> Result<CompiledRule, DetectorError> {
        Ok(CompiledRule {
            id: self.id,
            kind: self.kind.into(),
            regex: Regex::new(&self.regex).map_err(|source| DetectorError::Regex {
                pattern: self.regex,
                source,
            })?,
            secret_group: self.secret_group,
            keywords: normalize_keywords(self.keywords),
            entropy: self.entropy,
            path_allowlist: compile_regexes(self.path_allowlist)?,
            allowlists: self
                .allowlists
                .into_iter()
                .map(AllowlistConfig::compile)
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}

fn default_secret_group() -> usize {
    1
}

/// Candidate kind accepted by TOML configuration.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateKindConfig {
    PossibleSupabaseKey,
    ProviderSecret,
    PrivateKey,
    GenericHighEntropy,
    #[default]
    Other,
}

impl From<CandidateKindConfig> for CandidateKind {
    fn from(value: CandidateKindConfig) -> Self {
        match value {
            CandidateKindConfig::PossibleSupabaseKey => Self::PossibleSupabaseKey,
            CandidateKindConfig::ProviderSecret => Self::ProviderSecret,
            CandidateKindConfig::PrivateKey => Self::PrivateKey,
            CandidateKindConfig::GenericHighEntropy => Self::GenericHighEntropy,
            CandidateKindConfig::Other => Self::Other("configured".to_owned()),
        }
    }
}

/// OR-semantics allowlist. Any path, regex, or stopword match suppresses the
/// candidate.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct AllowlistConfig {
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub regexes: Vec<String>,
    #[serde(default)]
    pub commits: Vec<String>,
    #[serde(default)]
    pub stopwords: Vec<String>,
}

impl AllowlistConfig {
    fn compile(self) -> Result<CompiledAllowlist, DetectorError> {
        Ok(CompiledAllowlist {
            paths: compile_regexes(self.paths)?,
            regexes: compile_regexes(self.regexes)?,
            commits: self.commits.into_iter().collect(),
            stopwords: self.stopwords.into_iter().collect(),
        })
    }
}

/// Size/content policy used by callers before constructing scan units.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContentPolicy {
    pub max_bytes: usize,
}

impl Default for ContentPolicy {
    fn default() -> Self {
        Self {
            max_bytes: 4 * 1024 * 1024,
        }
    }
}

impl ContentPolicy {
    pub fn should_scan(&self, content: &[u8]) -> bool {
        content.len() <= self.max_bytes && !is_binary(content)
    }
}

/// Detect binary content by the null-byte heuristic required by the shared
/// content rules.
pub fn is_binary(content: &[u8]) -> bool {
    content.contains(&0)
}

/// Shannon entropy over bytes.
pub fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }

    let mut counts = [0_u32; 256];
    for byte in bytes {
        counts[*byte as usize] += 1;
    }

    counts
        .iter()
        .filter(|count| **count > 0)
        .map(|count| {
            let probability = f64::from(*count) / bytes.len() as f64;
            -probability * probability.log2()
        })
        .sum()
}

fn byte_to_one_based_col(line: &str, byte_index: usize) -> u32 {
    line[..byte_index].chars().count() as u32 + 1
}

fn normalize_keywords(keywords: Vec<String>) -> Vec<String> {
    keywords
        .into_iter()
        .map(|keyword| keyword.to_ascii_lowercase())
        .collect()
}

fn compile_regexes(patterns: Vec<String>) -> Result<Vec<Regex>, DetectorError> {
    patterns
        .into_iter()
        .map(|pattern| {
            Regex::new(&pattern).map_err(|source| DetectorError::Regex { pattern, source })
        })
        .collect()
}

/// Helper for tests and early callers before `vibescan-git` exists.
pub fn working_tree_unit(path: impl Into<String>, content: impl Into<Vec<u8>>) -> ScannableUnit {
    let content = content.into();
    ScannableUnit {
        content_id: ContentId(Sha256::digest(&content).into()),
        content,
        locations: vec![UnitLocation {
            path: RepoPath(path.into()),
            provenance: Provenance::WorkingTree,
            additional_provenance: Vec::new(),
            location_class: LocationClass::Unknown,
        }],
    }
}

/// Detector construction error.
#[derive(Debug)]
pub enum DetectorError {
    Regex {
        pattern: String,
        source: regex::Error,
    },
    Toml(toml::de::Error),
}

impl fmt::Display for DetectorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Regex { pattern, source } => {
                write!(formatter, "invalid regex pattern {pattern:?}: {source}")
            }
            Self::Toml(source) => write!(formatter, "invalid ruleset TOML: {source}"),
        }
    }
}

impl std::error::Error for DetectorError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn detect(content: &str) -> Vec<SecretCandidate> {
        let detector = Detector::default_rules().expect("default rules compile");
        let unit = working_tree_unit("src/app.tsx", content.as_bytes().to_vec());
        detector.detect_unit(&unit)
    }

    #[test]
    fn default_rules_compile() {
        Detector::default_rules().expect("embedded default ruleset compiles");
    }

    #[test]
    fn detects_supabase_new_key_shapes() {
        let findings = detect(
            "const url = 'https://x.supabase.co';\n\
             const anon = 'sb_publishable_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789';\n\
             const secret = 'sb_secret_0123456789abcdefghijklmnopqrstuvwxyzABCDEF';\n",
        );

        let rule_ids = findings
            .iter()
            .map(|candidate| candidate.rule_id.0.as_str())
            .collect::<BTreeSet<_>>();

        assert!(rule_ids.contains("supabase-publishable-key"));
        assert!(rule_ids.contains("supabase-secret-key"));
        assert!(
            findings
                .iter()
                .all(|candidate| candidate.kind == CandidateKind::PossibleSupabaseKey)
        );
    }

    #[test]
    fn applies_entropy_gate_to_generic_assignments() {
        let noisy = detect("const token = 'abcdefghijklmnopqrstuvwxyzABCDEFG1234567890';");
        let placeholder = detect("const token = 'example-example-example-example';");

        assert!(
            noisy
                .iter()
                .any(|candidate| candidate.rule_id.0 == "generic-high-entropy-assignment")
        );
        assert!(
            !placeholder
                .iter()
                .any(|candidate| candidate.rule_id.0 == "generic-high-entropy-assignment")
        );
    }

    #[test]
    fn generic_entropy_skips_minified_lines_but_provider_rules_still_fire() {
        let detector = Detector::default_rules().expect("default rules compile");
        let generic_line = format!(
            "var props={};const token='abcdefghijklmnopqrstuvwxyzABCDEFG1234567890';",
            "x".repeat(520)
        );
        let unit = working_tree_unit(".next/static/chunks/prop-types.js", generic_line);

        assert!(
            !detector
                .detect_unit(&unit)
                .iter()
                .any(|candidate| candidate.rule_id.0 == "generic-high-entropy-assignment")
        );

        let provider_line = format!(
            "var bundle={};const stripe='sk_live_abcdefghijklmnopqrstuvwxyz123456';",
            "x".repeat(520)
        );
        let unit = working_tree_unit(".next/static/chunks/app.js", provider_line);

        assert!(
            detector
                .detect_unit(&unit)
                .iter()
                .any(|candidate| candidate.rule_id.0 == "stripe-secret-key")
        );
    }

    #[test]
    fn inline_allow_suppresses_line() {
        let findings =
            detect("const key = 'sk-proj-abcdefghijklmnopqrstuvwxyz1234567890'; // vibescan:allow");

        assert!(findings.is_empty());
    }

    #[test]
    fn configured_allowlist_suppresses_stopword() {
        let detector = Detector::from_toml(
            r#"
            [[rules]]
            id = "toy"
            kind = "provider_secret"
            regex = '''token = "([A-Za-z0-9_]{8,})"'''
            keywords = ["token"]

            [[rules.allowlists]]
            stopwords = ["PLACEHOLDER"]
            "#,
        )
        .expect("ruleset compiles");
        let unit = working_tree_unit("src/app.ts", br#"token = "PLACEHOLDER_TOKEN""#.to_vec());

        assert!(detector.detect_unit(&unit).is_empty());
    }

    #[test]
    fn configured_allowlist_suppresses_commit_id() {
        let detector = Detector::from_toml(
            r#"
            [[rules]]
            id = "toy"
            kind = "provider_secret"
            regex = '''token = "([A-Za-z0-9_]{8,})"'''
            keywords = ["token"]

            [[rules.allowlists]]
            commits = ["abc123"]
            "#,
        )
        .expect("ruleset compiles");
        let mut unit = working_tree_unit("src/app.ts", br#"token = "REAL_TOKEN_VALUE""#.to_vec());
        unit.locations[0].provenance = Provenance::Commit {
            sha: "abc123".to_owned(),
            author: None,
            date: None,
        };

        assert!(detector.detect_unit(&unit).is_empty());
    }

    #[test]
    fn path_allowlist_removes_only_the_matching_source_occurrence() {
        let detector = Detector::from_toml(
            r#"
            [[rules]]
            id = "toy"
            kind = "provider_secret"
            regex = '''token = "([A-Za-z0-9_]{8,})"'''
            keywords = ["token"]
            path_allowlist = ["^docs/"]
            "#,
        )
        .expect("ruleset compiles");
        let mut unit =
            working_tree_unit("docs/example.ts", br#"token = "REAL_TOKEN_VALUE""#.to_vec());
        unit.locations.push(UnitLocation {
            path: RepoPath("src/config.ts".to_owned()),
            provenance: Provenance::WorkingTree,
            additional_provenance: Vec::new(),
            location_class: LocationClass::ServerOnly,
        });

        let candidates = detector.detect_unit(&unit);

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].unit_ref.locations.len(), 1);
        assert_eq!(candidates[0].unit_ref.locations[0].path.0, "src/config.ts");
    }

    #[test]
    fn commit_allowlist_removes_only_the_matching_source_occurrence() {
        let detector = Detector::from_toml(
            r#"
            [[rules]]
            id = "toy"
            kind = "provider_secret"
            regex = '''token = "([A-Za-z0-9_]{8,})"'''
            keywords = ["token"]

            [[rules.allowlists]]
            commits = ["abc123"]
            "#,
        )
        .expect("ruleset compiles");
        let mut unit =
            working_tree_unit("src/current.ts", br#"token = "REAL_TOKEN_VALUE""#.to_vec());
        unit.locations.push(UnitLocation {
            path: RepoPath("src/history.ts".to_owned()),
            provenance: Provenance::Commit {
                sha: "abc123".to_owned(),
                author: None,
                date: None,
            },
            additional_provenance: Vec::new(),
            location_class: LocationClass::Unknown,
        });

        let candidates = detector.detect_unit(&unit);

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].unit_ref.locations.len(), 1);
        assert_eq!(candidates[0].unit_ref.locations[0].path.0, "src/current.ts");
    }

    #[test]
    fn parallel_unit_detection_matches_serial_results() {
        let detector = Detector::default_rules().expect("default rules compile");
        let units = (0..128)
            .map(|index| {
                let content = if index % 2 == 0 {
                    format!(
                        "const key{index} = 'sb_secret_{index:04}abcdefghijklmnopqrstuvwxyzABCDEF';\n"
                    )
                } else {
                    format!(
                        "const stripe{index} = 'sk_live_abcdefghijklmnopqrstuvwxyz{index:06}';\n"
                    )
                };
                working_tree_unit(format!("src/file-{index}.ts"), content)
            })
            .collect::<Vec<_>>();

        let serial = candidate_snapshot(detector.detect_units_serial(&units));
        let parallel = candidate_snapshot(detector.detect_units(&units));

        assert_eq!(parallel, serial);
    }

    #[test]
    fn reports_one_based_spans() {
        let findings = detect("const key = 'sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890';");
        let anthropic = findings
            .iter()
            .find(|candidate| candidate.rule_id.0 == "anthropic-api-key")
            .expect("anthropic key detected");

        assert_eq!(anthropic.span.line, 1);
        assert!(anthropic.span.col_start > 1);
        assert!(anthropic.span.col_end > anthropic.span.col_start);
    }

    fn candidate_snapshot(mut candidates: Vec<SecretCandidate>) -> Vec<String> {
        candidates.sort_by(|left, right| {
            left.unit_ref
                .locations
                .cmp(&right.unit_ref.locations)
                .then_with(|| left.span.line.cmp(&right.span.line))
                .then_with(|| left.span.col_start.cmp(&right.span.col_start))
                .then_with(|| left.rule_id.cmp(&right.rule_id))
                .then_with(|| left.raw_match.cmp(&right.raw_match))
        });
        candidates
            .into_iter()
            .map(|candidate| {
                format!(
                    "{}:{}:{}:{}:{}",
                    candidate.unit_ref.locations[0].path.0,
                    candidate.span.line,
                    candidate.span.col_start,
                    candidate.rule_id.0,
                    String::from_utf8_lossy(&candidate.raw_match)
                )
            })
            .collect()
    }
}
