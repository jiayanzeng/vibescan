use super::*;

pub(super) const INLINE_ALLOW_MARKER: &str = "vibescan:allow";
pub(super) const MINIFIED_GENERIC_LINE_THRESHOLD: usize = 500;

/// Embedded default ruleset. The generic corpus is intentionally conservative
/// in v1; deeper breadth can come from configured rules without changing the
/// Supabase moat.
pub const DEFAULT_RULESET_TOML: &str = include_str!("rules/default-rules.toml");

/// Detection engine ready to scan `ScannableUnit`s.
#[derive(Debug)]
pub struct Detector {
    pub(super) rules: Vec<CompiledRule>,
    pub(super) global_allowlists: Vec<CompiledAllowlist>,
}

impl Detector {
    /// Build a detector from the embedded default ruleset.
    pub fn default_rules() -> Result<Self, DetectorError> {
        RulesetConfig::from_toml(DEFAULT_RULESET_TOML)?.compile()
    }

    /// Build a detector by retaining the embedded ruleset and appending a
    /// custom ruleset. Duplicate rule IDs are rejected rather than overridden.
    pub fn default_rules_with_custom_toml(input: &str) -> Result<Self, DetectorError> {
        RulesetConfig::from_toml(DEFAULT_RULESET_TOML)?
            .merge(RulesetConfig::from_toml(input)?)?
            .compile()
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
    pub(super) fn detect_units_serial<'a>(
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
pub(super) struct CompiledRule {
    pub(super) id: String,
    pub(super) kind: CandidateKind,
    pub(super) regex: Regex,
    pub(super) secret_group: usize,
    pub(super) keywords: Vec<String>,
    pub(super) entropy: Option<f64>,
    pub(super) path_allowlist: Vec<Regex>,
    pub(super) allowlists: Vec<CompiledAllowlist>,
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
pub(super) struct AllowlistContext<'a> {
    path: &'a str,
    secret: &'a str,
    line: &'a str,
    provenance: &'a Provenance,
    additional_provenance: &'a [Provenance],
}

#[derive(Debug)]
pub(super) struct CompiledAllowlist {
    pub(super) paths: Vec<Regex>,
    pub(super) regexes: Vec<Regex>,
    pub(super) commits: BTreeSet<String>,
    pub(super) stopwords: BTreeSet<String>,
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
