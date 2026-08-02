use super::*;

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

    pub(super) fn merge(mut self, custom: Self) -> Result<Self, DetectorError> {
        let mut rule_ids = self
            .rules
            .iter()
            .map(|rule| rule.id.clone())
            .collect::<BTreeSet<_>>();
        for rule in &custom.rules {
            if !rule_ids.insert(rule.id.clone()) {
                return Err(DetectorError::DuplicateRuleId(rule.id.clone()));
            }
        }
        self.rules.extend(custom.rules);
        self.allowlists.extend(custom.allowlists);
        Ok(self)
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

pub(super) fn default_secret_group() -> usize {
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
