use super::*;

/// Detector construction error.
#[derive(Debug)]
pub enum DetectorError {
    Regex {
        pattern: String,
        source: regex::Error,
    },
    DuplicateRuleId(String),
    Toml(toml::de::Error),
}

impl fmt::Display for DetectorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Regex { pattern, source } => {
                write!(formatter, "invalid regex pattern {pattern:?}: {source}")
            }
            Self::DuplicateRuleId(rule_id) => {
                write!(formatter, "duplicate detector rule id: {rule_id}")
            }
            Self::Toml(source) => write!(formatter, "invalid ruleset TOML: {source}"),
        }
    }
}

impl std::error::Error for DetectorError {}
