use super::*;

#[derive(Debug)]
pub enum GitWalkError {
    Discover {
        target: PathBuf,
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    GixDecode {
        operation: &'static str,
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    GixObject {
        operation: &'static str,
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    Glob(globset::Error),
    Hash {
        operation: &'static str,
        source: gix_hash::decode::Error,
    },
    Ignore(ignore::Error),
    Io(io::Error),
    Override(ignore::Error),
    Path {
        path: PathBuf,
        source: std::path::StripPrefixError,
    },
}

impl fmt::Display for GitWalkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Discover { target, source } => {
                write!(
                    formatter,
                    "failed to discover git repo at {}: {source}",
                    target.display()
                )
            }
            Self::GixDecode { operation, source } => {
                write!(
                    formatter,
                    "git object decode failed during {operation}: {source}"
                )
            }
            Self::GixObject { operation, source } => {
                write!(
                    formatter,
                    "git object-store operation failed during {operation}: {source}"
                )
            }
            Self::Glob(source) => write!(formatter, "glob setup failed: {source}"),
            Self::Hash { operation, source } => {
                write!(
                    formatter,
                    "git object id parse failed during {operation}: {source}"
                )
            }
            Self::Ignore(source) => write!(formatter, "ignore traversal failed: {source}"),
            Self::Io(source) => write!(formatter, "filesystem traversal failed: {source}"),
            Self::Override(source) => write!(formatter, "ignore override setup failed: {source}"),
            Self::Path { path, source } => {
                write!(
                    formatter,
                    "failed to relativize {}: {source}",
                    path.display()
                )
            }
        }
    }
}

impl std::error::Error for GitWalkError {}
