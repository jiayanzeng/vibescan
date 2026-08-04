use super::*;

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

pub(super) fn byte_to_one_based_col(line: &str, byte_index: usize) -> u32 {
    line[..byte_index].chars().count() as u32 + 1
}

pub(super) fn normalize_keywords(keywords: Vec<String>) -> Vec<String> {
    keywords
        .into_iter()
        .map(|keyword| keyword.to_ascii_lowercase())
        .collect()
}

pub(super) fn compile_regexes(patterns: Vec<String>) -> Result<Vec<Regex>, DetectorError> {
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
