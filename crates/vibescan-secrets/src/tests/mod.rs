use super::*;

fn detect(content: &str) -> Vec<SecretCandidate> {
    let detector = Detector::default_rules().expect("default rules compile");
    let unit = working_tree_unit("src/app.tsx", content.as_bytes().to_vec());
    detector.detect_unit(&unit)
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

#[path = "config.rs"]
mod config_tests;

#[path = "detector.rs"]
mod detector_tests;
