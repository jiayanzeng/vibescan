use super::*;

#[test]
fn dependency_evidence_names_both_f2_reasons() {
    for (reason, expected) in [
        (
            vibescan_types::DependencyIntegrityReason::KnownMalicious,
            "KnownMalicious",
        ),
        (
            vibescan_types::DependencyIntegrityReason::NonexistentPackage,
            "NonexistentPackage",
        ),
    ] {
        let summary = evidence_summary(&Evidence::Dependency {
            package: "fixture@1.0.0".to_owned(),
            manifest_path: RepoPath("package.json".to_owned()),
            reason,
        });

        assert!(summary.contains(expected));
        assert!(summary.contains("package.json"));
    }
}
