use super::*;

#[test]
fn baseline_suppresses_existing_findings() {
    let repo = TestRepo::new();
    repo.git(["init"]);
    repo.write(
        "src/app.ts",
        "const stripe = 'sk_live_abcdefghijklmnopqrstuvwxyz123456';\n",
    );

    let first = scan(
        repo.path(),
        ScanConfig {
            include_history: false,
            ..ScanConfig::default()
        },
    )
    .expect("first scan succeeds");
    let ids = first
        .findings
        .iter()
        .map(|finding| finding.id.0.clone())
        .collect::<Vec<_>>();
    repo.write(
        "baseline.json",
        &serde_json::to_string(&ids).expect("ids serialize"),
    );

    let second = scan(
        repo.path(),
        ScanConfig {
            include_history: false,
            baseline_path: Some(repo.path().join("baseline.json")),
            ..ScanConfig::default()
        },
    )
    .expect("second scan succeeds");

    assert!(second.findings.is_empty());
}
