use super::*;

#[test]
fn json_render_is_valid_and_redacted() {
    let mut result = sample_result();
    result.scope.network.actions.push(sample_network_action());
    let rendered = render_json(&result).expect("json renders");
    let value: Value = serde_json::from_str(&rendered).expect("json parses");

    assert_eq!(
        value["findings"][0]["evidence"]["redacted"],
        "sb_sec...CDEF"
    );
    assert!(!rendered.contains("full-secret"));
    assert_eq!(
        value["scope"]["network"]["actions"][0]["outcome"],
        "protected"
    );
    assert!(!rendered.contains("public-key"));
}

#[test]
fn html_render_escapes_content() {
    let mut result = sample_result();
    result.findings[0].title = "<script>alert(1)</script>".to_owned();
    let mut action = sample_network_action();
    action.table = Some("<private>".to_owned());
    result.scope.network.actions.push(action);
    let output = render_html(&result);

    assert!(output.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    assert!(!output.contains("<script>alert(1)</script>"));
    assert!(output.contains("Network actions"));
    assert!(output.contains("&lt;private&gt;"));
    assert!(output.contains("dedup: 25.00%"));
}

#[test]
fn exit_code_uses_severity_gate() {
    let result = sample_result();

    assert_eq!(exit_code(&result, Severity::Critical), 1);
    assert_eq!(exit_code(&result, Severity::Info), 1);
    assert_eq!(exit_code(&empty_result(), Severity::Info), 0);

    let mut only_scope_evidence = empty_result();
    only_scope_evidence
        .scope
        .network
        .actions
        .push(sample_network_action());
    assert_eq!(only_scope_evidence.stats, ScanStats::default());
    assert_eq!(exit_code(&only_scope_evidence, Severity::Info), 0);
}
