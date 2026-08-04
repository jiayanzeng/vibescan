use super::*;

#[test]
fn sarif_render_contains_results_and_locations() {
    let mut result = sample_result();
    result.scope.network.actions.push(sample_network_action());
    let rendered = render_sarif(&result).expect("sarif renders");
    let value: Value = serde_json::from_str(&rendered).expect("sarif parses");

    assert_eq!(value["version"], "2.1.0");
    assert_eq!(value["runs"][0]["results"][0]["ruleId"], "finding-1");
    assert_eq!(
        value["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        "src/app.tsx"
    );
    assert_eq!(
        value["runs"][0]["invocations"][0]["properties"]["networkActions"][0]["outcome"],
        "protected"
    );
    assert_eq!(
        value["runs"][0]["invocations"][0]["properties"]["scanStats"]["dedupRatioPercent"],
        "25.00"
    );
}
