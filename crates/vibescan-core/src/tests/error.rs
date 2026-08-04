use super::*;

#[test]
fn json_error_message_is_not_baseline_specific() {
    let error = serde_json::from_str::<serde_json::Value>("{")
        .map_err(CoreError::Json)
        .expect_err("invalid JSON fails");

    assert!(error.to_string().starts_with("JSON parse failed:"));
    assert!(!error.to_string().contains("baseline"));
}
