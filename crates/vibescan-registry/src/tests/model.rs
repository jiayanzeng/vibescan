use super::*;

#[test]
fn warning_messages_disclose_only_public_host_and_ecosystem() {
    assert_eq!(
        RegistryWarning::RegistryUnavailable {
            host: "registry.npmjs.org".to_owned()
        }
        .message(),
        "package registry unavailable at registry.npmjs.org"
    );
    assert!(
        RegistryWarning::OsvSnapshotUnavailable {
            ecosystem: Ecosystem::PyPi
        }
        .message()
        .contains("PyPi")
    );
}
