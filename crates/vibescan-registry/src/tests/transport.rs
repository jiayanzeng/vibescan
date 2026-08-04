use super::*;

#[cfg(feature = "transport")]
#[test]
fn production_source_constructs_without_opening_a_connection() {
    let _source = ReqwestRegistrySource::new().expect("rustls client constructs");
}
