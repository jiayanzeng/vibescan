use super::*;

#[cfg(feature = "network")]
#[test]
fn production_catalog_queries_are_select_only() {
    for query in [
        TABLE_RLS_QUERY.to_owned(),
        policies_query("public.profiles"),
        grants_query("public.profiles"),
    ] {
        assert!(catalog_query_is_read_only(&query), "unsafe query: {query}");
    }
    assert!(!catalog_query_is_read_only("SET ROLE postgres"));
    assert!(!catalog_query_is_read_only("DELETE FROM profiles"));
}
