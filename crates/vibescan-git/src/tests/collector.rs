use super::*;

#[test]
fn content_dedup_retains_distinct_source_paths_and_classes() {
    let content = b"same bytes".to_vec();
    let id = content_id(&content);
    let mut collector = UnitCollector::new();
    collector.push(test_unit(
        id.clone(),
        content.clone(),
        "apps/api/.env.local",
        LocationClass::ServerOnly,
        Provenance::WorkingTree,
    ));
    collector.push(test_unit(
        id,
        content,
        "apps/web/.next/static/chunks/config.js",
        LocationClass::ClientReachable,
        Provenance::WorkingTree,
    ));

    let stats = collector.stats();
    let units = collector.into_units();

    assert_eq!(stats.unique_contents, 1);
    assert_eq!(stats.units_materialized, 1);
    assert_eq!(units.len(), 1);
    assert_eq!(
        units[0]
            .locations
            .iter()
            .map(|location| (location.path.0.clone(), location.location_class))
            .collect::<Vec<_>>(),
        vec![
            ("apps/api/.env.local".to_owned(), LocationClass::ServerOnly),
            (
                "apps/web/.next/static/chunks/config.js".to_owned(),
                LocationClass::ClientReachable
            )
        ]
    );
}
