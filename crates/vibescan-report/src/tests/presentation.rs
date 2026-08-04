use super::*;

#[test]
fn tty_render_is_human_readable() {
    let mut result = sample_result();
    result.scope.network.actions.push(sample_network_action());
    let output = render_tty(&result, TtyStyle::Plain);

    assert!(output.contains("[critical] Supabase secret key exposed"));
    assert!(output.contains("remediation: Rotate it."));
    assert!(output.contains("GET table read for table profiles"));
    assert!(output.contains("-> protected; HTTP 403"));
    assert!(output.contains("dedup 25.00%"));
}

#[test]
fn tty_render_surfaces_all_locations_and_history_range() {
    let mut result = sample_result();
    result.findings[0].locations.push(Location {
        path: RepoPath("src/other.ts".to_owned()),
        span: None,
        provenance: Provenance::Commit {
            sha: "1111111111111111111111111111111111111111".to_owned(),
            author: None,
            date: Some("10 +0000".to_owned()),
        },
        additional_provenance: vec![Provenance::Commit {
            sha: "2222222222222222222222222222222222222222".to_owned(),
            author: None,
            date: Some("20 +0000".to_owned()),
        }],
        location_class: LocationClass::ServerOnly,
    });

    let output = render_tty(&result, TtyStyle::Plain);

    assert!(output.contains("src/app.tsx"));
    assert!(output.contains("src/other.ts"));
    assert!(output.contains("first seen commit 111111111111; last seen commit 222222222222"));
}
