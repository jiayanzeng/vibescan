use super::*;
use crate::correlation::{ApiReferenceKind, associate_api_references, harvest_api_references};

#[test]
fn offline_pipeline_finds_supabase_and_generic_secrets() {
    let repo = TestRepo::new();
    repo.git(["init"]);
    repo.write(
        "src/app.tsx",
        "const supabase = 'sb_secret_0123456789abcdefghijklmnopqrstuvwxyzABCDEF';\n",
    );
    repo.write(
        "server/stripe.ts",
        "const stripe = 'sk_live_abcdefghijklmnopqrstuvwxyz123456';\n",
    );

    let result = scan(
        repo.path(),
        ScanConfig {
            include_history: false,
            ..ScanConfig::default()
        },
    )
    .expect("scan succeeds");

    assert!(
        result
            .findings
            .iter()
            .any(|finding| finding.category == Category::SecretExposure)
    );
    assert!(!result.scope.network.enabled);
}

#[test]
fn scan_stats_carries_history_truncation() {
    let repo = TestRepo::new();
    repo.git(["init"]);
    repo.git(["config", "user.email", "a@example.com"]);
    repo.git(["config", "user.name", "A"]);
    repo.write("src/app.ts", "export const version = 1;\n");
    repo.git(["add", "."]);
    repo.git(["commit", "-m", "one"]);
    repo.write("src/app.ts", "export const version = 2;\n");
    repo.git(["add", "."]);
    repo.git(["commit", "-m", "two"]);

    let result = scan(
        repo.path(),
        ScanConfig {
            include_working_tree: false,
            max_commits: Some(1),
            ..ScanConfig::default()
        },
    )
    .expect("budgeted scan succeeds");

    assert!(result.stats.truncated);
    assert!(result.stats.scan_budget_hit);
    assert!(matches!(
        result.scope.history,
        HistoryScope::Budgeted {
            scanned_commits: 1,
            truncated: true,
            ..
        }
    ));
}

#[test]
fn collected_working_tree_units_feed_the_detector() {
    let repo = TestRepo::new();
    repo.git(["init"]);
    repo.write(
        "src/app.tsx",
        "const key = 'sb_publishable_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789';\n",
    );

    let output = collect_repository(
        repo.path(),
        WalkOptions {
            include_history: false,
            ..WalkOptions::default()
        },
    )
    .expect("repo collected");
    let detector = Detector::default_rules().expect("detector compiles");
    let candidates = detector.detect_units(&output.units);

    assert_eq!(output.units.len(), 1);
    assert!(
        candidates
            .iter()
            .any(|candidate| candidate.rule_id.0 == "supabase-publishable-key")
    );
}

#[test]
fn vibescanignore_suppresses_matching_paths() {
    let repo = TestRepo::new();
    repo.git(["init"]);
    repo.write(".vibescanignore", "ignored.ts\n");
    repo.write(
        "ignored.ts",
        "const key = 'sb_secret_0123456789abcdefghijklmnopqrstuvwxyzABCDEF';\n",
    );

    let config = ScanConfig::load(repo.path()).expect("config loads");
    let result = scan(repo.path(), config).expect("scan succeeds");

    assert!(result.findings.is_empty());
}

#[test]
fn gitignore_suppresses_matching_paths() {
    let repo = TestRepo::new();
    repo.git(["init"]);
    repo.write(".gitignore", "ignored.ts\n");
    repo.write(
        "ignored.ts",
        "const key = 'sb_secret_0123456789abcdefghijklmnopqrstuvwxyzABCDEF';\n",
    );

    let config = ScanConfig::load(repo.path()).expect("config loads");
    let result = scan(repo.path(), config).expect("scan succeeds");

    assert!(result.findings.is_empty());
}

#[test]
fn gitignored_env_secret_is_still_reported() {
    let repo = TestRepo::new();
    repo.git(["init"]);
    repo.write(".gitignore", ".env\n");
    repo.write(
        ".env",
        "SUPABASE_SERVICE_ROLE_KEY=sb_secret_0123456789abcdefghijklmnopqrstuvwxyzABCDEF\n",
    );

    let result = scan(
        repo.path(),
        ScanConfig {
            include_history: false,
            ..ScanConfig::default()
        },
    )
    .expect("scan succeeds");

    assert!(result.findings.iter().any(|finding| {
        finding.category == Category::SecretExposure
            && matches!(finding.severity, Severity::Critical | Severity::High)
            && finding
                .locations
                .iter()
                .any(|location| location.path.0 == ".env")
    }));
}

#[test]
fn scan_associates_new_publishable_key_with_colocated_project_url() {
    let repo = TestRepo::new();
    repo.git(["init"]);
    repo.write(
        "src/app.tsx",
        "const url = 'https://abcdefghijklmnopqrst.supabase.co';\nconst key = 'sb_publishable_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789';\n",
    );

    let result = scan(
        repo.path(),
        ScanConfig {
            include_history: false,
            ..ScanConfig::default()
        },
    )
    .expect("scan succeeds");

    assert!(result.findings.iter().any(|finding| {
        matches!(
            &finding.evidence,
            Evidence::SupabaseKey {
                class: SupabaseKeyClass::PublishableNew,
                project: Some(project),
                ..
            } if project.url == "https://abcdefghijklmnopqrst.supabase.co"
                && project.ref_id.as_deref() == Some("abcdefghijklmnopqrst")
        )
    }));
}

#[cfg(feature = "network")]
#[test]
fn tier1_credential_location_is_the_env_source() {
    let location = tier1_credential_location();

    assert_eq!(
        location.path,
        RepoPath("<environment:VIBESCAN_SUPABASE_DB_URL>".to_owned())
    );
    assert_eq!(location.provenance, Provenance::WorkingTree);
    assert_eq!(location.location_class, LocationClass::ServerOnly);
}

#[cfg(feature = "network")]
#[test]
fn tier0_probe_inputs_dedup_same_project_and_prefer_client_location() {
    let server_candidate = publishable_candidate("apps/web/.env.local", LocationClass::ServerOnly);
    let client_candidate = publishable_candidate(
        "apps/web/.next/static/chunks/x.js",
        LocationClass::ClientReachable,
    );
    let mut server_finding = public_key_finding_at(
        "server-key",
        "apps/web/.env.local",
        LocationClass::ServerOnly,
    );
    let mut client_finding = public_key_finding_at(
        "client-key",
        "apps/web/.next/static/chunks/x.js",
        LocationClass::ClientReachable,
    );
    if let Evidence::SupabaseKey {
        project: Some(project),
        ..
    } = &mut server_finding.evidence
    {
        project.url = "https://ABCDEFGHIJKLMNOPQRST.supabase.co/".to_owned();
    }
    if let Evidence::SupabaseKey {
        project: Some(project),
        ..
    } = &mut client_finding.evidence
    {
        project.url = "https://abcdefghijklmnopqrst.supabase.co".to_owned();
    }
    let classifications = coalesce_classified_key_facts(vec![
        classified_key_fact(&server_candidate, server_finding),
        classified_key_fact(&client_candidate, client_finding),
    ]);
    let candidate_tables = BTreeSet::from(["profiles".to_owned()]);
    let tables_by_project = BTreeMap::from([(
        "https://abcdefghijklmnopqrst.supabase.co".to_owned(),
        candidate_tables.clone(),
    )]);

    let inputs = tier0_probe_inputs(&classifications, &tables_by_project);

    assert_eq!(inputs.len(), 1);
    assert_eq!(
        inputs[0].key_location.path.0,
        "apps/web/.next/static/chunks/x.js"
    );
    assert_eq!(
        inputs[0].key_location.location_class,
        LocationClass::ClientReachable
    );
    assert_eq!(inputs[0].candidate_tables, candidate_tables);
}

#[cfg(feature = "network")]
#[test]
fn tier0_probe_inputs_keep_harvested_tables_project_local() {
    let mut candidate_a = publishable_candidate(
        "apps/a/.next/static/chunks/a.js",
        LocationClass::ClientReachable,
    );
    candidate_a.unit_ref.content_id = ContentId([10; 32]);
    let mut candidate_b = publishable_candidate(
        "apps/b/.next/static/chunks/b.js",
        LocationClass::ClientReachable,
    );
    candidate_b.unit_ref.content_id = ContentId([11; 32]);
    let finding_a = public_key_finding_at(
        "key-a",
        "apps/a/.next/static/chunks/a.js",
        LocationClass::ClientReachable,
    );
    let mut finding_b = public_key_finding_at(
        "key-b",
        "apps/b/.next/static/chunks/b.js",
        LocationClass::ClientReachable,
    );
    if let Evidence::SupabaseKey {
        project: Some(project),
        ..
    } = &mut finding_b.evidence
    {
        project.ref_id = Some("zyxwvutsrqponmlkjihg".to_owned());
        project.url = "https://zyxwvutsrqponmlkjihg.supabase.co".to_owned();
    }
    let classifications = coalesce_classified_key_facts(vec![
        classified_key_fact(&candidate_a, finding_a),
        classified_key_fact(&candidate_b, finding_b),
    ]);
    let units = vec![
        api_unit(
            ContentId([10; 32]),
            "apps/a/src/data.ts",
            "supabase.from('accounts_a').select('*');",
        ),
        api_unit(
            ContentId([11; 32]),
            "apps/b/src/data.ts",
            "supabase.from('accounts_b').select('*');",
        ),
    ];
    let references = harvest_api_references(&units);
    let associations = associate_api_references(&references, &classifications);

    let inputs = tier0_probe_inputs(&classifications, &associations.tables_by_project);
    let tables_by_project = inputs
        .into_iter()
        .map(|input| (input.project.url, input.candidate_tables))
        .collect::<BTreeMap<_, _>>();

    assert_eq!(
        tables_by_project["https://abcdefghijklmnopqrst.supabase.co"],
        BTreeSet::from(["accounts_a".to_owned()])
    );
    assert_eq!(
        tables_by_project["https://zyxwvutsrqponmlkjihg.supabase.co"],
        BTreeSet::from(["accounts_b".to_owned()])
    );
    assert!(associations.warnings.is_empty());
}

#[cfg(feature = "network")]
#[test]
fn tier0_probe_inputs_do_not_cross_probe_ambiguous_harvested_table() {
    let mut candidate_a = publishable_candidate("src/a-key.ts", LocationClass::ClientReachable);
    candidate_a.unit_ref.content_id = ContentId([20; 32]);
    let mut candidate_b = publishable_candidate("src/b-key.ts", LocationClass::ClientReachable);
    candidate_b.unit_ref.content_id = ContentId([21; 32]);
    let finding_a = public_key_finding_at("key-a", "src/a-key.ts", LocationClass::ClientReachable);
    let mut finding_b =
        public_key_finding_at("key-b", "src/b-key.ts", LocationClass::ClientReachable);
    if let Evidence::SupabaseKey {
        project: Some(project),
        ..
    } = &mut finding_b.evidence
    {
        project.ref_id = Some("zyxwvutsrqponmlkjihg".to_owned());
        project.url = "https://zyxwvutsrqponmlkjihg.supabase.co".to_owned();
    }
    let classifications = coalesce_classified_key_facts(vec![
        classified_key_fact(&candidate_a, finding_a),
        classified_key_fact(&candidate_b, finding_b),
    ]);
    let references = harvest_api_references(&[api_unit(
        ContentId([22; 32]),
        "src/shared.ts",
        "supabase.from('shared_profiles').select('*');",
    )]);
    let associations = associate_api_references(&references, &classifications);

    let inputs = tier0_probe_inputs(&classifications, &associations.tables_by_project);

    assert!(
        inputs.iter().all(|input| input.candidate_tables.is_empty()),
        "an ambiguously associated table must not be sent to either project"
    );
    assert!(associations.warnings.iter().any(|warning| matches!(
        warning,
        ScopeWarning::Other { message }
            if message.contains("shared_profiles")
                && message.contains("ambiguous Supabase project association")
    )));
}

#[test]
fn harvest_api_references_retains_table_and_rpc_kinds() {
    let units = vec![ScannableUnit {
        content_id: ContentId([2; 32]),
        content: br#"
            const profiles = supabase.from('profiles').select('*');
            await client.from("orders").select("id");
            await supabase.rpc('do_x');
            fetch("/rest/v1/widgets?select=*");
        "#
        .to_vec(),
        locations: vec![UnitLocation {
            path: RepoPath("apps/web/.next/static/chunks/x.js".to_owned()),
            provenance: Provenance::WorkingTree,
            additional_provenance: Vec::new(),
            location_class: LocationClass::ClientReachable,
        }],
    }];

    let references = harvest_api_references(&units)
        .into_iter()
        .map(|reference| (reference.kind, reference.name, reference.source_scope.0))
        .collect::<Vec<_>>();

    assert_eq!(
        references,
        vec![
            (
                ApiReferenceKind::Table,
                "orders".to_owned(),
                "apps/web".to_owned()
            ),
            (
                ApiReferenceKind::Table,
                "profiles".to_owned(),
                "apps/web".to_owned()
            ),
            (
                ApiReferenceKind::Table,
                "widgets".to_owned(),
                "apps/web".to_owned()
            ),
            (
                ApiReferenceKind::Rpc,
                "do_x".to_owned(),
                "apps/web".to_owned()
            ),
        ]
    );
}

#[test]
fn rpc_references_remain_typed_and_never_become_table_candidates() {
    let content_id = ContentId([30; 32]);
    let facts = vec![classified_fact_for_source(
        content_id.clone(),
        "apps/web/src/config.ts",
        project(),
    )];
    let references = harvest_api_references(&[api_unit(
        content_id,
        "apps/web/src/data.ts",
        "supabase.from('profiles').select('*'); supabase.rpc('do_x');",
    )]);

    let associations = associate_api_references(&references, &facts);

    assert_eq!(
        associations.tables_by_project,
        BTreeMap::from([(
            "https://abcdefghijklmnopqrst.supabase.co".to_owned(),
            BTreeSet::from(["profiles".to_owned()]),
        )])
    );
    assert!(associations.warnings.is_empty());
    assert!(
        references.iter().any(|reference| {
            reference.kind == ApiReferenceKind::Rpc && reference.name == "do_x"
        })
    );
}

#[test]
fn historical_api_references_use_exact_content_project_context() {
    let project_a = project();
    let project_b = SupabaseProject {
        ref_id: Some("zyxwvutsrqponmlkjihg".to_owned()),
        url: "https://zyxwvutsrqponmlkjihg.supabase.co".to_owned(),
    };
    let facts = vec![
        classified_fact_for_source(ContentId([31; 32]), "src/config.ts", project_a.clone()),
        classified_fact_for_source(ContentId([32; 32]), "src/config.ts", project_b.clone()),
    ];
    let references = harvest_api_references(&[
        api_unit(
            ContentId([31; 32]),
            "src/config.ts",
            "supabase.from('accounts_a').select('*');",
        ),
        api_unit(
            ContentId([32; 32]),
            "src/config.ts",
            "supabase.from('accounts_b').select('*');",
        ),
    ]);

    let associations = associate_api_references(&references, &facts);

    assert_eq!(
        associations.tables_by_project[&normalized_project_url(&project_a.url)],
        BTreeSet::from(["accounts_a".to_owned()])
    );
    assert_eq!(
        associations.tables_by_project[&normalized_project_url(&project_b.url)],
        BTreeSet::from(["accounts_b".to_owned()])
    );
    assert!(associations.warnings.is_empty());
}

#[test]
fn unassociated_table_reference_emits_coverage_warning() {
    let references = harvest_api_references(&[api_unit(
        ContentId([33; 32]),
        "shared/data.ts",
        "supabase.from('orphaned_table').select('*');",
    )]);

    let associations = associate_api_references(&references, &[]);

    assert!(associations.tables_by_project.is_empty());
    assert!(matches!(
        associations.warnings.as_slice(),
        [ScopeWarning::Other { message }]
            if message.contains("orphaned_table")
                && message.contains("no associated Supabase project")
    ));
}

#[test]
fn clean_control_fixture_produces_zero_findings() {
    let repo = TestRepo::new();
    repo.git(["init"]);
    repo.write(
        "package.json",
        r#"{"dependencies":{"@supabase/supabase-js":"2.0.0","next":"15.0.0"}}"#,
    );
    repo.write(
        "src/app/page.tsx",
        "export default function Page() { return <main>clean</main>; }\n",
    );
    repo.write(
        "supabase/functions/ping/index.ts",
        "Deno.serve(() => new Response('ok'));\n",
    );

    let result = scan(
        repo.path(),
        ScanConfig {
            include_history: false,
            severity_gate: Severity::Info,
            ..ScanConfig::default()
        },
    )
    .expect("scan succeeds");

    assert_eq!(result.findings, Vec::new());
}

#[test]
fn elevated_key_committed_then_removed_fixture_is_history_only_critical() {
    let repo = TestRepo::new();
    repo.git(["init"]);
    repo.git(["config", "user.email", "vibescan@example.invalid"]);
    repo.git(["config", "user.name", "vibescan test"]);
    repo.write(
        "src/history.ts",
        "export const key = 'sb_secret_0123456789abcdefghijklmnopqrstuvwxyzABCDEF';\n",
    );
    repo.git(["add", "src/history.ts"]);
    repo.git(["commit", "-m", "add historical secret"]);
    repo.write("src/history.ts", "export const ok = true;\n");
    repo.git(["add", "src/history.ts"]);
    repo.git(["commit", "-m", "remove historical secret"]);

    let result = scan(repo.path(), ScanConfig::default()).expect("scan succeeds");
    let findings = result
        .findings
        .iter()
        .filter(|finding| {
            matches!(
                finding.evidence,
                Evidence::SupabaseKey {
                    class: SupabaseKeyClass::SecretNew,
                    ..
                }
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].category, Category::SecretExposure);
    assert_eq!(findings[0].severity, Severity::Critical);
    assert!(findings[0].locations.iter().any(|location| {
        location.path.0 == "src/history.ts"
            && matches!(location.provenance, Provenance::Commit { .. })
    }));
}

#[test]
fn gitignored_env_fixture_has_exact_elevated_key_finding() {
    let repo = TestRepo::new();
    repo.git(["init"]);
    repo.write(".gitignore", ".env\n");
    repo.write(
        ".env",
        "SUPABASE_SERVICE_ROLE_KEY=sb_secret_0123456789abcdefghijklmnopqrstuvwxyzABCDEF\n",
    );

    let result = scan(
        repo.path(),
        ScanConfig {
            include_history: false,
            ..ScanConfig::default()
        },
    )
    .expect("scan succeeds");
    let findings = result
        .findings
        .iter()
        .filter(|finding| {
            finding
                .locations
                .iter()
                .any(|location| location.path.0 == ".env")
        })
        .collect::<Vec<_>>();

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].category, Category::SecretExposure);
    assert_eq!(findings[0].severity, Severity::Critical);
    assert!(matches!(
        findings[0].evidence,
        Evidence::SupabaseKey {
            class: SupabaseKeyClass::SecretNew,
            ..
        }
    ));
}

#[test]
fn next_build_tree_fixture_is_clean_after_ignore_overrides() {
    let repo = TestRepo::new();
    repo.git(["init"]);
    repo.write(".gitignore", ".next/\n");
    repo.write(
        "dashboard/.next/server/vendor-chunks/prop-types.js",
        "var x='abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ';\n",
    );
    repo.write(
        "dashboard/.next/static/chunks/app.js",
        "self.__next_f.push(['clean static bundle']);\n",
    );

    let result = scan(
        repo.path(),
        ScanConfig {
            include_history: false,
            severity_gate: Severity::Info,
            ..ScanConfig::default()
        },
    )
    .expect("scan succeeds");

    assert_eq!(result.findings, Vec::new());
}

#[test]
fn scan_result_started_at_is_rfc3339_timestamp() {
    let repo = TestRepo::new();
    repo.git(["init"]);

    let result = scan(
        repo.path(),
        ScanConfig {
            include_history: false,
            ..ScanConfig::default()
        },
    )
    .expect("scan succeeds");

    assert!(result.started_at.parse::<Timestamp>().is_ok());
    assert_ne!(result.started_at, "local-static");
}

#[test]
fn localstatic_dependency_boundary_excludes_network_crates() {
    if cfg!(feature = "network") || cfg!(feature = "registry") {
        return;
    }

    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let rustc = Command::new("rustc")
        .arg("-vV")
        .output()
        .expect("rustc version query runs");
    assert!(
        rustc.status.success(),
        "rustc -vV failed: {}",
        String::from_utf8_lossy(&rustc.stderr)
    );
    let rustc_stdout = String::from_utf8(rustc.stdout).expect("rustc output is UTF-8");
    let host = rustc_stdout
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .expect("rustc reports host triple");
    let output = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned()))
        .args([
            "metadata",
            "--format-version",
            "1",
            "--locked",
            "--offline",
            "--filter-platform",
            host,
        ])
        .current_dir(workspace_root)
        .output()
        .expect("cargo metadata runs");
    assert!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let metadata: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("metadata JSON parses");
    let packages = metadata["packages"]
        .as_array()
        .expect("metadata contains packages");
    let mut names_by_id = BTreeMap::new();
    let mut ids_by_name = BTreeMap::new();
    for package in packages {
        let id = package["id"].as_str().expect("package id").to_owned();
        let name = package["name"].as_str().expect("package name").to_owned();
        names_by_id.insert(id.clone(), name.clone());
        ids_by_name.entry(name).or_insert(id);
    }

    let mut normal_edges = BTreeMap::<String, Vec<String>>::new();
    for node in metadata["resolve"]["nodes"]
        .as_array()
        .expect("metadata contains resolve nodes")
    {
        let id = node["id"].as_str().expect("node id").to_owned();
        let mut deps = Vec::new();
        for dep in node["deps"].as_array().expect("node deps") {
            if dep["dep_kinds"]
                .as_array()
                .expect("dependency kinds")
                .iter()
                .any(|kind| kind["kind"].is_null() || kind["kind"] == "normal")
            {
                deps.push(dep["pkg"].as_str().expect("dep package id").to_owned());
            }
        }
        normal_edges.insert(id, deps);
    }

    let localstatic_crates = [
        "vibescan-types",
        "vibescan-git",
        "vibescan-secrets",
        "vibescan-supabase",
        "vibescan-report",
        "vibescan-core",
    ];
    let denied = BTreeSet::from([
        "reqwest",
        "hyper",
        "tokio",
        "ureq",
        "isahc",
        "curl",
        "openssl",
        "native-tls",
        "rustls",
        "gix-protocol",
        "gix-transport",
        "gix-transport-http",
        "gix-transport-http-client",
    ]);

    let mut violations = Vec::new();
    for crate_name in localstatic_crates {
        let root_id = ids_by_name.get(crate_name).expect("local crate present");
        let mut seen = BTreeSet::new();
        let mut stack = vec![root_id.clone()];
        while let Some(id) = stack.pop() {
            if !seen.insert(id.clone()) {
                continue;
            }
            let name = names_by_id.get(&id).expect("package name");
            if denied.contains(name.as_str()) {
                violations.push(format!("{crate_name} reaches {name}"));
            }
            if let Some(deps) = normal_edges.get(&id) {
                stack.extend(deps.iter().cloned());
            }
        }
    }

    assert!(
        violations.is_empty(),
        "LocalStatic network boundary violated: {}",
        violations.join(", ")
    );
}
