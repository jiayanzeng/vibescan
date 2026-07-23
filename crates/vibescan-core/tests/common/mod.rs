use std::cell::RefCell;
use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use vibescan_core::correlate_findings;
#[cfg(feature = "registry")]
use vibescan_registry::{
    AdvisorySet, RegistryCheckInput, RegistryError, RegistryResolution, RegistrySource,
    run_registry_checks,
};
use vibescan_supabase::{
    GrantRow, IntrospectError, PgCatalogSource, PolicyRow, TableRls, Tier1IntrospectInput,
    introspect_tier1_with_source,
};
use vibescan_types::{
    Category, Confidence, CorrelationRuleId, Evidence, Finding, FindingId, Location, LocationClass,
    NetworkActionIntent, Provenance, RepoPath, RlsExposure, SecretFingerprint, Severity, Span,
    SupabaseKeyClass, SupabaseProject,
};
#[cfg(feature = "registry")]
use vibescan_types::{DependencyIntegrityReason, Ecosystem, ParsedDependency};

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

pub(crate) const LIVE_FIXTURES: &[LiveFixture] = &[
    LiveFixture {
        name: "clean-control",
        history: false,
    },
    LiveFixture {
        name: "history-only-elevated-key",
        history: true,
    },
    LiveFixture {
        name: "publishable-client-reachable",
        history: false,
    },
    LiveFixture {
        name: "src-api-client-wrapper",
        history: false,
    },
    LiveFixture {
        name: "vendor-chunks-noise",
        history: false,
    },
    LiveFixture {
        name: "monorepo-layout",
        history: false,
    },
    LiveFixture {
        name: "nested-gitignore",
        history: false,
    },
    LiveFixture {
        name: "malformed-dependency",
        history: false,
    },
];

// This shared module is compiled once per integration-test binary; the golden
// binary uses these helpers only in its network-feature build.
#[allow(dead_code)]
pub(crate) const TIER1_FIXTURES: &[&str] = &["rls-off-table", "permissive-using-true-policy"];

#[cfg(feature = "registry")]
pub(crate) const REGISTRY_FIXTURES: &[&str] = &["hallucinated-dependency"];

#[derive(Clone, Copy, Debug)]
pub(crate) struct LiveFixture {
    pub(crate) name: &'static str,
    pub(crate) history: bool,
}

pub(crate) fn materialize_fixture(fixture: &LiveFixture) -> PathBuf {
    if fixture.history {
        materialize_history_fixture(fixture.name)
    } else {
        materialize_working_tree_fixture(fixture.name)
    }
}

pub(crate) fn fixture_dir(name: &str) -> PathBuf {
    workspace_root().join("tests").join("fixtures").join(name)
}

pub(crate) fn offline_composite_findings() -> Vec<Finding> {
    let key = synthetic_public_key_finding();
    let rls = synthetic_rls_finding();
    let correlation = correlate_findings(&[key.clone(), rls.clone()])
        .into_iter()
        .next()
        .expect("correlation emitted");
    let mut findings = vec![key, rls, correlation];
    absorb_exposed_public_key_constituents_for_test(&mut findings);
    findings
}

#[cfg(feature = "registry")]
pub(crate) fn registry_fixture_findings(name: &str) -> Vec<Finding> {
    assert!(REGISTRY_FIXTURES.contains(&name));
    let fixture = LiveFixture {
        name: "hallucinated-dependency",
        history: false,
    };
    let repo = materialize_fixture(&fixture);
    let dependencies = vibescan_core::parse_dependencies(&repo)
        .unwrap_or_else(|error| panic!("{name} dependencies failed to parse: {error}"));
    assert_eq!(
        dependencies.len(),
        2,
        "fixture must retain its guard control"
    );

    #[derive(Default)]
    struct MockRegistry {
        resolve_calls: RefCell<Vec<String>>,
    }

    impl RegistrySource for MockRegistry {
        fn resolves(
            &self,
            dependency: &ParsedDependency,
        ) -> Result<RegistryResolution, RegistryError> {
            self.resolve_calls
                .borrow_mut()
                .push(dependency.name.clone());
            Ok(RegistryResolution {
                exists: false,
                request_made: true,
            })
        }

        fn advisories_for(&self, ecosystem: Ecosystem) -> Result<AdvisorySet, RegistryError> {
            Ok(AdvisorySet::empty(ecosystem))
        }
    }

    let source = MockRegistry::default();
    let output = run_registry_checks(
        &source,
        &RegistryCheckInput {
            dependencies,
            private_registry_ecosystems: BTreeSet::new(),
        },
    )
    .expect("mocked Registry fixture succeeds");

    assert!(output.warnings.is_empty(), "{:#?}", output.warnings);
    assert_eq!(
        source.resolve_calls.borrow().as_slice(),
        ["vibescan-certainly-hallucinated-fixture-package"],
        "the scoped 404 control must never reach the public registry"
    );
    assert_eq!(output.actions.len(), 1);
    assert_eq!(output.findings.len(), 1);
    assert_eq!(output.findings[0].severity, Severity::High);
    assert_eq!(output.findings[0].confidence, Confidence::Confirmed);
    assert!(matches!(
        output.findings[0].evidence,
        Evidence::Dependency {
            reason: DependencyIntegrityReason::NonexistentPackage,
            ..
        }
    ));
    output.findings
}

#[allow(dead_code)]
pub(crate) fn tier1_fixture_findings(name: &str) -> Vec<Finding> {
    let (catalog, expected_exposure) = match name {
        "rls-off-table" => (
            MockPgCatalog::new(
                vec![TableRls {
                    schema: "public".to_owned(),
                    table: "profiles".to_owned(),
                    rowsecurity: false,
                }],
                Vec::new(),
                Vec::new(),
            ),
            RlsExposure::RlsDisabled,
        ),
        "permissive-using-true-policy" => (
            MockPgCatalog::new(
                vec![TableRls {
                    schema: "public".to_owned(),
                    table: "profiles".to_owned(),
                    rowsecurity: true,
                }],
                vec![PolicyRow {
                    schema: "public".to_owned(),
                    table: "profiles".to_owned(),
                    policy: "public-read".to_owned(),
                    command: "SELECT".to_owned(),
                    permissive: true,
                    roles: vec!["anon".to_owned()],
                    using_expr: Some("(true)".to_owned()),
                    check_expr: None,
                }],
                Vec::new(),
            ),
            RlsExposure::PermissivePolicy,
        ),
        other => panic!("unknown Tier 1 fixture {other}"),
    };
    let key = synthetic_public_key_finding();
    let output = introspect_tier1_with_source(
        &catalog,
        &Tier1IntrospectInput {
            project: synthetic_project(),
            db_url: "postgres://postgres:fixture-only@db.abcdefghijklmnopqrst.supabase.co/postgres"
                .to_owned(),
            credential_location: Location {
                path: RepoPath("<environment:VIBESCAN_SUPABASE_DB_URL>".to_owned()),
                span: None,
                provenance: Provenance::WorkingTree,
                additional_provenance: Vec::new(),
                location_class: LocationClass::ServerOnly,
            },
            candidate_tables: BTreeSet::from(["profiles".to_owned()]),
        },
    )
    .expect("mocked Tier 1 fixture succeeds");

    assert!(output.warnings.is_empty(), "{:#?}", output.warnings);
    assert_eq!(
        catalog.calls.borrow().as_slice(),
        ["tables", "policies:profiles", "grants:profiles"]
    );
    assert_eq!(output.actions.len(), 3);
    assert!(
        output
            .actions
            .iter()
            .all(|action| action.intent == NetworkActionIntent::Select),
        "Tier 1 fixture must issue catalog reads only"
    );
    assert!(
        output
            .findings
            .iter()
            .all(|finding| matches!(&finding.evidence, Evidence::RlsPolicy { .. })),
        "Tier 1 fixture must prove correlation without a Tier 0 probe"
    );
    let matching = output
        .findings
        .iter()
        .filter(|finding| {
            matches!(
                &finding.evidence,
                Evidence::RlsPolicy { exposure, .. } if *exposure == expected_exposure
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(matching.len(), 1, "{:#?}", output.findings);
    let rls = (*matching[0]).clone();
    assert_eq!(rls.category, Category::Rls);
    assert_eq!(
        rls.severity,
        Severity::Critical,
        "Tier 1 read exposure must be Critical before correlation"
    );
    let mut constituents = vec![key.clone()];
    constituents.extend(output.findings);
    let correlations = correlate_findings(&constituents);
    let correlation = correlations
        .into_iter()
        .find(|finding| {
            matches!(
                &finding.evidence,
                Evidence::Correlation { rule_id, .. }
                    if rule_id == &CorrelationRuleId("exposed-public-key-chain".to_owned())
            )
        })
        .expect("Tier 1 read exposure correlates with the public key");
    assert_eq!(correlation.severity, Severity::Critical);
    assert_eq!(
        correlation.related.iter().cloned().collect::<BTreeSet<_>>(),
        BTreeSet::from([key.id.clone(), rls.id.clone()])
    );
    assert_eq!(
        rls.severity,
        Severity::Critical,
        "correlation must not mutate or re-derive the constituent severity"
    );

    let mut findings = vec![key];
    findings.extend(constituents.into_iter().skip(1));
    findings.push(correlation);
    absorb_exposed_public_key_constituents_for_test(&mut findings);
    assert_eq!(
        findings
            .iter()
            .filter(|finding| finding.category == Category::Correlation)
            .count(),
        1,
        "the read exposure should produce exactly one composite"
    );
    findings
}

pub(crate) fn synthetic_public_key_finding() -> Finding {
    Finding {
        id: FindingId("golden-key".to_owned()),
        category: Category::KeyClassification,
        severity: Severity::Info,
        title: "Supabase publishable key found".to_owned(),
        detail: "synthetic public key".to_owned(),
        locations: vec![Location {
            path: RepoPath("src/app/page.tsx".to_owned()),
            span: Some(Span {
                line: 2,
                col_start: 14,
                col_end: 72,
            }),
            provenance: Provenance::WorkingTree,
            additional_provenance: Vec::new(),
            location_class: LocationClass::ClientReachable,
        }],
        evidence: Evidence::SupabaseKey {
            class: SupabaseKeyClass::PublishableNew,
            redacted: "sb_pub...6789".to_owned(),
            project: Some(synthetic_project()),
            fingerprint: SecretFingerprint("golden-public-fingerprint".to_owned()),
        },
        remediation: "fix RLS if exposed".to_owned(),
        related: Vec::new(),
        confidence: Confidence::Likely,
    }
}

pub(crate) fn synthetic_rls_finding() -> Finding {
    Finding {
        id: FindingId("golden-rls".to_owned()),
        category: Category::Rls,
        severity: Severity::Critical,
        title: "Supabase table profiles is readable with the public key".to_owned(),
        detail: "synthetic RLS exposure".to_owned(),
        locations: Vec::new(),
        evidence: Evidence::RlsProbe {
            project: synthetic_project(),
            table: "profiles".to_owned(),
            endpoint: "https://abcdefghijklmnopqrst.supabase.co/rest/v1/profiles?select=*&limit=1"
                .to_owned(),
            observed_row_count: 1,
            exposure: RlsExposure::Exposed,
        },
        remediation: "tighten RLS".to_owned(),
        related: Vec::new(),
        confidence: Confidence::Confirmed,
    }
}

pub(crate) fn synthetic_project() -> SupabaseProject {
    SupabaseProject {
        ref_id: Some("abcdefghijklmnopqrst".to_owned()),
        url: "https://abcdefghijklmnopqrst.supabase.co".to_owned(),
    }
}

pub(crate) fn absorb_exposed_public_key_constituents_for_test(findings: &mut Vec<Finding>) {
    let absorbed = findings
        .iter()
        .filter_map(|finding| {
            let Evidence::Correlation { rule_id, .. } = &finding.evidence else {
                return None;
            };
            if rule_id == &CorrelationRuleId("exposed-public-key-chain".to_owned()) {
                Some(finding.related.clone())
            } else {
                None
            }
        })
        .flatten()
        .collect::<BTreeSet<_>>();

    findings.retain(|finding| {
        finding.category == Category::Correlation || !absorbed.contains(&finding.id)
    });
}

#[allow(dead_code)]
struct MockPgCatalog {
    calls: RefCell<Vec<String>>,
    tables: Vec<TableRls>,
    policies: Vec<PolicyRow>,
    grants: Vec<GrantRow>,
}

#[allow(dead_code)]
impl MockPgCatalog {
    fn new(tables: Vec<TableRls>, policies: Vec<PolicyRow>, grants: Vec<GrantRow>) -> Self {
        Self {
            calls: RefCell::new(Vec::new()),
            tables,
            policies,
            grants,
        }
    }
}

impl PgCatalogSource for MockPgCatalog {
    fn tables_with_rowsecurity(&self) -> Result<Vec<TableRls>, IntrospectError> {
        self.calls.borrow_mut().push("tables".to_owned());
        Ok(self.tables.clone())
    }

    fn policies_for(&self, table: &str) -> Result<Vec<PolicyRow>, IntrospectError> {
        self.calls.borrow_mut().push(format!("policies:{table}"));
        Ok(self.policies.clone())
    }

    fn grants_for(&self, table: &str) -> Result<Vec<GrantRow>, IntrospectError> {
        self.calls.borrow_mut().push(format!("grants:{table}"));
        Ok(self.grants.clone())
    }
}

fn materialize_working_tree_fixture(name: &str) -> PathBuf {
    let source = fixture_dir(name).join("repo");
    let destination = unique_temp_dir(name);
    copy_dir(&source, &destination);
    run_git(&destination, ["init"]);
    destination
}

fn materialize_history_fixture(name: &str) -> PathBuf {
    let destination = unique_temp_dir(name);
    let bundle = fixture_dir(name).join("history.bundle");
    let output = Command::new("git")
        .arg("clone")
        .arg(&bundle)
        .arg(&destination)
        .output()
        .unwrap_or_else(|error| panic!("git clone {} failed: {error}", bundle.display()));
    assert!(
        output.status.success(),
        "git clone {} failed\nstdout:\n{}\nstderr:\n{}",
        bundle.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    destination
}

fn copy_dir(source: &Path, destination: &Path) {
    fs::create_dir_all(destination)
        .unwrap_or_else(|error| panic!("create {}: {error}", destination.display()));
    for entry in fs::read_dir(source)
        .unwrap_or_else(|error| panic!("read fixture source {}: {error}", source.display()))
    {
        let entry = entry.expect("fixture entry is readable");
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let file_type = entry.file_type().expect("fixture entry type is readable");
        if file_type.is_dir() {
            copy_dir(&source_path, &destination_path);
        } else if file_type.is_file() {
            fs::copy(&source_path, &destination_path).unwrap_or_else(|error| {
                panic!(
                    "copy {} to {}: {error}",
                    source_path.display(),
                    destination_path.display()
                )
            });
        }
    }
}

fn run_git<const N: usize>(repo: &Path, args: [&str; N]) {
    let output = Command::new("git")
        .args(args)
        .current_dir(repo)
        .output()
        .expect("git command starts");
    assert!(
        output.status.success(),
        "git failed in {}\nstdout:\n{}\nstderr:\n{}",
        repo.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn unique_temp_dir(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after epoch")
        .as_nanos();
    let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = env::temp_dir().join(format!(
        "vibescan-golden-{name}-{}-{nonce}-{counter}",
        std::process::id()
    ));
    fs::create_dir_all(&path).unwrap_or_else(|error| panic!("create {}: {error}", path.display()));
    path
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}
