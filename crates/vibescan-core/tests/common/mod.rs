use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use vibescan_core::correlate_findings;
use vibescan_types::{
    Category, Confidence, CorrelationRuleId, Evidence, Finding, FindingId, Location, LocationClass,
    Provenance, RepoPath, RlsExposure, SecretFingerprint, Severity, Span, SupabaseKeyClass,
    SupabaseProject,
};

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
