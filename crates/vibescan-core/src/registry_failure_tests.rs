use super::*;
use vibescan_registry::{
    AdvisorySet, RegistryError, RegistryResolution, RegistrySource, RegistryWarning,
};
use vibescan_types::{DependencyIntegrityReason, RegistryNameEgress, RepoPath};

#[derive(Clone, Copy)]
enum FailMode {
    Outage,
    OsvSnapshot,
}

struct FailingRegistry {
    mode: FailMode,
}

impl RegistrySource for FailingRegistry {
    fn resolves(
        &self,
        _dependency: &ParsedDependency,
    ) -> Result<RegistryResolution, RegistryError> {
        match self.mode {
            FailMode::Outage => Err(RegistryError::RegistryUnavailable {
                host: "registry.npmjs.org".to_owned(),
            }),
            FailMode::OsvSnapshot => Ok(RegistryResolution {
                exists: true,
                request_made: true,
            }),
        }
    }

    fn advisories_for(&self, ecosystem: Ecosystem) -> Result<AdvisorySet, RegistryError> {
        match self.mode {
            FailMode::Outage => Ok(AdvisorySet::empty(ecosystem)),
            FailMode::OsvSnapshot => Err(RegistryError::OsvSnapshotUnavailable { ecosystem }),
        }
    }
}

#[test]
fn structural_findings_survive_registry_outage() {
    assert_structural_findings_survive(
        FailMode::Outage,
        RegistryWarning::RegistryUnavailable {
            host: "registry.npmjs.org".to_owned(),
        },
    );
}

#[test]
fn structural_findings_survive_osv_snapshot_failure() {
    assert_structural_findings_survive(
        FailMode::OsvSnapshot,
        RegistryWarning::OsvSnapshotUnavailable {
            ecosystem: Ecosystem::Npm,
        },
    );
}

fn assert_structural_findings_survive(mode: FailMode, expected_warning: RegistryWarning) {
    let fixture_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/malformed-dependency/repo");
    let dependency_scan =
        scan_dependency_integrity(&fixture_root).expect("malformed fixture scans");
    let mut findings = dependency_scan.findings;
    let seeded = findings
        .iter()
        .map(|finding| {
            let Evidence::Dependency { reason, .. } = finding.evidence else {
                panic!("malformed fixture emitted non-dependency evidence")
            };
            (finding.id.clone(), reason)
        })
        .collect::<Vec<_>>();
    assert_eq!(
        seeded
            .iter()
            .map(|(_, reason)| *reason)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            DependencyIntegrityReason::InvalidPackageName,
            DependencyIntegrityReason::EmptyVersionSpecifier,
        ])
    );

    let input = RegistryCheckInput {
        dependencies: vec![ParsedDependency {
            name: "left-pad".to_owned(),
            version_req: "1.3.0".to_owned(),
            ecosystem: Ecosystem::Npm,
            manifest_path: RepoPath("package.json".to_owned()),
            is_scoped: false,
        }],
        private_registry_ecosystems: BTreeSet::new(),
    };
    let mut network_actions = Vec::<NetworkActionAudit>::new();
    let mut registry_name_egress = Vec::<RegistryNameEgress>::new();
    let mut warnings = Vec::<ScopeWarning>::new();

    apply_registry_findings(
        &FailingRegistry { mode },
        input,
        &mut findings,
        &mut network_actions,
        &mut registry_name_egress,
        &mut warnings,
    )
    .expect("registry failures remain non-fatal");

    for (seeded_id, seeded_reason) in &seeded {
        assert!(findings.iter().any(|finding| {
            finding.id == *seeded_id
                && matches!(
                    finding.evidence,
                    Evidence::Dependency { reason, .. } if reason == *seeded_reason
                )
        }));
    }
    assert!(warnings.iter().any(|warning| matches!(
        warning,
        ScopeWarning::Other { message } if message == &expected_warning.message()
    )));
    assert!(!findings.iter().any(|finding| matches!(
        finding.evidence,
        Evidence::Dependency {
            reason: DependencyIntegrityReason::NonexistentPackage,
            ..
        }
    )));
    assert_eq!(findings.len(), seeded.len());
}
