use super::*;

/// Run the high-confidence registry checks through an injected source.
///
/// OSV matches are evaluated before public existence requests. A confirmed
/// advisory therefore emits one Critical finding without leaking the package
/// name merely to prove that an already-known package exists.
pub fn run_registry_checks(
    source: &impl RegistrySource,
    input: &RegistryCheckInput,
) -> Result<RegistryCheckOutput, RegistryError> {
    let dependencies = grouped_dependencies(&input.dependencies);
    let mut advisory_sets = BTreeMap::new();
    let mut output = RegistryCheckOutput::default();
    let mut checkable = Vec::new();

    for (key, declarations) in dependencies {
        let dependency = ParsedDependency {
            name: key.name.clone(),
            version_req: key.version_req.clone(),
            ecosystem: key.ecosystem,
            manifest_path: declarations[0].clone(),
            is_scoped: key.is_scoped,
        };
        if coordinate_may_contain_secret(&dependency) {
            output
                .warnings
                .push(RegistryWarning::SensitiveCoordinateSuppressed);
            continue;
        }
        if !is_registry_version_requirement(&dependency.version_req) {
            output
                .warnings
                .push(RegistryWarning::NonRegistryCoordinateSuppressed);
            continue;
        }
        checkable.push((dependency, declarations));
    }

    for ecosystem in checkable
        .iter()
        .map(|(dependency, _)| dependency.ecosystem)
        .collect::<BTreeSet<_>>()
    {
        match source.advisories_for(ecosystem) {
            Ok(advisories) => {
                advisory_sets.insert(ecosystem, advisories);
            }
            Err(_) => output
                .warnings
                .push(RegistryWarning::OsvSnapshotUnavailable { ecosystem }),
        }
    }

    let mut malicious_names = BTreeSet::new();
    for (dependency, declarations) in &checkable {
        if advisory_sets
            .get(&dependency.ecosystem)
            .is_some_and(|advisories| advisories.contains(dependency))
        {
            malicious_names.insert(PackageKey::from(dependency));
            output.findings.push(dependency_finding(
                dependency,
                declarations,
                DependencyIntegrityReason::KnownMalicious,
            ));
        }
    }

    let mut existence_checks = BTreeMap::<PackageKey, (ParsedDependency, Vec<RepoPath>)>::new();
    for (dependency, declarations) in checkable {
        let package_key = PackageKey::from(&dependency);
        if malicious_names.contains(&package_key) {
            continue;
        }
        if dependency.is_scoped
            || input
                .private_registry_ecosystems
                .contains(&dependency.ecosystem)
        {
            continue;
        }
        let entry = existence_checks
            .entry(package_key)
            .or_insert_with(|| (dependency.clone(), Vec::new()));
        entry.1.extend(declarations);
        entry.1.sort();
        entry.1.dedup();
    }

    for (_, (dependency, declarations)) in existence_checks {
        let host = registry_host(dependency.ecosystem);
        match source.resolves(&dependency) {
            Ok(resolution) => {
                if resolution.request_made {
                    output.actions.push(existence_action(
                        &dependency,
                        host,
                        if resolution.exists {
                            Some(200)
                        } else {
                            Some(404)
                        },
                        if resolution.exists {
                            NetworkActionOutcome::RegistryResolved
                        } else {
                            NetworkActionOutcome::NotFound
                        },
                    ));
                    output.name_egress.push(RegistryNameEgress {
                        ecosystem: dependency.ecosystem,
                        host: host.to_owned(),
                    });
                }
                if !resolution.exists {
                    output.findings.push(dependency_finding(
                        &dependency,
                        &declarations,
                        DependencyIntegrityReason::NonexistentPackage,
                    ));
                }
            }
            Err(error) => {
                output.actions.push(existence_action(
                    &dependency,
                    host,
                    error_status(&error),
                    error_outcome(&error),
                ));
                output.name_egress.push(RegistryNameEgress {
                    ecosystem: dependency.ecosystem,
                    host: host.to_owned(),
                });
                output.warnings.push(warning_from_error(error, host));
            }
        }
    }

    output
        .findings
        .sort_by(|left, right| left.id.cmp(&right.id));
    output.warnings.sort_by_key(RegistryWarning::message);
    output.warnings.dedup();
    output.actions.sort_by(|left, right| {
        (&left.endpoint, &left.package, left.status).cmp(&(
            &right.endpoint,
            &right.package,
            right.status,
        ))
    });
    output.actions.dedup();
    output.name_egress.sort();
    output.name_egress.dedup();
    Ok(output)
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct DependencyKey {
    ecosystem: Ecosystem,
    name: String,
    version_req: String,
    is_scoped: bool,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct PackageKey {
    ecosystem: Ecosystem,
    normalized_name: String,
}

impl From<&ParsedDependency> for PackageKey {
    fn from(dependency: &ParsedDependency) -> Self {
        Self {
            ecosystem: dependency.ecosystem,
            normalized_name: normalize_package_name(dependency.ecosystem, &dependency.name),
        }
    }
}

pub(super) fn grouped_dependencies(
    dependencies: &[ParsedDependency],
) -> BTreeMap<DependencyKey, Vec<RepoPath>> {
    let mut grouped = BTreeMap::<DependencyKey, Vec<RepoPath>>::new();
    for dependency in dependencies {
        grouped
            .entry(DependencyKey {
                ecosystem: dependency.ecosystem,
                name: dependency.name.clone(),
                version_req: dependency.version_req.clone(),
                is_scoped: dependency.is_scoped,
            })
            .or_default()
            .push(dependency.manifest_path.clone());
    }
    for paths in grouped.values_mut() {
        paths.sort();
        paths.dedup();
    }
    grouped
}

pub(super) fn exact_version(dependency: &ParsedDependency) -> Option<&str> {
    let value = dependency.version_req.trim();
    let value = match dependency.ecosystem {
        Ecosystem::Npm => value.strip_prefix('=').unwrap_or(value),
        Ecosystem::PyPi => value.strip_prefix("==").unwrap_or(value),
    };
    (!value.is_empty()
        && value.chars().next().is_some_and(|ch| ch.is_ascii_digit())
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '+')))
    .then_some(value)
}

pub(super) fn normalize_package_name(ecosystem: Ecosystem, package: &str) -> String {
    match ecosystem {
        Ecosystem::Npm => package.to_owned(),
        Ecosystem::PyPi => {
            let mut normalized = String::new();
            let mut separator = false;
            for ch in package.chars() {
                if matches!(ch, '-' | '_' | '.') {
                    if !separator {
                        normalized.push('-');
                    }
                    separator = true;
                } else {
                    normalized.extend(ch.to_lowercase());
                    separator = false;
                }
            }
            normalized
        }
    }
}

pub(super) fn registry_host(ecosystem: Ecosystem) -> &'static str {
    match ecosystem {
        Ecosystem::Npm => "registry.npmjs.org",
        Ecosystem::PyPi => "pypi.org",
    }
}

pub(super) fn package_coordinate(dependency: &ParsedDependency) -> String {
    format!("{}@{}", dependency.name, dependency.version_req)
}

pub(super) fn coordinate_may_contain_secret(dependency: &ParsedDependency) -> bool {
    let coordinate = package_coordinate(dependency).to_ascii_lowercase();
    [
        "sb_secret_",
        "service_role",
        "sk_live_",
        "sk-proj-",
        "github_pat_",
        "ghp_",
        "-----begin",
    ]
    .iter()
    .any(|marker| coordinate.contains(marker))
        || coordinate
            .split(|ch: char| !ch.is_ascii_alphanumeric())
            .any(|part| part.len() >= 20 && part.starts_with("akia"))
}

pub(super) fn is_registry_version_requirement(version_req: &str) -> bool {
    let value = version_req.trim().to_ascii_lowercase();
    !value.is_empty()
        && !value.contains("://")
        && ![
            "git+",
            "git:",
            "file:",
            "link:",
            "workspace:",
            "github:",
            "http:",
            "https:",
        ]
        .iter()
        .any(|prefix| value.starts_with(prefix))
}

pub(super) fn existence_action(
    dependency: &ParsedDependency,
    host: &str,
    status: Option<u16>,
    outcome: NetworkActionOutcome,
) -> NetworkActionAudit {
    NetworkActionAudit {
        kind: NetworkActionKind::RegistryExistence,
        intent: NetworkActionIntent::Get,
        endpoint: host.to_owned(),
        table: None,
        package: Some(package_coordinate(dependency)),
        status,
        outcome,
        observed_row_count: None,
    }
}

pub(super) fn error_status(error: &RegistryError) -> Option<u16> {
    match error {
        RegistryError::RateLimited { .. } => Some(429),
        RegistryError::InvalidResponse { status, .. } => *status,
        RegistryError::RegistryUnavailable { .. }
        | RegistryError::OsvSnapshotUnavailable { .. } => None,
    }
}

pub(super) fn error_outcome(error: &RegistryError) -> NetworkActionOutcome {
    match error {
        RegistryError::RegistryUnavailable { .. } => NetworkActionOutcome::TransportError,
        RegistryError::RateLimited { .. }
        | RegistryError::InvalidResponse { .. }
        | RegistryError::OsvSnapshotUnavailable { .. } => NetworkActionOutcome::InvalidResponse,
    }
}

pub(super) fn warning_from_error(error: RegistryError, fallback_host: &str) -> RegistryWarning {
    match error {
        RegistryError::RegistryUnavailable { host } => {
            RegistryWarning::RegistryUnavailable { host }
        }
        RegistryError::RateLimited { host } => RegistryWarning::RateLimited { host },
        RegistryError::InvalidResponse { host, .. } => RegistryWarning::InvalidResponse { host },
        RegistryError::OsvSnapshotUnavailable { .. } => RegistryWarning::InvalidResponse {
            host: fallback_host.to_owned(),
        },
    }
}

pub(super) fn dependency_finding(
    dependency: &ParsedDependency,
    manifest_paths: &[RepoPath],
    reason: DependencyIntegrityReason,
) -> Finding {
    let mut hasher = Sha256::new();
    hasher.update(format!("{:?}", dependency.ecosystem).as_bytes());
    hasher.update(b"\0");
    hasher.update(dependency.name.as_bytes());
    hasher.update(b"\0");
    hasher.update(dependency.version_req.as_bytes());
    hasher.update(b"\0");
    hasher.update(format!("{reason:?}").as_bytes());
    let (severity, title, detail, remediation) = match reason {
        DependencyIntegrityReason::KnownMalicious => (
            Severity::Critical,
            format!("Known-malicious dependency: {}", dependency.name),
            format!(
                "{}@{} matches the locally cached OSV advisory snapshot.",
                dependency.name, dependency.version_req
            ),
            "Remove or upgrade the dependency to a version not affected by the advisory, then regenerate and review the lockfile.".to_owned(),
        ),
        DependencyIntegrityReason::NonexistentPackage => (
            Severity::High,
            format!("Package does not resolve publicly: {}", dependency.name),
            format!(
                "{}@{} returned not found from the public {:?} registry and may be hallucinated or vulnerable to slopsquatting.",
                dependency.name, dependency.version_req, dependency.ecosystem
            ),
            "Verify the intended public package name before install; correct or remove the declaration and regenerate the lockfile.".to_owned(),
        ),
        _ => unreachable!("registry engine emits only F2 reasons"),
    };
    let mut locations = manifest_paths
        .iter()
        .map(|path| Location {
            path: path.clone(),
            span: None,
            provenance: Provenance::WorkingTree,
            additional_provenance: Vec::new(),
            location_class: LocationClass::ServerOnly,
        })
        .collect::<Vec<_>>();
    locations.sort_by(|left, right| left.path.cmp(&right.path));
    Finding {
        id: FindingId(format!(
            "dependency-{}",
            hex::encode(&hasher.finalize()[..12])
        )),
        category: Category::DependencyIntegrity,
        severity,
        title,
        detail,
        locations,
        evidence: Evidence::Dependency {
            package: package_coordinate(dependency),
            manifest_path: manifest_paths[0].clone(),
            reason,
        },
        remediation,
        related: Vec::new(),
        confidence: Confidence::Confirmed,
    }
}
