use super::*;

#[derive(Debug, Default)]
pub(super) struct DependencyScanOutput {
    pub(super) findings: Vec<Finding>,
    pub(super) dependencies: Vec<ParsedDependency>,
}

/// Parse registry-shaped dependencies from manifests under the discovered
/// repository root without performing any egress.
pub fn parse_dependencies(target: impl AsRef<Path>) -> Result<Vec<ParsedDependency>, CoreError> {
    let repo_root = discover_repository_root(target.as_ref()).map_err(CoreError::Git)?;
    Ok(scan_dependency_integrity(&repo_root)?.dependencies)
}

pub(super) fn scan_dependency_integrity(
    repo_root: &Path,
) -> Result<DependencyScanOutput, CoreError> {
    let mut findings = Vec::new();
    let mut dependencies = Vec::new();
    for manifest in collect_manifest_paths(repo_root)? {
        match manifest.kind {
            DependencyManifestKind::PackageJson => {
                scan_package_json(repo_root, &manifest.path, &mut findings, &mut dependencies)?;
            }
            DependencyManifestKind::PackageLock => {
                scan_package_lock(repo_root, &manifest.path, &mut findings, &mut dependencies)?;
            }
            DependencyManifestKind::Pyproject => {
                scan_pyproject(repo_root, &manifest.path, &mut findings, &mut dependencies)?;
            }
            DependencyManifestKind::RequirementsTxt => {
                scan_requirements_txt(repo_root, &manifest.path, &mut findings, &mut dependencies)?;
            }
            DependencyManifestKind::PythonLock => {
                scan_python_lock(repo_root, &manifest.path, &mut dependencies)?;
            }
        }
    }
    dependencies.sort();
    dependencies.dedup();
    Ok(DependencyScanOutput {
        findings,
        dependencies,
    })
}

#[cfg(feature = "registry")]
pub(super) fn registry_eligible_dependencies(
    structural_findings: &[Finding],
    dependencies: Vec<ParsedDependency>,
) -> Vec<ParsedDependency> {
    let rejected = structural_findings
        .iter()
        .filter_map(|finding| match &finding.evidence {
            Evidence::Dependency {
                package,
                manifest_path,
                reason:
                    vibescan_types::DependencyIntegrityReason::InvalidPackageName
                    | vibescan_types::DependencyIntegrityReason::EmptyVersionSpecifier,
            } => Some((package.clone(), manifest_path.clone())),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    dependencies
        .into_iter()
        .filter(|dependency| {
            !rejected.contains(&(dependency.name.clone(), dependency.manifest_path.clone()))
        })
        .collect()
}

#[cfg(feature = "registry")]
pub(super) fn private_registry_ecosystems(
    repo_root: &Path,
) -> Result<BTreeSet<Ecosystem>, CoreError> {
    let mut ecosystems = BTreeSet::new();
    if std::env::var("NPM_CONFIG_REGISTRY").is_ok_and(|value| npm_registry_is_alternate(&value)) {
        ecosystems.insert(Ecosystem::Npm);
    }
    if std::env::var("PIP_INDEX_URL").is_ok_and(|value| python_registry_is_alternate(&value))
        || std::env::var("PIP_EXTRA_INDEX_URL").is_ok_and(|value| !value.trim().is_empty())
        || std::env::var("UV_INDEX_URL").is_ok_and(|value| python_registry_is_alternate(&value))
    {
        ecosystems.insert(Ecosystem::PyPi);
    }
    let npmrc = repo_root.join(".npmrc");
    if let Ok(content) = fs::read_to_string(&npmrc) {
        if content.lines().any(npmrc_line_is_alternate) {
            ecosystems.insert(Ecosystem::Npm);
        }
    }

    let pip_conf = repo_root.join("pip.conf");
    if fs::read_to_string(&pip_conf)
        .is_ok_and(|content| content.lines().any(is_python_index_configuration))
    {
        ecosystems.insert(Ecosystem::PyPi);
    }

    for manifest in collect_manifest_paths(repo_root)? {
        match manifest.kind {
            DependencyManifestKind::RequirementsTxt => {
                let content = fs::read_to_string(&manifest.path).map_err(CoreError::Io)?;
                if content.lines().any(is_python_index_configuration) {
                    ecosystems.insert(Ecosystem::PyPi);
                }
            }
            DependencyManifestKind::Pyproject => {
                let content = fs::read_to_string(&manifest.path).map_err(CoreError::Io)?;
                let value = toml::from_str::<toml::Value>(&content).map_err(CoreError::Toml)?;
                if pyproject_has_alternate_index(&value) {
                    ecosystems.insert(Ecosystem::PyPi);
                }
            }
            DependencyManifestKind::PackageJson => {
                if let Some(parent) = manifest.path.parent() {
                    if fs::read_to_string(parent.join(".npmrc"))
                        .is_ok_and(|content| content.lines().any(npmrc_line_is_alternate))
                    {
                        ecosystems.insert(Ecosystem::Npm);
                    }
                }
            }
            DependencyManifestKind::PackageLock | DependencyManifestKind::PythonLock => {}
        }
    }
    Ok(ecosystems)
}

#[cfg(feature = "registry")]
pub(super) fn npmrc_line_is_alternate(line: &str) -> bool {
    line.trim()
        .strip_prefix("registry=")
        .is_some_and(npm_registry_is_alternate)
}

#[cfg(feature = "registry")]
pub(super) fn npm_registry_is_alternate(value: &str) -> bool {
    let normalized = value.trim().trim_end_matches('/');
    normalized != "https://registry.npmjs.org" && normalized != "http://registry.npmjs.org"
}

#[cfg(feature = "registry")]
pub(super) fn python_registry_is_alternate(value: &str) -> bool {
    let normalized = value.trim().trim_end_matches('/');
    normalized != "https://pypi.org/simple" && normalized != "http://pypi.org/simple"
}

#[cfg(feature = "registry")]
pub(super) fn is_python_index_configuration(line: &str) -> bool {
    let line = line.trim();
    line.starts_with("--index-url")
        || line.starts_with("--extra-index-url")
        || line.starts_with("index-url")
        || line.starts_with("extra-index-url")
}

#[cfg(feature = "registry")]
pub(super) fn pyproject_has_alternate_index(value: &toml::Value) -> bool {
    value
        .get("tool")
        .and_then(|tool| tool.get("poetry"))
        .and_then(|poetry| poetry.get("source"))
        .is_some_and(|source| source.as_array().is_some_and(|items| !items.is_empty()))
        || value
            .get("tool")
            .and_then(|tool| tool.get("uv"))
            .and_then(|uv| uv.get("index"))
            .is_some()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DependencyManifestKind {
    PackageJson,
    PackageLock,
    Pyproject,
    RequirementsTxt,
    PythonLock,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct DependencyManifest {
    path: PathBuf,
    kind: DependencyManifestKind,
}

pub(super) fn collect_manifest_paths(
    repo_root: &Path,
) -> Result<Vec<DependencyManifest>, CoreError> {
    let mut manifests = Vec::new();
    collect_manifest_paths_in(repo_root, repo_root, &mut manifests)?;
    manifests.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(manifests)
}

pub(super) fn collect_manifest_paths_in(
    repo_root: &Path,
    dir: &Path,
    manifests: &mut Vec<DependencyManifest>,
) -> Result<(), CoreError> {
    for entry in fs::read_dir(dir).map_err(CoreError::Io)? {
        let entry = entry.map_err(CoreError::Io)?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(CoreError::Io)?;
        if file_type.is_dir() {
            if should_skip_dependency_dir(repo_root, &path) {
                continue;
            }
            collect_manifest_paths_in(repo_root, &path, manifests)?;
            continue;
        }
        if !file_type.is_file() {
            continue;
        }
        let Some(kind) = dependency_manifest_kind(&path) else {
            continue;
        };
        manifests.push(DependencyManifest { path, kind });
    }
    Ok(())
}

pub(super) fn should_skip_dependency_dir(repo_root: &Path, path: &Path) -> bool {
    let relative = repo_relative_path(repo_root, path);
    relative
        .split('/')
        .any(|component| matches!(component, ".git" | "node_modules" | "target" | ".next"))
}

pub(super) fn dependency_manifest_kind(path: &Path) -> Option<DependencyManifestKind> {
    match path.file_name().and_then(|name| name.to_str()) {
        Some("package.json") => Some(DependencyManifestKind::PackageJson),
        Some("package-lock.json") => Some(DependencyManifestKind::PackageLock),
        Some("pyproject.toml") => Some(DependencyManifestKind::Pyproject),
        Some("requirements.txt") => Some(DependencyManifestKind::RequirementsTxt),
        Some("poetry.lock" | "uv.lock") => Some(DependencyManifestKind::PythonLock),
        _ => None,
    }
}

pub(super) fn scan_package_json(
    repo_root: &Path,
    manifest_path: &Path,
    findings: &mut Vec<Finding>,
    dependencies: &mut Vec<ParsedDependency>,
) -> Result<(), CoreError> {
    let value = read_json_manifest(manifest_path)?;
    for section in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        if let Some(deps) = value.get(section).and_then(serde_json::Value::as_object) {
            for (name, version) in deps {
                let version_req = npm_version_req(version);
                dependencies.push(parsed_dependency(
                    repo_root,
                    manifest_path,
                    name,
                    version_req,
                    Ecosystem::Npm,
                    name.starts_with('@'),
                ));
                check_npm_dependency(repo_root, manifest_path, section, name, version, findings);
            }
        }
    }
    Ok(())
}

pub(super) fn scan_package_lock(
    repo_root: &Path,
    manifest_path: &Path,
    findings: &mut Vec<Finding>,
    dependencies: &mut Vec<ParsedDependency>,
) -> Result<(), CoreError> {
    let value = read_json_manifest(manifest_path)?;
    let packages = value.get("packages").and_then(serde_json::Value::as_object);
    if packages.is_none() {
        if let Some(deps) = value
            .get("dependencies")
            .and_then(serde_json::Value::as_object)
        {
            for (name, metadata) in deps {
                check_npm_dependency(
                    repo_root,
                    manifest_path,
                    "lockfile dependencies",
                    name,
                    metadata,
                    findings,
                );
                dependencies.push(parsed_dependency(
                    repo_root,
                    manifest_path,
                    name,
                    npm_version_req(metadata),
                    Ecosystem::Npm,
                    name.starts_with('@'),
                ));
            }
        }
    }
    if let Some(packages) = packages {
        for (path, metadata) in packages {
            let Some(name) = path.strip_prefix("node_modules/") else {
                continue;
            };
            if name.is_empty() || name.contains("/node_modules/") {
                continue;
            }
            check_npm_dependency(
                repo_root,
                manifest_path,
                "lockfile packages",
                name,
                metadata,
                findings,
            );
            dependencies.push(parsed_dependency(
                repo_root,
                manifest_path,
                name,
                npm_version_req(metadata),
                Ecosystem::Npm,
                name.starts_with('@'),
            ));
        }
    }
    Ok(())
}

pub(super) fn scan_python_lock(
    repo_root: &Path,
    manifest_path: &Path,
    dependencies: &mut Vec<ParsedDependency>,
) -> Result<(), CoreError> {
    let content = fs::read_to_string(manifest_path).map_err(CoreError::Io)?;
    let value = toml::from_str::<toml::Value>(&content).map_err(CoreError::Toml)?;
    if let Some(packages) = value.get("package").and_then(toml::Value::as_array) {
        for package in packages {
            let Some(name) = package.get("name").and_then(toml::Value::as_str) else {
                continue;
            };
            let Some(version) = package.get("version").and_then(toml::Value::as_str) else {
                continue;
            };
            dependencies.push(parsed_dependency(
                repo_root,
                manifest_path,
                name,
                version,
                Ecosystem::PyPi,
                false,
            ));
        }
    }
    Ok(())
}

pub(super) fn scan_pyproject(
    repo_root: &Path,
    manifest_path: &Path,
    findings: &mut Vec<Finding>,
    dependencies: &mut Vec<ParsedDependency>,
) -> Result<(), CoreError> {
    let content = fs::read_to_string(manifest_path).map_err(CoreError::Io)?;
    let value = toml::from_str::<toml::Value>(&content).map_err(CoreError::Toml)?;
    if let Some(deps) = value
        .get("project")
        .and_then(|project| project.get("dependencies"))
        .and_then(toml::Value::as_array)
    {
        for dep in deps.iter().filter_map(toml::Value::as_str) {
            check_python_requirement(
                repo_root,
                manifest_path,
                "project.dependencies",
                dep,
                findings,
                dependencies,
            );
        }
    }
    if let Some(deps) = value
        .get("tool")
        .and_then(|tool| tool.get("poetry"))
        .and_then(|poetry| poetry.get("dependencies"))
        .and_then(toml::Value::as_table)
    {
        for (name, version) in deps {
            if name == "python" {
                continue;
            }
            check_python_dependency_name(
                repo_root,
                manifest_path,
                "tool.poetry.dependencies",
                name,
                findings,
            );
            dependencies.push(parsed_dependency(
                repo_root,
                manifest_path,
                name,
                version.as_str().unwrap_or_default(),
                Ecosystem::PyPi,
                false,
            ));
            if version.as_str().is_some_and(|spec| spec.trim().is_empty()) {
                findings.push(dependency_finding(
                    repo_root,
                    manifest_path,
                    name,
                    "empty version specifier in tool.poetry.dependencies",
                    vibescan_types::DependencyIntegrityReason::EmptyVersionSpecifier,
                ));
            }
        }
    }
    Ok(())
}

pub(super) fn scan_requirements_txt(
    repo_root: &Path,
    manifest_path: &Path,
    findings: &mut Vec<Finding>,
    dependencies: &mut Vec<ParsedDependency>,
) -> Result<(), CoreError> {
    let content = fs::read_to_string(manifest_path).map_err(CoreError::Io)?;
    for line in content.lines() {
        check_python_requirement(
            repo_root,
            manifest_path,
            "requirements.txt",
            line,
            findings,
            dependencies,
        );
    }
    Ok(())
}

pub(super) fn read_json_manifest(path: &Path) -> Result<serde_json::Value, CoreError> {
    let content = fs::read_to_string(path).map_err(CoreError::Io)?;
    serde_json::from_str::<serde_json::Value>(&content).map_err(CoreError::Json)
}

pub(super) fn check_npm_dependency(
    repo_root: &Path,
    manifest_path: &Path,
    section: &str,
    name: &str,
    version: &serde_json::Value,
    findings: &mut Vec<Finding>,
) {
    if !valid_npm_name(name) {
        findings.push(dependency_finding(
            repo_root,
            manifest_path,
            name,
            &format!("invalid npm package name in {section}"),
            vibescan_types::DependencyIntegrityReason::InvalidPackageName,
        ));
    }
    let version = version
        .as_str()
        .or_else(|| version.get("version").and_then(serde_json::Value::as_str));
    if version.is_some_and(|spec| spec.trim().is_empty()) {
        findings.push(dependency_finding(
            repo_root,
            manifest_path,
            name,
            &format!("empty version specifier in {section}"),
            vibescan_types::DependencyIntegrityReason::EmptyVersionSpecifier,
        ));
    }
}

pub(super) fn valid_npm_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 214 || name.starts_with('.') || name.starts_with('_') {
        return false;
    }
    let valid_part = |part: &str| {
        !part.is_empty()
            && part.chars().all(|ch| {
                ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '-' | '_' | '.')
            })
    };
    if let Some(rest) = name.strip_prefix('@') {
        let Some((scope, package)) = rest.split_once('/') else {
            return false;
        };
        valid_part(scope) && valid_part(package)
    } else {
        valid_part(name)
    }
}

pub(super) fn check_python_requirement(
    repo_root: &Path,
    manifest_path: &Path,
    section: &str,
    requirement: &str,
    findings: &mut Vec<Finding>,
    dependencies: &mut Vec<ParsedDependency>,
) {
    let requirement = requirement
        .split_once('#')
        .map_or(requirement, |(before_comment, _)| before_comment)
        .trim();
    if requirement.is_empty()
        || requirement.starts_with('-')
        || requirement.contains("://")
        || requirement.starts_with("git+")
    {
        return;
    }
    let name = python_requirement_name(requirement);
    check_python_dependency_name(repo_root, manifest_path, section, name, findings);
    dependencies.push(parsed_dependency(
        repo_root,
        manifest_path,
        name,
        python_version_req(requirement, name),
        Ecosystem::PyPi,
        false,
    ));
}

pub(super) fn npm_version_req(value: &serde_json::Value) -> &str {
    value
        .as_str()
        .or_else(|| value.get("version").and_then(serde_json::Value::as_str))
        .unwrap_or_default()
}

pub(super) fn python_version_req<'a>(requirement: &'a str, name: &str) -> &'a str {
    requirement.get(name.len()..).unwrap_or_default().trim()
}

pub(super) fn parsed_dependency(
    repo_root: &Path,
    manifest_path: &Path,
    name: &str,
    version_req: &str,
    ecosystem: Ecosystem,
    is_scoped: bool,
) -> ParsedDependency {
    ParsedDependency {
        name: name.to_owned(),
        version_req: version_req.to_owned(),
        ecosystem,
        manifest_path: vibescan_types::RepoPath(repo_relative_path(repo_root, manifest_path)),
        is_scoped,
    }
}

pub(super) fn check_python_dependency_name(
    repo_root: &Path,
    manifest_path: &Path,
    section: &str,
    name: &str,
    findings: &mut Vec<Finding>,
) {
    if !valid_python_package_name(name) {
        findings.push(dependency_finding(
            repo_root,
            manifest_path,
            name,
            &format!("invalid Python package name in {section}"),
            vibescan_types::DependencyIntegrityReason::InvalidPackageName,
        ));
    }
}

pub(super) fn python_requirement_name(requirement: &str) -> &str {
    let version_start = requirement
        .find(['=', '<', '>', '!', '~'])
        .unwrap_or(requirement.len());
    let extras_start = requirement.find('[').unwrap_or(version_start);
    requirement[..version_start.min(extras_start)].trim()
}

pub(super) fn valid_python_package_name(name: &str) -> bool {
    let trimmed = name.trim();
    !trimmed.is_empty()
        && trimmed
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
        && trimmed
            .chars()
            .next()
            .is_some_and(|ch| ch.is_ascii_alphanumeric())
        && trimmed
            .chars()
            .last()
            .is_some_and(|ch| ch.is_ascii_alphanumeric())
}

pub(super) fn dependency_finding(
    repo_root: &Path,
    manifest_path: &Path,
    package: &str,
    detail: &str,
    reason: vibescan_types::DependencyIntegrityReason,
) -> Finding {
    let manifest_path = vibescan_types::RepoPath(repo_relative_path(repo_root, manifest_path));
    let mut hasher = Sha256::new();
    hasher.update(manifest_path.0.as_bytes());
    hasher.update(b"\0");
    hasher.update(package.as_bytes());
    hasher.update(b"\0");
    hasher.update(detail.as_bytes());
    Finding {
        id: FindingId(format!(
            "dependency-{}",
            hex::encode(&hasher.finalize()[..12])
        )),
        category: Category::DependencyIntegrity,
        severity: Severity::High,
        title: format!("Dependency requires review: {package}"),
        detail: detail.to_owned(),
        locations: vec![Location {
            path: manifest_path.clone(),
            span: None,
            provenance: Provenance::WorkingTree,
            additional_provenance: Vec::new(),
            location_class: vibescan_types::LocationClass::ServerOnly,
        }],
        evidence: Evidence::Dependency {
            package: package.to_owned(),
            manifest_path,
            reason,
        },
        remediation: "Correct or remove the dependency before install or deployment.".to_owned(),
        related: Vec::new(),
        confidence: Confidence::Review,
    }
}
