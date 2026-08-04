#[cfg(feature = "transport")]
use std::cell::Cell;
use std::cell::RefCell;

use super::*;

#[derive(Default)]
struct MockRegistry {
    advisories: BTreeMap<Ecosystem, AdvisorySet>,
    advisory_failures: BTreeSet<Ecosystem>,
    resolutions: BTreeMap<String, Result<RegistryResolution, RegistryError>>,
    resolve_calls: RefCell<Vec<String>>,
    advisory_calls: RefCell<Vec<Ecosystem>>,
}

impl RegistrySource for MockRegistry {
    fn resolves(&self, dependency: &ParsedDependency) -> Result<RegistryResolution, RegistryError> {
        self.resolve_calls
            .borrow_mut()
            .push(dependency.name.clone());
        self.resolutions
            .get(&dependency.name)
            .cloned()
            .unwrap_or(Ok(RegistryResolution {
                exists: true,
                request_made: true,
            }))
    }

    fn advisories_for(&self, ecosystem: Ecosystem) -> Result<AdvisorySet, RegistryError> {
        self.advisory_calls.borrow_mut().push(ecosystem);
        if self.advisory_failures.contains(&ecosystem) {
            return Err(RegistryError::OsvSnapshotUnavailable { ecosystem });
        }
        Ok(self
            .advisories
            .get(&ecosystem)
            .cloned()
            .unwrap_or_else(|| AdvisorySet::empty(ecosystem)))
    }
}

fn dependency(
    name: &str,
    version_req: &str,
    ecosystem: Ecosystem,
    is_scoped: bool,
) -> ParsedDependency {
    ParsedDependency {
        name: name.to_owned(),
        version_req: version_req.to_owned(),
        ecosystem,
        manifest_path: RepoPath(match ecosystem {
            Ecosystem::Npm => "package.json".to_owned(),
            Ecosystem::PyPi => "pyproject.toml".to_owned(),
        }),
        is_scoped,
    }
}

fn input(dependencies: Vec<ParsedDependency>) -> RegistryCheckInput {
    RegistryCheckInput {
        dependencies,
        private_registry_ecosystems: BTreeSet::new(),
    }
}

#[cfg(feature = "transport")]
fn osv_archive(name: &str, json: &str) -> Vec<u8> {
    use std::io::Write;

    let mut bytes = Cursor::new(Vec::new());
    {
        let mut writer = zip::ZipWriter::new(&mut bytes);
        writer
            .start_file(name, zip::write::SimpleFileOptions::default())
            .expect("zip entry starts");
        writer.write_all(json.as_bytes()).expect("zip entry writes");
        writer.finish().expect("zip finishes");
    }
    bytes.into_inner()
}

#[cfg(feature = "transport")]
struct TestDir {
    path: PathBuf,
}

#[cfg(feature = "transport")]
impl TestDir {
    fn new(label: &str) -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "vibescan-registry-{label}-{}-{}",
            std::process::id(),
            NEXT_ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).expect("test cache directory creates");
        Self { path }
    }
}

#[cfg(feature = "transport")]
impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[path = "checks.rs"]
mod checks_tests;

#[path = "model.rs"]
mod model_tests;

#[cfg(feature = "transport")]
#[path = "cache.rs"]
mod cache_tests;

#[cfg(feature = "transport")]
#[path = "transport.rs"]
mod transport_tests;
