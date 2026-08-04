use super::*;

/// Production sync/rustls HTTP source. Construction does not perform egress.
#[cfg(feature = "transport")]
#[derive(Clone, Debug)]
pub struct ReqwestRegistrySource {
    client: reqwest::blocking::Client,
    cache: RegistryCache,
}

#[cfg(feature = "transport")]
impl ReqwestRegistrySource {
    pub fn new() -> Result<Self, RegistryError> {
        let client = reqwest::blocking::Client::builder().build().map_err(|_| {
            RegistryError::InvalidResponse {
                host: "registry transport".to_owned(),
                status: None,
            }
        })?;
        Ok(Self {
            client,
            cache: RegistryCache::new(default_cache_dir(), Duration::from_secs(24 * 60 * 60)),
        })
    }

    fn registry_url(
        dependency: &ParsedDependency,
    ) -> Result<(reqwest::Url, &'static str), RegistryError> {
        let (base, host) = match dependency.ecosystem {
            Ecosystem::Npm => ("https://registry.npmjs.org/", "registry.npmjs.org"),
            Ecosystem::PyPi => ("https://pypi.org/pypi/", "pypi.org"),
        };
        let mut url = reqwest::Url::parse(base).map_err(|_| RegistryError::InvalidResponse {
            host: host.to_owned(),
            status: None,
        })?;
        url.path_segments_mut()
            .map_err(|_| RegistryError::InvalidResponse {
                host: host.to_owned(),
                status: None,
            })?
            .push(&dependency.name);
        if dependency.ecosystem == Ecosystem::PyPi {
            url.path_segments_mut()
                .map_err(|_| RegistryError::InvalidResponse {
                    host: host.to_owned(),
                    status: None,
                })?
                .push("json");
        }
        Ok((url, host))
    }

    fn resolve_uncached(&self, dependency: &ParsedDependency) -> Result<bool, RegistryError> {
        let (url, host) = Self::registry_url(dependency)?;
        let response =
            self.client
                .get(url)
                .send()
                .map_err(|_| RegistryError::RegistryUnavailable {
                    host: host.to_owned(),
                })?;
        match response.status() {
            status if status.is_success() => Ok(true),
            reqwest::StatusCode::NOT_FOUND => Ok(false),
            reqwest::StatusCode::TOO_MANY_REQUESTS => Err(RegistryError::RateLimited {
                host: host.to_owned(),
            }),
            status => Err(RegistryError::InvalidResponse {
                host: host.to_owned(),
                status: Some(status.as_u16()),
            }),
        }
    }

    fn fetch_osv_snapshot(&self, ecosystem: Ecosystem) -> Result<Vec<u8>, RegistryError> {
        const MAX_OSV_SNAPSHOT_BYTES: usize = 512 * 1024 * 1024;
        let host = "osv-vulnerabilities.storage.googleapis.com";
        let ecosystem_path = match ecosystem {
            Ecosystem::Npm => "npm",
            Ecosystem::PyPi => "PyPI",
        };
        let url = format!("https://{host}/{ecosystem_path}/all.zip");
        let response = self
            .client
            .get(url)
            .send()
            .map_err(|_| RegistryError::OsvSnapshotUnavailable { ecosystem })?;
        if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Err(RegistryError::RateLimited {
                host: host.to_owned(),
            });
        }
        if !response.status().is_success() {
            return Err(RegistryError::InvalidResponse {
                host: host.to_owned(),
                status: Some(response.status().as_u16()),
            });
        }
        if response
            .content_length()
            .is_some_and(|size| size > MAX_OSV_SNAPSHOT_BYTES as u64)
        {
            return Err(RegistryError::InvalidResponse {
                host: host.to_owned(),
                status: Some(200),
            });
        }
        let bytes = response
            .bytes()
            .map_err(|_| RegistryError::InvalidResponse {
                host: host.to_owned(),
                status: Some(200),
            })?;
        if bytes.len() > MAX_OSV_SNAPSHOT_BYTES {
            return Err(RegistryError::InvalidResponse {
                host: host.to_owned(),
                status: Some(200),
            });
        }
        Ok(bytes.to_vec())
    }
}

#[cfg(feature = "transport")]
impl RegistrySource for ReqwestRegistrySource {
    fn resolves(&self, dependency: &ParsedDependency) -> Result<RegistryResolution, RegistryError> {
        resolve_with_cache(&self.cache, dependency, || {
            self.resolve_uncached(dependency)
        })
    }

    fn advisories_for(&self, ecosystem: Ecosystem) -> Result<AdvisorySet, RegistryError> {
        advisories_with_cache(&self.cache, ecosystem, || {
            self.fetch_osv_snapshot(ecosystem)
        })
    }
}
