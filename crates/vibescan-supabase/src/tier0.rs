use super::*;

/// Inputs for the opt-in Tier 0 read probe.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Tier0RlsProbeInput {
    pub project: SupabaseProject,
    pub public_key: String,
    pub key_location: Location,
    pub candidate_tables: BTreeSet<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Tier0RlsProbeOutput {
    pub findings: Vec<Finding>,
    pub warnings: Vec<Tier0RlsProbeWarning>,
    pub actions: Vec<NetworkActionAudit>,
}
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Tier0RlsProbeWarning {
    KeyRejected { url: String },
    RootEnumerationUnavailable { url: String, status: u16 },
    NoCandidateTables { project_url: String },
    Transport { url: String, message: String },
}

impl Tier0RlsProbeWarning {
    pub fn message(&self) -> String {
        match self {
            Self::KeyRejected { url } => {
                format!("Tier 0 RLS read probe key rejected with HTTP 401 at {url}")
            }
            Self::RootEnumerationUnavailable { url, status } => {
                format!(
                    "Tier 0 RLS read probe root enumeration unavailable with public key at {url} (HTTP {status}); continuing with LocalStatic candidates"
                )
            }
            Self::NoCandidateTables { project_url } => {
                format!(
                    "Tier 0 RLS read probe found no candidate tables for {project_url}; nothing to probe"
                )
            }
            Self::Transport { url, message } => {
                format!("Tier 0 RLS read probe transport/other error at {url}: {message}")
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RlsHttpResponse {
    pub status: u16,
    pub body: String,
}

pub trait RlsHttpClient {
    fn get(
        &self,
        url: &str,
        headers: &[(String, String)],
    ) -> Result<RlsHttpResponse, RlsProbeError>;
}

#[derive(Debug)]
pub enum RlsProbeError {
    Http {
        url: String,
        status: Option<u16>,
        source: String,
    },
    InvalidProjectUrl(String),
    Json(serde_json::Error),
    OpenApi {
        url: String,
        status: u16,
    },
}

impl fmt::Display for RlsProbeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Http { url, source, .. } => {
                write!(formatter, "RLS probe HTTP failed for {url}: {source}")
            }
            Self::InvalidProjectUrl(url) => {
                write!(
                    formatter,
                    "RLS probe refused non-Supabase project URL: {url}"
                )
            }
            Self::Json(source) => write!(formatter, "RLS probe JSON parse failed: {source}"),
            Self::OpenApi { url, status } => {
                write!(
                    formatter,
                    "RLS probe OpenAPI enumeration failed for {url}: HTTP {status}"
                )
            }
        }
    }
}

impl std::error::Error for RlsProbeError {}

/// Run the Tier 0 read probe using a supplied HTTP client.
///
/// This function never writes to the target project. It treats PostgREST root
/// enumeration as a best-effort supplement to LocalStatic candidates, performs
/// read-only `select=*&limit=1` requests, and emits findings only for tables
/// that return rows to the public key.
pub fn probe_tier0_read_with_client(
    client: &impl RlsHttpClient,
    input: &Tier0RlsProbeInput,
) -> Result<Tier0RlsProbeOutput, RlsProbeError> {
    let base_url = normalized_supabase_url(&input.project.url)?;
    let mut output = Tier0RlsProbeOutput::default();
    let mut tables = input.candidate_tables.clone();
    let openapi_url = format!("{base_url}/rest/v1/");

    let headers = public_key_headers(&input.public_key, "application/openapi+json");
    match client.get(&openapi_url, &headers) {
        Ok(openapi) => match openapi.status {
            200 => match tables_from_openapi(&openapi.body) {
                Ok(openapi_tables) => {
                    output.actions.push(network_action(
                        NetworkActionKind::RootEnumeration,
                        &openapi_url,
                        None,
                        Some(200),
                        NetworkActionOutcome::RootEnumerated,
                        None,
                    ));
                    tables.extend(openapi_tables);
                }
                Err(error) => {
                    output.actions.push(network_action(
                        NetworkActionKind::RootEnumeration,
                        &openapi_url,
                        None,
                        Some(200),
                        NetworkActionOutcome::InvalidResponse,
                        None,
                    ));
                    output.warnings.push(Tier0RlsProbeWarning::Transport {
                        url: openapi_url.clone(),
                        message: error.to_string(),
                    });
                }
            },
            status @ (401 | 403) => {
                output.actions.push(network_action(
                    NetworkActionKind::RootEnumeration,
                    &openapi_url,
                    None,
                    Some(status),
                    NetworkActionOutcome::RootUnavailable,
                    None,
                ));
                output
                    .warnings
                    .push(Tier0RlsProbeWarning::RootEnumerationUnavailable {
                        url: openapi_url.clone(),
                        status,
                    })
            }
            _ => {
                output.actions.push(network_action(
                    NetworkActionKind::RootEnumeration,
                    &openapi_url,
                    None,
                    Some(openapi.status),
                    NetworkActionOutcome::InvalidResponse,
                    None,
                ));
                output.warnings.push(Tier0RlsProbeWarning::Transport {
                    url: openapi_url.clone(),
                    message: format!("OpenAPI root returned HTTP {}", openapi.status),
                });
            }
        },
        Err(error) => {
            output.actions.push(network_action(
                NetworkActionKind::RootEnumeration,
                &openapi_url,
                None,
                error.http_status(),
                NetworkActionOutcome::TransportError,
                None,
            ));
            output.warnings.push(Tier0RlsProbeWarning::Transport {
                url: openapi_url.clone(),
                message: error.to_string(),
            });
        }
    }

    if tables.is_empty() {
        output
            .warnings
            .push(Tier0RlsProbeWarning::NoCandidateTables {
                project_url: base_url,
            });
        dedup_probe_warnings(&mut output.warnings);
        return Ok(output);
    }

    for table in tables {
        let endpoint = format!("{base_url}/rest/v1/{table}?select=*&limit=1");
        let headers = public_key_headers(&input.public_key, "application/json");
        let response = match client.get(&endpoint, &headers) {
            Ok(response) => response,
            Err(error) => {
                output.actions.push(network_action(
                    NetworkActionKind::TableRead,
                    &endpoint,
                    Some(&table),
                    error.http_status(),
                    NetworkActionOutcome::TransportError,
                    None,
                ));
                output.warnings.push(Tier0RlsProbeWarning::Transport {
                    url: endpoint,
                    message: error.to_string(),
                });
                continue;
            }
        };
        match response.status {
            200 => {}
            401 => {
                output.actions.push(network_action(
                    NetworkActionKind::TableRead,
                    &endpoint,
                    Some(&table),
                    Some(401),
                    NetworkActionOutcome::KeyRejected,
                    None,
                ));
                output
                    .warnings
                    .push(Tier0RlsProbeWarning::KeyRejected { url: endpoint });
                continue;
            }
            403 => {
                output.actions.push(network_action(
                    NetworkActionKind::TableRead,
                    &endpoint,
                    Some(&table),
                    Some(403),
                    NetworkActionOutcome::Protected,
                    None,
                ));
                continue;
            }
            404 => {
                output.actions.push(network_action(
                    NetworkActionKind::TableRead,
                    &endpoint,
                    Some(&table),
                    Some(404),
                    NetworkActionOutcome::NotFound,
                    None,
                ));
                continue;
            }
            _ => {
                output.actions.push(network_action(
                    NetworkActionKind::TableRead,
                    &endpoint,
                    Some(&table),
                    Some(response.status),
                    NetworkActionOutcome::InvalidResponse,
                    None,
                ));
                output.warnings.push(Tier0RlsProbeWarning::Transport {
                    url: endpoint,
                    message: format!("table probe returned HTTP {}", response.status),
                });
                continue;
            }
        }

        let body = match serde_json::from_str::<Value>(&response.body) {
            Ok(body) => body,
            Err(error) => {
                output.actions.push(network_action(
                    NetworkActionKind::TableRead,
                    &endpoint,
                    Some(&table),
                    Some(200),
                    NetworkActionOutcome::InvalidResponse,
                    None,
                ));
                output.warnings.push(Tier0RlsProbeWarning::Transport {
                    url: endpoint,
                    message: format!("table probe JSON parse failed: {error}"),
                });
                continue;
            }
        };
        let Some(rows) = body.as_array() else {
            output.actions.push(network_action(
                NetworkActionKind::TableRead,
                &endpoint,
                Some(&table),
                Some(200),
                NetworkActionOutcome::InvalidResponse,
                None,
            ));
            output.warnings.push(Tier0RlsProbeWarning::Transport {
                url: endpoint,
                message: "table probe response was not a JSON array".to_owned(),
            });
            continue;
        };
        let observed_row_count = rows.len() as u64;
        if observed_row_count > 0 {
            output.actions.push(network_action(
                NetworkActionKind::TableRead,
                &endpoint,
                Some(&table),
                Some(200),
                NetworkActionOutcome::Exposed,
                Some(observed_row_count),
            ));
            output.findings.push(rls_exposed_finding(
                &input.project,
                &input.key_location,
                &table,
                &endpoint,
                observed_row_count,
            ));
        } else {
            output.actions.push(network_action(
                NetworkActionKind::TableRead,
                &endpoint,
                Some(&table),
                Some(200),
                NetworkActionOutcome::NoRowsObserved,
                None,
            ));
        }
    }

    dedup_probe_warnings(&mut output.warnings);
    Ok(output)
}

pub(super) fn network_action(
    kind: NetworkActionKind,
    endpoint: &str,
    table: Option<&str>,
    status: Option<u16>,
    outcome: NetworkActionOutcome,
    observed_row_count: Option<u64>,
) -> NetworkActionAudit {
    NetworkActionAudit {
        kind,
        intent: NetworkActionIntent::Get,
        endpoint: endpoint.to_owned(),
        table: table.map(str::to_owned),
        package: None,
        status,
        outcome,
        observed_row_count,
    }
}

impl RlsProbeError {
    fn http_status(&self) -> Option<u16> {
        match self {
            Self::Http { status, .. } => *status,
            _ => None,
        }
    }
}

#[cfg(feature = "network")]
#[derive(Debug)]
pub struct ReqwestRlsHttpClient {
    client: reqwest::blocking::Client,
}

#[cfg(feature = "network")]
impl ReqwestRlsHttpClient {
    pub fn new() -> Result<Self, RlsProbeError> {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent("vibescan")
            .build()
            .map_err(|source| RlsProbeError::Http {
                url: "client setup".to_owned(),
                status: None,
                source: source.to_string(),
            })?;
        Ok(Self { client })
    }
}

#[cfg(feature = "network")]
impl RlsHttpClient for ReqwestRlsHttpClient {
    fn get(
        &self,
        url: &str,
        headers: &[(String, String)],
    ) -> Result<RlsHttpResponse, RlsProbeError> {
        let mut request = self.client.get(url);
        for (name, value) in headers {
            request = request.header(name, value);
        }
        let response = request.send().map_err(|source| RlsProbeError::Http {
            url: url.to_owned(),
            status: None,
            source: source.to_string(),
        })?;
        let status = response.status().as_u16();
        let body = response.text().map_err(|source| RlsProbeError::Http {
            url: url.to_owned(),
            status: Some(status),
            source: source.to_string(),
        })?;
        Ok(RlsHttpResponse { status, body })
    }
}

#[cfg(feature = "network")]
pub fn probe_tier0_read(input: &Tier0RlsProbeInput) -> Result<Tier0RlsProbeOutput, RlsProbeError> {
    let client = ReqwestRlsHttpClient::new()?;
    probe_tier0_read_with_client(&client, input)
}
pub(super) fn normalized_supabase_url(url: &str) -> Result<String, RlsProbeError> {
    let normalized = url.trim_end_matches('/').to_owned();
    let host = normalized
        .strip_prefix("https://")
        .ok_or_else(|| RlsProbeError::InvalidProjectUrl(url.to_owned()))?;
    if host.contains('/') || !host.ends_with(SUPABASE_URL_SUFFIX) {
        return Err(RlsProbeError::InvalidProjectUrl(url.to_owned()));
    }
    let ref_id = host.trim_end_matches(SUPABASE_URL_SUFFIX);
    if !is_valid_project_ref(ref_id) {
        return Err(RlsProbeError::InvalidProjectUrl(url.to_owned()));
    }
    Ok(normalized)
}

pub(super) fn public_key_headers(public_key: &str, accept: &str) -> Vec<(String, String)> {
    vec![
        ("apikey".to_owned(), public_key.to_owned()),
        ("authorization".to_owned(), format!("Bearer {public_key}")),
        ("accept".to_owned(), accept.to_owned()),
    ]
}

pub(super) fn tables_from_openapi(body: &str) -> Result<Vec<String>, RlsProbeError> {
    let value = serde_json::from_str::<Value>(body).map_err(RlsProbeError::Json)?;
    let Some(paths) = value.get("paths").and_then(Value::as_object) else {
        return Ok(Vec::new());
    };
    let mut tables = paths
        .iter()
        .filter_map(|(path, methods)| {
            let table = path.strip_prefix('/')?;
            if table.is_empty() || table.contains('/') || table.starts_with("rpc/") {
                return None;
            }
            methods.get("get")?;
            Some(table.to_owned())
        })
        .collect::<Vec<_>>();
    tables.sort();
    tables.dedup();
    Ok(tables)
}

pub(super) fn dedup_probe_warnings(warnings: &mut Vec<Tier0RlsProbeWarning>) {
    let mut seen = BTreeSet::new();
    warnings.retain(|warning| seen.insert(probe_warning_cause_key(warning)));
}

pub(super) fn probe_warning_cause_key(warning: &Tier0RlsProbeWarning) -> String {
    match warning {
        Tier0RlsProbeWarning::KeyRejected { .. } => "key-rejected".to_owned(),
        Tier0RlsProbeWarning::RootEnumerationUnavailable { status, .. } => {
            format!("root-enumeration-unavailable:{status}")
        }
        Tier0RlsProbeWarning::NoCandidateTables { project_url } => {
            format!("no-candidate-tables:{project_url}")
        }
        Tier0RlsProbeWarning::Transport { message, .. } => format!("transport:{message}"),
    }
}

pub(super) fn rls_exposed_finding(
    project: &SupabaseProject,
    key_location: &Location,
    table: &str,
    endpoint: &str,
    observed_row_count: u64,
) -> Finding {
    let mut hasher = Sha256::new();
    hasher.update(project.url.as_bytes());
    hasher.update(b"\0");
    hasher.update(table.as_bytes());
    hasher.update(b"\0");
    hasher.update(endpoint.as_bytes());

    Finding {
        id: FindingId(format!("rls-{}", hex::encode(&hasher.finalize()[..12]))),
        category: Category::Rls,
        severity: Severity::Critical,
        title: format!("Supabase table {table} is readable with the public key"),
        detail: "A read-only Tier 0 probe confirmed that PostgREST returned rows to the discovered public Supabase key.".to_owned(),
        locations: vec![key_location.clone()],
        evidence: Evidence::RlsProbe {
            project: project.clone(),
            table: table.to_owned(),
            endpoint: endpoint.to_owned(),
            observed_row_count,
            exposure: vibescan_types::RlsExposure::Exposed,
        },
        remediation: "Enable and tighten RLS policies for this table, then rerun the read probe to confirm anonymous reads no longer return rows.".to_owned(),
        related: Vec::new(),
        confidence: Confidence::Confirmed,
    }
}
