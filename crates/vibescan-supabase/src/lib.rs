//! Supabase domain intelligence.
//!
//! By default this crate is LocalStatic only: it classifies Supabase key
//! candidates and emits linkable findings. The Tier 0 read probe is compiled
//! only with the `network` feature and must be explicitly enabled by callers.

use std::collections::BTreeSet;
use std::fmt;
#[cfg(feature = "network")]
use std::sync::Mutex;
#[cfg(feature = "network")]
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::Value;
use sha2::{Digest, Sha256};
use url::Url;
use vibescan_types::{
    CandidateKind, Category, Confidence, Evidence, Finding, FindingId, Location,
    NetworkActionAudit, NetworkActionIntent, NetworkActionKind, NetworkActionOutcome,
    SecretCandidate, SecretFingerprint, Severity, SupabaseKeyClass, SupabaseProject,
};

const SUPABASE_URL_SUFFIX: &str = ".supabase.co";

/// LocalStatic classifier for Supabase-shaped candidates.
#[derive(Debug, Default)]
pub struct SupabaseClassifier;

impl SupabaseClassifier {
    pub fn new() -> Self {
        Self
    }

    /// Classify one candidate. Non-Supabase candidate kinds are ignored.
    pub fn classify_candidate(&self, candidate: &SecretCandidate) -> Option<Finding> {
        self.classify_candidate_with_unit_content(candidate, None)
    }

    /// Classify one candidate with optional access to the source unit content.
    /// New publishable keys are opaque, so source content can provide a
    /// co-located `https://<ref>.supabase.co` project URL.
    pub fn classify_candidate_with_unit_content(
        &self,
        candidate: &SecretCandidate,
        unit_content: Option<&[u8]>,
    ) -> Option<Finding> {
        if candidate.kind != CandidateKind::PossibleSupabaseKey {
            return None;
        }

        let raw = std::str::from_utf8(&candidate.raw_match).ok()?;
        let project_hint = unit_content
            .and_then(|content| std::str::from_utf8(content).ok())
            .and_then(project_from_text);
        let classification = classify_raw_key(raw, project_hint);
        Some(classification.into_finding(candidate, raw))
    }

    /// Classify many candidates.
    pub fn classify_candidates<'a>(
        &self,
        candidates: impl IntoIterator<Item = &'a SecretCandidate>,
    ) -> Vec<Finding> {
        candidates
            .into_iter()
            .filter_map(|candidate| self.classify_candidate(candidate))
            .collect()
    }
}

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

/// Inputs for opt-in, credentialed Tier 1 catalog introspection.
#[derive(Clone, Eq, PartialEq)]
pub struct Tier1IntrospectInput {
    pub project: SupabaseProject,
    pub db_url: String,
    pub credential_location: Location,
    pub candidate_tables: BTreeSet<String>,
}

impl fmt::Debug for Tier1IntrospectInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Tier1IntrospectInput")
            .field("project", &self.project)
            .field("db_url", &"***redacted***")
            .field("credential_location", &self.credential_location)
            .field("candidate_tables", &self.candidate_tables)
            .finish()
    }
}

/// Read-only facts returned by the table catalog query.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TableRls {
    pub schema: String,
    pub table: String,
    pub rowsecurity: bool,
}

/// Read-only facts returned by `pg_catalog.pg_policies`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyRow {
    pub schema: String,
    pub table: String,
    pub policy: String,
    pub command: String,
    pub permissive: bool,
    pub roles: Vec<String>,
    pub using_expr: Option<String>,
    pub check_expr: Option<String>,
}

/// Read-only facts returned by `information_schema.role_table_grants`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrantRow {
    pub schema: String,
    pub table: String,
    pub grantee: String,
    pub privilege: String,
}

/// Catalog query category used in warnings and sanitized errors.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CatalogQueryKind {
    TablesWithRowSecurity,
    Policies,
    Grants,
}

impl fmt::Display for CatalogQueryKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TablesWithRowSecurity => formatter.write_str("table RLS state"),
            Self::Policies => formatter.write_str("table policies"),
            Self::Grants => formatter.write_str("table grants"),
        }
    }
}

/// Injectable seam for Tier 1 tests. Implementations return catalog metadata,
/// never application table contents.
pub trait PgCatalogSource {
    fn tables_with_rowsecurity(&self) -> Result<Vec<TableRls>, IntrospectError>;
    fn policies_for(&self, table: &str) -> Result<Vec<PolicyRow>, IntrospectError>;
    fn grants_for(&self, table: &str) -> Result<Vec<GrantRow>, IntrospectError>;
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Tier1IntrospectOutput {
    pub findings: Vec<Finding>,
    pub warnings: Vec<Tier1IntrospectWarning>,
    pub actions: Vec<NetworkActionAudit>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Tier1IntrospectWarning {
    CatalogQueryUnavailable {
        host: String,
        query: CatalogQueryKind,
        table: Option<String>,
    },
}

impl Tier1IntrospectWarning {
    pub fn message(&self) -> String {
        match self {
            Self::CatalogQueryUnavailable { host, query, table } => {
                let table = table
                    .as_deref()
                    .map(|table| format!(" for table {table}"))
                    .unwrap_or_default();
                format!("Tier 1 catalog {query} query failed at {host}{table}")
            }
        }
    }
}

/// Sanitized Tier 1 failure. Connection strings and database error bodies are
/// deliberately excluded because they may contain credentials or schema data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IntrospectError {
    InvalidDatabaseUrl {
        reason: &'static str,
    },
    ProjectMismatch {
        expected: String,
        actual: String,
    },
    ConnectionFailed {
        host: String,
    },
    CatalogQueryFailed {
        query: CatalogQueryKind,
        table: Option<String>,
    },
}

impl fmt::Display for IntrospectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDatabaseUrl { reason } => {
                write!(formatter, "Tier 1 refused database URL: {reason}")
            }
            Self::ProjectMismatch { expected, actual } => write!(
                formatter,
                "Tier 1 database project mismatch: expected {expected}, got {actual}"
            ),
            Self::ConnectionFailed { host } => {
                write!(formatter, "Tier 1 database connection failed for {host}")
            }
            Self::CatalogQueryFailed { query, table } => {
                let table = table
                    .as_deref()
                    .map(|table| format!(" for table {table}"))
                    .unwrap_or_default();
                write!(formatter, "Tier 1 catalog {query} query failed{table}")
            }
        }
    }
}

impl std::error::Error for IntrospectError {}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SupabaseDbTarget {
    host: String,
    port: u16,
    project_ref: String,
}

impl SupabaseDbTarget {
    fn endpoint(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

/// Derive the owning Supabase project from a validated database URL.
pub fn project_from_db_url(db_url: &str) -> Result<SupabaseProject, IntrospectError> {
    let target = validate_supabase_db_url(db_url, None)?;
    Ok(SupabaseProject {
        ref_id: Some(target.project_ref.clone()),
        url: format!("https://{}{}", target.project_ref, SUPABASE_URL_SUFFIX),
    })
}

/// Run Tier 1 catalog reads through an injected source.
///
/// E1 establishes the transport, audit, and failure seams. The returned rows
/// are intentionally not retained yet; E2 consumes them to emit findings.
pub fn introspect_tier1_with_source(
    source: &impl PgCatalogSource,
    input: &Tier1IntrospectInput,
) -> Result<Tier1IntrospectOutput, IntrospectError> {
    let target = validate_supabase_db_url(&input.db_url, Some(&input.project))?;
    let endpoint = target.endpoint();
    let mut output = Tier1IntrospectOutput::default();

    record_catalog_result(
        &mut output,
        &endpoint,
        CatalogQueryKind::TablesWithRowSecurity,
        None,
        source.tables_with_rowsecurity(),
    );

    for table in &input.candidate_tables {
        record_catalog_result(
            &mut output,
            &endpoint,
            CatalogQueryKind::Policies,
            Some(table),
            source.policies_for(table),
        );
        record_catalog_result(
            &mut output,
            &endpoint,
            CatalogQueryKind::Grants,
            Some(table),
            source.grants_for(table),
        );
    }

    Ok(output)
}

fn record_catalog_result<T>(
    output: &mut Tier1IntrospectOutput,
    endpoint: &str,
    query: CatalogQueryKind,
    table: Option<&str>,
    result: Result<Vec<T>, IntrospectError>,
) {
    let outcome = if result.is_ok() {
        NetworkActionOutcome::CatalogRead
    } else {
        output
            .warnings
            .push(Tier1IntrospectWarning::CatalogQueryUnavailable {
                host: endpoint.to_owned(),
                query,
                table: table.map(str::to_owned),
            });
        NetworkActionOutcome::TransportError
    };
    output.actions.push(NetworkActionAudit {
        kind: NetworkActionKind::CatalogIntrospection,
        intent: NetworkActionIntent::Select,
        endpoint: endpoint.to_owned(),
        table: table.map(str::to_owned),
        status: None,
        outcome,
        observed_row_count: None,
    });
}

fn validate_supabase_db_url(
    db_url: &str,
    expected_project: Option<&SupabaseProject>,
) -> Result<SupabaseDbTarget, IntrospectError> {
    let parsed = Url::parse(db_url).map_err(|_| IntrospectError::InvalidDatabaseUrl {
        reason: "expected a postgres:// or postgresql:// connection URL",
    })?;
    if !matches!(parsed.scheme(), "postgres" | "postgresql") {
        return Err(IntrospectError::InvalidDatabaseUrl {
            reason: "scheme must be postgres or postgresql",
        });
    }
    if parsed.fragment().is_some() {
        return Err(IntrospectError::InvalidDatabaseUrl {
            reason: "fragments are not allowed",
        });
    }
    for (key, value) in parsed.query_pairs() {
        if matches!(key.as_ref(), "host" | "hostaddr" | "port") {
            return Err(IntrospectError::InvalidDatabaseUrl {
                reason: "host and port overrides are not allowed",
            });
        }
        if key == "sslmode" && !matches!(value.as_ref(), "require" | "verify-ca" | "verify-full") {
            return Err(IntrospectError::InvalidDatabaseUrl {
                reason: "TLS cannot be disabled or downgraded",
            });
        }
    }

    let host = parsed
        .host_str()
        .ok_or(IntrospectError::InvalidDatabaseUrl {
            reason: "database host is required",
        })?
        .to_ascii_lowercase();
    let port = parsed.port().unwrap_or(5432);
    if !matches!(port, 5432 | 6543) {
        return Err(IntrospectError::InvalidDatabaseUrl {
            reason: "only Supabase database ports 5432 and 6543 are allowed",
        });
    }

    let project_ref = if let Some(rest) = host.strip_prefix("db.") {
        let Some(project_ref) = rest.strip_suffix(SUPABASE_URL_SUFFIX) else {
            return Err(IntrospectError::InvalidDatabaseUrl {
                reason: "host is not a Supabase database host",
            });
        };
        if !is_valid_project_ref(project_ref) {
            return Err(IntrospectError::InvalidDatabaseUrl {
                reason: "database host has an invalid project reference",
            });
        }
        project_ref.to_owned()
    } else if host.ends_with(".pooler.supabase.com") && valid_pooler_host(&host) {
        let username = parsed.username();
        let Some((_, project_ref)) = username.rsplit_once('.') else {
            return Err(IntrospectError::InvalidDatabaseUrl {
                reason: "Supabase pooler username must include the project reference",
            });
        };
        if !is_valid_project_ref(project_ref) {
            return Err(IntrospectError::InvalidDatabaseUrl {
                reason: "Supabase pooler username has an invalid project reference",
            });
        }
        project_ref.to_owned()
    } else {
        return Err(IntrospectError::InvalidDatabaseUrl {
            reason: "host is not a Supabase database or pooler host",
        });
    };

    if let Some(expected) = expected_project {
        let expected_ref = expected
            .ref_id
            .as_deref()
            .or_else(|| project_ref_from_project_url(&expected.url))
            .ok_or(IntrospectError::InvalidDatabaseUrl {
                reason: "expected project has no valid Supabase reference",
            })?;
        if expected_ref != project_ref {
            return Err(IntrospectError::ProjectMismatch {
                expected: expected_ref.to_owned(),
                actual: project_ref,
            });
        }
    }

    Ok(SupabaseDbTarget {
        host,
        port,
        project_ref,
    })
}

fn valid_pooler_host(host: &str) -> bool {
    let prefix = host
        .strip_suffix(".pooler.supabase.com")
        .unwrap_or_default();
    !prefix.is_empty()
        && prefix.split('.').all(|segment| {
            !segment.is_empty()
                && segment
                    .chars()
                    .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
        })
}

fn project_ref_from_project_url(url: &str) -> Option<&str> {
    url.trim_end_matches('/')
        .strip_prefix("https://")?
        .strip_suffix(SUPABASE_URL_SUFFIX)
        .filter(|project_ref| is_valid_project_ref(project_ref))
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

fn network_action(
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

#[cfg(feature = "network")]
const TABLE_RLS_QUERY: &str = r#"
SELECT
    n.nspname::text AS schema_name,
    c.relname::text AS table_name,
    c.relrowsecurity::text AS rowsecurity
FROM pg_catalog.pg_class AS c
JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
WHERE c.relkind IN ('r', 'p')
  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
ORDER BY n.nspname, c.relname
"#;

/// The sole production Tier 1 catalog source. Construction validates the
/// destination before opening a socket and configures rustls certificate
/// verification with the public WebPKI root set.
#[cfg(feature = "network")]
pub struct PostgresPgCatalogSource {
    client: Mutex<postgres::Client>,
}

#[cfg(feature = "network")]
impl fmt::Debug for PostgresPgCatalogSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostgresPgCatalogSource")
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "network")]
impl PostgresPgCatalogSource {
    pub fn connect(input: &Tier1IntrospectInput) -> Result<Self, IntrospectError> {
        let target = validate_supabase_db_url(&input.db_url, Some(&input.project))?;
        let mut config = input.db_url.parse::<postgres::Config>().map_err(|_| {
            IntrospectError::InvalidDatabaseUrl {
                reason: "connection URL is not valid PostgreSQL configuration",
            }
        })?;
        config
            .ssl_mode(postgres::config::SslMode::Require)
            .connect_timeout(Duration::from_secs(10));

        let roots =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let tls = tokio_postgres_rustls::MakeRustlsConnect::new(tls_config);
        let client = config
            .connect(tls)
            .map_err(|_| IntrospectError::ConnectionFailed {
                host: target.endpoint(),
            })?;
        Ok(Self {
            client: Mutex::new(client),
        })
    }

    fn simple_query(
        &self,
        query: &str,
        kind: CatalogQueryKind,
        table: Option<&str>,
    ) -> Result<Vec<postgres::SimpleQueryMessage>, IntrospectError> {
        if !catalog_query_is_read_only(query) {
            return Err(IntrospectError::CatalogQueryFailed {
                query: kind,
                table: table.map(str::to_owned),
            });
        }
        let mut client = self
            .client
            .lock()
            .map_err(|_| IntrospectError::CatalogQueryFailed {
                query: kind,
                table: table.map(str::to_owned),
            })?;
        client
            .simple_query(query)
            .map_err(|_| IntrospectError::CatalogQueryFailed {
                query: kind,
                table: table.map(str::to_owned),
            })
    }
}

#[cfg(feature = "network")]
impl PgCatalogSource for PostgresPgCatalogSource {
    fn tables_with_rowsecurity(&self) -> Result<Vec<TableRls>, IntrospectError> {
        let messages = self.simple_query(
            TABLE_RLS_QUERY,
            CatalogQueryKind::TablesWithRowSecurity,
            None,
        )?;
        Ok(messages
            .iter()
            .filter_map(|message| {
                let postgres::SimpleQueryMessage::Row(row) = message else {
                    return None;
                };
                Some(TableRls {
                    schema: row.get("schema_name")?.to_owned(),
                    table: row.get("table_name")?.to_owned(),
                    rowsecurity: matches!(row.get("rowsecurity"), Some("t" | "true")),
                })
            })
            .collect())
    }

    fn policies_for(&self, table: &str) -> Result<Vec<PolicyRow>, IntrospectError> {
        let query = policies_query(table);
        let messages = self.simple_query(&query, CatalogQueryKind::Policies, Some(table))?;
        Ok(messages
            .iter()
            .filter_map(|message| {
                let postgres::SimpleQueryMessage::Row(row) = message else {
                    return None;
                };
                Some(PolicyRow {
                    schema: row.get("schema_name")?.to_owned(),
                    table: row.get("table_name")?.to_owned(),
                    policy: row.get("policy_name")?.to_owned(),
                    command: row.get("command")?.to_owned(),
                    permissive: matches!(
                        row.get("permissive"),
                        Some("PERMISSIVE" | "YES" | "t" | "true")
                    ),
                    roles: parse_pg_text_array(row.get("roles").unwrap_or_default()),
                    using_expr: row.get("using_expr").map(str::to_owned),
                    check_expr: row.get("check_expr").map(str::to_owned),
                })
            })
            .collect())
    }

    fn grants_for(&self, table: &str) -> Result<Vec<GrantRow>, IntrospectError> {
        let query = grants_query(table);
        let messages = self.simple_query(&query, CatalogQueryKind::Grants, Some(table))?;
        Ok(messages
            .iter()
            .filter_map(|message| {
                let postgres::SimpleQueryMessage::Row(row) = message else {
                    return None;
                };
                Some(GrantRow {
                    schema: row.get("schema_name")?.to_owned(),
                    table: row.get("table_name")?.to_owned(),
                    grantee: row.get("grantee")?.to_owned(),
                    privilege: row.get("privilege")?.to_owned(),
                })
            })
            .collect())
    }
}

#[cfg(feature = "network")]
pub fn introspect_tier1(
    input: &Tier1IntrospectInput,
) -> Result<Tier1IntrospectOutput, IntrospectError> {
    let source = PostgresPgCatalogSource::connect(input)?;
    introspect_tier1_with_source(&source, input)
}

#[cfg(feature = "network")]
fn split_table_name(table: &str) -> (Option<&str>, &str) {
    table
        .split_once('.')
        .map_or((None, table), |(schema, table)| (Some(schema), table))
}

#[cfg(feature = "network")]
fn policies_query(table: &str) -> String {
    let (schema, table_name) = split_table_name(table);
    let filter = catalog_table_filter(schema, table_name, "schemaname", "tablename");
    format!(
        r#"
SELECT
    schemaname::text AS schema_name,
    tablename::text AS table_name,
    policyname::text AS policy_name,
    permissive::text AS permissive,
    roles::text AS roles,
    cmd::text AS command,
    qual::text AS using_expr,
    with_check::text AS check_expr
FROM pg_catalog.pg_policies
WHERE {filter}
ORDER BY schemaname, tablename, policyname
"#
    )
}

#[cfg(feature = "network")]
fn grants_query(table: &str) -> String {
    let (schema, table_name) = split_table_name(table);
    let filter = catalog_table_filter(schema, table_name, "table_schema", "table_name");
    format!(
        r#"
SELECT
    table_schema::text AS schema_name,
    table_name::text AS table_name,
    grantee::text AS grantee,
    privilege_type::text AS privilege
FROM information_schema.role_table_grants
WHERE {filter}
ORDER BY table_schema, table_name, grantee, privilege_type
"#
    )
}

#[cfg(feature = "network")]
fn catalog_query_is_read_only(query: &str) -> bool {
    let normalized = query.trim_start().to_ascii_uppercase();
    normalized.starts_with("SELECT")
        && !["INSERT ", "UPDATE ", "DELETE ", "ALTER ", "DROP ", "SET "]
            .iter()
            .any(|forbidden| normalized.contains(forbidden))
}

#[cfg(feature = "network")]
fn catalog_table_filter(
    schema: Option<&str>,
    table: &str,
    schema_column: &str,
    table_column: &str,
) -> String {
    let table = escape_sql_literal(table);
    match schema {
        Some(schema) => format!(
            "{table_column} = '{table}' AND {schema_column} = '{}'",
            escape_sql_literal(schema)
        ),
        None => format!("{table_column} = '{table}'"),
    }
}

#[cfg(feature = "network")]
fn escape_sql_literal(value: &str) -> String {
    value.replace('\'', "''")
}

#[cfg(feature = "network")]
fn parse_pg_text_array(value: &str) -> Vec<String> {
    value
        .trim_matches(|ch| matches!(ch, '{' | '}'))
        .split(',')
        .map(|role| role.trim_matches('"').trim())
        .filter(|role| !role.is_empty())
        .map(str::to_owned)
        .collect()
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct KeyClassification {
    class: SupabaseKeyClass,
    severity: Severity,
    confidence: Confidence,
    project: Option<SupabaseProject>,
    title: String,
    detail: String,
    remediation: String,
}

impl KeyClassification {
    fn into_finding(self, candidate: &SecretCandidate, raw: &str) -> Finding {
        let fingerprint = fingerprint(raw);
        let locations = candidate
            .unit_ref
            .locations
            .iter()
            .map(|location| Location {
                path: location.path.clone(),
                span: Some(candidate.span),
                provenance: location.provenance.clone(),
                additional_provenance: location.additional_provenance.clone(),
                location_class: location.location_class,
            })
            .collect::<Vec<_>>();
        let id = finding_id(
            &self.class,
            &fingerprint,
            locations
                .first()
                .expect("candidates retain a source location"),
        );

        Finding {
            id,
            category: if is_elevated(self.class) {
                Category::SecretExposure
            } else {
                Category::KeyClassification
            },
            severity: self.severity,
            title: self.title,
            detail: self.detail,
            locations,
            evidence: Evidence::SupabaseKey {
                class: self.class,
                redacted: redact_secret(raw),
                project: self.project,
                fingerprint,
            },
            remediation: self.remediation,
            related: Vec::new(),
            confidence: self.confidence,
        }
    }
}

fn classify_raw_key(raw: &str, project_hint: Option<SupabaseProject>) -> KeyClassification {
    if raw.starts_with("sb_publishable_") {
        return low_privilege(
            SupabaseKeyClass::PublishableNew,
            project_hint,
            "Supabase publishable key found",
            "A new-format Supabase publishable key was found. This key is low privilege by itself and must be evaluated together with RLS exposure.",
        );
    }

    if raw.starts_with("sb_secret_") {
        return elevated(
            SupabaseKeyClass::SecretNew,
            project_hint,
            "Supabase secret key exposed",
            "A new-format Supabase secret key was found. Secret keys are elevated credentials and bypass RLS.",
        );
    }

    if let Some(payload) = decode_legacy_jwt_payload(raw) {
        let role = payload.get("role").and_then(Value::as_str);
        let issuer = payload.get("iss").and_then(Value::as_str);
        let project = project_from_payload(&payload);

        if issuer.is_some_and(indicates_supabase) {
            return match role {
                Some("anon") => low_privilege(
                    SupabaseKeyClass::AnonLegacy,
                    project,
                    "Supabase legacy anon key found",
                    "A legacy Supabase anon JWT was found. This key is low privilege by itself and must be evaluated together with RLS exposure.",
                ),
                Some("service_role") => elevated(
                    SupabaseKeyClass::ServiceRoleLegacy,
                    project,
                    "Supabase legacy service_role key exposed",
                    "A legacy Supabase service_role JWT was found. Service role keys are elevated credentials and bypass RLS.",
                ),
                _ => unknown("Supabase-shaped JWT has no recognized Supabase role"),
            };
        }
    }

    unknown(
        "The value matched a Supabase-shaped rule but could not be classified as a known Supabase key class.",
    )
}

fn low_privilege(
    class: SupabaseKeyClass,
    project: Option<SupabaseProject>,
    title: &str,
    detail: &str,
) -> KeyClassification {
    KeyClassification {
        class,
        severity: Severity::Info,
        confidence: Confidence::Likely,
        project,
        title: title.to_owned(),
        detail: detail.to_owned(),
        remediation: "Keep the public key client-side only if RLS policies are correct. Enable network probing later to verify table exposure.".to_owned(),
    }
}

fn elevated(
    class: SupabaseKeyClass,
    project: Option<SupabaseProject>,
    title: &str,
    detail: &str,
) -> KeyClassification {
    KeyClassification {
        class,
        severity: Severity::Critical,
        confidence: Confidence::Likely,
        project,
        title: title.to_owned(),
        detail: detail.to_owned(),
        remediation: "Rotate the key immediately, remove it from the repository, and rewrite git history if the key was committed.".to_owned(),
    }
}

fn unknown(detail: &str) -> KeyClassification {
    KeyClassification {
        class: SupabaseKeyClass::Unknown,
        severity: Severity::Low,
        confidence: Confidence::Review,
        project: None,
        title: "Supabase-shaped key requires review".to_owned(),
        detail: detail.to_owned(),
        remediation: "Review the value and remove it if it is a real Supabase credential."
            .to_owned(),
    }
}

fn decode_legacy_jwt_payload(raw: &str) -> Option<Value> {
    let mut parts = raw.split('.');
    let _header = parts.next()?;
    let payload = parts.next()?;
    let _signature = parts.next()?;
    if parts.next().is_some() {
        return None;
    }

    let decoded = URL_SAFE_NO_PAD.decode(payload).ok()?;
    serde_json::from_slice(&decoded).ok()
}

fn project_from_payload(payload: &Value) -> Option<SupabaseProject> {
    let ref_id = payload.get("ref").and_then(Value::as_str)?;
    Some(SupabaseProject {
        ref_id: Some(ref_id.to_owned()),
        url: format!("https://{ref_id}{SUPABASE_URL_SUFFIX}"),
    })
}

fn project_from_text(text: &str) -> Option<SupabaseProject> {
    for (index, _) in text.match_indices("https://") {
        let after_scheme = &text[index + "https://".len()..];
        let Some(ref_end) = after_scheme.find(SUPABASE_URL_SUFFIX) else {
            continue;
        };
        let ref_id = &after_scheme[..ref_end];
        if is_valid_project_ref(ref_id) {
            return Some(SupabaseProject {
                ref_id: Some(ref_id.to_owned()),
                url: format!("https://{ref_id}{SUPABASE_URL_SUFFIX}"),
            });
        }
    }
    None
}

fn is_valid_project_ref(ref_id: &str) -> bool {
    !ref_id.is_empty()
        && ref_id
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
}

fn indicates_supabase(issuer: &str) -> bool {
    issuer.eq_ignore_ascii_case("supabase")
        || issuer.to_ascii_lowercase().contains(SUPABASE_URL_SUFFIX)
}

fn is_elevated(class: SupabaseKeyClass) -> bool {
    matches!(
        class,
        SupabaseKeyClass::SecretNew | SupabaseKeyClass::ServiceRoleLegacy
    )
}

fn finding_id(
    class: &SupabaseKeyClass,
    fingerprint: &SecretFingerprint,
    location: &Location,
) -> FindingId {
    let mut hasher = Sha256::new();
    hasher.update(format!("{class:?}").as_bytes());
    hasher.update(b"\0");
    hasher.update(fingerprint.0.as_bytes());
    hasher.update(b"\0");
    hasher.update(location.path.0.as_bytes());
    FindingId(format!(
        "supabase-key-{}",
        hex::encode(&hasher.finalize()[..12])
    ))
}

fn fingerprint(raw: &str) -> SecretFingerprint {
    let mut hasher = Sha256::new();
    hasher.update(raw.as_bytes());
    SecretFingerprint(hex::encode(&hasher.finalize()[..16]))
}

fn redact_secret(raw: &str) -> String {
    let chars = raw.chars().collect::<Vec<_>>();
    if chars.len() <= 12 {
        return "***".to_owned();
    }

    let prefix = chars.iter().take(6).collect::<String>();
    let suffix = chars
        .iter()
        .rev()
        .take(4)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<String>();
    format!("{prefix}...{suffix}")
}

fn normalized_supabase_url(url: &str) -> Result<String, RlsProbeError> {
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

fn public_key_headers(public_key: &str, accept: &str) -> Vec<(String, String)> {
    vec![
        ("apikey".to_owned(), public_key.to_owned()),
        ("authorization".to_owned(), format!("Bearer {public_key}")),
        ("accept".to_owned(), accept.to_owned()),
    ]
}

fn tables_from_openapi(body: &str) -> Result<Vec<String>, RlsProbeError> {
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

fn dedup_probe_warnings(warnings: &mut Vec<Tier0RlsProbeWarning>) {
    let mut seen = BTreeSet::new();
    warnings.retain(|warning| seen.insert(probe_warning_cause_key(warning)));
}

fn probe_warning_cause_key(warning: &Tier0RlsProbeWarning) -> String {
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

fn rls_exposed_finding(
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

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use vibescan_types::{
        ContentId, LocationClass, Provenance, RepoPath, RuleId, Span, UnitLocation, UnitRef,
    };

    use super::*;

    fn candidate(raw: &str, location_class: LocationClass) -> SecretCandidate {
        SecretCandidate {
            rule_id: RuleId("supabase-key-shaped".to_owned()),
            kind: CandidateKind::PossibleSupabaseKey,
            raw_match: raw.as_bytes().to_vec(),
            entropy: 4.0,
            unit_ref: UnitRef {
                content_id: ContentId([1; 32]),
                locations: vec![UnitLocation {
                    path: RepoPath("src/app.tsx".to_owned()),
                    provenance: Provenance::WorkingTree,
                    additional_provenance: Vec::new(),
                    location_class,
                }],
            },
            span: Span {
                line: 1,
                col_start: 1,
                col_end: raw.len() as u32,
            },
        }
    }

    #[test]
    fn classifies_new_publishable_key_as_info() {
        let finding = SupabaseClassifier::new()
            .classify_candidate(&candidate(
                "sb_publishable_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
                LocationClass::ClientReachable,
            ))
            .expect("finding emitted");

        assert_eq!(finding.category, Category::KeyClassification);
        assert_eq!(finding.severity, Severity::Info);
        assert!(matches!(
            finding.evidence,
            Evidence::SupabaseKey {
                class: SupabaseKeyClass::PublishableNew,
                ..
            }
        ));
    }

    #[test]
    fn finding_retains_every_candidate_source_location_with_the_same_span() {
        let raw = "sb_publishable_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";
        let mut candidate = candidate(raw, LocationClass::ServerOnly);
        candidate.unit_ref.locations.push(UnitLocation {
            path: RepoPath("apps/web/.next/static/chunks/config.js".to_owned()),
            provenance: Provenance::WorkingTree,
            additional_provenance: Vec::new(),
            location_class: LocationClass::ClientReachable,
        });

        let finding = SupabaseClassifier::new()
            .classify_candidate(&candidate)
            .expect("finding emitted");

        assert_eq!(finding.locations.len(), 2);
        assert!(
            finding
                .locations
                .iter()
                .all(|location| location.span == Some(candidate.span))
        );
        assert_eq!(
            finding
                .locations
                .iter()
                .map(|location| location.path.0.as_str())
                .collect::<Vec<_>>(),
            vec!["src/app.tsx", "apps/web/.next/static/chunks/config.js"]
        );
    }

    #[test]
    fn content_id_does_not_change_public_finding_identity() {
        let raw = "sb_publishable_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";
        let first = candidate(raw, LocationClass::ClientReachable);
        let mut second = first.clone();
        second.unit_ref.content_id = ContentId([9; 32]);
        let classifier = SupabaseClassifier::new();

        let first = classifier
            .classify_candidate(&first)
            .expect("first finding emitted");
        let second = classifier
            .classify_candidate(&second)
            .expect("second finding emitted");

        assert_eq!(first.id, second.id);
    }

    #[test]
    fn classifies_new_publishable_key_with_colocated_project_url() {
        let raw = "sb_publishable_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";
        let content = format!(
            "const url = 'https://abcdefghijklmnopqrst.supabase.co';\nconst key = '{raw}';\n"
        );
        let finding = SupabaseClassifier::new()
            .classify_candidate_with_unit_content(
                &candidate(raw, LocationClass::ClientReachable),
                Some(content.as_bytes()),
            )
            .expect("finding emitted");

        let Evidence::SupabaseKey { class, project, .. } = finding.evidence else {
            panic!("expected Supabase evidence");
        };

        assert_eq!(class, SupabaseKeyClass::PublishableNew);
        assert_eq!(finding.severity, Severity::Info);
        let project = project.expect("co-located project URL extracted");
        assert_eq!(project.ref_id.as_deref(), Some("abcdefghijklmnopqrst"));
        assert_eq!(project.url, "https://abcdefghijklmnopqrst.supabase.co");
    }

    #[test]
    fn classifies_new_secret_key_with_colocated_project_url() {
        let raw = "sb_secret_0123456789abcdefghijklmnopqrstuvwxyzABCDEF";
        let content = format!(
            "const url = 'https://abcdefghijklmnopqrst.supabase.co';\nconst key = '{raw}';\n"
        );
        let finding = SupabaseClassifier::new()
            .classify_candidate_with_unit_content(
                &candidate(raw, LocationClass::ServerOnly),
                Some(content.as_bytes()),
            )
            .expect("finding emitted");

        let Evidence::SupabaseKey { class, project, .. } = finding.evidence else {
            panic!("expected Supabase evidence");
        };

        assert_eq!(class, SupabaseKeyClass::SecretNew);
        assert_eq!(finding.severity, Severity::Critical);
        assert_eq!(
            project.expect("co-located project URL extracted").url,
            "https://abcdefghijklmnopqrst.supabase.co"
        );
    }

    #[test]
    fn classifies_new_secret_key_as_critical_when_client_reachable() {
        let finding = SupabaseClassifier::new()
            .classify_candidate(&candidate(
                "sb_secret_0123456789abcdefghijklmnopqrstuvwxyzABCDEF",
                LocationClass::ClientReachable,
            ))
            .expect("finding emitted");

        assert_eq!(finding.category, Category::SecretExposure);
        assert_eq!(finding.severity, Severity::Critical);
    }

    #[test]
    fn classifies_legacy_anon_jwt_and_project_ref() {
        let raw =
            jwt_with_payload(r#"{"iss":"supabase","role":"anon","ref":"abcdefghijklmnopqrst"}"#);
        let finding = SupabaseClassifier::new()
            .classify_candidate(&candidate(&raw, LocationClass::ClientReachable))
            .expect("finding emitted");

        let Evidence::SupabaseKey { class, project, .. } = finding.evidence else {
            panic!("expected Supabase evidence");
        };

        assert_eq!(class, SupabaseKeyClass::AnonLegacy);
        assert_eq!(finding.severity, Severity::Info);
        assert_eq!(
            project.expect("project").url,
            "https://abcdefghijklmnopqrst.supabase.co"
        );
    }

    #[test]
    fn classifies_legacy_service_role_as_elevated() {
        let raw = jwt_with_payload(
            r#"{"iss":"https://abcdefghijklmnopqrst.supabase.co/auth/v1","role":"service_role","ref":"abcdefghijklmnopqrst"}"#,
        );
        let finding = SupabaseClassifier::new()
            .classify_candidate(&candidate(&raw, LocationClass::ServerOnly))
            .expect("finding emitted");

        assert_eq!(finding.severity, Severity::Critical);
        assert!(matches!(
            finding.evidence,
            Evidence::SupabaseKey {
                class: SupabaseKeyClass::ServiceRoleLegacy,
                ..
            }
        ));
    }

    #[test]
    fn classifies_committed_secret_as_critical_even_when_server_only() {
        let mut candidate = candidate(
            "sb_secret_0123456789abcdefghijklmnopqrstuvwxyzABCDEF",
            LocationClass::ServerOnly,
        );
        candidate.unit_ref.locations[0].provenance = Provenance::Commit {
            sha: "abc123".to_owned(),
            author: None,
            date: None,
        };

        let finding = SupabaseClassifier::new()
            .classify_candidate(&candidate)
            .expect("finding emitted");

        assert_eq!(finding.severity, Severity::Critical);
    }

    #[test]
    fn ignores_non_supabase_candidate_kinds() {
        let mut candidate = candidate(
            "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890",
            LocationClass::Unknown,
        );
        candidate.kind = CandidateKind::ProviderSecret;

        assert!(
            SupabaseClassifier::new()
                .classify_candidate(&candidate)
                .is_none()
        );
    }

    #[test]
    fn tier0_read_probe_emits_exposed_table_without_row_data() {
        let client = FakeRlsClient::new([
            (
                "https://abcdefghijklmnopqrst.supabase.co/rest/v1/",
                RlsHttpResponse {
                    status: 200,
                    body: r#"{"paths":{"/profiles":{"get":{}},"/rpc/ping":{"post":{}}}}"#
                        .to_owned(),
                },
            ),
            (
                "https://abcdefghijklmnopqrst.supabase.co/rest/v1/profiles?select=*&limit=1",
                RlsHttpResponse {
                    status: 200,
                    body: r#"[{"id":1,"email":"not included in finding"}]"#.to_owned(),
                },
            ),
        ]);
        let input = tier0_input();

        let output = probe_tier0_read_with_client(&client, &input).expect("probe succeeds");

        client.assert_all_requests_include_apikey(&input.public_key);
        assert_eq!(output.warnings, Vec::new());
        assert_eq!(output.findings.len(), 1);
        assert_eq!(output.actions.len(), client.request_count());
        assert_eq!(
            output.actions[0].outcome,
            NetworkActionOutcome::RootEnumerated
        );
        assert_eq!(output.actions[1].outcome, NetworkActionOutcome::Exposed);
        assert_eq!(output.actions[1].observed_row_count, Some(1));
        assert!(output.actions[0].observed_row_count.is_none());
        let finding = &output.findings[0];
        assert_eq!(finding.category, Category::Rls);
        assert_eq!(finding.severity, Severity::Critical);
        let Evidence::RlsProbe {
            project,
            table,
            endpoint,
            observed_row_count,
            exposure,
        } = &finding.evidence
        else {
            panic!("expected RLS evidence");
        };
        assert_eq!(project.url, "https://abcdefghijklmnopqrst.supabase.co");
        assert_eq!(table, "profiles");
        assert_eq!(
            endpoint,
            "https://abcdefghijklmnopqrst.supabase.co/rest/v1/profiles?select=*&limit=1"
        );
        assert_eq!(*observed_row_count, 1);
        assert_eq!(*exposure, vibescan_types::RlsExposure::Exposed);
        assert!(!format!("{finding:?}").contains("not included in finding"));
        let serialized_actions = serde_json::to_string(&output.actions).expect("actions serialize");
        assert!(!serialized_actions.contains(&input.public_key));
        assert!(!serialized_actions.contains("apikey"));
        assert!(!serialized_actions.contains("not included in finding"));
    }

    #[test]
    fn tier0_read_probe_omits_protected_or_empty_tables() {
        let client = FakeRlsClient::new([
	            (
	                "https://abcdefghijklmnopqrst.supabase.co/rest/v1/",
	                RlsHttpResponse {
	                    status: 200,
	                    body: r#"{"paths":{"/private_table":{"get":{}},"/empty_table":{"get":{}},"/missing_table":{"get":{}}}}"#
	                        .to_owned(),
	                },
	            ),
            (
                "https://abcdefghijklmnopqrst.supabase.co/rest/v1/empty_table?select=*&limit=1",
                RlsHttpResponse {
                    status: 200,
                    body: "[]".to_owned(),
	                },
	            ),
	            (
	                "https://abcdefghijklmnopqrst.supabase.co/rest/v1/missing_table?select=*&limit=1",
	                RlsHttpResponse {
	                    status: 404,
	                    body: r#"{"message":"not found"}"#.to_owned(),
	                },
	            ),
	            (
	                "https://abcdefghijklmnopqrst.supabase.co/rest/v1/private_table?select=*&limit=1",
	                RlsHttpResponse {
                    status: 403,
                    body: r#"{"message":"forbidden"}"#.to_owned(),
                },
            ),
        ]);

        let output = probe_tier0_read_with_client(&client, &tier0_input()).expect("probe succeeds");

        client.assert_all_requests_include_apikey(&tier0_input().public_key);
        assert!(output.findings.is_empty());
        assert_eq!(output.warnings, Vec::new());
        assert_eq!(output.actions.len(), client.request_count());
        assert_eq!(
            output
                .actions
                .iter()
                .map(|action| action.outcome)
                .collect::<Vec<_>>(),
            vec![
                NetworkActionOutcome::RootEnumerated,
                NetworkActionOutcome::NoRowsObserved,
                NetworkActionOutcome::NotFound,
                NetworkActionOutcome::Protected,
            ]
        );
        assert!(
            output
                .actions
                .iter()
                .all(|action| action.observed_row_count.is_none())
        );
    }

    #[test]
    fn tier0_read_probe_audits_invalid_responses_without_response_material() {
        let client = FakeRlsClient::new([
            (
                "https://abcdefghijklmnopqrst.supabase.co/rest/v1/",
                RlsHttpResponse {
                    status: 500,
                    body: "sensitive root response".to_owned(),
                },
            ),
            (
                "https://abcdefghijklmnopqrst.supabase.co/rest/v1/profiles?select=*&limit=1",
                RlsHttpResponse {
                    status: 200,
                    body: r#"{"sensitive":"not an array"}"#.to_owned(),
                },
            ),
        ]);
        let input = tier0_input_with_tables(["profiles"]);

        let output = probe_tier0_read_with_client(&client, &input).expect("probe succeeds");

        assert_eq!(output.actions.len(), client.request_count());
        assert!(
            output
                .actions
                .iter()
                .all(|action| action.outcome == NetworkActionOutcome::InvalidResponse)
        );
        let serialized_actions = serde_json::to_string(&output.actions).expect("actions serialize");
        assert!(!serialized_actions.contains("sensitive"));
        assert!(!serialized_actions.contains(&input.public_key));
    }

    #[test]
    fn tier0_read_probe_audits_transport_errors_for_each_attempt() {
        let client = FakeRlsClient::default();
        let input = tier0_input_with_tables(["profiles"]);

        let output = probe_tier0_read_with_client(&client, &input).expect("probe succeeds");

        assert_eq!(output.actions.len(), 2);
        assert_eq!(output.actions.len(), client.request_count());
        assert!(output.actions.iter().all(|action| {
            action.status.is_none() && action.outcome == NetworkActionOutcome::TransportError
        }));
    }

    #[test]
    fn tier0_read_probe_continues_after_root_unavailable_with_harvested_tables() {
        let client = FakeRlsClient::new([
            (
                "https://abcdefghijklmnopqrst.supabase.co/rest/v1/",
                RlsHttpResponse {
                    status: 403,
                    body: r#"{"message":"forbidden"}"#.to_owned(),
                },
            ),
            (
                "https://abcdefghijklmnopqrst.supabase.co/rest/v1/profiles?select=*&limit=1",
                RlsHttpResponse {
                    status: 200,
                    body: r#"[{"id":1}]"#.to_owned(),
                },
            ),
        ]);
        let input = tier0_input_with_tables(["profiles"]);

        let output = probe_tier0_read_with_client(&client, &input).expect("probe succeeds");

        client.assert_all_requests_include_apikey(&input.public_key);
        assert_eq!(output.findings.len(), 1);
        assert_eq!(output.actions.len(), client.request_count());
        assert_eq!(
            output.actions[0].outcome,
            NetworkActionOutcome::RootUnavailable
        );
        assert_eq!(output.actions[0].status, Some(403));
        assert_eq!(output.actions[1].outcome, NetworkActionOutcome::Exposed);
        assert!(matches!(
            output.warnings.as_slice(),
            [Tier0RlsProbeWarning::RootEnumerationUnavailable { status: 403, .. }]
        ));
        assert!(
            output.warnings[0]
                .message()
                .contains("root enumeration unavailable with public key")
        );
    }

    #[test]
    fn tier0_read_probe_reserves_key_rejected_for_table_request() {
        let client = FakeRlsClient::new([
            (
                "https://abcdefghijklmnopqrst.supabase.co/rest/v1/",
                RlsHttpResponse {
                    status: 200,
                    body: r#"{"paths":{"/profiles":{"get":{}}}}"#.to_owned(),
                },
            ),
            (
                "https://abcdefghijklmnopqrst.supabase.co/rest/v1/profiles?select=*&limit=1",
                RlsHttpResponse {
                    status: 401,
                    body: r#"{"message":"invalid api key"}"#.to_owned(),
                },
            ),
        ]);
        let input = tier0_input_with_tables(["profiles"]);

        let output = probe_tier0_read_with_client(&client, &input).expect("probe succeeds");

        client.assert_all_requests_include_apikey(&input.public_key);
        assert!(output.findings.is_empty());
        assert_eq!(output.actions.len(), client.request_count());
        assert_eq!(output.actions[1].outcome, NetworkActionOutcome::KeyRejected);
        assert_eq!(output.actions[1].status, Some(401));
        assert!(matches!(
            output.warnings.as_slice(),
            [Tier0RlsProbeWarning::KeyRejected { .. }]
        ));
    }

    #[test]
    fn root_unauthorized_but_table_readable_is_not_reported_as_key_rejection() {
        let client = FakeRlsClient::new([
            (
                "https://abcdefghijklmnopqrst.supabase.co/rest/v1/",
                RlsHttpResponse {
                    status: 401,
                    body: r#"{"message":"root enumeration unavailable"}"#.to_owned(),
                },
            ),
            (
                "https://abcdefghijklmnopqrst.supabase.co/rest/v1/profiles?select=*&limit=1",
                RlsHttpResponse {
                    status: 200,
                    body: r#"[{"id":1}]"#.to_owned(),
                },
            ),
        ]);
        let input = tier0_input_with_tables(["profiles"]);

        let output = probe_tier0_read_with_client(&client, &input).expect("probe succeeds");

        client.assert_all_requests_include_apikey(&input.public_key);
        assert_eq!(output.findings.len(), 1);
        assert!(output.warnings.iter().any(|warning| matches!(
            warning,
            Tier0RlsProbeWarning::RootEnumerationUnavailable { status: 401, .. }
        )));
        assert!(
            !output
                .warnings
                .iter()
                .any(|warning| matches!(warning, Tier0RlsProbeWarning::KeyRejected { .. }))
        );
    }

    #[test]
    fn root_unauthorized_and_table_unauthorized_report_distinct_outcomes() {
        let client = FakeRlsClient::new([
            (
                "https://abcdefghijklmnopqrst.supabase.co/rest/v1/",
                RlsHttpResponse {
                    status: 401,
                    body: r#"{"message":"root enumeration unavailable"}"#.to_owned(),
                },
            ),
            (
                "https://abcdefghijklmnopqrst.supabase.co/rest/v1/profiles?select=*&limit=1",
                RlsHttpResponse {
                    status: 401,
                    body: r#"{"message":"invalid api key"}"#.to_owned(),
                },
            ),
        ]);
        let input = tier0_input_with_tables(["profiles"]);

        let output = probe_tier0_read_with_client(&client, &input).expect("probe succeeds");

        client.assert_all_requests_include_apikey(&input.public_key);
        assert!(output.findings.is_empty());
        assert!(output.warnings.iter().any(|warning| matches!(
            warning,
            Tier0RlsProbeWarning::RootEnumerationUnavailable { status: 401, .. }
        )));
        assert!(
            output
                .warnings
                .iter()
                .any(|warning| matches!(warning, Tier0RlsProbeWarning::KeyRejected { .. }))
        );
    }

    #[test]
    fn tier0_read_probe_warns_when_there_are_no_candidate_tables() {
        let client = FakeRlsClient::new([(
            "https://abcdefghijklmnopqrst.supabase.co/rest/v1/",
            RlsHttpResponse {
                status: 403,
                body: r#"{"message":"forbidden"}"#.to_owned(),
            },
        )]);
        let input = tier0_input();

        let output = probe_tier0_read_with_client(&client, &input).expect("probe succeeds");

        assert!(output.findings.is_empty());
        assert_eq!(output.warnings.len(), 2);
        assert!(output.warnings.iter().any(|warning| matches!(
            warning,
            Tier0RlsProbeWarning::RootEnumerationUnavailable { status: 403, .. }
        )));
        assert!(
            output
                .warnings
                .iter()
                .any(|warning| matches!(warning, Tier0RlsProbeWarning::NoCandidateTables { .. }))
        );
    }

    #[test]
    fn tier0_read_probe_refuses_non_supabase_urls() {
        let client = FakeRlsClient::default();
        let mut input = tier0_input();
        input.project.url = "https://example.com".to_owned();

        let error =
            probe_tier0_read_with_client(&client, &input).expect_err("invalid URL rejected");

        assert!(matches!(error, RlsProbeError::InvalidProjectUrl(_)));
    }

    #[test]
    fn tier1_mock_catalog_is_read_only_auditable_and_redacted() {
        let source = FakePgCatalog::default();
        let input = tier1_input(
            "postgresql://postgres:raw-db-password@db.abcdefghijklmnopqrst.supabase.co:5432/postgres",
        );
        assert!(!format!("{input:?}").contains("raw-db-password"));

        let output =
            introspect_tier1_with_source(&source, &input).expect("mock introspection succeeds");

        assert!(output.findings.is_empty(), "E1 does not emit E2 detections");
        assert!(output.warnings.is_empty());
        assert_eq!(
            source.calls.borrow().as_slice(),
            [
                (CatalogQueryKind::TablesWithRowSecurity, None),
                (CatalogQueryKind::Policies, Some("profiles".to_owned())),
                (CatalogQueryKind::Grants, Some("profiles".to_owned())),
            ]
        );
        assert_eq!(output.actions.len(), 3);
        assert!(output.actions.iter().all(|action| {
            action.kind == NetworkActionKind::CatalogIntrospection
                && action.intent == NetworkActionIntent::Select
                && action.endpoint == "db.abcdefghijklmnopqrst.supabase.co:5432"
                && action.outcome == NetworkActionOutcome::CatalogRead
                && action.status.is_none()
                && action.observed_row_count.is_none()
        }));

        let serialized = serde_json::to_string(&output.actions).expect("actions serialize");
        for forbidden in [
            "raw-db-password",
            "credential-row-marker",
            "owner_id = auth.uid()",
        ] {
            assert!(
                !serialized.contains(forbidden),
                "actions leaked {forbidden}"
            );
        }
    }

    #[test]
    fn tier1_catalog_failure_is_nonfatal_and_sanitized() {
        let source = FakePgCatalog {
            fail: Some(CatalogQueryKind::Policies),
            ..FakePgCatalog::default()
        };
        let input = tier1_input(
            "postgres://postgres:raw-db-password@db.abcdefghijklmnopqrst.supabase.co/postgres",
        );

        let output = introspect_tier1_with_source(&source, &input).expect("query failure degrades");

        assert_eq!(output.warnings.len(), 1);
        assert!(output.warnings[0].message().contains("table policies"));
        assert_eq!(
            output.actions[1].outcome,
            NetworkActionOutcome::TransportError
        );
        let serialized = serde_json::to_string(&output.actions).expect("actions serialize");
        assert!(!serialized.contains("raw-db-password"));
    }

    #[test]
    fn tier1_refuses_non_supabase_hosts_schemes_ports_and_overrides_before_queries() {
        for db_url in [
            "postgres://postgres:pw@example.com:5432/postgres",
            "https://postgres:pw@db.abcdefghijklmnopqrst.supabase.co:5432/postgres",
            "postgres://postgres:pw@db.abcdefghijklmnopqrst.supabase.co:7777/postgres",
            "postgres://postgres:pw@db.abcdefghijklmnopqrst.supabase.co:5432/postgres?host=example.com",
            "postgres://postgres:pw@db.abcdefghijklmnopqrst.supabase.co:5432/postgres?sslmode=disable",
            "postgres://postgres:pw@aws-0-us-east-1.pooler.supabase.com:5432/postgres",
        ] {
            let source = FakePgCatalog::default();
            let input = tier1_input(db_url);

            let error = introspect_tier1_with_source(&source, &input)
                .expect_err("unsafe destination must be rejected");

            assert!(matches!(error, IntrospectError::InvalidDatabaseUrl { .. }));
            assert!(
                source.calls.borrow().is_empty(),
                "source was queried for {db_url}"
            );
        }
    }

    #[test]
    fn tier1_accepts_supabase_direct_and_pooler_hosts_for_the_same_project() {
        let direct = project_from_db_url(
            "postgresql://postgres:pw@db.abcdefghijklmnopqrst.supabase.co:6543/postgres",
        )
        .expect("dedicated pooler accepted");
        let shared = project_from_db_url(
            "postgres://postgres.abcdefghijklmnopqrst:pw@aws-0-us-east-1.pooler.supabase.com:5432/postgres",
        )
        .expect("shared pooler accepted");

        assert_eq!(direct, shared);
        assert_eq!(direct.ref_id.as_deref(), Some("abcdefghijklmnopqrst"));
    }

    #[test]
    fn tier1_rejects_database_project_mismatch_before_queries() {
        let source = FakePgCatalog::default();
        let input =
            tier1_input("postgres://postgres:pw@db.zyxwvutsrqponmlkjihg.supabase.co:5432/postgres");

        let error = introspect_tier1_with_source(&source, &input)
            .expect_err("known-different project rejected");

        assert!(matches!(error, IntrospectError::ProjectMismatch { .. }));
        assert!(source.calls.borrow().is_empty());
    }

    #[cfg(feature = "network")]
    #[test]
    fn production_catalog_queries_are_select_only() {
        for query in [
            TABLE_RLS_QUERY.to_owned(),
            policies_query("public.profiles"),
            grants_query("public.profiles"),
        ] {
            assert!(catalog_query_is_read_only(&query), "unsafe query: {query}");
        }
        assert!(!catalog_query_is_read_only("SET ROLE postgres"));
        assert!(!catalog_query_is_read_only("DELETE FROM profiles"));
    }

    fn jwt_with_payload(payload: &str) -> String {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(payload.as_bytes());
        let signature = "abcdefghijklmnopqrstuvwxyz1234567890";
        format!("{header}.{payload}.{signature}")
    }

    fn tier0_input() -> Tier0RlsProbeInput {
        tier0_input_with_tables([])
    }

    fn tier0_input_with_tables<const N: usize>(tables: [&str; N]) -> Tier0RlsProbeInput {
        Tier0RlsProbeInput {
            project: SupabaseProject {
                ref_id: Some("abcdefghijklmnopqrst".to_owned()),
                url: "https://abcdefghijklmnopqrst.supabase.co".to_owned(),
            },
            public_key: "sb_publishable_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789".to_owned(),
            key_location: Location {
                path: RepoPath("src/app.tsx".to_owned()),
                span: None,
                provenance: Provenance::WorkingTree,
                additional_provenance: Vec::new(),
                location_class: LocationClass::ClientReachable,
            },
            candidate_tables: tables.into_iter().map(str::to_owned).collect(),
        }
    }

    fn tier1_input(db_url: &str) -> Tier1IntrospectInput {
        Tier1IntrospectInput {
            project: SupabaseProject {
                ref_id: Some("abcdefghijklmnopqrst".to_owned()),
                url: "https://abcdefghijklmnopqrst.supabase.co".to_owned(),
            },
            db_url: db_url.to_owned(),
            credential_location: Location {
                path: RepoPath("<environment>".to_owned()),
                span: None,
                provenance: Provenance::WorkingTree,
                additional_provenance: Vec::new(),
                location_class: LocationClass::ServerOnly,
            },
            candidate_tables: BTreeSet::from(["profiles".to_owned()]),
        }
    }

    #[derive(Default)]
    struct FakePgCatalog {
        calls: RefCell<Vec<(CatalogQueryKind, Option<String>)>>,
        fail: Option<CatalogQueryKind>,
    }

    impl FakePgCatalog {
        fn record(
            &self,
            query: CatalogQueryKind,
            table: Option<&str>,
        ) -> Result<(), IntrospectError> {
            self.calls
                .borrow_mut()
                .push((query, table.map(str::to_owned)));
            if self.fail == Some(query) {
                return Err(IntrospectError::CatalogQueryFailed {
                    query,
                    table: table.map(str::to_owned),
                });
            }
            Ok(())
        }
    }

    impl PgCatalogSource for FakePgCatalog {
        fn tables_with_rowsecurity(&self) -> Result<Vec<TableRls>, IntrospectError> {
            self.record(CatalogQueryKind::TablesWithRowSecurity, None)?;
            Ok(vec![TableRls {
                schema: "public".to_owned(),
                table: "profiles".to_owned(),
                rowsecurity: true,
            }])
        }

        fn policies_for(&self, table: &str) -> Result<Vec<PolicyRow>, IntrospectError> {
            self.record(CatalogQueryKind::Policies, Some(table))?;
            Ok(vec![PolicyRow {
                schema: "public".to_owned(),
                table: table.to_owned(),
                policy: "credential-row-marker".to_owned(),
                command: "SELECT".to_owned(),
                permissive: true,
                roles: vec!["anon".to_owned()],
                using_expr: Some("owner_id = auth.uid()".to_owned()),
                check_expr: None,
            }])
        }

        fn grants_for(&self, table: &str) -> Result<Vec<GrantRow>, IntrospectError> {
            self.record(CatalogQueryKind::Grants, Some(table))?;
            Ok(vec![GrantRow {
                schema: "public".to_owned(),
                table: table.to_owned(),
                grantee: "anon".to_owned(),
                privilege: "SELECT".to_owned(),
            }])
        }
    }

    #[derive(Default)]
    struct FakeRlsClient {
        responses: BTreeMap<String, RlsHttpResponse>,
        requests: RefCell<Vec<FakeRlsRequest>>,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct FakeRlsRequest {
        url: String,
        headers: Vec<(String, String)>,
    }

    impl FakeRlsClient {
        fn new<const N: usize>(responses: [(&str, RlsHttpResponse); N]) -> Self {
            Self {
                responses: responses
                    .into_iter()
                    .map(|(url, response)| (url.to_owned(), response))
                    .collect(),
                requests: RefCell::new(Vec::new()),
            }
        }

        fn assert_all_requests_include_apikey(&self, public_key: &str) {
            let requests = self.requests.borrow();
            assert!(!requests.is_empty(), "probe should issue requests");
            for request in requests.iter() {
                assert!(
                    request
                        .headers
                        .iter()
                        .any(|(name, value)| name == "apikey" && value == public_key),
                    "{} did not include matching apikey header: {:?}",
                    request.url,
                    request.headers
                );
            }
        }

        fn request_count(&self) -> usize {
            self.requests.borrow().len()
        }
    }

    impl RlsHttpClient for FakeRlsClient {
        fn get(
            &self,
            url: &str,
            headers: &[(String, String)],
        ) -> Result<RlsHttpResponse, RlsProbeError> {
            self.requests.borrow_mut().push(FakeRlsRequest {
                url: url.to_owned(),
                headers: headers.to_vec(),
            });
            self.responses
                .get(url)
                .cloned()
                .ok_or_else(|| RlsProbeError::Http {
                    url: url.to_owned(),
                    status: None,
                    source: "missing fake response".to_owned(),
                })
        }
    }
}
