//! Supabase domain intelligence.
//!
//! By default this crate is LocalStatic only: it classifies Supabase key
//! candidates and emits linkable findings. The Tier 0 read probe is compiled
//! only with the `network` feature and must be explicitly enabled by callers.

use std::collections::BTreeSet;
use std::fmt;
#[cfg(feature = "network")]
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::Value;
use sha2::{Digest, Sha256};
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
    use vibescan_secrets::{Detector, working_tree_unit};
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
    fn integrates_with_secret_detector_output() {
        let detector = Detector::default_rules().expect("rules compile");
        let unit = working_tree_unit(
            "src/app.tsx",
            "const key = 'sb_secret_0123456789abcdefghijklmnopqrstuvwxyzABCDEF';",
        );
        let candidates = detector.detect_unit(&unit);
        let findings = SupabaseClassifier::new().classify_candidates(&candidates);

        assert!(
            findings
                .iter()
                .any(|finding| finding.category == Category::SecretExposure)
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
