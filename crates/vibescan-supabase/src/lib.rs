//! Supabase domain intelligence.
//!
//! By default this crate is LocalStatic only: it classifies Supabase key
//! candidates and emits linkable findings. The Tier 0 read probe is compiled
//! only with the `network` feature and must be explicitly enabled by callers.

use std::fmt;
#[cfg(feature = "network")]
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::Value;
use sha2::{Digest, Sha256};
use vibescan_types::{
    CandidateKind, Category, Confidence, Evidence, Finding, FindingId, Location, LocationClass,
    Provenance, SecretCandidate, SecretFingerprint, Severity, SupabaseKeyClass, SupabaseProject,
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
        let classification = classify_raw_key(
            raw,
            candidate.unit_ref.location_class,
            &candidate.unit_ref.provenance,
            project_hint,
        );
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
    Http { url: String, source: String },
    InvalidProjectUrl(String),
    Json(serde_json::Error),
    OpenApi { url: String, status: u16 },
}

impl fmt::Display for RlsProbeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Http { url, source } => {
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
/// This function never writes to the target project. It enumerates PostgREST
/// OpenAPI paths, performs read-only `select=*&limit=1` requests, and emits
/// findings only for tables that return rows to the public key.
pub fn probe_tier0_read_with_client(
    client: &impl RlsHttpClient,
    input: &Tier0RlsProbeInput,
) -> Result<Vec<Finding>, RlsProbeError> {
    let base_url = normalized_supabase_url(&input.project.url)?;
    let headers = public_key_headers(&input.public_key, "application/openapi+json");
    let openapi_url = format!("{base_url}/rest/v1/");
    let openapi = client.get(&openapi_url, &headers)?;
    if openapi.status != 200 {
        return Err(RlsProbeError::OpenApi {
            url: openapi_url,
            status: openapi.status,
        });
    }

    let tables = tables_from_openapi(&openapi.body)?;
    let mut findings = Vec::new();
    for table in tables {
        let endpoint = format!("{base_url}/rest/v1/{table}?select=*&limit=1");
        let headers = public_key_headers(&input.public_key, "application/json");
        let response = client.get(&endpoint, &headers)?;
        if response.status == 401 || response.status == 403 {
            continue;
        }
        if response.status != 200 {
            continue;
        }

        let body = serde_json::from_str::<Value>(&response.body).map_err(RlsProbeError::Json)?;
        let observed_row_count = body.as_array().map_or(0, Vec::len) as u64;
        if observed_row_count > 0 {
            findings.push(rls_exposed_finding(
                &input.project,
                &input.key_location,
                &table,
                &endpoint,
                observed_row_count,
            ));
        }
    }

    Ok(findings)
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
            source: source.to_string(),
        })?;
        let status = response.status().as_u16();
        let body = response.text().map_err(|source| RlsProbeError::Http {
            url: url.to_owned(),
            source: source.to_string(),
        })?;
        Ok(RlsHttpResponse { status, body })
    }
}

#[cfg(feature = "network")]
pub fn probe_tier0_read(input: &Tier0RlsProbeInput) -> Result<Vec<Finding>, RlsProbeError> {
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
        let location = Location {
            path: candidate.unit_ref.path.clone(),
            span: Some(candidate.span),
            provenance: candidate.unit_ref.provenance.clone(),
            additional_provenance: candidate.unit_ref.additional_provenance.clone(),
            location_class: candidate.unit_ref.location_class,
        };
        let id = finding_id(&self.class, &fingerprint, &location);

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
            locations: vec![location],
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

fn classify_raw_key(
    raw: &str,
    location_class: LocationClass,
    provenance: &Provenance,
    project_hint: Option<SupabaseProject>,
) -> KeyClassification {
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
            location_class,
            provenance,
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
                    location_class,
                    provenance,
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
    _location_class: LocationClass,
    _provenance: &Provenance,
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
    use std::collections::BTreeMap;

    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use vibescan_secrets::{Detector, working_tree_unit};
    use vibescan_types::{RepoPath, RuleId, Span, UnitRef};

    use super::*;

    fn candidate(raw: &str, location_class: LocationClass) -> SecretCandidate {
        SecretCandidate {
            rule_id: RuleId("supabase-key-shaped".to_owned()),
            kind: CandidateKind::PossibleSupabaseKey,
            raw_match: raw.as_bytes().to_vec(),
            entropy: 4.0,
            unit_ref: UnitRef {
                path: RepoPath("src/app.tsx".to_owned()),
                provenance: Provenance::WorkingTree,
                additional_provenance: Vec::new(),
                location_class,
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
        candidate.unit_ref.provenance = Provenance::Commit {
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

        let findings = probe_tier0_read_with_client(&client, &input).expect("probe succeeds");

        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
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
    }

    #[test]
    fn tier0_read_probe_omits_protected_or_empty_tables() {
        let client = FakeRlsClient::new([
            (
                "https://abcdefghijklmnopqrst.supabase.co/rest/v1/",
                RlsHttpResponse {
                    status: 200,
                    body: r#"{"paths":{"/private_table":{"get":{}},"/empty_table":{"get":{}}}}"#
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
                "https://abcdefghijklmnopqrst.supabase.co/rest/v1/private_table?select=*&limit=1",
                RlsHttpResponse {
                    status: 403,
                    body: r#"{"message":"forbidden"}"#.to_owned(),
                },
            ),
        ]);

        let findings =
            probe_tier0_read_with_client(&client, &tier0_input()).expect("probe succeeds");

        assert!(findings.is_empty());
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
        }
    }

    #[derive(Default)]
    struct FakeRlsClient {
        responses: BTreeMap<String, RlsHttpResponse>,
    }

    impl FakeRlsClient {
        fn new<const N: usize>(responses: [(&str, RlsHttpResponse); N]) -> Self {
            Self {
                responses: responses
                    .into_iter()
                    .map(|(url, response)| (url.to_owned(), response))
                    .collect(),
            }
        }
    }

    impl RlsHttpClient for FakeRlsClient {
        fn get(
            &self,
            url: &str,
            _headers: &[(String, String)],
        ) -> Result<RlsHttpResponse, RlsProbeError> {
            self.responses
                .get(url)
                .cloned()
                .ok_or_else(|| RlsProbeError::Http {
                    url: url.to_owned(),
                    source: "missing fake response".to_owned(),
                })
        }
    }
}
