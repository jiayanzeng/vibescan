use super::*;

pub(super) const SUPABASE_URL_SUFFIX: &str = ".supabase.co";

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
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct KeyClassification {
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

pub(super) fn classify_raw_key(
    raw: &str,
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

pub(super) fn low_privilege(
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

pub(super) fn elevated(
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

pub(super) fn unknown(detail: &str) -> KeyClassification {
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

pub(super) fn decode_legacy_jwt_payload(raw: &str) -> Option<Value> {
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

pub(super) fn project_from_payload(payload: &Value) -> Option<SupabaseProject> {
    let ref_id = payload.get("ref").and_then(Value::as_str)?;
    Some(SupabaseProject {
        ref_id: Some(ref_id.to_owned()),
        url: format!("https://{ref_id}{SUPABASE_URL_SUFFIX}"),
    })
}

pub(super) fn project_from_text(text: &str) -> Option<SupabaseProject> {
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

pub(super) fn is_valid_project_ref(ref_id: &str) -> bool {
    !ref_id.is_empty()
        && ref_id
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
}

pub(super) fn indicates_supabase(issuer: &str) -> bool {
    issuer.eq_ignore_ascii_case("supabase")
        || issuer.to_ascii_lowercase().contains(SUPABASE_URL_SUFFIX)
}

pub(super) fn is_elevated(class: SupabaseKeyClass) -> bool {
    matches!(
        class,
        SupabaseKeyClass::SecretNew | SupabaseKeyClass::ServiceRoleLegacy
    )
}

pub(super) fn finding_id(
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

pub(super) fn fingerprint(raw: &str) -> SecretFingerprint {
    let mut hasher = Sha256::new();
    hasher.update(raw.as_bytes());
    SecretFingerprint(hex::encode(&hasher.finalize()[..16]))
}

pub(super) fn redact_secret(raw: &str) -> String {
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
