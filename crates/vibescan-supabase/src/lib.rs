//! Supabase domain intelligence.
//!
//! Step 4 is intentionally LocalStatic only: this crate classifies Supabase key
//! candidates and emits linkable findings. RLS probing is deferred to the
//! Network tier.

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
            None,
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
    location_class: LocationClass,
    provenance: &Provenance,
    title: &str,
    detail: &str,
) -> KeyClassification {
    let severity = match (provenance, location_class) {
        (Provenance::Commit { .. }, _) | (_, LocationClass::ClientReachable) => Severity::Critical,
        (_, LocationClass::ServerOnly | LocationClass::Unknown) => Severity::High,
    };

    KeyClassification {
        class,
        severity,
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

#[cfg(test)]
mod tests {
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

        assert_eq!(finding.severity, Severity::High);
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

    fn jwt_with_payload(payload: &str) -> String {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(payload.as_bytes());
        let signature = "abcdefghijklmnopqrstuvwxyz1234567890";
        format!("{header}.{payload}.{signature}")
    }
}
