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

fn tier1_db_url() -> &'static str {
    "postgres://postgres:pw@db.abcdefghijklmnopqrst.supabase.co/postgres"
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

struct FakePgCatalog {
    calls: RefCell<Vec<(CatalogQueryKind, Option<String>)>>,
    fail: Option<CatalogQueryKind>,
    tables: Vec<TableRls>,
    policies: Vec<PolicyRow>,
    grants: Vec<GrantRow>,
}

impl Default for FakePgCatalog {
    fn default() -> Self {
        let mut safe_policy = policy_row("ALL", Some("owner_id = auth.uid()"), true);
        safe_policy.policy = "credential-row-marker".to_owned();
        Self {
            calls: RefCell::new(Vec::new()),
            fail: None,
            tables: vec![table_rls(true)],
            policies: vec![safe_policy],
            grants: vec![grant_row("anon", "SELECT")],
        }
    }
}

impl FakePgCatalog {
    fn record(&self, query: CatalogQueryKind, table: Option<&str>) -> Result<(), IntrospectError> {
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
        Ok(self.tables.clone())
    }

    fn policies_for(&self, table: &str) -> Result<Vec<PolicyRow>, IntrospectError> {
        self.record(CatalogQueryKind::Policies, Some(table))?;
        Ok(self.policies.clone())
    }

    fn grants_for(&self, table: &str) -> Result<Vec<GrantRow>, IntrospectError> {
        self.record(CatalogQueryKind::Grants, Some(table))?;
        Ok(self.grants.clone())
    }
}

fn table_rls(rowsecurity: bool) -> TableRls {
    TableRls {
        schema: "public".to_owned(),
        table: "profiles".to_owned(),
        rowsecurity,
    }
}

fn policy_row(command: &str, using_expr: Option<&str>, permissive: bool) -> PolicyRow {
    PolicyRow {
        schema: "public".to_owned(),
        table: "profiles".to_owned(),
        policy: format!("{command}-policy"),
        command: command.to_owned(),
        permissive,
        roles: vec!["anon".to_owned()],
        using_expr: using_expr.map(str::to_owned),
        check_expr: None,
    }
}

fn grant_row(grantee: &str, privilege: &str) -> GrantRow {
    GrantRow {
        schema: "public".to_owned(),
        table: "profiles".to_owned(),
        grantee: grantee.to_owned(),
        privilege: privilege.to_owned(),
    }
}

struct PolicyEvidenceRef<'a> {
    command: &'a str,
    using_expr: Option<&'a str>,
    rowsecurity: bool,
    exposure: RlsExposure,
}

fn policy_evidence(finding: &Finding) -> PolicyEvidenceRef<'_> {
    let Evidence::RlsPolicy {
        command,
        using_expr,
        rowsecurity,
        exposure,
        ..
    } = &finding.evidence
    else {
        panic!("expected RLS policy evidence")
    };
    PolicyEvidenceRef {
        command,
        using_expr: using_expr.as_deref(),
        rowsecurity: *rowsecurity,
        exposure: *exposure,
    }
}

fn assert_single_tier1_finding(
    output: &Tier1IntrospectOutput,
    exposure: RlsExposure,
    command: &str,
) {
    assert_eq!(output.findings.len(), 1, "{:#?}", output.findings);
    let finding = &output.findings[0];
    let evidence = policy_evidence(finding);
    assert_eq!(finding.category, Category::Rls);
    assert_eq!(finding.confidence, Confidence::Confirmed);
    assert_eq!(evidence.exposure, exposure);
    assert_eq!(evidence.command, command);
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

#[path = "classifier.rs"]
mod classifier_tests;

#[path = "tier0.rs"]
mod tier0_tests;

#[path = "tier1.rs"]
mod tier1_tests;

#[cfg(feature = "network")]
#[path = "catalog.rs"]
mod catalog_tests;
