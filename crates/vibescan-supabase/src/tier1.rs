use super::*;

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
pub(super) struct SupabaseDbTarget {
    host: String,
    port: u16,
    project_ref: String,
}

impl SupabaseDbTarget {
    pub(super) fn endpoint(&self) -> String {
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
/// Successful catalog facts are converted into Tier 1 findings. Query failures
/// remain nonfatal and suppress only conclusions that require the missing
/// catalog facts.
pub fn introspect_tier1_with_source(
    source: &impl PgCatalogSource,
    input: &Tier1IntrospectInput,
) -> Result<Tier1IntrospectOutput, IntrospectError> {
    let target = validate_supabase_db_url(&input.db_url, Some(&input.project))?;
    let endpoint = target.endpoint();
    let mut output = Tier1IntrospectOutput::default();

    let table_states = record_catalog_result(
        &mut output,
        &endpoint,
        CatalogQueryKind::TablesWithRowSecurity,
        None,
        source.tables_with_rowsecurity(),
    );

    for table in &input.candidate_tables {
        let policies = record_catalog_result(
            &mut output,
            &endpoint,
            CatalogQueryKind::Policies,
            Some(table),
            source.policies_for(table),
        );
        let grants = record_catalog_result(
            &mut output,
            &endpoint,
            CatalogQueryKind::Grants,
            Some(table),
            source.grants_for(table),
        );

        let Some(table_states) = table_states.as_deref() else {
            continue;
        };
        for table_state in table_states
            .iter()
            .filter(|state| catalog_table_matches(table, &state.schema, &state.table))
        {
            output.findings.extend(detect_tier1_table_findings(
                input,
                table,
                table_state,
                policies.as_deref(),
                grants.as_deref(),
            ));
        }
    }

    output
        .findings
        .sort_by(|left, right| left.id.cmp(&right.id));
    output.findings.dedup_by(|left, right| left.id == right.id);

    Ok(output)
}

pub(super) fn record_catalog_result<T>(
    output: &mut Tier1IntrospectOutput,
    endpoint: &str,
    query: CatalogQueryKind,
    table: Option<&str>,
    result: Result<Vec<T>, IntrospectError>,
) -> Option<Vec<T>> {
    let (outcome, rows) = match result {
        Ok(rows) => (NetworkActionOutcome::CatalogRead, Some(rows)),
        Err(_) => {
            output
                .warnings
                .push(Tier1IntrospectWarning::CatalogQueryUnavailable {
                    host: endpoint.to_owned(),
                    query,
                    table: table.map(str::to_owned),
                });
            (NetworkActionOutcome::TransportError, None)
        }
    };
    output.actions.push(NetworkActionAudit {
        kind: NetworkActionKind::CatalogIntrospection,
        intent: NetworkActionIntent::Select,
        endpoint: endpoint.to_owned(),
        table: table.map(str::to_owned),
        package: None,
        status: None,
        outcome,
        observed_row_count: None,
    });
    rows
}

pub(super) const POLICY_COMMANDS: [&str; 4] = ["SELECT", "INSERT", "UPDATE", "DELETE"];
pub(super) const WRITE_COMMANDS: [&str; 3] = ["INSERT", "UPDATE", "DELETE"];

pub(super) fn detect_tier1_table_findings(
    input: &Tier1IntrospectInput,
    candidate_table: &str,
    table_state: &TableRls,
    policies: Option<&[PolicyRow]>,
    grants: Option<&[GrantRow]>,
) -> Vec<Finding> {
    // This mechanically decidable E2 pass intentionally does not infer that a
    // predicate is keyed on user-writable metadata. Architecture section 17.8
    // defers that noisy Review heuristic outside the confirmed finding set.
    let table = evidence_table_name(candidate_table, table_state);
    if !table_state.rowsecurity {
        return vec![rls_policy_finding(
            input,
            &table,
            "ALL",
            None,
            None,
            false,
            RlsExposure::RlsDisabled,
            Severity::Critical,
            format!("Supabase table {table} has RLS disabled"),
            "Credentialed Tier 1 catalog introspection confirmed that row-level security is disabled for this API-exposed table.".to_owned(),
            "Enable row-level security and add least-privilege policies for every intended API operation.".to_owned(),
            None,
        )];
    }

    let Some(policies) = policies else {
        return Vec::new();
    };
    let table_policies = policies
        .iter()
        .filter(|policy| policy.schema == table_state.schema && policy.table == table_state.table)
        .collect::<Vec<_>>();
    let mut findings = Vec::new();

    for policy in &table_policies {
        let Some(using_expr) = policy.using_expr.as_deref() else {
            continue;
        };
        if policy.permissive && is_literal_true(using_expr) {
            let command = normalized_policy_command(&policy.command);
            findings.push(rls_policy_finding(
                input,
                &table,
                &command,
                policy.using_expr.clone(),
                policy.check_expr.clone(),
                true,
                RlsExposure::PermissivePolicy,
                Severity::Critical,
                format!("Supabase table {table} has a literal-true {command} policy"),
                "Credentialed Tier 1 catalog introspection confirmed a permissive policy whose USING predicate is the literal true, so that policy does not restrict the operation.".to_owned(),
                "Replace the literal-true predicate with a least-privilege condition tied to the authenticated subject and intended rows.".to_owned(),
                Some(&command),
            ));
        }
    }

    if !table_policies.is_empty() {
        for command in POLICY_COMMANDS {
            if !table_policies
                .iter()
                .any(|policy| policy_covers_command(policy, command))
            {
                findings.push(rls_policy_finding(
                    input,
                    &table,
                    command,
                    None,
                    None,
                    true,
                    RlsExposure::MissingOperationPolicy,
                    Severity::Medium,
                    format!("Supabase table {table} has no {command} policy"),
                    format!("Credentialed Tier 1 catalog introspection confirmed that RLS is enabled and other policies exist, but no policy covers {command}. The operation is denied by default for anon/authenticated roles when no permissive policy applies; table owners and BYPASSRLS roles are exceptions. Verify that this secure default is the intended API behavior."),
                    format!("Add an explicit least-privilege {command} policy if the operation is intended, or document and test that the default denial is required."),
                    None,
                ));
            }
        }
    }

    if let Some(grants) = grants {
        for grant in grants.iter().filter(|grant| {
            grant.schema == table_state.schema
                && grant.table == table_state.table
                && is_api_role(&grant.grantee)
                && WRITE_COMMANDS
                    .iter()
                    .any(|command| grant.privilege.eq_ignore_ascii_case(command))
                && !table_policies
                    .iter()
                    .any(|policy| policy_covers_command(policy, &grant.privilege))
        }) {
            let command = grant.privilege.trim().to_ascii_uppercase();
            let grantee = grant.grantee.trim().to_ascii_lowercase();
            findings.push(rls_policy_finding(
                input,
                &table,
                &command,
                None,
                None,
                true,
                RlsExposure::InferredWriteExposure,
                Severity::High,
                format!("Supabase table {table} has inferred {command} exposure for {grantee}"),
                format!("Write exposure is inferred from the {grantee} role's {command} grant plus the absence of a policy covering {command}; no write was attempted."),
                format!("Revoke the {command} grant from {grantee} unless it is required, and add a least-privilege {command} policy before enabling the operation."),
                Some(&grantee),
            ));
        }
    }

    findings
}

#[allow(clippy::too_many_arguments)]
pub(super) fn rls_policy_finding(
    input: &Tier1IntrospectInput,
    table: &str,
    command: &str,
    using_expr: Option<String>,
    check_expr: Option<String>,
    rowsecurity: bool,
    exposure: RlsExposure,
    severity: Severity,
    title: String,
    detail: String,
    remediation: String,
    identity_detail: Option<&str>,
) -> Finding {
    let mut hasher = Sha256::new();
    hasher.update(format!("{exposure:?}").as_bytes());
    hasher.update(b"\0");
    hasher.update(input.project.url.trim_end_matches('/').as_bytes());
    hasher.update(b"\0");
    hasher.update(table.as_bytes());
    hasher.update(b"\0");
    hasher.update(command.as_bytes());
    hasher.update(b"\0");
    hasher.update(identity_detail.unwrap_or_default().as_bytes());

    Finding {
        id: FindingId(format!(
            "rls-policy-{}",
            hex::encode(&hasher.finalize()[..12])
        )),
        category: Category::Rls,
        severity,
        title,
        detail,
        locations: vec![input.credential_location.clone()],
        evidence: Evidence::RlsPolicy {
            project: input.project.clone(),
            table: table.to_owned(),
            command: command.to_owned(),
            using_expr,
            check_expr,
            rowsecurity,
            exposure,
        },
        remediation,
        related: Vec::new(),
        confidence: Confidence::Confirmed,
    }
}

pub(super) fn catalog_table_matches(candidate: &str, schema: &str, table: &str) -> bool {
    candidate
        .split_once('.')
        .map_or(candidate == table, |parts| {
            parts.0 == schema && parts.1 == table
        })
}

pub(super) fn evidence_table_name(candidate: &str, table_state: &TableRls) -> String {
    if candidate.contains('.') || table_state.schema == "public" {
        candidate.to_owned()
    } else {
        format!("{}.{}", table_state.schema, table_state.table)
    }
}

pub(super) fn normalized_policy_command(command: &str) -> String {
    command.trim().to_ascii_uppercase()
}

pub(super) fn policy_covers_command(policy: &PolicyRow, command: &str) -> bool {
    let policy_command = normalized_policy_command(&policy.command);
    policy_command == "ALL" || policy_command.eq_ignore_ascii_case(command.trim())
}

pub(super) fn is_api_role(role: &str) -> bool {
    matches!(
        role.trim().to_ascii_lowercase().as_str(),
        "anon" | "authenticated"
    )
}

pub(super) fn is_literal_true(expression: &str) -> bool {
    let mut normalized = expression.trim();
    while let Some(inner) = strip_balanced_outer_parentheses(normalized) {
        normalized = inner.trim();
    }
    normalized.eq_ignore_ascii_case("true")
}

pub(super) fn strip_balanced_outer_parentheses(expression: &str) -> Option<&str> {
    let expression = expression.trim();
    if !expression.starts_with('(') || !expression.ends_with(')') {
        return None;
    }

    let mut depth = 0_u64;
    for (index, character) in expression.char_indices() {
        match character {
            '(' => depth += 1,
            ')' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 && index + character.len_utf8() != expression.len() {
                    return None;
                }
            }
            _ => {}
        }
    }
    (depth == 0).then(|| &expression[1..expression.len() - 1])
}

pub(super) fn validate_supabase_db_url(
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

pub(super) fn valid_pooler_host(host: &str) -> bool {
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

pub(super) fn project_ref_from_project_url(url: &str) -> Option<&str> {
    url.trim_end_matches('/')
        .strip_prefix("https://")?
        .strip_suffix(SUPABASE_URL_SUFFIX)
        .filter(|project_ref| is_valid_project_ref(project_ref))
}
