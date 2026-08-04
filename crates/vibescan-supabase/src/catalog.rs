use super::*;

#[cfg(feature = "network")]
pub(super) const TABLE_RLS_QUERY: &str = r#"
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
pub(super) fn split_table_name(table: &str) -> (Option<&str>, &str) {
    table
        .split_once('.')
        .map_or((None, table), |(schema, table)| (Some(schema), table))
}

#[cfg(feature = "network")]
pub(super) fn policies_query(table: &str) -> String {
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
pub(super) fn grants_query(table: &str) -> String {
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
pub(super) fn catalog_query_is_read_only(query: &str) -> bool {
    let normalized = query.trim_start().to_ascii_uppercase();
    normalized.starts_with("SELECT")
        && !["INSERT ", "UPDATE ", "DELETE ", "ALTER ", "DROP ", "SET "]
            .iter()
            .any(|forbidden| normalized.contains(forbidden))
}

#[cfg(feature = "network")]
pub(super) fn catalog_table_filter(
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
pub(super) fn escape_sql_literal(value: &str) -> String {
    value.replace('\'', "''")
}

#[cfg(feature = "network")]
pub(super) fn parse_pg_text_array(value: &str) -> Vec<String> {
    value
        .trim_matches(|ch| matches!(ch, '{' | '}'))
        .split(',')
        .map(|role| role.trim_matches('"').trim())
        .filter(|role| !role.is_empty())
        .map(str::to_owned)
        .collect()
}
