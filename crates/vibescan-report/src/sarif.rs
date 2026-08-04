use super::*;

pub(super) fn sarif_value(result: &ScanResult) -> Value {
    let rules = result
        .findings
        .iter()
        .map(|finding| {
            json!({
                "id": finding.id.0,
                "name": finding.title,
                "shortDescription": { "text": finding.title },
                "fullDescription": { "text": finding.detail },
                "help": { "text": finding.remediation },
                "properties": {
                    "category": category_name(finding.category),
                    "confidence": confidence_name(finding.confidence),
                    "security-severity": security_severity(finding.severity),
                }
            })
        })
        .collect::<Vec<_>>();

    let results = result
        .findings
        .iter()
        .map(|finding| {
            json!({
                "ruleId": finding.id.0,
                "level": sarif_level(finding.severity),
                "message": {
                    "text": format!("{}: {}", finding.title, evidence_summary(&finding.evidence))
                },
                "locations": sarif_locations(finding),
                "properties": {
                    "severity": severity_name(finding.severity),
                    "category": category_name(finding.category),
                    "confidence": confidence_name(finding.confidence),
                    "related": finding.related.iter().map(|id| id.0.clone()).collect::<Vec<_>>(),
                }
            })
        })
        .collect::<Vec<_>>();

    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "vibescan",
                    "informationUri": "https://github.com/vibescan/vibescan",
                    "version": result.tool_version,
                    "rules": rules,
                }
            },
            "invocations": [{
                "executionSuccessful": true,
                "properties": {
                    "target": result.scope.target,
                    "history": history_summary(&result.scope.history),
                    "networkEnabled": result.scope.network.enabled,
                    "networkActions": &result.scope.network.actions,
                    "registryChecks": result.scope.network.registry_checks,
                    "registryNewcomer": result.scope.network.registry_newcomer,
                    "registryNameEgress": &result.scope.network.registry_name_egress,
                    "scanStats": scan_stats_value(&result.stats),
                    "warnings": result.scope.warnings.iter().map(warning_summary).collect::<Vec<_>>(),
                }
            }],
            "results": results,
        }]
    })
}

pub(super) fn scan_stats_value(stats: &ScanStats) -> Value {
    json!({
        "pathsWalked": stats.paths_walked,
        "blobsRead": stats.blobs_read,
        "uniqueContents": stats.unique_contents,
        "dedupRatioPercent": format!("{:.2}", stats.dedup_ratio() * 100.0),
        "unitsMaterialized": stats.units_materialized,
        "truncated": stats.truncated,
        "scanBudgetHit": stats.scan_budget_hit,
    })
}

pub(super) fn sarif_locations(finding: &Finding) -> Vec<Value> {
    finding
        .locations
        .iter()
        .map(|location| {
            let mut region = json!({});
            if let Some(span) = location.span {
                region = json!({
                    "startLine": span.line,
                    "startColumn": span.col_start,
                    "endColumn": span.col_end,
                });
            }
            json!({
                "physicalLocation": {
                    "artifactLocation": { "uri": location.path.0 },
                    "region": region,
                },
                "properties": {
                    "provenance": provenance_summary(&location.provenance),
                    "locationClass": format!("{:?}", location.location_class),
                }
            })
        })
        .collect()
}

pub(super) fn evidence_summary(evidence: &Evidence) -> String {
    match evidence {
        Evidence::Secret {
            redacted,
            fingerprint,
        } => format!("secret {redacted} fingerprint {}", fingerprint.0),
        Evidence::SupabaseKey {
            class,
            redacted,
            project,
            fingerprint,
        } => {
            let project = project
                .as_ref()
                .map(|project| project.url.as_str())
                .unwrap_or("unknown project");
            format!(
                "{class:?} {redacted} on {project} fingerprint {}",
                fingerprint.0
            )
        }
        Evidence::RlsProbe {
            project,
            table,
            endpoint,
            observed_row_count,
            exposure,
        } => format!(
            "{exposure:?} table {table} on {} via {endpoint}; observed {observed_row_count} row(s)",
            project.url
        ),
        Evidence::RlsPolicy {
            project,
            table,
            command,
            using_expr,
            check_expr,
            rowsecurity,
            exposure,
        } => {
            let rowsecurity = if *rowsecurity { "enabled" } else { "disabled" };
            let using_expr = using_expr.as_deref().unwrap_or("<none>");
            let check_expr = check_expr.as_deref().unwrap_or("<none>");
            format!(
                "{exposure:?} table {table} on {}; command {command}; rowsecurity {rowsecurity}; USING {using_expr}; WITH CHECK {check_expr}",
                project.url
            )
        }
        Evidence::Dependency {
            package,
            manifest_path,
            reason,
        } => format!("{reason:?} dependency {package} in {}", manifest_path.0),
        Evidence::Correlation {
            rule_id,
            reproduction,
        } => reproduction
            .as_ref()
            .map(|reproduction| format!("{}: {reproduction}", rule_id.0))
            .unwrap_or_else(|| rule_id.0.clone()),
        Evidence::Note { message } => message.clone(),
    }
}
