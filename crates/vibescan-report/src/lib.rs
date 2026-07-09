//! Report renderers for `ScanResult`.
//!
//! This crate is rendering-only. It does not decide findings, run scans, or
//! reach the network.

use serde_json::{Value, json};
use vibescan_types::{
    Category, Confidence, Evidence, Finding, HistoryScope, Location, Provenance, ScanResult,
    ScopeWarning, Severity,
};

/// Output format supported by the report crate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReportFormat {
    Json,
    Sarif,
    Tty,
    Html,
}

/// Render a scan result to the requested format.
pub fn render(result: &ScanResult, format: ReportFormat) -> Result<String, serde_json::Error> {
    match format {
        ReportFormat::Json => render_json(result),
        ReportFormat::Sarif => render_sarif(result),
        ReportFormat::Tty => Ok(render_tty(result, TtyStyle::Plain)),
        ReportFormat::Html => Ok(render_html(result)),
    }
}

/// Render machine-readable JSON.
pub fn render_json(result: &ScanResult) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(result)
}

/// Render SARIF 2.1.0 for code-scanning integrations.
pub fn render_sarif(result: &ScanResult) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(&sarif_value(result))
}

/// Render human-readable terminal output.
pub fn render_tty(result: &ScanResult, style: TtyStyle) -> String {
    let mut output = String::new();
    push_line(
        &mut output,
        &format!(
            "vibescan {} - {} finding(s) in {} ms",
            result.tool_version,
            result.findings.len(),
            result.duration_ms
        ),
    );
    push_line(
        &mut output,
        &format!(
            "target: {} | scope: {} | network: {}",
            result.scope.target,
            history_summary(&result.scope.history),
            if result.scope.network.enabled {
                "enabled"
            } else {
                "disabled"
            }
        ),
    );

    if !result.scope.warnings.is_empty() {
        push_line(&mut output, "");
        push_line(&mut output, "warnings:");
        for warning in &result.scope.warnings {
            push_line(&mut output, &format!("  - {}", warning_summary(warning)));
        }
    }

    if result.findings.is_empty() {
        push_line(&mut output, "");
        push_line(&mut output, "No findings.");
        return output;
    }

    push_line(&mut output, "");
    for finding in &result.findings {
        push_line(
            &mut output,
            &format!(
                "{} {} [{}]",
                style.severity(finding.severity),
                finding.title,
                category_name(finding.category)
            ),
        );
        push_line(&mut output, &format!("  id: {}", finding.id.0));
        push_line(
            &mut output,
            &format!("  confidence: {}", confidence_name(finding.confidence)),
        );
        if let Some(location) = finding.locations.first() {
            push_line(
                &mut output,
                &format!("  location: {}", location_summary(location)),
            );
        }
        push_line(
            &mut output,
            &format!("  evidence: {}", evidence_summary(&finding.evidence)),
        );
        push_line(
            &mut output,
            &format!("  remediation: {}", finding.remediation),
        );
        if !finding.related.is_empty() {
            let related = finding
                .related
                .iter()
                .map(|id| id.0.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            push_line(&mut output, &format!("  related: {related}"));
        }
        push_line(&mut output, "");
    }

    output
}

/// Render a self-contained HTML report.
pub fn render_html(result: &ScanResult) -> String {
    let mut html = String::new();
    html.push_str("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">");
    html.push_str("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">");
    html.push_str("<title>vibescan report</title>");
    html.push_str("<style>");
    html.push_str("body{font-family:system-ui,-apple-system,Segoe UI,sans-serif;margin:0;background:#f7f7f5;color:#1c1d1f}main{max-width:1040px;margin:0 auto;padding:32px 20px}h1{font-size:28px;margin:0 0 8px}.meta{color:#5c6068;margin-bottom:24px}.summary{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:24px}.pill{border:1px solid #d8dadf;border-radius:6px;padding:8px 10px;background:#fff}.finding{border-top:1px solid #dadde3;padding:18px 0}.sev{font-weight:700}.critical{color:#a40020}.high{color:#b54708}.medium{color:#8a6500}.low{color:#4d6475}.info{color:#47636b}.detail{color:#3f444c}.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px}.evidence{background:#fff;border:1px solid #dfe2e8;border-radius:6px;padding:10px;overflow-wrap:anywhere}</style>");
    html.push_str("</head><body><main>");
    html.push_str("<h1>vibescan report</h1>");
    html.push_str(&format!(
        "<div class=\"meta\">target: {} | version: {} | duration: {} ms | network: {}</div>",
        escape_html(&result.scope.target),
        escape_html(&result.tool_version),
        result.duration_ms,
        if result.scope.network.enabled {
            "enabled"
        } else {
            "disabled"
        }
    ));
    html.push_str("<section class=\"summary\">");
    html.push_str(&format!(
        "<div class=\"pill\">findings: {}</div><div class=\"pill\">scope: {}</div>",
        result.findings.len(),
        escape_html(&history_summary(&result.scope.history))
    ));
    for (severity, count) in &result.stats.by_severity {
        html.push_str(&format!(
            "<div class=\"pill\"><span class=\"sev {}\">{}</span>: {}</div>",
            severity_class(*severity),
            severity_name(*severity),
            count
        ));
    }
    html.push_str("</section>");

    if !result.scope.warnings.is_empty() {
        html.push_str("<section><h2>Warnings</h2><ul>");
        for warning in &result.scope.warnings {
            html.push_str(&format!(
                "<li>{}</li>",
                escape_html(&warning_summary(warning))
            ));
        }
        html.push_str("</ul></section>");
    }

    html.push_str("<section><h2>Findings</h2>");
    if result.findings.is_empty() {
        html.push_str("<p>No findings.</p>");
    }
    for finding in &result.findings {
        html.push_str("<article class=\"finding\">");
        html.push_str(&format!(
            "<h3><span class=\"sev {}\">{}</span> {}</h3>",
            severity_class(finding.severity),
            severity_name(finding.severity),
            escape_html(&finding.title)
        ));
        html.push_str(&format!(
            "<p class=\"detail\">{} | {} | confidence: {}</p>",
            escape_html(&finding.id.0),
            category_name(finding.category),
            confidence_name(finding.confidence)
        ));
        html.push_str(&format!("<p>{}</p>", escape_html(&finding.detail)));
        if let Some(location) = finding.locations.first() {
            html.push_str(&format!(
                "<p class=\"mono\">{}</p>",
                escape_html(&location_summary(location))
            ));
        }
        html.push_str(&format!(
            "<div class=\"evidence\">{}</div>",
            escape_html(&evidence_summary(&finding.evidence))
        ));
        html.push_str(&format!(
            "<p><strong>Remediation:</strong> {}</p>",
            escape_html(&finding.remediation)
        ));
        html.push_str("</article>");
    }
    html.push_str("</section></main></body></html>");
    html
}

/// Compute process exit code from a severity gate.
pub fn exit_code(result: &ScanResult, gate: Severity) -> i32 {
    result
        .findings
        .iter()
        .any(|finding| finding.severity >= gate)
        .then_some(1)
        .unwrap_or(0)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TtyStyle {
    Plain,
    Color,
}

impl TtyStyle {
    fn severity(self, severity: Severity) -> String {
        let label = severity_name(severity);
        match self {
            Self::Plain => format!("[{label}]"),
            Self::Color => {
                let code = match severity {
                    Severity::Critical => "31;1",
                    Severity::High => "31",
                    Severity::Medium => "33",
                    Severity::Low => "34",
                    Severity::Info => "36",
                };
                format!("\x1b[{code}m[{label}]\x1b[0m")
            }
        }
    }
}

fn sarif_value(result: &ScanResult) -> Value {
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
                    "warnings": result.scope.warnings.iter().map(warning_summary).collect::<Vec<_>>(),
                }
            }],
            "results": results,
        }]
    })
}

fn sarif_locations(finding: &Finding) -> Vec<Value> {
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

fn evidence_summary(evidence: &Evidence) -> String {
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

fn location_summary(location: &Location) -> String {
    let span = location
        .span
        .map(|span| format!(":{}:{}-{}", span.line, span.col_start, span.col_end))
        .unwrap_or_default();
    format!(
        "{}{} ({}, {})",
        location.path.0,
        span,
        provenance_summary(&location.provenance),
        format!("{:?}", location.location_class).to_ascii_lowercase()
    )
}

fn provenance_summary(provenance: &Provenance) -> String {
    match provenance {
        Provenance::WorkingTree => "working tree".to_owned(),
        Provenance::Commit { sha, .. } => format!("commit {sha}"),
    }
}

fn warning_summary(warning: &ScopeWarning) -> String {
    match warning {
        ScopeWarning::HistoryBudgetHit { max_commits } => {
            format!("history scan stopped at budget of {max_commits} commits")
        }
        ScopeWarning::ShallowClone => "repository is a shallow clone".to_owned(),
        ScopeWarning::SubmoduleSkipped { path } => format!("submodule skipped at {}", path.0),
        ScopeWarning::MergeCommitFirstParentOnly { sha } => {
            format!("merge commit {sha} diffed against first parent only")
        }
        ScopeWarning::LargeFileSkipped { path, bytes } => {
            format!("large file skipped: {} ({} bytes)", path.0, bytes)
        }
        ScopeWarning::BinaryFileSkipped { path } => format!("binary file skipped: {}", path.0),
        ScopeWarning::Other { message } => message.clone(),
    }
}

fn history_summary(history: &HistoryScope) -> String {
    match history {
        HistoryScope::Disabled => "history disabled".to_owned(),
        HistoryScope::WorkingTreeOnly => "working tree only".to_owned(),
        HistoryScope::Budgeted {
            max_commits,
            scanned_commits,
            truncated,
        } => format!(
            "history budgeted {scanned_commits}/{max_commits} commits{}",
            if *truncated { " truncated" } else { "" }
        ),
        HistoryScope::Exhaustive { scanned_commits } => {
            format!("history exhaustive {scanned_commits} commits")
        }
    }
}

fn sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium | Severity::Low => "warning",
        Severity::Info => "note",
    }
}

fn security_severity(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "9.5",
        Severity::High => "8.0",
        Severity::Medium => "5.0",
        Severity::Low => "2.5",
        Severity::Info => "0.0",
    }
}

fn severity_name(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}

fn severity_class(severity: Severity) -> &'static str {
    severity_name(severity)
}

fn category_name(category: Category) -> &'static str {
    match category {
        Category::SecretExposure => "secret_exposure",
        Category::KeyClassification => "key_classification",
        Category::Rls => "rls",
        Category::DependencyIntegrity => "dependency_integrity",
        Category::Correlation => "correlation",
    }
}

fn confidence_name(confidence: Confidence) -> &'static str {
    match confidence {
        Confidence::Confirmed => "confirmed",
        Confidence::Likely => "likely",
        Confidence::Review => "review",
    }
}

fn escape_html(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn push_line(output: &mut String, line: &str) {
    output.push_str(line);
    output.push('\n');
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use vibescan_types::{
        FindingId, LocationClass, NetworkScope, RepoPath, RlsExposure, ScanScope, ScanStats, Span,
        SupabaseProject,
    };

    use super::*;

    #[test]
    fn json_render_is_valid_and_redacted() {
        let result = sample_result();
        let rendered = render_json(&result).expect("json renders");
        let value: Value = serde_json::from_str(&rendered).expect("json parses");

        assert_eq!(
            value["findings"][0]["evidence"]["redacted"],
            "sb_sec...CDEF"
        );
        assert!(!rendered.contains("full-secret"));
    }

    #[test]
    fn sarif_render_contains_results_and_locations() {
        let result = sample_result();
        let rendered = render_sarif(&result).expect("sarif renders");
        let value: Value = serde_json::from_str(&rendered).expect("sarif parses");

        assert_eq!(value["version"], "2.1.0");
        assert_eq!(value["runs"][0]["results"][0]["ruleId"], "finding-1");
        assert_eq!(
            value["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
                ["uri"],
            "src/app.tsx"
        );
    }

    #[test]
    fn tty_render_is_human_readable() {
        let output = render_tty(&sample_result(), TtyStyle::Plain);

        assert!(output.contains("[critical] Supabase secret key exposed"));
        assert!(output.contains("remediation: Rotate it."));
    }

    #[test]
    fn html_render_escapes_content() {
        let mut result = sample_result();
        result.findings[0].title = "<script>alert(1)</script>".to_owned();
        let output = render_html(&result);

        assert!(output.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(!output.contains("<script>alert(1)</script>"));
    }

    #[test]
    fn exit_code_uses_severity_gate() {
        let result = sample_result();

        assert_eq!(exit_code(&result, Severity::Critical), 1);
        assert_eq!(exit_code(&result, Severity::Info), 1);
        assert_eq!(exit_code(&empty_result(), Severity::Info), 0);
    }

    fn sample_result() -> ScanResult {
        let finding = Finding {
            id: FindingId("finding-1".to_owned()),
            category: Category::SecretExposure,
            severity: Severity::Critical,
            title: "Supabase secret key exposed".to_owned(),
            detail: "A secret key was found.".to_owned(),
            locations: vec![Location {
                path: RepoPath("src/app.tsx".to_owned()),
                span: Some(Span {
                    line: 3,
                    col_start: 10,
                    col_end: 30,
                }),
                provenance: Provenance::WorkingTree,
                additional_provenance: Vec::new(),
                location_class: LocationClass::ClientReachable,
            }],
            evidence: Evidence::SupabaseKey {
                class: vibescan_types::SupabaseKeyClass::SecretNew,
                redacted: "sb_sec...CDEF".to_owned(),
                project: Some(SupabaseProject {
                    ref_id: Some("abcdefghijklmnopqrst".to_owned()),
                    url: "https://abcdefghijklmnopqrst.supabase.co".to_owned(),
                }),
                fingerprint: vibescan_types::SecretFingerprint("abc123".to_owned()),
            },
            remediation: "Rotate it.".to_owned(),
            related: Vec::new(),
            confidence: Confidence::Likely,
        };
        let mut stats = ScanStats::default();
        stats.by_severity = BTreeMap::from([(Severity::Critical, 1)]);
        stats.by_category = BTreeMap::from([(Category::SecretExposure, 1)]);

        ScanResult {
            findings: vec![finding],
            scope: ScanScope {
                target: ".".to_owned(),
                working_tree: true,
                history: HistoryScope::WorkingTreeOnly,
                network: NetworkScope {
                    enabled: false,
                    tier0_read_probe: false,
                    tier1_introspection: false,
                },
                warnings: vec![ScopeWarning::Other {
                    message: "fixture warning".to_owned(),
                }],
            },
            tool_version: "0.1.0".to_owned(),
            started_at: "test".to_owned(),
            duration_ms: 12,
            stats,
        }
    }

    fn empty_result() -> ScanResult {
        ScanResult {
            findings: Vec::new(),
            scope: ScanScope {
                target: ".".to_owned(),
                working_tree: true,
                history: HistoryScope::Disabled,
                network: NetworkScope {
                    enabled: false,
                    tier0_read_probe: false,
                    tier1_introspection: false,
                },
                warnings: Vec::new(),
            },
            tool_version: "0.1.0".to_owned(),
            started_at: "test".to_owned(),
            duration_ms: 0,
            stats: ScanStats::default(),
        }
    }

    #[allow(dead_code)]
    fn rls_evidence() -> Evidence {
        Evidence::RlsProbe {
            project: SupabaseProject {
                ref_id: Some("abcdefghijklmnopqrst".to_owned()),
                url: "https://abcdefghijklmnopqrst.supabase.co".to_owned(),
            },
            table: "profiles".to_owned(),
            endpoint: "https://abcdefghijklmnopqrst.supabase.co/rest/v1/profiles?limit=1"
                .to_owned(),
            observed_row_count: 1,
            exposure: RlsExposure::Exposed,
        }
    }
}
