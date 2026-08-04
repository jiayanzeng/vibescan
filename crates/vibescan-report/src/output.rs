use super::*;

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
            "collection: paths {} | blobs {} | unique {} | dedup {:.2}% | units {} | truncated {}",
            result.stats.paths_walked,
            result.stats.blobs_read,
            result.stats.unique_contents,
            result.stats.dedup_ratio() * 100.0,
            result.stats.units_materialized,
            if result.stats.truncated { "yes" } else { "no" }
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

    if !result.scope.network.actions.is_empty() {
        push_line(&mut output, "");
        push_line(&mut output, "network actions:");
        for action in &result.scope.network.actions {
            push_line(
                &mut output,
                &format!("  - {}", network_action_summary(action)),
            );
        }
    }

    if !result.scope.network.registry_name_egress.is_empty() {
        push_line(&mut output, "");
        push_line(&mut output, "registry package-name egress:");
        for disclosure in &result.scope.network.registry_name_egress {
            push_line(
                &mut output,
                &format!("  - {}", registry_egress_summary(disclosure)),
            );
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
        for location in &finding.locations {
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
    html.push_str(&format!(
        "<div class=\"pill\">paths: {}</div><div class=\"pill\">blobs: {}</div><div class=\"pill\">unique: {}</div><div class=\"pill\">dedup: {:.2}%</div><div class=\"pill\">units: {}</div><div class=\"pill\">truncated: {}</div>",
        result.stats.paths_walked,
        result.stats.blobs_read,
        result.stats.unique_contents,
        result.stats.dedup_ratio() * 100.0,
        result.stats.units_materialized,
        if result.stats.truncated { "yes" } else { "no" }
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

    if !result.scope.network.actions.is_empty() {
        html.push_str("<section><h2>Network actions</h2><ul>");
        for action in &result.scope.network.actions {
            html.push_str(&format!(
                "<li class=\"mono\">{}</li>",
                escape_html(&network_action_summary(action))
            ));
        }
        html.push_str("</ul></section>");
    }

    if !result.scope.network.registry_name_egress.is_empty() {
        html.push_str("<section><h2>Registry package-name egress</h2><ul>");
        for disclosure in &result.scope.network.registry_name_egress {
            html.push_str(&format!(
                "<li class=\"mono\">{}</li>",
                escape_html(&registry_egress_summary(disclosure))
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
        for location in &finding.locations {
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
    if result
        .findings
        .iter()
        .any(|finding| finding.severity >= gate)
    {
        1
    } else {
        0
    }
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
