use super::*;

pub(super) fn sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium | Severity::Low => "warning",
        Severity::Info => "note",
    }
}

pub(super) fn security_severity(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "9.5",
        Severity::High => "8.0",
        Severity::Medium => "5.0",
        Severity::Low => "2.5",
        Severity::Info => "0.0",
    }
}

pub(super) fn severity_name(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}

pub(super) fn severity_class(severity: Severity) -> &'static str {
    severity_name(severity)
}

pub(super) fn category_name(category: Category) -> &'static str {
    match category {
        Category::SecretExposure => "secret_exposure",
        Category::KeyClassification => "key_classification",
        Category::Rls => "rls",
        Category::DependencyIntegrity => "dependency_integrity",
        Category::Correlation => "correlation",
    }
}

pub(super) fn confidence_name(confidence: Confidence) -> &'static str {
    match confidence {
        Confidence::Confirmed => "confirmed",
        Confidence::Likely => "likely",
        Confidence::Review => "review",
    }
}

pub(super) fn escape_html(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

pub(super) fn push_line(output: &mut String, line: &str) {
    output.push_str(line);
    output.push('\n');
}
