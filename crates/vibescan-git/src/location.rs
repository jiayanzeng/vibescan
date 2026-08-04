use super::*;

pub(super) fn classify_location(path: &str, content: &[u8]) -> LocationClass {
    let lower = path.to_ascii_lowercase();
    let segments = lower
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    let basename = segments.last().copied().unwrap_or_default();

    if basename_is_env(basename)
        || path_has_segments(&segments, &["app", "api"])
        || path_has_segments(&segments, &["pages", "api"])
        || path_has_segments(&segments, &["src", "app", "api"])
        || path_has_segments(&segments, &["src", "pages", "api"])
        || segments.contains(&"server")
        || path_has_segments(&segments, &[".next", "server"])
        || path_has_segments(&segments, &["supabase", "functions"])
        || is_bare_api_package_root(&segments)
        || (is_src_api_root(&segments) && has_server_runtime_signal(content))
    {
        return LocationClass::ServerOnly;
    }

    if segments.contains(&"public")
        || segments.contains(&"app")
        || segments.contains(&"pages")
        || path_has_segments(&segments, &["src", "app"])
        || path_has_segments(&segments, &["src", "pages"])
        || path_has_segments(&segments, &["src", "components"])
        || segments.contains(&"dist")
        || segments.contains(&"build")
        || segments.contains(&"out")
        || path_has_segments(&segments, &[".next", "static"])
        || segments.contains(&".svelte-kit")
        || segments.contains(&"client")
        || basename.contains(".client.")
        || is_src_api_root(&segments)
    {
        return LocationClass::ClientReachable;
    }

    LocationClass::Unknown
}

pub(super) fn basename_is_env(basename: &str) -> bool {
    basename == ".env" || basename.starts_with(".env.")
}

pub(super) fn path_has_segments(path: &[&str], needle: &[&str]) -> bool {
    !needle.is_empty()
        && needle.len() <= path.len()
        && path.windows(needle.len()).any(|window| window == needle)
}

pub(super) fn is_bare_api_package_root(path: &[&str]) -> bool {
    path.starts_with(&["api"])
        || path.windows(2).any(|window| {
            matches!(window[0], "apps" | "packages" | "services") && window[1] == "api"
        })
        || path.windows(3).any(|window| {
            matches!(window[0], "apps" | "packages" | "services") && window[2] == "api"
        })
}

pub(super) fn is_src_api_root(path: &[&str]) -> bool {
    path.starts_with(&["src", "api"])
        || path.windows(4).any(|window| {
            matches!(window[0], "apps" | "packages" | "services")
                && window[2] == "src"
                && window[3] == "api"
        })
}

pub(super) fn has_server_runtime_signal(content: &[u8]) -> bool {
    let text = String::from_utf8_lossy(content);
    text.contains("\"use server\"")
        || text.contains("'use server'")
        || quoted_module_specifiers(&text).any(|specifier| {
            is_import_or_require_specifier(&text, specifier.start)
                && (specifier.value == "next/server" || specifier.value.starts_with("node:"))
        })
}

pub(super) struct QuotedSpecifier<'a> {
    start: usize,
    value: &'a str,
}

pub(super) fn quoted_module_specifiers(text: &str) -> impl Iterator<Item = QuotedSpecifier<'_>> {
    let bytes = text.as_bytes();
    let mut offset = 0;
    std::iter::from_fn(move || {
        while offset < bytes.len() {
            let quote = bytes[offset];
            if quote != b'\'' && quote != b'"' {
                offset += 1;
                continue;
            }

            let start = offset;
            offset += 1;
            let value_start = offset;
            while offset < bytes.len() {
                match bytes[offset] {
                    b'\\' => offset = (offset + 2).min(bytes.len()),
                    byte if byte == quote => {
                        let value_end = offset;
                        offset += 1;
                        return Some(QuotedSpecifier {
                            start,
                            value: &text[value_start..value_end],
                        });
                    }
                    _ => offset += 1,
                }
            }
        }
        None
    })
}

pub(super) fn is_import_or_require_specifier(text: &str, quote_start: usize) -> bool {
    let prefix = text[..quote_start].trim_end();
    if ends_with_identifier(prefix, "from") || ends_with_identifier(prefix, "import") {
        return true;
    }

    let Some(call_prefix) = prefix.strip_suffix('(') else {
        return false;
    };
    let call_prefix = call_prefix.trim_end();
    ends_with_identifier(call_prefix, "import") || ends_with_identifier(call_prefix, "require")
}

pub(super) fn ends_with_identifier(text: &str, identifier: &str) -> bool {
    let Some(prefix) = text.strip_suffix(identifier) else {
        return false;
    };
    prefix
        .chars()
        .next_back()
        .is_none_or(|ch| !ch.is_ascii_alphanumeric() && ch != '_' && ch != '$')
}
