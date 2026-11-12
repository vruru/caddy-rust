// Behavioral URI rewrite port of Caddy v2.11.7 (Apache-2.0).
use crate::http_config::helpers::replace;
use http::Uri;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};

// Special encoding set for URLPathEscape behavior (keeping /)
// We define a set that excludes '/' from the NON_ALPHANUMERIC set.
const QUERY_ENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'~')
    .remove(b'-')
    .remove(b'.')
    .remove(b'_');

// Go PathEscape allows :@&=+$, and this use deliberately retains slashes.
const PATH_ESCAPE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'~')
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'/')
    .remove(b':')
    .remove(b'@')
    .remove(b'&')
    .remove(b'=')
    .remove(b'+')
    .remove(b'$');

pub(super) fn rewrite_uri(
    template: &str,
    current: &Uri,
    lookup: impl Fn(&str) -> Option<String>,
) -> anyhow::Result<String> {
    if template.is_empty() {
        return Ok(get_path_and_query(current));
    }
    let before_fragment = template.split_once('#').map_or(template, |(head, _)| head);
    let (raw_path, raw_query) = before_fragment
        .split_once('?')
        .map_or((before_fragment, None), |(path, query)| (path, Some(query)));
    let mut query = raw_query.map(str::to_owned);
    let path = if raw_path.is_empty() {
        current.path_and_query().map_or("",|value|value.raw_path()).to_owned()
    } else {
        let escaped = escape_path_placeholders(raw_path, current, &lookup)?;
        let expanded = replace(&escaped, true, &lookup)?;
        let expanded = expanded
            .split_once('#')
            .map_or(expanded.as_str(), |(head, _)| head);
        if let Some((path, injected)) = expanded.split_once('?') {
            if query.as_ref().is_none_or(String::is_empty) {
                // Do not evaluate operator-looking bytes supplied by a user.
                query = Some(injected.replace('{', "%7B").replace('}', "%7D"));
            }
            path.to_owned()
        } else {
            expanded.to_owned()
        }
    };
    // A URI setter changes URL.Path, not Scheme/Host. Decode its supplied
    // path once then use Go's EscapedPath encoding, without cleaning dots or
    // treating a literal "https://..." path as a new absolute URI. An invalid
    // escape is retained as literal text, as the Go setter does.
    let path = if raw_path.is_empty() { path } else {
        let bytes = super::http_redirect::url::template_decode_bytes(path.as_bytes())
            .unwrap_or_else(|_|path.as_bytes().to_vec());
        String::from_utf8(super::http_redirect::url::template_encode_path_bytes(&bytes))?
    };
    let query = if let Some(query) = query {
        Some(build_query_string(&query, &lookup)?)
    } else {
        current.query().map(str::to_owned)
    };
    Ok(match query {
        Some(query) if !query.is_empty() || current.query() == Some("") => {
            format!("{path}?{query}")
        }
        Some(_) => path,
        None => path,
    })
}

fn get_path_and_query(uri: &Uri) -> String {
    let path = uri.path_and_query().map_or("",|value|value.raw_path());
    if let Some(q) = uri.query() {
        format!("{}?{}", path, q)
    } else {
        path.to_string()
    }
}

fn escape_path_placeholders(
    path: &str,
    current: &Uri,
    lookup: &impl Fn(&str) -> Option<String>,
) -> anyhow::Result<String> {
    let mut result = path.to_string();

    // Handle {http.request.uri.path}
    if result.contains("{http.request.uri.path}") {
        let escaped_path = current.path().to_owned();
        result = result.replace("{http.request.uri.path}", &escaped_path);
    }

    // Handle {http.matchers.file.relative}
    if result.contains("{http.matchers.file.relative}")
        && let Some(val) = lookup("http.matchers.file.relative")
    {
        let escaped = escape_path_preserving_slashes(&val);
        result = result.replace("{http.matchers.file.relative}", &escaped);
    }

    Ok(result)
}

fn escape_path_preserving_slashes(path: &str) -> String {
    utf8_percent_encode(path, PATH_ESCAPE_SET).to_string()
}

fn build_query_string(
    mut qs: &str,
    lookup: &impl Fn(&str) -> Option<String>,
) -> anyhow::Result<String> {
    let mut out = String::new();
    let mut wrote_value = true;
    while !qs.is_empty() {
        let next_amp = qs.find('&');
        let next_eq = if wrote_value { qs.find('=') } else { None };
        let amp_is_next = next_amp.is_some_and(|amp| next_eq.is_none_or(|eq| amp < eq));
        let end = if amp_is_next {
            next_amp.unwrap()
        } else {
            next_eq.unwrap_or(qs.len())
        };
        let comp = replace(&qs[..end], true, |name| {
            lookup(name).map(|value| {
                if name == "http.request.uri.query" && wrote_value {
                    value
                } else {
                    utf8_percent_encode(&value, QUERY_ENCODE_SET)
                        .to_string()
                        .replace("%20", "+")
                }
            })
        })?;
        if wrote_value {
            if !out.is_empty() && !comp.is_empty() {
                out.push('&');
            }
        } else {
            out.push('=');
        }
        out.push_str(&comp);
        qs = &qs[(end + usize::from(end < qs.len()))..];
        wrote_value = amp_is_next;
    }
    Ok(out)
}
