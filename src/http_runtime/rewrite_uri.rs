// Behavioral URI rewrite port of Caddy v2.11.7 (Apache-2.0).
use crate::http_config::helpers::replace_bytes_accounted;
use http::Uri;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, percent_encode};

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

#[derive(Debug)]
pub(super) struct Components {
    pub path: Option<Vec<u8>>,
    pub query: Option<Vec<u8>>,
}
pub(super) fn rewrite_uri(
    template: &str,
    current: &Uri,
    lookup: impl Fn(&str) -> Option<Vec<u8>>,
    mut charge: impl FnMut(usize) -> anyhow::Result<()>,
) -> anyhow::Result<Components> {
    charge(template.len() * 8 + super::rewrite_ops::uri_bytes(current) * 8 + 1024)?;
    if template.is_empty() {
        return Ok(Components {
            path: None,
            query: None,
        });
    }
    let before_fragment = template.split_once('#').map_or(template, |(head, _)| head);
    let (raw_path, raw_query) = before_fragment
        .split_once('?')
        .map_or((before_fragment, None), |(path, query)| (path, Some(query)));
    let mut query = raw_query.map(|q| q.as_bytes().to_vec());
    let path = if raw_path.is_empty() {
        current
            .path_and_query()
            .map_or("", |value| value.raw_path())
            .as_bytes()
            .to_vec()
    } else {
        let escaped = escape_path_placeholders(raw_path, current, &lookup, &mut charge)?;
        let expanded = replace_bytes_accounted(&escaped, true, &lookup, &mut charge)?;
        let expanded = &expanded[..expanded
            .iter()
            .position(|b| *b == b'#')
            .unwrap_or(expanded.len())];
        if let Some(at) = expanded.iter().position(|b| *b == b'?') {
            if query.as_ref().is_none_or(Vec::is_empty) {
                charge(expanded.len() * 8 + 64)?;
                let mut injected = Vec::new();
                for b in &expanded[at + 1..] {
                    match b {
                        b'{' => injected.extend_from_slice(b"%7B"),
                        b'}' => injected.extend_from_slice(b"%7D"),
                        _ => injected.push(*b),
                    }
                }
                query = Some(injected);
            }
            expanded[..at].to_vec()
        } else {
            expanded.to_vec()
        }
    };
    charge(path.len() * 10 + 128)?;
    let path = if raw_path.is_empty() {
        None
    } else {
        Some(super::http_redirect::url::template_decode_bytes(&path).unwrap_or(path))
    };
    let query = match query {
        Some(query) => Some(build_query_string(&query, &lookup, &mut charge)?),
        None => None,
    };
    anyhow::ensure!(
        path.as_ref().map_or(0, Vec::len) + query.as_ref().map_or(0, Vec::len) <= 4 << 20,
        "rewritten URI exceeds limit"
    );
    Ok(Components { path, query })
}

fn escape_path_placeholders(
    path: &str,
    current: &Uri,
    lookup: &impl Fn(&str) -> Option<Vec<u8>>,
    charge: &mut impl FnMut(usize) -> anyhow::Result<()>,
) -> anyhow::Result<String> {
    let mut result = path.to_string();

    // Handle {http.request.uri.path}
    if result.contains("{http.request.uri.path}") {
        let escaped_path = current.path().to_owned();
        result = replace_literal(&result, "{http.request.uri.path}", &escaped_path, charge)?;
    }

    // Handle {http.matchers.file.relative}
    if result.contains("{http.matchers.file.relative}")
        && let Some(val) = lookup("http.matchers.file.relative")
    {
        charge(val.len() * 8 + 64)?;
        let escaped = escape_path_preserving_slashes(&val)?;
        result = replace_literal(&result, "{http.matchers.file.relative}", &escaped, charge)?;
    }

    Ok(result)
}

fn escape_path_preserving_slashes(path: &[u8]) -> anyhow::Result<String> {
    let size = percent_encode(path, PATH_ESCAPE_SET)
        .map(str::len)
        .sum::<usize>();
    anyhow::ensure!(size <= 4 << 20, "escaped placeholder exceeds limit");
    Ok(percent_encode(path, PATH_ESCAPE_SET).to_string())
}

fn build_query_string(
    mut qs: &[u8],
    lookup: &impl Fn(&str) -> Option<Vec<u8>>,
    charge: &mut impl FnMut(usize) -> anyhow::Result<()>,
) -> anyhow::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut wrote_value = true;
    while !qs.is_empty() {
        let next_amp = qs.iter().position(|b| *b == b'&');
        let next_eq = if wrote_value {
            qs.iter().position(|b| *b == b'=')
        } else {
            None
        };
        let amp_is_next = next_amp.is_some_and(|amp| next_eq.is_none_or(|eq| amp < eq));
        let end = if amp_is_next {
            next_amp.unwrap()
        } else {
            next_eq.unwrap_or(qs.len())
        };
        let source = &qs[..end];
        let comp = if !source.contains(&b'{') {
            charge(source.len() * 2 + 64)?;
            source.to_vec()
        } else {
            replace_bytes_accounted(
                std::str::from_utf8(source)?,
                true,
                |name| {
                    lookup(name).map(|value| {
                        if name == "http.request.uri.query" && wrote_value {
                            value
                        } else {
                            percent_encode(&value, QUERY_ENCODE_SET)
                                .to_string()
                                .replace("%20", "+")
                                .into_bytes()
                        }
                    })
                },
                &mut *charge,
            )?
        };
        anyhow::ensure!(
            out.len() + comp.len() + 1 <= 4 << 20,
            "rewritten query exceeds limit"
        );
        let required = out.len() + comp.len() + 1;
        if required > out.capacity() {
            let capacity = out.capacity().saturating_mul(2).max(required).min(4 << 20);
            charge(capacity * 2 + 64)?;
            out.try_reserve_exact(capacity - out.len())?;
        }
        if wrote_value {
            if !out.is_empty() && !comp.is_empty() {
                out.push(b'&');
            }
        } else {
            out.push(b'=');
        }
        out.extend_from_slice(&comp);
        qs = &qs[(end + usize::from(end < qs.len()))..];
        wrote_value = amp_is_next;
    }
    Ok(out)
}

fn replace_literal(
    input: &str,
    find: &str,
    replacement: &str,
    charge: &mut impl FnMut(usize) -> anyhow::Result<()>,
) -> anyhow::Result<String> {
    let count = input.matches(find).count();
    let size = input
        .len()
        .checked_sub(count * find.len())
        .and_then(|n| {
            count
                .checked_mul(replacement.len())
                .and_then(|m| n.checked_add(m))
        })
        .filter(|n| *n <= 4 << 20)
        .ok_or_else(|| anyhow::anyhow!("escaped rewrite template exceeds limit"))?;
    charge(size * 2 + 64)?;
    Ok(input.replace(find, replacement))
}
