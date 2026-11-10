// Copyright 2015 Matthew Holt and The Caddy Authors
// SPDX-License-Identifier: Apache-2.0
//! Exact ordered shorthand passes, with a preallocation budget check.
use super::budget::Budget;
use crate::caddyfile_lexer::Token;
use anyhow::{Result, anyhow};
const SIMPLE: &[(&str, &str)] = &[
    ("{host}", "{http.request.host}"),
    ("{hostport}", "{http.request.hostport}"),
    ("{port}", "{http.request.port}"),
    ("{orig_method}", "{http.request.orig_method}"),
    ("{orig_uri}", "{http.request.orig_uri}"),
    ("{orig_path}", "{http.request.orig_uri.path}"),
    ("{orig_dir}", "{http.request.orig_uri.path.dir}"),
    ("{orig_file}", "{http.request.orig_uri.path.file}"),
    ("{orig_query}", "{http.request.orig_uri.query}"),
    ("{orig_?query}", "{http.request.orig_uri.prefixed_query}"),
    ("{method}", "{http.request.method}"),
    ("{uri}", "{http.request.uri}"),
    ("{%uri}", "{http.request.uri_escaped}"),
    ("{path}", "{http.request.uri.path}"),
    ("{%path}", "{http.request.uri.path_escaped}"),
    ("{dir}", "{http.request.uri.path.dir}"),
    ("{file}", "{http.request.uri.path.file}"),
    ("{query}", "{http.request.uri.query}"),
    ("{%query}", "{http.request.uri.query_escaped}"),
    ("{?query}", "{http.request.uri.prefixed_query}"),
    ("{remote}", "{http.request.remote}"),
    ("{remote_host}", "{http.request.remote.host}"),
    ("{remote_port}", "{http.request.remote.port}"),
    ("{scheme}", "{http.request.scheme}"),
    ("{uuid}", "{http.request.uuid}"),
    ("{tls_cipher}", "{http.request.tls.cipher_suite}"),
    ("{tls_version}", "{http.request.tls.version}"),
    (
        "{tls_client_fingerprint}",
        "{http.request.tls.client.fingerprint}",
    ),
    ("{tls_client_issuer}", "{http.request.tls.client.issuer}"),
    ("{tls_client_serial}", "{http.request.tls.client.serial}"),
    ("{tls_client_subject}", "{http.request.tls.client.subject}"),
    (
        "{tls_client_certificate_pem}",
        "{http.request.tls.client.certificate_pem}",
    ),
    (
        "{tls_client_certificate_der_base64}",
        "{http.request.tls.client.certificate_der_base64}",
    ),
    (
        "{upstream_hostport}",
        "{http.reverse_proxy.upstream.hostport}",
    ),
    ("{client_ip}", "{http.vars.client_ip}"),
];
const COMPLEX: &[(&str, &str, bool)] = &[
    ("header", "http.request.header", false),
    ("cookie", "http.request.cookie", false),
    ("labels", "http.request.host.labels", false),
    ("path", "http.request.uri.path", false),
    ("file", "http.request.uri.path.file", false),
    ("query", "http.request.uri.query", false),
    ("re", "http.regexp", true),
    ("vars", "http.vars", false),
    ("rp", "http.reverse_proxy", true),
    ("resp", "http.intercept", true),
    ("err", "http.error", true),
    ("file_match", "http.matchers.file", false),
];
fn checked(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b)
        .ok_or_else(|| anyhow!("Caddyfile shorthand size overflow"))
}
/// Both traversals inspect only the original pass input; replacement text is
/// never recursively replaced within a pass. Complex passes remain ordered.
const SIMPLE_MAX: usize = 35;
static SORTED: std::sync::LazyLock<Vec<(&str, &str)>> = std::sync::LazyLock::new(|| {
    let mut sorted = SIMPLE.to_vec();
    sorted.sort_unstable_by_key(|p| p.0);
    sorted
});
fn simple_at(rest: &str) -> Option<(&'static str, usize)> {
    let end = rest
        .as_bytes()
        .iter()
        .take(SIMPLE_MAX)
        .skip(1)
        .position(|b| *b == b'}' || *b == b'{')?
        + 1;
    if rest.as_bytes()[end] != b'}' {
        return None;
    }
    let candidate = &rest[..=end];
    SORTED
        .binary_search_by(|p| p.0.cmp(candidate))
        .ok()
        .map(|i| (SORTED[i].1, candidate.len()))
}
fn simple_pass(input: &str, mut emit: impl FnMut(&str) -> Result<()>) -> Result<()> {
    let mut cursor = 0;
    while let Some(rel) = input[cursor..].find('{') {
        let start = cursor + rel;
        emit(&input[cursor..start])?;
        if let Some((to, len)) = simple_at(&input[start..]) {
            emit(to)?;
            cursor = start + len;
        } else {
            emit("{")?;
            cursor = start + 1;
        }
    }
    emit(&input[cursor..])
}
fn complex_pass(
    input: &str,
    name: &str,
    target: &str,
    dot: bool,
    mut emit: impl FnMut(&str) -> Result<()>,
) -> Result<()> {
    let mut cursor = 0;
    while let Some(rel) = input[cursor..].find('{') {
        let start = cursor + rel;
        emit(&input[cursor..start])?;
        let suffix = &input[start + 1..];
        if let Some(suffix) = suffix.strip_prefix(name).and_then(|s| s.strip_prefix('.')) {
            let count = suffix
                .bytes()
                .take_while(|b| {
                    b.is_ascii_alphanumeric() || *b == b'_' || *b == b'-' || dot && *b == b'.'
                })
                .count();
            if suffix.as_bytes().get(count) == Some(&b'}') {
                emit("{")?;
                emit(target)?;
                emit(".")?;
                emit(&suffix[..count])?;
                emit("}")?;
                cursor = start + 1 + name.len() + 1 + count + 1;
                continue;
            }
        }
        emit("{")?;
        cursor = start + 1;
    }
    emit(&input[cursor..])
}
fn replace(
    input: &str,
    budget: &mut Budget,
    factor: u64,
    pass: impl Fn(&str, &mut dyn FnMut(&str) -> Result<()>) -> Result<()>,
) -> Result<Option<String>> {
    budget.work(
        (input.len() as u64)
            .checked_mul(factor)
            .and_then(|n| n.checked_mul(2))
            .ok_or_else(|| anyhow!("Caddyfile shorthand work overflow"))?,
    )?;
    let mut len = 0;
    pass(input, &mut |s| {
        len = checked(len, s.len())?;
        Ok(())
    })?;
    // All supported replacements strictly grow. Equal length means unchanged,
    // so the original token can be retained without another materialization.
    if len == input.len() {
        return Ok(None);
    }
    budget.materialize(len as u64)?;
    let mut result = String::with_capacity(len);
    pass(input, &mut |s| {
        result.push_str(s);
        Ok(())
    })?;
    Ok(Some(result))
}
pub(super) fn apply(tokens: &mut [Token], budget: &mut Budget) -> Result<()> {
    for token in tokens {
        budget.work(token.text.len() as u64)?;
        if !token.text.contains('{') {
            continue;
        }
        if let Some(text) = replace(&token.text, budget, 8, |s, emit| simple_pass(s, emit))? {
            token.text = text;
        }
        for (name, target, dot) in COMPLEX {
            budget.work(token.text.len() as u64)?;
            // At most 13 static short trigger bytes; the allocation is fixed,
            // independent of token/configuration size.
            let trigger = format!("{{{name}.");
            if !token.text.contains(&trigger) {
                continue;
            }
            if let Some(text) = replace(&token.text, budget, (name.len() + 3) as u64, |s, emit| {
                complex_pass(s, name, target, *dot, emit)
            })? {
                token.text = text;
            }
        }
    }
    Ok(())
}
