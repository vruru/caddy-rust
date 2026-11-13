// HeaderOps behavior follows Caddy v2.11.7 (Apache-2.0).
use super::{helpers::*, parse_response_matcher, types::*};
use anyhow::{Result, ensure};
use serde_json::{Map, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
const MAX_OPERATIONS: usize = 65536;
fn count(total: &mut usize, n: usize) -> Result<()> {
    *total = total
        .checked_add(n)
        .filter(|n| *n <= MAX_OPERATIONS)
        .ok_or_else(|| anyhow::anyhow!("header operation count limit exceeded"))?;
    Ok(())
}
pub(super) fn contains_placeholders(s: &str) -> bool {
    s.split_once('{')
        .and_then(|(_, tail)| tail.find('}'))
        .is_some_and(|n| n > 0)
}
fn text(m: &Map<String, Value>, key: &str, path: &str) -> Result<String> {
    m.get(key)
        .filter(|v| !v.is_null())
        .map(|v| string(v, path))
        .transpose()
        .map(Option::unwrap_or_default)
}
fn array_strings(v: &Value, path: &str, total: &mut usize) -> Result<Vec<String>> {
    if v.is_null() {
        return Ok(Vec::new());
    }
    let a = v
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("header array required at {path}"))?;
    count(total, a.len())?;
    a.iter()
        .map(|v| {
            if v.is_null() {
                Ok(String::new())
            } else {
                string(v, path)
            }
        })
        .collect()
}
fn field(v: &str) -> Result<String> {
    ensure!(
        !v.contains(['\r', '\n', '\0']),
        "invalid configured header name"
    );
    match http::HeaderName::try_from(v) {
        Ok(name) => Ok(name.as_str().to_owned()),
        Err(_) if contains_placeholders(v) => Ok(v.to_owned()),
        Err(_) => anyhow::bail!("invalid configured header name"),
    }
}
fn values(
    v: Option<&Value>,
    path: &str,
    merge: bool,
    total: &mut usize,
) -> Result<Vec<(String, Vec<String>)>> {
    let Some(v) = v.filter(|v| !v.is_null()) else {
        return Ok(Vec::new());
    };
    let m = object(v, path)?;
    count(total, m.len())?;
    let mut out = Vec::new();
    let mut grouped = BTreeMap::<String, Vec<String>>::new();
    for (k, v) in m {
        let canonical = field(k)?;
        let vals = array_strings(v, path, total)?;
        ensure!(
            vals.iter().all(|s| !s.contains(['\r', '\n', '\0'])),
            "invalid configured header value"
        );
        if merge {
            grouped.entry(canonical).or_default().extend(vals);
        } else {
            out.push((k.clone(), vals));
        }
    }
    if merge {
        out.extend(grouped);
    }
    Ok(out)
}
fn keys<'a>(text: &'a str, out: &mut BTreeSet<&'a str>) -> Result<()> {
    let bytes = text.as_bytes();
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] != b'{' || (at > 0 && bytes[at - 1] == b'\\') {
            at += 1;
            continue;
        }
        let mut end = at + 1;
        while end < bytes.len()
            && (bytes[end] != b'}' || (bytes[end - 1] == b'\\' && end + 1 < bytes.len()))
        {
            end += 1;
        }
        if end == bytes.len() {
            at += 1;
            continue;
        }
        out.insert(&text[at + 1..end]);
        ensure!(
            out.len() <= MAX_OPERATIONS,
            "header placeholder count limit exceeded"
        );
        // Unknown outer placeholders are retained by ReplaceKnown, which then
        // scans nested opening braces too. Capture every possible lookup.
        at += 1;
    }
    Ok(())
}
pub(super) fn parse(
    v: &Value,
    path: &str,
    response: bool,
    remaining: &mut usize,
) -> Result<HeaderOps> {
    if v.is_null() {
        return Ok(HeaderOps::default());
    }
    let m = object(v, path)?;
    deny_unknown(
        m,
        if response {
            &["set", "add", "delete", "replace", "deferred", "require"]
        } else {
            &["set", "add", "delete", "replace"]
        },
        path,
    )?;
    let mut total = 0;
    let set = values(m.get("set"), path, true, &mut total)?;
    let add = values(m.get("add"), path, false, &mut total)?;
    let delete = m
        .get("delete")
        .map(|v| array_strings(v, path, &mut total))
        .transpose()?
        .unwrap_or_default();
    ensure!(
        delete.iter().all(|s| !s.contains(['\r', '\n', '\0'])),
        "invalid configured header deletion"
    );
    let mut replace = Vec::new();
    if let Some(v) = m.get("replace").filter(|v| !v.is_null()) {
        let fields = object(v, path)?;
        count(&mut total, fields.len())?;
        for (name, v) in fields {
            ensure!(
                !name.contains(['\r', '\n', '\0']),
                "invalid replacement header selector"
            );
            let mut rules = Vec::new();
            if !v.is_null() {
                let array = v
                    .as_array()
                    .ok_or_else(|| anyhow::anyhow!("header replacement array required"))?;
                count(&mut total, array.len())?;
                for r in array {
                    if r.is_null() {
                        rules.push(HeaderReplacement::default());
                        continue;
                    }
                    let r = object(r, path)?;
                    deny_unknown(r, &["search", "search_regexp", "replace"], path)?;
                    let search = text(r, "search", path)?;
                    let search_regexp = text(r, "search_regexp", path)?;
                    let replacement = text(r, "replace", path)?;
                    ensure!(
                        search.is_empty() || search_regexp.is_empty(),
                        "cannot specify both header substring and regexp search"
                    );
                    let regex =
                        if !search_regexp.is_empty() && !contains_placeholders(&search_regexp) {
                            Some(super::header_compile::compile_static(
                                &search_regexp,
                                remaining,
                            )?)
                        } else {
                            None
                        };
                    rules.push(HeaderReplacement {
                        search,
                        search_regexp,
                        replace: replacement,
                        regex,
                    });
                }
            }
            replace.push((name.clone(), Arc::from(rules)));
        }
    }
    let replace: Arc<[(String, Arc<[HeaderReplacement]>)]> = replace.into();
    let mut names = BTreeSet::new();
    for (name, rules) in replace.iter() {
        keys(name, &mut names)?;
        for rule in rules.iter() {
            keys(&rule.search, &mut names)?;
            keys(&rule.search_regexp, &mut names)?;
            keys(&rule.replace, &mut names)?;
        }
    }
    let replace_keys = names
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>()
        .into();
    let require = m
        .get("require")
        .filter(|v| !v.is_null())
        .map(|v| parse_response_matcher(v, path))
        .transpose()?;
    Ok(HeaderOps {
        set,
        add,
        delete,
        require,
        replace,
        replace_keys,
    })
}
