use super::helpers::*;
use super::parse_request_regexp;
use super::types::*;
use anyhow::{Result, bail};
use serde_json::{Map, Value, json};
use std::sync::Arc;

/// Parse a RewritePlan from a JSON map.
///
/// When `handler` is true, the top-level "handler" field is accepted (in addition to the 7 standard fields).
/// When false, only the 7 standard fields are accepted.
/// Unknown fields are rejected. Null scalar defaults to empty string; null vec defaults to empty;
/// null query -> None; {} -> Some; array null elements -> default value (struct),
/// except for pathRegexp.replace and query.replace arrays where null elements -> Err.
pub(super) fn parse(
    m: &Map<String, Value>,
    path: &str,
    remaining: &mut usize,
    handler: bool,
) -> Result<RewritePlan> {
    // Standard fields: method, uri, strip_path_prefix, strip_path_suffix,
    // uri_substring, path_regexp, query
    let mut allowed = vec![
        "method",
        "uri",
        "strip_path_prefix",
        "strip_path_suffix",
        "uri_substring",
        "path_regexp",
        "query",
    ];
    if handler {
        allowed.push("handler");
    }
    deny_unknown(m, &allowed, path)?;

    // method: null scalar -> empty string
    let method = string_opt(m, "method", path, "")?;
    // uri: null scalar -> empty string
    let uri = string_opt(m, "uri", path, "")?;
    // strip_path_prefix: null scalar -> empty string
    let strip_path_prefix = string_opt(m, "strip_path_prefix", path, "")?;
    // strip_path_suffix: null scalar -> empty string
    let strip_path_suffix = string_opt(m, "strip_path_suffix", path, "")?;

    // uri_substring: null vec -> empty vec
    let uri_substring = parse_uri_substring(m, "uri_substring", path)?;

    // path_regexp: null vec -> empty vec; null element in array -> default value (Go struct semantics)
    let path_regexp = parse_path_regexp(m, "path_regexp", path, remaining)?;

    // query: null -> None; {} -> Some
    let query = parse_query_opt(m, "query", path, remaining)?;

    Ok(RewritePlan {
        method,
        uri,
        strip_path_prefix,
        strip_path_suffix,
        uri_substring,
        path_regexp,
        query,
    })
}

/// Helper: get a string field, treating null/missing as default.
fn string_opt(m: &Map<String, Value>, key: &str, path: &str, default: &str) -> Result<String> {
    match m.get(key) {
        None | Some(Value::Null) => Ok(default.to_string()),
        Some(v) => string(v, &format!("{}.{}", path, key)),
    }
}

/// Parse uri_substring array. Null elements become default RewriteSubstring.
fn parse_uri_substring(
    m: &Map<String, Value>,
    key: &str,
    path: &str,
) -> Result<Vec<RewriteSubstring>> {
    let arr_path = format!("{}.{}", path, key);
    match m.get(key) {
        None | Some(Value::Null) => Ok(vec![]),
        Some(Value::Array(arr)) => {
            anyhow::ensure!(arr.len() <= 65536, "rewrite operation count limit exceeded");
            let mut result = Vec::with_capacity(arr.len());
            for (i, item) in arr.iter().enumerate() {
                let item_path = format!("{}[{}]", arr_path, i);
                if item.is_null() {
                    result.push(RewriteSubstring::default());
                    continue;
                }
                let obj = expect_object(item, &item_path)?;
                result.push(parse_rewrite_substring(obj, &item_path)?);
            }
            Ok(result)
        }
        Some(_) => bail!("{} expected array", arr_path),
    }
}

fn parse_rewrite_substring(m: &Map<String, Value>, path: &str) -> Result<RewriteSubstring> {
    deny_unknown(m, &["find", "replace", "limit"], path)?;
    let find = string_opt(m, "find", path, "");
    let replace = string_opt(m, "replace", path, "");
    let limit = m
        .get("limit")
        .map(|v| {
            if v.is_null() {
                Ok(0i64)
            } else {
                v.as_i64()
                    .ok_or_else(|| anyhow::anyhow!("{}.limit expected i64", path))
            }
        })
        .unwrap_or(Ok(0i64))?;
    Ok(RewriteSubstring {
        find: find?,
        replace: replace?,
        limit,
    })
}

/// Parse path_regexp array. Null pointer rules are invalid.
fn parse_path_regexp(
    m: &Map<String, Value>,
    key: &str,
    path: &str,
    remaining: &mut usize,
) -> Result<Vec<RewriteRegex>> {
    let arr_path = format!("{}.{}", path, key);
    match m.get(key) {
        None | Some(Value::Null) => Ok(vec![]),
        Some(Value::Array(arr)) => {
            anyhow::ensure!(arr.len() <= 65536, "rewrite operation count limit exceeded");
            let mut result = Vec::with_capacity(arr.len());
            for (i, item) in arr.iter().enumerate() {
                let item_path = format!("{}[{}]", arr_path, i);
                if item.is_null() {
                    bail!("null path_regexp rule at {}", item_path);
                }
                let obj = expect_object(item, &item_path)?;
                result.push(parse_rewrite_regex(obj, &item_path, remaining)?);
            }
            Ok(result)
        }
        Some(_) => bail!("{} expected array", arr_path),
    }
}

fn parse_rewrite_regex(
    m: &Map<String, Value>,
    path: &str,
    remaining: &mut usize,
) -> Result<RewriteRegex> {
    deny_unknown(m, &["find", "replace"], path)?;
    // pathRegexp.find non-empty: parse_request_regexp expects {"pattern": pattern}
    let find_str = m
        .get("find")
        .map(|v| {
            if v.is_null() {
                Ok(String::new())
            } else {
                string(v, &format!("{}.find", path))
            }
        })
        .unwrap_or(Ok(String::new()))?;

    let regex = if find_str.is_empty() {
        None
    } else {
        Some(parse_request_regexp(&json!({"pattern": find_str}), remaining)?.regex)
    };

    let replace = string_opt(m, "replace", path, "")?;
    Ok(RewriteRegex { regex, replace })
}

/// Parse query option. Null -> None; Object -> Some.
fn parse_query_opt(
    m: &Map<String, Value>,
    key: &str,
    path: &str,
    remaining: &mut usize,
) -> Result<Option<RewriteQuery>> {
    let obj_path = format!("{}.{}", path, key);
    match m.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Object(obj)) => {
            let q = parse_rewrite_query(obj, &obj_path, remaining)?;
            Ok(Some(q))
        }
        Some(_) => bail!("{} expected object", obj_path),
    }
}

fn parse_rewrite_query(
    m: &Map<String, Value>,
    path: &str,
    remaining: &mut usize,
) -> Result<RewriteQuery> {
    deny_unknown(m, &["rename", "set", "add", "replace", "delete"], path)?;

    let rename = parse_args_array(m, "rename", path, false)?;
    let set = parse_args_array(m, "set", path, false)?;
    let add = parse_args_array(m, "add", path, false)?;
    let replace = parse_query_replace_array(m, "replace", path, remaining)?;
    let delete = parse_delete_array(m, "delete", path)?;

    Ok(RewriteQuery {
        rename,
        set,
        add,
        replace,
        delete,
    })
}

/// Parse Vec<RewriteArgument> from a key. Null elements -> default.
fn parse_args_array(
    m: &Map<String, Value>,
    key: &str,
    path: &str,
    _null_is_err: bool,
) -> Result<Vec<RewriteArgument>> {
    let arr_path = format!("{}.{}", path, key);
    match m.get(key) {
        None | Some(Value::Null) => Ok(vec![]),
        Some(Value::Array(arr)) => {
            anyhow::ensure!(arr.len() <= 65536, "rewrite operation count limit exceeded");
            let mut result = Vec::with_capacity(arr.len());
            for (i, item) in arr.iter().enumerate() {
                let item_path = format!("{}[{}]", arr_path, i);
                if item.is_null() {
                    // QueryArgs array null elements -> default value (Go struct)
                    result.push(RewriteArgument::default());
                    continue;
                }
                let obj = expect_object(item, &item_path)?;
                deny_unknown(obj, &["key", "val"], &item_path)?;
                let k = string_opt(obj, "key", &item_path, "")?;
                let v = string_opt(obj, "val", &item_path, "")?;
                result.push(RewriteArgument { key: k, val: v });
            }
            Ok(result)
        }
        Some(_) => bail!("{} expected array", arr_path),
    }
}

/// Parse query.replace array. Null elements -> Err.
fn parse_query_replace_array(
    m: &Map<String, Value>,
    key: &str,
    path: &str,
    remaining: &mut usize,
) -> Result<Vec<RewriteQueryReplace>> {
    let arr_path = format!("{}.{}", path, key);
    match m.get(key) {
        None | Some(Value::Null) => Ok(vec![]),
        Some(Value::Array(arr)) => {
            anyhow::ensure!(arr.len() <= 65536, "rewrite operation count limit exceeded");
            let mut result = Vec::with_capacity(arr.len());
            for (i, item) in arr.iter().enumerate() {
                let item_path = format!("{}[{}]", arr_path, i);
                if item.is_null() {
                    bail!(
                        "{}[{}] null element not allowed for query.replace",
                        arr_path,
                        i
                    );
                }
                let obj = expect_object(item, &item_path)?;
                result.push(parse_query_replace(obj, &item_path, remaining)?);
            }
            Ok(result)
        }
        Some(_) => bail!("{} expected array", arr_path),
    }
}

fn parse_query_replace(
    m: &Map<String, Value>,
    path: &str,
    remaining: &mut usize,
) -> Result<RewriteQueryReplace> {
    deny_unknown(m, &["key", "search", "search_regexp", "replace"], path)?;
    let key = string_opt(m, "key", path, "")?;
    let search = string_opt(m, "search", path, "")?;

    // search_regexp: only compile if non-empty
    let regex: Option<Arc<crate::go_regexp::GoRegexp>> = match m.get("search_regexp") {
        None | Some(Value::Null) => None,
        Some(v) => {
            let pattern = string(v, &format!("{}.search_regexp", path))?;
            if pattern.is_empty() {
                None
            } else {
                let json_val = json!({"pattern": pattern});
                let rr = parse_request_regexp(&json_val, remaining)?;
                Some(rr.regex)
            }
        }
    };

    let replace = string_opt(m, "replace", path, "")?;

    Ok(RewriteQueryReplace {
        key,
        search,
        regex,
        replace,
    })
}

/// Parse query deletions; null elements use the empty string default.
fn parse_delete_array(m: &Map<String, Value>, key: &str, path: &str) -> Result<Vec<String>> {
    let arr_path = format!("{}.{}", path, key);
    match m.get(key) {
        None | Some(Value::Null) => Ok(vec![]),
        Some(Value::Array(arr)) => {
            anyhow::ensure!(arr.len() <= 65536, "rewrite operation count limit exceeded");
            let mut result = Vec::with_capacity(arr.len());
            for (i, item) in arr.iter().enumerate() {
                let item_path = format!("{}[{}]", arr_path, i);
                if item.is_null() {
                    result.push(String::new());
                    continue;
                }
                let s = string(item, &item_path)?;
                result.push(s);
            }
            Ok(result)
        }
        Some(_) => bail!("{} expected array", arr_path),
    }
}

/// Helper: expect a Value to be a JSON object, returning its Map reference.
fn expect_object<'a>(v: &'a Value, path: &str) -> Result<&'a Map<String, Value>> {
    match v {
        Value::Object(map) => Ok(map),
        _ => bail!("{} expected object", path),
    }
}
