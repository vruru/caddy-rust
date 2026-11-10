// Copyright 2015 Matthew Holt and The Caddy Authors.
// SPDX-License-Identifier: Apache-2.0
//! Caddy v2.11.7 Admin API JSON traversal semantics. This module does not
//! authenticate requests, activate configuration, or perform filesystem I/O.
//! The controller must mutate a private candidate and publish only on success.

use serde_json::{Map, Value};
use std::fmt;

#[path = "admin_json/codec.rs"]
mod codec;

/// An explicit control-plane resource bound, rather than serde's implicit
/// 128-level parser bound. The original Go scanner accepts up to 10000 levels;
/// expanding this bound requires a measured stack budget for all consumers.
pub const MAX_CONFIG_DEPTH: usize = 256;

pub fn decoded(input: &[u8]) -> Result<Value, ConfigError> {
    let sanitized = codec::sanitize(input, MAX_CONFIG_DEPTH)?;
    let mut decoder = serde_json::Deserializer::from_slice(&sanitized);
    decoder.disable_recursion_limit();
    let value = serde::Deserialize::deserialize(&mut decoder).map_err(|_| ConfigError {
        status: 400,
        category: "invalid_json_configuration",
    })?;
    decoder.end().map_err(|_| ConfigError {
        status: 400,
        category: "invalid_json_configuration",
    })?;
    // Go's any -> marshal -> typed-decode path rounds all numbers to f64.
    // Re-read the canonical representation to retain integral typed fields.
    let bytes = encoded(&value)?;
    let mut decoder = serde_json::Deserializer::from_slice(&bytes);
    decoder.disable_recursion_limit();
    serde::Deserialize::deserialize(&mut decoder).map_err(|_| ConfigError {
        status: 400,
        category: "invalid_json_configuration",
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfigError {
    pub status: u16,
    pub category: &'static str,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.category)
    }
}
impl std::error::Error for ConfigError {}

fn failure(category: &'static str) -> ConfigError {
    ConfigError {
        status: 500,
        category,
    }
}

/// The caller supplies the complete root (normally {"config": <configuration>}).
/// Path segments are already URL-decoded by the HTTP layer. They are not JSON
/// Pointer escapes: ~0 and ~1 remain literal, as in the original implementation.
pub fn access(
    root: &mut Value,
    method: &str,
    path: &str,
    body: Option<Value>,
) -> Result<Option<Value>, ConfigError> {
    let (parts, ellipses) = path_parts(path)?;
    if method == "GET" {
        return read_parts(root, &parts).map(|v| v.cloned());
    }
    let payload = body.unwrap_or(Value::Null);
    let mut current = root;
    for (position, part) in parts.iter().enumerate() {
        match current {
            Value::Object(map) => {
                if position + 2 == parts.len() && map.get(*part).is_some_and(Value::is_array) {
                    let Some(Value::Array(array)) = map.get_mut(*part) else {
                        unreachable!()
                    };
                    return array_destination(
                        array,
                        method,
                        parts[position + 1],
                        payload,
                        ellipses,
                    );
                }
                if position + 1 == parts.len() {
                    return map_destination(map, method, part, payload, ellipses);
                }
                if method == "PUT" && map.get(*part).is_none_or(Value::is_null) {
                    map.insert((*part).to_owned(), Value::Object(Map::new()));
                }
                current = map
                    .get_mut(*part)
                    .ok_or_else(|| failure("invalid_traversal_path"))?;
            }
            Value::Array(array) => {
                let index = canonical_index(part)?;
                current = array
                    .get_mut(index)
                    .ok_or_else(|| failure("array_index_out_of_bounds"))?;
            }
            _ => return Err(failure("invalid_traversal_path")),
        }
    }
    // Preserve the original no-output/no-mutation case when traversal ends
    // directly inside a nested array, and the special path ending in /....
    Ok(None)
}

fn path_parts(path: &str) -> Result<(Vec<&str>, bool), ConfigError> {
    let clean = path.trim_matches('/');
    if clean.is_empty() {
        return Err(failure("no_traversable_path"));
    }
    let mut parts: Vec<_> = clean.split('/').take(MAX_CONFIG_DEPTH + 2).collect();
    let ellipses = parts.last() == Some(&"...");
    if ellipses {
        parts.pop();
    }
    if parts.len() > MAX_CONFIG_DEPTH {
        return Err(ConfigError {
            status: 400,
            category: "configuration_depth_limit",
        });
    }
    Ok((parts, ellipses))
}

static NULL_VALUE: Value = Value::Null;

/// Borrow a subpath of the virtual {"config": raw} root without cloning the
/// complete document. The caller retains its immutable version snapshot.
pub fn read_config<'a>(raw: &'a Value, path: &str) -> Result<Option<&'a Value>, ConfigError> {
    let (parts, _) = path_parts(path)?;
    match parts.split_first() {
        None => Ok(None),
        Some((&"config", [])) => Ok(Some(raw)),
        Some((&"config", [index])) if raw.is_array() => {
            let array = raw
                .as_array()
                .ok_or_else(|| failure("invalid_traversal_path"))?;
            array
                .get(canonical_index(index)?)
                .map(Some)
                .ok_or_else(|| failure("array_index_out_of_bounds"))
        }
        Some((&"config", rest)) => read_parts(raw, rest),
        Some((_, [])) => Ok(Some(&NULL_VALUE)),
        _ => Err(failure("invalid_traversal_path")),
    }
}

fn read_parts<'a>(
    mut current: &'a Value,
    parts: &[&str],
) -> Result<Option<&'a Value>, ConfigError> {
    for (position, part) in parts.iter().enumerate() {
        match current {
            Value::Object(map) => {
                if position + 2 == parts.len()
                    && let Some(Value::Array(array)) = map.get(*part)
                {
                    return array
                        .get(canonical_index(parts[position + 1])?)
                        .map(Some)
                        .ok_or_else(|| failure("array_index_out_of_bounds"));
                }
                if position + 1 == parts.len() {
                    return Ok(Some(map.get(*part).unwrap_or(&NULL_VALUE)));
                }
                current = map
                    .get(*part)
                    .ok_or_else(|| failure("invalid_traversal_path"))?;
            }
            Value::Array(array) => {
                current = array
                    .get(canonical_index(part)?)
                    .ok_or_else(|| failure("array_index_out_of_bounds"))?;
            }
            _ => return Err(failure("invalid_traversal_path")),
        }
    }
    // Preserve the original no-output nested-array terminal case.
    Ok(None)
}

fn map_destination(
    map: &mut Map<String, Value>,
    method: &str,
    key: &str,
    value: Value,
    splat: bool,
) -> Result<Option<Value>, ConfigError> {
    match method {
        "POST" => {
            if let Some(Value::Array(array)) = map.get_mut(key) {
                append(array, value, splat)?;
            } else {
                map.insert(key.to_owned(), value);
            }
        }
        "PUT" => {
            if map.contains_key(key) {
                return Err(ConfigError {
                    status: 409,
                    category: "key_already_exists",
                });
            }
            map.insert(key.to_owned(), value);
        }
        "PATCH" => {
            if !map.contains_key(key) {
                return Err(ConfigError {
                    status: 404,
                    category: "key_not_found",
                });
            }
            map.insert(key.to_owned(), value);
        }
        "DELETE" => {
            if map.remove(key).is_none() {
                return Err(ConfigError {
                    status: 404,
                    category: "key_not_found",
                });
            }
        }
        _ => return Err(failure("unrecognized_method")),
    }
    Ok(None)
}

fn array_destination(
    array: &mut Vec<Value>,
    method: &str,
    segment: &str,
    value: Value,
    splat: bool,
) -> Result<Option<Value>, ConfigError> {
    if method == "POST" {
        append(array, value, splat)?;
        return Ok(None);
    }
    let index = canonical_index(segment)?;
    if index > array.len() || (method != "PUT" && index == array.len()) {
        return Err(failure("array_index_out_of_bounds"));
    }
    match method {
        "PUT" => array.insert(index, value),
        "PATCH" => array[index] = value,
        "DELETE" => {
            array.remove(index);
        }
        _ => return Err(failure("unrecognized_method")),
    }
    Ok(None)
}

fn append(array: &mut Vec<Value>, value: Value, splat: bool) -> Result<(), ConfigError> {
    if splat {
        let Value::Array(mut values) = value else {
            return Err(failure("final_element_not_array"));
        };
        array.append(&mut values);
    } else {
        array.push(value);
    }
    Ok(())
}

fn canonical_index(segment: &str) -> Result<usize, ConfigError> {
    if segment.is_empty()
        || (segment.len() > 1 && segment.starts_with('0'))
        || !segment.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(failure("invalid_array_index"));
    }
    let value = segment
        .parse::<usize>()
        .map_err(|_| failure("invalid_array_index"))?;
    if value > isize::MAX as usize {
        return Err(failure("invalid_array_index"));
    }
    Ok(value)
}

/// Match encoding/json's map ordering, float64 numbers, HTML-safe escaping,
/// and Encoder.Encode trailing newline, which participate in Caddy ETags.
pub fn encoded(value: &Value) -> Result<Vec<u8>, ConfigError> {
    fn write(value: &Value, output: &mut Vec<u8>, depth: usize) -> Result<(), ConfigError> {
        if depth > MAX_CONFIG_DEPTH {
            return Err(failure("configuration_depth_limit"));
        }
        match value {
            Value::Null => output.extend_from_slice(b"null"),
            Value::Bool(value) => output.extend_from_slice(if *value { b"true" } else { b"false" }),
            Value::Number(value) => {
                let number = value
                    .as_f64()
                    .ok_or_else(|| failure("invalid_json_number"))?;
                output.extend_from_slice(go_float(number)?.as_bytes());
            }
            Value::String(value) => {
                let text = serde_json::to_string(value)
                    .map_err(|_| failure("json_encoding_failed"))?
                    .replace('<', "\\u003c")
                    .replace('>', "\\u003e")
                    .replace('&', "\\u0026")
                    .replace('\u{2028}', "\\u2028")
                    .replace('\u{2029}', "\\u2029");
                output.extend_from_slice(text.as_bytes());
            }
            Value::Array(values) => {
                output.push(b'[');
                for (index, value) in values.iter().enumerate() {
                    if index > 0 {
                        output.push(b',');
                    }
                    write(value, output, depth + 1)?;
                }
                output.push(b']');
            }
            Value::Object(values) => {
                output.push(b'{');
                let mut keys = values.keys().collect::<Vec<_>>();
                keys.sort_unstable();
                for (index, key) in keys.into_iter().enumerate() {
                    if index > 0 {
                        output.push(b',');
                    }
                    write(&Value::String(key.clone()), output, depth + 1)?;
                    output.push(b':');
                    write(&values[key], output, depth + 1)?;
                }
                output.push(b'}');
            }
        }
        Ok(())
    }
    let mut bytes = Vec::new();
    write(value, &mut bytes, 0)?;
    bytes.push(b'\n');
    Ok(bytes)
}

pub fn etag(path: &str, value: Option<&Value>) -> Result<String, ConfigError> {
    let bytes = value.map(encoded).transpose()?.unwrap_or_default();
    Ok(etag_encoded(path, &bytes))
}

/// Use the exact response bytes, including Encoder.Encode's trailing newline;
/// an absent output is the empty slice. This avoids encoding a large read twice.
pub fn etag_encoded(path: &str, bytes: &[u8]) -> String {
    let hash = xxhash_rust::xxh64::xxh64(bytes, 0);
    format!("\"{path} {hash:016x}\"")
}

fn go_float(value: f64) -> Result<String, ConfigError> {
    if !value.is_finite() {
        return Err(failure("invalid_json_number"));
    }
    if value == 0.0 {
        return Ok(if value.is_sign_negative() { "-0" } else { "0" }.to_owned());
    }
    let mut buffer = ryu::Buffer::new();
    let text = buffer.format_finite(value);
    let (sign, text) = text.strip_prefix('-').map_or(("", text), |s| ("-", s));
    let (mantissa, exponent) = if let Some((a, b)) = text.split_once('e') {
        (
            a,
            b.parse::<i32>()
                .map_err(|_| failure("json_number_encoding_failed"))?,
        )
    } else {
        (text, 0)
    };
    let point = mantissa.find('.').unwrap_or(mantissa.len()) as i32 + exponent;
    let raw = mantissa.bytes().filter(|b| *b != b'.').collect::<Vec<_>>();
    let start = raw
        .iter()
        .position(|b| *b != b'0')
        .ok_or_else(|| failure("json_number_encoding_failed"))?;
    let end = raw.iter().rposition(|b| *b != b'0').unwrap() + 1;
    let digits = std::str::from_utf8(&raw[start..end])
        .map_err(|_| failure("json_number_encoding_failed"))?;
    let point = point - start as i32;
    let mut result = String::from(sign);
    if value.abs() < 1e-6 || value.abs() >= 1e21 {
        result.push_str(&digits[..1]);
        if digits.len() > 1 {
            result.push('.');
            result.push_str(&digits[1..]);
        }
        result.push('e');
        let exponent = point - 1;
        if exponent >= 0 {
            result.push('+');
        }
        result.push_str(&exponent.to_string());
    } else if point <= 0 {
        result.push_str("0.");
        result.extend(std::iter::repeat_n('0', (-point) as usize));
        result.push_str(digits);
    } else if point as usize >= digits.len() {
        result.push_str(digits);
        result.extend(std::iter::repeat_n('0', point as usize - digits.len()));
    } else {
        let point = point as usize;
        result.push_str(&digits[..point]);
        result.push('.');
        result.push_str(&digits[point..]);
    }
    Ok(result)
}
