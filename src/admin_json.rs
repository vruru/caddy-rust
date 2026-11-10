// Copyright 2015 Matthew Holt and The Caddy Authors.
// SPDX-License-Identifier: Apache-2.0
//! Caddy v2.11.7 Admin API JSON traversal semantics. This module does not
//! authenticate requests, activate configuration, or perform filesystem I/O.
//! The controller must mutate a private candidate and publish only on success.

use serde_json::{Map, Value};
use std::fmt;

#[path = "admin_json/adapt.rs"]
mod adapt;
#[path = "admin_json/codec.rs"]
mod codec;
pub use adapt::encoded_adapt_raw;

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
    let mut bytes = Vec::new();
    let mut sink = EncodingBytes(&mut bytes);
    write_encoded(value, &mut sink, 0)?;
    sink.put(b"\n")?;
    Ok(bytes)
}

/// Count the same canonical bytes as `encoded`, including its final newline.
/// Stop at the byte limit without constructing the encoded result or escaped
/// strings. Sorting an object's borrowed keys still uses O(number of keys) space.
/// Number formatting retains the existing bounded temporary float string.
/// A limit reached before a later encoding error takes precedence over that error.
pub fn encoded_len(value: &Value, limit: usize) -> Result<usize, ConfigError> {
    let mut sink = EncodingCount { count: 0, limit };
    write_encoded(value, &mut sink, 0)?;
    sink.put(b"\n")?;
    Ok(sink.count)
}

/// Encode a typed adapter/CLI result without rounding integer durations through
/// float64. Raw Admin configuration maps and their ETags must keep using encoded.
pub fn encoded_typed(value: &Value) -> Result<Vec<u8>, ConfigError> {
    let mut bytes = Vec::new();
    let mut sink = EncodingBytes(&mut bytes);
    write_encoded_inner(value, &mut sink, 0, NumberMode::Typed)?;
    sink.put(b"\n")?;
    Ok(bytes)
}

/// Count the very same typed bytes, including the Encoder.Encode newline.
pub fn encoded_len_typed(value: &Value, limit: usize) -> Result<usize, ConfigError> {
    let mut sink = EncodingCount { count: 0, limit };
    write_encoded_inner(value, &mut sink, 0, NumberMode::Typed)?;
    sink.put(b"\n")?;
    Ok(sink.count)
}

trait EncodingSink {
    fn put(&mut self, bytes: &[u8]) -> Result<(), ConfigError>;
    fn lower_bound(&self, _length: usize) -> Result<(), ConfigError> {
        Ok(())
    }
}

struct EncodingBytes<'a>(&'a mut Vec<u8>);
impl EncodingSink for EncodingBytes<'_> {
    fn put(&mut self, bytes: &[u8]) -> Result<(), ConfigError> {
        self.0.extend_from_slice(bytes);
        Ok(())
    }
}

struct EncodingCount {
    count: usize,
    limit: usize,
}
impl EncodingSink for EncodingCount {
    fn put(&mut self, bytes: &[u8]) -> Result<(), ConfigError> {
        self.lower_bound(bytes.len())?;
        self.count += bytes.len();
        Ok(())
    }
    fn lower_bound(&self, length: usize) -> Result<(), ConfigError> {
        if self
            .count
            .checked_add(length)
            .is_none_or(|n| n > self.limit)
        {
            return Err(encoding_byte_limit());
        }
        Ok(())
    }
}

fn encoding_byte_limit() -> ConfigError {
    ConfigError {
        status: 413,
        category: "json_encoding_byte_limit",
    }
}

#[derive(Clone, Copy)]
enum NumberMode {
    GoFloat,
    Typed,
}

fn write_encoded<S: EncodingSink>(
    value: &Value,
    sink: &mut S,
    depth: usize,
) -> Result<(), ConfigError> {
    write_encoded_inner(value, sink, depth, NumberMode::GoFloat)
}

fn write_encoded_inner<S: EncodingSink>(
    value: &Value,
    sink: &mut S,
    depth: usize,
    mode: NumberMode,
) -> Result<(), ConfigError> {
    if depth > MAX_CONFIG_DEPTH {
        return Err(failure("configuration_depth_limit"));
    }
    match value {
        Value::Null => sink.put(b"null"),
        Value::Bool(value) => sink.put(if *value { b"true" } else { b"false" }),
        Value::Number(value) => {
            if matches!(mode, NumberMode::Typed) {
                if let Some(number) = value.as_i64() {
                    return sink.put(number.to_string().as_bytes());
                }
                if let Some(number) = value.as_u64() {
                    return sink.put(number.to_string().as_bytes());
                }
            }
            let number = value
                .as_f64()
                .ok_or_else(|| failure("invalid_json_number"))?;
            sink.put(go_float(number)?.as_bytes())
        }
        Value::String(value) => write_encoded_string(value, sink),
        Value::Array(values) => {
            sink.put(b"[")?;
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    sink.put(b",")?;
                }
                write_encoded_inner(value, sink, depth + 1, mode)?;
            }
            sink.put(b"]")
        }
        Value::Object(values) => {
            sink.put(b"{")?;
            let mut keys = values.keys().collect::<Vec<_>>();
            keys.sort_unstable();
            for (index, key) in keys.into_iter().enumerate() {
                if index > 0 {
                    sink.put(b",")?;
                }
                // The previous encoder visited a synthetic String at depth + 1.
                // Preserve that boundary without cloning the borrowed key.
                if depth + 1 > MAX_CONFIG_DEPTH {
                    return Err(failure("configuration_depth_limit"));
                }
                write_encoded_string(key, sink)?;
                sink.put(b":")?;
                write_encoded_inner(&values[key], sink, depth + 1, mode)?;
            }
            sink.put(b"}")
        }
    }
}

fn write_encoded_string<S: EncodingSink>(value: &str, sink: &mut S) -> Result<(), ConfigError> {
    sink.lower_bound(value.len().checked_add(2).ok_or_else(encoding_byte_limit)?)?;
    sink.put(b"\"")?;
    let bytes = value.as_bytes();
    let mut start = 0;
    let mut index = 0;
    while index < bytes.len() {
        if let Some((escaped, consumed)) = html_escape(bytes, index) {
            sink.put(&bytes[start..index])?;
            sink.put(escaped)?;
            index += consumed;
            start = index;
            continue;
        }
        let mut control = *b"\\u0000";
        let (escaped, consumed): (&[u8], usize) = match bytes[index] {
            b'"' => (b"\\\"", 1),
            b'\\' => (b"\\\\", 1),
            8 => (b"\\b", 1),
            12 => (b"\\f", 1),
            b'\n' => (b"\\n", 1),
            b'\r' => (b"\\r", 1),
            b'\t' => (b"\\t", 1),
            b @ 0..=31 => {
                const HEX: &[u8; 16] = b"0123456789abcdef";
                control[4] = HEX[(b >> 4) as usize];
                control[5] = HEX[(b & 15) as usize];
                (&control, 1)
            }
            _ => {
                index += 1;
                if index - start >= 256 {
                    sink.put(&bytes[start..index])?;
                    start = index;
                }
                continue;
            }
        };
        sink.put(&bytes[start..index])?;
        sink.put(escaped)?;
        index += consumed;
        start = index;
    }
    sink.put(&bytes[start..])?;
    sink.put(b"\"")
}

fn html_escape(bytes: &[u8], index: usize) -> Option<(&'static [u8], usize)> {
    match bytes[index] {
        b'<' => Some((b"\\u003c", 1)),
        b'>' => Some((b"\\u003e", 1)),
        b'&' => Some((b"\\u0026", 1)),
        0xe2 if bytes[index..].starts_with(b"\xe2\x80\xa8") => Some((b"\\u2028", 3)),
        0xe2 if bytes[index..].starts_with(b"\xe2\x80\xa9") => Some((b"\\u2029", 3)),
        _ => None,
    }
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
