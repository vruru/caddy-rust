use std::collections::BTreeMap;

/// net/url.ParseQuery partial-success semantics, followed by Values.Set/Encode.
/// Bytes are preserved: Go strings do not require UTF-8 query components.
pub(super) fn query_with_domain(query: &str, domain: &str) -> String {
    query_with_values(query, &[("domain", domain)])
}
pub(super) fn query_with_values(query: &str, replacements: &[(&str, &str)]) -> String {
    let mut values: BTreeMap<Vec<u8>, Vec<Vec<u8>>> = BTreeMap::new();
    let count = query.bytes().filter(|byte| *byte == b'&').count() + 1;
    let custom = std::env::var("GODEBUG").ok().and_then(|setting| {
        setting
            .split(',')
            .rev()
            .find_map(|part| part.strip_prefix("urlmaxqueryparams="))
            .and_then(|value| value.parse::<i64>().ok())
    });
    // net/url rejects the entire raw query above its limit. Values.Set still
    // adds the normalized domain; partial pairs survive only syntax failures.
    let within_limit = custom.map_or(count <= 10_000, |max| max == 0 || (count as i64) < max);
    for pair in query
        .split('&')
        .filter(|pair| within_limit && !pair.is_empty())
    {
        if pair.contains(';') {
            continue;
        }
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let (Some(key), Some(value)) = (decode(key), decode(value)) else {
            continue;
        };
        values.entry(key).or_default().push(value);
    }
    for (key,value) in replacements {
        values.insert(key.as_bytes().to_vec(), vec![value.as_bytes().to_vec()]);
    }
    let mut result = String::new();
    for (key, values) in values {
        for value in values {
            if !result.is_empty() {
                result.push('&');
            }
            escape(&key, &mut result);
            result.push('=');
            escape(&value, &mut result);
        }
    }
    result
}
fn decode(component: &str) -> Option<Vec<u8>> {
    let bytes = component.as_bytes();
    let mut result = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => result.push(b' '),
            b'%' => {
                let high = (*bytes.get(i + 1)? as char).to_digit(16)?;
                let low = (*bytes.get(i + 2)? as char).to_digit(16)?;
                result.push(((high << 4) | low) as u8);
                i += 2;
            }
            byte => result.push(byte),
        }
        i += 1;
    }
    Some(result)
}
fn escape(bytes: &[u8], result: &mut String) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for &byte in bytes {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(byte as char)
            }
            b' ' => result.push('+'),
            _ => {
                result.push('%');
                result.push(HEX[(byte >> 4) as usize] as char);
                result.push(HEX[(byte & 15) as usize] as char);
            }
        }
    }
}
