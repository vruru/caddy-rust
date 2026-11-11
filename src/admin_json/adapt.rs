//! Raw adaptation retains JSON lexemes instead of passing through a number DOM.
use super::{ConfigError, EncodingBytes, EncodingCount, EncodingSink, failure, html_escape};
use serde::Deserialize;

// Pinned Caddy 2.11.7 / Go 1.27.3 accepts raw depth 9999 and rejects 10000.
const MAX_RAW_DEPTH: usize = 9_999;

#[derive(Default)]
struct Quotes {
    inside: bool,
    escaped: bool,
}
impl Quotes {
    fn advance(&mut self, byte: u8) {
        if self.inside && self.escaped {
            self.escaped = false;
        } else if self.inside && byte == b'\\' {
            self.escaped = true;
        } else if byte == b'"' {
            self.inside = !self.inside;
        }
    }
}

fn validate(input: &[u8]) -> Result<(), ConfigError> {
    let mut quotes = Quotes::default();
    let mut depth = 0usize;
    for &byte in input {
        if !quotes.inside {
            match byte {
                b'[' | b'{' => {
                    depth += 1;
                    if depth > MAX_RAW_DEPTH {
                        return Err(failure("raw_json_depth_limit"));
                    }
                }
                b']' | b'}' => depth = depth.saturating_sub(1),
                _ => {}
            }
        }
        quotes.advance(byte);
    }
    // IgnoredAny uses serde_json's iterative grammar scanner: no number
    // conversion, recursive Value, string decoding or UTF-8 replacement.
    let mut decoder = serde_json::Deserializer::from_slice(input);
    serde::de::IgnoredAny::deserialize(&mut decoder).map_err(|_| failure("adapt_invalid_json"))?;
    decoder.end().map_err(|_| failure("adapt_invalid_json"))
}

fn write_raw<S: EncodingSink>(input: &[u8], sink: &mut S) -> Result<(), ConfigError> {
    sink.put(b"{\"result\":")?;
    let mut quotes = Quotes::default();
    let mut start = 0;
    let mut index = 0;
    while index < input.len() {
        let byte = input[index];
        if !quotes.inside && matches!(byte, b' ' | b'\n' | b'\r' | b'\t') {
            sink.put(&input[start..index])?;
            index += 1;
            start = index;
            continue;
        }
        if quotes.inside
            && !quotes.escaped
            && let Some((escaped, consumed)) = html_escape(input, index, true)
        {
            sink.put(&input[start..index])?;
            sink.put(escaped)?;
            index += consumed;
            start = index;
            continue;
        }
        quotes.advance(byte);
        index += 1;
    }
    sink.put(&input[start..])?;
    sink.put(b"}\n")
}

/// Encode the JSON no-op `/adapt` response. The byte limit includes the wrapper
/// and final newline. Ordinary configuration loads and ETags use the DOM codec.
pub fn encoded_adapt_raw(input: &[u8], limit: usize) -> Result<Vec<u8>, ConfigError> {
    encoded_adapt_raw_reserved(input, limit, |_| Ok(())).map(|(bytes, ())| bytes)
}

pub(crate) fn encoded_adapt_raw_reserved<G>(
    input: &[u8],
    limit: usize,
    reserve: impl FnOnce(usize) -> Result<G, ConfigError>,
) -> Result<(Vec<u8>, G), ConfigError> {
    validate(input)?;
    let mut count = EncodingCount { count: 0, limit };
    write_raw(input, &mut count)?;
    let reservation = reserve(count.count)?;
    let exhausted = || ConfigError {
        status: 503,
        category: "admin_buffer_allocation_failed",
    };
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(count.count)
        .map_err(|_| exhausted())?;
    if bytes.capacity() != count.count {
        return Err(exhausted());
    }
    write_raw(input, &mut EncodingBytes(&mut bytes))?;
    Ok((bytes, reservation))
}
