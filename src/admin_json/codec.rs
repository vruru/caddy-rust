use super::ConfigError;

// Punctuation outside quoted strings bounds the number of allocated tree
// entries before the DOM parser allocates. The existing Admin index has a
// 100,000-entry cap; allow up to four tokens per entry for structure and
// duplicate keys. Raw /adapt validation intentionally does not build a DOM.
const MAX_SHAPE_TOKENS: usize = 400_000;

#[derive(Default)]
struct Shape {
    tokens: usize,
    depth: usize,
}

impl Shape {
    fn advance(&mut self, byte: u8, max_depth: usize, max_shape_tokens:usize) -> Result<(), ConfigError> {
        if matches!(byte, b'[' | b'{' | b',' | b':') {
            self.tokens += 1;
            if self.tokens > max_shape_tokens {
                return Err(ConfigError {
                    status: 413,
                    category: "configuration_materialization_limit",
                });
            }
        }
        match byte {
            b'[' | b'{' => {
                self.depth += 1;
                if self.depth > max_depth {
                    return Err(ConfigError {
                        status: 400,
                        category: "configuration_depth_limit",
                    });
                }
            }
            b']' | b'}' => self.depth = self.depth.saturating_sub(1),
            _ => {}
        }
        Ok(())
    }
}

/// Check shape on bytes emitted by the canonical encoder. These bytes already
/// contain valid UTF-8 and well-formed escapes and need no sanitizer copy.
pub(super) fn check_canonical(input: &[u8], max_depth: usize) -> Result<(), ConfigError> {
    let mut shape = Shape::default();
    let mut in_string = false;
    let mut escaped = false;
    for &byte in input {
        if in_string {
            if escaped {
                escaped = false;
            } else {
                match byte {
                    b'\\' => escaped = true,
                    b'"' => in_string = false,
                    _ => {}
                }
            }
        } else {
            shape.advance(byte,max_depth,MAX_SHAPE_TOKENS)?;
            in_string = byte == b'"';
        }
    }
    Ok(())
}

/// Pure O(n) iterative byte-scan sanitizer for JSON body bytes.
/// - Inside strings: validates UTF-8 in ≤4-byte windows (rejects overlong,
///   surrogates, >U+10FFFF via `std::str::from_utf8`), emits one U+FFFD per
///   invalid byte.  Escaped lone surrogates rewritten to `\ufffd`; valid
///   high+low pairs copied; malformed hex passed through (serde rejects).
///   `\\` is a literal backslash (next char is NOT an escape toggle);
///   `\"` does NOT close the string.
/// - Outside strings: tracks `[`/`{` depth; saturating decrement on `]`/`}`;
///   rejects depth > max_depth.  All other bytes passed unchanged.
/// - No unsafe, no unwrap, no panic, no allocation beyond the output Vec.
pub(super) fn sanitize(input:&[u8],max_depth:usize)->Result<Vec<u8>,ConfigError>{sanitize_bounded(input,max_depth,MAX_SHAPE_TOKENS)}

pub(super) fn sanitize_bounded(input:&[u8],max_depth:usize,max_shape_tokens:usize)->Result<Vec<u8>,ConfigError>{
    let mut out: Vec<u8> = Vec::with_capacity(input.len().min(1024 * 1024));
    let mut shape = Shape::default();
    let mut in_string = false;
    let mut i: usize = 0;

    while i < input.len() {
        let b = input[i];

        if in_string {
            match b {
                b'\\' => {
                    // Push the backslash itself.
                    out.push(b'\\');
                    i += 1;
                    if i >= input.len() {
                        break;
                    }
                    let eb = input[i];
                    match eb {
                        b'u' => {
                            // Need 5 bytes from i: 'u' + 4 hex
                            if i + 5 > input.len() {
                                out.push(b'u');
                                i += 1;
                                continue;
                            }
                            let hex = &input[i + 1..i + 5];
                            if !hex.iter().all(|&h| is_hex_digit(h)) {
                                // Malformed hex – pass `\u` unchanged.
                                out.push(b'u');
                                i += 1;
                                continue;
                            }
                            let cp = hex_to_u32(hex);

                            if (0xD800..=0xDBFF).contains(&cp) {
                                // High surrogate – look for adjacent low surrogate \uDCxx
                                let pair_ok = i + 11 <= input.len()
                                    && input[i + 5] == b'\\'
                                    && input[i + 6] == b'u'
                                    && input[i + 7..i + 11].iter().all(|&h| is_hex_digit(h))
                                    && {
                                        let cp2 = hex_to_u32(&input[i + 7..i + 11]);
                                        (0xDC00..=0xDFFF).contains(&cp2)
                                    };
                                if pair_ok {
                                    out.extend_from_slice(&input[i..i + 11]);
                                    i += 11;
                                    continue;
                                }
                                // Lone high surrogate → \ufffd
                                out.extend_from_slice(b"ufffd");
                                i += 5;
                                continue;
                            } else if (0xDC00..=0xDFFF).contains(&cp) {
                                // Lone low surrogate → \ufffd
                                out.extend_from_slice(b"ufffd");
                                i += 5;
                                continue;
                            }

                            // Valid BMP \uXXXX (non-surrogate) – copy through.
                            out.extend_from_slice(&input[i..i + 5]);
                            i += 5;
                        }
                        b'\\' | b'"' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => {
                            out.push(eb);
                            i += 1;
                        }
                        _ => {
                            // Unknown escape – copy the byte; serde may reject.
                            out.push(eb);
                            i += 1;
                        }
                    }
                }
                b'"' => {
                    in_string = false;
                    out.push(b'"');
                    i += 1;
                }
                _ if b < 0x80 => {
                    out.push(b);
                    i += 1;
                }
                _ => {
                    // Multi-byte candidate – validate in a ≤4-byte window.
                    let w = utf8_seq_len(b) as usize;
                    let avail = input.len() - i;
                    let take = if w > avail { avail } else { w };
                    let window = &input[i..i + take];
                    if std::str::from_utf8(window).is_ok() {
                        out.extend_from_slice(window);
                        i += take;
                    } else {
                        // Per INVALID BYTE: emit one U+FFFD, consume 1.
                        out.extend_from_slice(b"\xEF\xBF\xBD");
                        i += 1;
                    }
                }
            }
        } else {
            // Outside a JSON string. Colons count object values, commas
            // count array continuation, and delimiters count containers.
            // No byte within a string or escape advances this budget.
            shape.advance(b,max_depth,max_shape_tokens)?;
            match b {
                b'"' => {
                    in_string = true;
                    out.push(b'"');
                    i += 1;
                }
                _ => {
                    out.push(b);
                    i += 1;
                }
            }
        }
    }

    Ok(out)
}

// ── private helpers ──────────────────────────────────────────────────────

#[inline(always)]
fn is_hex_digit(b: u8) -> bool {
    b.is_ascii_hexdigit()
}

#[inline(always)]
fn hex_to_u32(h: &[u8]) -> u32 {
    // Caller guarantees all 4 are valid hex digits.
    ((hex_nibble(h[0]) as u32) << 12)
        | ((hex_nibble(h[1]) as u32) << 8)
        | ((hex_nibble(h[2]) as u32) << 4)
        | (hex_nibble(h[3]) as u32)
}

#[inline(always)]
fn hex_nibble(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0, // unreachable for validated input
    }
}

/// Expected sequence length for a leading UTF-8 byte (1–4).
/// Continuation bytes (0x80–0xBF) and 0xFE/0xFF → 1 (treated as invalid
/// single byte, yielding one U+FFFD).
#[inline(always)]
fn utf8_seq_len(b: u8) -> u8 {
    match b {
        0x00..=0x7F => 1,
        0xC0..=0xDF => 2,
        0xE0..=0xEF => 3,
        0xF0..=0xF7 => 4,
        _ => 1, // continuation byte, 0xF8–0xFF: invalid lead
    }
}
