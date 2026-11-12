//! CEL string / bytes literal parsing.
//!
//! Implements the unescape rules from cel-spec (mirrors cel-go's
//! `parser/unescape.go`):
//!
//! * strips the optional `r`/`R` (raw) and — for bytes — `b`/`B` prefix,
//! * normalizes `\r\n` and lone `\r` inside the source to `\n`,
//! * unwraps single (`'"..."'`) or triple-quoted (`"""..."""`) literals,
//! * interprets `\a \b \f \n \r \t \v \\ \? \" \' \``, `\xHH` / `\XHH`,
//!   `\uHHHH`, `\UHHHHHHHH`, and `\ODD` (octal) escapes,
//! * `\uHHHH` / `\UHHHHHHHH` are rejected inside bytes literals,
//! * inside bytes, `\xHH` / `\XHH` and `\ODD` are raw byte values;
//!   inside strings they are Unicode codepoints that get UTF-8 encoded.
//!
//! `parse_string` / `parse_bytes` take the full lexer-produced literal
//! (`"..."`, `r'''...'''`, `br"..."`, …) and return the decoded value.

use std::num::ParseIntError;

/// Error type produced by [`parse_string`] / [`parse_bytes`].
#[derive(Debug, PartialEq)]
pub enum ParseSequenceError {
    InvalidEscape {
        escape: String,
        index: usize,
        string: String,
    },
    InvalidUnicode {
        source: ParseUnicodeError,
        index: usize,
        string: String,
    },
    MissingOpeningQuote,
    MissingClosingQuote,
    /// Catch-all for shape mismatches (missing/mismatched prefix, quote
    /// style, truncated escape, invalid UTF-8, …).
    Invalid(String),
}

#[derive(Debug, PartialEq, Clone)]
pub enum ParseUnicodeError {
    Hex {
        source: ParseIntError,
        string: String,
    },
    Unicode {
        value: u32,
    },
}

/// Parse a CEL string literal, including any surrounding quotes and
/// optional `r`/`R` raw prefix. Accepts single, double, and triple-quoted
/// forms.
pub fn parse_string(literal: &str) -> Result<String, ParseSequenceError> {
    let bytes = unescape(literal, false)?;
    String::from_utf8(bytes)
        .map_err(|_| ParseSequenceError::Invalid("invalid unicode code point".to_string()))
}

/// Parse a CEL bytes literal, including the `b`/`B` prefix, optional
/// `r`/`R` raw marker, and surrounding quotes. Accepts single, double, and
/// triple-quoted forms.
pub fn parse_bytes(literal: &str) -> Result<Vec<u8>, ParseSequenceError> {
    // Bytes literals are `[bB][rR]?"..."` per the grammar; peel the `b`/`B`
    // and hand off to the shared unescape.
    let rest = literal
        .strip_prefix('b')
        .or_else(|| literal.strip_prefix('B'))
        .ok_or_else(|| {
            ParseSequenceError::Invalid("bytes literal must start with b/B".to_string())
        })?;
    unescape(rest, true)
}

fn unescape(value: &str, is_bytes: bool) -> Result<Vec<u8>, ParseSequenceError> {
    // Normalize source-level newlines. Escape sequences `\r`/`\n` are
    // untouched (they aren't literal CR/LF at this point).
    let normalized = value.replace("\r\n", "\n").replace('\r', "\n");
    let mut val = normalized.as_str();

    if val.len() < 2 {
        return Err(ParseSequenceError::Invalid(
            "literal too short to be a valid string".to_string(),
        ));
    }

    let is_raw = if val.starts_with('r') || val.starts_with('R') {
        val = &val[1..];
        true
    } else {
        false
    };
    if val.len() < 2 {
        return Err(ParseSequenceError::Invalid(
            "literal too short to be a valid string".to_string(),
        ));
    }

    let first = val.chars().next().unwrap();
    let last = val.chars().last().unwrap();
    if first != '"' && first != '\'' {
        return Err(ParseSequenceError::MissingOpeningQuote);
    }
    if last != first {
        return Err(ParseSequenceError::MissingClosingQuote);
    }

    // Peel triple-quotes, falling back to a single pair.
    if val.len() >= 6 && (val.starts_with("'''") || val.starts_with("\"\"\"")) {
        let triple = if first == '\'' { "'''" } else { "\"\"\"" };
        if !val.ends_with(triple) || val.len() < 6 {
            return Err(ParseSequenceError::MissingClosingQuote);
        }
        val = &val[3..val.len() - 3];
    } else {
        val = &val[1..val.len() - 1];
    }

    // Raw or no escape: return content verbatim.
    if is_raw || !val.contains('\\') {
        return Ok(val.as_bytes().to_vec());
    }

    // The non-raw slow path: interpret escape sequences.
    let mut out = Vec::with_capacity(val.len());
    let mut chars = val.char_indices();
    while let Some((idx, c)) = chars.next() {
        if c != '\\' {
            let mut buf = [0u8; 4];
            out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            continue;
        }
        let (_, esc) = chars
            .next()
            .ok_or_else(|| ParseSequenceError::InvalidEscape {
                escape: "\\".to_string(),
                index: idx,
                string: val.to_string(),
            })?;
        match esc {
            'a' => out.push(0x07),
            'b' => out.push(0x08),
            'f' => out.push(0x0C),
            'n' => out.push(b'\n'),
            'r' => out.push(b'\r'),
            't' => out.push(b'\t'),
            'v' => out.push(0x0B),
            '\\' => out.push(b'\\'),
            '\'' => out.push(b'\''),
            '"' => out.push(b'"'),
            '`' => out.push(b'`'),
            '?' => out.push(b'?'),
            'x' | 'X' | 'u' | 'U' => {
                let width = match esc {
                    'x' | 'X' => 2,
                    'u' => {
                        if is_bytes {
                            return Err(ParseSequenceError::InvalidEscape {
                                escape: format!("\\{esc}"),
                                index: idx,
                                string: val.to_string(),
                            });
                        }
                        4
                    }
                    'U' => {
                        if is_bytes {
                            return Err(ParseSequenceError::InvalidEscape {
                                escape: format!("\\{esc}"),
                                index: idx,
                                string: val.to_string(),
                            });
                        }
                        8
                    }
                    _ => unreachable!(),
                };
                let mut hex = String::with_capacity(width);
                for _ in 0..width {
                    let (_, h) =
                        chars
                            .next()
                            .ok_or_else(|| ParseSequenceError::InvalidUnicode {
                                source: ParseUnicodeError::Unicode { value: 0 },
                                index: idx,
                                string: val.to_string(),
                            })?;
                    hex.push(h);
                }
                let v = u32::from_str_radix(&hex, 16).map_err(|e| {
                    ParseSequenceError::InvalidUnicode {
                        source: ParseUnicodeError::Hex {
                            source: e,
                            string: hex.clone(),
                        },
                        index: idx,
                        string: val.to_string(),
                    }
                })?;
                if is_bytes && (esc == 'x' || esc == 'X') {
                    out.push(v as u8);
                } else {
                    let ch = char::from_u32(v).ok_or(ParseSequenceError::InvalidUnicode {
                        source: ParseUnicodeError::Unicode { value: v },
                        index: idx,
                        string: val.to_string(),
                    })?;
                    let mut buf = [0u8; 4];
                    out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                }
            }
            n @ '0'..='3' => {
                let mut v = (n as u32) - ('0' as u32);
                let mut oct = String::from(n);
                for _ in 0..2 {
                    let (_, d) =
                        chars
                            .next()
                            .ok_or_else(|| ParseSequenceError::InvalidUnicode {
                                source: ParseUnicodeError::Unicode { value: 0 },
                                index: idx,
                                string: val.to_string(),
                            })?;
                    if !('0'..='7').contains(&d) {
                        return Err(ParseSequenceError::InvalidEscape {
                            escape: format!("\\{oct}"),
                            index: idx,
                            string: val.to_string(),
                        });
                    }
                    oct.push(d);
                    v = v * 8 + (d as u32 - '0' as u32);
                }
                if is_bytes {
                    out.push(v as u8);
                } else {
                    let ch = char::from_u32(v).ok_or(ParseSequenceError::InvalidUnicode {
                        source: ParseUnicodeError::Unicode { value: v },
                        index: idx,
                        string: val.to_string(),
                    })?;
                    let mut buf = [0u8; 4];
                    out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                }
            }
            _ => {
                return Err(ParseSequenceError::InvalidEscape {
                    escape: format!("\\{esc}"),
                    index: idx,
                    string: val.to_string(),
                });
            }
        }
    }
    Ok(out)
}
