// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use anyhow::{Result, anyhow};

/// Represents a single parsable unit from the Caddyfile.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Token {
    /// The filename associated with this token.
    pub file: String,
    /// The line number where the token starts.
    pub line: usize,
    /// The text content of the token.
    pub text: String,
    /// True if the token was enclosed in quotes (double quotes, backticks, or heredoc).
    pub was_quoted: bool,
    /// The kind of quote used: None, Some('"'), Some('`'), Some('<').
    pub quote_kind: Option<char>,
    /// The marker used for heredocs, if applicable.
    pub heredoc_marker: String,
    /// Imports associated with the token (used for directives).
    pub imports: Vec<String>,
    /// Snippet name associated with the token.
    pub snippet_name: String,
}

impl Token {
    pub fn quoted(&self) -> bool {
        self.quote_kind.is_some()
    }

    pub fn num_line_breaks(&self) -> usize {
        let mut count = self.text.matches('\n').count();
        if self.quote_kind == Some('<') {
            count += 2;
        }
        count
    }

    pub fn is_open_curly_brace(&self) -> bool {
        !self.was_quoted && self.text == "{"
    }

    pub fn is_close_curly_brace(&self) -> bool {
        !self.was_quoted && self.text == "}"
    }

    pub fn is_next_on_new_line(&self, next: &Token) -> bool {
        if self.file != next.file || self.imports != next.imports {
            return true;
        }
        self.line + self.num_line_breaks() < next.line
    }
}

/// Internal state for the lexer.
struct Lexer {
    reader: BufferedReader,
    token: Token,
    line: usize,
    skipped_lines: usize,
}

/// A simple buffered reader that reads bytes and decodes UTF-8 runes,
/// mimicking Go's bufio.Reader behavior for the specific needs of this lexer.
struct BufferedReader {
    buffer: Vec<u8>,
    pos: usize,
}

impl BufferedReader {
    fn new(data: &[u8]) -> Self {
        BufferedReader {
            buffer: data.to_vec(),
            pos: 0,
        }
    }

    /// Reads a single UTF-8 character (rune) from the stream.
    /// Returns Ok((char, size_in_bytes)) on success.
    /// Returns Err(()) on EOF.
    fn read_rune(&mut self) -> Result<(char, usize), ()> {
        if self.pos >= self.buffer.len() {
            return Err(());
        }

        let start = self.pos;
        let slice = &self.buffer[start..];

        // Decode UTF-8. We need to handle valid UTF-8.
        // Go's ReadRune returns RuneError for invalid UTF-8, consuming 1 byte.
        // Rust's str::from_utf8 is strict. We assume input is valid UTF-8 as per Caddyfile context,
        // or handle invalid bytes as replacement/lossy.
        // Given the source uses Go's ReadRune which handles UTF-8 decoding,
        // we will implement a robust UTF-8 decoder.

        let byte0 = slice[0];

        let (ch, len) = match utf8_decode(byte0, slice) {
            Some(c) => c,
            None => {
                // Invalid UTF-8, treat as replacement char, consume 1 byte
                (char::REPLACEMENT_CHARACTER, 1)
            }
        };

        self.pos += len;
        Ok((ch, len))
    }

    /// Unreads the last rune read (only works for one rune back, and only if it was read via read_rune).
    /// Go's UnreadRune only works for the last rune read.
    fn unread_rune(&mut self, size: usize) {
        if size > 0 && self.pos >= size {
            self.pos -= size;
        }
    }
}

fn utf8_decode(byte0: u8, slice: &[u8]) -> Option<(char, usize)> {
    if byte0 < 0x80 {
        return Some((byte0 as char, 1));
    }

    let n_bytes = match byte0 {
        0xC0..=0xDF => 2,
        0xE0..=0xEF => 3,
        0xF0..=0xF7 => 4,
        _ => return None,
    };

    if slice.len() < n_bytes {
        return None;
    }

    let mut code_point = match n_bytes {
        2 => (slice[0] & 0x1F) as u32,
        3 => (slice[0] & 0x0F) as u32,
        4 => (slice[0] & 0x07) as u32,
        _ => unreachable!(),
    };

    for &b in slice.iter().take(n_bytes).skip(1) {
        if b & 0xC0 != 0x80 {
            return None;
        }
        code_point = (code_point << 6) | (b & 0x3F) as u32;
    }

    // Check for overlong encodings and valid ranges
    let min_code_point = match n_bytes {
        2 => 0x80,
        3 => 0x800,
        4 => 0x10000,
        _ => 0,
    };

    if code_point < min_code_point || code_point > 0x10FFFF {
        return None;
    }

    // Check for surrogates
    if (0xD800..=0xDFFF).contains(&code_point) {
        return None;
    }

    char::from_u32(code_point).map(|c| (c, n_bytes))
}

impl Lexer {
    fn new(input: &[u8]) -> Result<Self, anyhow::Error> {
        let mut reader = BufferedReader::new(input);
        reader.pos = 0; // Ensure start

        let line = 1;
        let skipped_lines = 0;

        // Discard BOM if present
        // Read first rune
        match reader.read_rune() {
            Ok((ch, size)) => {
                if ch != '\u{FEFF}' {
                    reader.unread_rune(size);
                }
            }
            Err(_) => {
                // Empty input, EOF immediately
                return Err(anyhow!("EOF"));
            }
        }

        Ok(Lexer {
            reader,
            token: Token {
                file: String::new(),
                line: 1,
                text: String::new(),
                was_quoted: false,
                quote_kind: None,
                heredoc_marker: String::new(),
                imports: Vec::new(),
                snippet_name: String::new(),
            },
            line,
            skipped_lines,
        })
    }

    fn next(&mut self) -> Result<bool, anyhow::Error> {
        let mut val: Vec<char> = Vec::new();
        let mut comment = false;
        let mut quoted = false;
        let mut bt_quoted = false;
        let mut in_heredoc = false;
        let mut heredoc_escaped = false;
        let mut escaped = false;
        let mut heredoc_marker = String::new();

        // wasQuoted in Go is a rune (0, '"', '`', '<').
        // We map this to a boolean for the public API, but internally track it.
        // Public API: pub was_quoted: bool.
        // Logic: makeToken(quoted_rune).

        loop {
            // Read a character
            let (ch, _size) = match self.reader.read_rune() {
                Ok(c) => c,
                Err(()) => {
                    // EOF
                    if !val.is_empty() {
                        if in_heredoc {
                            return Err(anyhow!(
                                "incomplete heredoc <<{} on line #{}, expected ending marker {}",
                                heredoc_marker,
                                self.line + self.skipped_lines,
                                heredoc_marker
                            ));
                        }
                        // Make token with quoted=0 (false)
                        self.token = Token {
                            line: self.token.line,
                            text: val.into_iter().collect(),
                            was_quoted: false,
                            quote_kind: None,
                            heredoc_marker,
                            ..Default::default()
                        };
                        return Ok(true);
                    }
                    // No value, EOF -> return false (no token)
                    return Ok(false);
                }
            };

            // Detect start of heredoc
            // Condition: (!quoted && !bt_quoted) && (!in_heredoc && !heredoc_escaped) && len(val) > 1 && string(val[:2]) == "<<"
            if !quoted
                && !bt_quoted
                && !in_heredoc
                && !heredoc_escaped
                && val.len() > 1
                && val[0] == '<'
                && val[1] == '<'
            {
                if ch == ' ' {
                    self.token = Token {
                        line: self.token.line,
                        text: val.into_iter().collect(),
                        was_quoted: false,
                        quote_kind: None,
                        heredoc_marker,
                        ..Default::default()
                    };
                    return Ok(true);
                }

                if ch == '\r' {
                    continue;
                }

                if ch == '\n' {
                    if val.len() == 2 {
                        return Err(anyhow!(
                            "missing opening heredoc marker on line #{}; must contain only alphanumeric characters, dashes and underscores; got empty string",
                            self.line
                        ));
                    }

                    if val.len() > 2 && val[0] == '<' && val[1] == '<' && val[2] == '<' {
                        return Err(anyhow!(
                            "too many '<' for heredoc on line #{}; only use two, for example <<END",
                            self.line
                        ));
                    }

                    heredoc_marker = val[2..].iter().collect();

                    // Check regexp: ^[A-Za-z0-9_-]+$
                    if !is_valid_heredoc_marker(&heredoc_marker) {
                        return Err(anyhow!(
                            "heredoc marker on line #{} must contain only alphanumeric characters, dashes and underscores; got '{}'",
                            self.line,
                            heredoc_marker
                        ));
                    }

                    in_heredoc = true;
                    self.skipped_lines += 1;
                    val.clear();
                    continue;
                }

                val.push(ch);
                continue;
            }

            // If we're in a heredoc, read as-is
            if in_heredoc {
                val.push(ch);

                if ch == '\n' {
                    self.skipped_lines += 1;
                }

                // Check if we're done: last len(marker) chars match marker
                let marker_chars: Vec<char> = heredoc_marker.chars().collect();
                let m_len = marker_chars.len();

                if val.len() >= m_len {
                    let tail = &val[val.len() - m_len..];
                    if tail == marker_chars.as_slice() {
                        // Found end of heredoc
                        val = self.finalize_heredoc(&val, &heredoc_marker)?;

                        self.line += self.skipped_lines;
                        self.skipped_lines = 0;

                        self.token = Token {
                            line: self.token.line,
                            text: val.into_iter().collect(),
                            was_quoted: true,
                            quote_kind: Some('<'),
                            heredoc_marker,
                            ..Default::default()
                        };
                        return Ok(true);
                    }
                }

                continue;
            }

            // Track escapes
            // if !escaped && !btQuoted && ch == '\\'
            if !escaped && !bt_quoted && ch == '\\' {
                escaped = true;
                continue;
            }

            if quoted || bt_quoted {
                if quoted && escaped {
                    // In quoted string, backslash only escapes quote
                    if ch != '"' {
                        val.push('\\');
                    }
                    escaped = false;
                } else {
                    // Not escaped, check for closing quote
                    if (quoted && ch == '"') || (bt_quoted && ch == '`') {
                        let qk = if quoted { Some('"') } else { Some('`') };
                        self.token = Token {
                            line: self.token.line,
                            text: val.into_iter().collect(),
                            was_quoted: true,
                            quote_kind: qk,
                            heredoc_marker,
                            ..Default::default()
                        };
                        return Ok(true);
                    }
                }

                // Newlines inside quotes
                if ch == '\n' {
                    self.line += 1 + self.skipped_lines;
                    self.skipped_lines = 0;
                }

                val.push(ch);
                continue;
            }

            if is_whitespace(ch) {
                // Ignore CR
                if ch == '\r' {
                    continue;
                }

                if ch == '\n' {
                    if escaped {
                        self.skipped_lines += 1;
                        escaped = false;
                    } else {
                        self.line += 1 + self.skipped_lines;
                        self.skipped_lines = 0;
                    }
                    comment = false;
                }

                if !val.is_empty() {
                    self.token = Token {
                        line: self.token.line,
                        text: val.into_iter().collect(),
                        was_quoted: false,
                        quote_kind: None,
                        heredoc_marker,
                        ..Default::default()
                    };
                    return Ok(true);
                }
                continue;
            }

            // Comments
            if ch == '#' && val.is_empty() {
                comment = true;
            }

            if comment {
                continue;
            }

            // Start of a new token
            if val.is_empty() {
                self.token = Token {
                    line: self.line,
                    ..Default::default()
                };
                self.token.heredoc_marker = String::new(); // Reset for safety

                if ch == '"' {
                    quoted = true;
                    continue;
                }
                if ch == '`' {
                    bt_quoted = true;
                    continue;
                }
            }

            if escaped {
                // Handle escaped char
                // If escaped, next char is literal.
                // Special case: escape '<' to avoid heredoc detection.
                if ch == '<' {
                    heredoc_escaped = true;
                } else {
                    val.push('\\');
                }
                escaped = false;
                // Fall through to push ch
            }

            val.push(ch);
        }
    }

    fn finalize_heredoc(&self, val: &[char], marker: &str) -> Result<Vec<char>, anyhow::Error> {
        let string_val: String = val.iter().collect();

        // Find last newline
        let last_newline_idx = string_val.rfind('\n');

        if last_newline_idx.is_none() {
            // Should not happen in valid heredoc ending flow, as we check for marker at end.
            // If marker is at start of string?
            return Ok(vec![]);
        }

        let ln_idx = last_newline_idx.unwrap();

        // Content includes the newlines and text, up to the last newline.
        // The marker is on the line following the last newline.

        let content_part = &string_val[..ln_idx + 1];
        let padding_part = &string_val[ln_idx + 1..string_val.len() - marker.len()];

        // Split content into lines
        let lines: Vec<&str> = content_part.split('\n').collect();

        let padding_to_strip = padding_part;

        let mut out = String::new();

        // Iterate over lines except the last empty one (from trailing \n)
        // In Go: lines[:len(lines)-1]
        let total_lines = lines.len();

        for (line_num, line_text) in lines.iter().enumerate() {
            if line_num == total_lines - 1 {
                break;
            }

            // Check for empty line or just CR
            if line_text.is_empty() || *line_text == "\r" {
                out.push('\n');
                continue;
            }

            // Check if padding matches at start
            if let Some(stripped) = line_text.strip_prefix(padding_to_strip) {
                // Strip padding
                // Remove \r
                let cleaned = stripped.replace("\r", "");
                out.push_str(&cleaned);
                out.push('\n');
            } else {
                // Mismatch
                let clean_line_text = line_text.trim_end_matches(&['\r', '\n'][..]);
                return Err(anyhow!(
                    "mismatched leading whitespace in heredoc <<{} on line #{} [{}], expected whitespace [{}] to match the closing marker",
                    marker,
                    self.line + line_num + 1,
                    clean_line_text,
                    padding_to_strip
                ));
            }
        }

        // Remove trailing newline
        if out.ends_with('\n') {
            out.pop();
        }

        Ok(out.chars().collect())
    }
}

fn is_whitespace(ch: char) -> bool {
    ch.is_whitespace()
}

fn is_valid_heredoc_marker(marker: &str) -> bool {
    if marker.is_empty() {
        return false;
    }
    for c in marker.chars() {
        if !(c.is_ascii_alphanumeric() || c == '_' || c == '-') {
            return false;
        }
    }
    true
}

/// Tokenize takes bytes as input and lexes it into a list of tokens.
pub fn tokenize(input: &[u8], file: &str) -> Result<Vec<Token>> {
    let mut lexer = Lexer::new(input)?;
    let mut tokens: Vec<Token> = Vec::new();

    loop {
        match lexer.next() {
            Ok(found) => {
                if !found {
                    break;
                }
                lexer.token.file = file.to_string();
                tokens.push(lexer.token.clone());
            }
            Err(e) => {
                return Err(e);
            }
        }
    }

    Ok(tokens)
}
