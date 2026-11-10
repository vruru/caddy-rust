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

use std::char;
use std::collections::VecDeque;

enum Output<'a> {
    Buffer { bytes: Vec<u8>, limit: usize },
    Difference(DiffSink<'a>),
}
impl Output<'_> {
    fn write(&mut self, ch: char) -> anyhow::Result<()> {
        match self {
            Self::Buffer { bytes, limit } => {
                anyhow::ensure!(
                    bytes
                        .len()
                        .checked_add(ch.len_utf8())
                        .is_some_and(|n| n <= *limit),
                    "formatter output limit exceeded"
                );
                let mut encoded = [0; 4];
                bytes.extend_from_slice(ch.encode_utf8(&mut encoded).as_bytes());
            }
            Self::Difference(sink) => sink.write(ch),
        }
        Ok(())
    }
}

/// Whitespace comparisons remain provisional until the next non-whitespace
/// rune: EOF may remove the entire run, including a provisional mismatch.
/// All output is UTF-8 produced by WriteRune, including per-byte RuneError.
pub(super) struct DiffSink<'a> {
    input: &'a [u8],
    cursor: usize,
    line: usize,
    committed_cursor: usize,
    committed_line: usize,
    started: bool,
    pending_error: Option<usize>,
    difference: Option<usize>,
}
impl<'a> DiffSink<'a> {
    pub(super) fn new(input: &'a [u8]) -> Self {
        Self {
            input,
            cursor: 0,
            line: 1,
            committed_cursor: 0,
            committed_line: 1,
            started: false,
            pending_error: None,
            difference: None,
        }
    }
    fn compare(&mut self, bytes: &[u8]) -> Option<usize> {
        for byte in bytes {
            if self.input.get(self.cursor) != Some(byte) {
                return Some(self.line);
            }
            self.cursor += 1;
            if *byte == b'\n' {
                self.line += 1;
            }
        }
        None
    }
    pub(super) fn write(&mut self, ch: char) {
        if self.difference.is_some() {
            return;
        }
        let space = is_space(ch);
        if !self.started && space {
            return;
        }
        self.started = true;
        let mut bytes = [0; 4];
        let encoded = ch.encode_utf8(&mut bytes).as_bytes();
        if space {
            if self.pending_error.is_none() {
                self.pending_error = self.compare(encoded);
            }
        } else {
            self.difference = self.pending_error.take().or_else(|| self.compare(encoded));
            if self.difference.is_none() {
                self.committed_cursor = self.cursor;
                self.committed_line = self.line;
            }
        }
    }
    pub(super) fn finish(mut self) -> Option<usize> {
        if self.difference.is_some() {
            return self.difference;
        }
        self.cursor = self.committed_cursor;
        self.line = self.committed_line;
        self.compare(b"\n")
            .or_else(|| (self.cursor != self.input.len()).then_some(self.line))
    }
}

struct State<'a> {
    input: &'a [u8],
    pos: usize,
    out: Output<'a>,

    last: Option<char>,

    space: bool,
    beginning_of_line: bool,

    open_brace: bool,
    open_brace_written: bool,
    open_brace_space: bool,
    open_brace_own_line: bool,

    new_lines: usize,

    comment: bool,
    quotes: String,
    escaped: bool,

    heredoc: i32,
    heredoc_escaped: bool,
    heredoc_run: usize,
    heredoc_marker: Vec<char>,
    heredoc_closing_marker: VecDeque<char>,

    nesting: i32,

    current_token: String,
    current_line_first_token: String,
    previous_line_was_top_level_import: bool,
}

const HEREDOC_CLOSED: i32 = 0;
const HEREDOC_OPENING: i32 = 1;
const HEREDOC_OPENED: i32 = 2;

impl<'a> State<'a> {
    fn new(input: &'a [u8], max_output_bytes: usize) -> Self {
        State {
            input,
            pos: 0,
            out: Output::Buffer {
                bytes: Vec::new(),
                limit: max_output_bytes,
            },
            last: None,
            space: true,
            beginning_of_line: true,
            open_brace: false,
            open_brace_written: false,
            open_brace_space: false,
            open_brace_own_line: false,
            new_lines: 0,
            comment: false,
            quotes: String::new(),
            escaped: false,
            heredoc: HEREDOC_CLOSED,
            heredoc_escaped: false,
            heredoc_run: 0,
            heredoc_marker: Vec::new(),
            heredoc_closing_marker: VecDeque::new(),
            nesting: 0,
            current_token: String::new(),
            current_line_first_token: String::new(),
            previous_line_was_top_level_import: false,
        }
    }

    fn write(&mut self, ch: char) -> anyhow::Result<()> {
        self.out.write(ch)?;
        self.last = Some(ch);
        Ok(())
    }

    fn indent(&mut self) -> anyhow::Result<()> {
        for _ in 0..self.nesting {
            self.write('\t')?;
        }
        Ok(())
    }

    fn next_line(&mut self) -> anyhow::Result<()> {
        self.write('\n')?;
        self.beginning_of_line = true;
        Ok(())
    }

    fn finish_token(&mut self) {
        if self.current_token.is_empty() {
            return;
        }
        if self.current_line_first_token.is_empty() {
            self.current_line_first_token = self.current_token.clone();
        }
        self.current_token.clear();
    }

    fn finish_line(&mut self) {
        self.finish_token();
        if !self.current_line_first_token.is_empty() {
            self.previous_line_was_top_level_import =
                self.nesting == 0 && self.current_line_first_token == "import";
        } else if !self.open_brace || !self.open_brace_own_line || self.open_brace_written {
            self.previous_line_was_top_level_import = false;
        }
        self.current_line_first_token.clear();
    }

    fn flush_open_brace(&mut self) -> anyhow::Result<()> {
        if self.nesting == 0 && self.last == Some('}') {
            self.next_line()?;
            self.next_line()?;
        }

        self.open_brace = false;
        if self.open_brace_own_line && self.previous_line_was_top_level_import {
            if self.last != Some('\n') {
                self.next_line()?;
            }
            self.indent()?;
        } else if self.beginning_of_line {
            self.indent()?;
        } else if !self.open_brace_space || !is_space(self.last.unwrap_or('\0')) {
            self.write(' ')?;
        }
        self.write('{')?;
        self.open_brace_written = true;
        self.open_brace_own_line = false;
        self.next_line()?;
        self.new_lines = 0;
        if self.nesting < 10 {
            self.nesting += 1;
        }
        Ok(())
    }

    fn read_rune(&mut self) -> Option<(char, usize)> {
        if self.pos >= self.input.len() {
            return None;
        }

        let (ch, size) = decode_rune_go(&self.input[self.pos..]);
        self.pos += size;
        Some((ch, size))
    }

    fn match_heredoc_marker_regexp(marker: &[char]) -> bool {
        if marker.is_empty() {
            return false;
        }
        marker
            .iter()
            .all(|&c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    }
}

fn decode_rune_go(data: &[u8]) -> (char, usize) {
    if data.is_empty() {
        return ('\u{FFFD}', 0); // Should not happen if pos < len
    }
    let b = data[0];

    if b < 0x80 {
        return (b as char, 1);
    }

    if (0xC2..=0xDF).contains(&b) {
        if data.len() < 2 {
            return ('\u{FFFD}', 1);
        }
        let b1 = data[1];
        if !(0x80..=0xBF).contains(&b1) {
            return ('\u{FFFD}', 1);
        }
        let code_point = ((b as u32 & 0x1F) << 6) | (b1 as u32 & 0x3F);
        return (char::from_u32(code_point).unwrap_or('\u{FFFD}'), 2);
    }

    if (0xE0..=0xEF).contains(&b) {
        if data.len() < 3 {
            return ('\u{FFFD}', 1);
        }
        let b1 = data[1];
        let b2 = data[2];

        if !((0x80..=0xBF).contains(&b1) && (0x80..=0xBF).contains(&b2)) {
            return ('\u{FFFD}', 1);
        }

        if b == 0xE0 {
            if !(0xA0..=0xBF).contains(&b1) {
                return ('\u{FFFD}', 1);
            }
        } else if b == 0xED && b1 > 0x9F {
            return ('\u{FFFD}', 1);
        }

        let code_point = ((b as u32 & 0x0F) << 12) | ((b1 as u32 & 0x3F) << 6) | (b2 as u32 & 0x3F);
        return (char::from_u32(code_point).unwrap_or('\u{FFFD}'), 3);
    }

    if (0xF0..=0xF4).contains(&b) {
        if data.len() < 4 {
            return ('\u{FFFD}', 1);
        }
        let b1 = data[1];
        let b2 = data[2];
        let b3 = data[3];

        if !((0x80..=0xBF).contains(&b1)
            && (0x80..=0xBF).contains(&b2)
            && (0x80..=0xBF).contains(&b3))
        {
            return ('\u{FFFD}', 1);
        }

        if b == 0xF0 {
            if !(0x90..=0xBF).contains(&b1) {
                return ('\u{FFFD}', 1);
            }
        } else if b == 0xF4 && b1 > 0x8F {
            return ('\u{FFFD}', 1);
        }

        let code_point = ((b as u32 & 0x07) << 18)
            | ((b1 as u32 & 0x3F) << 12)
            | ((b2 as u32 & 0x3F) << 6)
            | (b3 as u32 & 0x3F);
        return (char::from_u32(code_point).unwrap_or('\u{FFFD}'), 4);
    }

    ('\u{FFFD}', 1)
}

fn is_space(ch: char) -> bool {
    matches!(ch, '\t'..='\r' | ' ' | '\u{0085}' | '\u{00A0}' | '\u{1680}' | '\u{2000}'..='\u{200A}' | '\u{2028}' | '\u{2029}' | '\u{202F}' | '\u{205F}' | '\u{3000}')
}

fn trim_space_go(input: &[u8]) -> &[u8] {
    let mut start = 0;
    while start < input.len() {
        let (ch, size) = decode_rune_go(&input[start..]);
        if is_space(ch) {
            start += size;
        } else {
            break;
        }
    }

    let mut end = input.len();
    while end > start {
        let mut last_rune_start = end - 1;
        let mut ch = char::REPLACEMENT_CHARACTER;
        for start_candidate in end.saturating_sub(4).max(start)..end {
            if let Ok(suffix) = std::str::from_utf8(&input[start_candidate..end]) {
                let mut chars = suffix.chars();
                if let (Some(c), None) = (chars.next(), chars.next()) {
                    last_rune_start = start_candidate;
                    ch = c;
                    break;
                }
            }
        }
        if is_space(ch) {
            end = last_rune_start;
        } else {
            break;
        }
    }

    &input[start..end]
}

fn run(state: &mut State<'_>) -> anyhow::Result<()> {
    while let Some((ch, _)) = state.read_rune() {
        if state.quotes.is_empty()
            && state.heredoc == HEREDOC_CLOSED
            && !state.heredoc_escaped
            && state.space
            && state.last == Some('<')
            && ch == '<'
        {
            state.write(ch)?;
            state.heredoc = HEREDOC_OPENING;
            state.space = false;
            continue;
        }

        if state.heredoc == HEREDOC_OPENING {
            if ch == '\n' {
                if !state.heredoc_marker.is_empty()
                    && State::match_heredoc_marker_regexp(&state.heredoc_marker)
                {
                    state.heredoc = HEREDOC_OPENED;
                    state.heredoc_run = 0;
                } else {
                    state.heredoc_marker.clear();
                    state.heredoc = HEREDOC_CLOSED;
                    state.next_line()?;
                    continue;
                }
                state.write(ch)?;
                continue;
            }
            if is_space(ch) {
                state.heredoc_marker.clear();
                state.heredoc = HEREDOC_CLOSED;
            } else {
                state.heredoc_marker.push(ch);
                state.write(ch)?;
                continue;
            }
        }
        if state.heredoc == HEREDOC_OPENED {
            state.heredoc_closing_marker.push_back(ch);
            if state.heredoc_closing_marker.len() > state.heredoc_marker.len() + 1 {
                state.heredoc_closing_marker.pop_front();
            }
            let marker_len = state.heredoc_marker.len();
            // A legal ASCII marker has no whitespace. A candidate therefore
            // needs at least marker_len fresh non-whitespace runes. Every full
            // comparison consumes such a run, making repeated spaces linear.
            let space = is_space(ch);
            let closes = space
                && state.heredoc_run >= marker_len
                && state.heredoc_closing_marker.len() == marker_len + 1
                && state
                    .heredoc_closing_marker
                    .iter()
                    .take(marker_len)
                    .eq(state.heredoc_marker.iter());
            state.heredoc_run = if space { 0 } else { state.heredoc_run + 1 };
            if closes {
                state.heredoc_marker.clear();
                state.heredoc_closing_marker.clear();
                state.heredoc = HEREDOC_CLOSED;
            } else {
                state.write(ch)?;
                if ch == '\n' {
                    state.heredoc_closing_marker.clear();
                }
                continue;
            }
        }

        if state.last == Some('<') && state.space {
            state.space = false;
        }

        if state.comment {
            if ch == '\n' {
                state.comment = false;
                state.space = true;
                state.next_line()?;
                continue;
            } else {
                state.write(ch)?;
                continue;
            }
        }

        if !state.escaped && ch == '\\' {
            if state.space {
                state.write(' ')?;
                state.space = false;
            }
            state.write(ch)?;
            state.escaped = true;
            continue;
        }

        if state.escaped {
            if ch == '<' {
                state.heredoc_escaped = true;
            }
            state.write(ch)?;
            state.escaped = false;
            continue;
        }

        if ch == '`' {
            match state.quotes.as_str() {
                "\"`" => {
                    state.quotes = "\"".to_string();
                }
                "`" => {
                    state.quotes = "".to_string();
                }
                "\"" => {
                    state.quotes = "\"`".to_string();
                }
                _ => {
                    state.quotes = "`".to_string();
                }
            }
        }

        if state.quotes == "\"" {
            if ch == '"' {
                state.quotes = "".to_string();
            }
            state.write(ch)?;
            continue;
        }

        if ch == '"' {
            match state.quotes.as_str() {
                "" => {
                    if state.space {
                        state.quotes = "\"".to_string();
                    }
                }
                "`\"" => {
                    state.quotes = "`".to_string();
                }
                "\"`" => {
                    state.quotes = "".to_string();
                }
                _ => {}
            }
        }

        if state.quotes.contains('`') {
            if ch == '`' && state.space && !state.beginning_of_line {
                state.write(' ')?;
            }
            state.write(ch)?;
            state.space = false;
            continue;
        }

        if is_space(ch) {
            state.finish_token();
            state.space = true;
            state.heredoc_escaped = false;
            if ch == '\n' {
                state.finish_line();
                state.new_lines += 1;
            }
            continue;
        }
        let space_prior = state.space;
        state.space = false;

        if ch == '#' {
            state.comment = true;
        }

        if state.open_brace && space_prior && !state.open_brace_written {
            state.flush_open_brace()?;
        }

        if ch == '{' {
            state.finish_token();
            if state.open_brace && !state.open_brace_written {
                state.flush_open_brace()?;
            }
            state.open_brace = true;
            state.open_brace_space = space_prior && !state.beginning_of_line;
            state.open_brace_own_line = state.new_lines > 0;
            if state.open_brace_space && state.new_lines == 0 {
                state.write(' ')?;
            }
            state.open_brace_written = false;
            if state.quotes == "`" {
                state.write('{')?;
                state.open_brace_written = true;
                state.open_brace_own_line = false;
                continue;
            }
            continue;
        }

        if ch == '}' && (space_prior || !state.open_brace) {
            state.finish_token();
            if state.quotes == "`" {
                state.write('}')?;
                continue;
            }
            if state.last != Some('\n') {
                state.next_line()?;
            }
            if state.nesting > 0 {
                state.nesting -= 1;
            }
            state.indent()?;
            state.write('}')?;
            state.new_lines = 0;
            continue;
        }

        if state.new_lines > 2 {
            state.new_lines = 2;
        }
        for _ in 0..state.new_lines {
            state.next_line()?;
        }
        state.new_lines = 0;
        if state.beginning_of_line {
            state.indent()?;
        }
        if state.nesting == 0 && state.last == Some('}') && state.beginning_of_line {
            state.next_line()?;
            state.next_line()?;
        }

        if !state.beginning_of_line && space_prior {
            state.write(' ')?;
        }

        if state.open_brace && !state.open_brace_written {
            state.write('{')?;
            state.open_brace_written = true;
        }

        if space_prior && ch == '<' {
            state.space = true;
        }

        state.current_token.push(ch);
        state.write(ch)?;

        state.beginning_of_line = false;
    }

    if state.open_brace && !state.open_brace_written {
        state.flush_open_brace()?;
    }

    Ok(())
}

pub(super) fn format(input: &[u8], max_output_bytes: usize) -> anyhow::Result<Vec<u8>> {
    let mut state = State::new(trim_space_go(input), max_output_bytes);
    run(&mut state)?;
    let Output::Buffer { bytes, limit } = state.out else {
        anyhow::bail!("invalid formatter sink")
    };
    let trimmed = trim_space_go(&bytes);
    anyhow::ensure!(
        trimmed.len().checked_add(1).is_some_and(|n| n <= limit),
        "formatter output limit exceeded"
    );
    let mut result = trimmed.to_vec();
    result.push(b'\n');
    Ok(result)
}

/// The same state machine writes to a comparator, never to an enlarged copy.
/// Its caller must offload this synchronous CPU work to a bounded worker.
pub(super) fn formatting_difference(
    input: &[u8],
    max_input_bytes: usize,
) -> anyhow::Result<Option<usize>> {
    anyhow::ensure!(
        input.len() <= max_input_bytes,
        "formatter input limit exceeded"
    );
    let mut normalized = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] == b'\r' && input.get(i + 1) == Some(&b'\n') {
            i += 1;
        }
        normalized.push(input[i]);
        i += 1;
    }
    let mut state = State::new(trim_space_go(&normalized), 0);
    state.out = Output::Difference(DiffSink::new(&normalized));
    run(&mut state)?;
    let Output::Difference(sink) = state.out else {
        anyhow::bail!("invalid formatter sink")
    };
    Ok(sink.finish())
}
