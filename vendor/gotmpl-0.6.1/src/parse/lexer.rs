//! Lexer (scanner) that tokenizes template source text into a stream of tokens.
//!
//! The lexer recognizes two "worlds":
//! - **Outside delimiters**: everything is raw text (`TokenKind::Text`)
//! - **Inside delimiters**: keywords, identifiers, operators, and literals
//!
//! Supports configurable delimiters (default `{{` / `}}`), trim markers
//! (`{{-` / `-}}`), comments (`{{/* ... */}}`), and Go-compatible number
//! literals (hex, octal, binary, underscores).
//!
//! This module is primarily used internally by the [`Parser`](crate::parse::Parser).

use alloc::borrow::Cow;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use super::node::Number;
use crate::error::{Result, TemplateError};

/// Build an integer-literal lex error message that distinguishes an
/// overflow from a syntax error, using `ParseIntError::kind()`.
fn int_parse_msg(kind: &str, err: &core::num::ParseIntError) -> String {
    use core::num::IntErrorKind::*;
    match err.kind() {
        // A non-negative magnitude is retried as `u64` before erroring, so an
        // overflow here means the literal exceeds even `u64` (or is a negative
        // value below `i64::MIN`).
        PosOverflow | NegOverflow => format!("{} integer literal overflows u64", kind),
        _ => format!("invalid {} number", kind),
    }
}

/// Parse the (unsigned) `digits` of an integer literal in `radix` into a
/// [`Number`], applying `negative`.
///
/// Mirrors Go: a non-negative literal that overflows `i64` is retried as `u64`
/// and becomes [`Number::Uint`]. A negative literal cannot be unsigned, so it
/// keeps the `i64` overflow error.
fn radix_number(
    digits: &str,
    radix: u32,
    negative: bool,
) -> core::result::Result<Number, core::num::ParseIntError> {
    match i64::from_str_radix(digits, radix) {
        Ok(n) => Ok(Number::Int(if negative { -n } else { n })),
        Err(e) => {
            if matches!(e.kind(), core::num::IntErrorKind::PosOverflow)
                && let Ok(magnitude) = u64::from_str_radix(digits, radix)
            {
                if !negative { return Ok(Number::Uint(magnitude)); }
                // Parsing the magnitude as i64 excludes the one additional
                // valid negative value. Do not negate or cast larger values.
                if magnitude == 1u64 << 63 { return Ok(Number::Int(i64::MIN)); }
            }
            Err(e)
        }
    }
}

/// ASCII whitespace recognised by Go's lexer (`isSpace` in
/// `text/template/parse/lex.go`). Trim markers only bind adjacent to one of
/// these bytes, not arbitrary Unicode whitespace.
fn is_go_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\r' | b'\n')
}

fn strip_underscores(raw: &str) -> Cow<'_, str> {
    if raw.contains('_') {
        Cow::Owned(raw.replace('_', ""))
    } else {
        Cow::Borrowed(raw)
    }
}

// Token types
/// The kind of a lexed [`Token`].
#[derive(Debug, Clone, PartialEq)]
pub enum TokenKind {
    // Structural
    Text,           // raw text outside {{ }}
    LeftDelim,      // {{
    RightDelim,     // }}
    LeftTrimDelim,  // {{- (trim whitespace before)
    RightTrimDelim, // -}} (trim whitespace after)

    // Values
    Dot,        // .
    Field,      // .FieldName
    Variable,   // $var
    Identifier, // function name or keyword
    String,     // "quoted string" or `raw string`
    Number,     // integer or float literal
    Bool,       // true / false
    Nil,        // nil
    Char,       // character literal

    // Operators
    Pipe,       // |
    Comma,      // ,
    Assign,     // =
    Declare,    // :=
    LeftParen,  // (
    RightParen, // )

    // Keywords (distinguished from Identifier after lexing)
    If,
    Else,
    End,
    Range,
    With,
    Define,
    Template,
    Block,
    Break,
    Continue,

    // Special
    Eof,
}

/// A single token produced by the [`Lexer`].
///
/// The `val` field borrows from the source when possible (text, identifiers,
/// field names, keywords, raw strings) and only allocates for values that
/// must be transformed, i.e. quoted strings with escapes. For `Number` and
/// `Char` tokens, `val` always borrows the raw source slice and the parsed
/// numeric value is carried in `num`, so the parser can skip the decimal
/// round-trip.
#[derive(Debug, Clone)]
pub struct Token<'a> {
    /// What kind of token this is.
    pub kind: TokenKind,
    /// The token's string value (literal text, identifier name, number, etc.).
    pub val: Cow<'a, str>,
    /// Original Text/String bytes. Structural tokens carry no raw payload.
    pub raw: Option<Cow<'a,[u8]>>,
    /// Pre-parsed numeric value for `Number` / `Char` tokens. `None` for all
    /// other token kinds.
    pub num: Option<Number>,
    /// Byte offset in the original source.
    pub pos: usize,
    /// 1-based line number tracked during scanning.
    pub line: usize,
}

impl Token<'_> {
    /// Compute the 1-based `(line, column)` from the byte offset and the original source.
    ///
    /// `self.pos` is a byte offset. Columns count UTF-8 *characters*, not bytes,
    /// so multi-byte characters advance the column by one.
    pub fn line_col(&self,source:&str)->(usize,usize){self.line_col_bytes(source.as_bytes())}
    pub fn line_col_bytes(&self,source:&[u8])->(usize,usize){
        let end=self.pos.min(source.len());let start=source[..end].iter().rposition(|byte|*byte==b'\n').map_or(0,|i|i+1);
        (self.line,crate::go_runes(&source[start..end]).count()+1)
    }

}

// Lexer
/// Tokenizer for Go template source text.
///
/// Converts a raw template string into a [`Vec<Token>`] via [`tokenize`](Self::tokenize).
/// Supports configurable delimiters, trim markers, comments, and Go-compatible
/// number literals.
///
/// This is used internally by the [`Parser`](crate::parse::Parser); most users
/// interact with [`Template`](crate::Template) directly.
pub struct Lexer<'a> {
    input: &'a [u8],
    previous:usize,
    pos: usize,
    start: usize,
    tokens: Vec<Token<'a>>,
    left_delim: &'a str,
    right_delim: &'a str,
    line: usize,
    parse_name: Option<&'a str>,
}

impl<'a> Lexer<'a> {
    /// Create a new lexer for the given input with the specified delimiters.
    pub fn new(input:&'a str,left_delim:&'a str,right_delim:&'a str)->Self{Self::new_bytes(input.as_bytes(),left_delim,right_delim)}
    pub fn new_bytes(input:&'a[u8],left_delim:&'a str,right_delim:&'a str)->Self {
        // Heuristic: one token per ~8 bytes of source. Overshoots slightly on
        // ASCII-heavy text, which is fine; it avoids the ~7 reallocations a
        // defaulted Vec would do on a 100-token template.
        let capacity = input.len() / 8 + 8;
        Lexer {
            input,
            previous:0,
            pos: 0,
            start: 0,
            tokens: Vec::with_capacity(capacity),
            left_delim,
            right_delim,
            line: 1,
            parse_name: None,
        }
    }

    /// Tag the lexer with a source name (e.g. file path) that is included in
    /// lex error messages. The name is borrowed for the lexer's lifetime and
    /// only copied into a `String` when a lex error is actually emitted.
    pub fn with_name(mut self, name: Option<&'a str>) -> Self {
        self.parse_name = name;
        self
    }

    fn at_left_trim(&self) -> bool {
        // Go requires a space (space/tab/CR/LF) after the `-` for `{{- ` to
        // count as a trim marker; `{{-foo}}` tokenises as the plain left delim
        // followed by `-foo`.
        let bytes = self.input;
        self.starts_with(self.left_delim)
            && bytes.get(self.pos + self.left_delim.len()) == Some(&b'-')
            && bytes
                .get(self.pos + self.left_delim.len() + 1)
                .is_some_and(|b| is_go_space(*b))
    }

    /// Detect a right trim marker at the current position. `ws_before` must be
    /// true if at least one ASCII space/tab/CR/LF was consumed immediately
    /// before; Go rejects `-}}` without a preceding space.
    fn at_right_trim(&self, ws_before: bool) -> bool {
        ws_before
            && self.input.get(self.pos) == Some(&b'-')
            && self.input[self.pos + 1..].starts_with(self.right_delim.as_bytes())
    }

    /// Tokenize the entire input and return the token stream.
    pub fn tokenize(mut self) -> Result<Vec<Token<'a>>> {
        self.lex_text()?;
        self.emit(TokenKind::Eof)?;
        Ok(self.tokens)
    }

    // Helpers
    fn starts_with(&self, prefix: &str) -> bool {
        self.input[self.pos..].starts_with(prefix.as_bytes())
    }

    fn peek(&self)->Option<char>{crate::decode_go_rune(&self.input[self.pos..]).map(|r|r.0)}
    fn peek_ahead(&self,n:usize)->Option<char>{crate::go_runes(&self.input[self.pos..]).nth(n).map(|r|r.0)}
    fn next_char(&mut self)->Option<char>{let(ch,width)=crate::decode_go_rune(&self.input[self.pos..])?;self.previous=self.pos;self.pos+=width;if ch=='\n'{self.line+=1;}Some(ch)}
    fn backup(&mut self){if self.previous<self.pos{if self.input[self.previous]==b'\n'{self.line-=1;}self.pos=self.previous;}}

    /// Advance `n` bytes, tracking newlines. `n` must land on a char boundary
    /// (callers pass `delim.len()` or byte counts of ASCII sequences).
    fn skip(&mut self, n: usize) {
        let target = self.pos + n;
        while self.pos < target {
            self.next_char();
        }
        debug_assert_eq!(self.pos, target, "skip({}) overshot a char boundary", n);
    }

    fn current_bytes(&self)->&'a[u8]{&self.input[self.start..self.pos]}
    fn current_str(&self)->Result<&'a str>{core::str::from_utf8(self.current_bytes()).map_err(|_|self.error("invalid UTF-8 structural token"))}
    fn emit(&mut self,kind:TokenKind)->Result<()>{
        let val=Cow::Borrowed(self.current_str()?);self.tokens.push(Token{kind,val,raw:None,num:None,pos:self.start,line:self.line});self.start=self.pos;Ok(())
    }
    fn emit_raw(&mut self,kind:TokenKind,raw:Cow<'a,[u8]>){
        self.tokens.push(Token{kind,val:Cow::Borrowed(""),raw:Some(raw),num:None,pos:self.start,line:self.line});self.start=self.pos;
    }

    fn emit_val(&mut self, kind: TokenKind, val: Cow<'a, str>) {
        self.tokens.push(Token {
            kind,
            val,
            raw:None,
            num: None,
            pos: self.start,
            line: self.line,
        });
        self.start = self.pos;
    }

    fn emit_num(&mut self, kind: TokenKind, num: Number) -> Result<()> {
        let val = Cow::Borrowed(self.current_str()?);
        self.tokens.push(Token {
            kind,
            val,
            raw:None,
            num: Some(num),
            pos: self.start,
            line: self.line,
        });
        self.start = self.pos;
        Ok(())
    }

    fn ignore(&mut self) {
        self.start = self.pos;
    }

    fn error(&self, msg: impl Into<String>) -> TemplateError {
        // Cold path: error construction. `col` is derived on demand rather
        // than carried through scanning because every `next_char` / `backup`
        // would otherwise need a branch to reset or decrement it. `line` is
        // already tracked because newlines are rare by comparison, and
        // scanning back to the previous newline runs once per error.
        let prefix = &self.input[..self.pos];
        let start=prefix.iter().rposition(|byte|*byte==b'\n').map_or(0,|i|i+1);
        let col=crate::go_runes(&prefix[start..]).count()+1;
        TemplateError::Lex {
            name: self.parse_name.map(String::from),
            line: self.line,
            col,
            message: msg.into(),
        }
    }

    // State: Scanning text outside delimiters
    fn lex_text(&mut self) -> Result<()> {
        // Track whether the last action ended with a trim marker (-}})
        // so we can trim leading whitespace from the next text.
        let mut trim_leading = false;

        loop {
            if self.pos >= self.input.len() {
                if self.pos > self.start {
                    self.emit_pending_text(trim_leading, false);
                }
                return Ok(());
            }

            // Check for left trim delimiter (e.g. "{{-")
            if self.at_left_trim() {
                if self.pos > self.start {
                    // {{- trims trailing whitespace from preceding text
                    self.emit_pending_text(trim_leading, true);
                }
                self.skip(self.left_delim.len() + 1);
                self.ignore();
                self.emit(TokenKind::LeftTrimDelim)?;
                trim_leading = self.lex_action_body()?;
                continue;
            }

            // Check for regular left delimiter (e.g. "{{")
            let ld = self.left_delim;
            if self.starts_with(ld) {
                if self.pos > self.start {
                    self.emit_pending_text(trim_leading, false);
                }
                let ld_len = self.left_delim.len();
                self.skip(ld_len);
                self.ignore();
                self.emit(TokenKind::LeftDelim)?;
                trim_leading = self.lex_action_body()?;
                continue;
            }

            self.next_char();
        }
    }

    /// Emit accumulated text before a delimiter, applying trim as needed.
    ///
    /// `trim_leading`: trim whitespace from the start (previous action had `-}}`).
    /// `trim_trailing`: trim whitespace from the end (current delimiter is `{{-`).
    fn emit_pending_text(&mut self, trim_leading: bool, trim_trailing: bool) {
        let mut slice=self.current_bytes();
        if trim_leading{let start=slice.iter().position(|byte|!is_go_space(*byte)).unwrap_or(slice.len());slice=&slice[start..];}
        if trim_trailing{let end=slice.iter().rposition(|byte|!is_go_space(*byte)).map_or(0,|i|i+1);slice=&slice[..end];}
        if !slice.is_empty(){self.emit_raw(TokenKind::Text,Cow::Borrowed(slice));}else{self.ignore();}
    }

    /// Lex the body of an action after the left delimiter has been emitted.
    /// Handles comments and regular action content.
    /// Returns whether the close delimiter was a trim marker (`-}}`).
    fn lex_action_body(&mut self) -> Result<bool> {
        if let Some(trims) = self.try_lex_comment()? {
            return Ok(trims);
        }
        self.lex_inside()?;
        Ok(self
            .tokens
            .last()
            .is_some_and(|t| t.kind == TokenKind::RightTrimDelim))
    }

    /// Try to lex a comment after the left delimiter has been consumed.
    /// Returns `Ok(Some(close_trims))` if a comment was found and consumed,
    /// where `close_trims` indicates whether trailing whitespace should be trimmed.
    /// Returns `Ok(None)` if not a comment (position is restored).
    fn try_lex_comment(&mut self) -> Result<Option<bool>> {
        let saved_pos = self.pos;
        let saved_start = self.start;
        let saved_line = self.line;

        // Skip whitespace
        while let Some(ch) = self.peek() {
            if ch.is_ascii()&&is_go_space(ch as u8) {
                self.next_char();
            } else {
                break;
            }
        }

        if !self.starts_with("/*") {
            // Not a comment, restore
            self.pos = saved_pos;
            self.start = saved_start;
            self.line = saved_line;
            return Ok(None);
        }

        self.skip(2); // consume /*

        // Scan to closing */
        loop {
            if self.pos >= self.input.len() {
                return Err(self.error("unclosed comment"));
            }
            if self.starts_with("*/") {
                self.skip(2);
                break;
            }
            self.next_char();
        }

        // Skip whitespace after */; `-}}` only binds as a trim marker when at
        // least one space/tab/CR/LF separates it from the comment terminator.
        let ws_before = self.skip_whitespace();

        let close_trims;
        if self.at_right_trim(ws_before) {
            self.skip(self.right_delim.len() + 1);
            close_trims = true;
        } else if self.starts_with(self.right_delim) {
            self.skip(self.right_delim.len());
            close_trims = false;
        } else {
            return Err(self.error("comment not terminated by closing delimiter"));
        }

        self.ignore();

        // Remove the LeftDelim/LeftTrimDelim token that was already emitted.
        // Check if the open was a trim delimiter.
        let open_was_trim = self
            .tokens
            .last()
            .is_some_and(|t| t.kind == TokenKind::LeftTrimDelim);
        self.tokens.pop();

        // The caller (lex_text) needs to know if trailing whitespace should be
        // trimmed. This happens when either open or close had a trim marker.
        Ok(Some(open_was_trim || close_trims))
    }

    // State: Scanning inside {{ ... }}
    fn lex_inside(&mut self) -> Result<()> {
        loop {
            let ws_before = self.skip_whitespace();
            self.ignore();

            if self.pos >= self.input.len() {
                return Err(self.error("unclosed action"));
            }

            if self.at_right_trim(ws_before) {
                self.skip(self.right_delim.len() + 1);
                self.ignore();
                self.emit(TokenKind::RightTrimDelim)?;
                return Ok(());
            }

            if self.starts_with(self.right_delim) {
                let rd_len = self.right_delim.len();
                self.skip(rd_len);
                self.ignore();
                self.emit(TokenKind::RightDelim)?;
                return Ok(());
            }

            let Some(ch) = self.peek() else {
                return Err(self.error("unclosed action"));
            };

            match ch {
                '|' => {
                    self.next_char();
                    self.emit(TokenKind::Pipe)?;
                }
                ',' => {
                    self.next_char();
                    self.emit(TokenKind::Comma)?;
                }
                '(' => {
                    self.next_char();
                    self.emit(TokenKind::LeftParen)?;
                }
                ')' => {
                    self.next_char();
                    self.emit(TokenKind::RightParen)?;
                }
                ':' => {
                    self.next_char();
                    if self.peek() == Some('=') {
                        self.next_char();
                        self.emit(TokenKind::Declare)?;
                    } else {
                        return Err(self.error("expected '=' after ':'"));
                    }
                }
                '=' => {
                    self.next_char();
                    self.emit(TokenKind::Assign)?;
                }
                '"' => self.lex_quoted_string()?,
                '`' => self.lex_raw_string()?,
                '.' => {
                    // Could be just dot, or a field like .Name, or a number like .5
                    self.next_char();
                    if self.peek().is_none_or(|c| !crate::go_unicode::is_alpha_numeric(c)) {
                        self.emit(TokenKind::Dot)?;
                    } else if self.peek().is_some_and(|c| c.is_ascii_digit()) {
                        // It's a float starting with .
                        self.backup();
                        self.lex_number()?;
                    } else {
                        // It's a field access: .Name
                        self.lex_field()?;
                    }
                }
                '$' => self.lex_variable()?,
                '-' | '+'
                    // Could be a sign for a number, or just a minus/plus
                    if self
                        .peek_ahead(1)
                        .is_some_and(|c| c.is_ascii_digit() || c == '.') =>
                {
                    self.lex_number()?;
                }
                '0'..='9' => self.lex_number()?,
                '\'' => self.lex_char_literal()?,
                _ if crate::go_unicode::is_alpha_numeric(ch) => self.lex_identifier()?,
                _ => return Err(self.error(format!("unexpected character: {:?}", ch))),
            }
        }
    }

    /// Consume ASCII space/tab/CR/LF. Returns true if any were consumed.
    fn skip_whitespace(&mut self) -> bool {
        let start = self.pos;
        while let Some(ch) = self.peek() {
            if ch.is_ascii()&&is_go_space(ch as u8) {
                self.next_char();
            } else {
                break;
            }
        }
        self.pos != start
    }

    // Individual token scanners
    fn lex_quoted_string(&mut self) -> Result<()> {
        self.next_char(); // consume opening "
        loop {
            match self.next_char() {
                None => return Err(self.error("unterminated string")),
                Some('\\') => {
                    self.next_char();
                } // skip escaped char
                Some('"') => {
                    let raw=self.current_bytes();let inner=&raw[1..raw.len()-1];
                    let bytes=crate::go_unquote::unquote_bytes(inner,false).map_err(|message|self.error(message))?;
                    self.emit_raw(TokenKind::String,Cow::Owned(bytes));
                    return Ok(());
                }
                _ => {}
            }
        }
    }

    fn lex_raw_string(&mut self) -> Result<()> {
        self.next_char(); // consume opening `
        loop {
            match self.next_char() {
                None => return Err(self.error("unterminated raw string")),
                Some('`') => {
                    let raw=self.current_bytes();let inner=&raw[1..raw.len()-1];
                    let bytes=crate::go_unquote::unquote_bytes(inner,true).map_err(|message|self.error(message))?;
                    self.emit_raw(TokenKind::String,Cow::Owned(bytes));
                    return Ok(());
                }
                _ => {}
            }
        }
    }

    /// Read exactly `digits` ASCII hex characters and return the resulting
    /// `char`, or `'\0'` if the value is not a valid Unicode scalar (matching
    /// Go's behavior for surrogates and out-of-range escapes). Emits `err_msg`
    /// on the first non-hex / EOF byte. Used by `\x`, `\u`, and `\U`.
    fn read_hex_escape(&mut self, digits: usize, err_msg: &'static str) -> Result<char> {
        let mut n: u32 = 0;
        for _ in 0..digits {
            match self.next_char() {
                Some(c) if c.is_ascii_hexdigit() => {
                    #[allow(clippy::unwrap_used, reason = "validated ASCII hex digit")]
                    let d = c.to_digit(16).unwrap();
                    n = n * 16 + d;
                }
                _ => return Err(self.error(err_msg)),
            }
        }
        char::from_u32(n).ok_or_else(||self.error("invalid Unicode escape"))
    }

    fn consume_ident_chars(&mut self) {
        while let Some(ch) = self.peek() {
            if crate::go_unicode::is_alpha_numeric(ch) {
                self.next_char();
            } else {
                break;
            }
        }
    }

    fn lex_field(&mut self) -> Result<()> {
        // We've already consumed the '.', now consume the identifier part
        self.consume_ident_chars();
        self.emit(TokenKind::Field)?;
        Ok(())
    }

    fn lex_variable(&mut self) -> Result<()> {
        self.next_char(); // consume $
        self.consume_ident_chars();
        self.emit(TokenKind::Variable)?;
        Ok(())
    }

    fn lex_number(&mut self) -> Result<()> {
        // Accept optional sign
        if self.peek() == Some('+') || self.peek() == Some('-') {
            self.next_char();
        }

        // Check for base prefixes: 0x, 0o, 0b
        if self.peek() == Some('0') {
            self.next_char();
            match self.peek() {
                Some('x' | 'X') => {
                    self.next_char();
                    return self.lex_hex_number();
                }
                Some('o' | 'O') => {
                    self.next_char();
                    return self.lex_base_number(8);
                }
                Some('b' | 'B') => {
                    self.next_char();
                    return self.lex_base_number(2);
                }
                _ => {
                    // Check for legacy octal: 0 followed only by [0-7_]
                    // (e.g., 0377 → 255). If a dot, 'e'/'E', or digit 8-9
                    // follows, fall through to decimal instead.
                    let bytes = self.input;
                    let mut look = self.pos;
                    let mut has_octal_digits = false;
                    let mut is_legacy_octal = true;
                    while look < bytes.len() {
                        let b = bytes[look];
                        if (b'0'..=b'7').contains(&b) {
                            has_octal_digits = true;
                            look += 1;
                        } else if b == b'_' {
                            look += 1;
                        } else if matches!(b, b'.' | b'e' | b'E' | b'8' | b'9') {
                            is_legacy_octal = false;
                            break;
                        } else {
                            break;
                        }
                    }
                    if is_legacy_octal && has_octal_digits {
                        while self
                            .peek()
                            .is_some_and(|c| ('0'..='7').contains(&c) || c == '_')
                        {
                            self.next_char();
                        }
                        let raw = self.current_str()?;
                        let clean = strip_underscores(raw);
                        let (negative, digits) = if let Some(d) = clean.strip_prefix("-0") {
                            (true, d)
                        } else if let Some(d) = clean.strip_prefix("+0") {
                            (false, d)
                        } else if let Some(d) = clean.strip_prefix('0') {
                            (false, d)
                        } else {
                            (false, clean.as_ref())
                        };
                        match radix_number(digits, 8, negative) {
                            Ok(num) => self.emit_num(TokenKind::Number, num)?,
                            Err(e) => return Err(self.error(int_parse_msg("octal", &e))),
                        }
                        return Ok(());
                    }
                    // Otherwise fall through to lex_decimal_number
                }
            }
        }

        self.lex_decimal_number()
    }

    fn lex_hex_number(&mut self) -> Result<()> {
        let mut has_digits = false;
        while let Some(ch) = self.peek() {
            if ch.is_ascii_hexdigit() {
                has_digits = true;
                self.next_char();
            } else if ch == '_' {
                self.next_char(); // skip digit separator
            } else if ch == '.' || ch == 'p' || ch == 'P' {
                // Hex float: 0x1.Fp10
                return self.lex_hex_float(has_digits);
            } else {
                break;
            }
        }
        if !has_digits {
            return Err(self.error("invalid hex number"));
        }
        // Emit as number but we need to convert to decimal for the value
        let raw = self.current_str()?;
        let clean = strip_underscores(raw);
        // Parse hex int
        let negative = clean.starts_with('-');
        let hex_str = if negative {
            clean
                .trim_start_matches('-')
                .trim_start_matches('+')
                .trim_start_matches("0x")
                .trim_start_matches("0X")
        } else {
            clean
                .trim_start_matches('+')
                .trim_start_matches("0x")
                .trim_start_matches("0X")
        };
        match radix_number(hex_str, 16, negative) {
            Ok(num) => self.emit_num(TokenKind::Number, num)?,
            Err(e) => return Err(self.error(int_parse_msg("hex", &e))),
        }
        Ok(())
    }

    fn lex_hex_float(&mut self, _had_digits: bool) -> Result<()> {
        // Consume hex float: digits, dot, hex digits, p/P, optional sign, decimal digits
        if self.peek() == Some('.') {
            self.next_char();
            while let Some(ch) = self.peek() {
                if ch.is_ascii_hexdigit() || ch == '_' {
                    self.next_char();
                } else {
                    break;
                }
            }
        }
        if self.peek() == Some('p') || self.peek() == Some('P') {
            self.next_char();
            if self.peek() == Some('+') || self.peek() == Some('-') {
                self.next_char();
            }
            while let Some(ch) = self.peek() {
                if ch.is_ascii_digit() || ch == '_' {
                    self.next_char();
                } else {
                    break;
                }
            }
        }
        // For hex floats, just emit the raw value. Rust can parse them with special handling
        let raw = self.current_str()?;
        let clean = strip_underscores(raw);
        // Parse hex float manually: use the format 0xHEX.HEXpEXP
        match crate::go::parse_hex_float(&clean) {
            Some(f) => self.emit_num(TokenKind::Number, Number::Float(f))?,
            None => return Err(self.error("invalid hex float")),
        }
        Ok(())
    }

    fn lex_base_number(&mut self, base: u32) -> Result<()> {
        let mut has_digits = false;
        while let Some(ch) = self.peek() {
            let valid = match base {
                2 => ch == '0' || ch == '1',
                8 => ('0'..='7').contains(&ch),
                _ => false,
            };
            if valid {
                has_digits = true;
                self.next_char();
            } else if ch == '_' {
                self.next_char();
            } else {
                break;
            }
        }
        if !has_digits {
            return Err(self.error(format!("invalid base-{} number", base)));
        }
        let raw = self.current_str()?;
        let clean = strip_underscores(raw);
        let negative = clean.starts_with('-');
        let prefix_len = if negative { 3 } else { 2 }; // skip sign + 0x/0o/0b
        let digits = &clean[prefix_len..];
        let kind = match base {
            2 => "binary",
            8 => "octal",
            _ => "integer",
        };
        match radix_number(digits, base, negative) {
            Ok(num) => self.emit_num(TokenKind::Number, num)?,
            Err(e) => return Err(self.error(int_parse_msg(kind, &e))),
        }
        Ok(())
    }

    fn lex_decimal_number(&mut self) -> Result<()> {
        let mut has_dot = false;
        let mut has_exp = false;
        let mut has_digits = self
            .input
            .get(self.pos.saturating_sub(1))
            .is_some_and(u8::is_ascii_digit);

        while let Some(ch) = self.peek() {
            if ch.is_ascii_digit() {
                has_digits = true;
                self.next_char();
            } else if ch == '_' {
                // Digit separator
                self.next_char();
            } else if ch == '.' && !has_dot && !has_exp {
                has_dot = true;
                self.next_char();
            } else if (ch == 'e' || ch == 'E') && !has_exp {
                has_exp = true;
                self.next_char();
                if self.peek() == Some('+') || self.peek() == Some('-') {
                    self.next_char();
                }
            } else {
                break;
            }
        }

        if !has_digits {
            return Err(self.error("invalid number"));
        }

        let raw = self.current_str()?;
        // Strip underscores for parsing; borrow when the literal has none.
        let clean = strip_underscores(raw);
        let num = if has_dot || has_exp {
            clean
                .parse::<f64>()
                .map(Number::Float)
                .map_err(|_| self.error("invalid number"))?
        } else {
            // Strip the sign so a non-negative overflow can fall back to u64.
            let negative = clean.starts_with('-');
            let digits = clean
                .strip_prefix('-')
                .or_else(|| clean.strip_prefix('+'))
                .unwrap_or(clean.as_ref());
            radix_number(digits, 10, negative)
                .map_err(|e| self.error(int_parse_msg("decimal", &e)))?
        };
        // Emit with underscore-stripped val so existing consumers (error
        // messages, tests) see a clean decimal string; the parser reads `num`.
        self.tokens.push(Token {
            kind: TokenKind::Number,
            val: clean,
            raw:None,
            num: Some(num),
            pos: self.start,
            line: self.line,
        });
        self.start = self.pos;
        Ok(())
    }

    fn lex_char_literal(&mut self) -> Result<()> {
        self.next_char(); // consume opening '
        let ch = match self.next_char() {
            Some('\\') => {
                // Escaped character
                match self.next_char() {
                    Some('n') => '\n',
                    Some('t') => '\t',
                    Some('r') => '\r',
                    Some('\\') => '\\',
                    Some('\'') => '\'',
                    Some('a') => '\x07', // bell
                    Some('b') => '\x08', // backspace
                    Some('f') => '\x0C', // form feed
                    Some('v') => '\x0B', // vertical tab
                    Some('x') => self.read_hex_escape(2, "invalid hex escape in char literal")?,
                    Some('u') => {
                        self.read_hex_escape(4, "invalid unicode escape in char literal")?
                    }
                    Some('U') => {
                        self.read_hex_escape(8, "invalid unicode escape in char literal")?
                    }
                    // Octal: \NNN — exactly three octal digits, value ≤ 255
                    // (Go parity). Shares `decode_octal_escape` with the
                    // string-literal path so the two cannot drift; `\0`, `\12`,
                    // and `\8` are rejected just as Go rejects them in char
                    // constants.
                    Some(d1 @ '0'..='7') => {
                        let byte = decode_octal_escape(d1, self.next_char(), self.next_char())
                            .map_err(|m| self.error(m))?;
                        char::from(byte)
                    }
                    Some(c) => c,
                    None => return Err(self.error("unterminated character literal")),
                }
            }
            Some(c) => c,
            None => return Err(self.error("unterminated character literal")),
        };

        if self.next_char() != Some('\'') {
            return Err(self.error("unterminated character literal"));
        }

        // Emit as a number (Go treats char constants as their Unicode code point)
        self.emit_num(TokenKind::Char, Number::Int(i64::from(ch as u32)))?;
        Ok(())
    }

    fn lex_identifier(&mut self) -> Result<()> {
        self.consume_ident_chars();
        let kind = match self.current_str()? {
            "if" => TokenKind::If,
            "else" => TokenKind::Else,
            "end" => TokenKind::End,
            "range" => TokenKind::Range,
            "with" => TokenKind::With,
            "define" => TokenKind::Define,
            "template" => TokenKind::Template,
            "block" => TokenKind::Block,
            "break" => TokenKind::Break,
            "continue" => TokenKind::Continue,
            "true" | "false" => TokenKind::Bool,
            "nil" => TokenKind::Nil,
            _ => TokenKind::Identifier,
        };
        self.emit(kind)?;
        Ok(())
    }
}

// String escape processing.
//
// Returns the message (without position) on the first invalid escape so the
// caller can wrap it via `Lexer::error` to attach line/col. The whole string
// has already been scanned at this point, so the reported position will land
// just after the closing quote — imprecise but unambiguous.
//
// Decode a `\NNN` octal escape: exactly three octal digits (0-7), value ≤ 255.
//
// Shared by the string-literal (`unescape`) and char-literal (`lex_char_literal`)
// paths so the two cannot drift apart — both reject `\0`, `\12`, `\8`, and
// `\777` to match Go, which parses `\N` as the first digit of a mandatory
// three-digit octal escape. `d1` is the already-consumed leading digit; `d2`
// and `d3` are the next two characters from the caller's cursor. Returns the
// message (without position) so the caller can attach line/col via `error`.
fn decode_octal_escape(
    d1: char,
    d2: Option<char>,
    d3: Option<char>,
) -> core::result::Result<u8, String> {
    let (c2, c3) = match (d2, d3) {
        (Some(c2 @ '0'..='7'), Some(c3 @ '0'..='7')) => (c2, c3),
        _ => {
            return Err(format!(
                "invalid octal escape (need three octal digits after \\{d1})"
            ));
        }
    };
    // Each digit is validated above; to_digit cannot fail.
    #[allow(clippy::unwrap_used, reason = "validated octal digit")]
    let n: u32 =
        d1.to_digit(8).unwrap() * 64 + c2.to_digit(8).unwrap() * 8 + c3.to_digit(8).unwrap();
    u8::try_from(n).map_err(|_| format!("octal escape value out of range: \\{d1}{c2}{c3}"))
}
