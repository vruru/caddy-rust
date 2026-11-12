use crate::common::ast::{
    operators, CallExpr, EntryExpr, Expr, IdedEntryExpr, IdedExpr, ListExpr, LiteralValue,
    MapEntryExpr, MapExpr, SelectExpr, SourceInfo, StructExpr, StructFieldExpr,
};
use crate::parser::macros::Macros;
use crate::parser::{MacroExprHelper, ParseError, ParseErrors, ParserHelper};
use std::mem;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenKind {
    TokError,
    TokEnd,
    TokWhitespace,
    TokComment,

    // Keywords
    TokNull,
    TokFalse,
    TokTrue,
    TokIn,
    TokReservedWord,

    // Literals
    TokInt,
    TokUint,
    TokFloat,
    TokString,
    TokBytes,

    // Identifiers
    TokIdent,

    // Delimiters
    TokLeftBracket,  // [
    TokRightBracket, // ]
    TokLeftBrace,    // {
    TokRightBrace,   // }
    TokLeftParen,    // (
    TokRightParen,   // )

    // Operators
    TokDot,              // .
    TokComma,            // ,
    TokMinus,            // -
    TokPlus,             // +
    TokAsterisk,         // *
    TokSlash,            // /
    TokPercent,          // %
    TokQuestion,         // ?
    TokColon,            // :
    TokExclamation,      // !
    TokEqual,            // =
    TokEqualEqual,       // ==
    TokExclamationEqual, // !=
    TokLess,             // <
    TokLessEqual,        // <=
    TokGreater,          // >
    TokGreaterEqual,     // >=
    TokLogicalAnd,       // &&
    TokLogicalOr,        // ||
}

impl TokenKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            TokenKind::TokError => "error",
            TokenKind::TokEnd => "end",
            TokenKind::TokWhitespace => "whitespace",
            TokenKind::TokComment => "comment",
            TokenKind::TokNull => "null",
            TokenKind::TokFalse => "false",
            TokenKind::TokTrue => "true",
            TokenKind::TokIn => "in",
            TokenKind::TokReservedWord => "reserved_word",
            TokenKind::TokInt => "int",
            TokenKind::TokUint => "uint",
            TokenKind::TokFloat => "float",
            TokenKind::TokString => "string",
            TokenKind::TokBytes => "bytes",
            TokenKind::TokIdent => "ident",
            TokenKind::TokLeftBracket => "[",
            TokenKind::TokRightBracket => "]",
            TokenKind::TokLeftBrace => "{",
            TokenKind::TokRightBrace => "}",
            TokenKind::TokLeftParen => "(",
            TokenKind::TokRightParen => ")",
            TokenKind::TokDot => ".",
            TokenKind::TokComma => ",",
            TokenKind::TokMinus => "-",
            TokenKind::TokPlus => "+",
            TokenKind::TokAsterisk => "*",
            TokenKind::TokSlash => "/",
            TokenKind::TokPercent => "%",
            TokenKind::TokQuestion => "?",
            TokenKind::TokColon => ":",
            TokenKind::TokExclamation => "!",
            TokenKind::TokEqual => "=",
            TokenKind::TokEqualEqual => "==",
            TokenKind::TokExclamationEqual => "!=",
            TokenKind::TokLess => "<",
            TokenKind::TokLessEqual => "<=",
            TokenKind::TokGreater => ">",
            TokenKind::TokGreaterEqual => ">=",
            TokenKind::TokLogicalAnd => "&&",
            TokenKind::TokLogicalOr => "||",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Token {
    pub kind: TokenKind,
    pub start: usize,
    pub end: usize,
}

impl Default for Token {
    fn default() -> Self {
        Self {
            kind: TokenKind::TokError,
            start: 0,
            end: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LexerError {
    pub start: usize,
    pub end: usize,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LexerPosition {
    pub pos: usize,
    pub at_end: bool,
    pub done: bool,
    pub err: Option<LexerError>,
}

const KEYWORDS: &[(&str, TokenKind)] = &[
    ("false", TokenKind::TokFalse),
    ("true", TokenKind::TokTrue),
    ("null", TokenKind::TokNull),
    ("in", TokenKind::TokIn),
    ("as", TokenKind::TokReservedWord),
    ("break", TokenKind::TokReservedWord),
    ("const", TokenKind::TokReservedWord),
    ("continue", TokenKind::TokReservedWord),
    ("else", TokenKind::TokReservedWord),
    ("for", TokenKind::TokReservedWord),
    ("function", TokenKind::TokReservedWord),
    ("if", TokenKind::TokReservedWord),
    ("import", TokenKind::TokReservedWord),
    ("let", TokenKind::TokReservedWord),
    ("loop", TokenKind::TokReservedWord),
    ("package", TokenKind::TokReservedWord),
    ("namespace", TokenKind::TokReservedWord),
    ("return", TokenKind::TokReservedWord),
    ("var", TokenKind::TokReservedWord),
    ("void", TokenKind::TokReservedWord),
    ("while", TokenKind::TokReservedWord),
];

const RESERVED_IDS: &[&str] = &[
    "as",
    "break",
    "const",
    "continue",
    "else",
    "for",
    "function",
    "if",
    "import",
    "let",
    "loop",
    "package",
    "namespace",
    "return",
    "var",
    "void",
    "while",
];

fn is_ident_trailing(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn is_alpha(b: u8) -> bool {
    b.is_ascii_alphabetic()
}

pub struct Lexer<'a> {
    source: &'a str,
    bytes: &'a [u8],
    length: usize,
    pos: usize,
    at_end: bool,
    done: bool,
    err: Option<LexerError>,
}

impl<'a> Lexer<'a> {
    pub fn new(source: &'a str) -> Self {
        Self {
            source,
            bytes: source.as_bytes(),
            length: source.len(),
            pos: 0,
            at_end: false,
            done: false,
            err: None,
        }
    }

    pub fn save_position(&self) -> LexerPosition {
        LexerPosition {
            pos: self.pos,
            at_end: self.at_end,
            done: self.done,
            err: self.err.clone(),
        }
    }

    pub fn restore_position(&mut self, p: LexerPosition) {
        self.pos = p.pos;
        self.at_end = p.at_end;
        self.done = p.done;
        self.err = p.err;
    }

    pub fn get_error(&self) -> Option<&LexerError> {
        self.err.as_ref()
    }

    fn make_token(&mut self, kind: TokenKind, start: usize, end: usize) -> Token {
        if self.at_end {
            self.done = true;
        }
        Token { kind, start, end }
    }

    fn set_error(&mut self, start: usize, end: usize, msg: String) -> Token {
        self.err = Some(LexerError {
            start,
            end,
            message: msg,
        });
        Token {
            kind: TokenKind::TokError,
            start,
            end,
        }
    }

    fn advance(&mut self, n: usize) {
        self.pos += n;
    }

    fn match_byte(&self, b: u8) -> bool {
        self.pos < self.length && self.bytes[self.pos] == b
    }

    fn match_ignore_case(&self, b: u8) -> bool {
        if self.pos >= self.length {
            return false;
        }
        self.bytes[self.pos].eq_ignore_ascii_case(&b)
    }

    fn consume_byte(&mut self, b: u8) -> bool {
        if self.match_byte(b) {
            self.advance(1);
            true
        } else {
            false
        }
    }

    fn consume_ignore_case(&mut self, b: u8) -> bool {
        if self.match_ignore_case(b) {
            self.advance(1);
            true
        } else {
            false
        }
    }

    fn consume_line(&mut self) {
        while self.pos < self.length {
            if self.bytes[self.pos] == b'\n' {
                self.advance(1);
                return;
            }
            self.advance(1);
        }
    }

    fn consume_whitespace(&mut self) {
        while self.pos < self.length {
            match self.bytes[self.pos] {
                b'\x0C' | b'\n' | b' ' | b'\r' | b'\x0B' | b'\t' => {
                    self.advance(1);
                }
                _ => return,
            }
        }
    }

    fn consume_digits(&mut self) -> bool {
        let mut advanced = false;
        while self.pos < self.length {
            if !self.bytes[self.pos].is_ascii_digit() {
                break;
            }
            self.advance(1);
            advanced = true;
        }
        advanced
    }

    fn consume_hex_digits(&mut self) -> bool {
        let mut advanced = false;
        while self.pos < self.length {
            if !self.bytes[self.pos].is_ascii_hexdigit() {
                break;
            }
            self.advance(1);
            advanced = true;
        }
        advanced
    }

    fn consume_integral_suffix(&mut self) -> TokenKind {
        if self.consume_ignore_case(b'u') {
            TokenKind::TokUint
        } else {
            TokenKind::TokInt
        }
    }

    fn consume_until_after(&mut self, quote: u8) -> bool {
        for pos in self.pos..self.length {
            if self.bytes[pos] == quote {
                self.pos = pos + 1;
                return true;
            }
        }
        self.pos = self.length;
        false
    }

    fn consume_until_after_triple(&mut self, quote: u8) -> bool {
        let mut pos = self.pos;
        while pos + 3 <= self.length {
            if self.bytes[pos] == quote
                && self.bytes[pos + 1] == quote
                && self.bytes[pos + 2] == quote
            {
                self.pos = pos + 3;
                return true;
            }
            pos += 1;
        }
        self.pos = self.length;
        false
    }

    fn consume_until_after_unescaped(&mut self, quote: u8) -> bool {
        let mut pos = self.pos;
        let mut escaped = false;
        while pos < self.length {
            let b = self.bytes[pos];
            if b == b'\\' {
                escaped = !escaped;
            } else {
                if b == quote && !escaped {
                    self.pos = pos + 1;
                    return true;
                }
                escaped = false;
            }
            pos += 1;
        }
        self.pos = self.length;
        false
    }

    fn consume_until_after_unescaped_triple(&mut self, quote: u8) -> bool {
        let mut pos = self.pos;
        let mut escaped = false;
        while pos < self.length {
            let b = self.bytes[pos];
            if b == b'\\' {
                escaped = !escaped;
            } else {
                if !escaped
                    && pos + 3 <= self.length
                    && self.bytes[pos] == quote
                    && self.bytes[pos + 1] == quote
                    && self.bytes[pos + 2] == quote
                {
                    self.pos = pos + 3;
                    return true;
                }
                escaped = false;
            }
            pos += 1;
        }
        self.pos = self.length;
        false
    }

    fn consume_quoted_ident(&mut self) -> Token {
        let start = self.pos;
        self.advance(1);
        if !self.consume_until_after(b'`') {
            return self.set_error(
                start,
                self.pos,
                "unterminated quoted identifier".to_string(),
            );
        }
        self.make_token(TokenKind::TokIdent, start, self.pos)
    }

    fn consume_string_literal(
        &mut self,
        start: usize,
        quote: u8,
        is_bytes: bool,
        is_raw: bool,
    ) -> Token {
        self.advance(1);
        if self.pos + 2 <= self.length
            && self.bytes[self.pos] == quote
            && self.bytes[self.pos + 1] == quote
        {
            self.advance(2);
            let found = if is_raw {
                self.consume_until_after_triple(quote)
            } else {
                self.consume_until_after_unescaped_triple(quote)
            };
            if !found {
                let msg = if is_bytes {
                    "unterminated bytes literal"
                } else {
                    "unterminated string literal"
                };
                return self.set_error(start, self.pos, msg.to_string());
            }
            let kind = if is_bytes {
                TokenKind::TokBytes
            } else {
                TokenKind::TokString
            };
            return self.make_token(kind, start, self.pos);
        }
        let found = if is_raw {
            self.consume_until_after(quote)
        } else {
            self.consume_until_after_unescaped(quote)
        };
        if !found {
            let msg = if is_bytes {
                "unterminated bytes literal"
            } else {
                "unterminated string literal"
            };
            return self.set_error(start, self.pos, msg.to_string());
        }
        let kind = if is_bytes {
            TokenKind::TokBytes
        } else {
            TokenKind::TokString
        };
        self.make_token(kind, start, self.pos)
    }

    fn consume_prefixed_string_literal(&mut self) -> Option<Token> {
        let start = self.pos;
        if self.pos >= self.length {
            return None;
        }
        let c = self.bytes[self.pos];
        let mut is_bytes = c == b'b' || c == b'B';
        let mut is_raw = c == b'r' || c == b'R';
        let mut lookahead = 1;
        if self.pos + 1 < self.length {
            let c2 = self.bytes[self.pos + 1];
            if (is_bytes && (c2 == b'r' || c2 == b'R'))
                || (!is_bytes && is_raw && (c2 == b'b' || c2 == b'B'))
            {
                is_bytes = true;
                is_raw = true;
                lookahead = 2;
            }
        }
        if self.pos + lookahead < self.length {
            let quote = self.bytes[self.pos + lookahead];
            if quote == b'"' || quote == b'\'' {
                self.advance(lookahead);
                return Some(self.consume_string_literal(start, quote, is_bytes, is_raw));
            }
        }
        None
    }

    fn consume_numeric_literal(&mut self) -> Token {
        let start = self.pos;
        let c = self.bytes[self.pos];
        let mut floating_point = false;
        if c == b'.' {
            floating_point = true;
            self.advance(1);
            if !self.consume_digits() {
                return self.set_error(
                    start,
                    self.pos,
                    "floating point literal missing digits after decimal separator".to_string(),
                );
            }
        } else {
            self.advance(1);
            if c == b'0' && self.consume_ignore_case(b'x') {
                if !self.consume_hex_digits() {
                    return self.set_error(
                        start,
                        self.pos,
                        "integral literal missing digits after hexadecimal separator".to_string(),
                    );
                }
                let tok_type = self.consume_integral_suffix();
                if self.pos < self.length && is_ident_trailing(self.bytes[self.pos]) {
                    self.advance(1);
                    return self.set_error(
                        start,
                        self.pos,
                        format!(
                            "{} literal has unexpected trailing characters",
                            tok_type.as_str()
                        ),
                    );
                }
                return self.make_token(tok_type, start, self.pos);
            }
            let _ = self.consume_digits();
            if self.pos < self.length
                && self.bytes[self.pos] == b'.'
                && self.pos + 1 < self.length
                && self.bytes[self.pos + 1].is_ascii_digit()
            {
                floating_point = true;
                self.advance(1);
                let _ = self.consume_digits();
            }
        }
        if self.consume_ignore_case(b'e') {
            floating_point = true;
            if self.pos < self.length
                && (self.bytes[self.pos] == b'+' || self.bytes[self.pos] == b'-')
            {
                self.advance(1);
            }
            if !self.consume_digits() {
                return self.set_error(
                    start,
                    self.pos,
                    "floating point literal missing digits after exponent separator".to_string(),
                );
            }
        }
        let tok_type = if floating_point {
            TokenKind::TokFloat
        } else {
            self.consume_integral_suffix()
        };
        if self.pos < self.length && is_ident_trailing(self.bytes[self.pos]) {
            self.advance(1);
            return self.set_error(
                start,
                self.pos,
                format!(
                    "{} literal has unexpected trailing characters",
                    tok_type.as_str()
                ),
            );
        }
        self.make_token(tok_type, start, self.pos)
    }

    fn consume_ident(&mut self) -> Token {
        let start = self.pos;
        while self.pos < self.length {
            if !is_ident_trailing(self.bytes[self.pos]) {
                break;
            }
            self.advance(1);
        }
        let end = self.pos;
        let word = &self.source[start..end];
        for (kw, kind) in KEYWORDS {
            if *kw == word {
                return self.make_token(*kind, start, end);
            }
        }
        self.make_token(TokenKind::TokIdent, start, end)
    }

    pub fn lex(&mut self) -> Token {
        let start = self.pos;
        if self.pos >= self.length {
            self.at_end = true;
            self.done = true;
            return self.make_token(TokenKind::TokEnd, start, start);
        }
        let c = self.bytes[self.pos];
        match c {
            b'\x0C' | b'\x0B' | b'\t' | b'\r' | b'\n' | b' ' => {
                self.consume_whitespace();
                self.make_token(TokenKind::TokWhitespace, start, self.pos)
            }
            b'.' => {
                if self.pos + 1 < self.length && self.bytes[self.pos + 1].is_ascii_digit() {
                    return self.consume_numeric_literal();
                }
                self.advance(1);
                self.make_token(TokenKind::TokDot, start, self.pos)
            }
            b',' => {
                self.advance(1);
                self.make_token(TokenKind::TokComma, start, self.pos)
            }
            b'!' => {
                self.advance(1);
                if self.consume_byte(b'=') {
                    self.make_token(TokenKind::TokExclamationEqual, start, self.pos)
                } else {
                    self.make_token(TokenKind::TokExclamation, start, self.pos)
                }
            }
            b'?' => {
                self.advance(1);
                self.make_token(TokenKind::TokQuestion, start, self.pos)
            }
            b'(' => {
                self.advance(1);
                self.make_token(TokenKind::TokLeftParen, start, self.pos)
            }
            b')' => {
                self.advance(1);
                self.make_token(TokenKind::TokRightParen, start, self.pos)
            }
            b'{' => {
                self.advance(1);
                self.make_token(TokenKind::TokLeftBrace, start, self.pos)
            }
            b'}' => {
                self.advance(1);
                self.make_token(TokenKind::TokRightBrace, start, self.pos)
            }
            b'[' => {
                self.advance(1);
                self.make_token(TokenKind::TokLeftBracket, start, self.pos)
            }
            b']' => {
                self.advance(1);
                self.make_token(TokenKind::TokRightBracket, start, self.pos)
            }
            b'=' => {
                self.advance(1);
                if self.consume_byte(b'=') {
                    self.make_token(TokenKind::TokEqualEqual, start, self.pos)
                } else {
                    self.make_token(TokenKind::TokEqual, start, self.pos)
                }
            }
            b'<' => {
                self.advance(1);
                if self.consume_byte(b'=') {
                    self.make_token(TokenKind::TokLessEqual, start, self.pos)
                } else {
                    self.make_token(TokenKind::TokLess, start, self.pos)
                }
            }
            b'>' => {
                self.advance(1);
                if self.consume_byte(b'=') {
                    self.make_token(TokenKind::TokGreaterEqual, start, self.pos)
                } else {
                    self.make_token(TokenKind::TokGreater, start, self.pos)
                }
            }
            b':' => {
                self.advance(1);
                self.make_token(TokenKind::TokColon, start, self.pos)
            }
            b'%' => {
                self.advance(1);
                self.make_token(TokenKind::TokPercent, start, self.pos)
            }
            b'+' => {
                self.advance(1);
                self.make_token(TokenKind::TokPlus, start, self.pos)
            }
            b'-' => {
                self.advance(1);
                self.make_token(TokenKind::TokMinus, start, self.pos)
            }
            b'*' => {
                self.advance(1);
                self.make_token(TokenKind::TokAsterisk, start, self.pos)
            }
            b'/' => {
                self.advance(1);
                if self.consume_byte(b'/') {
                    self.consume_line();
                    self.make_token(TokenKind::TokComment, start, self.pos)
                } else {
                    self.make_token(TokenKind::TokSlash, start, self.pos)
                }
            }
            b'&' => {
                self.advance(1);
                if self.consume_byte(b'&') {
                    self.make_token(TokenKind::TokLogicalAnd, start, self.pos)
                } else {
                    self.set_error(
                        start,
                        self.pos,
                        "unexpected single '&', expected '&&'".to_string(),
                    )
                }
            }
            b'|' => {
                self.advance(1);
                if self.consume_byte(b'|') {
                    self.make_token(TokenKind::TokLogicalOr, start, self.pos)
                } else {
                    self.set_error(
                        start,
                        self.pos,
                        "unexpected single '|', expected '||'".to_string(),
                    )
                }
            }
            b'_' => self.consume_ident(),
            b'`' => self.consume_quoted_ident(),
            b'\'' => self.consume_string_literal(start, b'\'', false, false),
            b'"' => self.consume_string_literal(start, b'"', false, false),
            b'r' | b'R' | b'b' | b'B' => {
                if let Some(tok) = self.consume_prefixed_string_literal() {
                    tok
                } else {
                    self.consume_ident()
                }
            }
            _ => {
                if c.is_ascii_digit() {
                    self.consume_numeric_literal()
                } else if is_alpha(c) {
                    self.consume_ident()
                } else {
                    self.advance(1);
                    self.set_error(start, self.pos, "unexpected character".to_string())
                }
            }
        }
    }
}

// BinaryOpInfo
#[derive(Debug, Clone, Copy)]
pub struct BinaryOpInfo {
    pub precedence: u8,
    pub name: &'static str,
    pub kind: TokenKind,
}

pub const OP_LOGICAL_OR: BinaryOpInfo = BinaryOpInfo {
    precedence: 1,
    name: operators::LOGICAL_OR,
    kind: TokenKind::TokLogicalOr,
};
pub const OP_LOGICAL_AND: BinaryOpInfo = BinaryOpInfo {
    precedence: 2,
    name: operators::LOGICAL_AND,
    kind: TokenKind::TokLogicalAnd,
};
pub const OP_LESS: BinaryOpInfo = BinaryOpInfo {
    precedence: 3,
    name: operators::LESS,
    kind: TokenKind::TokLess,
};
pub const OP_LESS_EQUAL: BinaryOpInfo = BinaryOpInfo {
    precedence: 3,
    name: operators::LESS_EQUALS,
    kind: TokenKind::TokLessEqual,
};
pub const OP_GREATER: BinaryOpInfo = BinaryOpInfo {
    precedence: 3,
    name: operators::GREATER,
    kind: TokenKind::TokGreater,
};
pub const OP_GREATER_EQUAL: BinaryOpInfo = BinaryOpInfo {
    precedence: 3,
    name: operators::GREATER_EQUALS,
    kind: TokenKind::TokGreaterEqual,
};
pub const OP_EQUAL_EQUAL: BinaryOpInfo = BinaryOpInfo {
    precedence: 3,
    name: operators::EQUALS,
    kind: TokenKind::TokEqualEqual,
};
pub const OP_EXCLAMATION_EQUAL: BinaryOpInfo = BinaryOpInfo {
    precedence: 3,
    name: operators::NOT_EQUALS,
    kind: TokenKind::TokExclamationEqual,
};
pub const OP_IN: BinaryOpInfo = BinaryOpInfo {
    precedence: 3,
    name: operators::IN,
    kind: TokenKind::TokIn,
};
pub const OP_PLUS: BinaryOpInfo = BinaryOpInfo {
    precedence: 4,
    name: operators::ADD,
    kind: TokenKind::TokPlus,
};
pub const OP_MINUS: BinaryOpInfo = BinaryOpInfo {
    precedence: 4,
    name: operators::SUBSTRACT,
    kind: TokenKind::TokMinus,
};
pub const OP_ASTERISK: BinaryOpInfo = BinaryOpInfo {
    precedence: 5,
    name: operators::MULTIPLY,
    kind: TokenKind::TokAsterisk,
};
pub const OP_SLASH: BinaryOpInfo = BinaryOpInfo {
    precedence: 5,
    name: operators::DIVIDE,
    kind: TokenKind::TokSlash,
};
pub const OP_PERCENT: BinaryOpInfo = BinaryOpInfo {
    precedence: 5,
    name: operators::MODULO,
    kind: TokenKind::TokPercent,
};
pub const OP_DEFAULT: BinaryOpInfo = BinaryOpInfo {
    precedence: 0,
    name: "",
    kind: TokenKind::TokError,
};

pub fn get_binary_op_info(kind: TokenKind) -> BinaryOpInfo {
    match kind {
        TokenKind::TokLogicalOr => OP_LOGICAL_OR,
        TokenKind::TokLogicalAnd => OP_LOGICAL_AND,
        TokenKind::TokLess => OP_LESS,
        TokenKind::TokLessEqual => OP_LESS_EQUAL,
        TokenKind::TokGreater => OP_GREATER,
        TokenKind::TokGreaterEqual => OP_GREATER_EQUAL,
        TokenKind::TokEqualEqual => OP_EQUAL_EQUAL,
        TokenKind::TokExclamationEqual => OP_EXCLAMATION_EQUAL,
        TokenKind::TokIn => OP_IN,
        TokenKind::TokPlus => OP_PLUS,
        TokenKind::TokMinus => OP_MINUS,
        TokenKind::TokAsterisk => OP_ASTERISK,
        TokenKind::TokSlash => OP_SLASH,
        TokenKind::TokPercent => OP_PERCENT,
        _ => OP_DEFAULT,
    }
}

// Unescape helper
fn unescape_string(value: &str) -> Result<String, String> {
    let bytes = unescape(value, false)?;
    String::from_utf8(bytes).map_err(|_| "invalid unicode code point".to_string())
}

fn unescape_bytes(mut value: &str) -> Result<Vec<u8>, String> {
    if value.starts_with('b') || value.starts_with('B') {
        value = &value[1..];
    } else if value.starts_with("rb")
        || value.starts_with("RB")
        || value.starts_with("rB")
        || value.starts_with("Rb")
    {
        let mut s = String::from("r");
        s.push_str(&value[2..]);
        return unescape(&s, true);
    } else if value.starts_with("br")
        || value.starts_with("BR")
        || value.starts_with("bR")
        || value.starts_with("Br")
    {
        value = &value[1..];
    }
    unescape(value, true)
}

fn unescape(value: &str, is_bytes: bool) -> Result<Vec<u8>, String> {
    let normalized = value.replace("\r\n", "\n").replace('\r', "\n");
    let mut val = normalized.as_str();
    if val.len() < 2 {
        return Err("unable to unescape string".to_string());
    }
    let is_raw = if val.starts_with('r') || val.starts_with('R') {
        val = &val[1..];
        true
    } else {
        false
    };
    if val.len() < 2 {
        return Err("unable to unescape string".to_string());
    }
    let first = val.chars().next().unwrap();
    let last = val.chars().last().unwrap();
    if first != last || (first != '"' && first != '\'') {
        return Err("unable to unescape string".to_string());
    }
    if val.len() >= 6 {
        if val.starts_with("'''") {
            if !val.ends_with("'''") {
                return Err("unable to unescape string".to_string());
            }
            val = &val[3..val.len() - 3];
        } else if val.starts_with("\"\"\"") {
            if !val.ends_with("\"\"\"") {
                return Err("unable to unescape string".to_string());
            }
            val = &val[3..val.len() - 3];
        } else {
            val = &val[1..val.len() - 1];
        }
    } else {
        val = &val[1..val.len() - 1];
    }
    if is_raw || !val.contains('\\') {
        return Ok(val.as_bytes().to_vec());
    }

    let mut buf = Vec::with_capacity(val.len());
    let mut chars = val.char_indices().peekable();
    while let Some((_, c)) = chars.next() {
        if c != '\\' {
            let mut b = [0u8; 4];
            let s = c.encode_utf8(&mut b);
            buf.extend_from_slice(s.as_bytes());
            continue;
        }
        let (_, next_c) = match chars.next() {
            Some(p) => p,
            None => {
                return Err("unable to unescape string, found '\\' as last character".to_string())
            }
        };
        match next_c {
            'a' => buf.push(0x07),
            'b' => buf.push(0x08),
            'f' => buf.push(0x0C),
            'n' => buf.push(b'\n'),
            'r' => buf.push(b'\r'),
            't' => buf.push(b'\t'),
            'v' => buf.push(0x0B),
            '\\' => buf.push(b'\\'),
            '\'' => buf.push(b'\''),
            '"' => buf.push(b'"'),
            '`' => buf.push(b'`'),
            '?' => buf.push(b'?'),
            'x' | 'X' | 'u' | 'U' => {
                let n = match next_c {
                    'x' | 'X' => 2,
                    'u' => {
                        if is_bytes {
                            return Err("unable to unescape string".to_string());
                        }
                        4
                    }
                    'U' => {
                        if is_bytes {
                            return Err("unable to unescape string".to_string());
                        }
                        8
                    }
                    _ => unreachable!(),
                };
                let mut v: u32 = 0;
                for _ in 0..n {
                    let (_, hex_c) = match chars.next() {
                        Some(p) => p,
                        None => return Err("unable to unescape string".to_string()),
                    };
                    let digit = hex_c
                        .to_digit(16)
                        .ok_or_else(|| "unable to unescape string".to_string())?;
                    v = (v << 4) | digit;
                }
                if is_bytes && (next_c == 'x' || next_c == 'X') {
                    buf.push(v as u8);
                } else {
                    let ch = char::from_u32(v)
                        .ok_or_else(|| "invalid unicode code point".to_string())?;
                    let mut b = [0u8; 4];
                    let s = ch.encode_utf8(&mut b);
                    buf.extend_from_slice(s.as_bytes());
                }
            }
            '0'..='3' => {
                let mut v = (next_c as u32) - ('0' as u32);
                for _ in 0..2 {
                    let (_, oct_c) = match chars.next() {
                        Some(p) => p,
                        None => {
                            return Err("unable to unescape octal sequence in string".to_string())
                        }
                    };
                    if !('0'..='7').contains(&oct_c) {
                        return Err("unable to unescape octal sequence in string".to_string());
                    }
                    v = v * 8 + (oct_c as u32 - '0' as u32);
                }
                if is_bytes {
                    buf.push(v as u8);
                } else {
                    let ch = char::from_u32(v)
                        .ok_or_else(|| "invalid unicode code point".to_string())?;
                    let mut b = [0u8; 4];
                    let s = ch.encode_utf8(&mut b);
                    buf.extend_from_slice(s.as_bytes());
                }
            }
            _ => return Err("unable to unescape string".to_string()),
        }
    }
    Ok(buf)
}

fn pos_for_offset(source: &str, start: usize) -> (isize, isize) {
    let start = start as isize;
    let mut offset = 0;
    let mut line = 0;
    for l in source.split_inclusive('\n') {
        line += 1;
        offset += l.len() as isize;
        if start < offset {
            return (line, start + (l.len() as isize) - offset + 1);
        }
    }
    if line == 0 {
        (1, 1)
    } else {
        let last_line_len = source.lines().last().map_or(0, |l| l.len() as isize);
        (line, last_line_len + 1)
    }
}

struct PrattLogicManager {
    function: String,
    terms: Vec<IdedExpr>,
    ops: Vec<u64>,
    variadic_asts: bool,
}

impl PrattLogicManager {
    fn new_balancing(func: &str, term: IdedExpr) -> Self {
        Self {
            function: func.to_string(),
            terms: vec![term],
            ops: vec![],
            variadic_asts: false,
        }
    }

    fn new_variadic(func: &str, term: IdedExpr) -> Self {
        Self {
            function: func.to_string(),
            terms: vec![term],
            ops: vec![],
            variadic_asts: true,
        }
    }

    fn add_term(&mut self, op_id: u64, expr: IdedExpr) {
        self.terms.push(expr);
        self.ops.push(op_id);
    }

    fn into_expr(mut self) -> IdedExpr {
        if self.terms.len() == 1 {
            self.terms.pop().expect("expected at least one term")
        } else if self.variadic_asts {
            IdedExpr {
                id: self.ops[0],
                expr: Expr::Call(CallExpr {
                    target: None,
                    func_name: self.function,
                    args: self.terms,
                }),
            }
        } else {
            self.balanced_tree(0, self.ops.len() - 1)
        }
    }

    fn balanced_tree(&mut self, lo: usize, hi: usize) -> IdedExpr {
        let mid = (lo + hi).div_ceil(2);

        let left = if mid == lo {
            mem::take(&mut self.terms[mid])
        } else {
            self.balanced_tree(lo, mid - 1)
        };

        let right = if mid == hi {
            mem::take(&mut self.terms[mid + 1])
        } else {
            self.balanced_tree(mid + 1, hi)
        };

        IdedExpr {
            id: self.ops[mid],
            expr: Expr::Call(CallExpr {
                target: None,
                func_name: self.function.clone(),
                args: vec![left, right],
            }),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PrattParser {
    pub max_recursion_depth: u16,
    pub error_recovery_limit: u32,
    pub error_reporting_limit: u32,
    pub max_expression_node_count: usize,
    pub enable_optional_syntax: bool,
    pub enable_variadic_operator_asts: bool,
    pub enable_ident_escape_syntax: bool,
    pub populate_macro_calls: bool,
    macros: Arc<Macros>,
}

impl Default for PrattParser {
    fn default() -> Self {
        Self {
            max_recursion_depth: 96,
            error_recovery_limit: 30,
            error_reporting_limit: 100,
            max_expression_node_count: usize::MAX,
            enable_optional_syntax: false,
            enable_variadic_operator_asts: false,
            enable_ident_escape_syntax: false,
            populate_macro_calls: false,
            macros: Macros::standard(),
        }
    }
}

impl PrattParser {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn max_recursion_depth(mut self, max: u16) -> Self {
        self.max_recursion_depth = max;
        self
    }

    pub fn error_recovery_limit(mut self, limit: u32) -> Self {
        self.error_recovery_limit = limit;
        self
    }

    pub fn error_reporting_limit(mut self, limit: u32) -> Self {
        self.error_reporting_limit = limit;
        self
    }

    pub fn max_expression_node_count(mut self, limit: usize) -> Self {
        self.max_expression_node_count = limit;
        self
    }

    pub fn enable_optional_syntax(mut self, enable: bool) -> Self {
        self.enable_optional_syntax = enable;
        self
    }

    pub fn enable_variadic_operator_asts(mut self, enable: bool) -> Self {
        self.enable_variadic_operator_asts = enable;
        self
    }

    pub fn enable_ident_escape_syntax(mut self, enable: bool) -> Self {
        self.enable_ident_escape_syntax = enable;
        self
    }

    pub fn populate_macro_calls(mut self, populate: bool) -> Self {
        self.populate_macro_calls = populate;
        self
    }

    pub fn parse(self, source: &str) -> Result<IdedExpr, ParseErrors> {
        let mut worker = PrattParserWorker::new(self, source);
        worker.parse()
    }
}

struct PrattParserWorker<'a> {
    source: &'a str,
    length: usize,
    helper: ParserHelper,
    errors: Vec<ParseError>,
    macros: Arc<Macros>,
    lexer: Lexer<'a>,
    curr_tok: Token,
    peek_tok: Token,
    recursion_depth: u16,
    recursion_limit_exceeded: bool,
    error_count: u32,
    max_recursion_depth: u16,
    max_expression_node_count: usize,
    error_reporting_limit: u32,
    error_recovery_limit: u32,
    enable_optional_syntax: bool,
    enable_variadic_operator_asts: bool,
    enable_ident_escape_syntax: bool,
}

impl<'a> PrattParserWorker<'a> {
    fn new(parser: PrattParser, source: &'a str) -> Self {
        let mut helper = ParserHelper::default();
        helper.source_info.source = source.to_string();
        Self {
            source,
            length: source.len(),
            helper,
            errors: Vec::new(),
            macros: parser.macros,
            lexer: Lexer::new(source),
            curr_tok: Token::default(),
            peek_tok: Token::default(),
            recursion_depth: 0,
            recursion_limit_exceeded: false,
            error_count: 0,
            max_recursion_depth: parser.max_recursion_depth,
            max_expression_node_count: parser.max_expression_node_count,
            error_reporting_limit: parser.error_reporting_limit,
            error_recovery_limit: parser.error_recovery_limit,
            enable_optional_syntax: parser.enable_optional_syntax,
            enable_variadic_operator_asts: parser.enable_variadic_operator_asts,
            enable_ident_escape_syntax: parser.enable_ident_escape_syntax,
        }
    }

    fn parse(&mut self) -> Result<IdedExpr, ParseErrors> {
        self.curr_tok = Token::default();
        self.peek_tok = self.next_significant_token(true);
        let out = self.parse_expr();
        if !self.recursion_limit_exceeded
            && !self.is_recovery_limit_exceeded()
            && self.peek_tok.kind != TokenKind::TokEnd
        {
            if self.peek_tok.kind != TokenKind::TokError {
                let peek = self.peek_tok;
                let text = self.token_text(&peek);
                let err_msg = format!("Syntax error: mismatched input '{text}' expecting <EOF>");
                self.report_error(&peek, err_msg);
            }
            while self.peek_tok.kind != TokenKind::TokEnd && !self.is_recovery_limit_exceeded() {
                self.next_token();
            }
        }
        if self.is_recovery_limit_exceeded() {
            let msg = format!(
                "error recovery attempt limit exceeded: {}",
                self.error_recovery_limit
            );
            self.errors.push(ParseError {
                source: None,
                pos: (0, 0),
                msg,
                expr_id: 0,
                source_info: None,
            });
        }
        self.errors.sort_by_key(|a| a.pos);
        if self.errors.is_empty() {
            Ok(out)
        } else {
            let source_info: Arc<SourceInfo> = Arc::new(mem::take(&mut self.helper.source_info));
            for err in &mut self.errors {
                if err.source_info.is_none() && err.pos.0 > 0 {
                    err.source_info = Some(source_info.clone());
                }
            }
            Err(ParseErrors {
                errors: mem::take(&mut self.errors),
            })
        }
    }

    fn is_recovery_limit_exceeded(&self) -> bool {
        self.error_count > self.error_recovery_limit
    }

    fn next_significant_token(&mut self, report_error: bool) -> Token {
        if self.is_recovery_limit_exceeded() {
            return Token {
                kind: TokenKind::TokEnd,
                start: self.length,
                end: self.length,
            };
        }
        loop {
            let tok = self.lexer.lex();
            if tok.kind == TokenKind::TokWhitespace || tok.kind == TokenKind::TokComment {
                continue;
            }
            if tok.kind == TokenKind::TokError && report_error {
                let err_msg = self
                    .lexer
                    .get_error()
                    .map(|e| e.message.clone())
                    .unwrap_or_else(|| "token recognition error".to_string());
                self.report_error(&tok, err_msg);
                if self.is_recovery_limit_exceeded() {
                    return Token {
                        kind: TokenKind::TokEnd,
                        start: self.length,
                        end: self.length,
                    };
                }
            }
            return tok;
        }
    }

    fn next_token(&mut self) -> Token {
        self.curr_tok = self.peek_tok;
        if self.is_recovery_limit_exceeded() {
            self.peek_tok = Token {
                kind: TokenKind::TokEnd,
                start: self.length,
                end: self.length,
            };
            return self.curr_tok;
        }
        if self.peek_tok.kind != TokenKind::TokEnd {
            self.peek_tok = self.next_significant_token(true);
        }
        self.curr_tok
    }

    fn token_text(&self, tok: &Token) -> &'a str {
        if tok.start <= self.length && tok.end <= self.length && tok.start <= tok.end {
            &self.source[tok.start..tok.end]
        } else {
            ""
        }
    }

    fn next_id(&mut self, tok: &Token) -> u64 {
        let id = self.helper.next_id;
        self.helper
            .source_info
            .add_offset(id, tok.start as u32, tok.end as u32);
        self.helper.next_id += 1;
        id
    }

    fn next_id_for_offsets(&mut self, start: u32, stop: u32) -> u64 {
        let id = self.helper.next_id;
        self.helper.source_info.add_offset(id, start, stop);
        self.helper.next_id += 1;
        id
    }

    fn expect(&mut self, kind: TokenKind, msg: &str) -> bool {
        if self.peek_tok.kind == kind {
            self.next_token();
            return true;
        }
        if self.is_recovery_limit_exceeded() {
            return false;
        }
        if self.peek_tok.kind != TokenKind::TokError {
            let peek = self.peek_tok;
            let err_msg = if msg.is_empty() {
                let tok_text = self.token_text(&peek);
                let formatted_tok = if peek.kind == TokenKind::TokEnd {
                    "<EOF>".to_string()
                } else {
                    format!("'{tok_text}'")
                };
                format!(
                    "Syntax error: mismatched input {formatted_tok} expecting '{}'",
                    kind.as_str()
                )
            } else {
                msg.to_string()
            };
            self.report_error(&peek, err_msg);
        }

        self.synchronize_on_delimiter();
        false
    }

    fn synchronize_on_delimiter(&mut self) {
        if self.is_recovery_limit_exceeded() {
            self.peek_tok = Token {
                kind: TokenKind::TokEnd,
                start: self.length,
                end: self.length,
            };
            return;
        }
        while self.peek_tok.kind != TokenKind::TokEnd {
            if matches!(
                self.peek_tok.kind,
                TokenKind::TokComma
                    | TokenKind::TokRightParen
                    | TokenKind::TokRightBracket
                    | TokenKind::TokRightBrace
            ) {
                break;
            }
            self.next_token();
        }
    }

    fn report_error(&mut self, tok: &Token, msg: String) -> IdedExpr {
        let id = self.next_id(tok);
        if self.is_recovery_limit_exceeded() {
            return IdedExpr {
                id,
                expr: Expr::Unspecified,
            };
        }
        self.error_count += 1;
        let pos = pos_for_offset(self.source, tok.start);
        if self.error_count <= self.error_reporting_limit {
            self.errors.push(ParseError {
                source: None,
                pos,
                msg,
                expr_id: id,
                source_info: None,
            });
        }
        if self.is_recovery_limit_exceeded() {
            self.peek_tok = Token {
                kind: TokenKind::TokEnd,
                start: self.length,
                end: self.length,
            };
        }
        IdedExpr {
            id,
            expr: Expr::Unspecified,
        }
    }

    fn expand_macro(
        &mut self,
        id: u64,
        func_name: &str,
        mut target: Option<IdedExpr>,
        mut args: Vec<IdedExpr>,
    ) -> Option<IdedExpr> {
        if let Some(m) = self.macros.find(func_name, target.as_ref(), &args) {
            if self.helper.next_id as usize > self.max_expression_node_count {
                let pos = self.helper.source_info.pos_for(id).unwrap_or((1, 1));
                self.errors.push(ParseError {
                    source: None,
                    pos,
                    msg: format!(
                        "expression count exceeds limit of {} while expanding macro '{}'",
                        self.max_expression_node_count, func_name
                    ),
                    expr_id: id,
                    source_info: None,
                });
                return Some(IdedExpr::default());
            }
            let mut macro_helper = MacroExprHelper {
                helper: &mut self.helper,
                id,
            };
            match m.expand(&mut macro_helper, &mut target, &mut args) {
                Ok(expansion) => expansion,
                Err(err) => {
                    self.errors.push(err);
                    Some(IdedExpr::default())
                }
            }
        } else {
            None
        }
    }

    fn normalize_ident(&mut self, tok: &Token, allow_quoted: bool) -> String {
        let text = self.token_text(tok);
        if text.is_empty() {
            return String::new();
        }
        if text.starts_with('`') {
            if !allow_quoted {
                self.report_error(tok, "unexpected quoted identifier".to_string());
                return String::new();
            }
            if !self.enable_ident_escape_syntax {
                self.report_error(tok, "unsupported syntax: '`'".to_string());
            }
            if text.len() < 2 || !text.ends_with('`') {
                self.report_error(tok, "unterminated quoted identifier".to_string());
                return String::new();
            }
            let inner = &text[1..text.len() - 1];
            if inner.is_empty() {
                self.report_error(tok, "unexpected quoted identifier".to_string());
                return String::new();
            }
            for c in inner.chars() {
                if !c.is_ascii_alphanumeric()
                    && c != '_'
                    && c != '.'
                    && c != '-'
                    && c != '/'
                    && c != ' '
                {
                    self.report_error(tok, "unexpected quoted identifier".to_string());
                    return String::new();
                }
            }
            return inner.to_string();
        }
        text.to_string()
    }

    fn parse_expr(&mut self) -> IdedExpr {
        if self.recursion_limit_exceeded || self.is_recovery_limit_exceeded() {
            return IdedExpr::default();
        }
        if self.recursion_depth > self.max_recursion_depth {
            self.recursion_limit_exceeded = true;
            let msg = format!(
                "expression recursion limit exceeded: {}",
                self.max_recursion_depth
            );
            self.errors.push(ParseError {
                source: None,
                pos: (0, 0),
                msg,
                expr_id: 0,
                source_info: None,
            });
            return IdedExpr::default();
        }
        self.recursion_depth += 1;
        let expr = self.parse_binary_and_ternary(0);
        self.recursion_depth -= 1;
        expr
    }

    fn parse_binary_and_ternary(&mut self, min_prec: u8) -> IdedExpr {
        let mut lhs = self.parse_selector_chain();
        loop {
            let tok = self.peek_tok.kind;
            if tok == TokenKind::TokQuestion && min_prec == 0 {
                lhs = self.parse_ternary(lhs);
                continue;
            }

            let op_info = get_binary_op_info(tok);
            if op_info.kind == TokenKind::TokError || op_info.precedence < min_prec {
                break;
            }

            if op_info.name == operators::LOGICAL_OR || op_info.name == operators::LOGICAL_AND {
                lhs = self.parse_logical_chain(lhs, op_info);
                continue;
            }

            let op_tok = self.next_token();
            let op_id = self.next_id(&op_tok);
            let rhs = self.parse_binary_and_ternary(op_info.precedence + 1);
            lhs = IdedExpr {
                id: op_id,
                expr: Expr::Call(CallExpr {
                    target: None,
                    func_name: op_info.name.to_string(),
                    args: vec![lhs, rhs],
                }),
            };
        }
        lhs
    }

    fn parse_ternary(&mut self, lhs: IdedExpr) -> IdedExpr {
        let q_tok = self.next_token();
        let op_id = self.next_id(&q_tok);
        let true_expr = self.parse_binary_and_ternary(1);
        if !self.expect(
            TokenKind::TokColon,
            "expected ':' in conditional expression",
        ) {
            return lhs;
        }
        let false_expr = self.parse_binary_and_ternary(0);
        IdedExpr {
            id: op_id,
            expr: Expr::Call(CallExpr {
                target: None,
                func_name: operators::CONDITIONAL.to_string(),
                args: vec![lhs, true_expr, false_expr],
            }),
        }
    }

    fn parse_logical_chain(&mut self, lhs: IdedExpr, op_info: BinaryOpInfo) -> IdedExpr {
        let mut l = if self.enable_variadic_operator_asts {
            PrattLogicManager::new_variadic(op_info.name, lhs)
        } else {
            PrattLogicManager::new_balancing(op_info.name, lhs)
        };
        while self.peek_tok.kind == op_info.kind {
            let op_tok = self.next_token();
            let rhs = self.parse_binary_and_ternary(op_info.precedence + 1);
            let op_id = self.next_id(&op_tok);
            l.add_term(op_id, rhs);
        }
        l.into_expr()
    }

    fn parse_selector_chain(&mut self) -> IdedExpr {
        let lhs = self.parse_unary();
        self.parse_selector_chain_tail(lhs)
    }

    fn parse_selector_chain_tail(&mut self, mut lhs: IdedExpr) -> IdedExpr {
        loop {
            match self.peek_tok.kind {
                TokenKind::TokDot => {
                    let dot_tok = self.next_token();
                    let mut optional = false;
                    if self.peek_tok.kind == TokenKind::TokQuestion {
                        self.next_token();
                        optional = true;
                        if !self.enable_optional_syntax {
                            self.report_error(&dot_tok, "unsupported syntax '.?'".to_string());
                        }
                    }
                    let field_tok = self.next_token();
                    if field_tok.kind != TokenKind::TokIdent
                        && field_tok.kind != TokenKind::TokReservedWord
                    {
                        if field_tok.kind != TokenKind::TokError {
                            self.report_error(
                                &field_tok,
                                "expected identifier after '.'".to_string(),
                            );
                        }
                        self.synchronize_on_delimiter();
                        return lhs;
                    }
                    let is_member_call = self.peek_tok.kind == TokenKind::TokLeftParen;
                    let field = self.normalize_ident(&field_tok, !is_member_call);
                    if optional {
                        let op_id = self.next_id(&dot_tok);
                        let field_id = self.next_id(&field_tok);
                        let str_expr = IdedExpr {
                            id: field_id,
                            expr: Expr::Literal(LiteralValue::String(field.into())),
                        };
                        lhs = IdedExpr {
                            id: op_id,
                            expr: Expr::Call(CallExpr {
                                target: None,
                                func_name: operators::OPT_SELECT.to_string(),
                                args: vec![lhs, str_expr],
                            }),
                        };
                    } else if is_member_call {
                        let lparen = self.next_token();
                        let call_id = self.next_id(&lparen);
                        let args = self.parse_arguments(TokenKind::TokRightParen);
                        if let Some(expr) =
                            self.expand_macro(call_id, &field, Some(lhs.clone()), args.clone())
                        {
                            lhs = expr;
                        } else {
                            lhs = IdedExpr {
                                id: call_id,
                                expr: Expr::Call(CallExpr {
                                    target: Some(Box::new(lhs)),
                                    func_name: field,
                                    args,
                                }),
                            };
                        }
                    } else {
                        let dot_id = self.next_id(&dot_tok);
                        lhs = IdedExpr {
                            id: dot_id,
                            expr: Expr::Select(SelectExpr {
                                operand: Box::new(lhs),
                                field,
                                test: false,
                            }),
                        };
                    }
                }
                TokenKind::TokLeftBracket => {
                    let bracket_tok = self.next_token();
                    let op_id = self.next_id(&bracket_tok);
                    let mut optional = false;
                    if self.peek_tok.kind == TokenKind::TokQuestion {
                        self.next_token();
                        optional = true;
                        if !self.enable_optional_syntax {
                            self.report_error(&bracket_tok, "unsupported syntax '?'".to_string());
                        }
                    }
                    let index = self.parse_expr();
                    self.expect(TokenKind::TokRightBracket, "expected ']'");
                    let op_name = if optional {
                        operators::OPT_INDEX
                    } else {
                        operators::INDEX
                    };
                    lhs = IdedExpr {
                        id: op_id,
                        expr: Expr::Call(CallExpr {
                            target: None,
                            func_name: op_name.to_string(),
                            args: vec![lhs, index],
                        }),
                    };
                }
                TokenKind::TokLeftBrace => {
                    if let Some((start, stop)) = self.helper.source_info.offset_for(lhs.id) {
                        if let Some(struct_name) = self.extract_struct_name(&lhs) {
                            let obj_id = self.next_id_for_offsets(start, stop);
                            lhs = self.parse_struct(obj_id, struct_name);
                        } else {
                            return lhs;
                        }
                    } else {
                        return lhs;
                    }
                }
                _ => return lhs,
            }
        }
    }

    fn extract_struct_name(&mut self, expr: &IdedExpr) -> Option<String> {
        match &expr.expr {
            Expr::Ident(name) => Some(name.clone()),
            Expr::Select(sel) if !sel.test => {
                let prefix = self.extract_struct_name(&sel.operand)?;
                Some(format!("{}.{}", prefix, sel.field))
            }
            _ => None,
        }
    }

    fn parse_struct(&mut self, obj_id: u64, struct_name: String) -> IdedExpr {
        self.next_token(); // consumes {
        let mut fields = Vec::new();
        while self.peek_tok.kind != TokenKind::TokRightBrace
            && self.peek_tok.kind != TokenKind::TokEnd
        {
            let mut optional = false;
            if self.peek_tok.kind == TokenKind::TokQuestion {
                let q = self.next_token();
                optional = true;
                if !self.enable_optional_syntax {
                    self.report_error(&q, "unsupported syntax '?'".to_string());
                }
            }
            let field_tok = self.next_token();
            if field_tok.kind != TokenKind::TokIdent && field_tok.kind != TokenKind::TokReservedWord
            {
                self.report_error(&field_tok, "expected struct field name".to_string());
                self.synchronize_on_delimiter();
                break;
            }
            let field_name = self.normalize_ident(&field_tok, true);
            let colon_tok = self.peek_tok;
            if !self.expect(TokenKind::TokColon, "expected ':' in struct field") {
                break;
            }
            let field_id = self.next_id(&colon_tok);
            let val = self.parse_expr();
            fields.push(IdedEntryExpr {
                id: field_id,
                expr: EntryExpr::StructField(StructFieldExpr {
                    field: field_name,
                    value: val,
                    optional,
                }),
            });
            if self.peek_tok.kind == TokenKind::TokComma {
                self.next_token();
            } else {
                break;
            }
        }
        self.expect(TokenKind::TokRightBrace, "expected '}'");
        IdedExpr {
            id: obj_id,
            expr: Expr::Struct(StructExpr {
                type_name: struct_name,
                entries: fields,
            }),
        }
    }

    fn parse_unary(&mut self) -> IdedExpr {
        let tok = self.peek_tok.kind;
        if tok == TokenKind::TokExclamation || tok == TokenKind::TokMinus {
            self.parse_unary_ops()
        } else {
            self.parse_primary()
        }
    }

    fn parse_unary_ops(&mut self) -> IdedExpr {
        let op = self.next_token();
        if self.peek_tok.kind == TokenKind::TokExclamation
            || self.peek_tok.kind == TokenKind::TokMinus
        {
            return self.parse_unary_ops_chain(op);
        }

        let op_id = self.next_id(&op);
        if op.kind == TokenKind::TokMinus {
            if self.peek_tok.kind == TokenKind::TokInt {
                return self.parse_negative_int_literal(op_id);
            }
            if self.peek_tok.kind == TokenKind::TokFloat {
                return self.parse_negative_double_literal(op_id);
            }
            let operand = self.parse_selector_chain();
            IdedExpr {
                id: op_id,
                expr: Expr::Call(CallExpr {
                    target: None,
                    func_name: operators::NEGATE.to_string(),
                    args: vec![operand],
                }),
            }
        } else {
            let operand = self.parse_selector_chain();
            IdedExpr {
                id: op_id,
                expr: Expr::Call(CallExpr {
                    target: None,
                    func_name: operators::LOGICAL_NOT.to_string(),
                    args: vec![operand],
                }),
            }
        }
    }

    fn parse_unary_ops_chain(&mut self, first_op: Token) -> IdedExpr {
        struct UnaryOpInfo {
            kind: TokenKind,
            id: u64,
        }
        let first_id = self.next_id(&first_op);
        let mut raw_ops = vec![UnaryOpInfo {
            kind: first_op.kind,
            id: first_id,
        }];

        while self.peek_tok.kind == TokenKind::TokExclamation
            || self.peek_tok.kind == TokenKind::TokMinus
        {
            let op = self.next_token();
            let id = self.next_id(&op);
            raw_ops.push(UnaryOpInfo { kind: op.kind, id });
        }

        let mut ops: Vec<UnaryOpInfo> = Vec::new();
        for op in raw_ops {
            if let Some(last) = ops.last() {
                if last.kind == op.kind {
                    ops.pop();
                    continue;
                }
            }
            ops.push(op);
        }

        let mut operand = self.parse_selector_chain();

        for op in ops.into_iter().rev() {
            let func_name = if op.kind == TokenKind::TokMinus {
                operators::NEGATE.to_string()
            } else {
                operators::LOGICAL_NOT.to_string()
            };
            operand = IdedExpr {
                id: op.id,
                expr: Expr::Call(CallExpr {
                    target: None,
                    func_name,
                    args: vec![operand],
                }),
            };
        }
        operand
    }

    fn count_grouping_parentheses(&mut self) -> usize {
        if self.peek_tok.kind != TokenKind::TokLeftParen {
            return 0;
        }
        let saved = self.lexer.save_position();

        let mut leading_open_parens = 1;
        let mut tok = self.next_significant_token(false);
        while tok.kind == TokenKind::TokLeftParen {
            leading_open_parens += 1;
            tok = self.next_significant_token(false);
        }
        if leading_open_parens == 1 {
            self.lexer.restore_position(saved);
            return 1;
        }
        let mut open_parens = leading_open_parens;
        let mut consecutive_leading_closed = 0;
        while open_parens > 0 {
            if tok.kind == TokenKind::TokEnd || tok.kind == TokenKind::TokError {
                self.lexer.restore_position(saved);
                return 1;
            }
            match tok.kind {
                TokenKind::TokLeftParen => {
                    open_parens += 1;
                    consecutive_leading_closed = 0;
                }
                TokenKind::TokRightParen => {
                    if leading_open_parens == open_parens {
                        leading_open_parens -= 1;
                        consecutive_leading_closed += 1;
                    } else {
                        consecutive_leading_closed = 0;
                    }
                    open_parens -= 1;
                }
                _ => {
                    consecutive_leading_closed = 0;
                }
            }
            if open_parens > 0 {
                tok = self.next_significant_token(false);
            }
        }
        self.lexer.restore_position(saved);
        if consecutive_leading_closed > 1 {
            consecutive_leading_closed
        } else {
            1
        }
    }

    fn parse_primary(&mut self) -> IdedExpr {
        match self.peek_tok.kind {
            TokenKind::TokLeftParen => {
                let grouping_count = self.count_grouping_parentheses();
                for _ in 0..grouping_count {
                    self.next_token();
                }
                let expr = self.parse_expr();
                for _ in 0..grouping_count {
                    self.expect(TokenKind::TokRightParen, "expected ')'");
                }
                expr
            }
            TokenKind::TokNull => {
                let tok = self.next_token();
                let id = self.next_id(&tok);
                IdedExpr {
                    id,
                    expr: Expr::Literal(LiteralValue::Null),
                }
            }
            TokenKind::TokTrue => {
                let tok = self.next_token();
                let id = self.next_id(&tok);
                IdedExpr {
                    id,
                    expr: Expr::Literal(LiteralValue::Boolean(true.into())),
                }
            }
            TokenKind::TokFalse => {
                let tok = self.next_token();
                let id = self.next_id(&tok);
                IdedExpr {
                    id,
                    expr: Expr::Literal(LiteralValue::Boolean(false.into())),
                }
            }
            TokenKind::TokInt => self.parse_int_literal(),
            TokenKind::TokUint => self.parse_uint_literal(),
            TokenKind::TokFloat => self.parse_double_literal(),
            TokenKind::TokString => self.parse_string_literal(),
            TokenKind::TokBytes => self.parse_bytes_literal(),
            TokenKind::TokLeftBracket => self.parse_list(),
            TokenKind::TokLeftBrace => self.parse_map(),
            TokenKind::TokDot | TokenKind::TokIdent | TokenKind::TokReservedWord => {
                self.parse_ident_or_call()
            }
            _ => {
                let bad_tok = self.next_token();
                if bad_tok.kind != TokenKind::TokError {
                    if bad_tok.kind == TokenKind::TokEnd {
                        self.report_error(
                            &bad_tok,
                            "Syntax error: mismatched input '<EOF>' expecting expression"
                                .to_string(),
                        );
                    } else {
                        self.report_error(&bad_tok, "unexpected token".to_string());
                    }
                }
                IdedExpr {
                    id: self.next_id(&bad_tok),
                    expr: Expr::Unspecified,
                }
            }
        }
    }

    fn parse_list(&mut self) -> IdedExpr {
        let open_tok = self.next_token();
        let list_id = self.next_id(&open_tok);
        let mut elems = Vec::new();
        let mut optionals = Vec::new();
        while self.peek_tok.kind != TokenKind::TokRightBracket
            && self.peek_tok.kind != TokenKind::TokEnd
        {
            let mut optional = false;
            if self.peek_tok.kind == TokenKind::TokQuestion {
                let q = self.next_token();
                optional = true;
                if !self.enable_optional_syntax {
                    self.report_error(&q, "unsupported syntax '?'".to_string());
                }
            }
            if optional {
                optionals.push(elems.len());
            }
            let elem = self.parse_expr();
            elems.push(elem);
            if self.peek_tok.kind == TokenKind::TokComma {
                self.next_token();
                if self.peek_tok.kind == TokenKind::TokRightBracket {
                    break;
                }
                continue;
            }
            break;
        }
        self.expect(TokenKind::TokRightBracket, "expected ']'");
        IdedExpr {
            id: list_id,
            expr: Expr::List(ListExpr {
                elements: elems,
                optional_indices: optionals,
            }),
        }
    }

    fn parse_map(&mut self) -> IdedExpr {
        let open_tok = self.next_token();
        let map_id = self.next_id(&open_tok);
        let mut entries = Vec::new();
        while self.peek_tok.kind != TokenKind::TokRightBrace
            && self.peek_tok.kind != TokenKind::TokEnd
        {
            let mut optional = false;
            if self.peek_tok.kind == TokenKind::TokQuestion {
                let q = self.next_token();
                optional = true;
                if !self.enable_optional_syntax {
                    self.report_error(&q, "unsupported syntax '?'".to_string());
                }
            }
            let key = self.parse_expr();
            let colon_tok = self.peek_tok;
            if !self.expect(TokenKind::TokColon, "expected ':' in map entry") {
                break;
            }
            let entry_id = self.next_id(&colon_tok);
            let val = self.parse_expr();
            entries.push(IdedEntryExpr {
                id: entry_id,
                expr: EntryExpr::MapEntry(MapEntryExpr {
                    key,
                    value: val,
                    optional,
                }),
            });
            if self.peek_tok.kind == TokenKind::TokComma {
                self.next_token();
                if self.peek_tok.kind == TokenKind::TokRightBrace {
                    break;
                }
                continue;
            }
            break;
        }
        self.expect(TokenKind::TokRightBrace, "expected '}'");
        IdedExpr {
            id: map_id,
            expr: Expr::Map(MapExpr { entries }),
        }
    }

    fn parse_ident_or_call(&mut self) -> IdedExpr {
        let mut leading_dot = false;
        let first_tok = self.peek_tok;
        if self.peek_tok.kind == TokenKind::TokDot {
            self.next_token();
            leading_dot = true;
        }
        let id_tok = self.next_token();
        if id_tok.kind != TokenKind::TokIdent && id_tok.kind != TokenKind::TokReservedWord {
            if id_tok.kind != TokenKind::TokError {
                self.report_error(&id_tok, "expected identifier".to_string());
            }
            return IdedExpr {
                id: self.next_id(&id_tok),
                expr: Expr::Unspecified,
            };
        }
        let id_text = self.normalize_ident(&id_tok, false);
        if id_tok.kind == TokenKind::TokReservedWord && RESERVED_IDS.contains(&id_text.as_str()) {
            self.report_error(&id_tok, format!("reserved identifier: {id_text}"));
        }
        let mut name = id_text;
        if leading_dot {
            name = format!(".{name}");
        }
        let id = self.next_id(&first_tok);
        if self.peek_tok.kind == TokenKind::TokLeftParen {
            self.next_token();
            let args = self.parse_arguments(TokenKind::TokRightParen);
            if let Some(expr) = self.expand_macro(id, &name, None, args.clone()) {
                return expr;
            }
            return IdedExpr {
                id,
                expr: Expr::Call(CallExpr {
                    target: None,
                    func_name: name,
                    args,
                }),
            };
        }
        IdedExpr {
            id,
            expr: Expr::Ident(name),
        }
    }

    fn parse_arguments(&mut self, close_tok: TokenKind) -> Vec<IdedExpr> {
        let mut args = Vec::new();
        if self.peek_tok.kind != close_tok && self.peek_tok.kind != TokenKind::TokEnd {
            loop {
                args.push(self.parse_expr());
                if self.peek_tok.kind == TokenKind::TokComma {
                    self.next_token();
                    if self.peek_tok.kind == close_tok {
                        let peek = self.peek_tok;
                        self.report_error(&peek, "unexpected token".to_string());
                        break;
                    }
                    continue;
                }
                break;
            }
        }
        self.expect(close_tok, "");
        args
    }

    fn parse_int_literal(&mut self) -> IdedExpr {
        let tok = self.next_token();
        let id = self.next_id(&tok);
        let text = self.token_text(&tok);
        let val = if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
            i64::from_str_radix(hex, 16)
        } else {
            text.parse::<i64>()
        };
        match val {
            Ok(v) => IdedExpr {
                id,
                expr: Expr::Literal(LiteralValue::Int(v.into())),
            },
            Err(_) => self.report_error(&tok, "invalid int literal".to_string()),
        }
    }

    fn parse_negative_int_literal(&mut self, op_id: u64) -> IdedExpr {
        let tok = self.next_token();
        let text = self.token_text(&tok);
        let val = if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
            i64::from_str_radix(hex, 16).map(|v| -v)
        } else {
            format!("-{text}").parse::<i64>()
        };
        match val {
            Ok(v) => IdedExpr {
                id: op_id,
                expr: Expr::Literal(LiteralValue::Int(v.into())),
            },
            Err(_) => self.report_error(&tok, "invalid int literal".to_string()),
        }
    }

    fn parse_uint_literal(&mut self) -> IdedExpr {
        let tok = self.next_token();
        let id = self.next_id(&tok);
        let text = self.token_text(&tok);
        let text = &text[..text.len() - 1]; // strip 'u' / 'U'
        let val = if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
            u64::from_str_radix(hex, 16)
        } else {
            text.parse::<u64>()
        };
        match val {
            Ok(v) => IdedExpr {
                id,
                expr: Expr::Literal(LiteralValue::UInt(v.into())),
            },
            Err(_) => self.report_error(&tok, "invalid uint literal".to_string()),
        }
    }

    fn parse_double_literal(&mut self) -> IdedExpr {
        let tok = self.next_token();
        let id = self.next_id(&tok);
        let text = self.token_text(&tok);
        match text.parse::<f64>() {
            Ok(v) if v.is_finite() => IdedExpr {
                id,
                expr: Expr::Literal(LiteralValue::Double(v.into())),
            },
            _ => self.report_error(&tok, "invalid double literal".to_string()),
        }
    }

    fn parse_negative_double_literal(&mut self, op_id: u64) -> IdedExpr {
        let tok = self.next_token();
        let text = self.token_text(&tok);
        match text.parse::<f64>() {
            Ok(v) if v.is_finite() => IdedExpr {
                id: op_id,
                expr: Expr::Literal(LiteralValue::Double((-v).into())),
            },
            _ => self.report_error(&tok, "invalid double literal".to_string()),
        }
    }

    fn parse_string_literal(&mut self) -> IdedExpr {
        let tok = self.next_token();
        let id = self.next_id(&tok);
        let text = self.token_text(&tok);
        match unescape_string(text) {
            Ok(unescaped) => IdedExpr {
                id,
                expr: Expr::Literal(LiteralValue::String(unescaped.into())),
            },
            Err(e) => self.report_error(&tok, e),
        }
    }

    fn parse_bytes_literal(&mut self) -> IdedExpr {
        let tok = self.next_token();
        let id = self.next_id(&tok);
        let text = self.token_text(&tok);
        match unescape_bytes(text) {
            Ok(unescaped) => IdedExpr {
                id,
                expr: Expr::Literal(LiteralValue::Bytes(unescaped.into())),
            },
            Err(e) => self.report_error(&tok, e),
        }
    }
}
