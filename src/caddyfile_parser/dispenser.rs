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

// Ported from Go caddyfile Dispenser

use anyhow::Error;
use serde_json::Value;
use std::collections::HashMap;

// Import Token from the lexer module
// Note: Token is expected to have fields:
// file: String, line: usize, text: String, was_quoted: bool, quote_kind: Option<char>,
// heredoc_marker: String, imports: Vec<String>, snippet_name: String
// and methods/fields: num_line_breaks, is_open_curly_brace, is_close_curly_brace, is_next_on_new_line(&Token)
use crate::caddyfile_lexer::Token;

/// Dispenser is a type that dispenses tokens, similarly to a lexer,
/// except that it can do so with some notion of structure. An empty
/// Dispenser is invalid; call new to make a proper instance.
pub struct Dispenser {
    pub(crate) tokens: Vec<Token>,
    pub(crate) cursor: isize,
    pub(crate) nesting: isize,
    // A map of arbitrary context data that can be used
    // to pass through some information to unmarshalers.
    context: HashMap<String, serde_json::Value>,
}

impl Dispenser {
    /// NewDispenser returns a Dispenser filled with the given tokens.
    pub fn new(tokens: Vec<Token>) -> Self {
        Self {
            tokens,
            cursor: -1,
            nesting: 0,
            context: HashMap::new(),
        }
    }

    /// Next loads the next token. Returns true if a token
    /// was loaded; false otherwise. If false, all tokens
    /// have been consumed.
    // This Go-compatible cursor advance returns bool, not an Iterator item.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> bool {
        if self.cursor < (self.tokens.len() as isize) - 1 {
            self.cursor += 1;
            true
        } else {
            false
        }
    }

    /// Prev moves to the previous token. It does the inverse
    /// of Next(), except this function may decrement the cursor
    /// to -1 so that the next call to Next() points to the
    /// first token; this allows dispensing to "start over". This
    /// method returns true if the cursor ends up pointing to a
    /// valid token.
    pub fn prev(&mut self) -> bool {
        if self.cursor > -1 {
            self.cursor -= 1;
            self.cursor > -1
        } else {
            false
        }
    }

    /// NextArg loads the next token if it is on the same
    /// line and if it is not a block opening (unquoted
    /// open curly brace; a quoted brace is a regular
    /// argument). Returns true if an argument token was
    /// loaded; false otherwise. If false, all tokens on
    /// the line have been consumed except for potentially
    /// a block opening. It handles imported tokens
    /// correctly.
    pub fn next_arg(&mut self) -> bool {
        if !self.next_on_same_line() {
            return false;
        }
        if self.token().is_open_curly_brace() {
            // roll back; a block opening is not an argument
            self.cursor -= 1;
            return false;
        }
        true
    }

    /// nextOnSameLine advances the cursor if the next
    /// token is on the same line of the same file.
    pub(crate) fn next_on_same_line(&mut self) -> bool {
        if self.cursor < 0 {
            self.cursor += 1;
            return true;
        }
        if self.cursor >= (self.tokens.len() as isize) - 1 {
            return false;
        }
        let curr = &self.tokens[self.cursor as usize];
        let next = &self.tokens[(self.cursor + 1) as usize];
        if !curr.is_next_on_new_line(next) {
            self.cursor += 1;
            return true;
        }
        false
    }

    /// NextLine loads the next token only if it is not on the same
    /// line as the current token, and returns true if a token was
    /// loaded; false otherwise. If false, there is not another token
    /// or it is on the same line. It handles imported tokens correctly.
    pub fn next_line(&mut self) -> bool {
        if self.cursor < 0 {
            self.cursor += 1;
            return true;
        }
        if self.cursor >= (self.tokens.len() as isize) - 1 {
            return false;
        }
        let curr = &self.tokens[self.cursor as usize];
        let next = &self.tokens[(self.cursor + 1) as usize];
        if curr.is_next_on_new_line(next) {
            self.cursor += 1;
            return true;
        }
        false
    }

    /// NextBlock can be used as the condition of a for loop
    /// to load the next token as long as it opens a block or
    /// is already in a block nested more than initialNestingLevel.
    /// In other words, a loop over NextBlock() will iterate
    /// all tokens in the block assuming the next token is an
    /// open curly brace, until the matching closing brace.
    /// The open and closing brace tokens for the outer-most
    /// block will be consumed internally and omitted from
    /// the iteration.
    ///
    /// Proper use of this method looks like this:
    ///
    ///    for nesting := d.Nesting(); d.NextBlock(nesting); {
    ///    }
    ///
    /// However, in simple cases where it is known that the
    /// Dispenser is new and has not already traversed state
    /// by a loop over NextBlock(), this will do:
    ///
    ///    for d.NextBlock(0) {
    ///    }
    ///
    /// As with other token parsing logic, a loop over
    /// NextBlock() should be contained within a loop over
    /// Next(), as it is usually prudent to skip the initial
    /// token.
    pub fn next_block(&mut self, initial_nesting: isize) -> bool {
        if self.nesting > initial_nesting {
            if !self.next() {
                return false; // should be EOF error
            }
            if self.token().is_close_curly_brace() && !self.next_on_same_line() {
                self.nesting -= 1;
            } else if self.token().is_open_curly_brace() && !self.next_on_same_line() {
                self.nesting += 1;
            }
            return self.nesting > initial_nesting;
        }
        if !self.next_on_same_line() {
            // block must open on same line
            return false;
        }
        if !self.token().is_open_curly_brace() {
            self.cursor -= 1; // roll back if not opening brace
            return false;
        }
        self.next(); // consume open curly brace
        if self.token().is_close_curly_brace() {
            return false; // open and then closed right away
        }
        self.nesting += 1;
        true
    }

    /// Nesting returns the current nesting level. Necessary
    /// if using NextBlock()
    pub fn nesting(&self) -> isize {
        self.nesting
    }

    /// Val gets the text of the current token. If there is no token
    /// loaded, it returns empty string.
    pub fn val(&self) -> &str {
        if self.cursor < 0 || self.cursor >= self.tokens.len() as isize {
            return "";
        }
        &self.tokens[self.cursor as usize].text
    }

    /// ValRaw gets the raw text of the current token (including quotes).
    /// If the token was a heredoc, then the delimiter is not included,
    /// because that is not relevant to any unmarshaling logic at this time.
    /// If there is no token loaded, it returns empty string.
    pub fn val_raw(&self) -> String {
        if self.cursor < 0 || self.cursor >= self.tokens.len() as isize {
            return String::new();
        }
        let tok = &self.tokens[self.cursor as usize];
        if tok.was_quoted {
            // In Go, quote was a rune. Here we use quote_kind.
            // Go logic: if quote > 0 && quote != '<' -> add quotes around text.
            // Heredoc quote_kind would be Some('<') or similar?
            // Token definition: quote_kind: Option<char>.
            // If was_quoted is true, quote_kind is likely Some(quote_char).
            // If quote_kind is Some('<'), it's a heredoc, so return text.
            // Otherwise, wrap with quote char.
            if let Some(q) = tok.quote_kind
                && q != '<'
            {
                return format!("{}{}{}", q, tok.text, q);
            }
        }
        tok.text.clone()
    }

    /// ScalarVal gets value of the current token, converted to the closest
    /// scalar type. If there is no token loaded, it returns nil.
    /// Non-finite floats return Err.
    pub fn scalar_val(&self) -> Result<Option<serde_json::Value>, Error> {
        if self.cursor < 0 || self.cursor >= self.tokens.len() as isize {
            return Ok(None);
        }
        let tok = &self.tokens[self.cursor as usize];
        let text = &tok.text;
        let quote = tok.was_quoted;

        // If quoted, return as string literal
        if quote {
            return Ok(Some(Value::String(text.clone())));
        }

        // Try integer
        if let Ok(num) = text.parse::<isize>() {
            return Ok(Some(Value::from(num as i64)));
        }

        // Try float
        if let Some(num) = super::scalar::parse_float(text) {
            if !num.is_finite() {
                return Err(Error::msg(format!("non-finite float value '{}'", text)));
            }
            return Ok(Some(Value::from(num)));
        }

        match text.as_str() {
            "1" | "t" | "T" | "true" | "TRUE" | "True" => return Ok(Some(Value::Bool(true))),
            "0" | "f" | "F" | "false" | "FALSE" | "False" => return Ok(Some(Value::Bool(false))),
            _ => {}
        }

        // Default: return as string
        Ok(Some(Value::String(text.clone())))
    }

    /// Line gets the line number of the current token.
    /// If there is no token loaded, it returns 0.
    pub fn line(&self) -> usize {
        if self.cursor < 0 || self.cursor >= self.tokens.len() as isize {
            return 0;
        }
        self.tokens[self.cursor as usize].line
    }

    /// File gets the filename where the current token originated.
    /// If there is no token loaded, it returns empty string.
    pub fn file(&self) -> String {
        if self.cursor < 0 || self.cursor >= self.tokens.len() as isize {
            return String::new();
        }
        self.tokens[self.cursor as usize].file.clone()
    }

    /// Token returns the current token.
    pub fn token(&self) -> Token {
        if self.cursor < 0 || self.cursor >= self.tokens.len() as isize {
            return Token::default();
        }
        self.tokens[self.cursor as usize].clone()
    }

    /// Args is a convenience function that loads the next arguments
    /// (tokens on the same line) into an arbitrary number of strings
    /// pointed to in targets. If there are not enough argument tokens
    /// available to fill targets, false is returned and the remaining
    /// targets are left unchanged. If all the targets are filled,
    /// then true is returned.
    ///
    /// Note: In Go, Args(...) bool. In Rust, we emulate by taking a count
    /// and returning Option<Vec<String>>.
    pub fn args(&mut self, count: usize) -> Option<Vec<String>> {
        let mut result = Vec::with_capacity(count);
        for _ in 0..count {
            if !self.next_arg() {
                return None;
            }
            result.push(self.val().to_owned());
        }
        Some(result)
    }

    /// AllArgs is like Args, but if there are more argument tokens
    /// available than there are targets, false is returned. The
    /// number of available argument tokens must match the number of
    /// targets exactly to return true.
    pub fn all_args(&mut self, count: usize) -> Option<Vec<String>> {
        match self.args(count) {
            Some(v) => {
                if self.next_arg() {
                    self.prev();
                    None
                } else {
                    Some(v)
                }
            }
            None => None,
        }
    }

    /// CountRemainingArgs counts the amount of remaining arguments
    /// (tokens on the same line) without consuming the tokens.
    pub fn count_remaining_args(&mut self) -> usize {
        let mut count = 0;
        while self.next_arg() {
            count += 1;
        }
        for _ in 0..count {
            self.prev();
        }
        count
    }

    /// RemainingArgs loads any more arguments (tokens on the same line)
    /// into a slice of strings and returns them. An unquoted open curly
    /// brace also indicates the end of arguments, and it is not included
    /// in the return value nor is it loaded; quoted braces are returned
    /// as regular arguments.
    pub fn remaining_args(&mut self) -> Vec<String> {
        let mut args = Vec::new();
        while self.next_arg() {
            args.push(self.val().to_owned());
        }
        args
    }

    /// RemainingArgsRaw loads any more arguments (tokens on the same line,
    /// retaining quotes) into a slice of strings and returns them.
    /// An unquoted open curly brace also indicates the end of arguments,
    /// and it is not included in the return value nor is it loaded; quoted
    /// braces are returned as regular arguments.
    pub fn remaining_args_raw(&mut self) -> Vec<String> {
        let mut args = Vec::new();
        while self.next_arg() {
            args.push(self.val_raw());
        }
        args
    }

    /// RemainingArgsAsTokens loads any more arguments (tokens on the same line)
    /// into a slice of Token-structs and returns them. An unquoted open curly
    /// brace also indicates the end of arguments, and it is not included
    /// in the return value nor is it loaded; quoted braces are returned
    /// as regular arguments.
    pub fn remaining_args_as_tokens(&mut self) -> Vec<Token> {
        let mut args = Vec::new();
        while self.next_arg() {
            args.push(self.token());
        }
        args
    }

    /// NewFromNextSegment returns a new dispenser with a copy of
    /// the tokens from the current token until the end of the
    /// "directive" whether that be to the end of the line or
    /// the end of a block that starts at the end of the line;
    /// in other words, until the end of the segment.
    pub fn new_from_next_segment(&mut self) -> Self {
        Self::new(self.next_segment())
    }

    /// NextSegment returns a copy of the tokens from the current
    /// token until the end of the line or block that starts at
    /// the end of the line.
    pub fn next_segment(&mut self) -> Vec<Token> {
        let mut tkns = Vec::new();

        // Append current token
        tkns.push(self.token());

        // Consume args on same line
        while self.next_arg() {
            tkns.push(self.token());
        }

        let mut opened_block = false;
        let initial_nesting = self.nesting();

        // Iterate over block
        while self.next_block(initial_nesting) {
            if !opened_block {
                // because NextBlock() consumes the initial open
                // curly brace, we rewind here to append it, since
                // our case is special in that we want the new
                // dispenser to have all the tokens including
                // surrounding curly braces
                self.prev();
                tkns.push(self.token());
                self.next();
                opened_block = true;
            }
            tkns.push(self.token());
        }

        if opened_block {
            // include closing brace
            tkns.push(self.token());

            // do not consume the closing curly brace; the
            // next iteration of the enclosing loop will
            // call Next() and consume it
        }

        tkns
    }

    /// Reset sets d's cursor to the beginning, as
    /// if this was a new and unused dispenser.
    pub fn reset(&mut self) {
        self.cursor = -1;
        self.nesting = 0;
    }

    /// ArgErr returns an argument error, meaning that the wrong
    /// number of arguments was given: either a required one was
    /// missing, or an extra one was found. If an argument is
    /// present but its value is invalid, use Errf or SyntaxErr
    /// instead.
    pub fn arg_err(&self) -> Error {
        if self.token().is_open_curly_brace() {
            self.error("unexpected token '{', expecting argument")
        } else {
            self.error(format!(
                "wrong argument count or unexpected line ending after '{}'",
                self.val()
            ))
        }
    }
    pub fn syntax_err(&self, expected: &str) -> Error {
        Error::msg(format!(
            "syntax error: unexpected token '{}', expecting '{}', at {}:{} import chain: ['{}']",
            self.val(),
            expected,
            self.file(),
            self.line(),
            self.token().imports.join("','")
        ))
    }
    pub fn eof_err(&self) -> Error {
        self.error("unexpected EOF")
    }
    pub fn error(&self, message: impl std::fmt::Display) -> Error {
        let token = self.token();
        if token.imports.is_empty() {
            Error::msg(format!("{}, at {}:{}", message, self.file(), self.line()))
        } else {
            Error::msg(format!(
                "{}, at {}:{} import chain ['{}']",
                message,
                self.file(),
                self.line(),
                token.imports.join("','")
            ))
        }
    }

    /// Delete deletes the current token and returns the updated slice
    /// of tokens. The cursor is not advanced to the next token.
    /// Because deletion modifies the underlying slice, this method
    /// should only be called if you have access to the original slice
    /// of tokens and/or are using the slice of tokens outside this
    /// Dispenser instance. If you do not re-assign the slice with the
    /// return value of this method, inconsistencies in the token
    /// array will become apparent (or worse, hide from you like they
    /// did me for 3 and a half freaking hours late one night).
    pub fn delete(&mut self) -> &[Token] {
        if self.cursor >= 0 && self.cursor < self.tokens.len() as isize {
            let idx = self.cursor as usize;
            self.tokens.remove(idx);
            self.cursor -= 1;
        }
        &self.tokens
    }

    /// DeleteN is the same as Delete, but can delete many tokens at once.
    /// If there aren't N tokens available to delete, none are deleted.
    pub fn delete_n(&mut self, amount: usize) -> &[Token] {
        let Ok(amount_signed) = isize::try_from(amount) else {
            return &self.tokens;
        };
        if amount > 0
            && self.cursor >= amount_signed - 1
            && self.cursor < self.tokens.len() as isize
        {
            let start = (self.cursor as usize) + 1 - amount;
            // Remove `amount` tokens starting from `start`
            // In Rust, we can drain
            self.tokens.drain(start..(start + amount));
            self.cursor -= amount_signed;
        }
        &self.tokens
    }

    /// SetContext sets a key-value pair in the context map.
    pub fn set_context(&mut self, key: &str, value: serde_json::Value) {
        self.context.insert(key.to_string(), value);
    }

    /// GetContext gets the value of a key in the context map.
    pub fn get_context(&self, key: &str) -> Option<serde_json::Value> {
        self.context.get(key).cloned()
    }

    /// GetContextString gets the value of a key in the context map
    /// as a string, or an empty string if the key does not exist.
    pub fn get_context_string(&self, key: &str) -> String {
        self.context
            .get(key)
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .unwrap_or_default()
    }

    /// isNewLine determines whether the current token is on a different
    /// line (higher line number) than the previous token. It handles imported
    /// tokens correctly. If there isn't a previous token, it returns true.
    pub(crate) fn is_new_line(&self) -> bool {
        if self.cursor < 1 {
            return true;
        }
        if self.cursor > (self.tokens.len() as isize) - 1 {
            return false;
        }
        let prev = &self.tokens[(self.cursor - 1) as usize];
        let curr = &self.tokens[self.cursor as usize];
        prev.is_next_on_new_line(curr)
    }

    /// isNextOnNewLine determines whether the current token is on a different
    /// line (higher line number) than the next token. It handles imported
    /// tokens correctly. If there isn't a next token, it returns true.
    pub(crate) fn is_next_on_new_line(&self) -> bool {
        if self.cursor < 0 {
            return false;
        }
        if self.cursor >= (self.tokens.len() as isize) - 1 {
            return true;
        }
        let curr = &self.tokens[self.cursor as usize];
        let next = &self.tokens[(self.cursor + 1) as usize];
        curr.is_next_on_new_line(next)
    }
}

pub const MATCHER_NAME_CTX_KEY: &str = "matcher_name";
