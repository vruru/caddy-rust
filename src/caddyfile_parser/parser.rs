// Copyright 2015 Matthew Holt and The Caddy Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

use super::{Segment, ServerBlock, State, Token};
use anyhow::Result;
use std::ops::{Deref, DerefMut};

pub(super) struct Parser<'s, 'o> {
    pub(super) d: super::dispenser::Dispenser,
    pub(super) block: ServerBlock,
    pub(super) eof: bool,
    pub(super) nesting: isize,
    pub(super) state: &'s mut State<'o>,
}

impl<'s, 'o> Deref for Parser<'s, 'o> {
    type Target = super::dispenser::Dispenser;
    fn deref(&self) -> &Self::Target {
        &self.d
    }
}

impl<'s, 'o> DerefMut for Parser<'s, 'o> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.d
    }
}

impl<'s, 'o> Parser<'s, 'o> {
    pub(super) fn new(tokens: Vec<Token>, state: &'s mut State<'o>) -> Self {
        Self {
            d: super::dispenser::Dispenser::new(tokens),
            block: ServerBlock::default(),
            eof: false,
            nesting: 0,
            state,
        }
    }

    pub(super) fn parse_all(&mut self) -> Result<Vec<ServerBlock>> {
        let mut blocks: Vec<ServerBlock> = Vec::new();

        while self.next() {
            self.parse_one()?;

            if !self.block.keys.is_empty() || !self.block.segments.is_empty() {
                blocks.push(std::mem::take(&mut self.block));
            }

            if self.nesting > 0 {
                return Err(self.eof_err());
            }
        }

        Ok(blocks)
    }

    pub(super) fn parse_one(&mut self) -> Result<()> {
        self.block = ServerBlock::default();
        self.begin()
    }

    pub(super) fn begin(&mut self) -> Result<()> {
        if self.d.tokens.is_empty() {
            return Ok(());
        }

        self.addresses()?;

        if self.eof {
            // this happens if the Caddyfile consists of only
            // a line of addresses and nothing else
            return Ok(());
        }

        if let Some(name) = self.is_named_route() {
            // we just need a dummy leading token to ease parsing later
            let mut name_token = self.token();
            name_token.text = name.clone();

            // named routes only have one key, the route name
            self.state.charge(std::slice::from_ref(&name_token))?;
            self.block.keys = vec![name_token.clone()];
            self.block.is_named_route = true;

            // get all the tokens from the block, including the braces
            let tokens = self.block_tokens(true)?;

            // expand any import directives inside the named route block
            let expanded_tokens = self.expand_imports_in_block(tokens)?;

            self.state.charge(std::slice::from_ref(&name_token))?;
            let mut final_segment = Vec::with_capacity(1 + expanded_tokens.len());
            final_segment.push(name_token);
            final_segment.extend(expanded_tokens);

            self.block.segments = vec![final_segment];
            return Ok(());
        }

        if let Some(name) = self.is_snippet() {
            if self.state.snippets.contains_key(&name) {
                return Err(self.error(format!(
                    "redeclaration of previously declared snippet {}",
                    name
                )));
            }
            // consume all tokens til matched close brace
            let mut tokens = self.block_tokens(false)?;

            // Just as we need to track which file the token comes from, we need to
            // keep track of which snippet the token comes from. This is helpful
            // in tracking import cycles across files/snippets by namespacing them.
            // Without this, we end up with false-positives in cycle-detection.
            for token in &mut tokens {
                token.snippet_name.clone_from(&name);
            }

            self.state.charge(&tokens)?;
            self.state.snippets.insert(name, tokens);

            // empty block keys so we don't save this block as a real server.
            self.block.keys.clear();
            return Ok(());
        }

        self.block_contents()
    }

    pub(super) fn addresses(&mut self) -> Result<()> {
        let mut expecting_another = false;

        loop {
            let value = self.val().to_string();
            let token = self.token();

            // Reject request matchers if trying to define them globally
            if value.starts_with('@') {
                return Err(self.error(format!(
                    "request matchers may not be defined globally, they must be in a site block; found {}",
                    value
                )));
            }

            // Special case: import directive replaces tokens during parse-time
            if value == "import" && self.is_new_line() {
                self.do_import(0)?;
                continue;
            }

            // Open brace definitely indicates end of addresses
            if is_open_curly_brace(&token) {
                if expecting_another {
                    return Err(self.error(format!(
                        "Expected another address but had '{}' - check for extra comma",
                        value
                    )));
                }
                // Mark this server block as being defined with braces.
                self.block.has_braces = true;
                break;
            }

            // Users commonly forget to place a space between the address and the '{'
            if value.ends_with('{') && !token.was_quoted {
                return Err(self.error(format!(
                    "Site addresses cannot end with a curly brace: '{}' - put a space between the token and the brace",
                    value
                )));
            }

            if !value.is_empty() {
                // Trailing comma indicates another address will follow, which
                // may possibly be on the next line
                let mut val = value.clone();
                if val.ends_with(',') {
                    val.pop();
                    expecting_another = true;
                } else {
                    expecting_another = false;
                }

                // If there's a comma here, it's probably because they didn't use a space
                // between their two domains, e.g. "foo.com,bar.com", which would not be
                // parsed as two separate site addresses.
                if val.contains(',') {
                    return Err(self.error(format!(
                        "Site addresses cannot contain a comma ',': '{}' - put a space after the comma to separate site addresses",
                        val
                    )));
                }

                // After the above, a comma surrounded by spaces would result
                // in an empty token which we should ignore
                if !val.is_empty() {
                    let mut t = token.clone();
                    t.text = val;
                    self.state.charge(std::slice::from_ref(&t))?;
                    self.block.keys.push(t);
                }
            }

            // Advance token and possibly break out of loop or return error
            let has_next = self.next();
            if expecting_another && !has_next {
                return Err(self.eof_err());
            }
            if !has_next {
                self.eof = true;
                break; // EOF
            }
            if !expecting_another && self.is_new_line() {
                break;
            }
        }

        Ok(())
    }

    pub(super) fn block_contents(&mut self) -> Result<()> {
        let err_open_curly_brace = self.open_curly_brace();
        if err_open_curly_brace.is_err() {
            // single-server configs don't need curly braces
            self.d.cursor -= 1;
        }

        self.directives()?;

        // only look for close curly brace if there was an opening
        if err_open_curly_brace.is_ok() {
            self.close_curly_brace()?;
        }

        Ok(())
    }

    pub(super) fn directives(&mut self) -> Result<()> {
        while self.next() {
            // end of server block
            if is_close_curly_brace(&self.token()) {
                // p.nesting has already been decremented
                break;
            }

            // special case: import directive replaces tokens during parse-time
            if self.val() == "import" {
                self.do_import(1)?;
                self.d.cursor -= 1; // cursor is advanced when we continue, so roll back one more
                continue;
            }

            // normal case: parse a directive as a new segment
            self.directive()?;
        }

        Ok(())
    }

    pub(super) fn directive(&mut self) -> Result<()> {
        // a segment is a list of tokens associated with this directive
        let mut segment: Segment = Vec::new();

        // the directive itself is appended as a relevant token
        let token = self.token();
        self.state.charge(std::slice::from_ref(&token))?;
        segment.push(token);

        while self.next() {
            let tok = self.token();
            if is_open_curly_brace(&tok) {
                self.nesting += 1;
                if self.nesting as usize > self.state.options.limits.nesting {
                    return Err(self.error("Caddyfile nesting limit exceeded"));
                }
                if !self.is_next_on_new_line() {
                    return Err(self.error("Unexpected next token after '{' on same line"));
                }
                if self.is_new_line() {
                    return Err(self.error("Unexpected '{' on a new line; did you mean to place the '{' on the previous line?"));
                }
            } else if self.val() == "{}" && !tok.was_quoted {
                if self.is_next_on_new_line() {
                    return Err(self.error("Unexpected '{}' at end of line"));
                }
            } else if self.is_new_line() && self.nesting == 0 {
                self.d.cursor -= 1; // read too far
                break;
            } else if is_close_curly_brace(&tok) && self.nesting > 0 {
                self.nesting -= 1;
            } else if is_close_curly_brace(&tok) && self.nesting == 0 {
                return Err(self.error("Unexpected '}' because no matching opening brace"));
            } else if self.val() == "import" && self.is_new_line() {
                self.do_import(1)?;
                self.d.cursor -= 1; // cursor is advanced when we continue, so roll back one more
                continue;
            }

            let token = self.token();
            self.state.charge(std::slice::from_ref(&token))?;
            segment.push(token);
        }

        self.block.segments.push(segment);

        if self.nesting > 0 {
            return Err(self.eof_err());
        }

        Ok(())
    }

    pub(super) fn open_curly_brace(&mut self) -> Result<()> {
        if !is_open_curly_brace(&self.token()) {
            if self.val_looks_like_global_options_after_imported_snippets() {
                return Err(self.error("global options block must appear before import directives; move the global options block to the top of the Caddyfile"));
            }
            return Err(self.syntax_err("{"));
        }
        Ok(())
    }

    fn val_looks_like_global_options_after_imported_snippets(&self) -> bool {
        if self.val() != "import" || self.block.keys.is_empty() {
            return false;
        }

        for key in &self.block.keys {
            if !(key.text.starts_with('(') && key.text.ends_with(')')) {
                return false;
            }
        }

        true
    }

    pub(super) fn close_curly_brace(&mut self) -> Result<()> {
        if !is_close_curly_brace(&self.token()) {
            return Err(self.syntax_err("}"));
        }
        Ok(())
    }

    pub(super) fn is_named_route(&self) -> Option<String> {
        let keys = &self.block.keys;
        // A named route block is a single key with parens, prefixed with &.
        if keys.len() == 1 && keys[0].text.starts_with("&(") && keys[0].text.ends_with(')') {
            // TrimSuffix keys[0].Text[2:], ")"
            let inner = &keys[0].text[2..];
            let name = inner.strip_suffix(')').unwrap();
            return Some(name.to_string());
        }
        None
    }

    pub(super) fn is_snippet(&self) -> Option<String> {
        let keys = &self.block.keys;
        // A snippet block is a single key with parens. Nothing else qualifies.
        if keys.len() == 1 && keys[0].text.starts_with('(') && keys[0].text.ends_with(')') {
            // TrimSuffix keys[0].Text[1:], ")"
            let inner = &keys[0].text[1..];
            let name = inner.strip_suffix(')').unwrap();
            return Some(name.to_string());
        }
        None
    }

    // read and store everything in a block for later replay.
    pub(super) fn block_tokens(&mut self, retain_curlies: bool) -> Result<Vec<Token>> {
        // block must have curlies.
        self.open_curly_brace()?;

        let mut nesting: isize = 1; // count our own nesting
        let mut tokens: Vec<Token> = Vec::new();

        if retain_curlies {
            let token = self.token();
            self.state.charge(std::slice::from_ref(&token))?;
            tokens.push(token);
        }

        while self.next() {
            let tok = self.token();
            if is_close_curly_brace(&tok) {
                nesting -= 1;
                if nesting == 0 {
                    if retain_curlies {
                        self.state.charge(std::slice::from_ref(&tok))?;
                        tokens.push(tok);
                    }
                    break;
                }
            }
            if is_open_curly_brace(&tok) {
                nesting += 1;
                if nesting as usize > self.state.options.limits.nesting {
                    return Err(self.error("Caddyfile nesting limit exceeded"));
                }
            }
            self.state.charge(std::slice::from_ref(&tok))?;
            tokens.push(tok);
        }

        // make sure we're matched up
        if nesting != 0 {
            return Err(self.syntax_err("}"));
        }

        Ok(tokens)
    }
}

fn is_open_curly_brace(token: &Token) -> bool {
    token.text == "{" && !token.was_quoted
}

fn is_close_curly_brace(token: &Token) -> bool {
    token.text == "}" && !token.was_quoted
}
