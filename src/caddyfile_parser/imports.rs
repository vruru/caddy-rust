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

use super::Token;
use super::args;
use super::io;
use super::parser::Parser;
use anyhow::{Result, bail};
use std::collections::HashMap;
use std::path::Path;

impl<'s, 'o> Parser<'s, 'o> {
    pub(super) fn do_import(&mut self, mut nesting: isize) -> Result<()> {
        self.state.import_count += 1;
        if self.state.import_count > self.state.options.limits.imports {
            bail!("import limit exceeded");
        }

        if !self.next_arg() {
            return Err(self.arg_err());
        }
        let import_pattern = self.val().to_string();
        if import_pattern.is_empty() {
            return Err(self.error("Import requires a non-empty filepath"));
        }

        let args = self.remaining_args();

        let mut block_tokens: Vec<Token> = Vec::new();
        let current_nesting = self.nesting();
        while self.next_block(current_nesting) {
            let token = self.token();
            self.state.charge(std::slice::from_ref(&token))?;
            block_tokens.push(token);
        }

        let mut block_mapping: HashMap<String, Vec<Token>> = HashMap::new();
        if !block_tokens.is_empty() {
            // Charge the separate owned Dispenser clone, not the tokens moved below.
            self.state.charge(&block_tokens)?;
            let mut bd = super::dispenser::Dispenser::new(block_tokens.clone());

            while bd.next() {
                let current_mapping_key = bd.val().to_string();

                if is_open_curly_brace(bd.token()) {
                    return Err(self.error("anonymous blocks are not supported"));
                }

                let mut current_mapping_tokens: Vec<Token> = bd.remaining_args_as_tokens().to_vec();
                self.state.charge(&current_mapping_tokens)?;

                let mapping_nesting = bd.nesting();
                while bd.next_block(mapping_nesting) {
                    let token = bd.token();
                    self.state.charge(std::slice::from_ref(&token))?;
                    current_mapping_tokens.push(token);
                }

                block_mapping.insert(current_mapping_key, current_mapping_tokens);
            }
        }

        let current_cursor = self.d.cursor;

        let removed = isize::try_from(1 + args.len() + block_tokens.len())?;
        let before = current_cursor
            .checked_sub(removed)
            .ok_or_else(|| self.error("invalid import cursor"))?;
        let tokens_before_len =
            usize::try_from(before).map_err(|_| self.error("invalid import splice"))?;
        let tokens_after_start = usize::try_from(current_cursor + 1)?;

        if tokens_before_len > self.d.tokens.len() || tokens_after_start > self.d.tokens.len() {
            bail!("internal error: import splice out of bounds");
        }

        let suffix_len = self.d.tokens.len() - tokens_after_start;

        let mut imported_tokens: Vec<Token> = Vec::new();
        let mut nodes: Vec<String> = Vec::new();

        if let Some(snippet) = self.state.clone_snippet(&import_pattern)? {
            imported_tokens = snippet;
            if !imported_tokens.is_empty() {
                nodes.push(format!(
                    "{}:{}",
                    imported_tokens[0].file, imported_tokens[0].snippet_name
                ));
            }
        } else {
            let abs_file = io::lexical_absolute(Path::new(&self.file()), &self.state.options.cwd)
                .map_err(|error| {
                self.error(format!(
                    "Failed to get absolute path of file: {}: {error}",
                    self.file()
                ))
            })?;

            let mut glob_pattern = import_pattern.clone();
            if !Path::new(&import_pattern).is_absolute() {
                let parent_dir = abs_file.parent().unwrap_or(Path::new("."));
                glob_pattern = io::lexical_absolute(Path::new(&import_pattern), parent_dir)
                    .map_err(|error| {
                        self.error(format!(
                            "Failed to use import pattern {import_pattern}: {error}"
                        ))
                    })?
                    .to_str()
                    .ok_or_else(|| self.error("non-UTF8 import paths are unsupported"))?
                    .to_owned();
            }

            if glob_pattern.matches('*').count() > 1
                || glob_pattern.matches('?').count() > 1
                || (glob_pattern.contains('[') && glob_pattern.contains(']'))
            {
                return Err(self.error(format!(
                    "Glob pattern may only contain one wildcard (*), but has others: {}",
                    glob_pattern
                )));
            }

            let mut matches = io::glob(Path::new(&glob_pattern), self.state.options.limits.imports)
                .map_err(|error| {
                    self.error(format!(
                        "Failed to use import pattern {import_pattern}: {error}"
                    ))
                })?;
            if matches.is_empty() {
                if glob_pattern.contains(['*', '?', '[', ']']) {
                    self.state.warn(&self.token(), "import_glob_no_matches")?;
                } else {
                    return Err(self.error(format!("File to import not found: {import_pattern}")));
                }
            } else if glob_pattern
                .rsplit('/')
                .next()
                .is_some_and(|part| part.starts_with('*'))
            {
                matches.retain(|path| {
                    !path
                        .file_name()
                        .is_some_and(|name| name.to_string_lossy().starts_with('.'))
                });
            }
            for import_file in &matches {
                imported_tokens.extend(self.do_single_import(import_file)?);
            }
            nodes = matches
                .iter()
                .map(|p| {
                    p.to_str()
                        .map(str::to_owned)
                        .ok_or_else(|| self.error("non-UTF8 import paths are unsupported"))
                })
                .collect::<Result<Vec<_>>>()?;
        }

        let mut node_name = self.file().to_string();
        if !self.token().snippet_name.is_empty() {
            node_name.push(':');
            node_name.push_str(&self.token().snippet_name);
        }

        self.state.graph.add_node(&node_name);
        self.state.graph.add_nodes(&nodes);
        if let Err(e) = self.state.graph.add_edges(&node_name, &nodes) {
            self.state.graph.remove_nodes(&nodes);
            bail!("{}", e);
        }

        let tokens_copy_capacity = imported_tokens.len();

        let total_tokens_len = tokens_before_len + tokens_copy_capacity + suffix_len;
        if total_tokens_len > self.state.options.limits.token_count {
            bail!("token limit exceeded");
        }

        let mut tokens_copy: Vec<Token> = Vec::with_capacity(tokens_copy_capacity);

        let mut var_maybe_snippet: bool = false;
        let mut var_maybe_snippet_id: bool = false;
        let mut var_index: usize = 0;

        for (i, mut token) in imported_tokens.into_iter().enumerate() {
            let import_str = if !token.snippet_name.is_empty() {
                format!(
                    "{}:{} (import {})",
                    self.file(),
                    self.line(),
                    token.snippet_name
                )
            } else {
                format!("{}:{} (import)", self.file(), self.line())
            };
            if token.imports.len() >= self.state.options.limits.import_chain {
                return Err(self.error("import chain limit exceeded"));
            }
            token.imports.push(import_str);

            if !var_maybe_snippet && nesting == 0 {
                if i > 0 && tokens_copy.is_empty() {
                    return Err(self.error("import expansion has no preceding token"));
                }
                if i == 0
                    || tokens_copy
                        .last()
                        .is_some_and(|previous| previous.is_next_on_new_line(&token))
                {
                    var_index = 0;
                } else {
                    var_index += 1;
                }

                if var_index == 0
                    && token.text.len() >= 3
                    && token.text.starts_with('(')
                    && token.text.ends_with(')')
                {
                    var_maybe_snippet_id = true;
                }
            }

            if token.is_open_curly_brace() {
                nesting += 1;
                if var_index == 1 && var_maybe_snippet_id && nesting == 1 {
                    var_maybe_snippet = true;
                    var_maybe_snippet_id = false;
                }
            } else if token.is_close_curly_brace() {
                nesting -= 1;
                if nesting == 0 && var_maybe_snippet {
                    var_maybe_snippet = false;
                }
            }
            if nesting > self.state.options.limits.nesting as isize {
                return Err(self.error("Caddyfile nesting limit exceeded"));
            }

            let mut tokens_to_add: &[Token] = &[];
            let mut found_block_directive = false;

            if token.text == "{block}" {
                found_block_directive = true;
                tokens_to_add = &block_tokens;
            } else if token.text.starts_with("{blocks.") && token.text.ends_with("}") {
                found_block_directive = true;
                let block_key = &token.text[8..token.text.len() - 1];
                if let Some(val) = block_mapping.get(block_key) {
                    tokens_to_add = val;
                }
            }

            if found_block_directive {
                if var_maybe_snippet {
                    self.state.charge(std::slice::from_ref(&token))?;
                    tokens_copy.push(token);
                } else {
                    self.state.charge(tokens_to_add)?;
                    tokens_copy.extend_from_slice(tokens_to_add);
                }
                continue;
            }

            if var_maybe_snippet {
                self.state.charge(std::slice::from_ref(&token))?;
                tokens_copy.push(token);
                continue;
            }

            let mut warnings = Vec::new();
            if let Some(range) = args::parse_variadic(&token.text, args.len(), &mut warnings) {
                for arg in &args[range] {
                    let mut expanded = token.clone();
                    expanded.text = arg.clone();
                    self.state.charge(std::slice::from_ref(&expanded))?;
                    tokens_copy.push(expanded);
                }
            } else {
                token.text = args::replace_args(
                    &token.text,
                    &args,
                    &mut warnings,
                    self.state.options.limits.source_bytes.min(
                        self.state
                            .options
                            .limits
                            .materialized_bytes
                            .saturating_sub(self.state.materialized_bytes),
                    ),
                )?;
                self.state.charge(std::slice::from_ref(&token))?;
                tokens_copy.push(token.clone());
            }
            for category in warnings {
                self.state.warn(&token, category)?;
            }
        }

        if tokens_before_len + tokens_copy.len() + suffix_len
            > self.state.options.limits.token_count
        {
            return Err(self.error("Caddyfile expanded token limit exceeded"));
        }
        let work = self
            .d
            .tokens
            .len()
            .saturating_sub(tokens_before_len)
            .checked_add(tokens_copy.len())
            .ok_or_else(|| self.error("Caddyfile import work budget overflow"))?;
        self.state.charge_splice(work)?;
        drop(
            self.d
                .tokens
                .splice(tokens_before_len..tokens_after_start, tokens_copy),
        );
        self.d.cursor = current_cursor - removed;

        Ok(())
    }

    pub(super) fn expand_imports_in_block(&mut self, tokens: Vec<Token>) -> Result<Vec<Token>> {
        let mut temp_parser = Parser {
            d: super::dispenser::Dispenser::new(tokens),
            block: Default::default(),
            eof: false,
            nesting: 0,
            state: self.state,
        };

        while temp_parser.next() {
            if temp_parser.val() == "import" && temp_parser.is_new_line() {
                temp_parser.do_import(1)?;
                temp_parser.d.cursor -= 1;
            }
        }

        Ok(temp_parser.d.tokens)
    }

    pub(super) fn do_single_import(&mut self, path: &Path) -> Result<Vec<Token>> {
        let path = io::lexical_absolute(path, &self.state.options.cwd)?;
        let filename = path
            .to_str()
            .ok_or_else(|| self.error("non-UTF8 import paths are unsupported"))?;
        let bytes = io::read_source(&path, self.state.options.limits.source_bytes)
            .map_err(|error| self.error(format!("Could not import {filename}: {error}")))?;
        if String::from_utf8_lossy(&bytes).trim().is_empty() {
            self.state.source_bytes = self
                .state
                .source_bytes
                .checked_add(bytes.len())
                .ok_or_else(|| self.error("Caddyfile source budget overflow"))?;
            if self.state.source_bytes > self.state.options.limits.total_source_bytes {
                return Err(self.error("Caddyfile total source byte limit exceeded"));
            }
            let token = Token {
                file: filename.to_owned(),
                ..Token::default()
            };
            self.state.warn(&token, "import_empty_file")?;
            return Ok(Vec::new());
        }
        self.state.all_tokens(filename, &bytes).map_err(|error| {
            self.error(format!(
                "Could not read tokens while importing {filename}: {error}"
            ))
        })
    }
}

fn is_open_curly_brace(token: Token) -> bool {
    token.is_open_curly_brace()
}
