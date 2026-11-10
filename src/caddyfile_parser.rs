// Copyright 2015 Matthew Holt and The Caddy Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//! Source-preserving Caddyfile parser. This synchronous CPU/filesystem entry
//! point must run on a caller-owned bounded blocking worker, not a reactor.
use crate::caddyfile_lexer::{self, Token};
use anyhow::{Result, bail};
use std::{collections::HashMap, path::PathBuf};

#[path = "caddyfile_parser/args.rs"]
mod args;
#[path = "caddyfile_parser/dispenser.rs"]
pub(crate) mod dispenser;
pub use dispenser::{Dispenser, MATCHER_NAME_CTX_KEY};
#[path = "caddyfile_parser/environment.rs"]
mod environment;
#[path = "caddyfile_parser/graph.rs"]
mod graph;
#[path = "caddyfile_parser/imports.rs"]
mod imports;
#[path = "caddyfile_parser/io.rs"]
mod io;
pub(crate) use io::read_source as read_config_source;
#[path = "caddyfile_parser/parser.rs"]
mod parser;
#[path = "caddyfile_parser/scalar.rs"]
pub(crate) mod scalar;

pub type Segment = Vec<Token>;
#[derive(Clone, Default)]
pub struct ServerBlock {
    pub has_braces: bool,
    pub keys: Vec<Token>,
    pub segments: Vec<Segment>,
    pub is_named_route: bool,
}
impl ServerBlock {
    pub fn keys_text(&self) -> Vec<&str> {
        self.keys.iter().map(|key| key.text.as_str()).collect()
    }
}
#[derive(Clone)]
pub struct ParseWarning {
    pub file: String,
    pub line: usize,
    pub category: String,
    pub import_chain: Vec<String>,
}
pub struct ParsedCaddyfile {
    pub blocks: Vec<ServerBlock>,
    pub warnings: Vec<ParseWarning>,
}
#[derive(Clone)]
pub struct ParseLimits {
    pub source_bytes: usize,
    pub total_source_bytes: usize,
    /// Maximum live length of an individual expanded token stream.
    pub token_count: usize,
    /// Cumulative owned-token copies, including lexer, snippets and AST output.
    pub materialized_token_units: usize,
    /// Conservative cumulative materialization work, not an exact RSS limit.
    pub materialized_bytes: usize,
    pub imports: usize,
    pub nesting: usize,
    pub import_chain: usize,
    /// Cumulative import rewrite slots (old suffix plus inserted tokens).
    /// This is an intentional resource cap, independent of the import count;
    /// rearranged large configurations may reach it before other limits.
    /// Default 1B was measured with 16,384 single-import sites (671,227,904
    /// slots) and an exhausted-budget fixture; not an exact CPU/RSS measure.
    pub splice_work: usize,
}
impl Default for ParseLimits {
    fn default() -> Self {
        Self {
            source_bytes: 16 << 20,
            total_source_bytes: 64 << 20,
            token_count: 1_000_000,
            materialized_token_units: 4_000_000,
            materialized_bytes: 256 << 20,
            imports: 16_384,
            nesting: 256,
            import_chain: 256,
            splice_work: 1_000_000_000,
        }
    }
}
/// `cwd` is the captured process-start working directory, preserving a valid
/// `$PWD` spelling when applicable. Environment values are immutable per parse.
#[derive(Clone)]
pub struct ParseOptions {
    pub cwd: PathBuf,
    pub environment: HashMap<Vec<u8>, Vec<u8>>,
    pub limits: ParseLimits,
}
impl ParseOptions {
    pub fn capture() -> Result<Self> {
        let actual = std::env::current_dir()?;
        let cwd = std::env::var_os("PWD")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute() && io::same_directory(p, &actual))
            .unwrap_or(actual);
        #[cfg(unix)]
        let environment = {
            use std::os::unix::ffi::OsStrExt;
            std::env::vars_os()
                .map(|(k, v)| (k.as_bytes().to_vec(), v.as_bytes().to_vec()))
                .collect()
        };
        #[cfg(not(unix))]
        let environment = std::env::vars()
            .map(|(k, v)| (k.into_bytes(), v.into_bytes()))
            .collect();
        Ok(Self {
            cwd,
            environment,
            limits: ParseLimits::default(),
        })
    }
}
struct State<'a> {
    options: &'a ParseOptions,
    snippets: HashMap<String, Vec<Token>>,
    graph: graph::ImportGraph,
    warnings: Vec<ParseWarning>,
    source_bytes: usize,
    materialized_bytes: usize,
    materialized_tokens: usize,
    import_count: usize,
    splice_work: usize,
}
impl State<'_> {
    fn charge_splice(&mut self, count: usize) -> Result<()> {
        let total = self
            .splice_work
            .checked_add(count)
            .ok_or_else(|| anyhow::anyhow!("Caddyfile import work budget overflow"))?;
        if total > self.options.limits.splice_work {
            bail!("Caddyfile import work budget exceeded");
        }
        self.splice_work = total;
        Ok(())
    }
    fn clone_snippet(&mut self, name: &str) -> Result<Option<Vec<Token>>> {
        let Some(tokens) = self.snippets.remove(name) else {
            return Ok(None);
        };
        self.charge(&tokens)?;
        let copy = tokens.clone();
        self.snippets.insert(name.to_owned(), tokens);
        Ok(Some(copy))
    }
    fn warn(&mut self, token: &Token, category: impl Into<String>) -> Result<()> {
        let category = category.into();
        let bytes = std::mem::size_of::<ParseWarning>()
            + token.file.len()
            + category.len()
            + token
                .imports
                .iter()
                .map(|s| s.len() + std::mem::size_of::<String>())
                .sum::<usize>();
        let total = self
            .materialized_bytes
            .checked_add(bytes)
            .ok_or_else(|| anyhow::anyhow!("Caddyfile warning budget overflow"))?;
        if self.warnings.len() >= self.options.limits.token_count
            || total > self.options.limits.materialized_bytes
        {
            bail!("Caddyfile diagnostic budget exceeded");
        }
        self.materialized_bytes = total;
        self.warnings.push(ParseWarning {
            file: token.file.clone(),
            line: token.line,
            category,
            import_chain: token.imports.clone(),
        });
        Ok(())
    }
    fn charge(&mut self, tokens: &[Token]) -> Result<()> {
        let mut bytes = 0usize;
        for token in tokens {
            bytes = bytes
                .checked_add(
                    std::mem::size_of::<Token>()
                        + token.file.len()
                        + token.text.len()
                        + token.snippet_name.len()
                        + token.heredoc_marker.len(),
                )
                .ok_or_else(|| anyhow::anyhow!("Caddyfile materialization budget overflow"))?;
            for item in &token.imports {
                bytes = bytes
                    .checked_add(item.len() + std::mem::size_of::<String>())
                    .ok_or_else(|| anyhow::anyhow!("Caddyfile materialization budget overflow"))?;
            }
        }
        let count = self
            .materialized_tokens
            .checked_add(tokens.len())
            .ok_or_else(|| anyhow::anyhow!("Caddyfile token budget overflow"))?;
        let total = self
            .materialized_bytes
            .checked_add(bytes)
            .ok_or_else(|| anyhow::anyhow!("Caddyfile materialization budget overflow"))?;
        if count > self.options.limits.materialized_token_units
            || total > self.options.limits.materialized_bytes
        {
            bail!("Caddyfile materialization budget exceeded");
        }
        self.materialized_tokens = count;
        self.materialized_bytes = total;
        Ok(())
    }
    fn all_tokens(&mut self, filename: &str, input: &[u8]) -> Result<Vec<Token>> {
        let total = self
            .source_bytes
            .checked_add(input.len())
            .ok_or_else(|| anyhow::anyhow!("Caddyfile source budget overflow"))?;
        if total > self.options.limits.total_source_bytes {
            bail!("Caddyfile total source byte limit exceeded");
        }
        self.source_bytes = total;
        let expanded = environment::replace_env(
            input,
            |name| self.options.environment.get(name).cloned(),
            self.options.limits.source_bytes,
        )?;
        // Lexing clones the filename into every token. Bound those allocations
        // before tokenization, including conservative room for UTF-8 repair,
        // heredoc markers and Vec growth; a post-lex check alone is too late.
        let remaining = self
            .options
            .limits
            .materialized_bytes
            .saturating_sub(self.materialized_bytes);
        let source_room = expanded
            .len()
            .checked_mul(4)
            .ok_or_else(|| anyhow::anyhow!("Caddyfile lexical byte budget overflow"))?;
        let remaining = remaining
            .checked_sub(source_room)
            .ok_or_else(|| anyhow::anyhow!("Caddyfile lexical byte budget exceeded"))?;
        let per_token = std::mem::size_of::<Token>()
            .checked_mul(2)
            .and_then(|n| n.checked_add(filename.len()))
            .ok_or_else(|| anyhow::anyhow!("Caddyfile lexical token budget overflow"))?;
        let count_limit = (remaining / per_token)
            .min(self.options.limits.token_count)
            .min(
                self.options
                    .limits
                    .materialized_token_units
                    .saturating_sub(self.materialized_tokens),
            );
        let tokens = caddyfile_lexer::tokenize_bounded(&expanded, filename, count_limit)?;
        self.charge(&tokens)?;
        Ok(tokens)
    }
}
pub fn parse(filename: &str, input: &[u8], options: &ParseOptions) -> Result<ParsedCaddyfile> {
    if !options.cwd.is_absolute() {
        bail!("Caddyfile working directory must be absolute");
    }
    let mut state = State {
        options,
        snippets: HashMap::new(),
        graph: graph::ImportGraph::default(),
        warnings: Vec::new(),
        source_bytes: 0,
        materialized_bytes: 0,
        materialized_tokens: 0,
        import_count: 0,
        splice_work: 0,
    };
    let tokens = state.all_tokens(filename, input)?;
    let blocks = parser::Parser::new(tokens, &mut state).parse_all()?;
    Ok(ParsedCaddyfile {
        blocks,
        warnings: state.warnings,
    })
}
