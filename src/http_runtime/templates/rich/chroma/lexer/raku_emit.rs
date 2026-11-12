use super::{Engine, Options, Result, State, Token};
use super::super::vm::Program;
use std::sync::Arc;
pub(super) struct NamedView<'a> {
    program: &'a Program,
    groups: Arc<Vec<Vec<u8>>>,
    extra: Arc<std::collections::BTreeMap<String, Vec<u8>>>,
}
impl<'a> NamedView<'a> {
    pub(super) fn new(
        program: &'a Program,
        groups: Arc<Vec<Vec<u8>>>,
        extra: Arc<std::collections::BTreeMap<String, Vec<u8>>>,
    ) -> Self {
        Self {
            program,
            groups,
            extra,
        }
    }
    pub(super) fn get(&self, name: &str) -> &[u8] {
        if let Some(value) = self.extra.get(name) {
            return value;
        }
        let slot = self.program.caplist.iter().position(|value| value == name);
        slot.and_then(|slot| self.groups.get(slot))
            .map_or(&[], Vec::as_slice)
    }
}
fn word(ch: u8) -> bool {
    ch.is_ascii_alphanumeric() || ch == b'_'
}
fn lang(config: &[u8]) -> &[u8] {
    for (i, part) in config.windows(5).enumerate() {
        if part != b":lang" {
            continue;
        }
        let mut pos = i + 5;
        let start = pos;
        while pos < config.len() && !word(config[pos]) {
            pos += 1
        }
        if pos == start {
            continue;
        }
        let start = pos;
        while pos < config.len() && word(config[pos]) {
            pos += 1
        }
        if pos > start {
            return &config[start..pos];
        }
    }
    &[]
}
impl Engine<'_> {
    pub(super) fn raku_nested(
        &mut self,
        lexer: usize,
        state: &str,
        input: &[u8],
        out: &mut Vec<Token>,
        depth: usize,
    ) -> Result<()> {
        self.tick(1, state.len() + std::mem::size_of::<Options>())?;
        let options = Options {
            state: state.to_owned(),
            nested: true,
            ensure_lf: false,
        };
        let tokens = self.lex_id(lexer, input, options, depth + 1)?;
        self.append_tokens(out, tokens)
    }
    pub(super) fn raku_colon(
        &mut self,
        class: i32,
        s: &mut State,
        out: &mut Vec<Token>,
        depth: usize,
    ) -> Result<()> {
        let registry = self.registry;
        let named = NamedView::new(
            &registry.db.programs[s.program],
            s.named_groups.clone(),
            s.named_extra.clone(),
        );
        self.push_token(5000, named.get("colon"), out)?;
        let key = named.get("key");
        if class == 2001 {
            self.push_token(2001, key, out)?
        } else {
            self.tick(key.len() as u64, 0)?;
            let state = if !key.is_empty() && key.iter().all(u8::is_ascii_digit) {
                "common"
            } else {
                "Q"
            };
            self.raku_nested(s.lexer, state, key, out, depth)?;
        }
        let open = named.get("opening_delimiters");
        self.push_token(5000, open, out)?;
        let state = match open {
            b"(" | b"{" | b"[" => Some("root"),
            b"<<" | b"\xc2\xab" => Some("ww"),
            b"<" => Some("Q"),
            _ => None,
        };
        if let Some(state) = state {
            self.raku_nested(s.lexer, state, named.get("value"), out, depth)?
        }
        self.push_token(5000, named.get("closing_delimiters"), out)
    }
    pub(super) fn raku_quote(
        &mut self,
        s: &mut State,
        out: &mut Vec<Token>,
        depth: usize,
    ) -> Result<()> {
        let registry = self.registry;
        let named = NamedView::new(
            &registry.db.programs[s.program],
            s.named_groups.clone(),
            s.named_extra.clone(),
        );
        for (key, kind) in [
            ("keyword", 1000),
            ("adverbs", 3101),
            ("ws", 8000),
            ("opening_delimiters", 5000),
        ] {
            self.push_token(kind, named.get(key), out)?;
        }
        let adverbs = named.get("adverbs");
        self.tick(adverbs.len() as u64, 0)?;
        let (mut qq, mut ww, mut closure, mut variable) = (false, false, false, false);
        for adverb in adverbs.split(|b| *b == b':') {
            match adverb {
                b"c" | b"closure" => closure = true,
                b"qq" => qq = true,
                b"ww" => ww = true,
                b"s" | b"scalar" | b"a" | b"array" | b"h" | b"hash" | b"f" | b"function" => {
                    variable = true
                }
                _ => {}
            }
        }
        let state = if named.get("keyword") == b"qq" || qq {
            "qq"
        } else if adverbs == b"ww" || ww {
            "ww"
        } else if closure && variable {
            "qq"
        } else if closure {
            "Q-closure"
        } else if variable {
            "Q-variable"
        } else {
            "Q"
        };
        self.raku_nested(s.lexer, state, named.get("value"), out, depth)?;
        self.push_token(5000, named.get("closing_delimiters"), out)
    }
    pub(super) fn raku_pod_config(
        &mut self,
        input: &[u8],
        s: &State,
        out: &mut Vec<Token>,
        depth: usize,
    ) -> Result<()> {
        self.raku_nested(s.lexer, "colon-pair-attribute", input, out, depth)
    }
    pub(super) fn raku_pod_code(
        &mut self,
        s: &mut State,
        out: &mut Vec<Token>,
        depth: usize,
    ) -> Result<()> {
        let registry = self.registry;
        let named = NamedView::new(
            &registry.db.programs[s.program],
            s.named_groups.clone(),
            s.named_extra.clone(),
        );
        for (key, kind) in [
            ("ws", 6000),
            ("keyword", 1000),
            ("ws2", 1000),
            ("name", 1000),
        ] {
            self.push_token(kind, named.get(key), out)?;
        }
        let config = named.get("config");
        self.raku_pod_config(config, s, out, depth)?;
        self.tick(config.len() as u64, 0)?;
        let language = lang(config);
        if let Some(lexer) = self.lookup(language)? {
            self.tick(0, 28)?;
            let tokens = self.lex_id(lexer, named.get("value"), Options::default(), depth + 1)?;
            self.append_tokens(out, tokens)?;
        } else {
            self.push_token(3107, named.get("value"), out)?;
        }
        for (key, kind) in [
            ("ws3", 6000),
            ("end_keyword", 1000),
            ("ws4", 1000),
            ("name", 1000),
        ] {
            self.push_token(kind, named.get(key), out)?;
        }
        Ok(())
    }
}
