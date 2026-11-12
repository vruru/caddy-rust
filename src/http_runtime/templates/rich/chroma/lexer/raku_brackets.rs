use super::raku_emit::NamedView;
use super::raku_rules::{Action, MatchSpec, Replacement};
use super::{Engine, Error, Result, State, map_node};
use std::{mem::size_of, sync::Arc};
#[path = "raku_bracket_data.rs"]
mod data;
fn adverb(bytes: &[u8]) -> bool {
    for (i, _) in bytes.iter().enumerate() {
        for word in [b":to".as_slice(), b":heredoc".as_slice()] {
            if bytes[i..].starts_with(word)
                && bytes
                    .get(i + word.len())
                    .is_none_or(|b| !b.is_ascii_alphanumeric() && *b != b'_')
            {
                return true;
            }
        }
    }
    false
}
impl Engine<'_> {
    fn set_named(&mut self, s: &mut State, name: &str, value: Vec<u8>) -> Result<()> {
        let p = &self.registry.db.programs[s.program];
        let slot = p
            .capnames
            .get(name)
            .and_then(|number| p.caps.get(number))
            .copied();
        let Some(slot) = slot else {
            if Arc::strong_count(&s.named_extra) > 1 {
                let bytes = s.named_extra.iter().try_fold(64usize, |n, (k, v)| {
                    n.checked_add(k.len())
                        .and_then(|n| n.checked_add(v.len()))
                        .and_then(|n| n.checked_add(map_node::<String,Vec<u8>>().ok()?))
                        .ok_or(Error::TotalLimit)
                })?;
                self.tick(s.named_extra.len() as u64, bytes)?;
            }
            let extra=if s.named_extra.contains_key(name){0}else{map_node::<String,Vec<u8>>()?};
            self.tick(1, name.len().checked_add(extra).ok_or(Error::TotalLimit)?)?;
            let map = Arc::make_mut(&mut s.named_extra);
            if map.get(name) != Some(&value) {
                map.insert(name.to_owned(), value);
                s.revision = s.revision.checked_add(1).ok_or(Error::TotalLimit)?;
            }
            return Ok(());
        };
        if Arc::strong_count(&s.named_groups) > 1 {
            let n = s.named_groups.iter().try_fold(
                s.named_groups
                    .len()
                    .checked_mul(size_of::<Vec<u8>>())
                    .ok_or(Error::TotalLimit)?,
                |n, g| n.checked_add(g.len()).ok_or(Error::TotalLimit),
            )?;
            self.tick(s.named_groups.len() as u64, n.checked_add(64).ok_or(Error::TotalLimit)?)?;
        }
        let groups = Arc::make_mut(&mut s.named_groups);
        let old = groups.get_mut(slot).ok_or("invalid Raku named slot")?;
        if *old != value {
            *old = value;
            s.revision = s.revision.checked_add(1).ok_or(Error::TotalLimit)?;
        }
        Ok(())
    }
    fn plain_index_at(
        &mut self,
        text: &[i32],
        needle: &[i32],
        pos: usize,
    ) -> Result<Option<usize>> {
        if pos > text.len() || needle.len() > text.len() - pos {
            return Ok(None);
        }
        for start in pos..=text.len() - needle.len() {
            self.tick(needle.len() as u64 + 1, 0)?;
            if text[start..].starts_with(needle) {
                return Ok(Some(start));
            }
        }
        Ok(None)
    }
    /// Preserve escape filtering in rune units. The Go reference converts a
    /// recursive rune index back through a byte slice and can panic; this loop
    /// intentionally avoids that original indexing bug.
    fn index_at(&mut self, text: &[i32], needle: &[i32], pos: usize) -> Result<Option<usize>> {
        let mut from = pos;
        while let Some(at) = self.plain_index_at(text, needle, from)? {
            self.tick(2, 0)?;
            let relative = at - from;
            let escaped =
                relative > 0 && text[at - 1] == 92 && (relative == 1 || text[at - 2] != 92);
            if !escaped {
                return Ok(Some(at));
            }
            from = at.checked_add(1).ok_or(Error::TotalLimit)?;
        }
        Ok(None)
    }
    fn repeat_runes(&mut self, text: &[i32], count: usize) -> Result<Arc<[i32]>> {
        let len = text.len().checked_mul(count).ok_or(Error::TotalLimit)?;
        self.tick(
            len as u64,
            len.checked_mul(8)
                .and_then(|n| n.checked_add(32))
                .ok_or(Error::TotalLimit)?,
        )?;
        let mut out = Vec::new();
        out.try_reserve_exact(len).map_err(|_| Error::TotalLimit)?;
        for _ in 0..count {
            out.extend_from_slice(text)
        }
        Ok(out.into())
    }
    fn pod_end(
        &mut self,
        s: &State,
        ws: &[u8],
        name: &[u8],
        start: usize,
    ) -> Result<Option<(usize, usize)>> {
        if ws.iter().any(|b| *b != b' ') {
            return Err("unsupported Raku pod whitespace pattern".into());
        }
        let mut prefix = Vec::new();
        self.append_bytes(&mut prefix, ws)?;
        self.append_bytes(&mut prefix, b"=end")?;
        let prefix = super::super::vm::decode_input(&prefix, &mut self.budget)?;
        let name = super::super::vm::decode_input(name, &mut self.budget)?;
        let index = self.dynamic_index("pod")?;
        let left = self.literal_slot(index, &[0xe002, 0xe003, 61, 101, 110, 100])?;
        let right = self.literal_slot(index, &[0xe004, 0xe005])?;
        self.tick(1, 2 * size_of::<(usize, Arc<[i32]>)>())?;
        let literals = [
            (left, self.rune_copy(&prefix)?),
            (right, self.rune_copy(&name)?),
        ];
        let mut pos = start;
        while let Some(at) = self.plain_index_at(s.text, &prefix, pos)? {
            let mut runner = super::super::vm::Runner::new(
                &self.registry.db,
                &self.registry.db.programs[index],
                s.text,
                at,
                &mut self.budget,
            )?;
            runner.set_literal_overrides(&literals)?;
            match runner.execute() {
                Ok(true) => {
                    let (a, n) = runner.captured(0)?.ok_or("missing pod regex capture")?;
                    return Ok(Some((a, n)));
                }
                Ok(false) => {}
                Err(Error::RuleLimit) => return Err(Error::RuleLimit),
                Err(e) => return Err(e),
            }
            pos = at.checked_add(1).ok_or(Error::TotalLimit)?;
        }
        Err("unterminated Raku pod".into())
    }
    fn make_replacement(
        &mut self,
        spec: MatchSpec,
        kind: i32,
        name: &str,
        flags: (bool, bool, bool),
        append: Option<Action>,
    ) -> Result<Arc<Replacement>> {
        let (bottom, pop_state, push_state) = flags;
        self.tick(1, size_of::<Replacement>() + name.len() + 32)?;
        let emitter = self.own_json(&serde_json::Value::from(kind))?;
        Ok(Arc::new(Replacement {
            matcher: spec,
            emitter,
            custom: None,
            append,
            name: name.to_owned(),
            bottom,
            pop_state,
            push_state,
            restore: false,
        }))
    }
    pub(super) fn find_raku_brackets(&mut self, s: &mut State, class: u64) -> Result<()> {
        if class > 7 {
            return Err("invalid Raku bracket token class".into());
        }
        let registry = self.registry;
        let named = NamedView::new(
            &registry.db.programs[s.program],
            s.named_groups.clone(),
            s.named_extra.clone(),
        );
        let mut opening_bytes = Vec::new();
        if class == 2 {
            if s.full_groups.len() < 5 {
                return Err("missing Raku pod groups".into());
            }
            for g in &s.full_groups[1..5] {
                self.append_bytes(&mut opening_bytes, g)?;
            }
        } else {
            self.append_bytes(&mut opening_bytes, named.get("opening_delimiters"))?;
        }
        let opening = super::super::vm::decode_input(&opening_bytes, &mut self.budget)?;
        let first = *opening.first().ok_or("empty Raku opening delimiter")?;
        let mut n = opening.len();
        let closing = data::BRACKETS
            .iter()
            .find(|(open, _)| *open == first)
            .map(|(_, close)| *close);
        if class == 3 {
            let kind = match named.get("keyword") {
                b"B" => 7008,
                b"I" => 7002,
                b"U" => 7011,
                _ => 3113,
            };
            let bottom = self.make_replacement(
                MatchSpec::Static(self.dynamic_index("formatter")?),
                kind,
                "pod-formatter",
                (true, false, false),
                None,
            )?;
            self.replace_rule(s, bottom.clone())?;
            let close = self.repeat_runes(&[closing.unwrap_or(0)], n)?;
            let top = self.make_replacement(
                MatchSpec::Literal(close),
                5000,
                "pod-formatter",
                (false, false, true),
                Some(Action::Restore(bottom)),
            )?;
            self.replace_rule(s, top)?;
            return Ok(());
        }
        if class == 6 {
            let delimiter = if let Some(close) = closing {
                self.rune_copy(&[close])?
            } else {
                self.rune_copy(&opening)?
            };
            let config = self.make_replacement(
                MatchSpec::Literal(delimiter),
                5000,
                "regex",
                (false, true, true),
                None,
            )?;
            self.replace_rule(s, config)?;
            return Ok(());
        }
        if class == 7 {
            let delimiter = self.rune_copy(&opening)?;
            let emitter=self.registry.raku_substitution_emitter.clone();
            self.tick(1, size_of::<Replacement>() + 37)?;
            let config = Arc::new(Replacement {
                matcher: MatchSpec::Substitution(delimiter),
                emitter,
                custom: None,
                append: None,
                name: "regex".to_owned(),
                bottom: false,
                pop_state: true,
                push_state: true,
                restore: false,
            });
            self.replace_rule(s, config)?;
            return Ok(());
        }
        let mut closing_runes: Arc<[i32]>;
        let mut end;
        if closing.is_none() && class != 2 {
            closing_runes = self.rune_copy(&opening)?;
            end = self
                .index_at(s.text, &closing_runes, s.position)?
                .unwrap_or(s.text.len());
        } else {
            closing_runes = if class == 2 {
                self.rune_copy(&[])?
            } else {
                self.repeat_runes(&[closing.unwrap_or(0)], n)?
            };
            let mut level = 1usize;
            let mut search = s
                .position
                .checked_sub(n)
                .ok_or("invalid Raku delimiter origin")?;
            let mut next_close = s.text.len();
            while level > 0 {
                let start = search.checked_add(n).ok_or(Error::TotalLimit)?;
                let close = if class == 2 {
                    match self.pod_end(s, named.get("ws"), named.get("name"), start)? {
                        Some((at, len)) => {
                            let finish = at
                                .checked_add(len)
                                .filter(|n| *n <= s.text.len())
                                .ok_or("invalid pod match")?;
                            closing_runes = self.rune_copy(&s.text[at..finish])?;
                            Some(at)
                        }
                        None => None,
                    }
                } else {
                    self.index_at(s.text, &closing_runes, start)?
                };
                let open = self.index_at(s.text, &opening, start)?;
                if close.is_none() {
                    next_close = s.text.len();
                    level = 0;
                } else if open.is_some_and(|at| at < close.unwrap_or(0)) {
                    level = level.checked_add(1).ok_or(Error::TotalLimit)?;
                    n = opening.len();
                    search = open.ok_or("missing nested opening")?;
                } else {
                    next_close = close.ok_or("missing closing")?;
                    level -= 1;
                    n = closing_runes.len();
                    search = next_close;
                }
            }
            end = next_close;
        }
        let adverbs = named.get("adverbs");
        self.tick(adverbs.len() as u64, 0)?;
        let mut terminator: Arc<[i32]> = self.rune_copy(&[])?;
        let mut heredoc_found = true;
        if adverb(adverbs) {
            if end != s.text.len() {
                terminator = self.rune_copy(
                    s.text
                        .get(s.position..end)
                        .ok_or("invalid heredoc terminator")?,
                )?;
                n = terminator.len();
            } else {
                end = s
                    .position
                    .checked_add(1)
                    .filter(|n| *n <= s.text.len())
                    .ok_or("invalid incomplete heredoc")?;
                n = 0;
            }
            if n > 0 {
                if let Some(offset) = self.index_at(&s.text[end..], &terminator, 0)? {
                    end = end.checked_add(offset).ok_or(Error::TotalLimit)?;
                } else {
                    end = s.text.len();
                    heredoc_found = false;
                }
            }
        }
        let value = s
            .text
            .get(s.position..end)
            .ok_or("invalid Raku bracket content")?;
        match class {
            1 | 2 | 4 => {
                let bytes = self.bytes(value)?;
                self.set_named(s, "value", bytes)?;
                let bytes = self.bytes(&closing_runes)?;
                self.set_named(s, "closing_delimiters", bytes)?;
            }
            0 => {
                if !terminator.is_empty() {
                    let punctuation = n
                        .checked_add(opening.len())
                        .and_then(|n| n.checked_add(1))
                        .ok_or(Error::TotalLimit)?;
                    let split = s
                        .position
                        .checked_add(punctuation)
                        .filter(|n| *n <= end)
                        .ok_or("invalid heredoc opening punctuation")?;
                    let mut bytes = self.bytes(&opening)?;
                    let suffix = self.bytes(&s.text[s.position..split])?;
                    self.append_bytes(&mut bytes, &suffix)?;
                    self.set_named(s, "opening_delimiters", bytes)?;
                    let value = self.bytes(&s.text[split..end])?;
                    self.set_named(s, "value", value)?;
                    if heredoc_found {
                        let close = self.bytes(&terminator)?;
                        self.set_named(s, "closing_delimiters", close)?;
                    }
                } else {
                    let bytes = self.bytes(value)?;
                    self.set_named(s, "value", bytes)?;
                    if n > 0 {
                        let bytes = self.bytes(&closing_runes)?;
                        self.set_named(s, "closing_delimiters", bytes)?;
                    }
                }
            }
            _ => {
                let finish = end
                    .checked_add(n)
                    .filter(|n| *n <= s.text.len())
                    .ok_or("invalid Raku comment range")?;
                let suffix = self.bytes(&s.text[s.position..finish])?;
                let old = s.full_groups.first().ok_or("missing Raku root group")?;
                let mut bytes = Vec::new();
                self.append_bytes(&mut bytes, old)?;
                self.append_bytes(&mut bytes, &suffix)?;
                self.tick(1, size_of::<Vec<u8>>() + 32)?;
                s.full_groups = Arc::new(vec![bytes]);
            }
        }
        s.position = end.checked_add(n).ok_or(Error::TotalLimit)?;
        Ok(())
    }
}
