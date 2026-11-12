use super::{Engine, Error, Result, State, map_node};
use serde_json::Value;
use std::{collections::BTreeMap, mem::size_of, sync::Arc};
#[derive(Clone, PartialEq)]
pub(super) enum MatchSpec {
    Static(usize),
    Literal(Arc<[i32]>),
    Substitution(Arc<[i32]>),
}
#[derive(Clone, PartialEq)]
pub(super) enum Action {
    Static(Arc<Value>),
    Pop,
    Restore(Arc<Replacement>),
}
#[derive(Clone, PartialEq)]
pub(super) struct Replacement {
    pub matcher: MatchSpec,
    pub emitter: Arc<Value>,
    pub custom: Option<Arc<Value>>,
    pub append: Option<Action>,
    pub name: String,
    pub bottom: bool,
    pub pop_state: bool,
    pub push_state: bool,
    pub restore: bool,
}
#[derive(PartialEq)]
pub(super) struct DynamicRule {
    pub program: usize,
    pub literals: Vec<(usize, Arc<[i32]>)>,
    pub emitter: Arc<Value>,
    pub actions: Vec<Action>,
}
pub(super) type OverlayKey = (usize, String, bool);
pub(super) type History = BTreeMap<(String, bool), Vec<Arc<Replacement>>>;
fn json_size(value: &Value, depth: usize) -> Result<(u64, usize)> {
    if depth > 64 {
        return Err(Error::TotalLimit);
    }
    let (mut count, mut bytes) = (1u64, size_of::<Value>());
    match value {
        Value::String(s) => bytes = bytes.checked_add(s.len()).ok_or(Error::TotalLimit)?,
        Value::Array(values) => {
            for value in values {
                let (n, b) = json_size(value, depth + 1)?;
                count = count.checked_add(n).ok_or(Error::TotalLimit)?;
                bytes = bytes.checked_add(b).ok_or(Error::TotalLimit)?;
            }
        }
        Value::Object(map) => {
            for (key, value) in map {
                let (n, b) = json_size(value, depth + 1)?;
                count = count.checked_add(n).ok_or(Error::TotalLimit)?;
                bytes = bytes
                    .checked_add(key.len())
                    .and_then(|x| x.checked_add(map_node::<String,Value>().ok()?))
                    .and_then(|x| x.checked_add(b))
                    .ok_or(Error::TotalLimit)?;
            }
        }
        _ => {}
    }
    Ok((count, bytes))
}
impl Engine<'_> {
    pub(super) fn own_json(&mut self, value: &Value) -> Result<Arc<Value>> {
        let (work, bytes) = json_size(value, 0)?;
        self.tick(work, bytes.checked_add(32).ok_or(Error::TotalLimit)?)?;
        Ok(Arc::new(value.clone()))
    }
    pub(super) fn rune_copy(&mut self, value: &[i32]) -> Result<Arc<[i32]>> {
        self.tick(
            value.len() as u64,
            value
                .len()
                .checked_mul(8)
                .and_then(|n| n.checked_add(32))
                .ok_or(Error::TotalLimit)?,
        )?;
        let mut out = Vec::new();
        out.try_reserve_exact(value.len())
            .map_err(|_| Error::TotalLimit)?;
        out.extend_from_slice(value);
        Ok(out.into())
    }
    pub(super) fn dynamic_index(&self, name: &str) -> Result<usize> {
        self.registry
            .db
            .dynamic_programs
            .get(name)
            .copied()
            .ok_or_else(|| "missing generated dynamic regex".into())
    }
    pub(super) fn literal_slot(&self, program: usize, wanted: &[i32]) -> Result<usize> {
        let p = &self.registry.db.programs[program];
        let mut found = p
            .strings
            .iter()
            .enumerate()
            .filter(|(_, s)| s.as_slice() == wanted);
        let slot = found
            .next()
            .map(|(slot, _)| slot)
            .ok_or("missing generated literal slot")?;
        if found.next().is_some() {
            return Err("ambiguous generated literal slot".into());
        }
        Ok(slot)
    }
    pub(super) fn replacement(&mut self, value: &Value) -> Result<Arc<Replacement>> {
        let name = value["stateName"]
            .as_str()
            .ok_or("missing replacement state")?;
        let bottom = match value["rulePosition"].as_u64() {
            Some(0) => false,
            Some(1) => true,
            _ => return Err("invalid replacement position".into()),
        };
        self.tick(1, name.len() + size_of::<Replacement>() + 32)?;
        let name = name.to_owned();
        let delimiter = value["delimiter"]
            .as_array()
            .ok_or("invalid replacement delimiter")?;
        let matcher = if !delimiter.is_empty() {
            let repeat = value["numberOfDelimiterChars"]
                .as_u64()
                .ok_or("invalid delimiter count")?
                .max(1);
            let repeat = usize::try_from(repeat).map_err(|_| Error::TotalLimit)?;
            let size = delimiter
                .len()
                .checked_mul(repeat)
                .ok_or(Error::TotalLimit)?;
            self.tick(
                size as u64,
                size.checked_mul(8)
                    .and_then(|n| n.checked_add(32))
                    .ok_or(Error::TotalLimit)?,
            )?;
            let mut runes = Vec::new();
            runes
                .try_reserve_exact(size)
                .map_err(|_| Error::TotalLimit)?;
            for _ in 0..repeat {
                for ch in delimiter {
                    runes.push(
                        ch.as_i64()
                            .and_then(|n| i32::try_from(n).ok())
                            .filter(|n| (0..=0x10ffff).contains(n))
                            .ok_or("invalid delimiter rune")?,
                    );
                }
            }
            MatchSpec::Literal(runes.into())
        } else {
            let name = match value["pattern"].as_str() {
                Some("\\A\\z") => "placeholder",
                Some(".+?") => "formatter",
                _ => return Err("unimplemented dynamic Raku regex pattern".into()),
            };
            MatchSpec::Static(self.dynamic_index(name)?)
        };
        let emitter = self.own_json(&value["tokenType"])?;
        let custom = if value["mutator"].is_null() {
            None
        } else {
            Some(self.own_json(&value["mutator"])?)
        };
        let append = if value["appendMutator"].is_null() {
            None
        } else {
            Some(Action::Static(self.own_json(&value["appendMutator"])?))
        };
        Ok(Arc::new(Replacement {
            matcher,
            emitter,
            custom,
            append,
            name,
            bottom,
            pop_state: value["popState"] == true,
            push_state: value["pushState"] == true,
            restore: value["pop"] == true,
        }))
    }
    pub(super) fn replace_rule(&mut self, s: &mut State, config: Arc<Replacement>) -> Result<()> {
        let lexer = self
            .registry
            .db
            .lexers
            .get(s.lexer)
            .ok_or("invalid replacement lexer")?;
        if lexer.states.get(&config.name).is_none_or(Vec::is_empty) {
            return Err("unknown replacement state".into());
        }
        self.tick(1, config.name.len())?;
        let key = (config.name.clone(), config.bottom);
        if s.rule_stacks.get(&key).is_none_or(Vec::is_empty) {
            self.tick(1, size_of::<Replacement>() + config.name.len() + 64 + map_node::<(String,bool),Vec<Arc<Replacement>>>()?)?;
            let placeholder = Arc::new(Replacement {
                matcher: MatchSpec::Static(self.dynamic_index("placeholder")?),
                emitter: self.own_json(&Value::Null)?,
                custom: None,
                append: None,
                name: config.name.clone(),
                bottom: config.bottom,
                pop_state: false,
                push_state: false,
                restore: false,
            });
            self.tick(1, size_of::<Arc<Replacement>>())?;
            let mut history = Vec::new();
            history
                .try_reserve_exact(1)
                .map_err(|_| Error::TotalLimit)?;
            history.push(placeholder);
            self.tick(1, key.0.len())?;
            s.rule_stacks.insert(key.clone(), history);
            s.revision = s.revision.checked_add(1).ok_or(Error::TotalLimit)?;
        }
        self.tick(1, size_of::<DynamicRule>() + 4 * size_of::<Action>() + 32)?;
        let mut actions = Vec::new();
        actions
            .try_reserve_exact(3)
            .map_err(|_| Error::TotalLimit)?;
        if !config.bottom {
            if let Some(custom) = &config.custom {
                actions.push(Action::Static(custom.clone()))
            } else {
                actions.push(Action::Pop)
            }
            actions.push(Action::Restore(config.clone()));
        } else if let Some(custom) = &config.custom {
            actions.push(Action::Static(custom.clone()))
        }
        if let Some(action) = &config.append {
            actions.push(action.clone())
        }
        let program;
        let mut literals = Vec::new();
        match &config.matcher {
            MatchSpec::Static(index) => program = *index,
            MatchSpec::Literal(text) | MatchSpec::Substitution(text) => {
                program =
                    self.dynamic_index(if matches!(config.matcher, MatchSpec::Literal(_)) {
                        "literal"
                    } else {
                        "substitution"
                    })?;
                let slot = self.literal_slot(program, &[0xe000, 0xe001])?;
                self.tick(1, size_of::<(usize, Arc<[i32]>)>())?;
                literals
                    .try_reserve_exact(1)
                    .map_err(|_| Error::TotalLimit)?;
                literals.push((slot, text.clone()));
            }
        }
        let candidate = Arc::new(DynamicRule {
            program,
            literals,
            emitter: config.emitter.clone(),
            actions,
        });
        self.tick(1, config.name.len())?;
        let effective_bottom = config.bottom && lexer.states[&config.name].len() > 1;
        let overlay = (s.lexer, config.name.clone(), effective_bottom);
        if self
            .raku_overlays
            .get(&overlay)
            .is_none_or(|old| old.as_ref() != candidate.as_ref())
        {
            if !self.raku_overlays.contains_key(&overlay){self.tick(0,map_node::<OverlayKey,Arc<DynamicRule>>()?)?;}
            self.raku_overlays.insert(overlay, candidate);
            self.overlay_generation = self
                .overlay_generation
                .checked_add(1)
                .ok_or(Error::TotalLimit)?;
            s.revision = s.revision.checked_add(1).ok_or(Error::TotalLimit)?;
        }
        if config.pop_state {
            let n = s
                .stack
                .len()
                .checked_sub(1)
                .ok_or("Raku state pop underflow")?;
            s.stack.truncate(n);
        }
        if config.push_state {
            self.push_state(s, &config.name)?
        }
        if !config.restore {
            let history = s.rule_stacks.get(&key).ok_or("missing Raku history")?;
            let grow = if history.len() == history.capacity() {
                Some(
                    history
                        .capacity()
                        .checked_mul(2)
                        .ok_or(Error::TotalLimit)?
                        .max(2),
                )
            } else {
                None
            };
            if let Some(cap) = grow {
                self.tick(
                    history.len() as u64,
                    cap.checked_mul(size_of::<Arc<Replacement>>())
                        .ok_or(Error::TotalLimit)?,
                )?;
            }
            let history = s.rule_stacks.get_mut(&key).ok_or("missing Raku history")?;
            if let Some(cap) = grow {
                history
                    .try_reserve_exact(cap - history.len())
                    .map_err(|_| Error::TotalLimit)?;
            }
            history.push(config);
            s.revision = s.revision.checked_add(1).ok_or(Error::TotalLimit)?;
        }
        Ok(())
    }
    pub(super) fn restore_rule(&mut self, s: &mut State, config: &Arc<Replacement>) -> Result<()> {
        self.tick(1, config.name.len() + size_of::<String>())?;
        let key = (config.name.clone(), config.bottom);
        let Some(history) = s.rule_stacks.get_mut(&key) else {
            return Ok(());
        };
        if history.is_empty() {
            return Ok(());
        }
        if history.len() < 2 {
            return Err("Raku replacement history underflow".into());
        }
        history.pop();
        let previous = history.last().ok_or("missing Raku predecessor")?.clone();
        s.revision = s.revision.checked_add(1).ok_or(Error::TotalLimit)?;
        self.tick(1, size_of::<Replacement>() + previous.name.len() + 32)?;
        let mut previous = (*previous).clone();
        previous.push_state = false;
        previous.pop_state = false;
        previous.restore = true;
        self.replace_rule(s, Arc::new(previous))
    }
    pub(super) fn raku_actions(
        &mut self,
        s: &mut State,
        actions: &[Action],
        depth: usize,
    ) -> Result<()> {
        for action in actions {
            self.tick(1, 0)?;
            match action {
                Action::Pop => {
                    let n = s
                        .stack
                        .len()
                        .checked_sub(1)
                        .ok_or("Raku state pop underflow")?;
                    s.stack.truncate(n);
                }
                Action::Static(value) => self.mutate(value, s, depth + 1)?,
                Action::Restore(config) => self.restore_rule(s, config)?,
            }
        }
        Ok(())
    }
}
