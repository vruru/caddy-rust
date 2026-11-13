mod custom;
mod delegate;
mod haxe;
mod model;
mod primitive;
mod raku_brackets;
mod raku_emit;
mod raku_rules;
mod registry;
mod wrappers;
use super::vm::{self, Budget, Database, Error, Result};
pub use model::Definition;
use std::{
    collections::{BTreeMap, HashMap},
    mem::size_of,
    sync::Arc,
};
pub struct Registry {
    pub db: Database,
    pub max_caps: usize,
    globs: Vec<(Vec<registry::path_glob::CompiledGoGlob>, Vec<registry::path_glob::CompiledGoGlob>)>,
    raku_substitution_emitter: Arc<serde_json::Value>,
}
impl Registry {
    pub fn new(mut db: Database) -> Result<Self> {
        db.validate()?;
        {
            let programs: HashMap<&str, usize> = db
                .programs
                .iter()
                .enumerate()
                .map(|(i, p)| (p.pattern.as_str(), i))
                .collect();
            let count = db.lexers.len();
            for lexer in &mut db.lexers {
                for mapping in std::mem::take(&mut lexer.mapping) {
                    let table = lexer.mapping_lookup.entry(mapping.from).or_default();
                    if mapping.words.is_empty() {
                        table.insert(String::new(), mapping.to);
                    } else {
                        for word in mapping.words {
                            table.insert(word, mapping.to);
                        }
                    }
                }
                for rules in lexer.states.values_mut() {
                    for rule in rules {
                        rule.program_index = *programs
                            .get(rule.program.as_str())
                            .ok_or("missing compiled Chroma rule program")?;
                        rule.program.clear();
                        rule.program.shrink_to_fit();
                    }
                }
                for &child in &lexer.children {
                    if child >= count {
                        return Err("invalid Chroma child lexer".into());
                    }
                }
            }
        }
        if db.registry_names.is_empty()
            || db.registry_aliases.is_empty()
            || db.registry_order.is_empty()
        {
            return Err("missing Chroma registry lookup tables".into());
        }
        for id in db
            .registry_names
            .values()
            .chain(db.registry_aliases.values())
            .chain(db.registry_order.iter())
        {
            if *id >= db.lexers.len() {
                return Err("invalid Chroma registry entry".into());
            }
        }
        let max_caps = db.programs.iter().map(|p| p.capsize).max().unwrap_or(0);
        let globs = db
            .lexers
            .iter()
            .map(|lexer| {
                let primary = lexer
                    .config
                    .filenames
                    .iter()
                    .map(|pattern| {
                        registry::path_glob::compile_go_path_glob(pattern)
                            .ok_or("invalid generated Chroma filename pattern")
                    })
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                let aliases = lexer
                    .config
                    .alias_filenames
                    .iter()
                    .map(|pattern| {
                        registry::path_glob::compile_go_path_glob(pattern)
                            .ok_or("invalid generated Chroma filename alias")
                    })
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                Ok((primary, aliases))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            db,
            max_caps,
            globs,
            // Constant, immutable lexer metadata belongs to registry preparation,
            // not to a request's dynamic overlay allocation lane.
            raku_substitution_emitter: Arc::new(serde_json::json!({"type":"chroma.byGroupsEmitter","Emitters":[5000,{"type":"chroma.usingSelfEmitter","State":"qq"},5000]})),
        })
    }
}
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct Token {
    pub kind: i32,
    pub text: Vec<u8>,
}
pub struct Options {
    pub state: String,
    pub nested: bool,
    pub ensure_lf: bool,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            state: "root".into(),
            nested: false,
            ensure_lf: true,
        }
    }
}
pub struct State<'a> {
    pub text: &'a [i32],
    pub full_groups: Arc<Vec<Vec<u8>>>,
    pub named_groups: Arc<Vec<Vec<u8>>>,
    pub named_extra: Arc<BTreeMap<String, Vec<u8>>>,
    pub revision: u64,
    pub initial: String,
    pub lexer: usize,
    pub current: String,
    pub stack: Vec<String>,
    pub(super) stack_capacity: usize,
    pub(super) stack_identity: u64,
    pub(super) next_stack_identity: u64,
    haxe: Vec<haxe::SavedStack>,
    rule_stacks: raku_rules::History,
    pub program: usize,
    pub position: usize,
}
/// Conservative full-node reservation for pointer-aligned maps, based on
/// Rust 1.99.1 BTree capacity 11 and up to 12 child edges. Charging a node
/// per inserted entry also covers the first leaf and split intermediates.
fn map_node<K,V>()->Result<usize> {
    if std::mem::align_of::<K>().max(std::mem::align_of::<V>())>16{return Err(Error::TotalLimit);}
    size_of::<K>().checked_add(size_of::<V>()).and_then(|n|n.checked_mul(11)).and_then(|n|n.checked_add(128)).ok_or(Error::TotalLimit)
}
pub struct Engine<'a> {
    pub registry: &'a Registry,
    raku_overlays: BTreeMap<raku_rules::OverlayKey, Arc<raku_rules::DynamicRule>>,
    overlay_generation: u64,
    pub budget: Budget,
}
impl<'a> Engine<'a> {
    pub fn new(registry: &'a Registry, budget: Budget) -> Self {
        Self {
            registry,
            budget,
            raku_overlays: BTreeMap::new(),
            overlay_generation: 0,
        }
    }
    fn tick(&mut self, work: u64, bytes: usize) -> Result<()> {
        self.budget.charge(work, bytes)
    }
    /// Charge the complete new allocation while the old buffer is still live.
    /// Earlier capacities stay conservatively owned until the Engine ends.
    fn grow_vec<T>(&mut self,out:&mut Vec<T>,needed:usize)->Result<()> {
        if needed<=out.capacity(){return Ok(());}
        let capacity=needed.max(out.capacity().checked_mul(2).ok_or(Error::TotalLimit)?).max(4);
        let bytes=capacity.checked_mul(size_of::<T>()).ok_or(Error::TotalLimit)?;
        self.tick(out.len() as u64+1,bytes)?;
        let mut fresh=Vec::new();fresh.try_reserve_exact(capacity).map_err(|_|Error::TotalLimit)?;
        let actual=fresh.capacity().checked_mul(size_of::<T>()).ok_or(Error::TotalLimit)?;
        if actual>bytes {self.tick(0,actual-bytes)?;}
        fresh.append(out);drop(std::mem::replace(out,fresh));Ok(())
    }
    fn push_token(&mut self,kind:i32,bytes:&[u8],out:&mut Vec<Token>)->Result<()> {
        if kind==-14{return Ok(());}
        self.tick(bytes.len().div_ceil(16) as u64+1,0)?;
        self.grow_vec(out,out.len().checked_add(1).ok_or(Error::TotalLimit)?)?;
        let mut text=Vec::new();self.grow_vec(&mut text,bytes.len())?;
        text.extend_from_slice(bytes);out.push(Token{kind,text});Ok(())
    }
    fn append_tokens(&mut self,out:&mut Vec<Token>,mut tokens:Vec<Token>)->Result<()> {
        self.tick(tokens.len() as u64,0)?;
        self.grow_vec(out,out.len().checked_add(tokens.len()).ok_or(Error::TotalLimit)?)?;
        out.append(&mut tokens);Ok(())
    }
    fn push_state(&mut self, s: &mut State, name: &str) -> Result<()> {
        self.prepare_stack_push(s, name)?;
        self.tick(
            1,
            name.len()
                .checked_add(size_of::<String>())
                .ok_or(Error::TotalLimit)?,
        )?;
        let needed=s.stack.len().checked_add(1).ok_or(Error::TotalLimit)?;
        self.grow_vec(&mut s.stack,needed)?;
        s.stack.push(name.to_owned());
        Ok(())
    }
    fn bytes(&mut self, text: &[i32]) -> Result<Vec<u8>> {
        let mut size = 0usize;
        for &ch in text {
            let ch = char::from_u32(ch as u32).ok_or("invalid Chroma input rune")?;
            size = size.checked_add(ch.len_utf8()).ok_or(Error::TotalLimit)?;
        }
        self.tick(text.len() as u64, size)?;
        let mut out = Vec::new();
        out.try_reserve_exact(size).map_err(|_| Error::TotalLimit)?;
        for &ch in text {
            let ch = char::from_u32(ch as u32).ok_or("invalid Chroma input rune")?;
            let mut buf = [0u8; 4];
            out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
        }
        Ok(out)
    }
    pub fn lex_id(
        &mut self,
        id: usize,
        input: &[u8],
        options: Options,
        depth: usize,
    ) -> Result<Vec<Token>> {
        if depth > 250 {
            return Err(Error::TotalLimit);
        }
        let registry = self.registry;
        let lexer = registry
            .db
            .lexers
            .get(id)
            .ok_or("invalid Chroma lexer index")?;
        if lexer.kind != "*chroma.RegexLexer" {
            return self.wrapped(id, input, options, depth);
        }
        self.tick(1, input.len())?;
        let mut normalized = Vec::new();
        normalized
            .try_reserve_exact(input.len())
            .map_err(|_| Error::TotalLimit)?;
        if options.ensure_lf {
            for (i, &byte) in input.iter().enumerate() {
                if byte == b'\r' {
                    if input.get(i + 1) == Some(&b'\n') {
                        continue;
                    }
                    normalized.push(b'\n')
                } else {
                    normalized.push(byte)
                }
            }
        } else {
            normalized.extend_from_slice(input)
        }
        let mut text = vm::decode_input(&normalized, &mut self.budget)?;
        let added = !options.nested && lexer.config.ensure_n_l && text.last() != Some(&10);
        if added {
            self.tick(1, 4)?;
            text.try_reserve_exact(1).map_err(|_| Error::TotalLimit)?;
            text.push(10);
        }
        let end = text.len() - usize::from(added);
        self.tick(
            1,
            options
                .state
                .len()
                .checked_mul(2)
                .and_then(|n| n.checked_add(128))
                .ok_or(Error::TotalLimit)?,
        )?;
        let empty = Arc::new(Vec::new());
        let mut state = State {
            text: &text,
            full_groups: empty.clone(),
            named_groups: empty,
            named_extra: Arc::new(BTreeMap::new()),
            revision: 0,
            initial: options.state.clone(),
            lexer: id,
            current: options.state.clone(),
            stack: vec![options.state],
            stack_capacity: 1,
            stack_identity: 1,
            next_stack_identity: 1,
            haxe: Vec::new(),
            rule_stacks: BTreeMap::new(),
            program: 0,
            position: 0,
        };
        let max_caps = registry.max_caps;
        self.tick(
            1,
            max_caps
                .checked_mul(size_of::<Option<(usize, usize)>>())
                .ok_or(Error::TotalLimit)?,
        )?;
        let mut offsets = vec![None; max_caps];
        let mut out = Vec::new();
        let mut zw_seen: Vec<(Vec<String>, u64, u64)> = Vec::new();
        while state.position < end && !state.stack.is_empty() {
            self.tick(1, 0)?;
            let old_position = state.position;
            let current = state.stack.last().ok_or("missing Chroma state")?;
            self.tick(0, current.len())?;
            state.current = current.clone();
            let rules = lexer
                .states
                .get(&state.current)
                .ok_or("unknown Chroma state")?;
            let mut found = None;
            for (rule_index, rule) in rules.iter().enumerate() {
                let at_edge = rule_index == 0 || rule_index + 1 == rules.len();
                self.tick(
                    if at_edge {
                        self.raku_overlays.len() as u64 + 1
                    } else {
                        1
                    },
                    0,
                )?;
                let bottom = rule_index > 0;
                let dynamic = if at_edge {
                    self.raku_overlays
                        .iter()
                        .find(|((id, name, is_bottom), _)| {
                            *id == state.lexer && name == &state.current && *is_bottom == bottom
                        })
                        .map(|(_, rule)| rule.clone())
                } else {
                    None
                };
                let program_index = dynamic
                    .as_ref()
                    .map_or(rule.program_index, |rule| rule.program);
                let program = &registry.db.programs[program_index];
                if dynamic.is_none() && !program.may_start(&registry.db, &text, state.position) {
                    continue;
                }
                let mut runner = vm::Runner::new(
                    &registry.db,
                    program,
                    &text,
                    state.position,
                    &mut self.budget,
                )?;
                if let Some(rule) = &dynamic {
                    runner.set_literal_overrides(&rule.literals)?;
                }
                match runner.execute() {
                    Ok(true) => {
                        for (i, offset) in offsets[..program.capsize].iter_mut().enumerate() {
                            *offset = runner.captured(i)?;
                        }
                        drop(runner);
                        let emitter = dynamic
                            .as_ref()
                            .map_or_else(|| rule.emitter.clone(), |r| r.emitter.clone());
                        found = Some((program_index, emitter, rule.mutator.clone(), dynamic));
                        break;
                    }
                    Ok(false) | Err(Error::RuleLimit) => {}
                    Err(error) => return Err(error),
                }
            }
            let Some((program_index, emitter, mutator, dynamic)) = found else {
                if text[state.position] == 10 && state.current != state.initial {
                    self.reset_stack(&mut state)?;
                    continue;
                }
                let value = self.bytes(&text[state.position..state.position + 1])?;
                self.push_token(-11, &value, &mut out)?;
                state.position += 1;
                zw_seen.clear();
                continue;
            };
            let program = &registry.db.programs[program_index];
            self.tick(
                1,
                program
                    .capsize
                    .checked_mul(size_of::<Vec<u8>>())
                    .ok_or(Error::TotalLimit)?,
            )?;
            let mut groups = Vec::with_capacity(program.capsize);
            for offset in &offsets[..program.capsize] {
                groups.push(if let Some((start, length)) = offset {
                    let end = start
                        .checked_add(*length)
                        .filter(|end| *end <= text.len())
                        .ok_or("invalid Chroma capture range")?;
                    self.bytes(&text[*start..end])?
                } else {
                    Vec::new()
                });
            }
            state.program = program_index;
            state.position = offsets[0]
                .ok_or("missing Chroma root capture")?
                .0
                .checked_add(offsets[0].ok_or("missing Chroma root capture")?.1)
                .ok_or(Error::TotalLimit)?;
            self.tick(0, 40)?;
            let groups = Arc::new(groups);
            state.full_groups = groups.clone();
            state.named_groups = groups.clone();
            if let Some(extra) = Arc::get_mut(&mut state.named_extra) {
                extra.clear();
            } else {
                self.tick(0, 32)?;
                state.named_extra = Arc::new(BTreeMap::new());
            }
            if let Some(rule) = dynamic {
                self.raku_actions(&mut state, &rule.actions, depth)?;
            } else {
                self.mutate(&mutator, &mut state, depth)?;
            }
            let current_groups = state.full_groups.clone();
            self.emit(
                &emitter,
                current_groups.as_ref(),
                &mut state,
                &mut out,
                depth,
            )?;
            if state.position != old_position {
                zw_seen.clear();
            } else if !state.stack.is_empty() {
                let weight = state.stack.iter().try_fold(0u64, |n, name| {
                    n.checked_add((name.len() / 16 + 1) as u64)
                        .ok_or(Error::TotalLimit)
                })?;
                self.tick(
                    weight
                        .checked_mul(zw_seen.len() as u64)
                        .ok_or(Error::TotalLimit)?,
                    0,
                )?;
                if zw_seen.iter().any(|(stack, revision, generation)| {
                    *revision == state.revision
                        && *generation == self.overlay_generation
                        && *stack == state.stack
                }) {
                    let value = self.bytes(&text[state.position..state.position + 1])?;
                    self.push_token(-11, &value, &mut out)?;
                    state.position += 1;
                    zw_seen.clear();
                } else {
                    if zw_seen.len() >= 512 {
                        return Err(Error::TotalLimit);
                    }
                    let bytes = state.stack.iter().try_fold(
                        size_of::<(Vec<String>, u64, u64)>(),
                        |n, name| {
                            n.checked_add(size_of::<String>())
                                .and_then(|n| n.checked_add(name.len()))
                                .ok_or(Error::TotalLimit)
                        },
                    )?;
                    self.tick(state.stack.len() as u64, bytes)?;
                    zw_seen
                        .try_reserve_exact(1)
                        .map_err(|_| Error::TotalLimit)?;
                    zw_seen.push((state.stack.clone(), state.revision, self.overlay_generation));
                }
            }
        }
        if state.stack.is_empty() && state.position != text.len() {
            let value = self.bytes(
                text.get(state.position..)
                    .ok_or("invalid final Chroma position")?,
            )?;
            self.push_token(-11, &value, &mut out)?;
        }
        Ok(out)
    }
    pub fn highlight(&mut self, name: &[u8], input: &[u8]) -> Result<Option<Vec<Token>>> {
        let Some(id) = self.lookup(name)? else {
            return Ok(None);
        };
        self.tick(1, 28)?;
        let tokens = self.lex_id(id, input, Options::default(), 0)?;
        Ok(Some(self.coalesce(tokens)?))
    }
    fn coalesce(&mut self,tokens:Vec<Token>)->Result<Vec<Token>> {
        self.tick(tokens.len() as u64,0)?;
        let mut out:Vec<Token>=Vec::new();self.grow_vec(&mut out,tokens.len())?;
        for token in tokens {
            if token.text.is_empty(){continue;}
            if let Some(previous)=out.last_mut() && previous.kind==token.kind && previous.text.len()<8192 {
                self.tick(token.text.len().div_ceil(16) as u64+1,0)?;
                let needed=previous.text.len().checked_add(token.text.len()).ok_or(Error::TotalLimit)?;
                self.grow_vec(&mut previous.text,needed)?;previous.text.extend_from_slice(&token.text);
            }else{out.push(token)}
        }
        Ok(out)
    }
}
