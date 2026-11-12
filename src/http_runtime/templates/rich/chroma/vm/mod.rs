// Behavioral port of regexp2 v2.2.1 bytecode runner (MIT).
mod characters;
mod control;
pub mod op;
mod validate;
use super::captures::{Captures, Error as CaptureError};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{Duration, Instant},
};
#[derive(Debug)]
pub enum Error {
    RuleLimit,
    Cancelled,
    TotalLimit,
    Invalid(String),
    Template(gotmpl::TemplateError),
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}
impl From<&str> for Error {
    fn from(x: &str) -> Self {
        Self::Invalid(x.to_owned())
    }
}
impl From<String> for Error {
    fn from(x: String) -> Self {
        Self::Invalid(x)
    }
}
fn capture_error(error: CaptureError) -> Error {
    match error {
        CaptureError::Resource => Error::TotalLimit,
        CaptureError::Invalid(x) | CaptureError::Charge(x) => Error::Invalid(x),
    }
}
pub type Result<T> = std::result::Result<T, Error>;
fn null_default<'de, D: serde::Deserializer<'de>, T: Deserialize<'de> + Default>(
    d: D,
) -> std::result::Result<T, D::Error> {
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}
#[derive(Clone, Copy, PartialEq)]
enum ParameterKind {
    Literal,
    Substitution,
    Pod,
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Program {
    pub pattern: String,
    pub codes: Vec<i32>,
    #[serde(deserialize_with = "null_default")]
    pub strings: Vec<Vec<i32>>,
    pub sets: Vec<usize>,
    pub track: usize,
    pub caps: BTreeMap<i32, usize>,
    pub capsize: usize,
    #[serde(deserialize_with = "null_default")]
    pub capnames: BTreeMap<String, i32>,
    #[serde(deserialize_with = "null_default")]
    pub caplist: Vec<String>,
    pub anchors: i32,
    #[serde(default)]
    pub options: i32,
    #[serde(default)]
    pub first_set: Option<usize>,
    #[serde(default)]
    pub first_ci: bool,
    #[serde(default)]
    pub min_required: usize,
    #[serde(skip)]
    starts: Vec<bool>,
    #[serde(skip)]
    conditional: bool,
    #[serde(skip)]
    parameter_kind: Option<ParameterKind>,
    #[serde(skip)]
    parameter_slots: Vec<usize>,
    #[serde(skip)]
    validated: bool,
}
impl Program {
    /// Necessary conditions exported by the pinned compiler, never a replacement
    /// for executing the bytecode. Conditional patterns keep the unfiltered path.
    pub fn may_start(&self, db: &Database, text: &[i32], pos: usize) -> bool {
        // Parameter templates execute at the caller's position. Their compiler
        // prefixes refer to marker literals and cannot reject substituted text.
        if self.parameter_kind.is_some() || self.conditional || self.options & 64 != 0 {
            return true;
        }
        if text.len().saturating_sub(pos) < self.min_required {
            return false;
        }
        let Some(index) = self.first_set else {
            return true;
        };
        let Some(&ch) = text.get(pos) else {
            return false;
        };
        let ranges = &db.sets[index];
        contains(ranges, ch)
            || (self.first_ci && {
                let lower = db
                    .lower
                    .binary_search_by_key(&ch, |&(key, _)| key)
                    .map_or(ch, |i| db.lower[i].1);
                contains(ranges, lower)
            })
    }
}
#[derive(Deserialize)]
pub struct Database {
    pub programs: Vec<Program>,
    pub sets: Vec<Vec<(i32, i32)>>,
    pub lower: Vec<(i32, i32)>,
    pub word: Vec<(i32, i32)>,
    pub ecma_word: Vec<(i32, i32)>,
    pub unicode_version: String,
    #[serde(default)]
    pub lexers: Vec<super::lexer::Definition>,
    #[serde(default)]
    pub registry_names: BTreeMap<String, usize>,
    #[serde(default)]
    pub registry_aliases: BTreeMap<String, usize>,
    #[serde(default)]
    pub registry_order: Vec<usize>,
    #[serde(default)]
    pub dynamic_programs: BTreeMap<String, usize>,
}
fn contains(ranges: &[(i32, i32)], ch: i32) -> bool {
    let i = ranges.partition_point(|(_, end)| *end < ch);
    ranges
        .get(i)
        .is_some_and(|(start, end)| *start <= ch && ch <= *end)
}
mod budget;
pub use budget::Budget;
use budget::Scope;
#[derive(Default)]
struct Stack {
    values: Vec<i32>,
    pos: usize,
}
impl Stack {
    fn grow(&mut self, b: &mut Scope<'_>) -> Result<()> {
        let old = self.values.len();
        let new = old.checked_mul(2).ok_or(Error::TotalLimit)?.max(32);
        if new > i32::MAX as usize {
            return Err(Error::TotalLimit);
        }
        b.charge(old as u64, new.checked_mul(4).ok_or(Error::TotalLimit)?)?;
        self.values
            .try_reserve_exact(new - old)
            .map_err(|_| Error::TotalLimit)?;
        self.values.resize(new, 0);
        self.values.copy_within(0..old, new - old);
        self.pos += new - old;
        Ok(())
    }
    fn push(&mut self, v: i32, b: &mut Scope<'_>) -> Result<()> {
        if self.pos == 0 {
            self.grow(b)?;
        }
        self.pos -= 1;
        self.values[self.pos] = v;
        Ok(())
    }
    fn pop(&mut self, n: usize) -> Result<()> {
        let p = self.pos.checked_add(n).ok_or("stack pop overflow")?;
        if p > self.values.len() {
            return Err("stack underflow".into());
        }
        self.pos = p;
        Ok(())
    }
    fn peek(&self, n: usize) -> Result<i32> {
        let i = self.pos.checked_sub(n + 1).ok_or("stack peek underflow")?;
        self.values
            .get(i)
            .copied()
            .ok_or_else(|| "stack peek out of range".into())
    }
    fn height(&self) -> i32 {
        i32::try_from(self.values.len() - self.pos).expect("budgeted stack fits i32")
    }
    fn set_height(&mut self, n: i32) -> Result<()> {
        let n = usize::try_from(n).map_err(|_| "negative stack height")?;
        self.pos = self
            .values
            .len()
            .checked_sub(n)
            .ok_or("stack height out of range")?;
        Ok(())
    }
}
#[derive(Debug)]
pub(super) enum Step {
    Continue,
    Backtrack,
    Stop,
    NotHandled,
}
pub type LiteralOverrides = [(usize, Arc<[i32]>)];
pub struct Runner<'a, 'b> {
    db: &'a Database,
    program: &'a Program,
    text: &'a [i32],
    pos: i32,
    start: i32,
    end: i32,
    codepos: usize,
    operator: i32,
    case_insensitive: bool,
    right_to_left: bool,
    track: Stack,
    stack: Stack,
    captures: Captures,
    rule_deadline: Instant,
    rule_ticks: u64,
    literal_overrides: Option<&'a LiteralOverrides>,
    budget: Scope<'b>,
}
impl<'a, 'b> Runner<'a, 'b> {
    pub fn new(
        db: &'a Database,
        program: &'a Program,
        text: &'a [i32],
        start: usize,
        budget: &'b mut Budget,
    ) -> Result<Self> {
        if !program.validated || start > text.len() {
            return Err("invalid regex initial state".into());
        }
        let end = i32::try_from(text.len())
            .ok()
            .filter(|n| *n < i32::MAX)
            .ok_or(Error::TotalLimit)?;
        let start = i32::try_from(start).map_err(|_| Error::TotalLimit)?;
        let mut budget = Scope::new(budget);
        let mut failure = None;
        let captures = Captures::new(program.capsize, usize::MAX, &mut |words| {
            budget
                .charge(
                    words as u64 / 8 + 1,
                    words.checked_mul(4).ok_or(Error::TotalLimit).map_err(|e| {
                        failure = Some(e);
                        "capture overflow".to_owned()
                    })?,
                )
                .map_err(|e| {
                    failure = Some(e);
                    "capture budget".to_owned()
                })
        })
        .map_err(|e| {
            failure.unwrap_or_else(|| capture_error(e))
        })?;
        Ok(Self {
            db,
            program,
            text,
            pos: start,
            start,
            end,
            codepos: 0,
            operator: 0,
            case_insensitive: false,
            right_to_left: false,
            track: Stack::default(),
            stack: Stack::default(),
            captures,
            budget,
            rule_deadline: Instant::now() + Duration::from_millis(250),
            rule_ticks: 0,
            literal_overrides: None,
        })
    }
    /// Substitute only compiler-verified Multi slots. Program and derived
    /// search metadata stay immutable; callers use the unfiltered at-pos path.
    pub fn set_literal_overrides(&mut self, literals: &'a LiteralOverrides) -> Result<()> {
        if literals.is_empty() {
            self.literal_overrides = None;
            return Ok(());
        }
        let kind = self
            .program
            .parameter_kind
            .ok_or("regex is not a verified parameter template")?;
        if literals.len() != self.program.parameter_slots.len() {
            return Err("invalid parameter template arity".into());
        }
        for (i, (slot, text)) in literals.iter().enumerate() {
            if !self.program.parameter_slots.contains(slot)
                || literals[..i].iter().any(|(previous, _)| previous == slot)
            {
                return Err("duplicate or nonparameter literal slot".into());
            }
            self.rule_charge(text.len() as u64 + 1, 0)?;
            if text.iter().any(|ch| !(0..=0x10ffff).contains(ch) || (0xd800..=0xdfff).contains(ch)) {
                return Err("invalid regex literal rune".into());
            }
            if kind != ParameterKind::Pod && text.is_empty() {
                return Err("empty dynamic Raku delimiter".into());
            }
        }
        if kind == ParameterKind::Pod {
            let prefix = literals
                .iter()
                .find(|(slot, _)| *slot == self.program.parameter_slots[0])
                .ok_or("missing pod prefix")?
                .1
                .as_ref();
            let name = literals
                .iter()
                .find(|(slot, _)| *slot == self.program.parameter_slots[1])
                .ok_or("missing pod name")?
                .1
                .as_ref();
            let ws = prefix
                .strip_suffix(&[61, 101, 110, 100])
                .ok_or("invalid pod marker prefix")?;
            let first = *name.first().ok_or("empty pod name")?;
            let local = *self
                .program
                .sets
                .first()
                .ok_or("missing pod whitespace set")?;
            if ws.iter().any(|ch| *ch != 32) || contains(&self.db.sets[local], first) {
                return Err("pod template literal violates compiler preconditions".into());
            }
        }
        self.literal_overrides = Some(literals);
        Ok(())
    }
    fn rule_charge(&mut self, steps: u64, bytes: usize) -> Result<()> {
        self.budget.charge(steps, bytes)?;
        self.rule_ticks = self.rule_ticks.saturating_add(steps);
        if self.rule_ticks >= 128 {
            self.rule_ticks = 0;
            if Instant::now() > self.rule_deadline {
                return Err(Error::RuleLimit);
            }
        }
        Ok(())
    }
    pub fn execute(&mut self) -> Result<bool> {
        self.go_to(0)?;
        loop {
            self.rule_charge(1, 0)?;
            let step = self.control()?;
            let step = if matches!(step, Step::NotHandled) {
                self.characters()?
            } else {
                step
            };
            match step {
                Step::Continue => {}
                Step::Stop => {
                    if Instant::now() > self.rule_deadline {
                        return Err(Error::RuleLimit);
                    }
                    let matched = self.captures.is_matched(0);
                    if matched {
                        let mut failure = None;
                        self.captures
                            .tidy(&mut |steps| {
                                self.budget.charge(steps as u64, 0).map_err(|e| {
                                    failure = Some(e);
                                    "capture tidy budget".to_owned()
                                })
                            })
                            .map_err(|e| failure.unwrap_or_else(|| capture_error(e)))?;
                    }
                    return Ok(matched);
                }
                Step::Backtrack => {
                    if self.track.height() == 0 {
                        return Ok(false);
                    }
                    self.backtrack()?;
                }
                Step::NotHandled => {
                    return Err(Error::Invalid(format!(
                        "unknown regexp opcode {}",
                        self.operator
                    )));
                }
            }
        }
    }
    pub fn captured(&self, slot: usize) -> Result<Option<(usize, usize)>> {
        self.captures.last(slot).map_err(capture_error)
    }
    fn operand(&self, n: usize) -> Result<i32> {
        self.program
            .codes
            .get(self.codepos + n + 1)
            .copied()
            .ok_or_else(|| "opcode operand out of range".into())
    }
    fn set_operator(&mut self, op: i32) {
        self.case_insensitive = op & op::CI != 0;
        self.right_to_left = op & op::RTL != 0;
        self.operator = op & !(op::CI | op::RTL);
    }
    fn go_to(&mut self, pc: i32) -> Result<()> {
        let pc = usize::try_from(pc).map_err(|_| "negative regex program counter")?;
        if self.program.starts.get(pc) != Some(&true) {
            return Err("regex program counter is not an instruction boundary".into());
        }
        let op = *self
            .program
            .codes
            .get(pc)
            .ok_or("regex program counter out of range")?;
        self.set_operator(op);
        self.codepos = pc;
        Ok(())
    }
    fn advance(&mut self, n: usize) -> Result<()> {
        let pc = self
            .codepos
            .checked_add(n + 1)
            .ok_or("program counter overflow")?;
        self.go_to(i32::try_from(pc).map_err(|_| "program counter overflow")?)
    }
    fn text_pos(&self) -> i32 {
        self.pos
    }
    fn text_start(&self) -> i32 {
        self.start
    }
    fn text_to(&mut self, pos: i32) -> Result<()> {
        if pos < 0 || pos > self.end {
            return Err("text position out of range".into());
        }
        self.pos = pos;
        Ok(())
    }
    fn track_pos(&self) -> i32 {
        self.track.height()
    }
    fn crawl_pos(&self) -> i32 {
        self.captures.crawl_pos() as i32
    }
    fn track_to(&mut self, n: i32) -> Result<()> {
        self.track.set_height(n)
    }
    fn track_push(&mut self) -> Result<()> {
        self.track.push(self.codepos as i32, &mut self.budget)
    }
    fn track_push1(&mut self, a: i32) -> Result<()> {
        self.track.push(a, &mut self.budget)?;
        self.track_push()
    }
    fn track_push2(&mut self, a: i32, b: i32) -> Result<()> {
        self.track.push(a, &mut self.budget)?;
        self.track.push(b, &mut self.budget)?;
        self.track_push()
    }
    fn track_push3(&mut self, a: i32, b: i32, c: i32) -> Result<()> {
        self.track.push(a, &mut self.budget)?;
        self.track.push(b, &mut self.budget)?;
        self.track.push(c, &mut self.budget)?;
        self.track_push()
    }
    fn track_push_neg1(&mut self, a: i32) -> Result<()> {
        self.track.push(a, &mut self.budget)?;
        self.track.push(-(self.codepos as i32), &mut self.budget)
    }
    fn track_push_neg2(&mut self, a: i32, b: i32) -> Result<()> {
        self.track.push(a, &mut self.budget)?;
        self.track.push(b, &mut self.budget)?;
        self.track.push(-(self.codepos as i32), &mut self.budget)
    }
    fn track_pop(&mut self) -> Result<()> {
        self.track.pop(1)
    }
    fn track_pop_n(&mut self, n: usize) -> Result<()> {
        self.track.pop(n)
    }
    fn track_peek(&self) -> Result<i32> {
        self.track.peek(0)
    }
    fn track_peek_n(&self, n: usize) -> Result<i32> {
        self.track.peek(n)
    }
    fn stack_push(&mut self, a: i32) -> Result<()> {
        self.stack.push(a, &mut self.budget)
    }
    fn stack_push2(&mut self, a: i32, b: i32) -> Result<()> {
        self.stack.push(a, &mut self.budget)?;
        self.stack.push(b, &mut self.budget)
    }
    fn stack_pop(&mut self) -> Result<()> {
        self.stack.pop(1)
    }
    fn stack_pop_n(&mut self, n: usize) -> Result<()> {
        self.stack.pop(n)
    }
    fn stack_peek(&self) -> Result<i32> {
        self.stack.peek(0)
    }
    fn stack_peek_n(&self, n: usize) -> Result<i32> {
        self.stack.peek(n)
    }
    fn backtrack(&mut self) -> Result<()> {
        self.track_pop()?;
        let pc = self.track_peek()?;
        let mode = if pc < 0 { op::BACK2 } else { op::BACK };
        let pc = pc.checked_abs().ok_or("regex program counter overflow")?;
        self.go_to(pc)?;
        self.set_operator(self.program.codes[pc as usize] | mode);
        Ok(())
    }
    fn is_matched(&self, slot: i32) -> bool {
        usize::try_from(slot)
            .ok()
            .is_some_and(|n| self.captures.is_matched(n))
    }
    fn capture(&mut self, slot: i32, start: i32, end: i32) -> Result<()> {
        let slot = usize::try_from(slot).map_err(|_| "negative capture slot")?;
        let mut failure = None;
        let result = self.captures.capture(slot, start, end, &mut |words| {
            self.budget
                .charge(
                    1,
                    words.checked_mul(4).ok_or(Error::TotalLimit).map_err(|e| {
                        failure = Some(e);
                        "capture overflow".to_owned()
                    })?,
                )
                .map_err(|e| {
                    failure = Some(e);
                    "capture budget".to_owned()
                })
        });
        result.map_err(|e| failure.unwrap_or_else(|| capture_error(e)))
    }
    fn transfer_capture(&mut self, cap: i32, uncap: i32, start: i32, end: i32) -> Result<()> {
        let uncap = usize::try_from(uncap).map_err(|_| "negative capture slot")?;
        let mut failure = None;
        let result = self
            .captures
            .transfer(cap, uncap, start, end, &mut |words| {
                self.budget
                    .charge(
                        1,
                        words.checked_mul(4).ok_or(Error::TotalLimit).map_err(|e| {
                            failure = Some(e);
                            "capture overflow".to_owned()
                        })?,
                    )
                    .map_err(|e| {
                        failure = Some(e);
                        "capture budget".to_owned()
                    })
            });
        result.map_err(|e| failure.unwrap_or_else(|| capture_error(e)))
    }
    fn uncapture(&mut self) -> Result<()> {
        self.budget.charge(1, 0)?;
        self.captures.uncapture().map_err(capture_error)
    }
    fn left_chars(&self) -> i32 {
        self.pos
    }
    fn right_chars(&self) -> i32 {
        self.end - self.pos
    }
    fn forward_chars(&self) -> i32 {
        if self.right_to_left {
            self.pos
        } else {
            self.end - self.pos
        }
    }
    fn bump(&self) -> i32 {
        if self.right_to_left { -1 } else { 1 }
    }
    fn char_at(&self, pos: i32) -> Result<i32> {
        let pos = usize::try_from(pos).map_err(|_| "negative rune offset")?;
        self.text
            .get(pos)
            .copied()
            .ok_or_else(|| "rune offset out of range".into())
    }
    fn forward_char_next(&mut self) -> Result<i32> {
        self.rule_charge(1, 0)?;
        let pos = if self.right_to_left {
            self.pos - 1
        } else {
            self.pos
        };
        let ch = self.char_at(pos)?;
        self.pos += self.bump();
        Ok(ch)
    }
    fn backward_next(&mut self) -> Result<()> {
        self.text_to(self.pos - self.bump())
    }
    fn set_char_in(&self, local: i32, ch: i32) -> Result<bool> {
        let local = usize::try_from(local).map_err(|_| "negative regex set index")?;
        let global = *self
            .program
            .sets
            .get(local)
            .ok_or("regex set index out of range")?;
        Ok(contains(
            self.db
                .sets
                .get(global)
                .ok_or("regex global set index out of range")?,
            ch,
        ))
    }
    fn lower(&self, ch: i32) -> i32 {
        let at = self.db.lower.binary_search_by_key(&ch, |x| x.0);
        at.map_or(ch, |i| self.db.lower[i].1)
    }
    fn is_boundary(&self, pos: i32, ecma: bool) -> bool {
        let ranges = if ecma {
            &self.db.ecma_word
        } else {
            &self.db.word
        };
        let before = pos > 0 && contains(ranges, self.text[(pos - 1) as usize]);
        let after = pos < self.end && contains(ranges, self.text[pos as usize]);
        before != after
    }
    fn is_ecma(&self) -> bool {
        self.program.options & 256 != 0
    }
    fn is_re2_or_ecma(&self) -> bool {
        self.program.options & (256 | 512) != 0
    }
    fn rune_match(&mut self, index: i32) -> Result<bool> {
        let index = usize::try_from(index).map_err(|_| "negative regex string index")?;
        let program = self.program;
        let string = self
            .literal_overrides
            .and_then(|values| {
                values
                    .iter()
                    .find(|(slot, _)| *slot == index)
                    .map(|(_, value)| value.as_ref())
            })
            .or_else(|| program.strings.get(index).map(Vec::as_slice))
            .ok_or("regex string index out of range")?;
        let n = i32::try_from(string.len()).map_err(|_| Error::TotalLimit)?;
        if self.forward_chars() < n {
            return Ok(false);
        }
        let mut pos = if self.right_to_left {
            self.pos
        } else {
            self.pos + n
        };
        for expected in string.iter().rev() {
            self.rule_charge(1, 0)?;
            pos -= 1;
            let actual = self.char_at(pos)?;
            if *expected
                != if self.case_insensitive {
                    self.lower(actual)
                } else {
                    actual
                }
            {
                return Ok(false);
            }
        }
        self.pos = if self.right_to_left { pos } else { pos + n };
        Ok(true)
    }
    fn last_capture(&self, slot: i32) -> Result<Option<(i32, i32)>> {
        let slot = usize::try_from(slot).map_err(|_| "negative capture slot")?;
        self.captured(slot)?
            .map(|(i, n)| {
                Ok((
                    i32::try_from(i).map_err(|_| Error::TotalLimit)?,
                    i32::try_from(n).map_err(|_| Error::TotalLimit)?,
                ))
            })
            .transpose()
    }
    fn ref_match(&mut self, start: i32, n: i32) -> Result<bool> {
        if n < 0 || start < 0 || start.checked_add(n).is_none_or(|end| end > self.end) {
            return Err("invalid regex backreference".into());
        }
        if self.forward_chars() < n {
            return Ok(false);
        }
        let mut pos = if self.right_to_left {
            self.pos
        } else {
            self.pos + n
        };
        let mut other = start + n;
        for _ in 0..n {
            self.rule_charge(1, 0)?;
            pos -= 1;
            other -= 1;
            let mut a = self.char_at(pos)?;
            let mut b = self.char_at(other)?;
            if self.case_insensitive {
                a = self.lower(a);
                b = self.lower(b)
            }
            if a != b {
                return Ok(false);
            }
        }
        self.pos = if self.right_to_left { pos } else { pos + n };
        Ok(true)
    }
    fn update_bumpalong(&mut self) -> Result<()> {
        let x = self
            .track
            .values
            .last_mut()
            .ok_or("regex root tracking state missing")?;
        *x = (*x).max(self.pos);
        Ok(())
    }
}
pub fn decode_input(bytes: &[u8], budget: &mut Budget) -> Result<Vec<i32>> {
    budget.charge(
        bytes.len() as u64,
        bytes.len().checked_mul(4).ok_or(Error::TotalLimit)?,
    )?;
    let mut out = Vec::new();
    out.try_reserve_exact(bytes.len())
        .map_err(|_| Error::TotalLimit)?;
    let mut rest = bytes;
    while !rest.is_empty() {
        match std::str::from_utf8(rest) {
            Ok(s) => {
                out.extend(s.chars().map(|x| x as i32));
                break;
            }
            Err(e) => {
                let valid = e.valid_up_to();
                if valid > 0 {
                    out.extend(
                        std::str::from_utf8(&rest[..valid])
                            .map_err(|_| "UTF8 validation inconsistency")?
                            .chars()
                            .map(|x| x as i32),
                    );
                    rest = &rest[valid..]
                } else {
                    out.push(0xfffd);
                    rest = &rest[1..]
                }
            }
        }
    }
    Ok(out)
}
