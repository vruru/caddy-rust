// Copyright The Go Authors. BSD-3-Clause.
// Go 1.27.3 regexp parsing and byte-level expansion with a native linear matcher.
#[path = "go_regexp/syntax.rs"]
mod syntax;
#[path = "go_regexp/unicode.rs"]
mod unicode;

use anyhow::{Result, anyhow, ensure};
use regex_automata::{Input, MatchKind, meta, nfa::thompson};
use std::{borrow::Cow, collections::BTreeMap, fmt, ops::Range, sync::Arc, time::Instant};

const MAX_PATTERN_MEMORY: usize = 32 << 20;
const MAX_INPUT_BYTES: usize = 8 << 20;
const MAX_SEARCH_MEMORY: usize = 8 << 20;
const MAX_SINGLE_SEARCH_WORK: usize = 64 << 20;
const HYBRID_CACHE: usize = 64 << 10;

#[derive(Debug)]
pub(crate) enum OperationError {
    ByteLimit,
    WorkLimit,
    Allocation,
    MatchInvariant,
}
impl fmt::Display for OperationError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str(match self {
            Self::ByteLimit => "regexp byte limit exceeded",
            Self::WorkLimit => "regexp work deadline exceeded",
            Self::Allocation => "regexp allocation failed",
            Self::MatchInvariant => "regexp match did not land on an input rune boundary",
        })
    }
}
impl std::error::Error for OperationError {}

/// Compile-time allocation and runtime match data stay on the native side.
pub(crate) struct GoRegexp {
    native: meta::Regex,
    names: Vec<Option<Box<str>>>,
    memory: usize,
    search_memory: usize,
    states: usize,
    maximum_match: Option<usize>,
    identity: Arc<()>,
}
impl GoRegexp {
    pub(crate) fn compile(pattern: &str, memory_limit: usize) -> Result<Self> {
        let limit = memory_limit.min(MAX_PATTERN_MEMORY);
        ensure!(limit >= 1024, "regexp compile memory limit too small");
        let syntax::Translated { pattern, names } = syntax::translate(pattern, limit)?;
        let hir = regex_syntax::ParserBuilder::new()
            .utf8(true)
            .nest_limit(3_100)
            .build()
            .parse(&pattern)
            .map_err(|_| anyhow!("regexp compilation failed after native translation"))?;
        let maximum_match = hir.properties().maximum_len();
        // PikeVM allocates two state×capture-slot tables at cache creation.
        // Bound them using the same Thompson NFA before constructing meta,
        // which can construct its initial pooled cache eagerly.
        let proof = thompson::NFA::compiler()
            .configure(thompson::Config::new().nfa_size_limit(Some(limit)))
            .build_from_hir(&hir)
            .map_err(|_| anyhow!("regexp native state limit exceeded"))?;
        let states = proof.states().len();
        let slots = proof.group_info().slot_len();
        let search_memory = states
            .checked_mul(slots)
            .and_then(|n| n.checked_add(slots))
            .and_then(|n| n.checked_mul(2 * std::mem::size_of::<usize>()))
            // Sparse sets, epsilon stack, alternate strategies, and the two
            // lazy DFA caches. Charge to a real per-event workspace permit.
            .and_then(|n| n.checked_add(states.saturating_mul(128)))
            .and_then(|n| n.checked_add(proof.memory_usage().saturating_mul(2)))
            .and_then(|n| n.checked_add(8 * HYBRID_CACHE))
            .filter(|n| *n <= MAX_SEARCH_MEMORY)
            .ok_or_else(|| anyhow!("regexp native search memory limit exceeded"))?;
        drop(proof);
        let native = meta::Regex::builder()
            .configure(
                meta::Config::new()
                    .match_kind(MatchKind::LeftmostFirst)
                    .utf8_empty(true)
                    .nfa_size_limit(Some(limit))
                    .onepass_size_limit(Some(limit.min(1 << 20)))
                    .dfa_size_limit(Some(limit.min(1 << 20)))
                    .hybrid_cache_capacity(HYBRID_CACHE),
            )
            .build_from_hir(&hir)
            .map_err(|_| anyhow!("regexp native engine preparation failed"))?;
        // HIR simplification may erase trailing groups inside {0} or a
        // match-nothing branch. Retain Go's declared names/indices; the
        // removed capture is simply never populated.
        ensure!(
            native.captures_len() <= names.len(),
            "regexp translation changed capture group numbering"
        );
        let names_size = names
            .iter()
            .try_fold(
                names.capacity() * std::mem::size_of::<Option<Box<str>>>(),
                |n, v| n.checked_add(v.as_ref().map_or(0, |name| name.len())),
            )
            .ok_or_else(|| anyhow!("regexp compiled capture size overflow"))?;
        let memory = native
            .memory_usage()
            .checked_add(names_size)
            .filter(|n| *n <= limit)
            .ok_or_else(|| anyhow!("regexp compiled memory limit exceeded"))?;
        Ok(Self {
            native,
            names,
            memory,
            search_memory,
            states,
            maximum_match,
            identity: Arc::new(()),
        })
    }
    pub(crate) fn search_memory(&self) -> usize {
        self.search_memory
    }
    pub(crate) fn memory_usage(&self) -> usize {
        self.memory
    }
    /// A bounded-width expression can safely scan large inputs in overlapping
    /// windows. The whole input is retained for assertions (anchors and word
    /// boundaries), and a match is never accepted in the overlap. An unbounded
    /// expression cannot be shortened without changing its greedy result.
    fn search_captures(
        &self,
        text: &str,
        mut at: usize,
        cache: &mut meta::Cache,
        caps: &mut regex_automata::util::captures::Captures,
        budget: &ReplaceBudget,
    ) -> std::result::Result<bool, OperationError> {
        let end = text.len();
        let width = (MAX_SINGLE_SEARCH_WORK / self.states.max(1)).saturating_sub(1);
        loop {
            budget.check()?;
            let (next, limit) = if end - at <= width {
                (None, end)
            } else {
                let keep = self.maximum_match.ok_or(OperationError::WorkLimit)?;
                let step = width
                    .checked_sub(keep.saturating_add(4))
                    .ok_or(OperationError::WorkLimit)?;
                let next = text.floor_char_boundary(at + step);
                if next <= at {
                    return Err(OperationError::WorkLimit);
                }
                (Some(next), text.floor_char_boundary(at + width))
            };
            self.native.search_captures_with(
                cache,
                &Input::new(text.as_bytes()).span(at..limit),
                caps,
            );
            budget.check()?;
            if cache.memory_usage() > self.search_memory {
                return Err(OperationError::MatchInvariant);
            }
            let matched = caps.get_group(0);
            if let Some(next) = next {
                if matched.is_some_and(|m| m.start < next) {
                    return Ok(true);
                }
                at = next;
            } else {
                return Ok(matched.is_some());
            }
        }
    }
    pub(crate) fn replace_all(
        &self,
        original: &[u8],
        replacement: &Replacement,
        cap: usize,
        truncate: bool,
        budget: &mut ReplaceBudget,
    ) -> std::result::Result<Vec<u8>, OperationError> {
        budget.check()?;
        if !Arc::ptr_eq(&self.identity, &replacement.identity) {
            return Err(OperationError::MatchInvariant);
        }
        let input = Normalized::new(original, budget)?;
        let mut output = Output {
            bytes: Vec::new(),
            cap,
            truncate,
        };
        let mut caps = self.native.create_captures();
        let mut cache = self.native.create_cache();
        let mut named = vec![None; replacement.named.len()];
        let (mut last, mut at) = (0usize, 0usize);
        let end = input.text.len();
        while at <= end {
            budget.check()?;
            if !self.search_captures(&input.text, at, &mut cache, &mut caps, budget)? {
                break;
            }
            let m = caps.get_group(0).ok_or(OperationError::MatchInvariant)?;
            let from = input.original_offset(last)?;
            let to = input.original_offset(m.start)?;
            output.add(
                original
                    .get(from..to)
                    .ok_or(OperationError::MatchInvariant)?,
            )?;
            if m.end > last || m.start == 0 {
                replacement.append(original, &input, &caps, &mut named, &mut output, budget)?;
            }
            last = m.end;
            if output.is_full_prefix() {
                budget.check()?;
                return Ok(output.bytes);
            }
            let width = input
                .text
                .get(at..)
                .ok_or(OperationError::MatchInvariant)?
                .chars()
                .next()
                .map_or(0, char::len_utf8);
            at = (at + width.max(1)).max(m.end);
        }
        budget.check()?;
        output.add(
            original
                .get(input.original_offset(last)?..)
                .ok_or(OperationError::MatchInvariant)?,
        )?;
        Ok(output.bytes)
    }
}
/// A logging filter can reuse this across all operations and array elements.
pub(crate) struct ReplaceBudget {
    scratch: usize,
    deadline: Option<Instant>,
}
impl ReplaceBudget {
    pub(crate) fn new(scratch: usize, deadline: Option<Instant>) -> Self {
        Self { scratch, deadline }
    }
    fn check(&self) -> std::result::Result<(), OperationError> {
        if self.deadline.is_some_and(|d| Instant::now() >= d) {
            return Err(OperationError::WorkLimit);
        }
        Ok(())
    }
}
struct Output {
    bytes: Vec<u8>,
    cap: usize,
    truncate: bool,
}
impl Output {
    fn add(&mut self, s: &[u8]) -> std::result::Result<(), OperationError> {
        let avail = self.cap - self.bytes.len();
        if s.len() > avail && !self.truncate {
            return Err(OperationError::ByteLimit);
        }
        let n = s.len().min(avail);
        let required = self.bytes.len() + n;
        if required > self.bytes.capacity() {
            let grown = self
                .bytes
                .capacity()
                .saturating_mul(2)
                .max(32)
                .min(self.cap)
                .max(required);
            self.bytes
                .try_reserve_exact(grown - self.bytes.len())
                .map_err(|_| OperationError::Allocation)?;
        }
        self.bytes.extend_from_slice(&s[..n]);
        Ok(())
    }
    fn is_full_prefix(&self) -> bool {
        self.truncate && self.bytes.len() == self.cap
    }
}
struct Normalized<'a> {
    text: Cow<'a, str>,
    invalid: Vec<u32>,
}
impl<'a> Normalized<'a> {
    fn new(
        original: &'a [u8],
        budget: &ReplaceBudget,
    ) -> std::result::Result<Self, OperationError> {
        if original.len() > MAX_INPUT_BYTES {
            return Err(OperationError::ByteLimit);
        }
        if let Ok(valid) = std::str::from_utf8(original) {
            return Ok(Self {
                text: valid.into(),
                invalid: Vec::new(),
            });
        }
        let mut rest = original;
        let mut bad = 0usize;
        // Invalid bytes need one RuneError (3 bytes) and one position
        // entry each. Stop counting as soon as no scratch allocation can fit.
        let max_bad = budget
            .scratch
            .checked_sub(original.len())
            .ok_or(OperationError::ByteLimit)?
            / (2 + std::mem::size_of::<u32>());
        while let Err(e) = std::str::from_utf8(rest) {
            bad += 1;
            if bad > max_bad {
                return Err(OperationError::ByteLimit);
            }
            if bad.is_multiple_of(1024) {
                budget.check()?;
            }
            rest = &rest[e.valid_up_to() + 1..];
        }
        let size = original.len() + 2 * bad;
        let mut text = String::new();
        let mut invalid = Vec::new();
        text.try_reserve_exact(size)
            .map_err(|_| OperationError::Allocation)?;
        invalid
            .try_reserve_exact(bad)
            .map_err(|_| OperationError::Allocation)?;
        let mut rest = original;
        loop {
            match std::str::from_utf8(rest) {
                Ok(valid) => {
                    text.push_str(valid);
                    break;
                }
                Err(e) => {
                    let (prefix, tail) = rest.split_at(e.valid_up_to());
                    text.push_str(
                        std::str::from_utf8(prefix).map_err(|_| OperationError::MatchInvariant)?,
                    );
                    invalid.push(u32::try_from(text.len()).map_err(|_| OperationError::ByteLimit)?);
                    if invalid.len().is_multiple_of(1024) {
                        budget.check()?;
                    }
                    text.push('\u{fffd}');
                    rest = &tail[1..];
                }
            }
        }
        Ok(Self {
            text: text.into(),
            invalid,
        })
    }
    fn original_offset(&self, at: usize) -> std::result::Result<usize, OperationError> {
        if !self.text.is_char_boundary(at) {
            return Err(OperationError::MatchInvariant);
        }
        let count = self.invalid.partition_point(|n| (*n as usize) < at);
        at.checked_sub(count * 2)
            .ok_or(OperationError::MatchInvariant)
    }
}

pub(crate) struct Replacement {
    text: Box<str>,
    parts: Vec<Part>,
    named: Vec<Vec<usize>>,
    identity: Arc<()>,
}
enum Part {
    Raw(Range<usize>),
    Dollar,
    Indexed(usize),
    Named(usize),
}
impl Replacement {
    pub(crate) fn compile(regex: &GoRegexp, text: String, budget: usize) -> Result<Self> {
        let mut parts = Vec::new();
        let mut lookup: BTreeMap<&str, (Vec<usize>, Option<usize>)> = BTreeMap::new();
        for (i, name) in regex.names.iter().enumerate() {
            if let Some(name) = name {
                lookup.entry(name.as_ref()).or_default().0.push(i);
            }
        }
        let mut named = Vec::new();
        let mut at = 0usize;
        let mut cost = text.len();
        let mut push = |part| {
            cost = cost
                .checked_add(std::mem::size_of::<Part>())
                .filter(|n| *n <= budget)
                .ok_or_else(|| anyhow!("regexp replacement workspace limit exceeded"))?;
            parts.push(part);
            Ok::<_, anyhow::Error>(())
        };
        while let Some(mark) = text[at..].find('$') {
            let mark = at + mark;
            if mark > at {
                push(Part::Raw(at..mark))?;
            }
            at = mark + 1;
            if text[at..].starts_with('$') {
                push(Part::Dollar)?;
                at += 1;
                continue;
            }
            if let Some((name, after)) = extract(&text, at) {
                at = after;
                let name = &text[name];
                if let Some(i) = parse_index(name) {
                    if i < regex.names.len() {
                        push(Part::Indexed(i))?;
                    }
                } else if let Some((groups, slot)) = lookup.get_mut(name) {
                    let index = *slot.get_or_insert_with(|| {
                        let i = named.len();
                        named.push(std::mem::take(groups));
                        i
                    });
                    push(Part::Named(index))?;
                }
            } else {
                push(Part::Dollar)?;
            }
        }
        if at < text.len() {
            push(Part::Raw(at..text.len()))?;
        }
        let result = Self {
            text: text.into_boxed_str(),
            parts,
            named,
            identity: regex.identity.clone(),
        };
        ensure!(
            result.memory_usage() <= budget,
            "regexp replacement memory limit exceeded"
        );
        Ok(result)
    }
    pub(crate) fn memory_usage(&self) -> usize {
        self.text.len()
            + self.parts.capacity() * std::mem::size_of::<Part>()
            + self.named.capacity() * std::mem::size_of::<Vec<usize>>()
            + self
                .named
                .iter()
                .map(|v| v.capacity() * std::mem::size_of::<usize>())
                .sum::<usize>()
    }
    fn append(
        &self,
        original: &[u8],
        input: &Normalized<'_>,
        caps: &regex_automata::util::captures::Captures,
        named: &mut [Option<regex_automata::Span>],
        out: &mut Output,
        budget: &mut ReplaceBudget,
    ) -> std::result::Result<(), OperationError> {
        for (i, (slot, groups)) in named.iter_mut().zip(&self.named).enumerate() {
            if i.is_multiple_of(64) {
                budget.check()?;
            }
            *slot = groups.iter().find_map(|&i| caps.get_group(i));
        }
        for (i, part) in self.parts.iter().enumerate() {
            if i % 64 == 0 {
                budget.check()?;
            }
            if out.is_full_prefix() {
                break;
            }
            let span = match part {
                Part::Raw(r) => {
                    out.add(self.text[r.clone()].as_bytes())?;
                    continue;
                }
                Part::Dollar => {
                    out.add(b"$")?;
                    continue;
                }
                Part::Indexed(i) => caps.get_group(*i),
                Part::Named(i) => named[*i],
            };
            if let Some(span) = span {
                let a = input.original_offset(span.start)?;
                let b = input.original_offset(span.end)?;
                out.add(original.get(a..b).ok_or(OperationError::MatchInvariant)?)?;
            }
        }
        Ok(())
    }
}
fn extract(text: &str, at: usize) -> Option<(Range<usize>, usize)> {
    let braced = text[at..].starts_with('{');
    let a = at + usize::from(braced);
    let len = text[a..]
        .char_indices()
        .find(|(_, c)| !unicode::is_name_character(*c))
        .map_or(text.len() - a, |(i, _)| i);
    if len == 0 {
        return None;
    }
    let end = a + len;
    if braced && !text[end..].starts_with('}') {
        return None;
    }
    Some((a..end, end + usize::from(braced)))
}
fn parse_index(name: &str) -> Option<usize> {
    if name.len() > 1 && name.starts_with('0') {
        return None;
    }
    let mut n = 0usize;
    for c in name.bytes() {
        if !c.is_ascii_digit() || n >= 100_000_000 {
            return None;
        }
        n = n * 10 + usize::from(c - b'0');
    }
    Some(n)
}
