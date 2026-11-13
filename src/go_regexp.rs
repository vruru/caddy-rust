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

/// Reuse Go's syntax normalization for native consumers with their own
/// bounded matching engine. The declared capture count includes group zero.
pub(crate) fn translate_native_pattern(
    pattern: &str,
    memory_limit: usize,
) -> Result<(String, usize)> {
    let limit = memory_limit.min(MAX_PATTERN_MEMORY);
    ensure!(limit >= 1024, "regexp compile memory limit too small");
    let translated = syntax::translate(pattern, limit)?;
    Ok((translated.pattern, translated.names.len()))
}

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

/// Scalar facts from the already-bounded Go syntax translation. No native
/// parser allocation has occurred when a preflight callback sees these values.
#[derive(Clone,Copy)]
pub(crate) struct NativeCompileSize{pub bytes:usize,pub nodes:usize,pub ranges:usize,pub captures:usize}
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
        Self::compile_preflight(pattern,memory_limit,|_|Ok(()))
    }
    /// Admit translated syntax before the native AST/HIR and engine allocate.
    /// Existing callers retain their original compiler through `compile`.
    pub(crate) fn compile_preflight(pattern:&str,memory_limit:usize,before_native:impl FnOnce(NativeCompileSize)->Result<()>)->Result<Self>{
        let limit = memory_limit.min(MAX_PATTERN_MEMORY);
        ensure!(limit >= 1024, "regexp compile memory limit too small");
        let syntax::Translated { pattern, names, native_nodes, native_ranges } = syntax::translate(pattern, limit)?;
        before_native(NativeCompileSize{bytes:pattern.len(),nodes:native_nodes,ranges:native_ranges,captures:names.len()})?;
        let hir = regex_syntax::ParserBuilder::new()
            .utf8(true)
            .nest_limit(3_100)
            .build()
            .parse(&pattern)
            .map_err(|_| anyhow!("regexp compilation failed after native translation"))?;
        Self::from_hir(hir,Some(names),limit)
    }
    /// Preserve the pre-existing Rust-regex Map extensions only when Go syntax
    /// rejected the expression. Admission precedes Rust AST/HIR allocation;
    /// Go-valid patterns always retain their Go flags, classes and expansion.
    pub(crate) fn compile_map_extension_preflight(pattern:&str,memory_limit:usize,before_parse:impl FnOnce(NativeCompileSize)->Result<()>)->Result<Self>{
        let limit=memory_limit.min(MAX_PATTERN_MEMORY);
        ensure!(limit>=1024,"regexp compile memory limit too small");
        ensure!(pattern.len()<=1<<20,"regexp source byte limit exceeded");
        let bytes=pattern.as_bytes();
        let unicode_atoms=bytes.iter().filter(|b|matches!(b,b'.'|b'['|b'\\')).count();
        before_parse(NativeCompileSize{
            bytes:pattern.len(),nodes:pattern.len().saturating_mul(2).saturating_add(16),
            ranges:unicode_atoms.checked_mul(8192).ok_or_else(||anyhow!("regexp native class size overflow"))?,
            captures:pattern.len()/2+1,
        })?;
        let hir=regex_syntax::ParserBuilder::new().utf8(true).nest_limit(250).build().parse(pattern)?;
        Self::from_hir(hir,None,limit)
    }
    fn from_hir(hir:regex_syntax::hir::Hir,names:Option<Vec<Option<Box<str>>>>,limit:usize)->Result<Self>{
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
        let names=names.unwrap_or_else(||proof.group_info().pattern_names(regex_automata::PatternID::ZERO).map(|name|name.map(Box::<str>::from)).collect());
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
    /// Go FindAllStringIndex for bounded template functions. Empty matches
    /// abutting a previous match are suppressed; offsets remain UTF-8 boundaries.
    pub(crate) fn find_all_ranges(
        &self, input: &str, count: i64, cap: usize, budget: &ReplaceBudget,
    ) -> std::result::Result<Vec<Range<usize>>, OperationError> {
        budget.check()?;
        if count == 0 { return Ok(Vec::new()); }
        if input.len() > MAX_INPUT_BYTES || self.search_memory > budget.scratch {
            return Err(OperationError::ByteLimit);
        }
        let mut captures=self.native.create_captures();
        let mut cache=self.native.create_cache();
        let mut matches=Vec::new();
        let mut at=0usize;
        let mut previous_end=None;
        while at<=input.len() && (count<0 || matches.len()<(count as usize)) {
            budget.check()?;
            if !self.search_captures(input,at,&mut cache,&mut captures,budget)? {break;}
            let found=captures.get_group(0).ok_or(OperationError::MatchInvariant)?;
            let empty=found.start==found.end;
            let accept=!empty || previous_end!=Some(found.start);
            previous_end=Some(found.end);
            if accept {
                if matches.len()>=cap{return Err(OperationError::ByteLimit);}
                matches.push(found.start..found.end);
            }
            at=if empty {
                found.end+input.get(found.end..).ok_or(OperationError::MatchInvariant)?.chars().next().map_or(1,char::len_utf8)
            }else{found.end};
        }
        Ok(matches)
    }
    /// First-match captures for bounded handshake inputs. The caller runs this
    /// within its TLS CPU lane and supplies the existing workspace allowance.
    pub(crate) fn first_match(
        &self,
        input: &str,
        budget: &ReplaceBudget,
    ) -> std::result::Result<Option<BTreeMap<String, String>>, OperationError> {
        self.first_match_limited(input, budget, usize::MAX)
    }

    pub(crate) fn first_match_limited(
        &self,
        input: &str,
        budget: &ReplaceBudget,
        limit: usize,
    ) -> std::result::Result<Option<BTreeMap<String, String>>, OperationError> {
        budget.check()?;
        if input.len() > MAX_INPUT_BYTES || self.search_memory > budget.scratch {
            return Err(OperationError::ByteLimit);
        }
        let mut captures = self.native.create_captures();
        let mut cache = self.native.create_cache();
        if !self.search_captures(input, 0, &mut cache, &mut captures, budget)? {
            return Ok(None);
        }
        let mut result = BTreeMap::new();
        let mut output = 0usize;
        for (index, name) in self.names.iter().enumerate() {
            let value = captures
                .get_group(index)
                .and_then(|range| input.get(range.range()))
                .unwrap_or_default();
            let key = index.to_string();
            output = output.saturating_add(key.len()).saturating_add(value.len());
            if let Some(name) = name {
                output = output
                    .saturating_add(name.len())
                    .saturating_add(value.len());
            }
            if output > limit {
                return Err(OperationError::ByteLimit);
            }
            result.insert(key, value.to_owned());
            if let Some(name) = name {
                result.insert(name.to_string(), value.to_owned());
            }
        }
        Ok(Some(result))
    }
    /// Match Go byte strings without replacing captured invalid UTF-8 bytes.
    /// The normalized search text is temporary; spans map back to the exact
    /// original input before any capture is copied to its bounded result.
    pub(crate) fn first_match_bytes_limited(
        &self, original:&[u8], budget:&ReplaceBudget, limit:usize,
        mut charge:impl FnMut(usize)->std::result::Result<(),OperationError>,
    )->std::result::Result<Option<BTreeMap<String,Vec<u8>>>,OperationError>{
        budget.check()?;
        let scratch=budget.scratch.checked_sub(self.search_memory).ok_or(OperationError::ByteLimit)?;
        let input=Normalized::new(original,&ReplaceBudget::new(scratch,budget.deadline))?;
        let mut captures=self.native.create_captures();let mut cache=self.native.create_cache();
        if !self.search_captures(&input.text,0,&mut cache,&mut captures,budget)?{return Ok(None)}
        let mut result=BTreeMap::new();let mut output=0usize;
        for(index,name)in self.names.iter().enumerate(){
            budget.check()?;
            let value=if let Some(span)=captures.get_group(index){
                let start=input.original_offset(span.start)?;let end=input.original_offset(span.end)?;
                original.get(start..end).ok_or(OperationError::MatchInvariant)?
            }else{&[]};
            charge(256)?;
            let key=index.to_string();output=output.saturating_add(key.len()).saturating_add(value.len());
            if let Some(name)=name{output=output.saturating_add(name.len()).saturating_add(value.len());}
            if output>limit{return Err(OperationError::ByteLimit)}
            charge(key.len().saturating_add(value.len()).saturating_add(name.as_ref().map_or(0,|n|n.len().saturating_add(value.len()))).saturating_mul(8).saturating_add(1024))?;
            result.insert(key,value.to_vec());if let Some(name)=name{result.insert(name.to_string(),value.to_vec());}
        }Ok(Some(result))
    }
    /// Boolean match of Go's byte input: each invalid UTF-8 byte is one RuneError.
    /// Reuse normalization and the same bounded native search as replacement.
    pub(crate) fn is_match_bytes(
        &self,
        original: &[u8],
        budget: &ReplaceBudget,
    ) -> std::result::Result<bool, OperationError> {
        budget.check()?;
        let scratch = budget
            .scratch
            .checked_sub(self.search_memory)
            .ok_or(OperationError::ByteLimit)?;
        let input = Normalized::new(original, &ReplaceBudget::new(scratch, budget.deadline))?;
        let mut captures = self.native.create_captures();
        let mut cache = self.native.create_cache();
        self.search_captures(&input.text, 0, &mut cache, &mut captures, budget)
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
    /// Closed map callers prepay the actual dollar-program/capture shape.
    pub(crate) fn replacement_compile_upper(&self,text:&[u8])->Result<usize>{
        let(mut at,mut parts)=(0usize,0usize);
        while let Some(mark)=text[at..].iter().position(|b|*b==b'$'){
            let mark=at+mark;if mark>at{parts=parts.checked_add(1).ok_or_else(||anyhow!("map replacement shape overflow"))?;}
            at=mark+1;parts=parts.checked_add(1).ok_or_else(||anyhow!("map replacement shape overflow"))?;
            if text[at..].starts_with(b"$"){at+=1;}else if let Some((_,after))=extract(text,at){at=after;}
        }
        if at<text.len(){parts=parts.checked_add(1).ok_or_else(||anyhow!("map replacement shape overflow"))?;}
        let capacity=if parts==0{0}else{parts.checked_next_power_of_two().ok_or_else(||anyhow!("map replacement shape overflow"))?.max(4)};
        let names=self.names.len();
        capacity.checked_mul(std::mem::size_of::<Part>()*2)
            .and_then(|n|n.checked_add(names.div_ceil(5).saturating_add(3).saturating_mul(1024)))
            .and_then(|n|n.checked_add(names.saturating_mul(320)))
            .and_then(|n|n.checked_add(text.len().saturating_mul(3)))
            .and_then(|n|n.checked_add(16384)).ok_or_else(||anyhow!("map replacement shape overflow"))
    }
    pub(crate) fn capture_memory_upper(&self)->usize{self.names.len().saturating_mul(128).saturating_add(16384)}
    /// Construct the dollar program and admit output only after a real match.
    /// The closed CPU caller returns the output owner alongside its bytes.
    pub(crate) fn expand_first_lazy<P:AsRef<Replacement>,O>(
        &self,original:&[u8],cap:usize,budget:&mut ReplaceBudget,
        make:impl FnOnce()->Result<(P,O)>,
    )->Result<Option<(Vec<u8>,O)>>{
        budget.check()?;
        if self.search_memory>budget.scratch{return Err(OperationError::ByteLimit.into())}
        let input=Normalized::new(original,budget)?;
        let mut caps=self.native.create_captures();let mut cache=self.native.create_cache();
        if !self.search_captures(&input.text,0,&mut cache,&mut caps,budget)?{return Ok(None)}
        let(program,owner)=make()?;let replacement=program.as_ref();
        if !Arc::ptr_eq(&self.identity,&replacement.identity){return Err(OperationError::MatchInvariant.into())}
        let mut named=vec![None;replacement.named.len()];
        let mut output=Output{bytes:Vec::new(),cap,truncate:false};
        replacement.append(original,&input,&caps,&mut named,&mut output,budget)?;
        budget.check()?;Ok(Some((output.bytes,owner)))
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
    text: Box<[u8]>,
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
        Self::compile_bytes(regex,text.into_bytes(),budget)
    }
    pub(crate) fn compile_bytes(regex:&GoRegexp,text:Vec<u8>,budget:usize)->Result<Self>{
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
        while let Some(mark) = text[at..].iter().position(|b|*b==b'$') {
            let mark = at + mark;
            if mark > at {
                push(Part::Raw(at..mark))?;
            }
            at = mark + 1;
            if text[at..].starts_with(b"$") {
                push(Part::Dollar)?;
                at += 1;
                continue;
            }
            if let Some((name, after)) = extract(&text, at) {
                at = after;
                let name = std::str::from_utf8(&text[name]).expect("extracted capture name is valid UTF-8");
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
            text: text.into_boxed_slice(),
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
                    out.add(&self.text[r.clone()])?;
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
fn extract(text:&[u8],at:usize)->Option<(Range<usize>,usize)>{
    let braced=text[at..].starts_with(b"{");let a=at+usize::from(braced);
    let suffix=&text[a..];let valid=match std::str::from_utf8(suffix){Ok(s)=>s,Err(e)=>std::str::from_utf8(&suffix[..e.valid_up_to()]).ok()?};
    let len=valid.char_indices().find(|(_,c)|!unicode::is_name_character(*c)).map_or(valid.len(),|(i,_)|i);
    if len==0{return None}let end=a+len;if braced&&!text[end..].starts_with(b"}"){return None}Some((a..end,end+usize::from(braced)))
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
