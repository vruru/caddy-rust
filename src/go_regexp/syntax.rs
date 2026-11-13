// Copyright The Go Authors. BSD-3-Clause.
// Behavioral port of Go 1.27.3 regexp/syntax/parse.go.
use super::unicode;
use anyhow::{Result, anyhow, bail, ensure};
use std::fmt::Write;
type Index = usize;

const MAX_RUNES: usize = 262_144;
const MAX_NEST: usize = 1_000;
const MAX_TRANSLATED: usize = 16 << 20;
const MAX_CAPTURE: usize = 4_096;

#[derive(Clone, Copy, Default)]
struct Flags(u8);
impl Flags {
    const I: u8 = 1;
    const M: u8 = 2;
    const S: u8 = 4;
    const U: u8 = 8;
    fn has(self, bit: u8) -> bool {
        self.0 & bit != 0
    }
}
#[derive(Clone, Copy)]
enum Repeat {
    Star,
    Plus,
    Optional,
    Count { min: u32, max: Option<u32> },
}
struct Frame {
    flags: Flags,
    capture: bool,
    branches: Vec<Vec<Index>>,
}
impl Frame {
    fn new(flags: Flags, capture: bool) -> Self {
        Self {
            flags,
            capture,
            branches: vec![Vec::new()],
        }
    }
    fn current(&mut self) -> &mut Vec<Index> {
        self.branches
            .last_mut()
            .expect("a frame always has a branch")
    }
}
enum Kind {
    Rune(u32),
    Class(Vec<(u32, u32)>),
    Text(&'static str),
    Group(Frame),
    Repeat(Index, Repeat, bool),
}
struct Node {
    kind: Kind,
    product: u16,
    height: u16,
}
pub(super) struct Translated {
    pub pattern: String,
    pub names: Vec<Option<Box<str>>>,
    pub native_nodes:usize,
    pub native_ranges:usize,
}
struct Parser<'a> {
    rest: &'a str,
    frames: Vec<Frame>,
    arena: Vec<Node>,
    names: Vec<Option<Box<str>>>,
    repeated: bool,
    charged: usize,
    limit: usize,
}
impl<'a> Parser<'a> {
    fn frame(&mut self) -> &mut Frame {
        self.frames.last_mut().expect("root frame")
    }
    fn charge(&mut self, bytes: usize) -> Result<()> {
        self.charged = self
            .charged
            .checked_add(bytes)
            .filter(|n| *n <= self.limit)
            .ok_or_else(|| anyhow!("regexp translation workspace limit exceeded"))?;
        Ok(())
    }
    fn node(&mut self, kind: Kind) -> Result<()> {
        let (product, height) = match &kind {
            Kind::Repeat(child, Repeat::Count { min, max }, _) => {
                let child = &self.arena[*child];
                let product = if *max == Some(0) {
                    // Only a finite zero maximum erases the inner expression.
                    1
                } else {
                    let factor = max.unwrap_or(*min).max(1);
                    u32::from(child.product) * factor
                };
                ensure!(product <= 1000, "invalid regexp repetition size");
                (product as u16, child.height + 1)
            }
            Kind::Repeat(child, _, _) => {
                let child = &self.arena[*child];
                (child.product, child.height + 1)
            }
            Kind::Group(frame) => frame.branches.iter().flatten().fold((1, 1), |(p, h), i| {
                let c = &self.arena[*i];
                (p.max(c.product), h.max(c.height + 1))
            }),
            _ => (1, 1),
        };
        ensure!(
            usize::from(height) <= MAX_NEST,
            "regexp nesting limit exceeded"
        );
        ensure!(
            self.arena.len() < MAX_RUNES,
            "regexp syntax node limit exceeded"
        );
        let overhead = std::mem::size_of::<Node>() + std::mem::size_of::<Index>() * 2;
        let ranges = match &kind {
            Kind::Class(values) => values
                .capacity()
                .saturating_mul(std::mem::size_of::<(u32, u32)>()),
            _ => 0,
        };
        self.charge(overhead.saturating_add(ranges))?;
        let index = self.arena.len();
        self.arena.push(Node {
            kind,
            product,
            height,
        });
        self.frame().current().push(index);
        Ok(())
    }
    fn flags(&self) -> Flags {
        self.frames.last().expect("root frame").flags
    }
    fn rune(&mut self, rune: u32) -> Result<()> {
        if self.flags().has(Flags::I) {
            let ranges = unicode::fold_range(rune, rune)?;
            if ranges.as_slice() != [(rune, rune)] {
                return self.node(Kind::Class(ranges));
            }
        }
        self.node(Kind::Rune(rune))
    }
    fn open(&mut self, flags: Flags, capture: bool, name: Option<&str>) -> Result<()> {
        ensure!(
            self.frames.len() < MAX_NEST,
            "regexp group nesting limit exceeded"
        );
        if capture {
            ensure!(
                self.names.len() <= MAX_CAPTURE,
                "regexp capture count limit exceeded"
            );
            if let Some(name) = name {
                self.charge(name.len())?;
            }
            self.names.push(name.map(Into::into));
        }
        self.charge(std::mem::size_of::<Frame>() + std::mem::size_of::<Vec<Index>>())?;
        self.frames.push(Frame::new(flags, capture));
        Ok(())
    }
    fn paren(&mut self) -> Result<()> {
        let initial = self.flags();
        if !self.rest.starts_with('?') {
            return self.open(initial, true, None);
        }
        self.rest = &self.rest[1..];
        if let Some(s) = self
            .rest
            .strip_prefix("P<")
            .or_else(|| self.rest.strip_prefix('<'))
        {
            let (name, rest) = s
                .split_once('>')
                .ok_or_else(|| anyhow!("invalid regexp capture name"))?;
            ensure!(
                !name.is_empty() && name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_'),
                "invalid regexp capture name"
            );
            self.rest = rest;
            return self.open(initial, true, Some(name));
        }
        let mut flags = initial;
        let mut negative = false;
        let mut saw = false;
        loop {
            let Some(c) = self.rest.as_bytes().first().copied() else {
                bail!("unterminated regexp flags")
            };
            let bit = match c {
                b'i' => Flags::I,
                b'm' => Flags::M,
                b's' => Flags::S,
                b'U' => Flags::U,
                b'-' if !negative => {
                    negative = true;
                    saw = false;
                    self.rest = &self.rest[1..];
                    continue;
                }
                b')' | b':' if !negative || saw => {
                    self.rest = &self.rest[1..];
                    if c == b':' {
                        return self.open(flags, false, None);
                    }
                    self.frame().flags = flags;
                    return Ok(());
                }
                _ => bail!("invalid or unsupported regexp flag or group"),
            };
            if negative {
                flags.0 &= !bit;
            } else {
                flags.0 |= bit;
            }
            saw = true;
            self.rest = &self.rest[1..];
        }
    }
    fn repeat(&mut self, repeat: Repeat) -> Result<()> {
        ensure!(!self.repeated, "invalid nested regexp quantifier");
        if let Repeat::Count { min, max } = repeat {
            ensure!(
                min <= 1000 && max.is_none_or(|n| n <= 1000 && min <= n),
                "invalid regexp repetition size"
            );
        }
        let child = self
            .frame()
            .current()
            .pop()
            .ok_or_else(|| anyhow!("regexp repeat has no operand"))?;
        let mut lazy = self.flags().has(Flags::U);
        if self.rest.starts_with('?') {
            self.rest = &self.rest[1..];
            lazy = !lazy;
        }
        self.node(Kind::Repeat(child, repeat, lazy))?;
        self.repeated = true;
        Ok(())
    }
    fn class(&mut self) -> Result<()> {
        let (negative, mut s) = self
            .rest
            .strip_prefix('^')
            .map_or((false, self.rest), |s| (true, s));
        let fold = self.flags().has(Flags::I);
        let mut first = true;
        let mut ranges = Vec::new();
        loop {
            if !first && s.starts_with(']') {
                self.rest = &s[1..];
                let mut ranges = unicode::clean(ranges);
                if negative {
                    ranges = unicode::negate(&ranges);
                }
                return self.node(Kind::Class(ranges));
            }
            first = false;
            if let Some((mut r, rest)) = unicode::special(s, fold, true)? {
                unicode::extend(&mut ranges, &mut r)?;
                s = rest;
                continue;
            }
            let (lo, rest) = class_char(s)?;
            s = rest;
            let mut hi = lo;
            if let Some(t) = s
                .strip_prefix('-')
                .filter(|t| !t.is_empty() && !t.starts_with(']'))
            {
                (hi, s) = class_char(t)?;
                ensure!(lo <= hi, "invalid descending regexp character range");
            }
            if fold {
                let mut r = unicode::fold_range(lo, hi)?;
                unicode::extend(&mut ranges, &mut r)?;
            } else {
                unicode::push(&mut ranges, (lo, hi))?;
            }
        }
    }
    fn escaped(&mut self) -> Result<()> {
        let full = self.rest;
        let code = full.as_bytes().get(1).copied();
        let boundary = match code {
            Some(b'A') => Some(r"\A"),
            Some(b'z') => Some(r"\z"),
            Some(b'b') => Some(r"(?-u:\b)"),
            Some(b'B') => Some(r"(?-u:\B)"),
            _ => None,
        };
        if let Some(text) = boundary {
            self.rest = &full[2..];
            return self.node(Kind::Text(text));
        }
        if code == Some(b'Q') {
            let (literal, rest) = full[2..].split_once(r"\E").unwrap_or((&full[2..], ""));
            self.rest = rest;
            for c in literal.chars() {
                self.rune(c as u32)?;
            }
            return Ok(());
        }
        if let Some((ranges, rest)) = unicode::special(full, self.flags().has(Flags::I), false)? {
            self.rest = rest;
            return self.node(Kind::Class(ranges));
        }
        let (cp, rest) = escape(full)?;
        self.rest = rest;
        self.rune(cp)
    }
    fn parse(mut self) -> Result<Translated> {
        while let Some(c) = self.rest.chars().next() {
            if c == '\\' {
                self.escaped()?;
                self.repeated = false;
                continue;
            }
            self.rest = &self.rest[c.len_utf8()..];
            match c {
                '*' | '+' | '?' => {
                    self.repeat(match c {
                        '*' => Repeat::Star,
                        '+' => Repeat::Plus,
                        _ => Repeat::Optional,
                    })?;
                    continue;
                }
                '{' => {
                    if let Some((min, max, rest)) = count(self.rest) {
                        self.rest = rest;
                        self.repeat(Repeat::Count { min, max })?;
                        continue;
                    }
                    self.rune(u32::from(c))?;
                }
                '(' => self.paren()?,
                ')' => {
                    ensure!(self.frames.len() > 1, "unexpected regexp right parenthesis");
                    let group = self.frames.pop().expect("non-root group");
                    self.node(Kind::Group(group))?;
                }
                '|' => {
                    self.charge(std::mem::size_of::<Vec<Index>>())?;
                    self.frame().branches.push(Vec::new());
                }
                '[' => self.class()?,
                '^' => self.node(Kind::Text(if self.flags().has(Flags::M) {
                    r"(?m:^)"
                } else {
                    r"\A"
                }))?,
                '$' => self.node(Kind::Text(if self.flags().has(Flags::M) {
                    r"(?m:$)"
                } else {
                    r"\z"
                }))?,
                '.' => self.node(Kind::Text(if self.flags().has(Flags::S) {
                    "(?s:.)"
                } else {
                    "."
                }))?,
                c => self.rune(c as u32)?,
            }
            self.repeated = false;
        }
        ensure!(self.frames.len() == 1, "missing regexp closing parenthesis");
        let root = self.frames.pop().expect("root");
        // Retain only scalar shape facts for callers that prepay native AST/HIR.
        // Branches can be empty, so they are counted independently of arena nodes.
        let mut native_nodes=self.arena.len().saturating_add(root.branches.len());
        let mut native_ranges=0usize;
        for node in &self.arena{match &node.kind{
            Kind::Group(frame)=>native_nodes=native_nodes.saturating_add(frame.branches.len()),
            Kind::Class(ranges)=>native_ranges=native_ranges.saturating_add(ranges.len()),
            _=>{},
        }}
        let pattern = render(root, &self.arena, self.limit.min(MAX_TRANSLATED))?;
        Ok(Translated {
            pattern,
            names: self.names,
            native_nodes,native_ranges,
        })
    }
}

fn count(s: &str) -> Option<(u32, Option<u32>, &str)> {
    fn integer(s: &str) -> Option<(u32, &str)> {
        let n = s.bytes().take_while(u8::is_ascii_digit).count();
        if n == 0 || (n > 1 && s.as_bytes()[0] == b'0') {
            return None;
        }
        let value = s.as_bytes()[..n].iter().fold(0u32, |x, c| {
            x.saturating_mul(10).saturating_add(u32::from(*c - b'0'))
        });
        Some((value, &s[n..]))
    }
    let (min, s) = integer(s)?;
    if let Some(rest) = s.strip_prefix('}') {
        return Some((min, Some(min), rest));
    }
    let s = s.strip_prefix(',')?;
    if let Some(rest) = s.strip_prefix('}') {
        return Some((min, None, rest));
    }
    let (max, s) = integer(s)?;
    Some((min, Some(max), s.strip_prefix('}')?))
}
fn class_char(s: &str) -> Result<(u32, &str)> {
    let c = s
        .chars()
        .next()
        .ok_or_else(|| anyhow!("missing regexp closing bracket"))?;
    if c == '\\' {
        escape(s)
    } else {
        Ok((c as u32, &s[c.len_utf8()..]))
    }
}
fn escape(s: &str) -> Result<(u32, &str)> {
    let s = &s[1..];
    let c = s
        .chars()
        .next()
        .ok_or_else(|| anyhow!("trailing regexp backslash"))?;
    let rest = &s[c.len_utf8()..];
    let special = match c {
        'a' => Some(7),
        'f' => Some(12),
        'n' => Some(10),
        'r' => Some(13),
        't' => Some(9),
        'v' => Some(11),
        _ => None,
    };
    if let Some(cp) = special {
        return Ok((cp, rest));
    }
    if c.is_ascii() && !c.is_ascii_alphanumeric() {
        return Ok((c as u32, rest));
    }
    if ('0'..='7').contains(&c) {
        let oct = rest
            .bytes()
            .take(2)
            .take_while(|c| (b'0'..=b'7').contains(c))
            .count();
        ensure!(c == '0' || oct > 0, "regexp backreferences are unsupported");
        let value = rest.as_bytes()[..oct]
            .iter()
            .fold(c as u32 - u32::from(b'0'), |x, d| {
                x * 8 + u32::from(*d - b'0')
            });
        return Ok((value, &rest[oct..]));
    }
    if c == 'x' {
        let (digits, rest) = if let Some(s) = rest.strip_prefix('{') {
            s.split_once('}')
                .ok_or_else(|| anyhow!("unterminated regexp hex escape"))?
        } else {
            let digits = rest
                .get(..2)
                .ok_or_else(|| anyhow!("invalid regexp hex escape"))?;
            (digits, &rest[2..])
        };
        ensure!(!digits.is_empty(), "empty regexp hex escape");
        let mut cp = 0;
        for d in digits.chars() {
            let x = d
                .to_digit(16)
                .ok_or_else(|| anyhow!("invalid regexp hex escape"))?;
            cp = cp * 16 + x;
            ensure!(cp <= 0x10ffff, "regexp hex escape outside Unicode");
        }
        return Ok((cp, rest));
    }
    bail!("invalid regexp escape")
}
fn add(out: &mut String, s: &str, cap: usize) -> Result<()> {
    ensure!(
        out.len().checked_add(s.len()).is_some_and(|n| n <= cap),
        "regexp translated pattern limit exceeded"
    );
    out.push_str(s);
    Ok(())
}
enum Emit {
    Node(Index),
    Text(&'static str),
    Repeat(Repeat, bool),
}
fn branches(stack: &mut Vec<Emit>, frame: &Frame) {
    for (i, branch) in frame.branches.iter().enumerate().rev() {
        stack.extend(branch.iter().rev().copied().map(Emit::Node));
        if i > 0 {
            stack.push(Emit::Text("|"));
        }
    }
}
fn push_rune(out: &mut String, cp: u32, cap: usize) -> Result<()> {
    if let Some(c) = char::from_u32(cp) {
        if c.is_ascii_alphanumeric() || c == '_' || !c.is_ascii() {
            let mut b = [0; 4];
            return add(out, c.encode_utf8(&mut b), cap);
        }
        let encoded = format!(r"\x{{{cp:x}}}");
        return add(out, &encoded, cap);
    }
    add(out, r"[a&&b]", cap)
}
fn render(root: Frame, nodes: &[Node], cap: usize) -> Result<String> {
    let mut stack = Vec::new();
    branches(&mut stack, &root);
    let mut out = String::new();
    while let Some(item) = stack.pop() {
        match item {
            Emit::Text(s) => add(&mut out, s, cap)?,
            Emit::Repeat(repeat, lazy) => {
                match repeat {
                    Repeat::Star => add(&mut out, "*", cap)?,
                    Repeat::Plus => add(&mut out, "+", cap)?,
                    Repeat::Optional => add(&mut out, "?", cap)?,
                    Repeat::Count { min, max } => {
                        let mut text = String::new();
                        match max {
                            Some(m) if min == m => write!(&mut text, "{{{min}}}")?,
                            Some(m) => write!(&mut text, "{{{min},{m}}}")?,
                            None => write!(&mut text, "{{{min},}}")?,
                        }
                        add(&mut out, &text, cap)?;
                    }
                }
                if lazy {
                    add(&mut out, "?", cap)?;
                }
            }
            Emit::Node(i) => match &nodes[i].kind {
                Kind::Text(s) => add(&mut out, s, cap)?,
                Kind::Rune(cp) => push_rune(&mut out, *cp, cap)?,
                Kind::Class(ranges) => {
                    let mut any = false;
                    for &(lo, hi) in ranges {
                        // Go accepts surrogate escapes; no input UTF-8 rune
                        // can match these, so never feed a surrogate to Rust.
                        for (start, end) in [(lo, hi.min(0xd7ff)), (lo.max(0xe000), hi)] {
                            if start > end {
                                continue;
                            }
                            if !any {
                                add(&mut out, "[", cap)?;
                                any = true;
                            }
                            push_rune(&mut out, start, cap)?;
                            if start != end {
                                add(&mut out, "-", cap)?;
                                push_rune(&mut out, end, cap)?;
                            }
                        }
                    }
                    if any {
                        add(&mut out, "]", cap)?;
                    } else {
                        add(&mut out, r"[a&&b]", cap)?;
                    }
                }
                Kind::Repeat(child, repeat, lazy) => {
                    add(&mut out, "(?:", cap)?;
                    stack.push(Emit::Repeat(*repeat, *lazy));
                    stack.push(Emit::Text(")"));
                    stack.push(Emit::Node(*child));
                }
                Kind::Group(group) => {
                    add(&mut out, if group.capture { "(" } else { "(?:" }, cap)?;
                    stack.push(Emit::Text(")"));
                    branches(&mut stack, group);
                }
            },
        }
    }
    Ok(out)
}
pub(super) fn translate(input: &str, limit: usize) -> Result<Translated> {
    ensure!(input.len() <= 1 << 20, "regexp source byte limit exceeded");
    Parser {
        rest: input,
        frames: vec![Frame::new(Flags::default(), false)],
        arena: Vec::new(),
        names: vec![None],
        repeated: false,
        charged: 0,
        limit,
    }
    .parse()
}
