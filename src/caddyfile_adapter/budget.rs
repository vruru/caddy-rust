//! Per-adaptation logical work and copy accounting. These units deliberately
//! exclude allocator capacity/slack and are not an RSS or process-memory bound.
use crate::{admin_json, caddyfile_lexer::Token, caddyfile_parser::ParseLimits};
use anyhow::{Result, anyhow, bail};
use serde_json::{Map, Value};

#[derive(Clone, Copy)]
pub(super) struct Limits {
    pub work: u64,
    pub materialized: u64,
    pub json_bytes: u64,
    pub nesting: usize,
    pub value_depth: usize,
}
impl Limits {
    pub(super) fn from_parse(p: &ParseLimits) -> Self {
        Self {
            work: p.splice_work as u64,
            materialized: p.materialized_bytes as u64,
            json_bytes: p.materialized_bytes as u64,
            nesting: p.nesting,
            value_depth: admin_json::MAX_CONFIG_DEPTH,
        }
    }
}

#[derive(Clone, Copy, Default)]
pub(super) struct Cost {
    pub bytes: u64,
    pub nodes: u64,
    pub json_upper: u64,
    /// Maximum simultaneously open containers, not the number of containers.
    pub depth: usize,
}

struct Meter {
    kind: &'static str,
    used: u64,
    cap: u64,
}
impl Meter {
    fn new(kind: &'static str, cap: u64) -> Self {
        Self { kind, used: 0, cap }
    }
    fn take(&mut self, n: u64) -> Result<()> {
        let next = self
            .used
            .checked_add(n)
            .filter(|n| *n <= self.cap)
            .ok_or_else(|| anyhow!("Caddyfile adapter {} budget exceeded", self.kind))?;
        self.used = next;
        Ok(())
    }
}

#[must_use]
pub(super) struct Reservation {
    bytes: u64,
}

pub(super) struct Budget {
    work: Meter,
    materialized: Meter,
    json_cap: u64,
    depth: usize,
    nest_cap: usize,
    value_depth: usize,
}
impl Budget {
    pub(super) fn new(limits: Limits) -> Self {
        Self {
            work: Meter::new("work", limits.work),
            materialized: Meter::new("materialization", limits.materialized),
            json_cap: limits.json_bytes,
            depth: 0,
            nest_cap: limits.nesting,
            value_depth: limits.value_depth,
        }
    }
    pub(super) fn work(&mut self, n: u64) -> Result<()> {
        self.work.take(n)
    }
    pub(super) fn materialize(&mut self, n: u64) -> Result<()> {
        self.materialized.take(n)
    }

    /// Charge before handing an owned token copy to a helper. Parser and
    /// adapter have independent pools; their logical total is at most two
    /// configured pools, rather than pretending the parser ledger is shared.
    pub(super) fn tokens(&mut self, tokens: &[Token], copies: u64) -> Result<()> {
        if copies == 0 {
            return Ok(());
        }
        self.work.take(mul(tokens.len() as u64, copies)?)?;
        let mut total = 0;
        for token in tokens {
            let mut bytes = std::mem::size_of::<Token>() as u64;
            for text in [
                &token.file,
                &token.text,
                &token.heredoc_marker,
                &token.snippet_name,
            ] {
                bytes = add(bytes, text.len() as u64)?;
            }
            self.work.take(mul(token.imports.len() as u64, copies)?)?;
            for imported in &token.imports {
                bytes = add(
                    bytes,
                    add(std::mem::size_of::<String>() as u64, imported.len() as u64)?,
                )?;
            }
            total = add(total, bytes)?;
        }
        self.materialized.take(mul(total, copies)?)
    }

    /// `added_depth` is the number of containers the caller will wrap around
    /// this value. Call before every matcher/route/server copy, using a cached
    /// Cost instead of measuring the same large definition for each reference.
    pub(super) fn copies(&mut self, cost: Cost, copies: u64, added_depth: usize) -> Result<()> {
        if cost
            .depth
            .checked_add(added_depth)
            .is_none_or(|d| d > self.value_depth)
        {
            bail!("Caddyfile adapter value depth limit exceeded");
        }
        self.work.take(mul(cost.nodes, copies)?)?;
        self.materialized.take(mul(cost.bytes, copies)?)
    }
    pub(super) fn reserve_value(&mut self, upper: u64) -> Result<Reservation> {
        self.work.take(add(upper / 64, 1)?)?;
        self.materialized.take(upper)?;
        Ok(Reservation { bytes: upper })
    }
    pub(super) fn finish_value(&mut self, reservation: Reservation, value: &Value) -> Result<Cost> {
        let actual = self.measure(value)?;
        if actual.bytes > reservation.bytes {
            bail!("Caddyfile adapter helper estimate_breach");
        }
        // Reservation costs remain charged even when the bound was generous.
        Ok(actual)
    }
    pub(super) fn finish_map(
        &mut self,
        reservation: Reservation,
        value: &Map<String, Value>,
    ) -> Result<Cost> {
        let actual = self.measure_map(value)?;
        if actual.bytes > reservation.bytes {
            bail!("Caddyfile adapter helper estimate_breach");
        }
        Ok(actual)
    }
    pub(super) fn measure(&mut self, value: &Value) -> Result<Cost> {
        self.walk(Node::Value(value))
    }
    pub(super) fn measure_map(&mut self, value: &Map<String, Value>) -> Result<Cost> {
        self.walk(Node::Object(value))
    }

    fn walk<'a>(&mut self, root: Node<'a>) -> Result<Cost> {
        let mut cost = Cost::default();
        let mut stack: Vec<Frame<'a>> = Vec::new();
        let mut next = Some(root);
        loop {
            if let Some(node) = next.take() {
                self.work.take(1)?;
                cost.nodes = add(cost.nodes, 1)?;
                cost.bytes = add(cost.bytes, 64)?;
                let container = match node {
                    Node::Object(value) => Some(Frame::Object(value.iter())),
                    Node::Value(value) => match value {
                        Value::Object(value) => Some(Frame::Object(value.iter())),
                        Value::Array(value) => Some(Frame::Array(value.iter())),
                        Value::String(value) => {
                            cost.bytes = add(cost.bytes, value.len() as u64)?;
                            cost.json_upper =
                                add(cost.json_upper, add(mul(value.len() as u64, 6)?, 2)?)?;
                            None
                        }
                        Value::Number(_) => {
                            cost.json_upper = add(cost.json_upper, 32)?;
                            None
                        }
                        Value::Bool(_) => {
                            cost.json_upper = add(cost.json_upper, 5)?;
                            None
                        }
                        Value::Null => {
                            cost.json_upper = add(cost.json_upper, 4)?;
                            None
                        }
                    },
                };
                if let Some(frame) = container {
                    let depth = stack.len().checked_add(1).ok_or_else(overflow)?;
                    if depth > self.value_depth {
                        bail!("Caddyfile adapter value depth limit exceeded");
                    }
                    cost.depth = cost.depth.max(depth);
                    cost.json_upper = add(cost.json_upper, 2)?;
                    stack.push(frame);
                }
            } else {
                match stack.last_mut() {
                    Some(Frame::Array(iter)) => match iter.next() {
                        Some(value) => {
                            cost.json_upper = add(cost.json_upper, 1)?;
                            next = Some(Node::Value(value));
                        }
                        None => {
                            stack.pop();
                        }
                    },
                    Some(Frame::Object(iter)) => match iter.next() {
                        Some((key, value)) => {
                            cost.bytes = add(cost.bytes, add(64, key.len() as u64)?)?;
                            cost.json_upper =
                                add(cost.json_upper, add(mul(key.len() as u64, 6)?, 4)?)?;
                            next = Some(Node::Value(value));
                        }
                        None => {
                            stack.pop();
                        }
                    },
                    None => return Ok(cost),
                }
            }
        }
    }

    pub(super) fn nested<T>(&mut self, f: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        if self.depth >= self.nest_cap {
            bail!("Caddyfile adapter nesting limit exceeded");
        }
        self.depth += 1;
        let result = f(self);
        self.depth -= 1;
        // A panic discards this entire adaptation; reusing its ledger after a
        // panic is not supported. Ordinary success and errors restore depth.
        result
    }

    pub(super) fn check_json(&mut self, value: &Value) -> Result<()> {
        // The final authoritative root measurement cannot trust a cached
        // subtree cost after assembly; depth and bounds are rechecked here.
        let cost = self.measure(value)?;
        let upper = add(cost.json_upper, 1)?;
        if upper > self.json_cap {
            self.work.take(upper.min(self.json_cap.saturating_add(1)))?;
            let cap = usize::try_from(self.json_cap).unwrap_or(usize::MAX);
            admin_json::encoded_len_typed(value, cap)
                .map_err(|error| anyhow!("Caddyfile adapter {}", error.category))?;
        }
        Ok(())
    }
}

enum Node<'a> {
    Value(&'a Value),
    Object(&'a Map<String, Value>),
}
enum Frame<'a> {
    Array(std::slice::Iter<'a, Value>),
    Object(serde_json::map::Iter<'a>),
}
fn overflow() -> anyhow::Error {
    anyhow!("Caddyfile adapter accounting overflow")
}
pub(super) fn add(a: u64, b: u64) -> Result<u64> {
    a.checked_add(b).ok_or_else(overflow)
}
pub(super) fn mul(a: u64, b: u64) -> Result<u64> {
    a.checked_mul(b).ok_or_else(overflow)
}
