// Copyright 2015 Matthew Holt and The Caddy Authors. Apache-2.0.
// Single and ordered multi-regexp filters on Zap's string/string-array types.
use super::{bounded::ByteLimit, config, types::FieldValue};
use crate::go_regexp::{GoRegexp, OperationError, ReplaceBudget, Replacement};
use anyhow::{Result, anyhow, bail, ensure};
use serde_json::{Map, Value};
use std::{borrow::Cow, time::Instant};

const GO_MULTI_BYTES: usize = 1_000_000;
const MAX_OPERATIONS: usize = 50;
const MAX_MULTI_PATTERN: usize = 1000;
struct Operation {
    regexp: GoRegexp,
    value: Replacement,
}
pub(super) struct Regexp {
    operations: Vec<Operation>,
    multi: bool,
    search_memory: usize,
}
impl Regexp {
    pub(super) fn parse(
        multi: bool,
        mut fields: Map<String, Value>,
        budget: &mut usize,
    ) -> Result<Self> {
        let rules = if multi {
            crate::http_config::helpers::deny_unknown(
                &fields,
                &["operations"],
                "/logging/filter/multi_regexp",
            )?;
            let Some(Value::Array(items)) = fields.remove("operations") else {
                bail!("multi-regexp logging filter requires an operations array");
            };
            ensure!(
                !items.is_empty() && items.len() <= MAX_OPERATIONS,
                "invalid multi-regexp logging operation count"
            );
            items
                .into_iter()
                .map(|op| {
                    let Value::Object(op) = op else {
                        bail!("multi-regexp logging operation must be an object")
                    };
                    Ok(op)
                })
                .collect::<Result<Vec<_>>>()?
        } else {
            vec![fields]
        };
        *budget = budget
            .checked_sub(rules.len() * std::mem::size_of::<Operation>())
            .ok_or_else(|| anyhow!("log regexp configuration memory limit exceeded"))?;
        let mut operations = Vec::with_capacity(rules.len());
        let mut search_memory = 0;
        for mut fields in rules {
            crate::http_config::helpers::deny_unknown(
                &fields,
                &["regexp", "value"],
                "/logging/filter/regexp",
            )?;
            let pattern = config::string(fields.remove("regexp"))?;
            let value = config::string(fields.remove("value"))?;
            ensure!(
                !multi || (!pattern.is_empty() && pattern.len() <= MAX_MULTI_PATTERN),
                "multi-regexp logging pattern length out of range"
            );
            let regexp = GoRegexp::compile(&pattern, *budget)?;
            *budget = budget
                .checked_sub(regexp.memory_usage())
                .ok_or_else(|| anyhow!("log regexp configuration memory limit exceeded"))?;
            let value = Replacement::compile(&regexp, value, *budget)?;
            *budget = budget
                .checked_sub(value.memory_usage())
                .ok_or_else(|| anyhow!("log regexp replacement memory limit exceeded"))?;
            search_memory = search_memory.max(regexp.search_memory());
            operations.push(Operation { regexp, value });
        }
        Ok(Self {
            operations,
            multi,
            search_memory,
        })
    }
    pub(super) fn search_memory(&self) -> usize {
        self.search_memory
    }
    pub(super) fn apply(
        &self,
        value: &FieldValue,
        limit: usize,
        deadline: Option<Instant>,
    ) -> Result<Option<FieldValue>> {
        let mut budget = ReplaceBudget::new(limit, deadline);
        Ok(match value {
            FieldValue::String(s) => Some(FieldValue::RawString(self.process(
                s.as_bytes(),
                limit,
                &mut budget,
            )?)),
            FieldValue::RawString(s) => Some(FieldValue::RawString(self.process(
                s,
                limit,
                &mut budget,
            )?)),
            FieldValue::StringArray(values) => {
                let slots = values
                    .len()
                    .checked_mul(std::mem::size_of::<Vec<u8>>())
                    .filter(|n| *n <= limit)
                    .ok_or(ByteLimit("log regexp array byte limit exceeded"))?;
                let mut remaining = limit - slots;
                let mut output = Vec::new();
                output.try_reserve_exact(values.len())?;
                for value in values {
                    let next = self.process(value, remaining, &mut budget)?;
                    remaining = remaining
                        .checked_sub(next.capacity())
                        .ok_or(ByteLimit("log regexp array byte limit exceeded"))?;
                    output.push(next);
                }
                Some(FieldValue::StringArray(output))
            }
            _ => None,
        })
    }
    fn process(&self, input: &[u8], limit: usize, budget: &mut ReplaceBudget) -> Result<Vec<u8>> {
        let mut input = Cow::Borrowed(if self.multi {
            &input[..input.len().min(GO_MULTI_BYTES)]
        } else {
            input
        });
        let cap = if self.multi {
            limit.min(GO_MULTI_BYTES)
        } else {
            limit
        };
        let truncate = self.multi && limit >= GO_MULTI_BYTES;
        for op in &self.operations {
            input = Cow::Owned(
                op.regexp
                    .replace_all(&input, &op.value, cap, truncate, budget)
                    .map_err(|error| match error {
                        OperationError::ByteLimit => {
                            anyhow!(ByteLimit("log regexp processing byte limit exceeded"))
                        }
                        other => anyhow!(other),
                    })?,
            );
        }
        Ok(input.into_owned())
    }
}
