// Copyright 2015 Matthew Holt and The Caddy Authors
// SPDX-License-Identifier: Apache-2.0
use crate::{caddyfile_lexer::Token, caddyfile_parser::Dispenser};
use anyhow::{Result, bail};
use serde_json::{Map, Value};
#[derive(Default)]
pub(super) struct Ops {
    add: Map<String, Value>,
    set: Map<String, Value>,
    delete: Vec<String>,
    replace: Map<String, Value>,
    deferred: bool,
    require: Option<Value>,
}
impl Ops {
    pub(super) fn value(self, response: bool) -> Value {
        let mut object = Map::new();
        if !self.add.is_empty() {
            object.insert("add".into(), Value::Object(self.add));
        }
        if !self.set.is_empty() {
            object.insert("set".into(), Value::Object(self.set));
        }
        if !self.delete.is_empty() {
            object.insert(
                "delete".into(),
                self.delete.into_iter().map(Value::String).collect(),
            );
        }
        if !self.replace.is_empty() {
            object.insert("replace".into(), Value::Object(self.replace));
        }
        if response {
            if self.deferred {
                object.insert("deferred".into(), true.into());
            }
            if let Some(require) = self.require {
                object.insert("require".into(), require);
            }
        }
        Value::Object(object)
    }
    pub(super) fn apply(
        &mut self,
        response: bool,
        field: &str,
        value: &str,
        replacement: Option<String>,
    ) -> Result<()> {
        if let Some(field) = field.strip_prefix('+') {
            let key = super::matcher_atoms::canonical_header(field);
            let entry = self
                .add
                .entry(key)
                .or_insert_with(|| Value::Array(Vec::new()));
            entry.as_array_mut().unwrap().push(value.into());
        } else if let Some(field) = field.strip_prefix('-') {
            self.delete.push(field.into());
            if response {
                self.deferred = true;
            }
        } else if let Some(field) = field.strip_prefix('?') {
            if !response {
                bail!(
                    "{field}: the default header modifier ('?') can only be used on response headers; for conditional manipulation of request headers, use matchers"
                );
            }
            let require = self
                .require
                .get_or_insert_with(|| Value::Object(Map::new()))
                .as_object_mut()
                .ok_or_else(|| anyhow::anyhow!("invalid response matcher"))?;
            let headers = require
                .entry("headers")
                .or_insert_with(|| Value::Object(Map::new()))
                .as_object_mut()
                .ok_or_else(|| anyhow::anyhow!("invalid response headers"))?;
            headers.insert(field.into(), Value::Null);
            self.set.insert(
                super::matcher_atoms::canonical_header(field),
                Value::Array(vec![value.into()]),
            );
        } else if let Some(replacement) = replacement {
            if response && field.starts_with('>') {
                self.deferred = true;
            }
            let field = field.trim_start_matches(['+', '-', '?', '>']);
            let entries = self
                .replace
                .entry(field)
                .or_insert_with(|| Value::Array(Vec::new()));
            let mut change = Map::new();
            if !value.is_empty() {
                change.insert("search_regexp".into(), value.into());
            }
            if !replacement.is_empty() {
                change.insert("replace".into(), replacement.into());
            }
            entries.as_array_mut().unwrap().push(Value::Object(change));
        } else {
            let field = if let Some(field) = field.strip_prefix('>') {
                if response {
                    self.deferred = true;
                }
                field
            } else {
                field
            };
            self.set.insert(
                super::matcher_atoms::canonical_header(field),
                Value::Array(vec![value.into()]),
            );
        }
        Ok(())
    }
}
fn arguments(d: &mut Dispenser) -> (String, Option<String>) {
    let value = if d.next_arg() {
        d.val().to_owned()
    } else {
        String::new()
    };
    let replacement = if d.next_arg() {
        Some(d.val().to_owned())
    } else {
        None
    };
    (value, replacement)
}
fn handler(ops: Value, response: bool) -> Result<Value> {
    let mut object = Map::new();
    object.insert("handler".into(), "headers".into());
    object.insert(if response { "response" } else { "request" }.into(), ops);
    super::module_value::normalize(Value::Object(object))
}
pub(super) fn parse(name: &str, tokens: &[Token]) -> Result<Vec<Value>> {
    let mut d = Dispenser::new(tokens.to_vec());
    d.next();
    if name == "request_header" {
        if !d.next_arg() {
            return Err(d.arg_err());
        }
        let field = d.val().strip_suffix(':').unwrap_or(d.val()).to_owned();
        let (value, replacement) = arguments(&mut d);
        if replacement.is_some() && d.next_arg() {
            return Err(d.arg_err());
        }
        let mut ops = Ops::default();
        ops.apply(false, &field, &value, replacement)
            .map_err(|e| d.error(e.to_string()))?;
        if d.next_arg() {
            return Err(d.arg_err());
        }
        return Ok(vec![handler(ops.value(false), false)?]);
    }
    let mut ops = Ops::default();
    let mut defaults = Ops::default();
    let has_args = d.next_arg();
    if has_args {
        let field = d.val().to_owned();
        let (value, replacement) = arguments(&mut d);
        ops.apply(true, &field, &value, replacement)
            .map_err(|e| d.error(e.to_string()))?;
    }
    while d.next_block(0) {
        let field = d.val();
        if field == "defer" {
            ops.deferred = true;
            continue;
        }
        if field == "match" {
            ops.require = Some(super::response_matcher::parse(&d.next_segment())?);
            continue;
        }
        if has_args {
            return Err(d.error("cannot specify headers in both arguments and block"));
        }
        let field = field.strip_suffix(':').unwrap_or(field).to_owned();
        let (value, replacement) = arguments(&mut d);
        let target = if field.starts_with('?') {
            &mut defaults
        } else {
            &mut ops
        };
        target
            .apply(true, &field, &value, replacement)
            .map_err(|e| d.error(e.to_string()))?;
    }
    let mut values = Vec::new();
    for ops in [ops, defaults] {
        let value = ops.value(true);
        if value.as_object().is_some_and(|m| !m.is_empty()) {
            values.push(handler(value, true)?);
        }
    }
    Ok(values)
}
