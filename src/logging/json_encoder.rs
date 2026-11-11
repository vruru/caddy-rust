// Copyright 2016 Uber Technologies, Inc. SPDX-License-Identifier: MIT
//! Ordered Zap fields retain duplicate keys, typed scalars and open namespaces.
use super::{
    bounded::Buffer,
    float,
    primitives::{Common, LocalZone},
    time_components,
    types::{Entry, Field, FieldValue},
};
use anyhow::{Result, bail, ensure};
use base64::Engine;

/// Synchronous encoder operations, preserving namespaces and object marshalers.
/// Objects may deliberately ignore the encoder given to their marshaler, as in
/// Caddy's nested FilterEncoder. Arrays always encode their elements raw.
pub(super) trait Sink {
    fn add(&mut self, key: &str, value: &FieldValue) -> Result<()>;
    fn object(
        &mut self,
        key: &str,
        emit: &mut dyn FnMut(&mut dyn Sink) -> Result<()>,
    ) -> Result<()>;
}
pub(super) struct JsonEncoder {
    pub common: Common,
}
impl JsonEncoder {
    pub(super) fn encode_stream(
        &self,
        event: Entry<'_>,
        limit: usize,
        local: LocalZone,
        emit: &mut dyn FnMut(&mut dyn Sink) -> Result<()>,
    ) -> Result<Vec<u8>> {
        let mut output = Buffer::new(limit);
        output.byte(b'{')?;
        let mut e = Context {
            output: &mut output,
            common: &self.common,
            local,
            spaced: false,
            namespaces: 0,
            depth: 0,
        };
        if !self.common.level_key.is_empty()
            && let Some(level) = self.common.level.text(event.level)
        {
            e.string(&self.common.level_key, &level)?;
        }
        if !self.common.time_key.is_empty() && !time_components::is_zero(event.time) {
            e.key(&self.common.time_key)?;
            self.common
                .time
                .scalar(event.time, e.output.remaining(), local)?
                .json(e.output)?;
        }
        if !event.logger.is_empty() && !self.common.name_key.is_empty() {
            e.string(&self.common.name_key, &event.logger)?;
        }
        if let Some(caller) = event.caller
            && !self.common.caller_key.is_empty()
        {
            e.string(
                &self.common.caller_key,
                &short_caller(&caller.file, caller.line),
            )?;
        }
        if !self.common.message_key.is_empty() {
            e.string(&self.common.message_key, &event.message)?;
        }
        emit(&mut e)?;
        e.close_namespaces()?;
        if let Some(stack) = event.stacktrace
            && !stack.is_empty()
            && !self.common.stacktrace_key.is_empty()
        {
            e.string(&self.common.stacktrace_key, stack)?;
        }
        e.output.byte(b'}')?;
        e.output.bytes(self.common.line_ending.as_bytes())?;
        Ok(output.into_vec())
    }
    pub(super) fn context_stream(
        &self,
        limit: usize,
        local: LocalZone,
        emit: &mut dyn FnMut(&mut dyn Sink) -> Result<()>,
    ) -> Result<Vec<u8>> {
        let mut output = Buffer::new(limit);
        let mut e = Context {
            output: &mut output,
            common: &self.common,
            local,
            spaced: true,
            namespaces: 0,
            depth: 0,
        };
        emit(&mut e)?;
        e.close_namespaces()?;
        Ok(output.into_vec())
    }
}
struct Context<'a> {
    output: &'a mut Buffer,
    common: &'a Common,
    local: LocalZone,
    spaced: bool,
    namespaces: usize,
    depth: usize,
}
impl Context<'_> {
    fn separator(&mut self) -> Result<()> {
        if self
            .output
            .as_slice()
            .last()
            .is_some_and(|b| !b"{[:, ".contains(b))
        {
            self.output.byte(b',')?;
            if self.spaced {
                self.output.byte(b' ')?;
            }
        }
        Ok(())
    }
    fn key(&mut self, key: &str) -> Result<()> {
        self.separator()?;
        self.output.quoted(key.as_bytes())?;
        self.output.byte(b':')?;
        if self.spaced {
            self.output.byte(b' ')?;
        }
        Ok(())
    }
    fn string(&mut self, key: &str, value: &str) -> Result<()> {
        self.key(key)?;
        self.output.quoted(value.as_bytes())
    }
    fn close_namespaces(&mut self) -> Result<()> {
        for _ in 0..self.namespaces {
            self.output.byte(b'}')?;
        }
        self.namespaces = 0;
        Ok(())
    }
    fn field(&mut self, field: &Field, depth: usize) -> Result<()> {
        ensure!(depth <= 256, "log field encoding depth limit exceeded");
        self.key(&field.key)?;
        if matches!(field.value, FieldValue::Namespace) {
            self.output.byte(b'{')?;
            self.namespaces += 1;
            Ok(())
        } else {
            self.value(&field.value, depth)
        }
    }
    fn value(&mut self, value: &FieldValue, depth: usize) -> Result<()> {
        ensure!(depth <= 256, "log field encoding depth limit exceeded");
        match value {
            FieldValue::Null => self.output.bytes(b"null"),
            FieldValue::Bool(b) => self.output.bytes(if *b { b"true" } else { b"false" }),
            FieldValue::I64(n) => self.output.bytes(n.to_string().as_bytes()),
            FieldValue::U64(n) => self.output.bytes(n.to_string().as_bytes()),
            FieldValue::F64(n) => self.number(*n, false),
            FieldValue::F32(n) => self.number(f64::from(*n), true),
            FieldValue::String(s) | FieldValue::Error(s) => self.output.quoted(s.as_bytes()),
            FieldValue::ByteString(b) | FieldValue::RawString(b) => self.output.quoted(b),
            FieldValue::StringArray(values) => {
                self.output.byte(b'[')?;
                for value in values {
                    self.separator()?;
                    self.output.quoted(value)?;
                }
                self.output.byte(b']')
            }
            FieldValue::Binary(b) => {
                let length = base64::encoded_len(b.len(), true)
                    .filter(|n| *n <= self.output.remaining().saturating_sub(2))
                    .ok_or(super::bounded::ByteLimit(
                        "log binary output limit exceeded",
                    ))?;
                let mut encoded = String::with_capacity(length);
                base64::engine::general_purpose::STANDARD.encode_string(b, &mut encoded);
                self.output.quoted(encoded.as_bytes())
            }
            FieldValue::Duration(n) => self.common.duration.scalar(*n).json(self.output),
            FieldValue::Time(time) => self
                .common
                .time
                .scalar(*time, self.output.remaining(), self.local)?
                .json(self.output),
            FieldValue::Array(values) => {
                self.output.byte(b'[')?;
                for value in values {
                    self.separator()?;
                    self.value(value, depth + 1)?;
                }
                self.output.byte(b']')
            }
            FieldValue::Object(fields) => {
                self.output.byte(b'{')?;
                let old = std::mem::replace(&mut self.namespaces, 0);
                for field in fields {
                    self.field(field, depth + 1)?;
                }
                self.output.byte(b'}')?;
                self.close_namespaces()?;
                self.namespaces = old;
                Ok(())
            }
            FieldValue::Reflected(value) => {
                // The injected shared Go JSON encoder is HTML-unescaped and
                // limit-aware. Its one trailing newline is not part of a field.
                let mut bytes = crate::admin_json::encoded_typed_no_html(
                    value,
                    self.output.remaining().saturating_add(1),
                )
                .map_err(super::bounded::reflection_error)?;
                if bytes.last() == Some(&b'\n') {
                    bytes.pop();
                }
                self.output.bytes(&bytes)
            }
            FieldValue::Namespace => bail!("namespace cannot be an array element"),
        }
    }
    fn number(&mut self, n: f64, narrow: bool) -> Result<()> {
        if n.is_nan() {
            return self.output.quoted(b"NaN");
        }
        if n.is_infinite() {
            return self.output.quoted(if n.is_sign_negative() {
                b"-Inf"
            } else {
                b"+Inf"
            });
        }
        let text = if narrow {
            float::f32_text(n as f32)?
        } else {
            float::f64_text(n)?
        };
        self.output.bytes(text.as_bytes())
    }
}
pub(super) fn short_caller(file: &str, line: u32) -> String {
    let mut positions = file.rmatch_indices('/');
    positions.next();
    let start = positions.next().map_or(0, |(i, _)| i + 1);
    format!("{}:{line}", &file[start..])
}

impl Sink for Context<'_> {
    fn add(&mut self, key: &str, value: &FieldValue) -> Result<()> {
        self.key(key)?;
        if matches!(value, FieldValue::Namespace) {
            self.output.byte(b'{')?;
            self.namespaces += 1;
            Ok(())
        } else {
            self.value(value, self.depth)
        }
    }
    fn object(
        &mut self,
        key: &str,
        emit: &mut dyn FnMut(&mut dyn Sink) -> Result<()>,
    ) -> Result<()> {
        ensure!(self.depth < 256, "log field encoding depth limit exceeded");
        self.key(key)?;
        self.output.byte(b'{')?;
        let old = std::mem::replace(&mut self.namespaces, 0);
        self.depth += 1;
        let result = emit(self);
        self.depth -= 1;
        result?;
        self.close_namespaces()?;
        self.output.byte(b'}')?;
        self.namespaces = old;
        Ok(())
    }
}
