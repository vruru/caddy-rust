// Copyright 2016 Uber Technologies, Inc. SPDX-License-Identifier: MIT
//! Zap console metadata is raw text; its structured context is spaced JSON.
use super::{
    bounded::Buffer,
    json_encoder::{JsonEncoder, Sink, short_caller},
    primitives::LocalZone,
    time_components,
    types::Entry,
};
use anyhow::Result;
pub(super) struct ConsoleEncoder {
    pub wrapped: JsonEncoder,
}
impl ConsoleEncoder {
    pub(super) fn encode_stream(
        &self,
        event: Entry<'_>,
        limit: usize,
        local: LocalZone,
        emit: &mut dyn FnMut(&mut dyn Sink) -> Result<()>,
    ) -> Result<Vec<u8>> {
        let c = &self.wrapped.common;
        let mut output = Buffer::new(limit);
        if !c.time_key.is_empty() && !time_components::is_zero(event.time) {
            let scalar = c
                .time
                .scalar(event.time, output.remaining(), local)?
                .display()?;
            part(&mut output, &scalar)?;
        }
        if !c.level_key.is_empty()
            && let Some(level) = c.level.text(event.level)
        {
            part(&mut output, &level)?;
        }
        if !event.logger.is_empty() && !c.name_key.is_empty() {
            part(&mut output, &event.logger)?;
        }
        if let Some(caller) = event.caller
            && !c.caller_key.is_empty()
        {
            part(&mut output, &short_caller(&caller.file, caller.line))?;
        }
        if !c.message_key.is_empty() {
            part(&mut output, &event.message)?;
        }
        // Reserve the optional separator/braces before building the context.
        // Empty contexts cost nothing; a nonempty one must fit the complete line.
        let context = self
            .wrapped
            .context_stream(output.remaining(), local, emit)?;
        if !context.is_empty() {
            if !output.as_slice().is_empty() {
                output.byte(b'\t')?;
            }
            output.byte(b'{')?;
            output.bytes(&context)?;
            output.byte(b'}')?;
        }
        if let Some(stack) = event.stacktrace
            && !stack.is_empty()
            && !c.stacktrace_key.is_empty()
        {
            output.byte(b'\n')?;
            output.bytes(stack.as_bytes())?;
        }
        output.bytes(c.line_ending.as_bytes())?;
        Ok(output.into_vec())
    }
}
fn part(output: &mut Buffer, text: &str) -> Result<()> {
    if !output.as_slice().is_empty() {
        output.byte(b'\t')?;
    }
    output.bytes(text.as_bytes())
}
