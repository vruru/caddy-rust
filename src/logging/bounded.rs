// Copyright 2016 Uber Technologies, Inc. SPDX-License-Identifier: MIT
//! Bounded Zap-style escaping; unlike encoding/json HTML and U+2028 are literal.
use anyhow::Result;
#[derive(Debug)]
pub(super) struct ByteLimit(pub(super) &'static str);
impl std::fmt::Display for ByteLimit {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.write_str(self.0)
    }
}
impl std::error::Error for ByteLimit {}
pub(super) fn reflection_error(error: crate::admin_json::ConfigError) -> anyhow::Error {
    if error.status == 413 {
        ByteLimit("reflected log field byte limit exceeded").into()
    } else {
        anyhow::anyhow!("reflected log field encoding failed")
    }
}
pub(super) struct Buffer {
    data: Vec<u8>,
    limit: usize,
}
impl Buffer {
    pub(super) fn new(limit: usize) -> Self {
        Self {
            data: Vec::new(),
            limit,
        }
    }
    pub(super) fn bytes(&mut self, bytes: &[u8]) -> Result<()> {
        let needed = self
            .data
            .len()
            .checked_add(bytes.len())
            .filter(|n| *n <= self.limit)
            .ok_or(ByteLimit("log encoding byte limit exceeded"))?;
        if needed > self.data.capacity() {
            let grown = self
                .data
                .capacity()
                .saturating_mul(2)
                .max(32)
                .min(self.limit)
                .max(needed);
            self.data.try_reserve_exact(grown - self.data.len())?;
        }
        self.data.extend_from_slice(bytes);
        Ok(())
    }
    pub(super) fn byte(&mut self, byte: u8) -> Result<()> {
        self.bytes(&[byte])
    }
    pub(super) fn remaining(&self) -> usize {
        self.limit - self.data.len()
    }
    pub(super) fn as_slice(&self) -> &[u8] {
        &self.data
    }
    pub(super) fn into_vec(self) -> Vec<u8> {
        self.data
    }
    pub(super) fn quoted(&mut self, input: &[u8]) -> Result<()> {
        self.byte(b'"')?;
        let (mut i, mut last) = (0, 0);
        while i < input.len() {
            let byte = input[i];
            if (0x20..0x80).contains(&byte) && byte != b'"' && byte != b'\\' {
                i += 1;
                continue;
            }
            if byte >= 0x80 {
                let width = match byte {
                    0xc2..=0xdf => 2,
                    0xe0..=0xef => 3,
                    0xf0..=0xf4 => 4,
                    _ => 0,
                };
                if width > 0
                    && input
                        .get(i..i + width)
                        .is_some_and(|s| std::str::from_utf8(s).is_ok())
                {
                    i += width;
                    continue;
                }
            }
            self.bytes(&input[last..i])?;
            match byte {
                b'"' => self.bytes(b"\\\"")?,
                b'\\' => self.bytes(b"\\\\")?,
                b'\n' => self.bytes(b"\\n")?,
                b'\r' => self.bytes(b"\\r")?,
                b'\t' => self.bytes(b"\\t")?,
                0..0x20 => {
                    const HEX: &[u8; 16] = b"0123456789abcdef";
                    self.bytes(&[
                        b'\\',
                        b'u',
                        b'0',
                        b'0',
                        HEX[(byte >> 4) as usize],
                        HEX[(byte & 15) as usize],
                    ])?;
                }
                _ => self.bytes(b"\\ufffd")?,
            }
            i += 1;
            last = i;
        }
        self.bytes(&input[last..])?;
        self.byte(b'"')
    }
}
