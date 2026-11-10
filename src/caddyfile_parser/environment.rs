// Copyright 2015 Matthew Holt and The Caddy Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
use anyhow::{Result, bail};

/// Expand before tokenization, once per source file. An existing empty value
/// overrides the default. Inserted bytes are never recursively expanded.
pub(crate) fn replace_env(
    input: &[u8],
    lookup: impl Fn(&[u8]) -> Option<Vec<u8>>,
    max_bytes: usize,
) -> Result<Vec<u8>> {
    if input.len() > max_bytes {
        bail!("Caddyfile source exceeds byte limit");
    }
    let mut out = Vec::with_capacity(input.len());
    let mut offset = 0;
    while let Some(relative) = input[offset..].windows(2).position(|p| p == b"{$") {
        let begin = offset + relative;
        let Some(end_relative) = input[begin + 2..].iter().position(|b| *b == b'}') else {
            break;
        };
        let end = begin + 2 + end_relative;
        let expression = &input[begin + 2..end];
        if expression.is_empty() {
            append(&mut out, &input[offset..end + 1], max_bytes)?;
            offset = end + 1;
            continue;
        }
        let colon = expression.iter().position(|b| *b == b':');
        let key = colon.map_or(expression, |n| &expression[..n]);
        let fallback = colon.map_or(&[][..], |n| &expression[n + 1..]);
        let value = if key.is_empty() || key.contains(&b'=') || key.contains(&0) {
            None
        } else {
            lookup(key)
        };
        append(&mut out, &input[offset..begin], max_bytes)?;
        append(&mut out, value.as_deref().unwrap_or(fallback), max_bytes)?;
        offset = end + 1;
    }
    append(&mut out, &input[offset..], max_bytes)?;
    Ok(out)
}

fn append(out: &mut Vec<u8>, bytes: &[u8], limit: usize) -> Result<()> {
    if out
        .len()
        .checked_add(bytes.len())
        .is_none_or(|size| size > limit)
    {
        bail!("Caddyfile environment expansion exceeds byte limit");
    }
    out.extend_from_slice(bytes);
    Ok(())
}
