// Copyright 2015 Matthew Holt and The Caddy Authors
// SPDX-License-Identifier: Apache-2.0
//! Original env-file byte semantics, including deliberately limited quoting.
use anyhow::{Result, anyhow, ensure};
use std::collections::BTreeMap;
fn spaces(input: &[u8]) -> usize {
    match input.first() {
        Some(b'\t'..=b'\r' | b' ') => 1,
        Some(0..=127) | None => 0,
        _ => {
            const SPACE: &[&str] = &[
                "\u{85}", "\u{a0}", "\u{1680}", "\u{2000}", "\u{2001}", "\u{2002}", "\u{2003}",
                "\u{2004}", "\u{2005}", "\u{2006}", "\u{2007}", "\u{2008}", "\u{2009}", "\u{200a}",
                "\u{2028}", "\u{2029}", "\u{202f}", "\u{205f}", "\u{3000}",
            ];
            SPACE
                .iter()
                .find(|s| input.starts_with(s.as_bytes()))
                .map_or(0, |s| s.len())
        }
    }
}
fn trim(mut input: &[u8]) -> &[u8] {
    loop {
        let n = spaces(input);
        if n == 0 {
            break;
        }
        input = &input[n..];
    }
    loop {
        let mut n = 0;
        for width in 1..=3.min(input.len()) {
            if spaces(&input[input.len() - width..]) == width {
                n = width;
                break;
            }
        }
        if n == 0 {
            break;
        }
        input = &input[..input.len() - n];
    }
    input
}
struct Lines<'a> {
    input: &'a [u8],
    number: usize,
}
impl<'a> Lines<'a> {
    fn next(&mut self) -> Result<Option<&'a [u8]>> {
        if self.input.is_empty() {
            return Ok(None);
        }
        let end = self.input.iter().position(|b| *b == b'\n');
        let count = end.map_or(self.input.len(), |n| n + 1);
        ensure!(
            count < 65536 || count == 65536 && end.is_some(),
            "environment line exceeds scanner limit at {}",
            self.number + 1
        );
        let mut line = &self.input[..end.unwrap_or(count)];
        self.input = &self.input[count..];
        self.number += 1;
        if line.last() == Some(&b'\r') {
            line = &line[..line.len() - 1]
        }
        Ok(Some(line))
    }
}
fn unescape(input: &[u8], quote: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut p = 0;
    while p < input.len() {
        if input[p] == b'\\' && input.get(p + 1) == Some(&quote) {
            p += 1
        }
        out.push(input[p]);
        p += 1
    }
    out
}
pub(super) fn parse(input: &[u8]) -> Result<BTreeMap<Vec<u8>, Vec<u8>>> {
    let mut lines = Lines { input, number: 0 };
    let mut result = BTreeMap::new();
    while let Some(raw) = lines.next()? {
        let first = trim(raw);
        if first.is_empty() || first.starts_with(b"#") {
            continue;
        }
        let equal = first
            .iter()
            .position(|b| *b == b'=')
            .ok_or_else(|| anyhow!("environment assignment missing at {}", lines.number))?;
        let key = &first[..equal];
        let key = key.strip_prefix(b"export ").unwrap_or(key);
        ensure!(
            !key.is_empty() && !key.contains(&b' '),
            "invalid environment key at {}",
            lines.number
        );
        let mut value = &first[equal + 1..];
        ensure!(
            !value.starts_with(b" ") && !value.starts_with(b"\t"),
            "environment value has leading whitespace at {}",
            lines.number
        );
        if let Some(comment) = value.iter().position(|b| *b == b'#') {
            value = &value[..comment];
            while matches!(value.last(), Some(b' ' | b'\t')) {
                value = &value[..value.len() - 1]
            }
        }
        let mut value = value.to_vec();
        if let Some(&quote) = value.first().filter(|q| matches!(q, b'\'' | b'"')) {
            let mut line = first.to_vec();
            while !line.ends_with(&[quote]) || line.ends_with(&[b'\\', quote]) {
                value = unescape(&value, quote);
                let Some(next) = lines.next()? else { break };
                line = unescape(next, quote);
                ensure!(
                    value
                        .len()
                        .checked_add(line.len())
                        .and_then(|n| n.checked_add(1))
                        .is_some_and(|n| n <= 64 * 1024 * 1024),
                    "environment multiline value exceeds limit"
                );
                value.push(b'\n');
                value.extend_from_slice(&line);
            }
            if value.first() == Some(&quote) {
                value.remove(0);
            }
            if value.last() == Some(&quote) {
                value.pop();
            }
        }
        result.insert(key.to_vec(), value);
    }
    Ok(result)
}
