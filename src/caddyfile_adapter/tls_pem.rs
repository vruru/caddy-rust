// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file of the original Go distribution.
// Native byte-oriented PEM compatibility decoding for adaptation only.
use super::budget::{Budget, add, mul};
use anyhow::{Result, ensure};
use base64::{
    Engine, alphabet,
    engine::{GeneralPurpose, GeneralPurposeConfig},
};
use std::path::Path;

const BEGIN: &[u8] = b"-----BEGIN ";
const END: &[u8] = b"\n-----END ";
const DASHES: &[u8] = b"-----";
const BASE64: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new().with_decode_allow_trailing_bits(true),
);
const MAX_FILE_BYTES: u64 = 8 << 20;

pub(super) fn read_certificates(
    path: &str,
    cwd: &Path,
    budget: &mut Budget,
) -> Result<Vec<String>> {
    budget.work(path.len() as u64 + 1)?;
    budget.materialize(path.len() as u64 + 128)?;
    let path = cwd.join(path);
    let metadata = std::fs::metadata(&path)?;
    ensure!(
        metadata.is_file(),
        "Caddyfile certificate source must be a regular file"
    );
    let len = metadata.len();
    ensure!(
        len <= MAX_FILE_BYTES,
        "Caddyfile certificate source byte limit exceeded"
    );
    // The prior size bounds the actual shared read, including a file changed
    // between metadata and open. Reserve decoding/DER/base64/array copies first.
    budget.work(mul(len + 1, 8)?)?;
    budget.materialize(add(mul(len, 8)?, 2048)?)?;
    let bytes = crate::caddyfile_parser::read_config_source(&path, len as usize)?;
    let mut rest = bytes.as_slice();
    let mut certificates = Vec::new();
    while let Some((label, der, consumed)) = decode(rest) {
        ensure!(
            label == b"CERTIFICATE",
            "no CERTIFICATE pem block found in {}",
            path.display()
        );
        certificates.push(BASE64.encode(der));
        rest = &rest[consumed..];
    }
    ensure!(
        !certificates.is_empty(),
        "no CERTIFICATE pem block found in {}",
        path.display()
    );
    Ok(certificates)
}

// Mirrors the linear END/last-BEGIN decoder in Go encoding/pem. The parser
// accepts arbitrary prefix bytes, ignores malformed blocks, and never validates
// the certificate itself. Runtime certificate validation remains mandatory.
pub(super) fn decode(data: &[u8]) -> Option<(Vec<u8>, Vec<u8>, usize)> {
    let mut start = 0;
    let mut next_end = 0isize;
    loop {
        if next_end < 0 || next_end as usize > data.len() - start {
            return None;
        }
        start += next_end as usize;
        let rest = &data[start..];
        let mut end = find(rest, END)? as isize;
        next_end = end + END.len() as isize;
        let Some(begin) = rest[..end as usize]
            .windows(BEGIN.len())
            .rposition(|v| v == BEGIN)
        else {
            continue;
        };
        if begin > 0 && rest[begin - 1] != b'\n' {
            continue;
        }
        let consumed = begin + BEGIN.len();
        start += consumed;
        end -= consumed as isize;
        next_end -= consumed as isize;
        let (label_line, line_len) = line(&data[start..]);
        start += line_len;
        end -= line_len as isize;
        next_end -= line_len as isize;
        let Some(label) = label_line.strip_suffix(DASHES) else {
            continue;
        };
        let mut headers = false;
        loop {
            if start == data.len() {
                return None;
            }
            let (header, len) = line(&data[start..]);
            if !header.contains(&b':') {
                break;
            }
            headers = true;
            start += len;
            end -= len as isize;
            next_end -= len as isize;
        }
        if headers && end < 0 {
            continue;
        }
        if next_end < 0 {
            continue;
        }
        let Some(trailer) = data.get(start + next_end as usize..) else {
            continue;
        };
        let trailer_len = label.len().checked_add(DASHES.len())?;
        let Some(end_label) = trailer.get(..trailer_len) else {
            continue;
        };
        if !end_label.starts_with(label) || !end_label.ends_with(DASHES) {
            continue;
        }
        if !line(&trailer[trailer_len..]).0.is_empty() {
            continue;
        }
        let der = if end > 0 {
            let encoded = data.get(start..start + end as usize)?;
            let compact = encoded
                .iter()
                .copied()
                .filter(|v| !matches!(v, b' ' | b'\t' | b'\r' | b'\n'))
                .collect::<Vec<_>>();
            let Ok(value) = BASE64.decode(compact) else {
                continue;
            };
            value
        } else {
            Vec::new()
        };
        let footer_start = (start as isize)
            .checked_add(end)?
            .checked_add(END.len() as isize - 1)?;
        if footer_start < 0 {
            return None;
        }
        let footer_start = footer_start as usize;
        let (_, len) = line(data.get(footer_start..)?);
        return Some((label.to_vec(), der, footer_start + len));
    }
}
fn find(input: &[u8], needle: &[u8]) -> Option<usize> {
    input.windows(needle.len()).position(|v| v == needle)
}
fn line(input: &[u8]) -> (&[u8], usize) {
    let newline = input.iter().position(|v| *v == b'\n');
    let consumed = newline.map_or(input.len(), |n| n + 1);
    let mut end = newline.unwrap_or(input.len());
    if newline.is_some() && end > 0 && input[end - 1] == b'\r' {
        end -= 1;
    }
    while end > 0 && matches!(input[end - 1], b' ' | b'\t') {
        end -= 1;
    }
    (&input[..end], consumed)
}
