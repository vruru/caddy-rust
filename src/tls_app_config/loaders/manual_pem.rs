// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license reproduced
// in THIRD-PARTY-NOTICES. Based on Go 1.27.3 encoding/pem/pem.go.
//! Provision-time manual PEM compatibility; persisted material stays strict.
use anyhow::{Result, anyhow, ensure};
use base64::{
    Engine,
    engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig, general_purpose::STANDARD},
};
use zeroize::Zeroizing;

const LIMIT: usize = super::MAX_MATERIAL;
const MAX_BLOCKS: usize = 32;
const BEGIN: &[u8] = b"-----BEGIN ";
const END: &[u8] = b"\n-----END ";

struct Block<'a> {
    label: &'a [u8],
    der: Zeroizing<Vec<u8>>,
}
struct Decoder<'a> {
    input: &'a [u8],
    cursor: usize,
    count: usize,
}
fn line(input: &[u8], start: usize) -> (&[u8], usize) {
    let (mut end, next) = match memchr::memchr(b'\n', &input[start..]) {
        Some(n) => {
            let end = start + n;
            (
                if end > start && input[end - 1] == b'\r' {
                    end - 1
                } else {
                    end
                },
                end + 1,
            )
        }
        None => (input.len(), input.len()),
    };
    while end > start && matches!(input[end - 1], b' ' | b'\t') {
        end -= 1;
    }
    (&input[start..end], next)
}
impl<'a> Decoder<'a> {
    fn new(input: &'a [u8]) -> Result<Self> {
        ensure!(
            input.len() <= LIMIT,
            "configured certificate input exceeds size limit"
        );
        Ok(Self {
            input,
            cursor: 0,
            count: 0,
        })
    }
    // Go 1.27 encoding/pem.Decode searches END, then the last preceding BEGIN.
    // Failed framing/base64 candidates are skipped; decoded but invalid DER is
    // returned to the caller and must never be replaced by a later key.
    fn next(&mut self) -> Result<Option<Block<'a>>> {
        let mut rest = &self.input[self.cursor..];
        let mut trailer_index = 0isize;
        loop {
            if trailer_index < 0 || trailer_index as usize > rest.len() {
                self.cursor = self.input.len();
                return Ok(None);
            }
            rest = &rest[trailer_index as usize..];
            let Some(end) = memchr::memmem::find(rest, END) else {
                self.cursor = self.input.len();
                return Ok(None);
            };
            let mut end_index = end as isize;
            trailer_index = (end + END.len()) as isize;
            let begin = memchr::memmem::rfind(&rest[..end], BEGIN);
            let Some(begin) = begin.filter(|&n| n == 0 || rest[n - 1] == b'\n') else {
                continue;
            };
            let consumed = begin + BEGIN.len();
            rest = &rest[consumed..];
            end_index -= consumed as isize;
            trailer_index -= consumed as isize;
            let (label, consumed) = line(rest, 0);
            rest = &rest[consumed..];
            end_index -= consumed as isize;
            trailer_index -= consumed as isize;
            let Some(label) = label.strip_suffix(b"-----") else {
                continue;
            };
            let mut headers = false;
            loop {
                if rest.is_empty() {
                    self.cursor = self.input.len();
                    return Ok(None);
                }
                let (value, consumed) = line(rest, 0);
                if !value.contains(&b':') {
                    break;
                }
                headers = true;
                rest = &rest[consumed..];
                end_index -= consumed as isize;
                trailer_index -= consumed as isize;
            }
            if headers && end_index < 0 {
                continue;
            }
            // The signed positions intentionally preserve Go's nil result when
            // header consumption moves a subsequent retry before this slice.
            ensure!(
                trailer_index >= 0 && trailer_index as usize <= rest.len(),
                "invalid configured PEM framing"
            );
            let trailer = trailer_index as usize;
            let Some(footer_end) = trailer
                .checked_add(label.len())
                .and_then(|n| n.checked_add(5))
                .filter(|&n| n <= rest.len())
            else {
                continue;
            };
            if &rest[trailer..footer_end - 5] != label
                || &rest[footer_end - 5..footer_end] != b"-----"
            {
                continue;
            }
            let (tail, _) = line(rest, footer_end);
            if !tail.is_empty() {
                continue;
            }
            let encoded_input = if end_index > 0 {
                &rest[..end_index as usize]
            } else {
                &[]
            };
            let mut encoded = Zeroizing::new(Vec::new());
            encoded
                .try_reserve_exact(encoded_input.len())
                .map_err(|_| anyhow!("configured PEM memory limit"))?;
            encoded.extend(
                encoded_input
                    .iter()
                    .copied()
                    .filter(|c| !matches!(c, b' ' | b'\t' | b'\r' | b'\n')),
            );
            let mut der = Zeroizing::new(Vec::new());
            der.try_reserve_exact(encoded.len() / 4 * 3 + 3)
                .map_err(|_| anyhow!("configured PEM memory limit"))?;
            let engine = GeneralPurpose::new(
                &base64::alphabet::STANDARD,
                GeneralPurposeConfig::new()
                    .with_decode_padding_mode(DecodePaddingMode::RequireCanonical)
                    .with_decode_allow_trailing_bits(true),
            );
            if engine.decode_vec(&encoded, &mut der).is_err() {
                continue;
            }
            self.count += 1;
            ensure!(
                self.count <= MAX_BLOCKS,
                "configured PEM block count limit exceeded"
            );
            let ending = end_index + (END.len() - 1) as isize;
            ensure!(
                ending >= 0 && ending as usize <= rest.len(),
                "invalid configured PEM framing"
            );
            let (_, consumed) = line(rest, ending as usize);
            self.cursor = self.input.len() - rest.len() + consumed;
            return Ok(Some(Block { label, der }));
        }
    }
}
fn append(output: &mut Vec<u8>, label: &str, der: &[u8]) -> Result<()> {
    let encoded = Zeroizing::new(STANDARD.encode(der));
    let size = output
        .len()
        .checked_add(encoded.len())
        .and_then(|n| n.checked_add(encoded.len().div_ceil(64)))
        .and_then(|n| n.checked_add(2 * label.len() + 32))
        .ok_or_else(|| anyhow!("configured PEM size overflow"))?;
    ensure!(
        size <= LIMIT,
        "configured certificate input exceeds size limit"
    );
    output
        .try_reserve(size - output.len())
        .map_err(|_| anyhow!("configured PEM memory limit"))?;
    output.extend_from_slice(b"-----BEGIN ");
    output.extend_from_slice(label.as_bytes());
    output.extend_from_slice(b"-----\n");
    for part in encoded.as_bytes().chunks(64) {
        output.extend_from_slice(part);
        output.push(b'\n');
    }
    output.extend_from_slice(b"-----END ");
    output.extend_from_slice(label.as_bytes());
    output.extend_from_slice(b"-----\n");
    Ok(())
}
fn private(label: &[u8]) -> bool {
    label == b"PRIVATE KEY" || label.ends_with(b" PRIVATE KEY")
}
fn key_pem(der: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    // X509KeyPair parses the selected DER independently of its original label.
    // Borrowing avoids an unzeroized temporary DER copy.
    let key = rustls::pki_types::PrivateKeyDer::try_from(der)
        .map_err(|_| anyhow!("invalid configured private key DER"))?;
    let label = match &key {
        rustls::pki_types::PrivateKeyDer::Pkcs1(_) => "RSA PRIVATE KEY",
        rustls::pki_types::PrivateKeyDer::Pkcs8(_) => "PRIVATE KEY",
        rustls::pki_types::PrivateKeyDer::Sec1(_) => "EC PRIVATE KEY",
        _ => return Err(anyhow!("unsupported configured private key DER")),
    };
    let mut output = Zeroizing::new(Vec::new());
    append(&mut output, label, key.secret_der())?;
    Ok(output)
}
pub(super) fn file_key(input: &[u8]) -> Result<()> {
    // Match FileLoader/StorageLoader's encrypted-prefix rejection without
    // reproducing their short-input slice panic. PEMLoader has no such check.
    ensure!(
        !input[..input.len().min(40)]
            .windows(9)
            .any(|s| s == b"ENCRYPTED"),
        "encrypted configured private keys are not supported"
    );
    Ok(())
}
pub(super) fn pair(certificate: &[u8], key: &[u8]) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>)> {
    let mut certs = Vec::new();
    let mut decoder = Decoder::new(certificate)?;
    while let Some(block) = decoder.next()? {
        if block.label == b"CERTIFICATE" {
            append(&mut certs, "CERTIFICATE", &block.der)?;
        }
    }
    ensure!(!certs.is_empty(), "configured certificate block missing");
    let mut decoder = Decoder::new(key)?;
    let mut chosen = None;
    while let Some(block) = decoder.next()? {
        if chosen.is_none() && private(block.label) {
            chosen = Some(key_pem(&block.der)?);
            break;
        }
    }
    Ok((
        certs,
        chosen.ok_or_else(|| anyhow!("configured private key block missing"))?,
    ))
}
pub(super) fn bundle(input: &[u8]) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>)> {
    let mut decoder = Decoder::new(input)?;
    let mut certs = Vec::new();
    let mut chosen = None;
    while let Some(block) = decoder.next()? {
        if block.label == b"CERTIFICATE" {
            append(&mut certs, "CERTIFICATE", &block.der)?;
        } else if block.label == b"EC PARAMETERS" {
            if chosen.is_none() {
                let next = decoder
                    .next()?
                    .ok_or_else(|| anyhow!("EC parameters must immediately precede private key"))?;
                ensure!(
                    next.label == b"EC PRIVATE KEY",
                    "EC parameters must immediately precede private key"
                );
                chosen = Some(key_pem(&next.der)?);
            }
        } else if private(block.label) {
            if chosen.is_none() {
                chosen = Some(key_pem(&block.der)?);
            }
        } else {
            return Err(anyhow!("unsupported configured folder PEM block"));
        }
    }
    ensure!(!certs.is_empty(), "configured certificate block missing");
    Ok((
        certs,
        chosen.ok_or_else(|| anyhow!("configured private key block missing"))?,
    ))
}
