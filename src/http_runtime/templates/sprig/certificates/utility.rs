use anyhow::{Result, anyhow};
use base64::Engine;
use base64::{
    alphabet,
    engine::{GeneralPurpose, GeneralPurposeConfig},
};
use openssl::asn1::{Asn1Object, Asn1OctetString};
use openssl::x509::X509Extension;
use std::net::IpAddr;

use pem::Pem;

pub(super) fn first_pem(data: &[u8]) -> Result<Pem> {
    let (label, bytes) = first_pem_parts(data)?;
    Ok(Pem::new(std::str::from_utf8(&label)?.to_owned(), bytes))
}

pub(super) fn first_pem_parts(data: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    // Reset at a later BEGIN instead of rescanning an invalid nested payload.
    // Go permits empty/otherwise nonstandard labels; each caller decides which
    // labels its decoded DER may use. Leading text and later blocks are ignored.
    let mut candidate: Option<(usize, Vec<u8>)> = None;
    let mut offset = 0;
    for raw in data.split_inclusive(|byte| *byte == b'\n') {
        let mut line = if let Some(line) = raw.strip_suffix(b"\n") {
            line.strip_suffix(b"\r").unwrap_or(line)
        } else {
            raw
        };
        while matches!(line.last(), Some(b' ' | b'\t')) {
            line = &line[..line.len() - 1];
        }
        if let Some(label) = line
            .strip_prefix(b"-----BEGIN ")
            .and_then(|v| v.strip_suffix(b"-----"))
        {
            candidate = Some((offset + raw.len(), label.to_vec()));
        } else if let Some((body_start, label)) = &candidate
            && line
                .strip_prefix(b"-----END ")
                .and_then(|v| v.strip_suffix(b"-----"))
                == Some(label.as_slice())
        {
            let body = &data[*body_start..offset];
            let mut start = 0;
            // PEM headers are parsed only before the first non-header line.
            for header in body.split_inclusive(|byte| *byte == b'\n') {
                if !header.contains(&b':') {
                    break;
                }
                start += header.len();
            }
            let encoded: Vec<_> = body[start..]
                .iter()
                .copied()
                .filter(|b| !matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
                .collect();
            if let Ok(bytes) = base64_engine().decode(&encoded) {
                return Ok((label.clone(), bytes));
            }
            candidate = None;
        }
        offset += raw.len();
    }
    Err(anyhow!("no PEM data in input"))
}

fn base64_engine() -> GeneralPurpose {
    GeneralPurpose::new(
        &alphabet::STANDARD,
        GeneralPurposeConfig::new().with_decode_allow_trailing_bits(true),
    )
}

pub(super) fn decode_base64(input: &str) -> Result<Vec<u8>> {
    let mut cleaned = String::with_capacity(input.len());
    for c in input.chars() {
        if c != '\r' && c != '\n' {
            cleaned.push(c);
        }
    }
    base64_engine()
        .decode(cleaned)
        .map_err(|e| anyhow!("base64 decode error: {}", e))
}

pub(super) fn ext(oid: &str, critical: bool, bytes: &[u8]) -> Result<X509Extension> {
    let obj = Asn1Object::from_str(oid)?;
    let octet_str = Asn1OctetString::new_from_bytes(bytes)?;
    let ext = X509Extension::new_from_der(&obj, critical, &octet_str)?;
    Ok(ext)
}

pub(super) fn san(ips: &[String], dns: &[String]) -> Result<Option<Vec<u8>>> {
    let mut items = Vec::new();
    for d in dns {
        anyhow::ensure!(d.is_ascii(), "alternate DNS name is not ASCII");
        items.push(tlv(0x82, d.as_bytes()));
    }
    for ip_str in ips {
        let ip = ip_str
            .parse::<IpAddr>()
            .map_err(|_| anyhow!("error parsing ip: {ip_str}"))?;
        let octets = match ip {
            IpAddr::V4(v4) => v4.octets().to_vec(),
            IpAddr::V6(v6) => {
                if let Some(v4) = v6.to_ipv4_mapped() {
                    v4.octets().to_vec()
                } else {
                    v6.octets().to_vec()
                }
            }
        };
        items.push(tlv(0x87, &octets));
    }
    if items.is_empty() {
        return Ok(None);
    }
    let mut body = Vec::new();
    for item in items {
        body.extend_from_slice(&item);
    }
    Ok(Some(der(0x30, &body)))
}

fn tlv(tag: u8, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 1 + data.len());
    out.push(tag);
    out.extend_from_slice(&der_length(data.len()));
    out.extend_from_slice(data);
    out
}

fn der_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else {
        let bytes = len.to_be_bytes();
        let mut start = 0;
        while start < bytes.len() && bytes[start] == 0 {
            start += 1;
        }
        let trimmed = &bytes[start..];
        let mut out = vec![0x80 | trimmed.len() as u8];
        out.extend_from_slice(trimmed);
        out
    }
}

pub(super) fn der(tag: u8, data: &[u8]) -> Vec<u8> {
    tlv(tag, data)
}
