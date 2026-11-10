//! Bounded DER framing only, for lossless Name preservation. Non-Name fields
//! are still decoded and roundtripped through x509-cert by the caller.
use anyhow::{Result, anyhow, ensure};
pub(super) fn wrap(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut output = vec![tag];
    if body.len() < 128 {
        output.push(body.len() as u8);
    } else {
        let bytes = body.len().to_be_bytes();
        let start = bytes
            .iter()
            .position(|v| *v != 0)
            .unwrap_or(bytes.len() - 1);
        output.push(0x80 | ((bytes.len() - start) as u8));
        output.extend_from_slice(&bytes[start..]);
    }
    output.extend_from_slice(body);
    output
}
fn item(bytes: &[u8]) -> Result<(usize, usize)> {
    ensure!(bytes.len() >= 2, "truncated DER item");
    let mut offset = 1;
    if bytes[0] & 31 == 31 {
        let mut number = 0u32;
        let first = *bytes
            .get(offset)
            .ok_or_else(|| anyhow!("missing DER tag"))?;
        ensure!(first != 0x80, "nonminimal DER tag");
        loop {
            let b = *bytes
                .get(offset)
                .ok_or_else(|| anyhow!("truncated DER tag"))?;
            number = number
                .checked_mul(128)
                .and_then(|n| n.checked_add(u32::from(b & 127)))
                .ok_or_else(|| anyhow!("DER tag overflow"))?;
            offset += 1;
            if b & 128 == 0 {
                break;
            }
        }
        ensure!(number >= 31, "nonminimal DER tag");
    }
    let first = *bytes
        .get(offset)
        .ok_or_else(|| anyhow!("missing DER length"))?;
    offset += 1;
    let length = if first & 128 == 0 {
        usize::from(first)
    } else {
        let count = usize::from(first & 127);
        ensure!(
            count > 0 && count <= std::mem::size_of::<usize>(),
            "indefinite/oversized DER length"
        );
        let end = offset
            .checked_add(count)
            .ok_or_else(|| anyhow!("DER length overflow"))?;
        let encoded = bytes
            .get(offset..end)
            .ok_or_else(|| anyhow!("truncated DER length"))?;
        ensure!(encoded[0] != 0, "nonminimal DER length");
        offset = end;
        let mut n = 0usize;
        for b in encoded {
            n = n
                .checked_mul(256)
                .and_then(|v| v.checked_add(usize::from(*b)))
                .ok_or_else(|| anyhow!("DER length overflow"))?;
        }
        ensure!(n >= 128, "nonminimal long DER length");
        n
    };
    let total = offset
        .checked_add(length)
        .ok_or_else(|| anyhow!("DER extent overflow"))?;
    ensure!(total <= bytes.len(), "truncated DER content");
    Ok((offset, total))
}
pub(super) fn parts(bytes: &[u8], tag: u8) -> Result<Vec<&[u8]>> {
    let (header, total) = item(bytes)?;
    ensure!(
        bytes[0] == tag && total == bytes.len(),
        "invalid DER container or trailing bytes"
    );
    let mut body = &bytes[header..];
    let mut output = Vec::new();
    while !body.is_empty() {
        ensure!(output.len() < 32768, "DER node limit");
        let (_, n) = item(body)?;
        output.push(&body[..n]);
        body = &body[n..];
    }
    Ok(output)
}
pub(super) fn validate(bytes: &[u8]) -> Result<()> {
    fn walk(bytes: &[u8], depth: usize, nodes: &mut usize) -> Result<()> {
        ensure!(depth <= 32 && *nodes < 32768, "DER complexity limit");
        *nodes += 1;
        let (header, total) = item(bytes)?;
        ensure!(total == bytes.len(), "trailing DER bytes");
        if bytes[0] & 0xe0 == 0 {
            ensure!(
                !matches!(bytes[0] & 31, 0 | 16 | 17),
                "invalid primitive universal DER type"
            );
        }
        if bytes[0] & 32 != 0 {
            if bytes[0] & 0xc0 == 0 {
                ensure!(
                    matches!(bytes[0] & 31, 8 | 11 | 16 | 17 | 29),
                    "constructed DER primitive"
                );
            }
            let mut body = &bytes[header..];
            while !body.is_empty() {
                let (_, n) = item(body)?;
                walk(&body[..n], depth + 1, nodes)?;
                body = &body[n..];
            }
        }
        Ok(())
    }
    walk(bytes, 0, &mut 0)
}
pub(super) fn name(bytes: &[u8]) -> Result<()> {
    validate(bytes)?;
    for rdn in parts(bytes, 0x30)? {
        let attributes = parts(rdn, 0x31)?;
        ensure!(!attributes.is_empty(), "empty RDN set");
        for attr in attributes {
            let fields = parts(attr, 0x30)?;
            ensure!(fields.len() == 2, "invalid Name attribute");
            use der::Decode;
            der::asn1::ObjectIdentifier::from_der(fields[0])?;
        }
    }
    Ok(())
}
pub(super) fn tbs_fields(tbs: &[u8]) -> Result<(Vec<&[u8]>, usize)> {
    let fields = parts(tbs, 0x30)?;
    let base = usize::from(fields.first().is_some_and(|v| v[0] == 0xa0));
    ensure!(fields.len() >= base + 6, "truncated TBS certificate");
    ensure!(
        fields[base][0] == 2 && fields[base + 1..base + 6].iter().all(|v| v[0] == 0x30),
        "invalid TBS field tags"
    );
    name(fields[base + 2])?;
    name(fields[base + 4])?;
    Ok((fields, base))
}

/// New CSR subjects use strict string values and canonical SET order. Imported
/// issuer Names remain opaque: do not rewrite or reject old CA attributes.
pub(super) fn csr_name(bytes: &[u8]) -> Result<()> {
    name(bytes)?;
    for rdn in parts(bytes, 0x30)? {
        let attributes = parts(rdn, 0x31)?;
        ensure!(
            attributes.windows(2).all(|v| v[0] <= v[1]),
            "noncanonical CSR RDN order"
        );
        for attribute in attributes {
            let fields = parts(attribute, 0x30)?;
            let value = fields[1];
            let (header, _) = item(value)?;
            let content = &value[header..];
            match value[0] {
                12 => {
                    std::str::from_utf8(content)?;
                }
                18 => ensure!(
                    content.iter().all(|v| v.is_ascii_digit() || *v == b' '),
                    "invalid NumericString"
                ),
                19 => ensure!(
                    content
                        .iter()
                        .all(|v| v.is_ascii_alphanumeric() || b" '()+,-./:=?*&".contains(v)),
                    "invalid PrintableString"
                ),
                20 => {}
                22 => ensure!(content.is_ascii(), "invalid IA5String"),
                26 => ensure!(
                    content.iter().all(|v| (32..=126).contains(v)),
                    "invalid VisibleString"
                ),
                28 => {
                    ensure!(content.len().is_multiple_of(4), "invalid UniversalString");
                    for point in content.as_chunks::<4>().0 {
                        ensure!(
                            char::from_u32(u32::from_be_bytes(*point)).is_some(),
                            "invalid UniversalString scalar"
                        );
                    }
                }
                30 => {
                    ensure!(content.len().is_multiple_of(2), "invalid BMPString");
                    for point in content.as_chunks::<2>().0 {
                        let point = u16::from_be_bytes(*point);
                        ensure!(
                            !matches!(point,0xd800..=0xdfff|0xfdd0..=0xfdef|0xfffe|0xffff),
                            "invalid BMPString scalar"
                        );
                    }
                }
                _ => return Err(anyhow!("unsupported CSR subject value type")),
            }
        }
    }
    Ok(())
}
