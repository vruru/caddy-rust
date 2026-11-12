//! Allocation-free shape admission before borrowed/shallow X.509 parsing.
use anyhow::{Result, anyhow, ensure};
use std::mem::size_of;
#[derive(Debug)]
pub(crate) struct Resource(pub &'static str);
impl std::fmt::Display for Resource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "certificate shape resource limit: {}", self.0)
    }
}
impl std::error::Error for Resource {}
struct Item<'a> {
    tag: u8,
    raw: &'a [u8],
    body: &'a [u8],
}
fn next<'a>(input: &mut &'a [u8]) -> Result<Item<'a>> {
    let bytes = *input;
    ensure!(bytes.len() >= 2, "short ACME DER header");
    let mut header = 2usize;
    let length = if bytes[1] < 128 {
        bytes[1] as usize
    } else {
        let count = (bytes[1] & 127) as usize;
        ensure!(
            (1..=4).contains(&count) && bytes.len() >= 2 + count,
            "invalid ACME DER length"
        );
        ensure!(bytes[2] != 0, "noncanonical ACME DER length");
        header += count;
        let mut n = 0usize;
        for b in &bytes[2..header] {
            n = n
                .checked_mul(256)
                .and_then(|v| v.checked_add(*b as usize))
                .ok_or_else(|| anyhow!("ACME DER size overflow"))?;
        }
        ensure!(n >= 128, "noncanonical ACME DER length");
        n
    };
    let end = header
        .checked_add(length)
        .ok_or_else(|| anyhow!("ACME DER size overflow"))?;
    ensure!(end <= bytes.len(), "truncated ACME DER");
    *input = &bytes[end..];
    Ok(Item {
        tag: bytes[0],
        raw: &bytes[..end],
        body: &bytes[header..end],
    })
}
fn take<'a>(input: &mut &'a [u8], tag: u8) -> Result<Item<'a>> {
    let item = next(input)?;
    ensure!(item.tag == tag, "unexpected ACME DER tag");
    Ok(item)
}
fn add(value: &mut usize, n: usize) -> Result<()> {
    *value = value
        .checked_add(n)
        .ok_or_else(|| Resource("scratch arithmetic overflow"))?;
    Ok(())
}
fn mul(a: usize, b: usize) -> Result<usize> {
    a.checked_mul(b)
        .ok_or_else(|| Resource("scratch arithmetic overflow").into())
}
fn slots(n: usize) -> Result<usize> {
    if n == 0 {
        return Ok(0);
    }
    // For the pinned parser's Vec element types MIN_NON_ZERO_CAP is four.
    // At a 2^k+1 push the old 2^k allocation overlaps the new 2^(k+1).
    let capacity = n
        .checked_next_power_of_two()
        .ok_or(Resource("vector capacity"))?
        .max(4);
    if capacity > 4 {
        capacity
            .checked_add(capacity / 2)
            .ok_or_else(|| Resource("vector reallocation capacity").into())
    } else {
        Ok(capacity)
    }
}

fn names(mut sequence: &[u8]) -> Result<(usize, usize, usize)> {
    let mut rdns = 0usize;
    let mut attrs = 0usize;
    let mut cost = 0usize;
    while !sequence.is_empty() {
        let mut set = take(&mut sequence, 0x31)?.body;
        let mut count = 0usize;
        add(&mut rdns, 1)?;
        while !set.is_empty() {
            take(&mut set, 0x30)?;
            add(&mut count, 1)?;
            add(&mut attrs, 1)?;
        }
        add(
            &mut cost,
            mul(
                slots(count)?,
                size_of::<x509_parser::x509::AttributeTypeAndValue<'static>>(),
            )?,
        )?;
    }
    add(
        &mut cost,
        mul(
            slots(rdns)?,
            size_of::<x509_parser::x509::RelativeDistinguishedName<'static>>(),
        )?,
    )?;
    Ok((rdns, attrs, cost))
}
pub(super) fn shallow_cost(der: &[u8]) -> Result<usize> {
    let mut input = der;
    let mut certificate = take(&mut input, 0x30)?.body;
    ensure!(input.is_empty(), "trailing ACME certificate DER");
    let mut tbs = take(&mut certificate, 0x30)?.body;
    if tbs.first() == Some(&0xa0) {
        take(&mut tbs, 0xa0)?;
    }
    let mut cost = 4096usize;
    add(&mut cost, mul(take(&mut tbs, 0x02)?.body.len(), 4)?)?;
    take(&mut tbs, 0x30)?;
    add(&mut cost, names(take(&mut tbs, 0x30)?.body)?.2)?;
    take(&mut tbs, 0x30)?;
    add(&mut cost, names(take(&mut tbs, 0x30)?.body)?.2)?;
    if take(&mut tbs, 0x30)?.raw.len() > 16384 {
        return Err(Resource("public key encoding").into());
    }
    while !tbs.is_empty() {
        let item = next(&mut tbs)?;
        if item.tag == 0xa3 {
            let mut tagged = item.body;
            let mut extensions = take(&mut tagged, 0x30)?.body;
            ensure!(tagged.is_empty(), "trailing ACME extension container");
            let mut count = 0usize;
            while !extensions.is_empty() {
                take(&mut extensions, 0x30)?;
                add(&mut count, 1)?;
            }
            add(
                &mut cost,
                mul(
                    slots(count)?,
                    size_of::<x509_parser::extensions::X509Extension<'static>>(),
                )?,
            )?;
        }
    }
    if take(&mut certificate, 0x30)?.raw.len() > 16384 {
        return Err(Resource("signature algorithm encoding").into());
    }
    if take(&mut certificate, 0x03)?.raw.len() > 16384 {
        return Err(Resource("signature encoding").into());
    }
    ensure!(certificate.is_empty(), "trailing ACME certificate fields");
    Ok(cost)
}
pub(super) fn name_cost(name: &[u8]) -> Result<usize> {
    let mut input = name;
    let sequence = take(&mut input, 0x30)?.body;
    ensure!(input.is_empty(), "trailing ACME issuer name");
    let (rdns, attrs, _) = names(sequence)?;
    let mut cost = 4096usize;
    // Name::fill_from_rdns copies typed attributes and selected strings. The
    // 64-byte factor includes the decoder's OID/decimal/display String vectors;
    // per-attribute costs separately cover two minimum-capacity Vec<Attribute>s.
    add(&mut cost, mul(name.len(), 64)?)?;
    let per_attr = 8 * size_of::<crate::http_runtime::pkix_name::Attribute>()
        + 8 * size_of::<String>()
        + 8 * size_of::<u32>()
        + 128;
    add(&mut cost, mul(attrs, per_attr)?)?;
    add(
        &mut cost,
        mul(
            rdns,
            8 * size_of::<Vec<crate::http_runtime::pkix_name::Attribute>>(),
        )?,
    )?;
    Ok(cost)
}
