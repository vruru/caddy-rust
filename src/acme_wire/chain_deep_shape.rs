//! Borrowed shape pass for x509-parser 0.18.1's supported deep extensions.
//! The parser's heap collections contain the concrete types listed below.
//! Every dynamic element corresponds to a DER node. Eight max-sized slots
//! per node cover two overlapping Vec allocations (each minimum capacity4,
//! or geometric growth below2*n). Serial/Name/outer extension Vecs are charged
//! by shallow_cost; SCT's non-DER entry list is counted separately.
//! Unknown extension payload is opaque to the pinned parser and this pass.
#[derive(Debug)]
pub(crate) enum FootprintError {
    Malformed(&'static str),
    Resource(&'static str),
}
impl std::fmt::Display for FootprintError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(s) => write!(f, "malformed certificate footprint: {s}"),
            Self::Resource(s) => write!(f, "certificate footprint resource limit: {s}"),
        }
    }
}
impl std::error::Error for FootprintError {}
type Result<T> = std::result::Result<T, FootprintError>;
use std::mem::size_of;
use x509_parser::{extensions::*, oid_registry::*, x509::*};

fn add(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b)
        .ok_or_else(|| FootprintError::Resource("AST arithmetic overflow"))
}
fn mul(a: usize, b: usize) -> Result<usize> {
    a.checked_mul(b)
        .ok_or_else(|| FootprintError::Resource("AST arithmetic overflow"))
}
fn max_record() -> usize {
    [
        size_of::<GeneralName<'static>>(),
        size_of::<GeneralSubtree<'static>>(),
        size_of::<PolicyInformation<'static>>(),
        size_of::<PolicyQualifierInfo<'static>>(),
        size_of::<PolicyMapping<'static>>(),
        size_of::<AccessDescription<'static>>(),
        size_of::<CRLDistributionPoint<'static>>(),
        size_of::<AttributeTypeAndValue<'static>>(),
        size_of::<RelativeDistinguishedName<'static>>(),
        size_of::<x509_parser::der_parser::ber::BerObject<'static>>(),
        size_of::<x509_parser::asn1_rs::Oid<'static>>(),
    ]
    .into_iter()
    .max()
    .unwrap_or(0)
}
struct Item<'a> {
    tag: u8,
    body: &'a [u8],
}
fn next<'a>(input: &mut &'a [u8]) -> Option<Item<'a>> {
    let b = *input;
    let tag = *b.first()?;
    let mut header = 1usize;
    if tag & 31 == 31 {
        loop {
            let n = *b.get(header)?;
            header += 1;
            if n & 128 == 0 {
                break;
            }
            if header > 8 {
                return None;
            }
        }
    }
    let first = *b.get(header)?;
    header += 1;
    let length = if first < 128 {
        first as usize
    } else {
        let n = (first & 127) as usize;
        if n == 0 || n > 4 {
            return None;
        }
        let mut value = 0usize;
        for byte in b.get(header..header + n)? {
            value = value.checked_mul(256)?.checked_add(*byte as usize)?;
        }
        header += n;
        value
    };
    let end = header.checked_add(length)?;
    let body = b.get(header..end)?;
    *input = &b[end..];
    Some(Item { tag, body })
}
fn take<'a>(input: &mut &'a [u8], tag: u8) -> Result<&'a [u8]> {
    let item = next(input).ok_or_else(|| FootprintError::Malformed("TLV"))?;
    if item.tag != tag {
        return Err(FootprintError::Malformed("tag"));
    }
    Ok(item.body)
}
fn nodes(mut bytes: &[u8], depth: usize) -> Result<usize> {
    // x509-parser's recursive generic DER decoder itself has a depth bound.
    // This pass never recursively decodes OCTET/BIT STRING primitive payloads.
    if depth > 128 {
        return Err(FootprintError::Resource("AST depth"));
    }
    let mut count = 0usize;
    while !bytes.is_empty() {
        let Some(item) = next(&mut bytes) else {
            return add(count, 1);
        };
        count = add(count, 1)?;
        if item.tag & 32 != 0 {
            count = add(count, nodes(item.body, depth + 1)?)?;
        }
    }
    Ok(count)
}
fn supported(oid: &[u8]) -> bool {
    [
        &OID_X509_EXT_SUBJECT_KEY_IDENTIFIER,
        &OID_X509_EXT_KEY_USAGE,
        &OID_X509_EXT_SUBJECT_ALT_NAME,
        &OID_X509_EXT_ISSUER_ALT_NAME,
        &OID_X509_EXT_BASIC_CONSTRAINTS,
        &OID_X509_EXT_NAME_CONSTRAINTS,
        &OID_X509_EXT_CERTIFICATE_POLICIES,
        &OID_X509_EXT_POLICY_MAPPINGS,
        &OID_X509_EXT_POLICY_CONSTRAINTS,
        &OID_X509_EXT_EXTENDED_KEY_USAGE,
        &OID_X509_EXT_CRL_DISTRIBUTION_POINTS,
        &OID_X509_EXT_INHIBIT_ANY_POLICY,
        &OID_PKIX_AUTHORITY_INFO_ACCESS,
        &OID_PKIX_SUBJECT_INFO_ACCESS,
        &OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER,
        &OID_X509_EXT_CERT_TYPE,
        &OID_X509_EXT_CERT_COMMENT,
        &OID_X509_EXT_CRL_NUMBER,
        &OID_X509_EXT_REASON_CODE,
        &OID_X509_EXT_INVALIDITY_DATE,
        &OID_X509_EXT_ISSUER_DISTRIBUTION_POINT,
    ]
    .iter()
    .any(|known| known.as_bytes() == oid)
}
fn extension(oid: &[u8], value: &[u8]) -> Result<usize> {
    if oid == OID_CT_LIST_SCT.as_bytes() {
        // SCT is an OCTET STRING containing a u16-sized list of u16-sized
        // entries. Ignore trailing bytes exactly as the pinned parser does.
        let mut encoded = value;
        let mut count = 0usize;
        if let Some(item) = next(&mut encoded) {
            if item.tag == 4 && item.body.len() >= 2 {
                let declared = u16::from_be_bytes([item.body[0], item.body[1]]) as usize;
                if let Some(mut entries) = item.body.get(2..2 + declared) {
                    while entries.len() >= 2 {
                        let n = u16::from_be_bytes([entries[0], entries[1]]) as usize;
                        count = add(count, 1)?;
                        let Some(rest) = entries.get(2 + n..) else {
                            break;
                        };
                        entries = rest;
                    }
                }
            }
        }
        return add(
            4096,
            mul(
                count
                    .max(1)
                    .checked_next_power_of_two()
                    .ok_or(FootprintError::Resource("SCT capacity"))?
                    .max(4)
                    * 2,
                size_of::<SignedCertificateTimestamp<'static>>(),
            )?,
        );
    }
    if !supported(oid) {
        return Ok(0);
    }
    let records = nodes(value, 0)?;
    // CRL BigUint and primitive DER decoder buffers have at most four bytes
    // of backing capacity per encoded byte; AST containers are separate.
    add(mul(records, mul(8, max_record())?)?, mul(value.len(), 4)?)
}
pub(crate) fn full_cost(der: &[u8]) -> Result<usize> {
    let mut cost = add(
        super::chain_shape::shallow_cost(der).map_err(|error| {
            if error.is::<super::chain_shape::Resource>() {
                FootprintError::Resource("outer certificate shape")
            } else {
                FootprintError::Malformed("outer shallow certificate")
            }
        })?,
        16384,
    )?;
    let mut input = der;
    let mut certificate = take(&mut input, 0x30)?;
    let mut tbs = take(&mut certificate, 0x30)?;
    if tbs.first() == Some(&0xa0) {
        take(&mut tbs, 0xa0)?;
    }
    for tag in [0x02, 0x30, 0x30, 0x30, 0x30, 0x30] {
        take(&mut tbs, tag)?;
    }
    while !tbs.is_empty() {
        let item = next(&mut tbs).ok_or_else(|| FootprintError::Malformed("optional field TLV"))?;
        if item.tag != 0xa3 {
            continue;
        }
        let mut wrapper = item.body;
        let mut extensions = take(&mut wrapper, 0x30)?;
        while !extensions.is_empty() {
            let mut ext = take(&mut extensions, 0x30)?;
            let oid = take(&mut ext, 0x06)?;
            if ext.first() == Some(&0x01) {
                take(&mut ext, 0x01)?;
            }
            cost = add(cost, extension(oid, take(&mut ext, 0x04)?)?)?;
        }
    }
    Ok(cost)
}
