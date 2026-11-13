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


// CSR admission deliberately uses a strict walker. Unlike certificate
// full_cost's historical diagnostic pass, malformed constructed values must
// not terminate counting early before the pinned CSR parser allocates.
fn csr_next<'a>(input: &mut &'a [u8]) -> Result<Item<'a>> {
    let bytes = *input;
    let tag = *bytes.first().ok_or(FootprintError::Malformed("CSR tag"))?;
    if tag == 0 { return Err(FootprintError::Malformed("CSR end-of-content")); }
    let mut header = 1usize;
    if tag & 31 == 31 {
        let mut number = 0u32;
        loop {
            let byte = *bytes.get(header).ok_or(FootprintError::Malformed("CSR high tag"))?;
            if header == 1 && byte & 127 == 0 {
                return Err(FootprintError::Malformed("CSR nonminimal tag"));
            }
            number = number.checked_mul(128).and_then(|v| v.checked_add((byte & 127) as u32))
                .ok_or(FootprintError::Malformed("CSR tag overflow"))?;
            header += 1;
            if byte & 128 == 0 { break; }
        }
        if number < 31 { return Err(FootprintError::Malformed("CSR nonminimal high tag")); }
    }
    let first = *bytes.get(header).ok_or(FootprintError::Malformed("CSR length"))?;
    header += 1;
    let length = if first < 128 { first as usize } else {
        let count = (first & 127) as usize;
        // Every admitted CSR is at most 64 KiB. Indefinite and nonminimal
        // encodings are rejected here even if a nested BER helper accepts it.
        if count == 0 || count > 4 {
            return Err(FootprintError::Malformed("CSR indefinite/oversized length"));
        }
        let raw = bytes.get(header..header + count)
            .ok_or(FootprintError::Malformed("CSR truncated length"))?;
        if raw[0] == 0 { return Err(FootprintError::Malformed("CSR nonminimal length")); }
        let mut value = 0usize;
        for byte in raw {
            value = value.checked_mul(256).and_then(|v| v.checked_add(*byte as usize))
                .ok_or(FootprintError::Malformed("CSR length overflow"))?;
        }
        if value < 128 { return Err(FootprintError::Malformed("CSR long short-length")); }
        header += count;
        value
    };
    let end = header.checked_add(length).ok_or(FootprintError::Malformed("CSR length overflow"))?;
    let body = bytes.get(header..end).ok_or(FootprintError::Malformed("CSR truncated body"))?;
    *input = &bytes[end..];
    Ok(Item { tag, body })
}
fn csr_take<'a>(input: &mut &'a [u8], tag: u8) -> Result<&'a [u8]> {
    let item = csr_next(input)?;
    if item.tag != tag { return Err(FootprintError::Malformed("CSR field tag")); }
    Ok(item.body)
}
fn csr_nodes(mut input: &[u8], depth: usize) -> Result<usize> {
    if depth > 128 { return Err(FootprintError::Resource("CSR AST depth")); }
    let mut count = 0;
    while !input.is_empty() {
        let item = csr_next(&mut input)?;
        count = add(count, 1)?;
        if item.tag & 32 != 0 { count = add(count, csr_nodes(item.body, depth + 1)?)?; }
    }
    Ok(count)
}
/// Allocation bound for x509-parser 0.18.1's CSR AST, separate from retained
/// input buffers and the private-key/signature CPU scratch. No heap allocation
/// occurs in this borrowed shape pass. Unknown primitive payloads stay opaque.
pub(crate) fn csr_cost(der: &[u8]) -> Result<usize> {
    if der.is_empty() || der.len() > 65536 {
        return Err(FootprintError::Resource("CSR encoded size"));
    }
    let records = csr_nodes(der, 0)?;
    let slot = max_record()
        .max(size_of::<x509_parser::cri_attributes::X509CriAttribute<'static>>())
        .max(size_of::<X509Extension<'static>>());
    // Attribute/extension, outer RDN and inner ATV Vecs each have their own
    // corresponding DER nodes. Eight slots/node cover minimum-capacity four
    // and overlapping geometric growth. The byte term covers owned
    // challengePassword strings and generic primitive decoder buffers.
    let mut cost = add(16384, add(mul(records, mul(8, slot)?)?, mul(der.len(), 4)?)?)?;
    let mut outer = der;
    let mut request = csr_take(&mut outer, 0x30)?;
    if !outer.is_empty() { return Err(FootprintError::Malformed("CSR trailing data")); }
    let mut info = csr_take(&mut request, 0x30)?;
    csr_take(&mut info, 0x02)?;
    csr_take(&mut info, 0x30)?;
    csr_take(&mut info, 0x30)?;
    let mut attributes = csr_take(&mut info, 0xa0)?;
    if !info.is_empty() { return Err(FootprintError::Malformed("CSR info trailing data")); }
    csr_take(&mut request, 0x30)?;
    csr_take(&mut request, 0x03)?;
    if !request.is_empty() { return Err(FootprintError::Malformed("CSR request trailing data")); }
    while !attributes.is_empty() {
        let mut attribute = csr_take(&mut attributes, 0x30)?;
        let oid = csr_take(&mut attribute, 0x06)?;
        let mut values = csr_take(&mut attribute, 0x31)?;
        if !attribute.is_empty() { return Err(FootprintError::Malformed("CSR attribute trailing data")); }
        if oid != OID_PKCS9_EXTENSION_REQUEST.as_bytes() { continue; }
        while !values.is_empty() {
            let mut extensions = csr_take(&mut values, 0x30)?;
            while !extensions.is_empty() {
                let mut ext = csr_take(&mut extensions, 0x30)?;
                let oid = csr_take(&mut ext, 0x06)?;
                if ext.first() == Some(&0x01) { csr_take(&mut ext, 0x01)?; }
                let value = csr_take(&mut ext, 0x04)?;
                if !ext.is_empty() { return Err(FootprintError::Malformed("CSR extension trailing data")); }
                // Supported extension OCTET payloads allocate their own AST.
                // SCT's nested payload is a length-prefixed byte list, whose
                // concrete entry capacity is already counted by extension().
                if supported(oid) { csr_nodes(value, 0)?; }
                cost = add(cost, extension(oid, value)?)?;
            }
        }
    }
    Ok(cost)
}
