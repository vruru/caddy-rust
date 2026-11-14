//! Owned/prepaid certificate decoding. Shallow X.509 AST capacity is derived
//! from a borrowed DER shape pass; no deep extension AST is built for chaining.
use super::chain_memory::{self, Buffer, Lease, Pool};
use anyhow::{Result, anyhow, ensure};
use base64::Engine;
use std::sync::Arc;
use x509_parser::{certificate::X509CertificateParser, nom::Parser};

pub(super) const CRYPTO_SCRATCH: usize = 4 * 1024 * 1024;
pub(super) const SORT_SCRATCH: usize = 64 * 1024;
const DECODE_OVERHEAD: usize = 8192;

/// Wanted name metadata failed; this is not an ordinary CN non-match.
#[derive(Debug)]
pub(crate) struct NamesUnavailable;
impl std::fmt::Display for NamesUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("certificate chain name metadata unavailable")
    }
}
impl std::error::Error for NamesUnavailable {}

pub(super) struct Names {
    pub values: Vec<String>,
    _memory: Lease,
}
pub(super) struct Validated {
    pub first: Arc<Buffer>,
    pub last: Arc<Buffer>,
    pub count: usize,
    pub names: Option<Arc<Names>>,
}
pub(super) fn decode_cost(length: usize) -> Result<usize> {
    length
        .checked_mul(2)
        .and_then(|n| n.checked_add(DECODE_OVERHEAD + CRYPTO_SCRATCH))
        .ok_or_else(|| crate::cert_transient::ResourceDenied.into())
}
/// Equivalent strict certificate framing to certmagic::pem_blocks, but its
/// base64/DER buffers are pre-sized. Header text is rejected before allocating.
pub(crate) fn decode(pem: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut text = std::str::from_utf8(pem)
        .map_err(|_| anyhow!("ACME PEM is not UTF8"))?
        .trim();
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let mut blocks = Vec::with_capacity(32);
    while !text.is_empty() {
        ensure!(blocks.len() < 32, "ACME certificate block limit exceeded");
        let body = text
            .strip_prefix(BEGIN)
            .ok_or_else(|| anyhow!("invalid ACME certificate PEM framing"))?;
        let end = body
            .find(END)
            .ok_or_else(|| anyhow!("ACME certificate PEM footer missing"))?;
        let raw = &body[..end];
        let mut count = 0usize;
        for ch in raw.chars().filter(|ch| !ch.is_whitespace()) {
            ensure!(
                ch.is_ascii_alphanumeric() || matches!(ch, '+' | '/' | '='),
                "invalid ACME PEM data or headers"
            );
            count += 1;
        }
        let mut encoded = Vec::new();
        encoded
            .try_reserve_exact(count)
            .map_err(|error| anyhow::Error::new(error).context(crate::cert_transient::ResourceDenied))?;
        for ch in raw.chars().filter(|ch| !ch.is_whitespace()) {
            encoded.push(ch as u8);
        }
        let capacity = count
            .checked_add(3)
            .and_then(|n| (n / 4).checked_mul(3))
            .ok_or(crate::cert_transient::ResourceDenied)?;
        let mut der = Vec::new();
        der.try_reserve_exact(capacity)
            .map_err(|error| anyhow::Error::new(error).context(crate::cert_transient::ResourceDenied))?;
        base64::engine::general_purpose::STANDARD
            .decode_vec(&encoded, &mut der)
            .map_err(|_| anyhow!("invalid ACME base64"))?;
        ensure!(
            der.capacity() <= capacity.max(8),
            "unexpected ACME DER capacity"
        );
        blocks.push(der);
        text = body[end + END.len()..].trim();
    }
    ensure!(!blocks.is_empty(), "empty ACME certificate material");
    Ok(blocks)
}
fn parser(der: &[u8]) -> Result<x509_parser::certificate::X509Certificate<'_>> {
    crate::cert_uri_san::check_der(der)?;
    let (rest, cert) = X509CertificateParser::new()
        .with_deep_parse_extensions(false)
        .parse(der)
        .map_err(|_| anyhow!("invalid ACME chain certificate DER"))?;
    ensure!(rest.is_empty(), "trailing ACME chain DER");
    ensure!(
        cert.public_key().raw.len() <= 16384,
        "ACME public key encoding exceeds supported bounds"
    );
    Ok(cert)
}
fn link(
    child: &x509_parser::certificate::X509Certificate<'_>,
    parent: &x509_parser::certificate::X509Certificate<'_>,
) -> Result<()> {
    ensure!(
        child.issuer().as_raw() == parent.subject().as_raw(),
        "ACME issuer path name mismatch"
    );
    crate::cert_status::verify_x509_signature(
        parent.public_key(),
        &child.signature_algorithm,
        &child.signature_value.data,
        child.tbs_certificate.as_ref(),
        true,
    )
}
fn names(
    certs: &[x509_parser::certificate::X509Certificate<'_>],
    pool: &Arc<Pool>,
) -> Result<Arc<Names>> {
    let bytes = certs.len().checked_mul(std::mem::size_of::<String>())
        .ok_or(crate::cert_transient::ResourceDenied)?;
    let mut memory = pool.reserve(bytes)?;
    let mut values = Vec::new();
    values.try_reserve_exact(certs.len())
        .map_err(|error| anyhow::Error::new(error).context(crate::cert_transient::ResourceDenied))?;
    memory.resize(values.capacity().checked_mul(std::mem::size_of::<String>())
        .ok_or(crate::cert_transient::ResourceDenied)?)?;
    let mut output = Names { values, _memory: memory };
    for cert in certs {
        let raw = cert.issuer().as_raw();
        let cost = super::chain_shape::name_cost(raw)?;
        let _scratch = chain_memory::try_scratch(cost)?;
        let mut name = crate::http_runtime::client_cert_facts::parse_name(raw)
            .map_err(anyhow::Error::msg)?;
        let cn = std::mem::take(&mut name.common_name);
        drop(name);
        let total = output._memory_bytes().checked_add(cn.capacity())
            .ok_or(crate::cert_transient::ResourceDenied)?;
        output._memory.resize(total)?;
        output.values.push(cn);
    }
    Ok(Arc::new(output))
}
impl Names {
    fn _memory_bytes(&self) -> usize {
        self._memory.bytes()
    }
}
/// The caller captures decode/scratch credit in the actual blocking closure.
pub(super) fn validate(pem: Arc<Buffer>, pool: Arc<Pool>, want_names: bool) -> Result<Validated> {
    let mut blocks = decode(pem.as_slice())?;
    let meta = blocks.iter().try_fold(0usize, |n, b| {
        n.checked_add(super::chain_shape::shallow_cost(b)?)
            .ok_or_else(|| anyhow::Error::new(crate::cert_transient::ResourceDenied))
    })?;
    let _meta = chain_memory::try_scratch(meta)?;
    let mut certs = Vec::with_capacity(blocks.len());
    for block in &blocks {
        certs.push(parser(block)?);
    }
    for pair in certs.windows(2) {
        link(&pair[0], &pair[1])?;
    }
    let names = if want_names {
        Some(names(&certs, &pool).map_err(|error| error.context(NamesUnavailable))?)
    } else {
        None
    };
    let count = certs.len();
    drop(certs);
    // Move DER out of the already prepaid decoder; no leaf bytes are cloned.
    let first_bytes = std::mem::take(&mut blocks[0]);
    let first_lease = pool.reserve(first_bytes.capacity())?;
    let first = Arc::new(Buffer::adopt(first_bytes, first_lease)?);
    let last = if count == 1 {
        first.clone()
    } else {
        let bytes = std::mem::take(&mut blocks[count - 1]);
        let credit = pool.reserve(bytes.capacity())?;
        Arc::new(Buffer::adopt(bytes, credit)?)
    };
    Ok(Validated {
        first,
        last,
        count,
        names,
    })
}
/// Up edges only need the two already-owned endpoint DER buffers, not another
/// full PEM allocation/decode. Parsed AST and crypto scratch stay with worker.
pub(super) fn bridge(child: Arc<Buffer>, parent: Arc<Buffer>) -> Result<()> {
    let cost = super::chain_shape::shallow_cost(child.as_slice())?
        .checked_add(super::chain_shape::shallow_cost(parent.as_slice())?)
        .ok_or(crate::cert_transient::ResourceDenied)?;
    let _meta = chain_memory::try_scratch(cost)?;
    let child = parser(child.as_slice())?;
    let parent = parser(parent.as_slice())?;
    link(&child, &parent)
}
