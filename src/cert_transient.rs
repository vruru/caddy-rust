//! Per-object temporary ownership for certificate decoding. Admission belongs
//! to the actual AST/buffer, not just the awaiting task or an operation counter.
use crate::acme_wire::{
    chain_deep_shape,
    chain_memory::{self, Scratch},
    chain_validation,
};
use anyhow::{Result, anyhow};
use std::ops::Deref;

#[derive(Debug)]
pub(crate) struct ResourceDenied;
impl std::fmt::Display for ResourceDenied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("certificate transient memory budget exhausted")
    }
}
impl std::error::Error for ResourceDenied {}
pub(crate) fn is_resource(error: &anyhow::Error) -> bool {
    // anyhow contexts are downcastable through Error, but are not exposed as
    // their payload type by the std::error::Error source iterator.
    error.is::<native_write_policy::Denied>()
        || error.is::<ResourceDenied>()
        || error.is::<chain_memory::MemoryDenied>()
        || error.is::<crate::acme_wire::chain_shape::Resource>()
        || error.downcast_ref::<chain_deep_shape::FootprintError>()
            .is_some_and(|value| matches!(value, chain_deep_shape::FootprintError::Resource(_)))
        || error.chain().any(|cause| {
        cause.is::<native_write_policy::Denied>()
            || cause.downcast_ref::<std::io::Error>()
                .and_then(std::io::Error::get_ref)
                .is_some_and(|inner| inner.is::<native_write_policy::Denied>())
            || cause.is::<ResourceDenied>()
            || cause.is::<chain_memory::MemoryDenied>()
            || cause.is::<crate::acme_wire::chain_shape::Resource>()
            || cause
                .downcast_ref::<chain_deep_shape::FootprintError>()
                .is_some_and(|value| matches!(value, chain_deep_shape::FootprintError::Resource(_)))
    })
}

pub(crate) fn reserve(bytes: usize) -> Result<Scratch> {
    chain_memory::try_scratch(bytes).map_err(|_| ResourceDenied.into())
}

pub(crate) struct Parsed<'a> {
    value: x509_parser::certificate::X509Certificate<'a>,
    _memory: Scratch,
}
impl<'a> Deref for Parsed<'a> {
    type Target = x509_parser::certificate::X509Certificate<'a>;
    fn deref(&self) -> &Self::Target {
        &self.value
    }
}
pub(crate) fn parse_certificate(der: &[u8]) -> Result<(&[u8], Parsed<'_>)> {
    let cost = chain_deep_shape::full_cost(der)?;
    let memory = reserve(cost)?;
    crate::cert_uri_san::check_der(der)?;
    let (rest, value) = x509_parser::parse_x509_certificate(der)
        .map_err(|_| anyhow!("malformed X509 certificate DER"))?;
    Ok((
        rest,
        Parsed {
            value,
            _memory: memory,
        },
    ))
}

pub(crate) struct Blocks {
    value: Vec<(String, Vec<u8>)>,
    _memory: Scratch,
}
impl Deref for Blocks {
    type Target = [(String, Vec<u8>)];
    fn deref(&self) -> &Self::Target {
        &self.value
    }
}
impl<'a> IntoIterator for &'a Blocks {
    type Item = &'a (String, Vec<u8>);
    type IntoIter = std::slice::Iter<'a, (String, Vec<u8>)>;
    fn into_iter(self) -> Self::IntoIter {
        self.value.iter()
    }
}
pub(crate) fn certificate_blocks(pem: &[u8]) -> Result<Blocks> {
    // Base64 input + decoded DER fit below2*PEM; 8KiB covers both container
    // arrays, 32 fixed certificate labels, and tiny allocator rounding.
    let cost = pem
        .len()
        .checked_mul(2)
        .and_then(|n| n.checked_add(8192))
        .ok_or(ResourceDenied)?;
    let memory = reserve(cost)?;
    let blocks = chain_validation::decode(pem)?;
    let value = blocks
        .into_iter()
        .map(|der| ("CERTIFICATE".to_owned(), der))
        .collect();
    Ok(Blocks {
        value,
        _memory: memory,
    })
}

#[derive(Clone, Copy)]
pub(crate) enum Lifetime {
    Temporary,
    Persistent,
}
pub(crate) enum Credit {
    Temporary(Scratch),
    Persistent(chain_memory::Lease),
}
fn credit(bytes: usize, lifetime: Lifetime) -> Result<Credit> {
    match lifetime {
        Lifetime::Temporary => Ok(Credit::Temporary(reserve(bytes)?)),
        Lifetime::Persistent => chain_memory::shared()
            .payload
            .reserve(bytes)
            .map(Credit::Persistent)
            .map_err(|_| ResourceDenied.into()),
    }
}
/// Raw input owns its real allocation admission across worker result delivery,
/// including a completed JoinHandle whose caller has not consumed its result.
pub(crate) struct Bytes {
    value: zeroize::Zeroizing<Vec<u8>>,
    memory: Option<Credit>,
}
impl Deref for Bytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.value
    }
}
impl Bytes {
    pub(crate) fn allocate(bytes: usize, lifetime: Option<Lifetime>) -> Result<Self> {
        let memory = lifetime.map(|kind| credit(bytes, kind)).transpose()?;
        let mut value = zeroize::Zeroizing::new(Vec::new());
        value.try_reserve_exact(bytes).map_err(|_| ResourceDenied)?;
        anyhow::ensure!(
            value.capacity() == bytes,
            "unexpected certificate read capacity"
        );
        value.resize(bytes, 0);
        Ok(Self { value, memory })
    }
    pub(crate) fn copy(bytes: &[u8], lifetime: Lifetime) -> Result<Self> {
        let mut owned = Self::allocate(bytes.len(), Some(lifetime))?;
        owned.value.copy_from_slice(bytes);
        Ok(owned)
    }
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.value
    }
    pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.value
    }
    pub(crate) fn into_parts(self) -> (zeroize::Zeroizing<Vec<u8>>, Option<Credit>) {
        (self.value, self.memory)
    }
    pub(crate) fn into_untracked(self) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        anyhow::ensure!(
            self.memory.is_none(),
            "admitted certificate bytes require owned result"
        );
        Ok(self.value)
    }
}

pub(crate) struct Json {
    value: serde_json::Value,
    memory: Option<Credit>,
}
impl Deref for Json {
    type Target = serde_json::Value;
    fn deref(&self) -> &Self::Target {
        &self.value
    }
}
pub(crate) fn json_value(raw: &[u8], lifetime: Option<Lifetime>) -> Result<Json> {
    let (memory, temporary) = if let Some(kind) = lifetime {
        let footprint = crate::cert_json_shape::footprint(raw)?;
        // Both admissions precede serde construction. Transient parsing
        // scratch never becomes a credit shared with the retained DOM.
        let temporary = reserve(footprint.temporary)?;
        let memory = credit(footprint.owned, kind)?;
        (Some(memory), Some(temporary))
    } else {
        (None, None)
    };
    let value = serde_json::from_slice(raw)?;
    drop(temporary);
    Ok(Json { value, memory })
}
impl Json {
    pub(crate) fn into_parts(self) -> (serde_json::Value, Option<Credit>) {
        (self.value, self.memory)
    }
    pub(crate) fn into_untracked(self) -> Result<serde_json::Value> {
        anyhow::ensure!(self.memory.is_none(), "admitted JSON requires owned result");
        Ok(self.value)
    }
}

pub(crate) fn edited_json(
    value: &serde_json::Value,
    allowance: usize,
    edit: impl FnOnce(&mut serde_json::Value) -> Result<()>,
) -> Result<Json> {
    let cost = crate::cert_json_shape::clone_cost(value)?
        .checked_add(allowance)
        .ok_or(ResourceDenied)?;
    let memory = credit(cost, Lifetime::Persistent)?;
    let mut value = value.clone();
    edit(&mut value)?;
    Ok(Json {
        value,
        memory: Some(memory),
    })
}

/// The existing provider accepts one unencrypted private-key block. Reject
/// unsupported headers before the legacy decoder could allocate header lists.
pub(crate) fn key_decode_bound(bytes: &[u8]) -> Result<usize> {
    if bytes.len() > 128 * 1024 {
        return Err(ResourceDenied.into());
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| anyhow!("private key PEM is not UTF8"))?
        .trim();
    let forms = [
        ("-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----"),
        (
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----END RSA PRIVATE KEY-----",
        ),
        (
            "-----BEGIN EC PRIVATE KEY-----",
            "-----END EC PRIVATE KEY-----",
        ),
        (
            "-----BEGIN ED25519 PRIVATE KEY-----",
            "-----END ED25519 PRIVATE KEY-----",
        ),
    ];
    let body = forms
        .iter()
        .find_map(|(begin, end)| text.strip_prefix(begin).and_then(|x| x.strip_suffix(end)))
        .ok_or_else(|| anyhow!("unsupported private key PEM framing"))?;
    anyhow::ensure!(
        body.chars().all(|c| c.is_whitespace()
            || c.is_ascii_alphanumeric()
            || matches!(c, '+' | '/' | '=')),
        "private key PEM headers or data invalid"
    );
    // Whitespace compaction, DER decode and provider clone_key overlap;
    // this covers the named Rust input buffers, not opaque provider/cache RSS.
    bytes
        .len()
        .checked_mul(4)
        .and_then(|n| n.checked_add(16384))
        .ok_or_else(|| ResourceDenied.into())
}
pub(crate) fn signing_key(
    bytes: &[u8],
    id: &str,
) -> Result<std::sync::Arc<dyn rustls::sign::SigningKey>> {
    let memory = reserve(key_decode_bound(bytes)?)?;
    let result = crate::certmagic::signing_key(bytes, id);
    drop(memory);
    result
}
pub(crate) fn clone_input_bound(certificate: &[u8], key: &[u8], names: &[String]) -> Result<usize> {
    key_decode_bound(key)?;
    let mut n = certificate
        .len()
        .checked_add(key.len())
        .and_then(|n| n.checked_add(32768))
        .ok_or(ResourceDenied)?;
    n = n
        .checked_add(names.len() * std::mem::size_of::<String>())
        .ok_or(ResourceDenied)?;
    for name in names {
        n = n.checked_add(name.len()).ok_or(ResourceDenied)?;
    }
    Ok(n)
}
pub(crate) fn vec_slots(count: usize) -> Result<usize> {
    if count == 0 {
        return Ok(0);
    }
    let cap = count
        .checked_next_power_of_two()
        .ok_or(ResourceDenied)?
        .max(4);
    cap.checked_add(if cap > 4 { cap / 2 } else { 0 })
        .ok_or_else(|| ResourceDenied.into())
}

/// Exact bounded JSON output. The first pass counts bytes without constructing
/// a DOM or output buffer; the real bytes and their credit travel together.
pub(crate) fn encode_json(value: &impl serde::Serialize) -> Result<Bytes> {
    struct Count(usize);
    impl std::io::Write for Count {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self.0.checked_add(bytes.len()).filter(|n| *n <= 12*1024*1024)
                .ok_or_else(||std::io::Error::other("certificate JSON output exceeds storage limit"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {Ok(())}
    }
    let mut count=Count(0); serde_json::to_writer(&mut count,value)?;
    let mut output=Bytes::allocate(count.0,Some(Lifetime::Temporary))?;
    let mut target=output.as_mut_slice(); serde_json::to_writer(&mut target,value)?;
    anyhow::ensure!(target.is_empty(),"certificate JSON output size changed");
    Ok(output)
}
impl AsRef<[u8]> for Bytes {fn as_ref(&self)->&[u8]{self.as_slice()}}

/// A bounded typed-header String transfers before its actual IO worker returns.
pub(crate) struct Text {value:String,_memory:Credit}
impl Deref for Text {type Target=str;fn deref(&self)->&str{&self.value}}
impl Text {
    pub(crate) fn admit(value:String)->Result<Self>{
        let memory=credit(value.capacity(),Lifetime::Persistent)?;
        Ok(Self{value,_memory:memory})
    }
}

/// Strict duplicate extension rejection without an uncharged HashMap or OID
/// deep copies. Sorting borrowed encodings uses no auxiliary heap.
pub(crate) fn check_unique_extensions(leaf:&x509_parser::certificate::X509Certificate<'_>)->Result<()> {
    let count=leaf.extensions().len();
    let bytes=count.checked_mul(std::mem::size_of::<&[u8]>()).ok_or(ResourceDenied)?;
    let _credit=reserve(bytes)?;
    let mut encodings=Vec::new();encodings.try_reserve_exact(count).map_err(|_|ResourceDenied)?;
    for extension in leaf.extensions(){encodings.push(extension.oid.as_bytes());}
    encodings.sort_unstable();
    anyhow::ensure!(encodings.windows(2).all(|pair|pair[0]!=pair[1]),"duplicate certificate extensions");
    Ok(())
}

/// SAN working copies only, independent of unrelated opaque metadata fields.
/// Four overlapping collection capacities plus eight text copies cover the
/// metadata/normalization/names-key/Name0 comparisons, without billing a whole
/// arbitrary metadata DOM for each SAN lookup.
pub(crate) fn metadata_names_work(metadata:&serde_json::Value)->Result<usize>{
    let values=metadata.get("sans").and_then(serde_json::Value::as_array)
        .ok_or_else(||anyhow!("certificate metadata requires SAN list"))?;
    anyhow::ensure!(!values.is_empty()&&values.len()<=1024,"invalid certificate SAN list");
    let text=values.iter().try_fold(0usize,|n,v|n.checked_add(v.as_str().map_or(0,str::len)).ok_or(ResourceDenied))?;
    vec_slots(values.len())?.checked_mul(4*std::mem::size_of::<String>())
        .and_then(|n|text.checked_mul(8).and_then(|text|n.checked_add(text)))
        .and_then(|n|n.checked_add(8192)).ok_or_else(||ResourceDenied.into())
}
pub(crate) fn leaf_names_work(leaf:&x509_parser::certificate::X509Certificate<'_>)->Result<usize>{
    use x509_parser::extensions::GeneralName;
    let Some(san)=leaf.subject_alternative_name().map_err(|_|anyhow!("invalid certificate SAN"))?else{return Ok(0)};
    let mut count=0usize;let mut text=0usize;
    for name in &san.value.general_names{
        let bytes=match name {GeneralName::DNSName(v)=>v.len(),GeneralName::IPAddress(v)if matches!(v.len(),4|16)=>45,_=>continue};
        count=count.checked_add(1).ok_or(ResourceDenied)?;text=text.checked_add(bytes).ok_or(ResourceDenied)?;
    }
    vec_slots(count)?.checked_mul(4*std::mem::size_of::<String>())
        .and_then(|n|text.checked_mul(4).and_then(|text|n.checked_add(text)))
        .and_then(|n|n.checked_add(8192)).ok_or_else(||ResourceDenied.into())
}
