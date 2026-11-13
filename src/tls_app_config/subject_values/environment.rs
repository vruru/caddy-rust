//! Private bounded getenv reader for the sealed native CLI. All environment
//! mutation must finish before threads/foreign libraries start. A local mutex
//! cannot establish this process-wide contract for foreign setenv/putenv.
use crate::{
    acme_wire::chain_memory::Scratch,
    cert_transient::{self, ResourceDenied},
};
use anyhow::{Result, ensure};
use zeroize::Zeroizing;
const FIELD: usize = 1 << 20;
pub(in crate::tls_app_config) struct ProviderValue {
    pub(in crate::tls_app_config) bytes: Zeroizing<Vec<u8>>,
    pub(in crate::tls_app_config) memory: Scratch,
}
impl AsRef<[u8]> for ProviderValue {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}
impl ProviderValue {
    pub(in crate::tls_app_config) fn empty() -> Result<Self> {
        Ok(Self {
            bytes: Zeroizing::new(Vec::new()),
            memory: cert_transient::reserve(0)?,
        })
    }
}
pub(super) struct EnvironmentValue {
    text: Zeroizing<String>,
    _memory: Scratch,
}
impl EnvironmentValue {
    pub(super) fn as_str(&self) -> &str {
        &self.text
    }
}
/// Byte-valued sibling entry point retains Go strings without leaking getenv
/// borrows. The 1MiB scan/copy bound applies before allocating the value.
#[cfg(unix)]
fn read_environment(key: &str, utf8_only: bool) -> Result<ProviderValue> {
    ensure!(
        key.len() <= FIELD,
        "certificate subject environment exceeds limit"
    );
    if key.is_empty() || key.as_bytes().contains(&0) || key.as_bytes().contains(&b'=') {
        return ProviderValue::empty();
    }
    let _key_memory = cert_transient::reserve(
        key.len()
            .checked_mul(2)
            .and_then(|n| n.checked_add(65))
            .ok_or(ResourceDenied)?,
    )?;
    let mut bytes = Zeroizing::new(Vec::new());
    bytes.try_reserve_exact(key.len() + 1)?;
    bytes.extend_from_slice(key.as_bytes());
    bytes.push(0);
    let key = std::ffi::CStr::from_bytes_with_nul(&bytes)
        .map_err(|_| anyhow::anyhow!("certificate subject environment failed"))?;
    // SAFETY: startup-sealed CLI environment remains immutable, including foreign
    // code. This synchronous bounded scan/copy contains no await or escaped borrow.
    let pointer = unsafe { libc::getenv(key.as_ptr()) };
    if pointer.is_null() {
        return ProviderValue::empty();
    }
    let mut len = 0usize;
    loop {
        let byte = unsafe { pointer.add(len).read() };
        if byte == 0 {
            break;
        }
        ensure!(len < FIELD, "certificate subject environment exceeds limit");
        len += 1;
    }
    let borrowed = unsafe { std::slice::from_raw_parts(pointer.cast::<u8>(), len) };
    if utf8_only && std::str::from_utf8(borrowed).is_err() {
        return ProviderValue::empty();
    }
    let memory = cert_transient::reserve(
        len.checked_mul(2)
            .and_then(|n| n.checked_add(64))
            .ok_or(ResourceDenied)?,
    )?;
    let mut bytes = Zeroizing::new(Vec::new());
    bytes.try_reserve_exact(len)?;
    bytes.extend_from_slice(borrowed);
    Ok(ProviderValue { bytes, memory })
}
#[cfg(unix)]
pub(in crate::tls_app_config) fn bounded_bytes(key: &str) -> Result<ProviderValue> {
    read_environment(key, false)
}
#[cfg(not(unix))]
fn read_environment(_key: &str, _utf8_only: bool) -> Result<ProviderValue> {
    anyhow::bail!("certificate subject environment provider unavailable")
}
#[cfg(not(unix))]
pub(in crate::tls_app_config) fn bounded_bytes(_key: &str) -> Result<ProviderValue> {
    anyhow::bail!("certificate subject environment provider unavailable")
}
pub(super) fn bounded_environment(key: &str) -> Result<EnvironmentValue> {
    let value = read_environment(key, true)?;
    if std::str::from_utf8(&value.bytes).is_err() {
        let empty = ProviderValue::empty()?;
        return Ok(EnvironmentValue {
            text: Zeroizing::new(String::new()),
            _memory: empty.memory,
        });
    }
    let ProviderValue { mut bytes, memory } = value;
    let text = String::from_utf8(std::mem::take(&mut *bytes)).map_err(|e| {
        let _wipe = Zeroizing::new(e.into_bytes());
        anyhow::anyhow!("certificate subject environment failed")
    })?;
    Ok(EnvironmentValue {
        text: Zeroizing::new(text),
        _memory: memory,
    })
}
