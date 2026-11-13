//! Private subject-provider environment reader for the sealed native CLI.
//!
//! This does NOT make environment access safer than std::env. Unix correctness
//! requires the CLI's process-wide contract: all environment set/remove calls
//! complete before threads/foreign libraries start; no code may mutate it later.
//! A local lock would not establish this contract for foreign setenv/putenv.
use anyhow::{Result, ensure};
use crate::acme_wire::chain_memory::Scratch;
use crate::cert_transient::{self, ResourceDenied};

const FIELD: usize = 1 << 20;

// The returned configured bytes retire before their owned admission.
pub(super) struct EnvironmentValue {
    text: String,
    _memory: Scratch,
}
impl EnvironmentValue {
    pub(super) fn as_str(&self) -> &str { &self.text }
    fn empty() -> Result<Self> {
        Ok(Self { text: String::new(), _memory: cert_transient::reserve(0)? })
    }
}

/// Synchronous only: the borrowed libc pointer is never stored or returned.
/// Unknown/unset/empty/non-UTF8 values are recognized-empty, matching the
/// native global provider's current ReplaceAll semantics. Oversized names or
/// values fail with a static error which contains neither key nor value.
#[cfg(unix)]
pub(super) fn bounded_environment(key: &str) -> Result<EnvironmentValue> {
    ensure!(key.len() <= FIELD, "certificate subject environment exceeds limit");
    if key.is_empty() || key.as_bytes().contains(&0) || key.as_bytes().contains(&b'=') {
        return EnvironmentValue::empty();
    }
    let key_len = key.len().checked_add(1).ok_or(ResourceDenied)?;
    let key_allowance = key_len.checked_mul(2).and_then(|n| n.checked_add(64))
        .ok_or(ResourceDenied)?;
    // Key payload plus terminator are prepaid before Vec/CString construction.
    let _key_memory = cert_transient::reserve(key_allowance)?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(key_len).map_err(|_| ResourceDenied)?;
    ensure!(bytes.capacity() <= key_allowance, "certificate subject memory limit");
    bytes.extend_from_slice(key.as_bytes());
    bytes.push(0);
    let key = std::ffi::CString::from_vec_with_nul(bytes)
        .map_err(|_| anyhow::anyhow!("certificate subject environment failed"))?;
    // SAFETY: key is NUL-terminated. The closed CLI guarantees process-wide
    // immutable environment after startup, including foreign code. Therefore a
    // non-null getenv result remains a valid NUL-terminated C string throughout
    // this synchronous scan/validation/copy. No await, cache or escaped borrow.
    let ptr = unsafe { libc::getenv(key.as_ptr()) };
    if ptr.is_null() { return EnvironmentValue::empty(); }
    let mut len = 0usize;
    loop {
        // SAFETY: immutable getenv string remains valid; only bytes through its
        // terminating NUL are visited. At most FIELD+1 bytes are inspected.
        let byte = unsafe { ptr.add(len).read() };
        if byte == 0 { break; }
        ensure!(len < FIELD, "certificate subject environment exceeds limit");
        len += 1;
    }
    // SAFETY: scan established that exactly len bytes before NUL are readable.
    let borrowed = unsafe { std::slice::from_raw_parts(ptr.cast::<u8>(), len) };
    let Ok(value) = std::str::from_utf8(borrowed) else {
        return EnvironmentValue::empty();
    };
    let allowance = len.checked_mul(2).and_then(|n| n.checked_add(64))
        .ok_or(ResourceDenied)?;
    // Admission precedes value copy; returned value owns it until actual drop.
    let memory = cert_transient::reserve(allowance)?;
    let mut text = String::new();
    text.try_reserve_exact(len).map_err(|_| ResourceDenied)?;
    ensure!(text.capacity() <= allowance, "certificate subject memory limit");
    text.push_str(value);
    Ok(EnvironmentValue { text, _memory: memory })
}

#[cfg(not(unix))]
pub(super) fn bounded_environment(_key: &str) -> Result<EnvironmentValue> {
    anyhow::bail!("certificate subject environment provider unavailable")
}
