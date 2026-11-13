//! Owned, prepaid CertificateRequest facts. Capture only on the SSL CPU lane.
use foreign_types::ForeignTypeRef;
use openssl::{
    ssl::{SslRef, SslVersion},
    stack::StackRef,
    x509::X509Name,
};
use rustls::{ProtocolVersion, SignatureScheme};
use std::{
    ffi::{c_int, c_void},
    io,
    sync::atomic::{AtomicUsize, Ordering},
};
const LIMIT: usize = 8 * 1024 * 1024;
static USED: AtomicUsize = AtomicUsize::new(0);
struct Credit(usize);
impl Credit {
    fn reserve(bytes: usize) -> io::Result<Self> {
        USED.try_update(Ordering::AcqRel, Ordering::Acquire, |old| {
            old.checked_add(bytes).filter(|n| *n <= LIMIT)
        })
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::OutOfMemory,
                "client certificate request budget exhausted",
            )
        })?;
        Ok(Self(bytes))
    }
}
impl Drop for Credit {
    fn drop(&mut self) {
        USED.fetch_sub(self.0, Ordering::AcqRel);
    }
}
fn bad() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid client certificate request",
    )
}
fn memory() -> io::Error {
    io::Error::new(
        io::ErrorKind::OutOfMemory,
        "client certificate request allocation denied",
    )
}
pub(crate) struct Request {
    pub hints: Vec<Vec<u8>>,
    pub schemes: Vec<SignatureScheme>,
    pub version: ProtocolVersion,
    _credit: Credit,
}
unsafe extern "C" {
    fn SSL_get0_peer_CA_list(ssl: *const openssl_sys::SSL) -> *const c_void;
    fn SSL_get_sigalgs(
        ssl: *mut openssl_sys::SSL,
        idx: c_int,
        sign: *mut c_int,
        hash: *mut c_int,
        signhash: *mut c_int,
        rsig: *mut u8,
        rhash: *mut u8,
    ) -> c_int;
}
fn allowed(s: SignatureScheme) -> bool {
    use SignatureScheme::*;
    matches!(
        s,
        ECDSA_NISTP256_SHA256
            | ECDSA_NISTP384_SHA384
            | ECDSA_NISTP521_SHA512
            | RSA_PSS_SHA256
            | RSA_PSS_SHA384
            | RSA_PSS_SHA512
            | RSA_PKCS1_SHA256
            | RSA_PKCS1_SHA384
            | RSA_PKCS1_SHA512
            | ED25519
    )
}
pub(crate) fn capture(ssl: &SslRef) -> io::Result<Request> {
    let version = match ssl.version2() {
        Some(SslVersion::TLS1_2) => ProtocolVersion::TLSv1_2,
        Some(SslVersion::TLS1_3) => ProtocolVersion::TLSv1_3,
        _ => return Err(bad()),
    };
    let mut types_pointer = std::ptr::null::<u8>();
    let (rsa, ec) = if version == ProtocolVersion::TLSv1_2 {
        let n = unsafe {
            openssl_sys::SSL_ctrl(
                ssl.as_ptr(),
                103,
                0,
                (&mut types_pointer as *mut *const u8).cast(),
            )
        };
        if n <= 0 || n > 255 || types_pointer.is_null() {
            return Err(bad());
        }
        let types = unsafe { std::slice::from_raw_parts(types_pointer, n as usize) };
        (types.contains(&1), types.contains(&64))
    } else {
        (true, true)
    };
    let pointer = unsafe { SSL_get0_peer_CA_list(ssl.as_ptr()) };
    // The stack and names are borrowed from this exclusively owned SSL; never free.
    let names = if pointer.is_null() {
        None
    } else {
        Some(unsafe { StackRef::<X509Name>::from_ptr(pointer.cast_mut().cast()) })
    };
    let count = names.map_or(0, StackRef::len);
    if count > 32767 {
        return Err(bad());
    }
    let mut bytes = 0usize;
    let mut wire = 0usize;
    if let Some(names) = names {
        for name in names {
            let n = usize::try_from(unsafe {
                openssl_sys::i2d_X509_NAME(name.as_ptr(), std::ptr::null_mut())
            })
            .map_err(|_| bad())?;
            if n == 0 {
                return Err(bad());
            }
            bytes = bytes.checked_add(n).ok_or_else(bad)?;
            wire = wire
                .checked_add(n)
                .and_then(|n| n.checked_add(2))
                .filter(|n| *n <= 65535)
                .ok_or_else(bad)?;
        }
    }
    let total = unsafe {
        SSL_get_sigalgs(
            ssl.as_ptr(),
            -1,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if !(0..=32767).contains(&total) {
        return Err(bad());
    }
    let cost = bytes
        .checked_mul(2)
        .and_then(|n| {
            count
                .checked_mul(2 * std::mem::size_of::<Vec<u8>>())
                .and_then(|v| n.checked_add(v))
        })
        .and_then(|n| n.checked_add(4096))
        .ok_or_else(memory)?;
    let credit = Credit::reserve(cost)?;
    // Credit is last in the owner so all actual Rust facts die before refund.
    let mut result = Request {
        hints: Vec::new(),
        schemes: Vec::new(),
        version,
        _credit: credit,
    };
    result
        .hints
        .try_reserve_exact(count)
        .map_err(|_| memory())?;
    result.schemes.try_reserve_exact(10).map_err(|_| memory())?;
    if let Some(names) = names {
        let mut measured = 0usize;
        for name in names {
            let n = usize::try_from(unsafe {
                openssl_sys::i2d_X509_NAME(name.as_ptr(), std::ptr::null_mut())
            })
            .map_err(|_| bad())?;
            measured = measured
                .checked_add(n)
                .filter(|v| *v <= bytes)
                .ok_or_else(bad)?;
            if n == 0 {
                return Err(bad());
            }
            let mut der = Vec::new();
            der.try_reserve_exact(n).map_err(|_| memory())?;
            der.resize(n, 0);
            let mut end = der.as_mut_ptr();
            let written = unsafe { openssl_sys::i2d_X509_NAME(name.as_ptr(), &mut end) };
            if usize::try_from(written).ok() != Some(n) || end != unsafe { der.as_mut_ptr().add(n) }
            {
                return Err(bad());
            }
            result.hints.push(der);
        }
        if measured != bytes {
            return Err(bad());
        }
    }
    for index in 0..total {
        let (mut sig, mut hash) = (0, 0);
        let n = unsafe {
            SSL_get_sigalgs(
                ssl.as_ptr(),
                index,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut sig,
                &mut hash,
            )
        };
        if n <= 0 {
            return Err(bad());
        }
        let scheme = SignatureScheme::from(u16::from_be_bytes([hash, sig]));
        let family = matches!(
            scheme,
            SignatureScheme::RSA_PSS_SHA256
                | SignatureScheme::RSA_PSS_SHA384
                | SignatureScheme::RSA_PSS_SHA512
                | SignatureScheme::RSA_PKCS1_SHA256
                | SignatureScheme::RSA_PKCS1_SHA384
                | SignatureScheme::RSA_PKCS1_SHA512
        );
        if allowed(scheme) && (if family { rsa } else { ec }) && !result.schemes.contains(&scheme) {
            result.schemes.push(scheme)
        }
    }
    Ok(result)
}
