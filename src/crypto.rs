//! Keep the ring cipher/verification policy while supporting the larger RSA
//! private keys accepted by the original server. Key material is never logged.

use rsa::pkcs8::der::Decode;
use rustls::{
    Error,
    crypto::{CryptoProvider, KeyProvider},
    pki_types::PrivateKeyDer,
    sign::SigningKey,
};
use std::sync::{Arc, LazyLock};

#[derive(Debug)]
struct CompatibleKeys;

impl KeyProvider for CompatibleKeys {
    fn load_private_key(&self, key: PrivateKeyDer<'static>) -> Result<Arc<dyn SigningKey>, Error> {
        match rsa_modulus_bits(&key) {
            Some(4097..=8192) => rustls::crypto::aws_lc_rs::sign::any_supported_type(&key),
            Some(bits) if bits > 8192 => Err(Error::General("RSA key size exceeds limit".into())),
            _ => rustls::crypto::ring::sign::any_supported_type(&key),
        }
    }
}

static PROVIDER: LazyLock<Arc<CryptoProvider>> = LazyLock::new(|| {
    Arc::new(CryptoProvider {
        key_provider: &CompatibleKeys,
        ..rustls::crypto::ring::default_provider()
    })
});

pub fn provider() -> Arc<CryptoProvider> {
    PROVIDER.clone()
}

/// Call before constructing the process runtime or implicit rustls clients.
/// Explicit provider users remain independent of a process-wide default.
pub fn install_default() -> Result<(), Error> {
    if let Some(current) = CryptoProvider::get_default() {
        if std::ptr::eq(current.key_provider, PROVIDER.key_provider) {
            return Ok(());
        }
        return Err(Error::General("conflicting process TLS provider".into()));
    }
    match (**PROVIDER).clone().install_default() {
        Ok(()) => Ok(()),
        Err(_)
            if CryptoProvider::get_default().is_some_and(|current| {
                std::ptr::eq(current.key_provider, PROVIDER.key_provider)
            }) =>
        {
            Ok(())
        }
        Err(_) => Err(Error::General("conflicting process TLS provider".into())),
    }
}

fn rsa_modulus_bits(key: &PrivateKeyDer<'_>) -> Option<usize> {
    let raw = match key {
        PrivateKeyDer::Pkcs1(key) => key.secret_pkcs1_der(),
        PrivateKeyDer::Pkcs8(key) => {
            let info = rsa::pkcs8::PrivateKeyInfo::from_der(key.secret_pkcs8_der()).ok()?;
            if info.algorithm.oid != rsa::pkcs1::ALGORITHM_OID {
                return None;
            }
            info.private_key
        }
        _ => return None,
    };
    let parsed = rsa::pkcs1::RsaPrivateKey::from_der(raw).ok()?;
    let modulus = parsed.modulus.as_bytes();
    let first = modulus.iter().position(|byte| *byte != 0)?;
    Some((modulus.len() - first) * 8 - modulus[first].leading_zeros() as usize)
}
