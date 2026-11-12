//! Preserve ring ciphers/KX while adding bounded, authenticated signature
//! compatibility. Certificate/path/name/time/purpose validation stays WebPKI.

#[path = "crypto/ecdsa.rs"]
mod ecdsa;
#[path = "crypto/legacy_sign.rs"]
mod legacy_sign;
#[path = "crypto/verification.rs"]
mod verification;
#[path = "crypto/x509_signer.rs"]
pub(crate) mod x509_signer;

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
        if key.secret_der().len() > 16 * 1024 {
            return Err(Error::General("private key exceeds size limit".into()));
        }
        match rsa_modulus_bits(&key) {
            Some(1024..=2047) => legacy_sign::load(&key),
            Some(bits) if bits < 1024 => Err(Error::General(
                "RSA key size below compatibility limit".into(),
            )),
            Some(4097..=8192) => rustls::crypto::aws_lc_rs::sign::any_supported_type(&key),
            Some(bits) if bits > 8192 => Err(Error::General("RSA key size exceeds limit".into())),
            _ => {
                if let Ok(preferred) = rustls::crypto::ring::sign::any_supported_type(&key) {
                    return Ok(preferred);
                }
                if let Ok(preferred) = rustls::crypto::aws_lc_rs::sign::any_supported_type(&key)
                    && ecdsa::curve_scheme(preferred.as_ref())
                        == Some(rustls::SignatureScheme::ECDSA_NISTP521_SHA512)
                {
                    return Ok(preferred);
                }
                legacy_sign::load(&key)
            }
        }
    }
}

static PROVIDER: LazyLock<Arc<CryptoProvider>> = LazyLock::new(|| {
    Arc::new(CryptoProvider {
        key_provider: &CompatibleKeys,
        signature_verification_algorithms: verification::algorithms(),
        ..rustls::crypto::ring::default_provider()
    })
});

pub fn provider() -> Arc<CryptoProvider> {
    PROVIDER.clone()
}

/// Prepare the generic-hash view only for TLS1.2 certificate use. The ordinary
/// key provider remains curve-bound, so CSR/CA signing algorithm labels and
/// non-TLS consumers retain their existing native-hash behavior.
pub(crate) fn tls12_signer(
    key: &Arc<dyn SigningKey>,
    pem: &[u8],
) -> Result<Arc<dyn SigningKey>, Error> {
    if key.algorithm() != rustls::SignatureAlgorithm::ECDSA
        || ecdsa::curve_scheme(key.as_ref()).is_none()
    {
        return Ok(key.clone());
    }
    let blocks = crate::certmagic::pem_blocks(pem, "tls12-signing-key")
        .map_err(|_| Error::General("invalid TLS private key".into()))?;
    if blocks.len() != 1 {
        return Err(Error::General("invalid TLS private key count".into()));
    }
    let (label, bytes) = &blocks[0];
    let der = match label.as_str() {
        "EC PRIVATE KEY" => rustls::pki_types::PrivateSec1KeyDer::from(bytes.as_slice()).into(),
        "PRIVATE KEY" => rustls::pki_types::PrivatePkcs8KeyDer::from(bytes.as_slice()).into(),
        _ => return Err(Error::General("invalid TLS EC key label".into())),
    };
    ecdsa::load(key.clone(), &der)
}

/// Precomputed curve-bound TLS1.3 view. P224 has no TLS1.3 signature scheme.
pub(crate) fn tls13_signer(key: &Arc<dyn SigningKey>) -> Option<Arc<dyn SigningKey>> {
    match key.algorithm() {
        rustls::SignatureAlgorithm::ECDSA => {
            let scheme = ecdsa::curve_scheme(key.as_ref())?;
            Some(Arc::new(ecdsa::BoundKey {
                inner: key.clone(),
                scheme,
            }))
        }
        rustls::SignatureAlgorithm::RSA => {
            Some(Arc::new(ecdsa::BoundRsaKey { inner: key.clone() }))
        }
        rustls::SignatureAlgorithm::ED25519 => Some(key.clone()),
        _ => None,
    }
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
