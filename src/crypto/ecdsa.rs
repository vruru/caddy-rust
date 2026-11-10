//! TLS 1.2 hash agility, with the original ring/AWS signer on its native hash.
use openssl::pkey::{PKey, Private};
use rsa::pkcs8::der::Decode;
use rustls::{
    Error, SignatureAlgorithm, SignatureScheme,
    pki_types::{PrivateKeyDer, SubjectPublicKeyInfoDer},
    sign::{Signer, SigningKey},
};
use std::{fmt, sync::Arc};

pub(super) fn curve_scheme(key: &dyn SigningKey) -> Option<SignatureScheme> {
    let public = key.public_key()?;
    let spki = rsa::pkcs8::SubjectPublicKeyInfoRef::from_der(public.as_ref()).ok()?;
    let curve = spki.algorithm.parameters_oid().ok()?;
    match curve.to_string().as_str() {
        "1.2.840.10045.3.1.7" => Some(SignatureScheme::ECDSA_NISTP256_SHA256),
        "1.3.132.0.34" => Some(SignatureScheme::ECDSA_NISTP384_SHA384),
        "1.3.132.0.35" => Some(SignatureScheme::ECDSA_NISTP521_SHA512),
        _ => None,
    }
}
fn failed() -> Error {
    Error::General("invalid generic ECDSA signing key".into())
}
pub(super) fn load(
    preferred: Arc<dyn SigningKey>,
    der: &PrivateKeyDer<'_>,
) -> Result<Arc<dyn SigningKey>, Error> {
    let native = curve_scheme(preferred.as_ref()).ok_or_else(failed)?;
    let public = preferred.public_key().ok_or_else(failed)?;
    let fallback = super::legacy_sign::curve_hash_key(der, public.as_ref())?;
    Ok(Arc::new(GenericEcdsa {
        preferred,
        native,
        fallback,
    }))
}

struct GenericEcdsa {
    preferred: Arc<dyn SigningKey>,
    native: SignatureScheme,
    fallback: Arc<PKey<Private>>,
}
impl fmt::Debug for GenericEcdsa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GenericEcdsa")
            .field("native_scheme", &self.native)
            .finish_non_exhaustive()
    }
}
impl SigningKey for GenericEcdsa {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        for scheme in offered {
            if !matches!(
                scheme,
                SignatureScheme::ECDSA_NISTP256_SHA256
                    | SignatureScheme::ECDSA_NISTP384_SHA384
                    | SignatureScheme::ECDSA_NISTP521_SHA512
            ) {
                continue;
            }
            if *scheme == self.native {
                return self.preferred.choose_scheme(&[*scheme]);
            }
            return Some(Box::new(super::legacy_sign::LegacySigner {
                private: self.fallback.clone(),
                scheme: *scheme,
            }));
        }
        None
    }
    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        self.preferred.public_key()
    }
    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }
}
/// A precomputed TLS1.3 view. No transcript sniffing, task-local state or
/// mutation of the shared private signing object is used.
pub(super) struct BoundKey {
    pub inner: Arc<dyn SigningKey>,
    pub scheme: SignatureScheme,
}
impl fmt::Debug for BoundKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CurveBoundKey")
            .field("scheme", &self.scheme)
            .finish_non_exhaustive()
    }
}
impl SigningKey for BoundKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offered
            .contains(&self.scheme)
            .then(|| self.inner.choose_scheme(&[self.scheme]))
            .flatten()
    }
    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        self.inner.public_key()
    }
    fn algorithm(&self) -> SignatureAlgorithm {
        self.inner.algorithm()
    }
}
pub(super) struct BoundRsaKey {
    pub inner: Arc<dyn SigningKey>,
}
impl fmt::Debug for BoundRsaKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PssBoundKey").finish_non_exhaustive()
    }
}
impl SigningKey for BoundRsaKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        let mut filtered = Vec::with_capacity(3);
        for scheme in offered {
            if matches!(
                scheme,
                SignatureScheme::RSA_PSS_SHA256
                    | SignatureScheme::RSA_PSS_SHA384
                    | SignatureScheme::RSA_PSS_SHA512
            ) && !filtered.contains(scheme)
            {
                filtered.push(*scheme);
                if filtered.len() == 3 {
                    break;
                }
            }
        }
        self.inner.choose_scheme(&filtered)
    }
    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        self.inner.public_key()
    }
    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::RSA
    }
}
