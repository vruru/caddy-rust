//! Restricted legacy keys. OpenSSL is a signature backend, never a TLS transport.
use openssl::{
    ec::EcKey,
    hash::MessageDigest,
    nid::Nid,
    pkey::{Id, PKey, Private},
    rsa::{Padding, Rsa},
    sign::{RsaPssSaltlen, Signer as OsslSigner},
};
use rsa::pkcs8::der::{Decode, Tagged};
use rustls::{
    Error, SignatureAlgorithm, SignatureScheme,
    pki_types::{PrivateKeyDer, SubjectPublicKeyInfoDer},
    sign::{Signer, SigningKey},
};
use std::{fmt, sync::Arc};

pub(super) fn ready() -> bool {
    // The locked vendored build is 4.0.3. Never silently accept a stale host
    // library or a different major through a build environment override.
    (0x4000_0030..0x5000_0000).contains(&openssl::version::number())
}
fn failure() -> Error {
    Error::General("unsupported or invalid legacy signing key".into())
}

fn parse(key: &PrivateKeyDer<'_>) -> Result<PKey<Private>, Error> {
    if !ready() || key.secret_der().len() > 16 * 1024 {
        return Err(failure());
    }
    let outer = rsa::pkcs8::der::AnyRef::from_der(key.secret_der()).map_err(|_| failure())?;
    if outer.tag() != rsa::pkcs8::der::Tag::Sequence {
        return Err(failure());
    }
    let private = match key {
        PrivateKeyDer::Pkcs1(v) => {
            PKey::from_rsa(Rsa::private_key_from_der(v.secret_pkcs1_der()).map_err(|_| failure())?)
        }
        PrivateKeyDer::Sec1(v) => PKey::from_ec_key(
            EcKey::private_key_from_der(v.secret_sec1_der()).map_err(|_| failure())?,
        ),
        PrivateKeyDer::Pkcs8(v) => PKey::private_key_from_pkcs8(v.secret_pkcs8_der()),
        _ => return Err(failure()),
    }
    .map_err(|_| failure())?;
    Ok(private)
}
pub(super) fn curve_hash_key(
    key: &PrivateKeyDer<'_>,
    expected_spki: &[u8],
) -> Result<Arc<PKey<Private>>, Error> {
    let private = parse(key)?;
    if private.id() != Id::EC {
        return Err(failure());
    }
    let ec = private.ec_key().map_err(|_| failure())?;
    if !matches!(
        ec.group().curve_name(),
        Some(Nid::X9_62_PRIME256V1 | Nid::SECP384R1 | Nid::SECP521R1)
    ) {
        return Err(failure());
    }
    ec.check_key().map_err(|_| failure())?;
    if private.public_key_to_der().map_err(|_| failure())? != expected_spki {
        return Err(failure());
    }
    Ok(Arc::new(private))
}
pub(super) fn load(key: &PrivateKeyDer<'_>) -> Result<Arc<dyn SigningKey>, Error> {
    if !ready() || key.secret_der().len() > 16 * 1024 {
        return Err(failure());
    }
    let outer = rsa::pkcs8::der::AnyRef::from_der(key.secret_der()).map_err(|_| failure())?;
    if outer.tag() != rsa::pkcs8::der::Tag::Sequence {
        return Err(failure());
    }
    let private = parse(key)?;
    let (algorithm, bits) = match private.id() {
        Id::RSA => {
            let rsa = private.rsa().map_err(|_| failure())?;
            let bits = rsa.n().num_bits() as usize;
            if !(1024..2048).contains(&bits)
                || rsa.e().num_bits() > 64
                || !rsa.check_key().map_err(|_| failure())?
            {
                return Err(failure());
            }
            (SignatureAlgorithm::RSA, bits)
        }
        Id::EC => {
            let ec = private.ec_key().map_err(|_| failure())?;
            if ec.group().curve_name() != Some(Nid::SECP224R1) {
                return Err(failure());
            }
            ec.check_key().map_err(|_| failure())?;
            (SignatureAlgorithm::ECDSA, 224)
        }
        _ => return Err(failure()),
    };
    let public = private.public_key_to_der().map_err(|_| failure())?;
    Ok(Arc::new(LegacyKey {
        private: Arc::new(private),
        public,
        algorithm,
        bits,
    }))
}
struct LegacyKey {
    private: Arc<PKey<Private>>,
    public: Vec<u8>,
    algorithm: SignatureAlgorithm,
    bits: usize,
}
impl fmt::Debug for LegacyKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LegacyKey")
            .field("algorithm", &self.algorithm)
            .field("bits", &self.bits)
            .finish_non_exhaustive()
    }
}
impl SigningKey for LegacyKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        // Match Go's peer-preference order, subject to exact PSS capacity.
        let scheme = offered
            .iter()
            .copied()
            .find(|scheme| match self.algorithm {
                SignatureAlgorithm::RSA => rsa_scheme(*scheme, self.bits),
                SignatureAlgorithm::ECDSA => matches!(
                    scheme,
                    SignatureScheme::ECDSA_NISTP256_SHA256
                        | SignatureScheme::ECDSA_NISTP384_SHA384
                        | SignatureScheme::ECDSA_NISTP521_SHA512
                ),
                _ => false,
            })?;
        Some(Box::new(LegacySigner {
            private: self.private.clone(),
            scheme,
        }))
    }
    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(SubjectPublicKeyInfoDer::from(self.public.as_slice()))
    }
    fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }
}
pub(super) fn rsa_scheme(scheme: SignatureScheme, bits: usize) -> bool {
    let hash = match scheme {
        SignatureScheme::RSA_PSS_SHA256 => 32,
        SignatureScheme::RSA_PSS_SHA384 => 48,
        SignatureScheme::RSA_PSS_SHA512 => 64,
        SignatureScheme::RSA_PKCS1_SHA256
        | SignatureScheme::RSA_PKCS1_SHA384
        | SignatureScheme::RSA_PKCS1_SHA512 => return true,
        _ => return false,
    };
    // ceil((modBits - 1) / 8), RFC8017, with salt length exactly hash length.
    bits.saturating_sub(1).div_ceil(8) >= 2 * hash + 2
}
pub(super) fn digest(scheme: SignatureScheme) -> Option<MessageDigest> {
    match scheme {
        SignatureScheme::RSA_PSS_SHA256
        | SignatureScheme::RSA_PKCS1_SHA256
        | SignatureScheme::ECDSA_NISTP256_SHA256 => Some(MessageDigest::sha256()),
        SignatureScheme::RSA_PSS_SHA384
        | SignatureScheme::RSA_PKCS1_SHA384
        | SignatureScheme::ECDSA_NISTP384_SHA384 => Some(MessageDigest::sha384()),
        SignatureScheme::RSA_PSS_SHA512
        | SignatureScheme::RSA_PKCS1_SHA512
        | SignatureScheme::ECDSA_NISTP521_SHA512 => Some(MessageDigest::sha512()),
        _ => None,
    }
}
pub(super) struct LegacySigner {
    pub private: Arc<PKey<Private>>,
    pub scheme: SignatureScheme,
}
impl fmt::Debug for LegacySigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LegacySigner")
            .field("scheme", &self.scheme)
            .finish_non_exhaustive()
    }
}
impl Signer for LegacySigner {
    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let digest = digest(self.scheme).ok_or_else(failure)?;
        let mut signer = OsslSigner::new(digest, &self.private).map_err(|_| failure())?;
        if self.private.id() == Id::RSA {
            if matches!(
                self.scheme,
                SignatureScheme::RSA_PSS_SHA256
                    | SignatureScheme::RSA_PSS_SHA384
                    | SignatureScheme::RSA_PSS_SHA512
            ) {
                signer
                    .set_rsa_padding(Padding::PKCS1_PSS)
                    .map_err(|_| failure())?;
                signer.set_rsa_mgf1_md(digest).map_err(|_| failure())?;
                signer
                    .set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)
                    .map_err(|_| failure())?;
            } else {
                signer
                    .set_rsa_padding(Padding::PKCS1)
                    .map_err(|_| failure())?;
            }
        }
        signer.update(message).map_err(|_| failure())?;
        signer
            .sign_to_vec()
            .map_err(|_| Error::General("legacy signature failed".into()))
    }
}
