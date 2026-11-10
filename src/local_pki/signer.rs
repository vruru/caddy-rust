//! Reuse the process's validated private-key loader without rewriting old keys.
use anyhow::{Result, anyhow, ensure};
use rcgen::{PublicKeyData, SignatureAlgorithm};
use rustls::{SignatureScheme, sign::SigningKey};
use std::sync::Arc;
use x509_parser::prelude::FromDer;

#[derive(Clone)]
enum Key {
    Tls(Arc<dyn SigningKey>, SignatureScheme),
    P521(Arc<rcgen::KeyPair>),
    P224(Arc<p224::ecdsa::SigningKey>),
    Rsa(Arc<rsa::RsaPrivateKey>),
}
#[derive(Clone)]
pub(super) struct CaSigner {
    key: Key,
    public: SubjectKey,
}
impl CaSigner {
    pub(super) fn from_pem(pem: &[u8], certificate: &[u8]) -> Result<Self> {
        let (tail, cert) = x509_parser::parse_x509_certificate(certificate)
            .map_err(|_| anyhow!("invalid CA certificate"))?;
        ensure!(tail.is_empty(), "trailing CA certificate bytes");
        let public = SubjectKey::from_spki(cert.public_key().raw)?;
        let curve = cert
            .public_key()
            .algorithm
            .parameters
            .as_ref()
            .and_then(|v| v.as_oid().ok())
            .map(|v| v.to_id_string());
        let key = match curve.as_deref() {
            Some("1.3.132.0.33") => {
                use p224::pkcs8::DecodePrivateKey;
                let blocks = crate::certmagic::pem_blocks(pem, "local-pki")?;
                ensure!(blocks.len() == 1, "CA private key count invalid");
                let secret = match blocks[0].0.as_str() {
                    "EC PRIVATE KEY" => p224::SecretKey::from_sec1_der(&blocks[0].1)?,
                    "PRIVATE KEY" => p224::SecretKey::from_pkcs8_der(&blocks[0].1)?,
                    _ => return Err(anyhow!("invalid P224 private key label")),
                };
                let signing = p224::ecdsa::SigningKey::from(secret);
                ensure!(
                    signing.verifying_key().to_encoded_point(false).as_bytes() == public.bits,
                    "P224 certificate/key mismatch"
                );
                Key::P224(Arc::new(signing))
            }
            Some("1.3.132.0.35") => {
                let blocks = crate::certmagic::pem_blocks(pem, "local-pki")?;
                ensure!(
                    blocks.len() == 1
                        && matches!(blocks[0].0.as_str(), "EC PRIVATE KEY" | "PRIVATE KEY"),
                    "invalid P521 private key label"
                );
                let key = rcgen::KeyPair::from_pem_and_sign_algo(
                    std::str::from_utf8(pem)?,
                    &rcgen::PKCS_ECDSA_P521_SHA512,
                )?;
                ensure!(
                    key.subject_public_key_info() == public.spki,
                    "P521 certificate/key mismatch"
                );
                Key::P521(Arc::new(key))
            }
            _ => match crate::certmagic::signing_key(pem, "local-pki") {
                Ok(key) => {
                    let spki = key
                        .public_key()
                        .ok_or_else(|| anyhow!("CA public key unavailable"))?;
                    ensure!(spki.as_ref() == public.spki, "CA certificate/key mismatch");
                    let scheme = key
                        .choose_scheme(&[
                            SignatureScheme::ECDSA_NISTP256_SHA256,
                            SignatureScheme::ECDSA_NISTP384_SHA384,
                            SignatureScheme::RSA_PKCS1_SHA256,
                            SignatureScheme::ED25519,
                        ])
                        .ok_or_else(|| anyhow!("unsupported CA signature algorithm"))?
                        .scheme();
                    Key::Tls(key, scheme)
                }
                Err(error) => {
                    ensure!(
                        cert.public_key().algorithm.algorithm.to_id_string()
                            == "1.2.840.113549.1.1.1",
                        "{error}"
                    );
                    use rsa::{
                        pkcs1::DecodeRsaPrivateKey,
                        pkcs8::{DecodePrivateKey, EncodePublicKey},
                        traits::PublicKeyParts,
                    };
                    let blocks = crate::certmagic::pem_blocks(pem, "local-pki")?;
                    ensure!(blocks.len() == 1, "invalid RSA key count");
                    let key = match blocks[0].0.as_str() {
                        "RSA PRIVATE KEY" => rsa::RsaPrivateKey::from_pkcs1_der(&blocks[0].1)?,
                        "PRIVATE KEY" => rsa::RsaPrivateKey::from_pkcs8_der(&blocks[0].1)?,
                        _ => return Err(anyhow!("invalid RSA key label")),
                    };
                    ensure!(
                        (1024..=8192).contains(&key.n().bits()),
                        "RSA CA key size out of range"
                    );
                    ensure!(
                        key.to_public_key().to_public_key_der()?.as_ref() == public.spki,
                        "RSA certificate/key mismatch"
                    );
                    Key::Rsa(Arc::new(key))
                }
            },
        };
        Ok(Self { key, public })
    }
}
impl PublicKeyData for CaSigner {
    fn der_bytes(&self) -> &[u8] {
        self.public.der_bytes()
    }
    fn algorithm(&self) -> &'static SignatureAlgorithm {
        self.public.algorithm()
    }
    fn subject_public_key_info(&self) -> Vec<u8> {
        self.public.subject_public_key_info()
    }
}
impl rcgen::SigningKey for CaSigner {
    fn sign(&self, message: &[u8]) -> std::result::Result<Vec<u8>, rcgen::Error> {
        match &self.key {
            Key::Tls(key, scheme) => key
                .choose_scheme(&[*scheme])
                .ok_or(rcgen::Error::UnsupportedSignatureAlgorithm)?
                .sign(message)
                .map_err(|_| rcgen::Error::UnsupportedSignatureAlgorithm),
            Key::P521(key) => rcgen::SigningKey::sign(key.as_ref(), message),
            Key::P224(key) => {
                use p224::ecdsa::signature::hazmat::PrehashSigner;
                use sha2::Digest;
                let sig: p224::ecdsa::Signature = key
                    .sign_prehash(&sha2::Sha256::digest(message))
                    .map_err(|_| rcgen::Error::UnsupportedSignatureAlgorithm)?;
                Ok(sig.to_der().as_bytes().to_vec())
            }
            Key::Rsa(key) => {
                use rsa::signature::{SignatureEncoding, Signer};
                Ok(
                    rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new((**key).clone())
                        .sign(message)
                        .to_vec(),
                )
            }
        }
    }
}

#[derive(Clone)]
pub(super) struct SubjectKey {
    bits: Vec<u8>,
    spki: Vec<u8>,
    algorithm: &'static SignatureAlgorithm,
}
impl SubjectKey {
    pub(super) fn from_spki(spki: &[u8]) -> Result<Self> {
        let (tail, key) = x509_parser::x509::SubjectPublicKeyInfo::from_der(spki)
            .map_err(|_| anyhow!("invalid public key"))?;
        ensure!(
            tail.is_empty() && key.subject_public_key.unused_bits == 0,
            "invalid public key encoding"
        );
        let algorithm = match key.algorithm.algorithm.to_id_string().as_str() {
            "1.2.840.113549.1.1.1" => {
                ensure!(
                    key.algorithm
                        .parameters
                        .as_ref()
                        .is_some_and(|p| p.tag().0 == 5 && p.data.is_empty()),
                    "RSA public key requires NULL parameters"
                );
                &rcgen::PKCS_RSA_SHA256
            }
            "1.3.101.112" => {
                ensure!(
                    key.algorithm.parameters.is_none() && key.subject_public_key.data.len() == 32,
                    "invalid Ed25519 public key"
                );
                &rcgen::PKCS_ED25519
            }
            "1.2.840.10045.2.1" => {
                let curve = key
                    .algorithm
                    .parameters
                    .as_ref()
                    .and_then(|value| value.as_oid().ok())
                    .ok_or_else(|| anyhow!("EC named curve missing"))?;
                let length = match curve.to_id_string().as_str() {
                    "1.3.132.0.33" => 57,
                    "1.2.840.10045.3.1.7" => 65,
                    "1.3.132.0.34" => 97,
                    "1.3.132.0.35" => 133,
                    _ => return Err(anyhow!("unsupported EC named curve")),
                };
                ensure!(
                    key.subject_public_key.data.len() == length
                        && key.subject_public_key.data.first() == Some(&4),
                    "EC key must be an uncompressed named-curve point"
                );
                match curve.to_id_string().as_str() {
                    "1.2.840.10045.3.1.7" => &rcgen::PKCS_ECDSA_P256_SHA256,
                    "1.3.132.0.34" => &rcgen::PKCS_ECDSA_P384_SHA384,
                    "1.3.132.0.33" => &rcgen::PKCS_ECDSA_P256_SHA256,
                    "1.3.132.0.35" => &rcgen::PKCS_ECDSA_P521_SHA512,
                    _ => return Err(anyhow!("unsupported local CA/CSR EC curve")),
                }
            }
            _ => return Err(anyhow!("unsupported local CA/CSR public key")),
        };
        Ok(Self {
            bits: key.subject_public_key.data.to_vec(),
            spki: spki.to_vec(),
            algorithm,
        })
    }
}
impl PublicKeyData for SubjectKey {
    fn der_bytes(&self) -> &[u8] {
        &self.bits
    }
    fn algorithm(&self) -> &'static SignatureAlgorithm {
        self.algorithm
    }
    fn subject_public_key_info(&self) -> Vec<u8> {
        self.spki.clone()
    }
}
