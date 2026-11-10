//! ACME account identity conversion and RFC 7515 signatures. Public JWKs contain
//! public members only. Existing key bytes are never rewritten during import.
use anyhow::{Result, anyhow, bail, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey, LineEnding};
use rsa::{
    pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey},
    signature::{RandomizedSigner, SignatureEncoding, Signer},
    traits::PublicKeyParts,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum KeyType {
    #[default]
    P256,
    P384,
    Rsa2048,
    Rsa4096,
    Rsa8192,
    Ed25519,
}

pub enum AccountSigner {
    P256(p256::ecdsa::SigningKey),
    P384(p384::ecdsa::SigningKey),
    Rsa(Box<rsa::RsaPrivateKey>),
    Ed25519(ed25519_dalek::SigningKey),
}

impl AccountSigner {
    pub fn from_pem(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() <= 128 * 1024, "ACME account key exceeds bounds");
        let blocks = crate::certmagic::pem_blocks(bytes, "acme-account")?;
        ensure!(blocks.len() == 1, "ACME account requires exactly one key");
        let (label, der) = &blocks[0];
        match label.as_str() {
            "EC PRIVATE KEY" => {
                if let Ok(key) = p256::SecretKey::from_sec1_der(der) {
                    return Ok(Self::P256(key.into()));
                }
                if let Ok(key) = p384::SecretKey::from_sec1_der(der) {
                    return Ok(Self::P384(key.into()));
                }
            }
            "RSA PRIVATE KEY" => {
                return Self::rsa(
                    rsa::RsaPrivateKey::from_pkcs1_der(der)
                        .map_err(|_| anyhow!("invalid ACME RSA account key"))?,
                );
            }
            "PRIVATE KEY" | "ED25519 PRIVATE KEY" => {
                if label == "PRIVATE KEY" {
                    if let Ok(key) = p256::SecretKey::from_pkcs8_der(der) {
                        return Ok(Self::P256(key.into()));
                    }
                    if let Ok(key) = p384::SecretKey::from_pkcs8_der(der) {
                        return Ok(Self::P384(key.into()));
                    }
                    if let Ok(key) = rsa::RsaPrivateKey::from_pkcs8_der(der) {
                        return Self::rsa(key);
                    }
                }
                if let Ok(key) = ed25519_dalek::SigningKey::from_pkcs8_der(der) {
                    return Ok(Self::Ed25519(key));
                }
            }
            _ => bail!("unsupported ACME account PEM label"),
        }
        bail!("invalid or unsupported ACME account key")
    }

    fn rsa(key: rsa::RsaPrivateKey) -> Result<Self> {
        ensure!(
            (2048..=8192).contains(&key.n().bits()),
            "ACME RSA key size outside bounds"
        );
        key.validate()
            .map_err(|_| anyhow!("invalid ACME RSA account key"))?;
        Ok(Self::Rsa(Box::new(key)))
    }

    pub fn generate(kind: KeyType) -> Result<(Self, Zeroizing<Vec<u8>>)> {
        use p256::elliptic_curve::rand_core::{OsRng, RngCore};
        let (key, pem) = match kind {
            KeyType::P256 => {
                let key = p256::SecretKey::random(&mut OsRng);
                // RustCrypto's standalone SEC1 encoder omits curve parameters.
                // Its typed Rust decoder accepts that, whereas Go's generic
                // x509 parser cannot infer the curve. PKCS8 carries the named
                // curve in AlgorithmIdentifier and is portable to old Caddy.
                let pem = key
                    .to_pkcs8_pem(LineEnding::LF)
                    .map_err(|_| anyhow!("ACME P256 export failed"))?;
                (
                    Self::P256(key.into()),
                    Zeroizing::new(pem.as_bytes().to_vec()),
                )
            }
            KeyType::P384 => {
                let key = p384::SecretKey::random(&mut OsRng);
                let pem = key
                    .to_pkcs8_pem(LineEnding::LF)
                    .map_err(|_| anyhow!("ACME P384 export failed"))?;
                (
                    Self::P384(key.into()),
                    Zeroizing::new(pem.as_bytes().to_vec()),
                )
            }
            KeyType::Rsa2048 | KeyType::Rsa4096 | KeyType::Rsa8192 => {
                let key = rsa::RsaPrivateKey::new(
                    &mut OsRng,
                    match kind {
                        KeyType::Rsa2048 => 2048,
                        KeyType::Rsa4096 => 4096,
                        _ => 8192,
                    },
                )
                .map_err(|_| anyhow!("ACME RSA generation failed"))?;
                let pem = key
                    .to_pkcs1_pem(LineEnding::LF)
                    .map_err(|_| anyhow!("ACME RSA export failed"))?;
                (
                    Self::Rsa(Box::new(key)),
                    Zeroizing::new(pem.as_bytes().to_vec()),
                )
            }
            KeyType::Ed25519 => {
                let mut seed = Zeroizing::new([0u8; 32]);
                OsRng.fill_bytes(seed.as_mut());
                let key = ed25519_dalek::SigningKey::from_bytes(&seed);
                let der = key
                    .to_pkcs8_der()
                    .map_err(|_| anyhow!("ACME Ed25519 export failed"))?;
                let encoded = Zeroizing::new(
                    base64::engine::general_purpose::STANDARD.encode(der.as_bytes()),
                );
                let header = b"-----BEGIN ED25519 PRIVATE KEY-----\n";
                let footer = b"-----END ED25519 PRIVATE KEY-----\n";
                let mut pem = Zeroizing::new(Vec::with_capacity(
                    header.len() + footer.len() + encoded.len() + encoded.len().div_ceil(64),
                ));
                pem.extend_from_slice(header);
                for chunk in encoded.as_bytes().chunks(64) {
                    pem.extend_from_slice(chunk);
                    pem.push(b'\n');
                }
                pem.extend_from_slice(footer);
                (Self::Ed25519(key), pem)
            }
        };
        Ok((key, pem))
    }

    pub fn algorithm(&self) -> &'static str {
        match self {
            Self::P256(_) => "ES256",
            Self::P384(_) => "ES384",
            Self::Rsa(_) => "RS256",
            Self::Ed25519(_) => "EdDSA",
        }
    }

    /// Deliberately build a public-member whitelist. No private JWK `d`, CRT
    /// factors, seed, private scalar or DER material can enter this value.
    pub fn jwk(&self) -> Value {
        match self {
            Self::P256(key) => {
                let point = key.verifying_key().to_encoded_point(false);
                let bytes = point.as_bytes();
                json!({"crv":"P-256","kty":"EC","x":URL_SAFE_NO_PAD.encode(&bytes[1..33]),"y":URL_SAFE_NO_PAD.encode(&bytes[33..65])})
            }
            Self::P384(key) => {
                let point = key.verifying_key().to_encoded_point(false);
                let bytes = point.as_bytes();
                json!({"crv":"P-384","kty":"EC","x":URL_SAFE_NO_PAD.encode(&bytes[1..49]),"y":URL_SAFE_NO_PAD.encode(&bytes[49..97])})
            }
            Self::Rsa(key) => {
                json!({"e":URL_SAFE_NO_PAD.encode(key.e().to_bytes_be()),"kty":"RSA","n":URL_SAFE_NO_PAD.encode(key.n().to_bytes_be())})
            }
            Self::Ed25519(key) => {
                json!({"crv":"Ed25519","kty":"OKP","x":URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes())})
            }
        }
    }

    pub fn thumbprint(&self) -> String {
        // Canonical serialization is explicit and independent of serde_json's
        // optional preserve_order feature being enabled by another dependency.
        let jwk = self.jwk();
        let canonical = match self {
            Self::P256(_) | Self::P384(_) => format!(
                "{{\"crv\":{},\"kty\":\"EC\",\"x\":{},\"y\":{}}}",
                jwk["crv"], jwk["x"], jwk["y"]
            ),
            Self::Rsa(_) => format!("{{\"e\":{},\"kty\":\"RSA\",\"n\":{}}}", jwk["e"], jwk["n"]),
            Self::Ed25519(_) => {
                format!("{{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":{}}}", jwk["x"])
            }
        };
        URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()))
    }

    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        Ok(match self {
            Self::P256(key) => {
                let sig: p256::ecdsa::Signature = key
                    .try_sign(message)
                    .map_err(|_| anyhow!("ACME ES256 signing failed"))?;
                sig.to_bytes().to_vec()
            }
            Self::P384(key) => {
                let sig: p384::ecdsa::Signature = key
                    .try_sign(message)
                    .map_err(|_| anyhow!("ACME ES384 signing failed"))?;
                sig.to_bytes().to_vec()
            }
            Self::Rsa(key) => {
                let signer = rsa::pkcs1v15::SigningKey::<Sha256>::new((**key).clone());
                signer
                    .try_sign_with_rng(&mut p256::elliptic_curve::rand_core::OsRng, message)
                    .map_err(|_| anyhow!("ACME RS256 signing failed"))?
                    .to_vec()
            }
            Self::Ed25519(key) => key
                .try_sign(message)
                .map_err(|_| anyhow!("ACME EdDSA signing failed"))?
                .to_bytes()
                .to_vec(),
        })
    }

    pub fn public_spki(&self) -> Result<Vec<u8>> {
        let der = match self {
            Self::P256(key) => key
                .verifying_key()
                .to_public_key_der()
                .map_err(|_| anyhow!("ACME public key encoding failed"))?,
            Self::P384(key) => key
                .verifying_key()
                .to_public_key_der()
                .map_err(|_| anyhow!("ACME public key encoding failed"))?,
            Self::Rsa(key) => key
                .to_public_key()
                .to_public_key_der()
                .map_err(|_| anyhow!("ACME public key encoding failed"))?,
            Self::Ed25519(key) => key
                .verifying_key()
                .to_public_key_der()
                .map_err(|_| anyhow!("ACME public key encoding failed"))?,
        };
        Ok(der.as_bytes().to_vec())
    }
}
