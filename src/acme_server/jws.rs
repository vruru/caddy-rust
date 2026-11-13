//! Bounded RFC 7515/7517/7638 verification for RFC 8555 requests.
//! Parsing, single-use nonce consumption, resource lookup and signature checking
//! are deliberately separate: only the database can atomically consume a nonce.

use super::bolt::Budget;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey, EcPoint},
    ecdsa::EcdsaSig,
    hash::MessageDigest,
    nid::Nid,
    pkey::{Id, PKey, Public},
    rsa::{Padding, Rsa},
    sign::{RsaPssSaltlen, Verifier},
};
use serde::{
    Deserialize,
    de::{IgnoredAny, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Value, value::RawValue};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fmt::Write};

#[derive(Debug)]
pub enum Error {
    Malformed(&'static str),
    BadAlgorithm,
    InvalidSignature,
    Resource(super::bolt::Error),
}
impl From<super::bolt::Error> for Error {
    fn from(e: super::bolt::Error) -> Self {
        Self::Resource(e)
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(s) => write!(f, "malformed ACME JWS: {s}"),
            Self::BadAlgorithm => f.write_str("unsuitable ACME signature algorithm"),
            Self::InvalidSignature => f.write_str("ACME signature verification failed"),
            Self::Resource(e) => e.fmt(f),
        }
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;
fn crypto<T>(r: std::result::Result<T, openssl::error::ErrorStack>) -> Result<T> {
    r.map_err(|_| Error::Malformed("invalid cryptographic key or signature"))
}
fn required(field: Option<&str>) -> Result<&str> {
    field.ok_or(Error::Malformed("JWK member missing"))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    Rs256,
    Rs384,
    Rs512,
    Ps256,
    Ps384,
    Ps512,
    Es256,
    Es384,
    Es512,
    EdDsa,
}
impl Algorithm {
    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "RS256" => Self::Rs256,
            "RS384" => Self::Rs384,
            "RS512" => Self::Rs512,
            "PS256" => Self::Ps256,
            "PS384" => Self::Ps384,
            "PS512" => Self::Ps512,
            "ES256" => Self::Es256,
            "ES384" => Self::Es384,
            "ES512" => Self::Es512,
            "EdDSA" => Self::EdDsa,
            _ => return Err(Error::BadAlgorithm),
        })
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Rs256 => "RS256",
            Self::Rs384 => "RS384",
            Self::Rs512 => "RS512",
            Self::Ps256 => "PS256",
            Self::Ps384 => "PS384",
            Self::Ps512 => "PS512",
            Self::Es256 => "ES256",
            Self::Es384 => "ES384",
            Self::Es512 => "ES512",
            Self::EdDsa => "EdDSA",
        }
    }
    fn digest(self) -> Option<MessageDigest> {
        Some(match self {
            Self::Rs256 | Self::Ps256 | Self::Es256 => MessageDigest::sha256(),
            Self::Rs384 | Self::Ps384 | Self::Es384 => MessageDigest::sha384(),
            Self::Rs512 | Self::Ps512 | Self::Es512 => MessageDigest::sha512(),
            Self::EdDsa => return None,
        })
    }
}

#[derive(Deserialize)]
struct Parts {
    protected: Option<String>,
    signature: Option<String>,
    header: Option<Box<RawValue>>,
}
#[derive(Deserialize)]
struct Envelope {
    protected: Option<String>,
    payload: Option<String>,
    signature: Option<String>,
    header: Option<Box<RawValue>>,
    signatures: Option<Box<RawValue>>,
}
struct Single(Parts);
impl<'de> Deserialize<'de> for Single {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> std::result::Result<Self, D::Error> {
        struct One;
        impl<'de> Visitor<'de> for One {
            type Value = Single;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("one JWS signature")
            }
            fn visit_seq<S: SeqAccess<'de>>(
                self,
                mut seq: S,
            ) -> std::result::Result<Single, S::Error> {
                let part = seq
                    .next_element::<Parts>()?
                    .ok_or_else(|| serde::de::Error::custom("signature missing"))?;
                if seq.next_element::<IgnoredAny>()?.is_some() {
                    return Err(serde::de::Error::custom("multiple signatures"));
                }
                Ok(Single(part))
            }
        }
        de.deserialize_seq(One)
    }
}
struct EmptyHeader;
impl<'de> Deserialize<'de> for EmptyHeader {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> std::result::Result<Self, D::Error> {
        struct Empty;
        impl<'de> Visitor<'de> for Empty {
            type Value = EmptyHeader;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("empty unprotected header")
            }
            fn visit_map<M: MapAccess<'de>>(
                self,
                mut map: M,
            ) -> std::result::Result<EmptyHeader, M::Error> {
                if map.next_key::<IgnoredAny>()?.is_some() {
                    return Err(serde::de::Error::custom("unprotected header forbidden"));
                }
                Ok(EmptyHeader)
            }
        }
        de.deserialize_map(Empty)
    }
}
#[derive(Deserialize, Debug)]
pub struct Header {
    pub alg: String,
    pub nonce: Option<String>,
    pub url: Option<String>,
    pub kid: Option<String>,
    pub jwk: Option<Box<RawValue>>,
    b64: Option<bool>,
    crit: Option<Vec<String>>,
}
pub struct Signed {
    pub header: Header,
    pub algorithm: Algorithm,
    pub payload: Vec<u8>,
    message: Vec<u8>,
    signature: Vec<u8>,
}

fn decode(s: &str, max: usize, budget: &mut impl Budget) -> Result<Vec<u8>> {
    let limit = s
        .len()
        .checked_mul(3)
        .ok_or(Error::Malformed("base64 size"))?
        / 4
        + 3;
    if limit > max + 3 {
        return Err(Error::Malformed("base64 size"));
    }
    budget.work(s.len().div_ceil(64).max(1))?;
    budget.charge(limit)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(limit)
        .map_err(|_| Error::Resource(super::bolt::Error::Limit))?;
    URL_SAFE_NO_PAD
        .decode_vec(s, &mut bytes)
        .map_err(|_| Error::Malformed("noncanonical base64url"))?;
    if bytes.len() > max {
        return Err(Error::Malformed("base64 size"));
    }
    Ok(bytes)
}

pub fn parse(body: &[u8], budget: &mut impl Budget) -> Result<Signed> {
    if body.len() > 512 * 1024 {
        return Err(Error::Malformed("request exceeds bounds"));
    }
    // Envelope fields are strings/raw fragments; a general signature array is
    // decoded with a one-element visitor, and nonempty unprotected headers are
    // rejected without building a Value graph. Six input lengths cover both
    // fragment copies, decoded strings, signing input, and fixed metadata.
    budget.work(body.len().div_ceil(16).max(1))?;
    budget.charge(
        body.len()
            .checked_mul(6)
            .and_then(|n| n.checked_add(4096))
            .ok_or(Error::Malformed("request size"))?,
    )?;
    let envelope: Envelope =
        serde_json::from_slice(body).map_err(|_| Error::Malformed("invalid JWS JSON"))?;
    let (protected, signature, header) = if let Some(all) = envelope.signatures {
        if envelope.protected.is_some() || envelope.signature.is_some() || envelope.header.is_some()
        {
            return Err(Error::Malformed("exactly one signature required"));
        }
        let Single(p) = serde_json::from_str(all.get())
            .map_err(|_| Error::Malformed("exactly one signature required"))?;
        (p.protected, p.signature, p.header)
    } else {
        (envelope.protected, envelope.signature, envelope.header)
    };
    if let Some(header) = header {
        serde_json::from_str::<EmptyHeader>(header.get())
            .map_err(|_| Error::Malformed("unprotected header"))?;
    }
    let protected = protected.ok_or(Error::Malformed("protected header missing"))?;
    let payload = envelope
        .payload
        .ok_or(Error::Malformed("detached payload"))?;
    let raw = decode(&protected, 16 * 1024, budget)?;
    budget.charge(
        raw.len()
            .checked_mul(64)
            .ok_or(Error::Malformed("protected header size"))?,
    )?;
    let header: Header =
        serde_json::from_slice(&raw).map_err(|_| Error::Malformed("invalid protected header"))?;
    let algorithm = Algorithm::parse(&header.alg)?;
    let signature = decode(
        &signature.ok_or(Error::Malformed("signature missing"))?,
        2048,
        budget,
    )?;
    let decoded = decode(&payload, 384 * 1024, budget)?;
    let len = protected
        .len()
        .checked_add(payload.len())
        .and_then(|n| n.checked_add(1))
        .ok_or(Error::Malformed("signing input size"))?;
    budget.charge(len)?;
    budget.work(len.div_ceil(64).max(1))?;
    let mut message = Vec::new();
    message
        .try_reserve_exact(len)
        .map_err(|_| Error::Resource(super::bolt::Error::Limit))?;
    message.extend_from_slice(protected.as_bytes());
    message.push(b'.');
    message.extend_from_slice(payload.as_bytes());
    Ok(Signed {
        header,
        algorithm,
        payload: decoded,
        message,
        signature,
    })
}

impl Signed {
    /// Call only AFTER the nonce transaction. Empty kid has Go's absent-keyID
    /// meaning. Inner keyChange JWS uses the same verifier without a nonce.
    pub fn validate_binding(&self, url: &str) -> Result<()> {
        if self.header.url.as_deref() != Some(url) {
            return Err(Error::Malformed("protected URL mismatch"));
        }
        let kid = self.header.kid.as_ref().is_some_and(|s| !s.is_empty());
        if kid == self.header.jwk.is_some() {
            return Err(Error::Malformed("exactly one of jwk and kid required"));
        }
        Ok(())
    }
}

#[derive(Deserialize)]
struct Jwk {
    kty: String,
    crv: Option<String>,
    x: Option<String>,
    y: Option<String>,
    n: Option<String>,
    e: Option<String>,
    alg: Option<String>,
    #[serde(rename = "use")]
    _usage: Option<String>,
    #[serde(rename = "kid")]
    _key_id: Option<String>,
    x5c: Option<Vec<String>>,
    x5u: Option<String>,
    x5t: Option<String>,
    #[serde(rename = "x5t#S256")]
    x5t_s256: Option<String>,
    #[serde(flatten)]
    extra: BTreeMap<String, Value>,
}
#[path = "jwk_metadata.rs"]
mod metadata;
#[derive(Clone, Copy)]
enum Family {
    Rsa,
    P256,
    P384,
    P521,
    Ed25519,
}
pub struct VerificationKey {
    key: PKey<Public>,
    family: Family,
    hint: Option<String>,
    thumbprint: String,
}

impl VerificationKey {
    pub fn from_jwk(raw: &RawValue, budget: &mut impl Budget) -> Result<Self> {
        if raw.get().len() > 16 * 1024 {
            return Err(Error::Malformed("JWK exceeds bounds"));
        }
        budget.work(raw.get().len().div_ceil(16).max(1))?;
        budget.charge(
            raw.get()
                .len()
                .checked_mul(64)
                .and_then(|n| n.checked_add(1024 * 1024))
                .ok_or(Error::Malformed("JWK size"))?,
        )?;
        let jwk: Jwk =
            serde_json::from_str(raw.get()).map_err(|_| Error::Malformed("invalid JWK"))?;
        if ["d", "p", "q", "dp", "dq", "qi", "oth", "k"]
            .iter()
            .any(|name| jwk.extra.contains_key(*name))
        {
            return Err(Error::Malformed("private JWK material forbidden"));
        }
        let mut canonical = String::new();
        canonical
            .try_reserve_exact(raw.get().len() * 2 + 128)
            .map_err(|_| Error::Resource(super::bolt::Error::Limit))?;
        let (key, family) = match jwk.kty.as_str() {
            "RSA" => {
                let ns = required(jwk.n.as_deref())?;
                let es = required(jwk.e.as_deref())?;
                let n = decode(ns, 1024, budget)?;
                let e = decode(es, 4, budget)?;
                if n.is_empty() || n[0] == 0 || e.is_empty() || e[0] == 0 {
                    return Err(Error::Malformed("noncanonical RSA integer"));
                }
                let exponent = e.iter().fold(0u64, |n, b| (n << 8) | u64::from(*b));
                let modulus = crypto(BigNum::from_slice(&n))?;
                if !(2048..=8192).contains(&modulus.num_bits())
                    || !(2..=2147483647).contains(&exponent)
                {
                    return Err(Error::Malformed("RSA key outside bounds"));
                }
                budget.work(n.len() * 64)?;
                let key = crypto(PKey::from_rsa(crypto(Rsa::from_public_components(
                    modulus,
                    crypto(BigNum::from_slice(&e))?,
                ))?))?;
                write!(
                    &mut canonical,
                    "{{\"e\":\"{es}\",\"kty\":\"RSA\",\"n\":\"{ns}\"}}"
                )
                .map_err(|_| Error::Malformed("JWK serialization"))?;
                (key, Family::Rsa)
            }
            "EC" => {
                let crv = required(jwk.crv.as_deref())?;
                let (nid, size, family) = match crv {
                    "P-256" => (Nid::X9_62_PRIME256V1, 32, Family::P256),
                    "P-384" => (Nid::SECP384R1, 48, Family::P384),
                    "P-521" => (Nid::SECP521R1, 66, Family::P521),
                    _ => return Err(Error::Malformed("unsupported JWK curve")),
                };
                let xs = required(jwk.x.as_deref())?;
                let ys = required(jwk.y.as_deref())?;
                let x = decode(xs, size, budget)?;
                let y = decode(ys, size, budget)?;
                if x.len() != size || y.len() != size {
                    return Err(Error::Malformed("EC coordinate length"));
                }
                let mut point = [0u8; 133];
                point[0] = 4;
                point[1..1 + size].copy_from_slice(&x);
                point[1 + size..1 + size * 2].copy_from_slice(&y);
                budget.work(16384)?;
                let group = crypto(EcGroup::from_curve_name(nid))?;
                let mut context = crypto(BigNumContext::new())?;
                let point = crypto(EcPoint::from_bytes(
                    &group,
                    &point[..1 + size * 2],
                    &mut context,
                ))?;
                let ec = crypto(EcKey::from_public_key(&group, &point))?;
                crypto(ec.check_key())?;
                let key = crypto(PKey::from_ec_key(ec))?;
                write!(
                    &mut canonical,
                    "{{\"crv\":\"{crv}\",\"kty\":\"EC\",\"x\":\"{xs}\",\"y\":\"{ys}\"}}"
                )
                .map_err(|_| Error::Malformed("JWK serialization"))?;
                (key, family)
            }
            "OKP" => {
                if jwk.crv.as_deref() != Some("Ed25519") {
                    return Err(Error::Malformed("unsupported OKP curve"));
                }
                let xs = required(jwk.x.as_deref())?;
                let x = decode(xs, 32, budget)?;
                if x.len() != 32 {
                    return Err(Error::Malformed("Ed25519 key length"));
                }
                budget.work(4096)?;
                let key = crypto(PKey::public_key_from_raw_bytes(&x, Id::ED25519))?;
                write!(
                    &mut canonical,
                    "{{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"{xs}\"}}"
                )
                .map_err(|_| Error::Malformed("JWK serialization"))?;
                (key, Family::Ed25519)
            }
            _ => return Err(Error::Malformed("unsupported JWK key type")),
        };
        metadata::validate(&jwk, &key, budget)?;
        budget.charge(64)?;
        let mut thumbprint = String::new();
        thumbprint
            .try_reserve_exact(64)
            .map_err(|_| Error::Resource(super::bolt::Error::Limit))?;
        URL_SAFE_NO_PAD.encode_string(Sha256::digest(canonical.as_bytes()), &mut thumbprint);
        Ok(Self {
            key,
            family,
            hint: jwk.alg,
            thumbprint,
        })
    }
    pub fn thumbprint(&self) -> &str {
        &self.thumbprint
    }
    pub fn matches_spki(&self, spki: &[u8], budget: &mut impl Budget) -> Result<bool> {
        if spki.len() > 16384 {
            return Err(Error::Malformed("certificate public key exceeds bounds"));
        }
        budget.charge(
            spki.len()
                .checked_mul(64)
                .and_then(|n| n.checked_add(4096))
                .ok_or(super::bolt::Error::Limit)?,
        )?;
        budget.work(spki.len().div_ceil(16).max(1))?;
        let other = crypto(PKey::public_key_from_der(spki))?;
        Ok(self.key.public_eq(&other))
    }
    pub fn spki(&self, budget: &mut impl Budget) -> Result<Vec<u8>> {
        budget.work(1)?;
        budget.charge(4096)?;
        crypto(self.key.public_key_to_der())
    }

    pub fn verify(&self, signed: &Signed, budget: &mut impl Budget) -> Result<()> {
        if signed.header.b64 == Some(false) {
            return Err(Error::Malformed("unencoded payload forbidden"));
        }
        if let Some(critical) = &signed.header.crit {
            if critical.len() > 1
                || critical.iter().any(|name| name != "b64")
                || (!critical.is_empty() && signed.header.b64 != Some(true))
            {
                return Err(Error::Malformed("unsupported critical header"));
            }
        }
        if self
            .hint
            .as_deref()
            .is_some_and(|alg| !alg.is_empty() && alg != signed.algorithm.name())
        {
            return Err(Error::Malformed("JWK/signature algorithm mismatch"));
        }
        let alg = signed.algorithm;
        let ec_size = match (self.family, alg) {
            (Family::P256, Algorithm::Es256) => Some(64),
            (Family::P384, Algorithm::Es384) => Some(96),
            (Family::P521, Algorithm::Es512) => Some(132),
            (
                Family::Rsa,
                Algorithm::Rs256
                | Algorithm::Rs384
                | Algorithm::Rs512
                | Algorithm::Ps256
                | Algorithm::Ps384
                | Algorithm::Ps512,
            ) => None,
            (Family::Ed25519, Algorithm::EdDsa) => None,
            _ => return Err(Error::Malformed("JWK/signature type mismatch")),
        };
        budget.charge(65536)?;
        budget.work(signed.message.len().div_ceil(64) + 16384)?;
        if let Some(size) = ec_size {
            if signed.signature.len() == size {
                if self.ecdsa(&signed.message, &signed.signature, alg, budget)? {
                    return Ok(());
                }
            } else {
                // Pinned Smallstep accepts the observed Apple client omission of
                // one leading R/S zero. Every candidate still verifies in full.
                let original = &signed.signature;
                let half = size / 2;
                let mut patched = [0u8; 132];
                if original.len() + 1 == size {
                    patched[1..size].copy_from_slice(original);
                    if self.ecdsa(&signed.message, &patched[..size], alg, budget)? {
                        return Ok(());
                    }
                    patched.fill(0);
                    patched[..half].copy_from_slice(&original[..half]);
                    patched[half + 1..size].copy_from_slice(&original[half..]);
                    if self.ecdsa(&signed.message, &patched[..size], alg, budget)? {
                        return Ok(());
                    }
                } else if original.len() + 2 == size {
                    patched[1..half].copy_from_slice(&original[..half - 1]);
                    patched[half + 1..size].copy_from_slice(&original[half - 1..]);
                    if self.ecdsa(&signed.message, &patched[..size], alg, budget)? {
                        return Ok(());
                    }
                }
            }
            return Err(Error::InvalidSignature);
        }
        let valid = if alg == Algorithm::EdDsa {
            if signed.signature.len() != 64 {
                return Err(Error::InvalidSignature);
            }
            let mut verifier = crypto(Verifier::new_without_digest(&self.key))?;
            crypto(verifier.verify_oneshot(&signed.signature, &signed.message))?
        } else {
            if signed.signature.len() != self.key.size() {
                return Err(Error::InvalidSignature);
            }
            let digest = alg.digest().ok_or(Error::BadAlgorithm)?;
            let mut verifier = crypto(Verifier::new(digest, &self.key))?;
            if matches!(alg, Algorithm::Ps256 | Algorithm::Ps384 | Algorithm::Ps512) {
                crypto(verifier.set_rsa_padding(Padding::PKCS1_PSS))?;
                crypto(verifier.set_rsa_mgf1_md(digest))?;
                crypto(verifier.set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH))?;
            } else {
                crypto(verifier.set_rsa_padding(Padding::PKCS1))?;
            }
            crypto(verifier.verify_oneshot(&signed.signature, &signed.message))?
        };
        budget.work(1)?;
        if valid {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }

    fn ecdsa(
        &self,
        message: &[u8],
        signature: &[u8],
        alg: Algorithm,
        budget: &mut impl Budget,
    ) -> Result<bool> {
        budget.work(16384)?;
        budget.charge(4096)?;
        let half = signature.len() / 2;
        let sig = crypto(EcdsaSig::from_private_components(
            crypto(BigNum::from_slice(&signature[..half]))?,
            crypto(BigNum::from_slice(&signature[half..]))?,
        ))?;
        let der = crypto(sig.to_der())?;
        let mut verifier = crypto(Verifier::new(
            alg.digest().ok_or(Error::BadAlgorithm)?,
            &self.key,
        ))?;
        let verified = crypto(verifier.verify_oneshot(&der, message))?;
        budget.work(1)?;
        Ok(verified)
    }
}
