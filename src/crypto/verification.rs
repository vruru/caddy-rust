//! Extra signature implementations used by the existing complete WebPKI path.
use openssl::{
    bn::BigNumContext,
    ec::{EcGroup, EcKey, EcPoint},
    nid::Nid,
    pkey::PKey,
    rsa::{Padding, Rsa},
    sign::{RsaPssSaltlen, Verifier},
};
use rsa::pkcs8::der::Decode;
use rustls::{
    SignatureScheme,
    crypto::WebPkiSupportedAlgorithms,
    pki_types::{AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm, alg_id},
};
use std::sync::LazyLock;
use webpki::aws_lc_rs as aws;

fn rsa_bits(key: &[u8]) -> Result<usize, InvalidSignature> {
    if key.len() > 2048 {
        return Err(InvalidSignature);
    }
    let parsed = rsa::pkcs1::RsaPublicKey::from_der(key).map_err(|_| InvalidSignature)?;
    let n = parsed.modulus.as_bytes();
    if n.is_empty() || n.len() > 1024 || parsed.public_exponent.as_bytes().len() > 8 {
        return Err(InvalidSignature);
    }
    let exponent = parsed
        .public_exponent
        .as_bytes()
        .iter()
        .fold(0u64, |acc, b| (acc << 8) | u64::from(*b));
    if exponent < 3 || exponent & 1 == 0 || n[n.len() - 1] & 1 == 0 {
        return Err(InvalidSignature);
    }
    let bits = n.len() * 8 - n[0].leading_zeros() as usize;
    if !(1024..=8192).contains(&bits) {
        return Err(InvalidSignature);
    }
    Ok(bits)
}
#[derive(Debug)]
struct RsaCompatible {
    inner: &'static dyn SignatureVerificationAlgorithm,
    scheme: SignatureScheme,
}
impl SignatureVerificationAlgorithm for RsaCompatible {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        self.inner.public_key_alg_id()
    }
    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        self.inner.signature_alg_id()
    }
    fn verify_signature(
        &self,
        key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        let bits = rsa_bits(key)?;
        if bits >= 2048 {
            return self.inner.verify_signature(key, message, signature);
        }
        if !super::legacy_sign::ready()
            || !super::legacy_sign::rsa_scheme(self.scheme, bits)
            || signature.len() != bits.div_ceil(8)
        {
            return Err(InvalidSignature);
        }
        let key =
            PKey::from_rsa(Rsa::public_key_from_der_pkcs1(key).map_err(|_| InvalidSignature)?)
                .map_err(|_| InvalidSignature)?;
        let digest = super::legacy_sign::digest(self.scheme).ok_or(InvalidSignature)?;
        let mut verifier = Verifier::new(digest, &key).map_err(|_| InvalidSignature)?;
        if matches!(
            self.scheme,
            SignatureScheme::RSA_PSS_SHA256
                | SignatureScheme::RSA_PSS_SHA384
                | SignatureScheme::RSA_PSS_SHA512
        ) {
            verifier
                .set_rsa_padding(Padding::PKCS1_PSS)
                .map_err(|_| InvalidSignature)?;
            verifier
                .set_rsa_mgf1_md(digest)
                .map_err(|_| InvalidSignature)?;
            verifier
                .set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)
                .map_err(|_| InvalidSignature)?;
        } else {
            verifier
                .set_rsa_padding(Padding::PKCS1)
                .map_err(|_| InvalidSignature)?;
        }
        verifier.update(message).map_err(|_| InvalidSignature)?;
        if verifier.verify(signature).map_err(|_| InvalidSignature)? {
            Ok(())
        } else {
            Err(InvalidSignature)
        }
    }
}
const P224_ID: AlgorithmIdentifier = AlgorithmIdentifier::from_slice(&[
    6, 7, 0x2a, 0x86, 0x48, 0xce, 0x3d, 2, 1, 6, 5, 0x2b, 0x81, 4, 0, 0x21,
]);
#[derive(Debug)]
struct P224 {
    signature_id: AlgorithmIdentifier,
    scheme: SignatureScheme,
}
impl SignatureVerificationAlgorithm for P224 {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        P224_ID
    }
    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        self.signature_id
    }
    fn verify_signature(
        &self,
        key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        if !super::legacy_sign::ready() || key.len() != 57 || key[0] != 4 {
            return Err(InvalidSignature);
        }
        // Canonical ASN.1 and nonzero/in-range r,s, independently of backend.
        p224::ecdsa::Signature::from_der(signature).map_err(|_| InvalidSignature)?;
        let group = EcGroup::from_curve_name(Nid::SECP224R1).map_err(|_| InvalidSignature)?;
        let mut context = BigNumContext::new().map_err(|_| InvalidSignature)?;
        let point = EcPoint::from_bytes(&group, key, &mut context).map_err(|_| InvalidSignature)?;
        let ec = EcKey::from_public_key(&group, &point).map_err(|_| InvalidSignature)?;
        ec.check_key().map_err(|_| InvalidSignature)?;
        let key = PKey::from_ec_key(ec).map_err(|_| InvalidSignature)?;
        let mut verifier = Verifier::new(
            super::legacy_sign::digest(self.scheme).ok_or(InvalidSignature)?,
            &key,
        )
        .map_err(|_| InvalidSignature)?;
        verifier.update(message).map_err(|_| InvalidSignature)?;
        if verifier.verify(signature).map_err(|_| InvalidSignature)? {
            Ok(())
        } else {
            Err(InvalidSignature)
        }
    }
}
static P224_256: P224 = P224 {
    signature_id: alg_id::ECDSA_SHA256,
    scheme: SignatureScheme::ECDSA_NISTP256_SHA256,
};
static P224_384: P224 = P224 {
    signature_id: alg_id::ECDSA_SHA384,
    scheme: SignatureScheme::ECDSA_NISTP384_SHA384,
};
static P224_512: P224 = P224 {
    signature_id: alg_id::ECDSA_SHA512,
    scheme: SignatureScheme::ECDSA_NISTP521_SHA512,
};
fn wrap_rsa(
    inner: &'static dyn SignatureVerificationAlgorithm,
) -> &'static dyn SignatureVerificationAlgorithm {
    if inner.public_key_alg_id() != alg_id::RSA_ENCRYPTION {
        return inner;
    }
    let id = inner.signature_alg_id();
    let mut found = None;
    for (expected, scheme, absent) in [
        (
            alg_id::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA256,
            false,
        ),
        (
            alg_id::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA384,
            false,
        ),
        (
            alg_id::RSA_PSS_SHA512,
            SignatureScheme::RSA_PSS_SHA512,
            false,
        ),
        (
            alg_id::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA256,
            true,
        ),
        (
            alg_id::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA384,
            true,
        ),
        (
            alg_id::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PKCS1_SHA512,
            true,
        ),
    ] {
        if id == expected
            || (absent && id.as_ref() == &expected.as_ref()[..expected.as_ref().len() - 2])
        {
            found = Some(scheme);
            break;
        }
    }
    found.map_or(inner, |scheme| {
        Box::leak(Box::new(RsaCompatible { inner, scheme }))
            as &'static dyn SignatureVerificationAlgorithm
    })
}
static ALGORITHMS: LazyLock<WebPkiSupportedAlgorithms> = LazyLock::new(|| {
    let base = rustls::crypto::ring::default_provider().signature_verification_algorithms;
    let mut all = base.all.iter().copied().map(wrap_rsa).collect::<Vec<_>>();
    all.extend_from_slice(&[
        aws::ECDSA_P256_SHA512,
        aws::ECDSA_P384_SHA512,
        aws::ECDSA_P521_SHA256,
        aws::ECDSA_P521_SHA384,
        aws::ECDSA_P521_SHA512,
        &P224_256,
        &P224_384,
        &P224_512,
    ]);
    let mut mapping = Vec::with_capacity(base.mapping.len() + 1);
    for (scheme, original) in base.mapping {
        let mut values = original.iter().copied().map(wrap_rsa).collect::<Vec<_>>();
        match scheme {
            SignatureScheme::ECDSA_NISTP256_SHA256 => {
                values.extend_from_slice(&[aws::ECDSA_P521_SHA256, &P224_256])
            }
            SignatureScheme::ECDSA_NISTP384_SHA384 => {
                values.extend_from_slice(&[aws::ECDSA_P521_SHA384, &P224_384])
            }
            _ => {}
        }
        mapping.push((
            *scheme,
            Box::leak(values.into_boxed_slice())
                as &'static [&'static dyn SignatureVerificationAlgorithm],
        ));
    }
    // TLS1.3 checks only the first entry. The remaining curves are TLS1.2
    // generic-hash candidates and cannot authorize a TLS1.3 P224 signature.
    mapping.push((
        SignatureScheme::ECDSA_NISTP521_SHA512,
        Box::leak(
            vec![
                aws::ECDSA_P521_SHA512,
                aws::ECDSA_P384_SHA512,
                aws::ECDSA_P256_SHA512,
                &P224_512,
            ]
            .into_boxed_slice(),
        ),
    ));
    WebPkiSupportedAlgorithms {
        all: Box::leak(all.into_boxed_slice()),
        mapping: Box::leak(mapping.into_boxed_slice()),
    }
});
pub(super) fn algorithms() -> WebPkiSupportedAlgorithms {
    *ALGORITHMS
}
