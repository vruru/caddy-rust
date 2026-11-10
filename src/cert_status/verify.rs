//! One DER interpretation; crypto libraries receive original TBS bytes only.
use super::{OcspState, VerifiedStatus};
use anyhow::{Result, anyhow, ensure};
use aws_lc_rs::signature as aws;
use der::{
    Decode, Encode,
    asn1::{Null, ObjectIdentifier, OctetString},
};
use rsa::{pkcs1::DecodeRsaPublicKey, pkcs1v15, signature::Verifier};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};
use x509_ocsp::{
    BasicOcspResponse, CertId, CertStatus, OcspRequest, OcspResponse, OcspResponseStatus, Request,
    ResponderId, TbsRequest, Version,
};
use x509_parser::{
    certificate::X509Certificate,
    extensions::{GeneralName, ParsedExtension},
    prelude::FromDer,
    x509::{AlgorithmIdentifier, SubjectPublicKeyInfo},
};

const SHA1_OID: &str = "1.3.14.3.2.26";
const BASIC_OID: &str = "1.3.6.1.5.5.7.48.1.1";
const SKEW: i64 = 300;

pub fn certificate(bytes: &[u8]) -> Result<X509Certificate<'_>> {
    let (rest, cert) =
        X509Certificate::from_der(bytes).map_err(|_| anyhow!("invalid OCSP certificate DER"))?;
    ensure!(rest.is_empty(), "trailing certificate DER");
    cert.extensions_map()
        .map_err(|_| anyhow!("duplicate certificate extensions"))?;
    ensure!(
        cert.signature_algorithm == cert.tbs_certificate.signature,
        "certificate signature algorithms disagree"
    );
    ensure!(
        cert.raw_serial().first().is_some_and(|b| b & 0x80 == 0),
        "negative certificate serial is not supported"
    );
    ensure!(
        cert.signature_value.unused_bits == 0
            && cert.public_key().subject_public_key.unused_bits == 0,
        "unaligned certificate signature or public key bit string"
    );
    Ok(cert)
}

pub fn must_staple(cert: &X509Certificate<'_>) -> Result<bool> {
    for extension in cert.extensions() {
        if extension.oid.to_id_string() == "1.3.6.1.5.5.7.1.24" {
            let features = <Vec<u64> as Decode>::from_der(extension.value)?;
            return Ok(features.contains(&5));
        }
    }
    Ok(false)
}

pub fn endpoints(leaf: &[u8]) -> Result<(Option<String>, Option<String>)> {
    let cert = certificate(leaf)?;
    let mut responder = None;
    let mut issuer = None;
    for extension in cert.extensions() {
        if let ParsedExtension::AuthorityInfoAccess(aia) = extension.parsed_extension() {
            for description in &aia.accessdescs {
                if let GeneralName::URI(value) = description.access_location {
                    match description.access_method.to_id_string().as_str() {
                        "1.3.6.1.5.5.7.48.1" if responder.is_none() => {
                            responder = Some(value.to_owned())
                        }
                        "1.3.6.1.5.5.7.48.2" if issuer.is_none() => issuer = Some(value.to_owned()),
                        _ => {}
                    }
                }
            }
        }
    }
    Ok((responder, issuer))
}

pub fn validate_issuer(leaf_der: &[u8], issuer_der: &[u8], now: i64) -> Result<()> {
    let leaf = certificate(leaf_der)?;
    let issuer = certificate(issuer_der)?;
    ensure!(
        leaf.issuer().as_raw() == issuer.subject().as_raw(),
        "OCSP issuer name does not match leaf"
    );
    ensure!(
        issuer.basic_constraints()?.is_some_and(|v| v.value.ca),
        "OCSP issuer is not a CA"
    );
    ensure!(
        issuer.key_usage()?.is_none_or(|v| v.value.key_cert_sign()),
        "OCSP issuer cannot sign certificates"
    );
    check_time(&issuer, now)?;
    check_time(&leaf, now)?;
    let mut aki = None;
    let mut ski = None;
    for extension in leaf.extensions() {
        if let ParsedExtension::AuthorityKeyIdentifier(value) = extension.parsed_extension() {
            aki = value.key_identifier.as_ref().map(|v| v.0);
        }
    }
    for extension in issuer.extensions() {
        if let ParsedExtension::SubjectKeyIdentifier(value) = extension.parsed_extension() {
            ski = Some(value.0);
        }
    }
    if let (Some(a), Some(s)) = (aki, ski) {
        ensure!(a == s, "OCSP issuer key identifier mismatch");
    }
    verify_signature(
        issuer.public_key(),
        &leaf.signature_algorithm,
        &leaf.signature_value.data,
        leaf.tbs_certificate.as_ref(),
        true,
    )?;
    Ok(())
}

pub fn request(leaf_der: &[u8], issuer_der: &[u8]) -> Result<Vec<u8>> {
    let leaf = certificate(leaf_der)?;
    let issuer = certificate(issuer_der)?;
    let cert_id = CertId {
        hash_algorithm: rsa::pkcs8::spki::AlgorithmIdentifierOwned {
            oid: ObjectIdentifier::new(SHA1_OID)?,
            parameters: Some(Null.into()),
        },
        issuer_name_hash: OctetString::new(Sha1::digest(issuer.subject().as_raw()).to_vec())?,
        issuer_key_hash: OctetString::new(
            Sha1::digest(&issuer.public_key().subject_public_key.data).to_vec(),
        )?,
        serial_number: x509_cert::serial_number::SerialNumber::from_der(
            &der::asn1::Uint::new(unsigned(leaf.raw_serial()))?.to_der()?,
        )?,
    };
    Ok(OcspRequest {
        tbs_request: TbsRequest {
            request_list: vec![Request {
                req_cert: cert_id,
                single_request_extensions: None,
            }],
            ..TbsRequest::default()
        },
        optional_signature: None,
    }
    .to_der()?)
}

pub fn verify_response(
    raw: &[u8],
    leaf_der: &[u8],
    issuer_der: &[u8],
    now: i64,
) -> Result<VerifiedStatus> {
    verify_response_with_max_age(
        raw,
        leaf_der,
        issuer_der,
        now,
        std::time::Duration::from_secs(86400),
    )
}

pub fn verify_response_with_max_age(
    raw: &[u8],
    leaf_der: &[u8],
    issuer_der: &[u8],
    now: i64,
    max_age: std::time::Duration,
) -> Result<VerifiedStatus> {
    ensure!(
        !raw.is_empty() && raw.len() <= 1024 * 1024,
        "OCSP response length invalid"
    );
    validate_issuer(leaf_der, issuer_der, now)?;
    let leaf = certificate(leaf_der)?;
    let issuer = certificate(issuer_der)?;
    let outer = OcspResponse::from_der(raw)?;
    ensure!(outer.to_der()? == raw, "non-canonical OCSP DER");
    ensure!(
        outer.response_status == OcspResponseStatus::Successful,
        "OCSP responder status is unsuccessful"
    );
    let response = outer
        .response_bytes
        .ok_or_else(|| anyhow!("missing OCSP response body"))?;
    ensure!(
        response.response_type.to_string() == BASIC_OID,
        "unsupported OCSP response type"
    );
    let basic_raw = response.response.as_bytes();
    let basic = BasicOcspResponse::from_der(basic_raw)?;
    ensure!(basic.to_der()? == basic_raw, "non-canonical basic OCSP DER");
    let data = &basic.tbs_response_data;
    ensure!(
        data.version == Version::default(),
        "unsupported OCSP version"
    );
    ensure!(
        data.responses.len() == 1,
        "OCSP response must contain exactly one certificate status"
    );
    reject_critical(data.response_extensions.as_deref())?;
    let single = &data.responses[0];
    reject_critical(single.single_extensions.as_deref())?;
    ensure!(
        single
            .cert_id
            .hash_algorithm
            .parameters
            .as_ref()
            .is_none_or(|p| p == &Null.into()),
        "invalid OCSP hash algorithm parameters"
    );
    let serial_encoding = single.cert_id.serial_number.to_der()?;
    let (serial_header, _) = tlv(&serial_encoding)?;
    ensure!(
        serial_encoding[serial_header] & 0x80 == 0,
        "negative OCSP serial is not supported"
    );
    let hash = single.cert_id.hash_algorithm.oid.to_string();
    ensure!(
        single.cert_id.issuer_name_hash.as_bytes() == hash_bytes(&hash, issuer.subject().as_raw())?,
        "OCSP issuer name hash mismatch"
    );
    ensure!(
        single.cert_id.issuer_key_hash.as_bytes()
            == hash_bytes(&hash, &issuer.public_key().subject_public_key.data)?,
        "OCSP issuer key hash mismatch"
    );
    ensure!(
        unsigned(single.cert_id.serial_number.as_bytes()) == unsigned(leaf.raw_serial()),
        "OCSP leaf serial mismatch"
    );
    let responder_der = basic
        .certs
        .as_ref()
        .and_then(|v| v.first())
        .map(Encode::to_der)
        .transpose()?;
    let responder = match responder_der.as_ref() {
        Some(v) => certificate(v)?,
        None => issuer.clone(),
    };
    let delegated = responder.as_raw() != issuer.as_raw();
    check_time(&responder, now)?;
    if delegated {
        ensure!(
            responder.issuer().as_raw() == issuer.subject().as_raw(),
            "OCSP delegated responder issuer mismatch"
        );
        ensure!(
            responder
                .extended_key_usage()?
                .is_some_and(|v| v.value.ocsp_signing),
            "OCSP delegated responder lacks signing EKU"
        );
        ensure!(
            responder
                .key_usage()?
                .is_none_or(|v| v.value.digital_signature()),
            "OCSP delegated responder cannot sign"
        );
        for extension in responder.extensions() {
            ensure!(
                !extension.critical
                    || (!extension.parsed_extension().unsupported()
                        && extension.parsed_extension().error().is_none()
                        && !matches!(extension.parsed_extension(), ParsedExtension::Unparsed)),
                "unknown critical responder certificate extension"
            );
        }
        verify_signature(
            issuer.public_key(),
            &responder.signature_algorithm,
            &responder.signature_value.data,
            responder.tbs_certificate.as_ref(),
            true,
        )?;
    }
    match &data.responder_id {
        ResponderId::ByName(name) => ensure!(
            name.to_der()? == responder.subject().as_raw(),
            "OCSP responder name mismatch"
        ),
        ResponderId::ByKey(key) => ensure!(
            key.as_bytes() == &Sha1::digest(&responder.public_key().subject_public_key.data)[..],
            "OCSP responder key hash mismatch"
        ),
    }
    let alg_bytes = basic.signature_algorithm.to_der()?;
    let (rest, algorithm) = AlgorithmIdentifier::from_der(&alg_bytes)
        .map_err(|_| anyhow!("invalid OCSP signature algorithm"))?;
    ensure!(rest.is_empty(), "trailing OCSP signature algorithm");
    verify_signature(
        responder.public_key(),
        &algorithm,
        basic
            .signature
            .as_bytes()
            .ok_or_else(|| anyhow!("invalid OCSP signature bit string"))?,
        original_tbs(basic_raw)?,
        false,
    )?;
    let this_update = unix(single.this_update.0.to_unix_duration().as_secs())?;
    let produced_at = unix(data.produced_at.0.to_unix_duration().as_secs())?;
    let next_update = single
        .next_update
        .map(|v| unix(v.0.to_unix_duration().as_secs()))
        .transpose()?;
    ensure!(
        (std::time::Duration::from_secs(1)..=std::time::Duration::from_secs(31 * 86400))
            .contains(&max_age),
        "invalid no-nextUpdate OCSP maximum age"
    );
    ensure!(
        this_update <= now.saturating_add(SKEW) && produced_at <= now.saturating_add(SKEW),
        "OCSP response is from the future"
    );
    ensure!(
        produced_at >= this_update.saturating_sub(SKEW),
        "OCSP producedAt predates thisUpdate"
    );
    if let Some(next) = next_update {
        ensure!(
            next > this_update && next <= leaf.validity().not_after.timestamp(),
            "invalid OCSP nextUpdate interval"
        );
    }
    let effective_next =
        next_update.unwrap_or_else(|| this_update.saturating_add(max_age.as_secs() as i64));
    let valid_until = effective_next
        .min(responder.validity().not_after.timestamp())
        .min(leaf.validity().not_after.timestamp());
    ensure!(
        valid_until > now,
        "OCSP response or responder certificate expired"
    );
    let legacy_signature = is_sha1_oid(&algorithm.algorithm.to_id_string())
        || algorithm
            .parameters
            .as_ref()
            .is_some_and(|v| v.tag().0 == 5)
            && algorithm
                .algorithm
                .to_id_string()
                .starts_with("1.2.840.10045.4")
        || is_sha1_oid(&responder.signature_algorithm.algorithm.to_id_string())
        || responder
            .public_key()
            .algorithm
            .parameters
            .as_ref()
            .and_then(|p| p.as_oid().ok())
            .is_some_and(|o| o.to_id_string() == "1.3.132.0.33");
    let (state, revoked_at, revocation_reason) = match &single.cert_status {
        CertStatus::Good(_) => (OcspState::Good, None, None),
        CertStatus::Unknown(_) => (OcspState::Unknown, None, None),
        CertStatus::Revoked(info) => {
            let at = unix(info.revocation_time.0.to_unix_duration().as_secs())?;
            ensure!(
                at <= produced_at.saturating_add(SKEW),
                "OCSP revocation time is in the future"
            );
            (
                OcspState::Revoked,
                Some(at),
                info.revocation_reason.map(|r| r as u8),
            )
        }
    };
    Ok(VerifiedStatus {
        state,
        this_update,
        next_update,
        legacy_signature,
        produced_at,
        valid_until,
        refresh_at: this_update + (valid_until - this_update) / 2,
        revoked_at,
        revocation_reason,
    })
}

fn reject_critical(extensions: Option<&[x509_cert::ext::Extension]>) -> Result<()> {
    ensure!(
        extensions.is_none_or(|v| v.iter().all(|e| !e.critical)),
        "unsupported critical OCSP extension"
    );
    Ok(())
}
fn check_time(cert: &X509Certificate<'_>, now: i64) -> Result<()> {
    ensure!(
        cert.validity().not_before.timestamp() <= now
            && now < cert.validity().not_after.timestamp(),
        "OCSP certificate is outside its validity interval"
    );
    Ok(())
}
fn unsigned(bytes: &[u8]) -> &[u8] {
    let position = bytes
        .iter()
        .position(|b| *b != 0)
        .unwrap_or(bytes.len().saturating_sub(1));
    &bytes[position..]
}
fn unix(value: u64) -> Result<i64> {
    i64::try_from(value).map_err(|_| anyhow!("OCSP time overflow"))
}
fn hash_bytes(oid: &str, bytes: &[u8]) -> Result<Vec<u8>> {
    Ok(match oid {
        SHA1_OID => Sha1::digest(bytes).to_vec(),
        "2.16.840.1.101.3.4.2.1" => Sha256::digest(bytes).to_vec(),
        "2.16.840.1.101.3.4.2.2" => Sha384::digest(bytes).to_vec(),
        "2.16.840.1.101.3.4.2.3" => Sha512::digest(bytes).to_vec(),
        _ => return Err(anyhow!("unsupported OCSP CertID hash")),
    })
}
fn original_tbs(basic: &[u8]) -> Result<&[u8]> {
    let (header, total) = tlv(basic)?;
    ensure!(
        basic[0] == 0x30 && total == basic.len(),
        "invalid OCSP basic sequence"
    );
    let inner = &basic[header..];
    let (_, length) = tlv(inner)?;
    ensure!(inner[0] == 0x30, "invalid OCSP TBS sequence");
    Ok(&inner[..length])
}
fn tlv(bytes: &[u8]) -> Result<(usize, usize)> {
    ensure!(bytes.len() >= 2, "short DER");
    let n = bytes[1];
    let (header, length) = if n < 128 {
        (2, n as usize)
    } else {
        let count = (n & 127) as usize;
        ensure!(
            (1..=4).contains(&count) && bytes.len() >= 2 + count,
            "invalid DER length"
        );
        let length = bytes[2..2 + count]
            .iter()
            .fold(0usize, |v, b| (v << 8) | (*b as usize));
        (2 + count, length)
    };
    let total = header
        .checked_add(length)
        .ok_or_else(|| anyhow!("DER length overflow"))?;
    ensure!(total <= bytes.len(), "truncated DER");
    Ok((header, total))
}

fn verify_signature(
    key: &SubjectPublicKeyInfo<'_>,
    algorithm: &AlgorithmIdentifier<'_>,
    signature: &[u8],
    message: &[u8],
    certificate_signature: bool,
) -> Result<()> {
    let oid = algorithm.algorithm.to_id_string();
    let key_oid = key.algorithm.algorithm.to_id_string();
    let null_params = algorithm
        .parameters
        .as_ref()
        .is_none_or(|v| v.tag().0 == 5 && v.data.is_empty());
    if matches!(
        oid.as_str(),
        "1.2.840.113549.1.1.5"
            | "1.3.14.3.2.29"
            | "1.2.840.113549.1.1.11"
            | "1.2.840.113549.1.1.12"
            | "1.2.840.113549.1.1.13"
    ) {
        ensure!(
            key_oid == "1.2.840.113549.1.1.1" && null_params,
            "invalid RSA signature key or parameters"
        );
        let public = rsa::RsaPublicKey::from_pkcs1_der(&key.subject_public_key.data)?;
        use rsa::traits::PublicKeyParts;
        ensure!(
            (1024..=8192).contains(&public.n().bits()),
            "OCSP RSA key size out of range"
        );
        let sig = pkcs1v15::Signature::try_from(signature)?;
        let valid = match oid.as_str() {
            "1.2.840.113549.1.1.5" | "1.3.14.3.2.29" => {
                pkcs1v15::VerifyingKey::<Sha1>::new(public).verify(message, &sig)
            }
            "1.2.840.113549.1.1.11" => {
                pkcs1v15::VerifyingKey::<Sha256>::new(public).verify(message, &sig)
            }
            "1.2.840.113549.1.1.12" => {
                pkcs1v15::VerifyingKey::<Sha384>::new(public).verify(message, &sig)
            }
            _ => pkcs1v15::VerifyingKey::<Sha512>::new(public).verify(message, &sig),
        };
        return valid.map_err(|_| anyhow!("OCSP RSA signature verification failed"));
    }
    if certificate_signature && oid == "1.2.840.113549.1.1.10" {
        ensure!(
            key_oid == "1.2.840.113549.1.1.1",
            "invalid PSS certificate key"
        );
        let parameters = algorithm
            .parameters
            .as_ref()
            .ok_or_else(|| anyhow!("missing PSS parameters"))?;
        ensure!(parameters.tag().0 == 16, "invalid PSS parameter sequence");
        let encoded = der::asn1::AnyRef::new(der::Tag::Sequence, parameters.data)?.to_der()?;
        let params = <rsa::pkcs1::RsaPssParams<'_> as Decode>::from_der(&encoded)?;
        ensure!(params.to_der()? == encoded, "non-canonical PSS parameters");
        ensure!(
            params.mask_gen.oid.to_string() == "1.2.840.113549.1.1.8",
            "invalid PSS MGF"
        );
        let mgf = params
            .mask_gen
            .parameters
            .ok_or_else(|| anyhow!("missing PSS MGF hash"))?;
        ensure!(
            mgf.oid == params.hash.oid,
            "PSS MGF hash differs from signature hash"
        );
        ensure!(
            params
                .hash
                .parameters
                .is_none_or(|p| p == der::asn1::AnyRef::NULL)
                && mgf.parameters.is_none_or(|p| p == der::asn1::AnyRef::NULL),
            "invalid PSS hash parameters"
        );
        let public = rsa::RsaPublicKey::from_pkcs1_der(&key.subject_public_key.data)?;
        use rsa::traits::PublicKeyParts;
        ensure!(
            (1024..=8192).contains(&public.n().bits()),
            "OCSP RSA key size out of range"
        );
        let sig = rsa::pss::Signature::try_from(signature)?;
        let valid = match params.hash.oid.to_string().as_str() {
            "2.16.840.1.101.3.4.2.1" => {
                ensure!(params.salt_len == 32, "invalid PSS SHA256 salt length");
                rsa::pss::VerifyingKey::<Sha256>::new_with_salt_len(public, 32)
                    .verify(message, &sig)
            }
            "2.16.840.1.101.3.4.2.2" => {
                ensure!(params.salt_len == 48, "invalid PSS SHA384 salt length");
                rsa::pss::VerifyingKey::<Sha384>::new_with_salt_len(public, 48)
                    .verify(message, &sig)
            }
            "2.16.840.1.101.3.4.2.3" => {
                ensure!(params.salt_len == 64, "invalid PSS SHA512 salt length");
                rsa::pss::VerifyingKey::<Sha512>::new_with_salt_len(public, 64)
                    .verify(message, &sig)
            }
            _ => return Err(anyhow!("unsupported PSS certificate hash")),
        };
        return valid.map_err(|_| anyhow!("PSS certificate signature verification failed"));
    }
    let verifier: &dyn aws::VerificationAlgorithm = match oid.as_str() {
        "1.2.840.10045.4.1"
        | "1.2.840.10045.4.3.2"
        | "1.2.840.10045.4.3.3"
        | "1.2.840.10045.4.3.4" => {
            ensure!(
                key_oid == "1.2.840.10045.2.1" && null_params,
                "invalid ECDSA signature key or parameters"
            );
            let curve = key
                .algorithm
                .parameters
                .as_ref()
                .ok_or_else(|| anyhow!("missing EC named curve"))?
                .as_oid()
                .map_err(|_| anyhow!("invalid EC named curve"))?
                .to_id_string();
            if curve == "1.3.132.0.33" {
                use p224::ecdsa::signature::hazmat::PrehashVerifier;
                let public =
                    p224::ecdsa::VerifyingKey::from_sec1_bytes(&key.subject_public_key.data)?;
                let sig = p224::ecdsa::Signature::from_der(signature)?;
                let digest = match oid.as_str() {
                    "1.2.840.10045.4.1" => Sha1::digest(message).to_vec(),
                    "1.2.840.10045.4.3.2" => Sha256::digest(message).to_vec(),
                    "1.2.840.10045.4.3.3" => Sha384::digest(message).to_vec(),
                    _ => Sha512::digest(message).to_vec(),
                };
                return public
                    .verify_prehash(&digest, &sig)
                    .map_err(|_| anyhow!("OCSP P224 signature verification failed"));
            }
            match (curve.as_str(), oid.as_str()) {
                ("1.2.840.10045.3.1.7", "1.2.840.10045.4.1") => &aws::ECDSA_P256_SHA1_ASN1,
                ("1.2.840.10045.3.1.7", "1.2.840.10045.4.3.2") => &aws::ECDSA_P256_SHA256_ASN1,
                ("1.2.840.10045.3.1.7", "1.2.840.10045.4.3.3") => &aws::ECDSA_P256_SHA384_ASN1,
                ("1.2.840.10045.3.1.7", "1.2.840.10045.4.3.4") => &aws::ECDSA_P256_SHA512_ASN1,
                ("1.3.132.0.34", "1.2.840.10045.4.1") => {
                    use p384::ecdsa::signature::hazmat::PrehashVerifier;
                    let public =
                        p384::ecdsa::VerifyingKey::from_sec1_bytes(&key.subject_public_key.data)?;
                    let sig = p384::ecdsa::Signature::from_der(signature)?;
                    let mut digest = [0u8; 48];
                    digest[28..].copy_from_slice(&Sha1::digest(message));
                    return public
                        .verify_prehash(&digest, &sig)
                        .map_err(|_| anyhow!("OCSP ECDSA SHA1 signature verification failed"));
                }
                ("1.3.132.0.34", "1.2.840.10045.4.3.2") => &aws::ECDSA_P384_SHA256_ASN1,
                ("1.3.132.0.34", "1.2.840.10045.4.3.3") => &aws::ECDSA_P384_SHA384_ASN1,
                ("1.3.132.0.34", "1.2.840.10045.4.3.4") => &aws::ECDSA_P384_SHA512_ASN1,
                ("1.3.132.0.35", "1.2.840.10045.4.1") => &aws::ECDSA_P521_SHA1_ASN1,
                ("1.3.132.0.35", "1.2.840.10045.4.3.2") => &aws::ECDSA_P521_SHA256_ASN1,
                ("1.3.132.0.35", "1.2.840.10045.4.3.3") => &aws::ECDSA_P521_SHA384_ASN1,
                ("1.3.132.0.35", "1.2.840.10045.4.3.4") => &aws::ECDSA_P521_SHA512_ASN1,
                _ => return Err(anyhow!("unsupported OCSP EC curve or hash")),
            }
        }
        "1.3.101.112" if certificate_signature => {
            ensure!(
                key_oid == "1.3.101.112" && algorithm.parameters.is_none(),
                "invalid Ed25519 certificate signature parameters"
            );
            &aws::ED25519
        }
        _ => return Err(anyhow!("unsupported OCSP signature algorithm")),
    };
    aws::UnparsedPublicKey::new(verifier, &key.subject_public_key.data)
        .verify(message, signature)
        .map_err(|_| anyhow!("OCSP signature verification failed"))
}

fn is_sha1_oid(oid: &str) -> bool {
    matches!(
        oid,
        "1.2.840.113549.1.1.5" | "1.3.14.3.2.29" | "1.2.840.10045.4.1"
    )
}
