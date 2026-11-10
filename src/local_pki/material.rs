use super::{
    raw_der,
    signer::{CaSigner, SubjectKey},
};
use anyhow::{Result, anyhow, ensure};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use der::{Decode, Encode};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, IsCa, KeyIdMethod, KeyUsagePurpose, PublicKeyData,
};
use sha1::{Digest, Sha1};
use std::{collections::HashSet, time::Duration};
use time::OffsetDateTime;
use x509_parser::{extensions::ParsedExtension, prelude::FromDer};
use zeroize::Zeroizing;

#[derive(Clone)]
pub(super) struct Pair {
    pub chain_pem: Vec<u8>,
    pub private_key_pem: Option<Zeroizing<Vec<u8>>>,
    /// Set only by explicit root configuration, never decoded from a journal.
    pub explicit_anchor: bool,
}

pub(super) fn chain(bytes: &[u8]) -> Result<Vec<Vec<u8>>> {
    ensure!(bytes.len() <= 1024 * 1024, "CA chain size limit exceeded");
    let blocks = crate::certmagic::pem_blocks(bytes, "local-pki")?;
    ensure!(
        !blocks.is_empty() && blocks.len() <= 16,
        "invalid CA chain length"
    );
    blocks
        .into_iter()
        .map(|(label, bytes)| {
            ensure!(
                label == "CERTIFICATE" && bytes.len() <= 128 * 1024,
                "invalid CA certificate PEM"
            );
            let (tail, certificate) = x509_parser::parse_x509_certificate(&bytes)
                .map_err(|_| anyhow!("invalid CA certificate DER"))?;
            ensure!(tail.is_empty(), "trailing CA certificate bytes");
            ensure!(
                certificate.signature_value.unused_bits == 0
                    && certificate.public_key().subject_public_key.unused_bits == 0,
                "invalid CA signature/public key bit string"
            );
            ensure!(certificate_syntax(&bytes).is_ok(), "non-canonical CA DER");
            ensure!(
                certificate.signature_algorithm == certificate.tbs_certificate.signature,
                "CA signature algorithm mismatch"
            );
            let mut oids = HashSet::new();
            for extension in certificate.extensions() {
                ensure!(
                    oids.insert(extension.oid.to_id_string()),
                    "duplicate CA extension"
                );
            }
            Ok(bytes.to_vec())
        })
        .collect()
}

/// Caddy's configured root KeyPair.Load parses a bundle but uses its first
/// certificate as the explicit trust anchor. Extra certificates are not an
/// automatically trusted issuer path for that anchor. Never rewrite the file.
pub(super) fn configured_anchor(mut pair: Pair) -> Result<Pair> {
    pair.explicit_anchor = true;
    let certificates = chain(&pair.chain_pem)?;
    if certificates.len() > 1 {
        pair.chain_pem =
            pem::encode(&pem::Pem::new("CERTIFICATE", certificates[0].clone())).into_bytes();
    }
    Ok(pair)
}

pub(super) fn validity(pair: &Pair) -> Result<(i64, i64)> {
    let chain = chain(&pair.chain_pem)?;
    let (_, cert) = x509_parser::parse_x509_certificate(&chain[0])
        .map_err(|_| anyhow!("invalid CA certificate"))?;
    Ok((
        cert.validity().not_before.timestamp(),
        cert.validity().not_after.timestamp(),
    ))
}

pub(super) fn validate(
    pair: &Pair,
    issuer: Option<&Pair>,
    now: i64,
    allow_expired: bool,
) -> Result<()> {
    let mut certs = chain(&pair.chain_pem)?;
    if let Some(key) = &pair.private_key_pem {
        ensure!(
            key.len() <= 128 * 1024,
            "CA private key size limit exceeded"
        );
        CaSigner::from_pem(key, &certs[0])?;
    }
    if let Some(issuer) = issuer {
        let roots = chain(&issuer.chain_pem)?;
        if certs.last() != roots.first() {
            certs.extend(roots);
        }
    }
    for (index, bytes) in certs.iter().enumerate() {
        let (_, cert) = x509_parser::parse_x509_certificate(bytes)
            .map_err(|_| anyhow!("invalid CA certificate"))?;
        ensure!(
            cert.validity().not_before.timestamp() <= now,
            "CA certificate not yet valid"
        );
        ensure!(
            allow_expired || cert.validity().not_after.timestamp() > now,
            "CA certificate expired"
        );
        let bc = cert
            .basic_constraints()?
            .ok_or_else(|| anyhow!("CA basic constraints missing"))?;
        ensure!(bc.value.ca, "issuer certificate is not a CA");
        if let Some(usage) = cert.key_usage()? {
            ensure!(usage.value.key_cert_sign(), "CA cannot sign certificates");
        }
        if let Some(max) = bc.value.path_len_constraint {
            ensure!(index <= max as usize, "CA path length exceeded");
        }
        if index + 1 < certs.len() {
            ensure!(
                !matches!(
                    cert.signature_algorithm.algorithm.to_id_string().as_str(),
                    "1.2.840.113549.1.1.5" | "1.3.14.3.2.29" | "1.2.840.10045.4.1"
                ),
                "SHA1 CA chain signature is not trusted"
            );
            let (_, parent) = x509_parser::parse_x509_certificate(&certs[index + 1])
                .map_err(|_| anyhow!("invalid parent CA"))?;
            ensure!(
                cert.issuer().as_raw() == parent.subject().as_raw(),
                "CA issuer name mismatch"
            );
            crate::cert_status::verify_x509_signature(
                parent.public_key(),
                &cert.signature_algorithm,
                &cert.signature_value.data,
                cert.tbs_certificate.as_ref(),
                true,
            )
            .map_err(|_| anyhow!("invalid CA chain signature"))?;
            // The supplied parent already passed raw issuer-name and actual
            // signature verification above. AKI/SKI are path-building hints,
            // not a reason to reject an otherwise valid configured chain.
        } else {
            // Explicit trust anchors may be cross-signed, including a key
            // rollover with the same issuer/subject Name. Their certificate
            // self-signature is not a trust criterion (RFC 5280 trust input).
            if issuer.map_or(pair.explicit_anchor, |parent| parent.explicit_anchor) {
                continue;
            }
            ensure!(
                cert.issuer().as_raw() == cert.subject().as_raw(),
                "generated/stored root is not self-issued"
            );
            crate::cert_status::verify_x509_signature(
                cert.public_key(),
                &cert.signature_algorithm,
                &cert.signature_value.data,
                cert.tbs_certificate.as_ref(),
                true,
            )
            .map_err(|_| anyhow!("invalid root signature"))?;
        }
    }
    Ok(())
}

pub(super) fn has_name_constraints(pair: &Pair) -> Result<bool> {
    for bytes in chain(&pair.chain_pem)? {
        let (_, cert) = x509_parser::parse_x509_certificate(&bytes)
            .map_err(|_| anyhow!("invalid constrained CA"))?;
        if cert
            .extensions()
            .iter()
            .any(|extension| extension.oid.to_id_string() == "2.5.29.30")
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn serial() -> Result<rcgen::SerialNumber> {
    let mut bytes = [0u8; 20];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| anyhow!("certificate entropy unavailable"))?;
    bytes[0] &= 0x7f;
    bytes[0] |= 1;
    Ok(bytes.to_vec().into())
}

fn parameters(name: &str, now: i64, lifetime: Duration, pathlen: u8) -> Result<CertificateParams> {
    ensure!(
        name.len() <= 4096 && !name.contains('\0'),
        "invalid CA common name"
    );
    let mut params = CertificateParams::default();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, name);
    params.not_before = OffsetDateTime::from_unix_timestamp(now)?;
    params.not_after = OffsetDateTime::from_unix_timestamp(
        now.checked_add(i64::try_from(lifetime.as_secs())?)
            .ok_or_else(|| anyhow!("CA lifetime overflow"))?,
    )?;
    params.serial_number = Some(serial()?);
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(pathlen));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    Ok(params)
}

pub(super) fn new_root(name: &str, now: i64) -> Result<Pair> {
    let key = rcgen::KeyPair::generate()?;
    let mut params = parameters(name, now, Duration::from_secs(3600 * 86400), 1)?;
    params.key_identifier_method =
        KeyIdMethod::PreSpecified(Sha1::digest(key.der_bytes()).to_vec());
    let cert = params.self_signed(&key)?;
    Ok(Pair {
        explicit_anchor: false,
        chain_pem: cert.pem().into_bytes(),
        private_key_pem: Some(Zeroizing::new(key.serialize_pem().into_bytes())),
    })
}

fn issuer(pair: &Pair) -> Result<(rcgen::Issuer<'static, CaSigner>, Vec<u8>)> {
    let certs = chain(&pair.chain_pem)?;
    let signer = CaSigner::from_pem(
        pair.private_key_pem
            .as_ref()
            .ok_or_else(|| anyhow!("CA signing key missing"))?,
        &certs[0],
    )?;
    let (_, cert) =
        x509_parser::parse_x509_certificate(&certs[0]).map_err(|_| anyhow!("invalid CA"))?;
    let key_id = cert
        .extensions()
        .iter()
        .find_map(|ext| match ext.parsed_extension() {
            ParsedExtension::SubjectKeyIdentifier(value) => Some(value.0.to_vec()),
            _ => None,
        })
        .unwrap_or_else(|| Sha1::digest(signer.der_bytes()).to_vec());
    let mut params = CertificateParams::default();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.key_identifier_method = KeyIdMethod::PreSpecified(key_id);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    Ok((rcgen::Issuer::new(params, signer), certs[0].clone()))
}

/// Rcgen's Name model cannot represent multi-valued/repeated RDNs. Preserve
/// the original ASN.1 names, then sign that exact final TBS, rather than
/// treating a re-encoded approximation of an imported issuer as its identity.
fn certificate_syntax(bytes: &[u8]) -> Result<()> {
    raw_der::validate(bytes)?;
    let outer = raw_der::parts(bytes, 0x30)?;
    ensure!(outer.len() == 3, "invalid certificate fields");
    let (mut fields, base) = raw_der::tbs_fields(outer[0])?;
    // Only Name is opaque. Preserve all previous typed canonical checks on
    // version, serial, algorithms, dates, SPKI, unique IDs and extensions.
    fields[base + 2] = b"\x30\x00";
    fields[base + 4] = b"\x30\x00";
    let tbs = raw_der::wrap(0x30, &fields.concat());
    let replacement = raw_der::wrap(0x30, &[tbs.as_slice(), outer[1], outer[2]].concat());
    ensure!(
        x509_cert::Certificate::from_der(&replacement)?.to_der()? == replacement,
        "noncanonical certificate fields"
    );
    Ok(())
}
fn csr_syntax(bytes: &[u8]) -> Result<()> {
    raw_der::validate(bytes)?;
    let outer = raw_der::parts(bytes, 0x30)?;
    ensure!(outer.len() == 3, "invalid CSR fields");
    let mut info = raw_der::parts(outer[0], 0x30)?;
    ensure!(
        info.len() == 4 && info[0] == b"\x02\x01\x00" && info[2][0] == 0x30 && info[3][0] == 0xa0,
        "invalid CSR fields"
    );
    raw_der::csr_name(info[1])?;
    info[1] = b"\x30\x00";
    let info = raw_der::wrap(0x30, &info.concat());
    let replacement = raw_der::wrap(0x30, &[info.as_slice(), outer[1], outer[2]].concat());
    ensure!(
        x509_cert::request::CertReq::from_der(&replacement)?.to_der()? == replacement,
        "noncanonical CSR fields"
    );
    Ok(())
}
fn p224_template_spki(template: &[u8], actual: &[u8]) -> Result<()> {
    raw_der::validate(template)?;
    raw_der::validate(actual)?;
    let template_fields = raw_der::parts(template, 0x30)?;
    let actual_fields = raw_der::parts(actual, 0x30)?;
    const P224_ALGORITHM: &[u8] = &[
        0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81,
        0x04, 0x00, 0x21,
    ];
    const P256_ALGORITHM: &[u8] = &[
        0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86,
        0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
    ];
    ensure!(
        template_fields.len() == 2
            && actual_fields.len() == 2
            && template_fields[0] == P256_ALGORITHM
            && actual_fields[0] == P224_ALGORITHM,
        "unexpected rcgen SPKI algorithm mismatch"
    );
    let template_bits = der::asn1::BitString::from_der(template_fields[1])?;
    let actual_bits = der::asn1::BitString::from_der(actual_fields[1])?;
    ensure!(
        template_bits.unused_bits() == 0
            && actual_bits.unused_bits() == 0
            && actual_bits.raw_bytes().len() == 57
            && actual_bits.raw_bytes()[0] == 4
            && template_bits.raw_bytes() == actual_bits.raw_bytes(),
        "rcgen P224 template public key mismatch"
    );
    Ok(())
}

fn bind_names(
    cert: &[u8],
    issuer_der: &[u8],
    subject: Option<(&[u8], &[u8])>,
    signer: &CaSigner,
) -> Result<Vec<u8>> {
    certificate_syntax(cert)?;
    let outer = raw_der::parts(cert, 0x30)?;
    let (mut fields, base) = raw_der::tbs_fields(outer[0])?;
    ensure!(
        base == 1 && fields.len() == 8 && fields[7][0] == 0xa3,
        "unexpected generated certificate layout"
    );
    let (tail, parent) = x509_parser::parse_x509_certificate(issuer_der)
        .map_err(|_| anyhow!("invalid issuer DER"))?;
    ensure!(tail.is_empty(), "trailing issuer DER");
    let parent_has_ski = parent
        .extensions()
        .iter()
        .any(|e| e.oid.to_id_string() == "2.5.29.14");
    fields[base + 2] = parent.subject().as_raw();
    if let Some((name, spki)) = subject {
        raw_der::csr_name(name)?;
        fields[base + 4] = name;
        if fields[base + 5] != spki {
            // rcgen 0.14 has no P224 SignatureAlgorithm. It serializes a P256
            // curve OID despite our PublicKeyData override, while its key-ID
            // input is the original SPKI. Permit only this exact layout gap.
            p224_template_spki(fields[base + 5], spki)?;
            fields[base + 5] = spki;
        }
    }
    let explicit = raw_der::parts(fields[7], 0xa3)?;
    ensure!(explicit.len() == 1, "invalid generated extensions");
    let mut encoded_extensions = Vec::new();
    let mut has_san = false;
    for encoded in raw_der::parts(explicit[0], 0x30)? {
        let mut ext = x509_cert::ext::Extension::from_der(encoded)?;
        ensure!(ext.to_der()? == encoded, "noncanonical generated extension");
        let oid = ext.extn_id.to_string();
        // rcgen NoCa must not emit SKI. Expose a future template change rather
        // than silently accepting a key identifier bound to another layout.
        ensure!(
            !(subject.is_some() && oid == "2.5.29.14"),
            "unexpected leaf SKI"
        );
        if !parent_has_ski && oid == "2.5.29.35" {
            continue;
        }
        if oid == "2.5.29.17" {
            has_san = true;
            ext.critical = fields[base + 4] == b"\x30\x00";
        }
        encoded_extensions.extend(ext.to_der()?);
    }
    ensure!(
        !encoded_extensions.is_empty(),
        "generated extensions are empty"
    );
    ensure!(
        fields[base + 4] != b"\x30\x00" || has_san,
        "empty subject requires SAN"
    );
    let extensions = raw_der::wrap(0xa3, &raw_der::wrap(0x30, &encoded_extensions));
    fields[7] = &extensions;
    // rcgen was given the real signer, not a temporary key: both algorithm
    // fields and all key identifiers already refer to the real subject/issuer.
    ensure!(
        fields[base + 1] == outer[1],
        "generated signature algorithm mismatch"
    );
    let tbs = raw_der::wrap(0x30, &fields.concat());
    let signature = rcgen::SigningKey::sign(signer, &tbs)?;
    let bits = raw_der::wrap(3, &[&[0u8][..], &signature].concat());
    let final_der = raw_der::wrap(0x30, &[tbs.as_slice(), outer[1], bits.as_slice()].concat());
    certificate_syntax(&final_der)?;
    let (tail, finished) = x509_parser::parse_x509_certificate(&final_der)
        .map_err(|_| anyhow!("invalid final DER"))?;
    ensure!(
        tail.is_empty() && finished.tbs_certificate.as_ref() == tbs.as_slice(),
        "final TBS mismatch"
    );
    crate::cert_status::verify_x509_signature(
        parent.public_key(),
        &finished.signature_algorithm,
        &finished.signature_value.data,
        finished.tbs_certificate.as_ref(),
        true,
    )?;
    Ok(final_der)
}

pub(super) fn new_intermediate(
    name: &str,
    root: &Pair,
    now: i64,
    lifetime: Duration,
) -> Result<Pair> {
    let (_, root_expiry) = validity(root)?;
    ensure!(
        !lifetime.is_zero() && i64::try_from(lifetime.as_secs())? < root_expiry - now,
        "intermediate lifetime exceeds remaining root lifetime"
    );
    let (issuer, issuer_der) = issuer(root)?;
    let key = rcgen::KeyPair::generate()?;
    let mut params = parameters(name, now, lifetime, 0)?;
    params.key_identifier_method =
        KeyIdMethod::PreSpecified(Sha1::digest(key.der_bytes()).to_vec());
    params.use_authority_key_identifier_extension = true;
    let cert = params.signed_by(&key, &issuer)?;
    let der = bind_names(cert.der(), &issuer_der, None, issuer.key())?;
    let pair = Pair {
        explicit_anchor: false,
        chain_pem: pem::encode(&pem::Pem::new("CERTIFICATE", der)).into_bytes(),
        private_key_pem: Some(Zeroizing::new(key.serialize_pem().into_bytes())),
    };
    validate(&pair, Some(root), now, false)?;
    Ok(pair)
}

pub(super) fn issue(
    csr: &[u8],
    signing: &Pair,
    now: i64,
    lifetime: Duration,
    include_signer: bool,
) -> Result<Vec<u8>> {
    ensure!(
        !csr.is_empty() && csr.len() <= 128 * 1024 && lifetime.as_secs() > 0,
        "invalid internal certificate request"
    );
    let (tail, request) =
        x509_parser::certification_request::X509CertificationRequest::from_der(csr)
            .map_err(|_| anyhow!("invalid CSR DER"))?;
    ensure!(tail.is_empty(), "trailing CSR bytes");
    ensure!(
        request.signature_value.unused_bits == 0,
        "invalid CSR signature bit string"
    );
    ensure!(csr_syntax(csr).is_ok(), "non-canonical CSR DER");
    crate::cert_status::verify_x509_signature(
        &request.certification_request_info.subject_pki,
        &request.signature_algorithm,
        &request.signature_value.data,
        request.certification_request_info.raw,
        true,
    )
    .map_err(|_| anyhow!("invalid CSR signature"))?;
    let mut attributes = HashSet::new();
    for attribute in request.certification_request_info.iter_attributes() {
        ensure!(
            attributes.insert(attribute.oid.to_id_string()),
            "duplicate CSR attribute"
        );
        if let x509_parser::cri_attributes::ParsedCriAttribute::ExtensionRequest(requested) =
            attribute.parsed_attribute()
        {
            let mut oids = HashSet::new();
            for extension in &requested.extensions {
                ensure!(
                    oids.insert(extension.oid.to_id_string()),
                    "duplicate CSR extension"
                );
                ensure!(
                    !matches!(
                        extension.parsed_extension(),
                        ParsedExtension::ParseError { .. }
                    ),
                    "malformed CSR extension"
                );
            }
        }
    }
    let public = SubjectKey::from_spki(request.certification_request_info.subject_pki.raw)?;
    let (issuer, issuer_der) = issuer(signing)?;
    let (not_before, not_after) = validity(signing)?;
    ensure!(
        not_before <= now && not_after > now,
        "internal issuer is not currently valid"
    );
    let mut params = CertificateParams::default();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.serial_number = Some(serial()?);
    params.not_before = OffsetDateTime::from_unix_timestamp(now)?;
    params.not_after = OffsetDateTime::from_unix_timestamp(
        now.saturating_add(i64::try_from(lifetime.as_secs())?)
            .min(not_after),
    )?;
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    if public.algorithm() == &rcgen::PKCS_RSA_SHA256 {
        params.key_usages.push(KeyUsagePurpose::KeyEncipherment);
    }
    params.extended_key_usages = vec![
        rcgen::ExtendedKeyUsagePurpose::ServerAuth,
        rcgen::ExtendedKeyUsagePurpose::ClientAuth,
    ];
    params.use_authority_key_identifier_extension = true;
    let mut saw_san = false;
    if let Some(extensions) = request.requested_extensions() {
        for extension in extensions {
            if let ParsedExtension::SubjectAlternativeName(san) = extension {
                ensure!(!saw_san, "duplicate CSR SAN extension");
                saw_san = true;
                ensure!(san.general_names.len() <= 4096, "CSR SAN count exceeded");
                for name in &san.general_names {
                    use x509_parser::extensions::GeneralName;
                    params.subject_alt_names.push(match name {
                        GeneralName::DNSName(name) => rcgen::SanType::DnsName((*name).try_into()?),
                        GeneralName::RFC822Name(name) => {
                            rcgen::SanType::Rfc822Name((*name).try_into()?)
                        }
                        GeneralName::URI(name) => rcgen::SanType::URI((*name).try_into()?),
                        GeneralName::IPAddress(bytes) => {
                            let address = if let Ok(value) = <[u8; 4]>::try_from(*bytes) {
                                std::net::IpAddr::from(value)
                            } else {
                                std::net::IpAddr::from(
                                    <[u8; 16]>::try_from(*bytes)
                                        .map_err(|_| anyhow!("invalid CSR IP"))?,
                                )
                            };
                            rcgen::SanType::IpAddress(address)
                        }
                        _ => return Err(anyhow!("unsupported internal CSR SAN type")),
                    });
                }
            }
        }
    }
    let cert = params.signed_by(&public, &issuer)?;
    let der = bind_names(
        cert.der(),
        &issuer_der,
        Some((
            request.certification_request_info.subject.as_raw(),
            request.certification_request_info.subject_pki.raw,
        )),
        issuer.key(),
    )?;
    let (_, finished) =
        x509_parser::parse_x509_certificate(&der).map_err(|_| anyhow!("invalid generated leaf"))?;
    let (_, parent) =
        x509_parser::parse_x509_certificate(&issuer_der).map_err(|_| anyhow!("invalid issuer"))?;
    ensure!(
        finished.public_key().raw == request.certification_request_info.subject_pki.raw
            && finished.subject().as_raw() == request.certification_request_info.subject.as_raw()
            && finished.issuer().as_raw() == parent.subject().as_raw(),
        "generated leaf identity binding failed"
    );
    ensure!(
        finished.signature_algorithm == finished.tbs_certificate.signature,
        "generated signature algorithm mismatch"
    );
    crate::cert_status::verify_x509_signature(
        parent.public_key(),
        &finished.signature_algorithm,
        &finished.signature_value.data,
        finished.tbs_certificate.as_ref(),
        true,
    )?;
    let mut result = pem::encode(&pem::Pem::new("CERTIFICATE", der)).into_bytes();
    if include_signer {
        result.extend_from_slice(&signing.chain_pem);
    }
    Ok(result)
}
