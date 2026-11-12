//! Sprig certificate functions. Callers own bounded blocking execution and bytes.
use anyhow::{Context, Result, anyhow, ensure};
use openssl::{
    asn1::Asn1Time,
    bn::BigNum,
    hash::MessageDigest,
    nid::Nid,
    pkey::{Id, PKey, PKeyRef, Private},
    x509::{
        X509, X509Name,
        extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage},
    },
};
use time::OffsetDateTime;
use x509_parser::prelude::FromDer;
#[path="certificates/keys.rs"] mod keys;
#[path="certificates/utility.rs"] mod utility;

pub(crate) struct Certificate {
    pub cert: String,
    pub key: String,
}

pub(crate) fn gen_private_key(kind: &str) -> Result<String> {
    keys::generated(kind)
}

pub(crate) fn build_custom_cert(cert_base64: &str, key_base64: &str) -> Result<Certificate> {
    let cert = utility::decode_base64(cert_base64)
        .map_err(|_| anyhow!("unable to decode base64 certificate"))?;
    let key = utility::decode_base64(key_base64)
        .map_err(|_| anyhow!("unable to decode base64 private key"))?;
    let block = utility::first_pem(&cert).context("unable to decode certificate")?;
    parse_certificate(block.contents()).context("error parsing certificate")?;
    let key = String::from_utf8(key).context("private key PEM is not UTF-8")?;
    keys::parse_key(&key).context("error parsing private key")?;
    // Sprig validates each independently. A custom pair need not match until
    // it is actually used to sign a certificate.
    Ok(Certificate {
        cert: String::from_utf8(cert).context("certificate PEM is not UTF-8")?,
        key,
    })
}

/// Internal signing material only. Template-visible fields must retain the
/// original Go byte strings, including preamble, headers and additional blocks.
pub(crate) fn custom_cert_signer_material(cert_pem: &[u8], key_pem: &[u8]) -> Result<Certificate> {
    let (_, cert_der) =
        utility::first_pem_parts(cert_pem).context("unable to decode certificate")?;
    parse_certificate(&cert_der).context("error parsing certificate")?;
    let key = private_key_signer_material(key_pem)?;
    Ok(Certificate {
        cert: pem::encode(&pem::Pem::new("CERTIFICATE", cert_der)),
        key,
    })
}

/// Parse Go byte-string PEM input into internal, validated signing material.
/// The supplied byte string is never exposed through this normalized value.
pub(crate) fn private_key_signer_material(key_pem: &[u8]) -> Result<String> {
    let (key_label, key_der) =
        utility::first_pem_parts(key_pem).context("unable to decode private key")?;
    let key_label = std::str::from_utf8(&key_label).context("unsupported private key PEM tag")?;
    let key = pem::encode(&pem::Pem::new(key_label, key_der));
    keys::parse_key(&key).context("error parsing private key")?;
    Ok(key)
}

pub(crate) fn gen_ca(common_name: &str, days: i64, key: Option<&str>) -> Result<Certificate> {
    let key = choose_key(key)?;
    issue(common_name, &[], &[], days, true, &key, None)
}

pub(crate) fn gen_self_signed(
    common_name: &str,
    ips: &[String],
    dns: &[String],
    days: i64,
    key: Option<&str>,
) -> Result<Certificate> {
    let key = choose_key(key)?;
    issue(common_name, ips, dns, days, false, &key, None)
}

pub(crate) fn gen_signed(
    common_name: &str,
    ips: &[String],
    dns: &[String],
    days: i64,
    ca: &Certificate,
    key: Option<&str>,
) -> Result<Certificate> {
    let key = choose_key(key)?;
    let block = utility::first_pem(ca.cert.as_bytes()).context("unable to decode certificate")?;
    let parent = parse_certificate(block.contents()).context("error parsing certificate")?;
    let signer = keys::parse_key(&ca.key).context("error parsing private key")?;
    ensure!(
        signer.public_eq(parent.public_key()?.as_ref()),
        "provided private key does not match parent public key"
    );
    issue(
        common_name,
        ips,
        dns,
        days,
        false,
        &key,
        Some((&parent, &signer)),
    )
}

fn choose_key(key: Option<&str>) -> Result<PKey<Private>> {
    match key {
        Some(text) => keys::parse_key(text).context("parsing private key"),
        None => keys::default_key(),
    }
}

fn parse_certificate(der: &[u8]) -> Result<X509> {
    let (tail, certificate) = x509_parser::certificate::X509Certificate::from_der(der)
        .map_err(|_| anyhow!("invalid certificate DER"))?;
    ensure!(tail.is_empty(), "trailing certificate DER");
    ensure!(
        certificate.signature_algorithm == certificate.tbs_certificate.signature,
        "certificate signature algorithm mismatch"
    );
    ensure!(
        certificate
            .raw_serial()
            .first()
            .is_none_or(|byte| byte & 0x80 == 0),
        "negative certificate serial"
    );
    let mut extensions = std::collections::HashSet::new();
    for extension in certificate.extensions() {
        ensure!(
            extensions.insert(extension.oid.to_id_string()),
            "duplicate certificate extension"
        );
        ensure!(
            !matches!(
                extension.parsed_extension(),
                x509_parser::extensions::ParsedExtension::ParseError { .. }
            ),
            "malformed certificate extension"
        );
    }
    Ok(X509::from_der(der)?)
}

fn subject(common_name: &str) -> Result<X509Name> {
    if common_name.is_empty() {
        return Ok(X509Name::from_der(&[0x30, 0])?);
    }
    let printable = common_name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b" '()+,-./:=?".contains(&b));
    let mut entry = vec![0x06, 0x03, 0x55, 0x04, 0x03];
    entry.extend(utility::der(
        if printable { 0x13 } else { 0x0c },
        common_name.as_bytes(),
    ));
    let entry = utility::der(0x30, &entry);
    let rdn = utility::der(0x31, &entry);
    Ok(X509Name::from_der(&utility::der(0x30, &rdn))?)
}

fn digest(key: &PKeyRef<Private>) -> Result<MessageDigest> {
    match key.id() {
        Id::RSA => {
            ensure!(
                key.bits() >= 1024,
                "RSA signing key is smaller than 1024 bits"
            );
            Ok(MessageDigest::sha256())
        }
        Id::ED25519 => Ok(MessageDigest::null()),
        Id::EC => match key.ec_key()?.group().curve_name() {
            Some(Nid::SECP224R1 | Nid::X9_62_PRIME256V1) => Ok(MessageDigest::sha256()),
            Some(Nid::SECP384R1) => Ok(MessageDigest::sha384()),
            Some(Nid::SECP521R1) => Ok(MessageDigest::sha512()),
            _ => Err(anyhow!("unsupported EC curve for certificate")),
        },
        _ => Err(anyhow!("unsupported key type for certificate")),
    }
}

fn issue(
    common_name: &str,
    ips: &[String],
    dns: &[String],
    days: i64,
    is_ca: bool,
    key: &PKeyRef<Private>,
    parent: Option<(&X509, &PKeyRef<Private>)>,
) -> Result<Certificate> {
    // Go does not support DSA/X25519 subjects even when a valid RSA CA signs.
    ensure!(
        matches!(key.id(), Id::RSA | Id::EC | Id::ED25519),
        "unsupported key type for certificate"
    );
    let signer = parent.map_or(key, |(_, key)| key);
    let signature_digest = digest(signer)?;
    let name = subject(common_name)?;
    let subject_der = name.to_der()?;
    let issuer = parent.map_or(name.as_ref(), |(certificate, _)| certificate.subject_name());
    let issuer_der = issuer.to_der()?;
    let san = utility::san(ips, dns)?;
    let now = OffsetDateTime::now_utc();
    let not_before = Asn1Time::from_unix(now.unix_timestamp())?;
    let duration = days.wrapping_mul(86_400_000_000_000);
    let not_after_secs =
        (now.unix_timestamp_nanos() + i128::from(duration)).div_euclid(1_000_000_000);
    let not_after = Asn1Time::from_unix(i64::try_from(not_after_secs)?)?;
    let mut serial_bytes = [0; 16];
    openssl::rand::rand_bytes(&mut serial_bytes)?;
    let serial = BigNum::from_slice(&serial_bytes)?.to_asn1_integer()?;
    let mut builder = X509::builder()?;
    builder.set_version(2)?;
    builder.set_serial_number(&serial)?;
    builder.set_subject_name(&name)?;
    builder.set_issuer_name(issuer)?;
    builder.set_pubkey(key)?;
    builder.set_not_before(&not_before)?;
    builder.set_not_after(&not_after)?;
    let mut usage = KeyUsage::new();
    usage.critical().digital_signature().key_encipherment();
    if is_ca {
        usage.key_cert_sign();
    }
    builder.append_extension(usage.build()?)?;
    builder.append_extension(
        ExtendedKeyUsage::new()
            .server_auth()
            .client_auth()
            .build()?,
    )?;
    let mut constraints = BasicConstraints::new();
    constraints.critical();
    if is_ca {
        constraints.ca();
    }
    builder.append_extension(constraints.build()?)?;
    if is_ca {
        let spki = key.public_key_to_der()?;
        let (tail, public) = x509_parser::x509::SubjectPublicKeyInfo::from_der(&spki)
            .map_err(|_| anyhow!("invalid subject public key"))?;
        ensure!(tail.is_empty(), "trailing public key DER");
        let digest = openssl::sha::sha256(public.subject_public_key.data.as_ref());
        let ski = utility::der(0x04, &digest[..20]);
        builder.append_extension(utility::ext("2.5.29.14", false, &ski)?)?;
    }
    if subject_der != issuer_der
        && let Some((parent, _)) = parent
        && let Some(ski) = parent.subject_key_id()
    {
        let aki = utility::der(0x30, &utility::der(0x80, ski.as_slice()));
        builder.append_extension(utility::ext("2.5.29.35", false, &aki)?)?;
    }
    if let Some(san) = san {
        builder.append_extension(utility::ext("2.5.29.17", subject_der == [0x30, 0], &san)?)?;
    }
    builder
        .sign(signer, signature_digest)
        .context("error creating certificate")?;
    let built = builder.build();
    ensure!(
        built.verify(signer)?,
        "signature over certificate returned by signer is invalid"
    );
    let cert = String::from_utf8(built.to_pem()?)?;
    Ok(Certificate {
        cert,
        key: keys::encode_key(key)?,
    })
}
