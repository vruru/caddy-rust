//! An explicitly configured exact end-entity DER is a direct trust input.
//! This is not a verifier bypass: all other certificates use WebPKI, and TLS
//! CertificateVerify signatures always use the normal cryptographic verifier.
use rustls::{
    client::danger::HandshakeSignatureValid,
    pki_types::{CertificateDer, UnixTime},
    server::danger::{ClientCertVerified, ClientCertVerifier},
};
use std::sync::Arc;
fn bad() -> rustls::Error {
    rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
}
fn purpose() -> rustls::Error {
    rustls::Error::InvalidCertificate(rustls::CertificateError::InvalidPurpose)
}
pub(super) fn is_end_entity(der: &CertificateDer<'_>) -> Result<bool, rustls::Error> {
    let (rest, cert) = x509_parser::parse_x509_certificate(der.as_ref()).map_err(|_| bad())?;
    if !rest.is_empty() {
        return Err(bad());
    }
    cert.extensions_map().map_err(|_| bad())?;
    Ok(!cert
        .basic_constraints()
        .map_err(|_| bad())?
        .is_some_and(|b| b.value.ca))
}
pub(super) fn validate(der: &CertificateDer<'_>, now: UnixTime) -> Result<(), rustls::Error> {
    let (rest, cert) = x509_parser::parse_x509_certificate(der.as_ref()).map_err(|_| bad())?;
    if !rest.is_empty() {
        return Err(bad());
    }
    // The same parser used by ordinary rustls certificate verification must
    // also accept this EE. Never authorize a trailing raw certificate instead.
    webpki::EndEntityCert::try_from(der).map_err(|_| bad())?;
    cert.extensions_map().map_err(|_| bad())?;
    let now = i64::try_from(now.as_secs()).map_err(|_| bad())?;
    if now < cert.validity().not_before.timestamp() {
        return Err(rustls::Error::InvalidCertificate(
            rustls::CertificateError::NotValidYet,
        ));
    }
    if now > cert.validity().not_after.timestamp() {
        return Err(rustls::Error::InvalidCertificate(
            rustls::CertificateError::Expired,
        ));
    }
    if cert
        .basic_constraints()
        .map_err(|_| bad())?
        .is_some_and(|b| b.value.ca)
    {
        return Err(purpose());
    }
    // Go x509 deliberately ignores KU status bits (verify.go isValid).
    // Parse for malformed/duplicate extensions, but do not impose an extra
    // digitalSignature bit requirement. TLS CertificateVerify below still
    // cryptographically proves possession of this exact trusted leaf's key.
    let _ = cert.key_usage().map_err(|_| bad())?;
    if cert
        .extended_key_usage()
        .map_err(|_| bad())?
        .is_some_and(|k| !k.value.client_auth && !k.value.any)
    {
        return Err(purpose());
    }
    use x509_parser::extensions::ParsedExtension;
    for ext in cert.extensions() {
        match ext.parsed_extension() {
            ParsedExtension::ParseError { .. } => return Err(bad()),
            // Unsupported critical constraints are rejected, never ignored.
            ParsedExtension::KeyUsage(_)
            | ParsedExtension::ExtendedKeyUsage(_)
            | ParsedExtension::BasicConstraints(_) => {}
            ParsedExtension::SubjectAlternativeName(san) => {
                if ext.critical
                    && !san.general_names.iter().any(|name| {
                        matches!(
                            name,
                            x509_parser::extensions::GeneralName::DNSName(_)
                                | x509_parser::extensions::GeneralName::RFC822Name(_)
                                | x509_parser::extensions::GeneralName::URI(_)
                                | x509_parser::extensions::GeneralName::IPAddress(_)
                        )
                    })
                {
                    return Err(bad());
                }
            }
            ParsedExtension::SubjectKeyIdentifier(_)
            | ParsedExtension::AuthorityKeyIdentifier(_)
                if ext.critical =>
            {
                return Err(bad());
            }
            _ if ext.critical => {
                return Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::UnhandledCriticalExtension,
                ));
            }
            _ => {}
        }
    }
    Ok(())
}
pub(super) struct Verifier {
    signatures: Arc<dyn ClientCertVerifier>,
    normal: Option<Arc<dyn ClientCertVerifier>>,
    pins: Vec<CertificateDer<'static>>,
}
impl std::fmt::Debug for Verifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ExplicitEndEntityOrWebPkiClientVerifier")
    }
}
impl Verifier {
    pub fn new(
        signatures: Arc<dyn ClientCertVerifier>,
        normal: Option<Arc<dyn ClientCertVerifier>>,
        pins: Vec<CertificateDer<'static>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            signatures,
            normal,
            pins,
        })
    }
}

impl ClientCertVerifier for Verifier {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        self.signatures.root_hint_subjects()
    }
    fn verify_client_cert(
        &self,
        ee: &CertificateDer<'_>,
        chain: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        if self.pins.iter().any(|pin| pin.as_ref() == ee.as_ref()) {
            validate(ee, now)?;
            return Ok(ClientCertVerified::assertion());
        }
        self.normal
            .as_ref()
            .ok_or(rustls::Error::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer,
            ))?
            .verify_client_cert(ee, chain, now)
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.signatures.verify_tls12_signature(message, cert, dss)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.signatures.verify_tls13_signature(message, cert, dss)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.signatures.supported_verify_schemes()
    }
}
