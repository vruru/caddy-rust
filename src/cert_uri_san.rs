//! Certificate URI SAN syntax shared by material admission and peer verifiers.
//! It does not establish trust or change DER, names, time, purpose or signatures.
use crate::acme_wire::chain_memory;
use anyhow::{Result, anyhow};
use rustls::{DigitallySignedStruct, SignatureScheme};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use std::{fmt, sync::Arc};
#[path = "cert_uri_san/der.rs"]
mod der;

/// Admit all temporary host/user/path vectors before the pure validation pass.
/// Per-certificate admission is sequential; no retained peer or render state.
pub(crate) fn check_der(bytes: &[u8]) -> Result<()> {
    let maximum = der::uri_max_bytes(bytes).map_err(|kind| anyhow!(kind))?;
    if maximum == 0 { return Ok(()); }
    let bound = maximum.checked_mul(32).and_then(|n| n.checked_add(65536))
        .ok_or(chain_memory::MemoryDenied)?;
    let _scratch = chain_memory::try_scratch(bound)?;
    der::check_der_uris(bytes).map_err(|kind| anyhow!(kind))
}

pub(crate) fn check_chain(chain: &[CertificateDer<'_>]) -> Result<()> {
    for cert in chain { check_der(cert.as_ref())?; }
    Ok(())
}

pub(crate) fn tls_error(error: anyhow::Error) -> rustls::Error {
    if crate::cert_transient::is_resource(&error) {
        rustls::Error::General("certificate URI syntax memory admission failed".into())
    } else {
        rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
    }
}

pub(crate) fn check_chain_tls(chain: &[CertificateDer<'_>]) -> Result<(), rustls::Error> {
    check_chain(chain).map_err(tls_error)
}

struct GuardedServerVerifier {
    inner: Arc<dyn ServerCertVerifier>,
    // Last field: inner policy is retired before its actual metadata allowance.
    _metadata: chain_memory::Lease,
}
impl fmt::Debug for GuardedServerVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UriSyntaxServerVerifier").field("inner", &self.inner).finish()
    }
}
impl ServerCertVerifier for GuardedServerVerifier {
    fn verify_server_cert(&self, end: &CertificateDer<'_>, chain: &[CertificateDer<'_>],
        name: &ServerName<'_>, ocsp: &[u8], now: UnixTime) -> Result<ServerCertVerified, rustls::Error> {
        if !self.inner.requires_raw_public_keys() {
            check_der(end.as_ref()).map_err(tls_error)?;
            check_chain_tls(chain)?;
        }
        self.inner.verify_server_cert(end, chain, name, ocsp, now)
    }
    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct)
        -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }
    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct)
        -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> { self.inner.supported_verify_schemes() }
    fn requires_raw_public_keys(&self) -> bool { self.inner.requires_raw_public_keys() }
    fn root_hint_subjects(&self) -> Option<&[rustls::DistinguishedName]> { self.inner.root_hint_subjects() }
}

/// A fixed fallible constructor hook: original verifier and every policy flag
/// are retained, with resident metadata backed only by an atomic payload lease.
pub(crate) fn wrap_server_verifier(inner: Arc<dyn ServerCertVerifier>)
    -> Result<Arc<dyn ServerCertVerifier>, rustls::Error> {
    let bytes = std::mem::size_of::<GuardedServerVerifier>().checked_add(256)
        .ok_or_else(|| rustls::Error::General("certificate verifier metadata overflow".into()))?;
    let metadata = chain_memory::shared().payload.reserve(bytes)
        .map_err(|_| rustls::Error::General("certificate verifier metadata admission failed".into()))?;
    Ok(Arc::new(GuardedServerVerifier { inner, _metadata: metadata }))
}

pub(crate) fn guarded_config(mut config: rustls::ClientConfig) -> Result<rustls::ClientConfig, rustls::Error> {
    let original = config.dangerous().certificate_verifier();
    let wrapped = wrap_server_verifier(original)?;
    config.dangerous().set_certificate_verifier(wrapped);
    Ok(config)
}

/// AppendCertsFromPEM-style admission: unusable syntax is skipped, resource
/// exhaustion is propagated so it cannot poison a success-only root cache.
pub(crate) fn add_root(roots: &mut rustls::RootCertStore, cert: CertificateDer<'static>) -> Result<bool> {
    match check_der(cert.as_ref()) {
        Ok(()) => Ok(roots.add(cert).is_ok()),
        Err(error) if crate::cert_transient::is_resource(&error) => Err(error),
        Err(_) => Ok(false),
    }
}

/// Explicit reqwest PEM roots are strict in the original builder; retain the
/// same bytes and builder policy after syntax admission, including empty input.
pub(crate) fn check_pem_roots(pem: &[u8]) -> Result<()> {
    let bytes = pem.len().checked_mul(4).and_then(|n| n.checked_add(65536))
        .ok_or(chain_memory::MemoryDenied)?;
    let _scratch = chain_memory::try_scratch(bytes)?;
    for cert in rustls_pemfile::certs(&mut pem.as_ref()) {
        check_der(cert?.as_ref())?;
    }
    Ok(())
}
