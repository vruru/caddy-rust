//! Generation/policy-scoped certificate access used outside the TLS signer.
use anyhow::Result;
use futures_util::future::BoxFuture;
use tokio_util::sync::CancellationToken;
use std::sync::Arc;
use crate::tls_resolver::{CertificateResidency, ScopedCertificate};

/// The exact successfully acquired instance, bound to its resolver generation.
/// A subject name alone is not a receipt: several authorities may coexist.
#[derive(Clone)]
pub struct AcquiredCertificate {
    pub(crate) subject: String,
    pub(crate) receipt: ScopedCertificate,
    pub(crate) slot: Arc<CertificateResidency>,
    pub(crate) external: Option<Arc<TransientCertificate>>,
}

/// One private, uncached publication, owned by its actual TLS connection.
/// Status work keeps its reservation until cancelled work has really stopped.
pub(crate) struct TransientCertificate {
    pub(crate) resolver: Arc<crate::tls_resolver::HotCertificateResolver>,
    pub(crate) cancel: CancellationToken,
    pub(crate) reservation: Arc<tokio::sync::OwnedSemaphorePermit>,
}
impl Drop for TransientCertificate { fn drop(&mut self) { self.cancel.cancel(); } }
impl AcquiredCertificate {
    pub(crate) fn select(&self, managed: &crate::tls_resolver::HotCertificateResolver,
        schemes: &[rustls::SignatureScheme], version: Option<rustls::ProtocolVersion>)
        -> Option<crate::tls_resolver::CertificateSelection> {
        self.external.as_ref().map_or(managed, |external| external.resolver.as_ref())
            .select_receipt(&self.receipt, &self.slot, schemes, version)
    }
}
#[derive(Clone)]
pub(crate) struct CertificateHello {
    pub(crate) server_name: String,
    pub(crate) signatures: Vec<u16>,
    pub(crate) ciphers: Vec<u16>,
    pub(crate) local_ip: Option<Vec<u8>>,
}
#[derive(Clone)]
pub(crate) struct WarmSelection {
    pub(crate) filter: Option<Arc<crate::tls_policy::certificate_selection::CertificateFilter>>,
    pub(crate) schemes: Vec<rustls::SignatureScheme>,
    pub(crate) version: Option<rustls::ProtocolVersion>,
}

/// The authorization origin remains the offered name while a defaulted
/// lookup can acquire a different DNS or IP subject.
pub struct CertificateRequest {
    pub(crate) origin: String,
    pub(crate) subject: String,
    pub(crate) force_lookup: bool,
    pub(crate) hello: Option<CertificateHello>,
    pub(crate) cached: Option<AcquiredCertificate>,
    pub(crate) selection: Option<WarmSelection>,
}

/// A capability for one immutable application generation and its automation
/// policies. It must not expose a process-global certificate cache as authority.
/// Certificate validity, actual protocol/signature selection and shared leaf
/// admission are still checked by the final certificate resolver.
pub trait ScopedCertificateProvider: Send + Sync {
    fn ensure_request(
        &self,
        request: CertificateRequest,
        cancel: CancellationToken,
    ) -> BoxFuture<'static, Result<Option<AcquiredCertificate>>> {
        if request.origin == request.subject && !request.force_lookup {
            let ensure = self.ensure(request.subject, cancel);
            Box::pin(async move { ensure.await.map(|_| None) })
        } else {
            Box::pin(async { anyhow::bail!("typed certificate acquisition unavailable") })
        }
    }
    /// Pure in-memory eligibility for a normalized DNS name in this generation's
    /// resident inventory. No network, filesystem, X509 parsing or permission
    /// request may run here: existing connections call this on each new request.
    fn cached_name(&self, normalized_name: &str) -> bool;

    /// Whether QUIC needs to read the client name before accepting the handshake.
    /// No network or storage access may run here.
    fn needs_quic_preflight(&self) -> bool {
        true
    }

    /// Pure resident maintenance check. It may only request ordinary QUIC
    /// address validation; it must not acquire, schedule or mutate anything.
    fn maintenance_due(&self, _normalized_name: &str) -> bool {
        false
    }

    fn maintenance_due_for(&self, request: &CertificateRequest) -> bool {
        self.maintenance_due(&request.subject)
    }

    /// Whether the selected policy permits attempting acquisition for this name.
    /// The real permission endpoint still decides at acquisition time.
    fn can_acquire_quic_name(&self, _normalized_name: &str) -> bool {
        true
    }

    /// Whether this generation would try the original name before using an
    /// already-resident fallback. A conservative implementation must return
    /// true: issuance permission failures cannot become a fallback bypass.
    fn should_probe_before_fallback(&self, _normalized_name: &str) -> bool {
        true
    }

    /// Called before the synchronous TLS resolver for an ordinary, non-tagged
    /// handshake. A valid resident hit is an immediate path; bounded maintenance
    /// may be scheduled when due. A genuine miss owns permission/storage/issuance
    /// work, respecting this generation and the supplied cancellation token.
    /// Permission governs acquisition rather than every use of a resident key.
    /// ACME proof handshakes never call this capability.
    ///
    /// `cancel` belongs only to this handshake waiter. Cancelling it, including
    /// after a successful ensure, must not cancel another waiter or maintenance
    /// owned by this generation. The implementation must release or join work
    /// owned solely by the cancelled waiter; shared acquisition flights retain
    /// their remaining waiters and generation-owned maintenance has a separate
    /// owner. Dropping this future must obey the same ownership boundary.
    fn ensure(
        &self,
        normalized_name: String,
        cancel: CancellationToken,
    ) -> BoxFuture<'static, Result<()>>;
}
