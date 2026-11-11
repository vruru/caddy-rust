//! Generation/policy-scoped certificate access used outside the TLS signer.
use anyhow::Result;
use futures_util::future::BoxFuture;
use tokio_util::sync::CancellationToken;

/// A capability for one immutable application generation and its automation
/// policies. It must not expose a process-global certificate cache as authority.
/// Certificate validity, actual protocol/signature selection and shared leaf
/// admission are still checked by the final certificate resolver.
pub trait ScopedCertificateProvider: Send + Sync {
    /// Pure in-memory eligibility for a normalized DNS name in this generation's
    /// resident inventory. No network, filesystem, X509 parsing or permission
    /// request may run here: existing connections call this on each new request.
    fn cached_name(&self, normalized_name: &str) -> bool;

    /// Whether QUIC needs to read the client name before accepting the handshake.
    /// No network or storage access may run here.
    fn needs_quic_preflight(&self) -> bool {
        true
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
