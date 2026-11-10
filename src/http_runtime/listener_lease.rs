//! Shared challenge listener ownership. Providers hold weak runtime references;
//! a lease retains only the listener owners acquired for the request batch.
use super::StagedAddress;
use anyhow::Result;
use futures_util::future::BoxFuture;
use tokio_util::sync::CancellationToken;

#[derive(Clone, Default)]
pub struct ChallengeBindingRequest {
    /// Empty follows the operating system's wildcard bind convention. Numeric
    /// addresses are supported first; hostname binds remain an explicit gate.
    pub bind_host: String,
    /// None disables this protocol; the caller supplies its configured port.
    pub http_port: Option<u16>,
    /// None disables this protocol; the caller supplies its configured port.
    pub tls_alpn_port: Option<u16>,
}

pub trait ChallengeListenerLease: Send + Sync {
    fn addresses(&self) -> &[StagedAddress];
    /// Explicit release may wait for a last-owner listener to finish closing.
    /// Dropping a lease still releases ownership without awaiting.
    fn release(self: Box<Self>) -> BoxFuture<'static, Result<()>>;
}

pub trait ChallengeListenerProvider: Send + Sync {
    fn acquire(
        &self,
        requests: Vec<ChallengeBindingRequest>,
        cancel: CancellationToken,
    ) -> BoxFuture<'static, Result<Box<dyn ChallengeListenerLease>>>;
}
