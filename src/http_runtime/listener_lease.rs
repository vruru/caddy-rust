//! Shared challenge listener ownership. Providers hold weak runtime references;
//! a lease retains only the listener owners acquired for the request batch.
use super::StagedAddress;
use anyhow::Result;
use futures_util::future::BoxFuture;
use tokio_util::sync::CancellationToken;

#[derive(Clone, Default)]
pub struct ChallengeBindingRequest {
    /// Empty follows the operating system's wildcard bind convention. Numeric
    /// addresses are always supported; hostname binds require a candidate snapshot.
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

pub(crate) fn numeric_bind_host(host:&str)->Result<Option<std::net::SocketAddr>> {
    if host.is_empty(){return Ok(None);}
    let ip=host.parse::<std::net::IpAddr>().map_err(|_|anyhow::anyhow!("hostname binding has no candidate resolution snapshot"))?;
    Ok(Some(std::net::SocketAddr::new(ip,0)))
}
pub trait ChallengeListenerProvider: Send + Sync {
    /// Snapshot-only selection. The conservative default performs no DNS and
    /// makes no dual-stack capability claim. Returned port is ignored.
    fn resolve_bind_host(&self,host:&str)->Result<Option<std::net::SocketAddr>> {numeric_bind_host(host)}
    fn acquire(
        &self,
        requests: Vec<ChallengeBindingRequest>,
        cancel: CancellationToken,
    ) -> BoxFuture<'static, Result<Box<dyn ChallengeListenerLease>>>;
}
