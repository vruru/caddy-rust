//! Concrete, prepaid metadata ownership. No callbacks or application objects.
use native_write_policy::Lease;
use std::{io, sync::Arc};

/// The caller prepays the Vec capacity, Arc metadata and held connection data.
/// This holder creates no pool or allowance and never refunds another owner.
#[derive(Debug)]
pub struct ConnectionCredits {
    _leases: Vec<Arc<Lease>>,
}
impl ConnectionCredits {
    pub fn new(leases: Vec<Arc<Lease>>) -> Self {
        Self { _leases: leases }
    }
}

#[derive(Debug)]
struct CreditedIoError {
    inner: io::Error,
    // Error data must be destroyed before its atomic metadata ownership.
    credits: Arc<ConnectionCredits>,
}
impl std::fmt::Display for CreditedIoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.inner.fmt(f)
    }
}
impl std::error::Error for CreditedIoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.inner)
    }
}
pub(crate) fn retain_error(
    error: io::Error,
    credits: &Option<Arc<ConnectionCredits>>,
) -> io::Error {
    let Some(credits) = credits else {
        return error;
    };
    if error
        .get_ref()
        .and_then(|e| e.downcast_ref::<CreditedIoError>())
        .is_some_and(|old| Arc::ptr_eq(&old.credits, credits))
    {
        return error;
    }
    // Stable io::Error cannot combine its inline OS representation with an
    // owned payload. Only the new credited route gains this source wrapper;
    // kind/Display and the original error/source (including errno) survive.
    io::Error::new(
        error.kind(),
        CreditedIoError {
            inner: error,
            credits: credits.clone(),
        },
    )
}

/// Submit this whole concrete input, including on an unpolled/closed runtime.
/// Empty Drop prevents disjoint closure capture of data and its credits.
pub(crate) struct ClientFactoryInput {
    name: Option<rustls::pki_types::ServerName<'static>>,
    alpn: Option<Vec<u8>>,
    base: Arc<crate::ClientConfig>,
    credits: Option<Arc<ConnectionCredits>>,
}
impl Drop for ClientFactoryInput {
    fn drop(&mut self) {}
}
impl ClientFactoryInput {
    pub(crate) fn new(
        base: Arc<crate::ClientConfig>,
        name: rustls::pki_types::ServerName<'static>,
        alpn: Option<&[u8]>,
    ) -> Self {
        let credits = base.connection_credits.clone();
        Self {
            name: Some(name),
            alpn: alpn.map(<[u8]>::to_vec),
            base,
            credits,
        }
    }
    pub(crate) fn configure(&mut self) -> io::Result<(openssl::ssl::Ssl, Arc<crate::Guard>)> {
        self.base.configured_connection(
            self.name
                .take()
                .ok_or_else(|| io::Error::other("client factory already consumed"))?,
            self.alpn.as_deref(),
        )
    }
    pub(crate) fn retained(
        &self,
        result: io::Result<crate::server_engine::ServerEngine>,
    ) -> io::Result<crate::server_engine::ServerEngine> {
        result.map_err(|error| retain_error(error, &self.credits))
    }
}
