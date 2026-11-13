//! Generation-owned client credential views. Handshake callbacks only select
//! accepted cache data; acquisition/permission/storage stay in CertificateServices.
use crate::tls_resolver::{CertificateSelection, HotCertificateResolver, PreparedNativeKey};
use rustls::{ProtocolVersion, SignatureScheme, client::ResolvesClientCert, sign::CertifiedKey};
use std::{
    fmt, io,
    sync::{Arc, Mutex},
};
pub(crate) struct ManagedClientSource {
    name: Arc<str>,
    manual: Arc<HotCertificateResolver>,
    business: Arc<HotCertificateResolver>,
}
impl fmt::Debug for ManagedClientSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ManagedClientSource")
    }
}
impl ManagedClientSource {
    pub(super) fn new(
        name: &str,
        manual: Arc<HotCertificateResolver>,
        business: Arc<HotCertificateResolver>,
    ) -> anyhow::Result<Arc<Self>> {
        let name = crate::tls_resolver::normalize_certificate_name(name)?;
        Ok(Arc::new(Self {
            name: name.into(),
            manual,
            business,
        }))
    }
    pub(crate) fn name(&self) -> &str {
        &self.name
    }
    fn select(
        &self,
        allowed: impl Fn(&[u8]) -> bool,
        schemes: &[SignatureScheme],
        version: ProtocolVersion,
    ) -> Option<Arc<CertificateSelection>> {
        let manual = self.manual
            .select_client_for_version(&self.name, &allowed, schemes, version);
        if let Some(manual) = manual {
            // X509 validity is encoded in whole UTC seconds. Avoid starting a
            // new handshake with the manual leaf in its last valid second when
            // a strictly longer-lived, independently CRI-compatible managed
            // successor is already available. This does not predict arbitrary
            // peer/network delays and never retries an application request.
            let boundary = || {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH).ok()?;
                i64::try_from(now.as_secs().checked_add(1)?).ok()
            };
            if let (Some(until), Some(before)) = (
                manual.native.as_ref().map(|native| native.not_after), boundary(),
            ) && until <= before {
                let managed = self.business
                    .select_client_for_version(&self.name, &allowed, schemes, version);
                if let (Some(managed), Some(after)) = (managed, boundary()) {
                    // A backwards/invalid clock must not cause an early switch.
                    // Recheck the successor's own window after cache lookup.
                    if after >= before && let Some(native) = managed.native.as_ref()
                        && native.not_after > until && native.not_after > after
                    {
                        return Some(Arc::new(managed));
                    }
                }
            }
            return Some(Arc::new(manual));
        }
        self.business
            .select_client_for_version(&self.name, &allowed, schemes, version)
            .map(Arc::new)
    }
    pub(crate) fn binding(self: &Arc<Self>) -> Arc<ClientBinding> {
        Arc::new(ClientBinding {
            source: self.clone(),
            state: Mutex::new(State {
                selected: None,
                failed: false,
            }),
        })
    }
}
struct State {
    selected: Option<Arc<CertificateSelection>>,
    failed: bool,
}
pub(crate) struct ClientBinding {
    source: Arc<ManagedClientSource>,
    state: Mutex<State>,
}
impl fmt::Debug for ClientBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ManagedClientBinding")
    }
}
fn withdrawn() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "managed client certificate unavailable or withdrawn",
    )
}
impl ClientBinding {
    fn remember(
        &self,
        selected: Option<Arc<CertificateSelection>>,
    ) -> Option<Arc<CertificateSelection>> {
        let prior = {
            let mut state = self.state.lock().ok()?;
            if selected.is_none() {
                state.failed = true
            }
            std::mem::replace(&mut state.selected, selected.clone())
        };
        drop(prior);
        selected
    }
    pub(crate) fn check(&self) -> io::Result<()> {
        let (selected, failed) = {
            let state = self.state.lock().map_err(|_| withdrawn())?;
            (state.selected.clone(), state.failed)
        };
        if failed
            || selected
                .as_ref()
                .is_some_and(|key| key.native.as_ref().is_none_or(|native| !native.admitted()))
        {
            return Err(withdrawn());
        }
        Ok(())
    }
    fn resolve_version(
        &self,
        hints: &[&[u8]],
        schemes: &[SignatureScheme],
        version: ProtocolVersion,
    ) -> Option<Arc<CertifiedKey>> {
        let selected = self.source.select(
            |issuer| hints.is_empty() || hints.contains(&issuer),
            schemes,
            version,
        );
        self.remember(selected).map(|key| key.key.clone())
    }
}
impl ResolvesClientCert for ClientBinding {
    fn resolve(&self, hints: &[&[u8]], schemes: &[SignatureScheme]) -> Option<Arc<CertifiedKey>> {
        self.resolve_version(hints, schemes, ProtocolVersion::TLSv1_2)
    }
    fn resolve_for_version(
        &self,
        hints: &[&[u8]],
        schemes: &[SignatureScheme],
        version: ProtocolVersion,
    ) -> Option<Arc<CertifiedKey>> {
        self.resolve_version(hints, schemes, version)
    }
    fn has_certs(&self) -> bool {
        true
    }
}
struct NativeCredential {
    private: PreparedNativeKey,
    selection: Arc<CertificateSelection>,
}
impl native_ssl_tls::ClientCredential for NativeCredential {
    fn chain(&self) -> &[rustls::pki_types::CertificateDer<'static>] {
        &self.selection.key.cert
    }
    fn private_key(&self) -> &openssl::pkey::PKeyRef<openssl::pkey::Private> {
        self.private.key()
    }
    fn admitted(&self) -> bool {
        self.selection
            .native
            .as_ref()
            .is_some_and(|native| native.admitted())
    }
}
impl native_ssl_tls::ClientIdentityResolver for ClientBinding {
    fn resolve(
        &self,
        request: native_ssl_tls::ClientCertificateRequest<'_>,
    ) -> io::Result<Arc<dyn native_ssl_tls::ClientCredential>> {
        let selected = self.source.select(
            |issuer| {
                request.issuer_hints.is_empty()
                    || request
                        .issuer_hints
                        .iter()
                        .any(|hint| hint.as_slice() == issuer)
            },
            request.signature_schemes,
            request.version,
        );
        let selected = self.remember(selected).ok_or_else(withdrawn)?;
        let native = selected.native.as_ref().ok_or_else(withdrawn)?;
        if !native.admitted() {
            return Err(withdrawn());
        }
        let private = native.private.prepare().map_err(|error| {
            io::Error::new(
                if error.is::<crate::cert_transient::ResourceDenied>() {
                    io::ErrorKind::OutOfMemory
                } else {
                    io::ErrorKind::InvalidData
                },
                "managed client private key unavailable",
            )
        })?;
        self.check()?;
        Ok(Arc::new(NativeCredential {
            private,
            selection: selected,
        }))
    }
}
/// Real TLS data is destroyed before its selected-credential view. No new DER
/// copy is made here, and a revoked key cannot emit/receive application bytes.
pub(crate) struct BoundClientIo<S> {
    inner: S,
    binding: Arc<ClientBinding>,
}
impl<S> BoundClientIo<S> {
    pub(crate) fn new(inner: S, binding: Arc<ClientBinding>) -> Self {
        Self { inner, binding }
    }
    pub(crate) fn get_ref(&self) -> &S {
        &self.inner
    }
}
impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for BoundClientIo<S> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let this = self.get_mut();
        this.binding.check()?;
        let old = buf.filled().len();
        let result = std::pin::Pin::new(&mut this.inner).poll_read(cx, buf);
        if let Err(error) = this.binding.check() {
            buf.filled_mut()[old..].fill(0);
            buf.set_filled(old);
            return std::task::Poll::Ready(Err(error));
        }
        result
    }
}
impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for BoundClientIo<S> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.binding.check()?;
        let result = std::pin::Pin::new(&mut this.inner).poll_write(cx, data);
        this.binding.check()?;
        result
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let this = self.get_mut();
        this.binding.check()?;
        let result = std::pin::Pin::new(&mut this.inner).poll_flush(cx);
        this.binding.check()?;
        result
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let this = self.get_mut();
        this.binding.check()?;
        let result = std::pin::Pin::new(&mut this.inner).poll_shutdown(cx);
        this.binding.check()?;
        result
    }
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
    fn poll_write_vectored(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[io::IoSlice<'_>],
    ) -> std::task::Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.binding.check()?;
        let result = std::pin::Pin::new(&mut this.inner).poll_write_vectored(cx, data);
        this.binding.check()?;
        result
    }
}
