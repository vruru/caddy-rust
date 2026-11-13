//! Managed client identities on the complete owned SSL engine. Source access
//! and lifecycle provisioning remain the host's responsibility; callbacks use
//! prepared certificates only and execute on the bounded SSL CPU lane.
use crate::{
    ClientConfig, Guard, ServerStream, managed_request,
    server_engine::{Admission, ServerEngine},
};
use foreign_types::{ForeignType, ForeignTypeRef};
use openssl::{
    ex_data::Index,
    pkey::{PKeyRef, Private},
    ssl::{Ssl, SslMode, SslRef},
    stack::Stack,
    x509::X509,
};
use rustls::{
    ProtocolVersion, SignatureScheme,
    pki_types::{CertificateDer, ServerName},
};
use std::sync::atomic::AtomicUsize;
use std::{
    ffi::c_void,
    io,
    pin::Pin,
    sync::{Arc, Mutex, OnceLock, atomic::Ordering},
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
/// A host-owned selection pins its actual leaf/key states and private-key owner.
/// No method may perform I/O. Private key preparation must already be bounded
/// by this SSL CPU operation, not by an asynchronous callback on an HTTP worker.
pub trait ClientCredential: Send + Sync {
    fn chain(&self) -> &[CertificateDer<'static>];
    fn private_key(&self) -> &PKeyRef<Private>;
    fn admitted(&self) -> bool;
}
pub struct ClientCertificateRequest<'a> {
    pub issuer_hints: &'a [Vec<u8>],
    pub signature_schemes: &'a [SignatureScheme],
    pub version: ProtocolVersion,
}
pub trait ClientIdentityResolver: Send + Sync {
    fn resolve(
        &self,
        request: ClientCertificateRequest<'_>,
    ) -> io::Result<Arc<dyn ClientCredential>>;
}
struct Selected {
    handshake: usize,
    credential: Arc<dyn ClientCredential>,
}
struct Selection {
    resolver: Arc<dyn ClientIdentityResolver>,
    selected: Mutex<Option<Selected>>,
    error: Mutex<Option<Arc<io::Error>>>,
    guard: Arc<Guard>,
    sent_handshake: AtomicUsize,
}
impl Selection {
    fn check(&self) -> io::Result<()> {
        self.check_inner().map_err(|e|self.guard.retained_error(e))
    }
    fn check_inner(&self) -> io::Result<()> {
        let error = self
            .error
            .lock()
            .map_err(|_| io::Error::other("managed identity state poisoned"))?
            .clone();
        if let Some(e) = error {
            return Err(io::Error::new(e.kind(), e));
        }
        let credential = self
            .selected
            .lock()
            .map_err(|_| io::Error::other("managed identity state poisoned"))?
            .as_ref()
            .map(|s| (s.handshake, s.credential.clone()));
        if credential.as_ref().is_some_and(|(handshake, _)| {
            self.guard.completed.load(Ordering::Acquire) > *handshake
                && self.sent_handshake.load(Ordering::Acquire) < handshake.saturating_add(1)
        }) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "requested managed client identity was not sent",
            ));
        }
        if credential.is_some_and(|(_, c)| !c.admitted()) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "managed client identity withdrawn",
            ));
        }
        self.guard.check()
    }
    fn fail(&self, error: io::Error) {
        let prior = {
            let mut slot = self.error.lock().unwrap_or_else(|e| e.into_inner());
            if slot.is_none() {
                slot.replace(Arc::new(error))
            } else {
                None
            }
        };
        drop(prior);
    }
    fn choose(&self, ssl: &mut SslRef) -> io::Result<()> {
        self.check()?;
        let handshake = self.guard.completed.load(Ordering::Acquire);
        let current = self
            .selected
            .lock()
            .map_err(|_| io::Error::other("managed identity state poisoned"))?
            .as_ref()
            .filter(|s| s.handshake == handshake)
            .map(|s| s.credential.clone());
        let credential = if let Some(current) = current {
            current
        } else {
            let request = managed_request::capture(ssl)?;
            self.resolver.resolve(ClientCertificateRequest {
                issuer_hints: &request.hints,
                signature_schemes: &request.schemes,
                version: request.version,
            })?
        };
        if !credential.admitted() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "managed client identity withdrawn",
            ));
        }
        let chain = credential.chain();
        if chain.is_empty() || chain.len() > 64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "managed client certificate chain outside bounds",
            ));
        }
        let bytes = chain
            .iter()
            .try_fold(0usize, |n, c| n.checked_add(c.as_ref().len()))
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::OutOfMemory,
                    "managed client chain size overflow",
                )
            })?;
        if bytes > crate::raw::MAX_MESSAGE {
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "managed client chain exceeds SSL bounds",
            ));
        }
        unsafe {
            SSL_certs_clear(ssl.as_ptr());
        }
        let leaf = X509::from_der(chain[0].as_ref()).map_err(io::Error::other)?;
        ssl.set_certificate(&leaf).map_err(io::Error::other)?;
        ssl.set_private_key(credential.private_key())
            .map_err(io::Error::other)?;
        if unsafe { SSL_check_private_key(ssl.as_ptr()) } != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "managed client certificate key mismatch",
            ));
        }
        // An explicit empty per-certificate chain suppresses any inherited static
        // context extra-chain fallback, including for a single-leaf selection.
        let empty = Stack::<X509>::new().map_err(io::Error::other)?;
        if unsafe { openssl_sys::SSL_ctrl(ssl.as_ptr(), 88, 0, empty.as_ptr().cast()) } <= 0 {
            return Err(io::Error::other("managed client chain setup failed"));
        }
        std::mem::forget(empty);
        for cert in &chain[1..] {
            ssl.add_chain_cert(X509::from_der(cert.as_ref()).map_err(io::Error::other)?)
                .map_err(io::Error::other)?;
        }
        self.check()?;
        if !credential.admitted() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "managed client identity withdrawn",
            ));
        }
        let prior = {
            self.selected
                .lock()
                .map_err(|_| io::Error::other("managed identity state poisoned"))?
                .replace(Selected {
                    handshake,
                    credential,
                })
        };
        drop(prior);
        Ok(())
    }
}
static INDEX: OnceLock<Index<Ssl, Arc<Selection>>> = OnceLock::new();
static INIT: Mutex<()> = Mutex::new(());
fn index() -> Result<Index<Ssl, Arc<Selection>>, openssl::error::ErrorStack> {
    if let Some(index) = INDEX.get() {
        return Ok(*index);
    }
    let _lock = INIT.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(index) = INDEX.get() {
        return Ok(*index);
    }
    let value = Ssl::new_ex_index()?;
    let _ = INDEX.set(value);
    Ok(value)
}
unsafe extern "C" {
    fn SSL_set_cert_cb(
        ssl: *mut openssl_sys::SSL,
        callback: Option<unsafe extern "C" fn(*mut openssl_sys::SSL, *mut c_void) -> i32>,
        arg: *mut c_void,
    );
    fn SSL_certs_clear(ssl: *mut openssl_sys::SSL);
    fn SSL_check_private_key(ssl: *const openssl_sys::SSL) -> i32;
}
unsafe extern "C" fn select(ssl: *mut openssl_sys::SSL, _arg: *mut c_void) -> i32 {
    if ssl.is_null() {
        return 0;
    }
    let ssl = unsafe { SslRef::from_ptr_mut(ssl) };
    let Some(selection) = INDEX.get().and_then(|index| ssl.ex_data(*index)).cloned() else {
        return 0;
    };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| selection.choose(ssl)));
    match result {
        Ok(Ok(())) => 1,
        Ok(Err(error)) => {
            selection.fail(error);
            0
        }
        Err(_) => {
            selection.fail(io::Error::other(
                "managed client certificate callback failed",
            ));
            0
        }
    }
}
/// Observe the actual outgoing Certificate plaintext from SSL's public message
/// callback. This only checks the selected leaf, without re-encoding X509 or
/// implementing any TLS record authentication/crypto.
pub(crate) fn observe_sent(ssl: &SslRef, b: &[u8]) {
    if b.first() != Some(&11) {
        return;
    }
    let Some(selection) = INDEX.get().and_then(|index| ssl.ex_data(*index)).cloned() else {
        return;
    };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> io::Result<()> {
        fn len(b: &[u8], offset: usize) -> Option<usize> {
            let v = b.get(offset..offset.checked_add(3)?)?;
            Some((usize::from(v[0]) << 16) | (usize::from(v[1]) << 8) | usize::from(v[2]))
        }
        let invalid = || {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "outgoing managed certificate evidence rejected",
            )
        };
        if len(b, 1) != b.len().checked_sub(4) {
            return Err(invalid());
        }
        let mut offset = 4usize;
        if ssl.version2() == Some(openssl::ssl::SslVersion::TLS1_3) {
            offset = offset
                .checked_add(1 + usize::from(*b.get(offset).ok_or_else(invalid)?))
                .ok_or_else(invalid)?;
        }
        let bytes = len(b, offset).ok_or_else(invalid)?;
        offset += 3;
        if offset.checked_add(bytes) != Some(b.len()) {
            return Err(invalid());
        }
        let selected = selection
            .selected
            .lock()
            .map_err(|_| invalid())?
            .as_ref()
            .map(|s| (s.handshake, s.credential.clone()));
        match selected {
            Some((handshake, credential)) => {
                let n = len(b, offset).ok_or_else(invalid)?;
                offset += 3;
                let leaf = b
                    .get(offset..offset.checked_add(n).ok_or_else(invalid)?)
                    .ok_or_else(invalid)?;
                if credential
                    .chain()
                    .first()
                    .is_none_or(|cert| cert.as_ref() != leaf)
                {
                    return Err(invalid());
                }
                selection
                    .sent_handshake
                    .store(handshake.saturating_add(1), Ordering::Release);
            }
            None if bytes == 0 => {}
            None => return Err(invalid()),
        }
        Ok(())
    }));
    match result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => selection.fail(e),
        Err(_) => selection.fail(io::Error::other(
            "outgoing managed certificate observer failed",
        )),
    }
}

/// A distinct connector preserves the existing legacy ClientConfig/Stream API,
/// whose raw ssl() reference cannot represent a concurrently owned worker.
pub struct ManagedClientConfig {
    base: Arc<ClientConfig>,
    resolver: Arc<dyn ClientIdentityResolver>,
}
impl ManagedClientConfig {
    pub fn new(base: ClientConfig, resolver: Arc<dyn ClientIdentityResolver>) -> io::Result<Self> {
        Self::from_shared_base(Arc::new(base), resolver)
    }
    pub fn from_shared_base(
        base: Arc<ClientConfig>,
        resolver: Arc<dyn ClientIdentityResolver>,
    ) -> io::Result<Self> {
        index().map_err(io::Error::other)?;
        Ok(Self { base, resolver })
    }
    pub async fn connect<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        name: ServerName<'static>,
        io: S,
    ) -> io::Result<ManagedStream<S>> {
        self.connect_with_alpn(name, io, None).await
    }
    pub async fn connect_with_alpn<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        name: ServerName<'static>,
        io: S,
        alpn: Option<&[u8]>,
    ) -> io::Result<ManagedStream<S>> {
        let base = self.base.clone();
        let resolver = self.resolver.clone();
        let scope = base.scope.clone();
        let credits=base.connection_credits.clone();
        let result=async {
        let mut input=crate::connection_credits::ClientFactoryInput::new(base,name,alpn);
        let output = Arc::new(Mutex::new(None));
        let handoff = output.clone();
        let stream = ServerStream::prepare(io, scope, move || {
            let result=(||{
            let (mut ssl, guard) = input.configure()?;
            let selection = Arc::new(Selection {
                resolver,
                selected: Mutex::new(None),
                error: Mutex::new(None),
                guard: guard.clone(),
                sent_handshake: AtomicUsize::new(0),
            });
            unsafe {
                SSL_certs_clear(ssl.as_ptr());
                openssl_sys::SSL_ctrl(
                    ssl.as_ptr(),
                    openssl_sys::SSL_CTRL_MODE,
                    SslMode::NO_AUTO_CHAIN.bits() as _,
                    std::ptr::null_mut(),
                );
                SSL_set_cert_cb(ssl.as_ptr(), Some(select), std::ptr::null_mut());
            }
            ssl.set_ex_data(index().map_err(io::Error::other)?, selection.clone());
            let gate = selection.clone();
            let admission: Admission = Arc::new(move || gate.check().is_ok());
            let engine = ServerEngine::new_client(ssl, guard, admission)?;
            let prior = {
                handoff
                    .lock()
                    .map_err(|_| io::Error::other("managed identity handoff poisoned"))?
                    .replace(selection)
            };
            drop(prior);
            Ok(engine)
            })();input.retained(result)
        })
        .await.map_err(|e|crate::connection_credits::retain_error(e,&credits))?;
        let selection = output
            .lock()
            .map_err(|_| io::Error::other("managed identity handoff poisoned"))?
            .take()
            .ok_or_else(|| io::Error::other("managed identity handoff missing"))?;
        selection.check()?;
        if selection.guard.completed.load(Ordering::Acquire) != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "managed TLS handshake facts incomplete",
            ));
        }
        let (stream, alpn) = stream
            .inspect(|ssl| ssl.selected_alpn_protocol().unwrap_or_default().to_vec())
            .await?;
        selection.check()?;
        Ok(ManagedStream {
            stream,
            alpn,
            selection,
        })
        }.await;
        result.map_err(|e|crate::connection_credits::retain_error(e,&credits))
    }
}
pub struct ManagedStream<S> {
    stream: ServerStream<S>,
    alpn: Vec<u8>,
    selection: Arc<Selection>,
}
impl<S: AsyncRead + AsyncWrite + Unpin> ManagedStream<S> {
    pub fn get_ref(&self) -> &S {
        self.stream.get_ref()
    }
    pub fn ssl_if_idle(&self) -> Option<&SslRef> {
        self.stream.ssl()
    }
    pub fn selected_alpn_protocol(&self) -> &[u8] {
        &self.alpn
    }
    pub fn completed_handshakes(&self) -> usize {
        self.selection.guard.completed.load(Ordering::Acquire)
    }
    pub fn with_peer_certificates<T>(&self, f: impl FnOnce(&[&[u8]]) -> T) -> io::Result<T> {
        self.selection.check()?;
        let chain = self
            .selection
            .guard
            .certs
            .lock()
            .map_err(|_| io::Error::other("TLS observer state poisoned"))?
            .initial
            .clone()
            .ok_or_else(|| io::Error::other("peer certificate facts unavailable"))?;
        let mut refs = [&[][..]; 64];
        let mut count = 0;
        for cert in chain.certificates() {
            refs[count] = cert;
            count += 1;
        }
        Ok(f(&refs[..count]))
    }
}
impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for ManagedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.selection.check()?;
        let old = buf.filled().len();
        let result = Pin::new(&mut this.stream).poll_read(cx, buf);
        if let Err(error) = this.selection.check() {
            buf.filled_mut()[old..].fill(0);
            buf.set_filled(old);
            return Poll::Ready(Err(error));
        }
        result.map(|r|r.map_err(|e|this.selection.guard.retained_error(e)))
    }
}
impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for ManagedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.selection.check()?;
        let result = Pin::new(&mut this.stream).poll_write(cx, data);
        this.selection.check()?;
        result.map(|r|r.map_err(|e|this.selection.guard.retained_error(e)))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.selection.check()?;
        let result = Pin::new(&mut this.stream).poll_flush(cx);
        this.selection.check()?;
        result.map(|r|r.map_err(|e|this.selection.guard.retained_error(e)))
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.selection.check()?;
        let result = Pin::new(&mut this.stream).poll_shutdown(cx);
        this.selection.check()?;
        result.map(|r|r.map_err(|e|this.selection.guard.retained_error(e)))
    }
}
