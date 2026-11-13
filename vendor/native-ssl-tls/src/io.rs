use crate::Guard;
use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
pub(crate) struct GuardedIo<S> {
    pub(crate) inner: S,
    pub(crate) guard: Arc<Guard>,
}
pub struct Stream<S> {
    pub(crate) inner: tokio_openssl::SslStream<GuardedIo<S>>,
    pub(crate) guard: Arc<Guard>,
}
// The lower wrapper prevents SSL_write from sending application ciphertext
// after a callback vetoes a handshake. The upper wrapper prevents SSL_read
// from exposing plaintext produced in the same poll as that veto.
macro_rules! guarded {
 ($self:ident,$cx:ident,$method:ident $(,$arg:expr)*)=>{{
  $self.guard.check()?;
  let result=Pin::new(&mut $self.inner).$method($cx $(,$arg)*);
  $self.guard.check()?;
  result.map(|r|r.map_err(|e|$self.guard.retained_error(e)))
 }};
}
macro_rules! impl_io {
    ($ty:ident) => {
        impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for $ty<S> {
            fn poll_read(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                self.guard.check()?;
                let old = buf.filled().len();
                let result = Pin::new(&mut self.inner).poll_read(cx, buf);
                if let Err(e) = self.guard.check() {
                    buf.filled_mut()[old..].fill(0);
                    buf.set_filled(old);
                    return Poll::Ready(Err(e));
                }
                result.map(|r|r.map_err(|e|self.guard.retained_error(e)))
            }
        }
        impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for $ty<S> {
            fn poll_write(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<io::Result<usize>> {
                guarded!(self, cx, poll_write, buf)
            }
            fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                guarded!(self, cx, poll_flush)
            }
            fn poll_shutdown(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<io::Result<()>> {
                guarded!(self, cx, poll_shutdown)
            }
        }
    };
}
impl_io!(GuardedIo);
impl_io!(Stream);
impl<S: AsyncRead + AsyncWrite + Unpin> Stream<S> {
    pub fn get_ref(&self) -> &S {
        &self.inner.get_ref().inner
    }
    pub fn ssl(&self) -> &openssl::ssl::SslRef {
        self.inner.ssl()
    }
    pub fn completed_handshakes(&self) -> usize {
        self.guard
            .completed
            .load(std::sync::atomic::Ordering::Acquire)
    }
    /// Visits the exact peer DER bytes observed in the TLS Certificate message.
    /// No X509 re-encoding or claim about a reconstructed verified path is made.
    pub fn with_peer_certificates<T>(&self, f: impl FnOnce(&[&[u8]]) -> T) -> io::Result<T> {
        self.guard.with_peer_certificates(f)
    }
}
