use std::{io, pin::Pin, task::{Context, Poll}};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Observe the fixed first peer record, without parsing or implementing TLS.
pub(super) struct FirstAlertIo<S> {
    inner: S,
    first: [u8; 7],
    used: u8,
}
impl<S> FirstAlertIo<S> {
    pub(super) fn new(inner: S) -> Self { Self { inner, first: [0; 7], used: 0 } }
    pub(super) fn inner(&self) -> &S { &self.inner }
    pub(super) fn early_handshake_failure(&self, error: &io::Error) -> bool {
        self.used == 7
            && matches!(self.first, [21, 3, 1..=3, 0, 2, 2, 40])
            && matches!(error.get_ref().and_then(|e| e.downcast_ref::<rustls::Error>()),
                Some(rustls::Error::AlertReceived(rustls::AlertDescription::HandshakeFailure)))
    }
}
impl<S: AsyncRead + Unpin> AsyncRead for FirstAlertIo<S> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(cx, buf);
        if matches!(result, Poll::Ready(Ok(()))) {
            let start = usize::from(this.used);
            let count = (7 - start).min(buf.filled().len() - before);
            this.first[start..start + count].copy_from_slice(&buf.filled()[before..before + count]);
            this.used += count as u8;
        }
        result
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for FirstAlertIo<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> { Pin::new(&mut self.get_mut().inner).poll_write(cx, buf) }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> { Pin::new(&mut self.get_mut().inner).poll_flush(cx) }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> { Pin::new(&mut self.get_mut().inner).poll_shutdown(cx) }
    fn is_write_vectored(&self) -> bool { self.inner.is_write_vectored() }
    fn poll_write_vectored(self: Pin<&mut Self>, cx: &mut Context<'_>, bufs: &[io::IoSlice<'_>]) -> Poll<io::Result<usize>> { Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs) }
}
