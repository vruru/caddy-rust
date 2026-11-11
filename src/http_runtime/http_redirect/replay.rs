use std::{
    io::{self, IoSlice},
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Retain the sniffed bytes and the original socket/admission owner.
pub(crate) struct ReplayIo<I> {
    inner: I,
    prefix: Vec<u8>,
    offset: usize,
}

impl<I> ReplayIo<I> {
    pub(crate) fn new(inner: I, prefix: Vec<u8>) -> Self {
        Self {
            inner,
            prefix,
            offset: 0,
        }
    }

    pub(super) fn plain(inner: I) -> Self {
        Self::new(inner, Vec::new())
    }
}

impl<I: AsyncRead + Unpin> AsyncRead for ReplayIo<I> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let remaining = self.prefix.len() - self.offset;
        if remaining == 0 {
            return Pin::new(&mut self.inner).poll_read(cx, buffer);
        }
        let count = remaining.min(buffer.remaining());
        buffer.put_slice(&self.prefix[self.offset..self.offset + count]);
        self.offset += count;
        Poll::Ready(Ok(()))
    }
}

impl<I: AsyncWrite + Unpin> AsyncWrite for ReplayIo<I> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffers: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, buffers)
    }
}
