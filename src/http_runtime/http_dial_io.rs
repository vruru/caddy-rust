//! A TCP or Unix stream behind the same HTTP pooling and timeout machinery.
use hyper::rt::{Read, ReadBufCursor, Write};
use hyper_util::{
    client::legacy::connect::{Connected, Connection},
    rt::TokioIo,
};
use std::{
    io::{self, IoSlice},
    pin::Pin,
    task::{Context, Poll},
};
pub(super) trait AsyncIo:tokio::io::AsyncRead+tokio::io::AsyncWrite+Send+Unpin{}
impl<T:tokio::io::AsyncRead+tokio::io::AsyncWrite+Send+Unpin> AsyncIo for T{}
pub(super) enum DialIo {
    Tcp(TokioIo<tokio::net::TcpStream>),
    Limited{inner:Box<DialIo>,_connection:std::sync::Arc<tokio::sync::OwnedSemaphorePermit>},
    Tunnel{io:TokioIo<Box<dyn AsyncIo>>,proxied:bool},
    #[cfg(unix)]
    Unix(TokioIo<tokio::net::UnixStream>),
}
impl std::fmt::Debug for DialIo{fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{f.write_str("UpstreamDialIo")}}
impl Read for DialIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(io) => Pin::new(io).poll_read(cx, buf),
            Self::Limited{inner,..}=>Pin::new(inner.as_mut()).poll_read(cx,buf),
            Self::Tunnel{io,..}=>Pin::new(io).poll_read(cx,buf),
            #[cfg(unix)]
            Self::Unix(io) => Pin::new(io).poll_read(cx, buf),
        }
    }
}
impl Write for DialIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Tcp(io) => Pin::new(io).poll_write(cx, buf),
            Self::Limited{inner,..}=>Pin::new(inner.as_mut()).poll_write(cx,buf),
            Self::Tunnel{io,..}=>Pin::new(io).poll_write(cx,buf),
            #[cfg(unix)]
            Self::Unix(io) => Pin::new(io).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(io) => Pin::new(io).poll_flush(cx),
            Self::Limited{inner,..}=>Pin::new(inner.as_mut()).poll_flush(cx),
            Self::Tunnel{io,..}=>Pin::new(io).poll_flush(cx),
            #[cfg(unix)]
            Self::Unix(io) => Pin::new(io).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(io) => Pin::new(io).poll_shutdown(cx),
            Self::Limited{inner,..}=>Pin::new(inner.as_mut()).poll_shutdown(cx),
            Self::Tunnel{io,..}=>Pin::new(io).poll_shutdown(cx),
            #[cfg(unix)]
            Self::Unix(io) => Pin::new(io).poll_shutdown(cx),
        }
    }
    fn is_write_vectored(&self) -> bool {
        match self {
            Self::Tcp(io) => io.is_write_vectored(),
            Self::Limited{inner,..}=>inner.is_write_vectored(),
            Self::Tunnel{io,..}=>io.is_write_vectored(),
            #[cfg(unix)]
            Self::Unix(io) => io.is_write_vectored(),
        }
    }
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Tcp(io) => Pin::new(io).poll_write_vectored(cx, buf),
            Self::Limited{inner,..}=>Pin::new(inner.as_mut()).poll_write_vectored(cx,buf),
            Self::Tunnel{io,..}=>Pin::new(io).poll_write_vectored(cx,buf),
            #[cfg(unix)]
            Self::Unix(io) => Pin::new(io).poll_write_vectored(cx, buf),
        }
    }
}
impl Connection for DialIo {
    fn connected(&self) -> Connected {
        match self {
            Self::Tcp(io) => io.connected(),
            Self::Limited{inner,..}=>inner.connected(),
            Self::Tunnel{proxied,..}=>Connected::new().proxy(*proxied),
            #[cfg(unix)]
            Self::Unix(_) => Connected::new(),
        }
    }
}
