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
#[derive(Debug)]
pub(super) enum DialIo {
    Tcp(TokioIo<tokio::net::TcpStream>),
    #[cfg(unix)]
    Unix(TokioIo<tokio::net::UnixStream>),
}
impl Read for DialIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(io) => Pin::new(io).poll_read(cx, buf),
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
            #[cfg(unix)]
            Self::Unix(io) => Pin::new(io).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(io) => Pin::new(io).poll_flush(cx),
            #[cfg(unix)]
            Self::Unix(io) => Pin::new(io).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(io) => Pin::new(io).poll_shutdown(cx),
            #[cfg(unix)]
            Self::Unix(io) => Pin::new(io).poll_shutdown(cx),
        }
    }
    fn is_write_vectored(&self) -> bool {
        match self {
            Self::Tcp(io) => io.is_write_vectored(),
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
            #[cfg(unix)]
            Self::Unix(io) => Pin::new(io).poll_write_vectored(cx, buf),
        }
    }
}
impl Connection for DialIo {
    fn connected(&self) -> Connected {
        match self {
            Self::Tcp(io) => io.connected(),
            #[cfg(unix)]
            Self::Unix(_) => Connected::new(),
        }
    }
}
