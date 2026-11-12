//! Owned system TCP or per-question configured DNS exchange stream.
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures_io::{AsyncRead, AsyncWrite};
use hickory_resolver::net::runtime::{DnsTcpStream, RuntimeProvider, TokioRuntimeProvider};

/// Tokio 运行时提供的真实 TCP 类型（AsyncIoTokioAsStd<TcpStream>）。
pub type BaseTcp = <TokioRuntimeProvider as RuntimeProvider>::Tcp;

pub struct DnsStream {
    inner: Inner,
}

enum Inner {
    Direct(BaseTcp),
    Exchange(super::proxy_dns_exchange::ExchangeStream),
}

impl DnsStream {
    pub(super) fn exchange(
        dial: super::proxy_dns_exchange::Exchange,
        logical: SocketAddr,
        timeout: std::time::Duration,
        stop: tokio_util::sync::CancellationToken,
    ) -> Self {
        Self {
            inner: Inner::Exchange(super::proxy_dns_exchange::ExchangeStream::new(
                dial, logical, timeout, stop,
            )),
        }
    }

    /// 系统 resolver 原路径：直接透传真实 TCP。
    pub fn direct(tcp: BaseTcp) -> Self {
        Self {
            inner: Inner::Direct(tcp),
        }
    }
}

impl AsyncRead for DnsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        match &mut self.get_mut().inner {
            Inner::Direct(tcp) => Pin::new(tcp).poll_read(cx, buf),
            Inner::Exchange(r) => Pin::new(r).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for DnsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut self.get_mut().inner {
            Inner::Direct(tcp) => Pin::new(tcp).poll_write(cx, buf),
            Inner::Exchange(r) => Pin::new(r).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.get_mut().inner {
            Inner::Direct(tcp) => Pin::new(tcp).poll_flush(cx),
            Inner::Exchange(r) => Pin::new(r).poll_flush(cx),
        }
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.get_mut().inner {
            Inner::Direct(tcp) => Pin::new(tcp).poll_close(cx),
            Inner::Exchange(r) => Pin::new(r).poll_close(cx),
        }
    }
}

impl DnsTcpStream for DnsStream {
    type Time = <TokioRuntimeProvider as RuntimeProvider>::Timer;
}
