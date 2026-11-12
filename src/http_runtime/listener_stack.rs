//! Operations preserve their configured order on each side of the TLS marker.
use crate::{net_address::NetAddress, proxy_protocol};
use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::sync::CancellationToken;
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Operation {
    Proxy(proxy_protocol::Config),
    Redirect(i64),
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Stack {
    pub before: Arc<[Operation]>,
    pub after: Arc<[Operation]>,
}
impl Stack {
    pub fn ordered(values: Vec<(usize, Operation)>, tls: Option<usize>) -> Self {
        let (mut before, mut after) = (vec![], vec![]);
        for (index, value) in values {
            if tls.is_some_and(|tls| index < tls) {
                before.push(value)
            } else {
                after.push(value)
            }
        }
        Self {
            before: before.into(),
            after: after.into(),
        }
    }
}
pub(super) trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}
pub(super) type BoxIo = Box<dyn Stream>;
/// The common empty stack remains monomorphic and performs no heap allocation.
pub(super) enum Prepared<I> {
    Direct(I),
    Wrapped(BoxIo),
}
impl<I: Stream> AsyncRead for Prepared<I> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Direct(io) => Pin::new(io).poll_read(cx, buf),
            Self::Wrapped(io) => Pin::new(io).poll_read(cx, buf),
        }
    }
}
impl<I: Stream> AsyncWrite for Prepared<I> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut *self {
            Self::Direct(io) => Pin::new(io).poll_write(cx, buf),
            Self::Wrapped(io) => Pin::new(io).poll_write(cx, buf),
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Direct(io) => Pin::new(io).poll_flush(cx),
            Self::Wrapped(io) => Pin::new(io).poll_flush(cx),
        }
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Direct(io) => Pin::new(io).poll_shutdown(cx),
            Self::Wrapped(io) => Pin::new(io).poll_shutdown(cx),
        }
    }
    fn is_write_vectored(&self) -> bool {
        match self {
            Self::Direct(io) => io.is_write_vectored(),
            Self::Wrapped(io) => io.is_write_vectored(),
        }
    }
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match &mut *self {
            Self::Direct(io) => Pin::new(io).poll_write_vectored(cx, buf),
            Self::Wrapped(io) => Pin::new(io).poll_write_vectored(cx, buf),
        }
    }
}
pub(super) async fn prepare<I: Stream + 'static>(
    io: I,
    operations: &[Operation],
    peer: &mut NetAddress,
    local: &mut NetAddress,
    deadline: Option<tokio::time::Instant>,
    cancel: CancellationToken,
) -> anyhow::Result<Prepared<I>> {
    if operations.is_empty() {
        return Ok(Prepared::Direct(io));
    }
    let mut io: BoxIo = Box::new(io);
    for operation in operations {
        match operation {
            Operation::Proxy(config) => {
                let policy = config.policy(peer)?;
                let own_deadline = config.timeout
                    .map(|duration| tokio::time::Instant::now().checked_add(duration)
                        .ok_or_else(|| anyhow::anyhow!("PROXY timeout overflow")))
                    .transpose()?;
                let limit = match (own_deadline, deadline) {
                    (Some(own), Some(outer)) => Some(own.min(outer)),
                    (Some(own), None) => Some(own),
                    (None, outer) => outer,
                };
                let prepared =
                    proxy_protocol::io::prepare(io, policy, limit, cancel.clone()).await?;
                if let Some(header) = prepared.header {
                    if let Some(source) = header.source {
                        *peer = source.into();
                    }
                    if let Some(destination) = header.destination {
                        *local = destination.into();
                    }
                }
                io = Box::new(prepared.io);
            }
            Operation::Redirect(maximum) => {
                io = Box::new(
                    super::http_redirect::prepare(io, Some(*maximum), deadline, cancel.clone())
                        .await?,
                )
            }
        }
    }
    Ok(Prepared::Wrapped(io))
}
