//! Per-operation TCP deadlines, including bytes used by a TLS handshake.
use hyper::rt::{Read, ReadBufCursor, Write};
use hyper_util::client::legacy::connect::{Connected, Connection};
use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::Sleep;

pub(super) struct TimeoutIo<T> {
    inner: T,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
    read_timer: Option<Pin<Box<Sleep>>>,
    write_timer: Option<Pin<Box<Sleep>>>,
}
impl<T> TimeoutIo<T> {
    pub(super) fn new(inner: T, read: Option<Duration>, write: Option<Duration>) -> Self {
        Self {
            inner,
            read_timeout: read.filter(|d| !d.is_zero()),
            write_timeout: write.filter(|d| !d.is_zero()),
            read_timer: None,
            write_timer: None,
        }
    }
}
fn timed<T, R>(
    inner: Pin<&mut T>,
    timer: &mut Option<Pin<Box<Sleep>>>,
    timeout: Option<Duration>,
    cx: &mut Context<'_>,
    operation: impl FnOnce(Pin<&mut T>, &mut Context<'_>) -> Poll<io::Result<R>>,
) -> Poll<io::Result<R>> {
    let expired = timer
        .as_mut()
        .is_some_and(|sleep| sleep.as_mut().poll(cx).is_ready());
    if expired {
        *timer = None;
        return Poll::Ready(Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "upstream I/O deadline exceeded",
        )));
    }
    match operation(inner, cx) {
        Poll::Ready(result) => {
            *timer = None;
            Poll::Ready(result)
        }
        Poll::Pending => {
            if timer.is_none()
                && let Some(duration) = timeout
            {
                *timer = Some(Box::pin(tokio::time::sleep(duration)));
            }
            if timer
                .as_mut()
                .is_some_and(|sleep| sleep.as_mut().poll(cx).is_ready())
            {
                *timer = None;
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "upstream I/O deadline exceeded",
                )))
            } else {
                Poll::Pending
            }
        }
    }
}
impl<T: Read + Unpin> Read for TimeoutIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        let Self {
            inner,
            read_timeout,
            read_timer,
            ..
        } = self.get_mut();
        timed(
            Pin::new(inner),
            read_timer,
            *read_timeout,
            cx,
            |inner, cx| inner.poll_read(cx, buf),
        )
    }
}
impl<T: Write + Unpin> Write for TimeoutIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let Self {
            inner,
            write_timeout,
            write_timer,
            ..
        } = self.get_mut();
        timed(
            Pin::new(inner),
            write_timer,
            *write_timeout,
            cx,
            |inner, cx| inner.poll_write(cx, buf),
        )
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let Self {
            inner,
            write_timeout,
            write_timer,
            ..
        } = self.get_mut();
        timed(
            Pin::new(inner),
            write_timer,
            *write_timeout,
            cx,
            |inner, cx| inner.poll_flush(cx),
        )
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let Self {
            inner,
            write_timeout,
            write_timer,
            ..
        } = self.get_mut();
        timed(
            Pin::new(inner),
            write_timer,
            *write_timeout,
            cx,
            |inner, cx| inner.poll_shutdown(cx),
        )
    }
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let Self {
            inner,
            write_timeout,
            write_timer,
            ..
        } = self.get_mut();
        timed(
            Pin::new(inner),
            write_timer,
            *write_timeout,
            cx,
            |inner, cx| inner.poll_write_vectored(cx, bufs),
        )
    }
}
impl<T: Connection> Connection for TimeoutIo<T> {
    fn connected(&self) -> Connected {
        self.inner.connected()
    }
}
