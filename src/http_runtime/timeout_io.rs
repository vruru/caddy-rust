//! Per-operation TCP deadlines, including bytes used by a TLS handshake.
use futures_util::task::AtomicWaker;
use hyper::rt::{Read, ReadBufCursor, Write};
use hyper_util::client::legacy::connect::{Connected, Connection};
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::Sleep;

const CLIENT_IDLE: u64 = 1;
const CLIENT_OBSERVED: u64 = 2;

#[derive(Default)]
struct ClientReadActivity {
    // Low bits are observed/idle; the remaining bits fence each phase change.
    phase: AtomicU64,
    reader: AtomicWaker,
}
impl ClientReadActivity {
    fn notify(&self, idle: bool) {
        let changed = self
            .phase
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |old| {
                if old & CLIENT_OBSERVED != 0 && (old & CLIENT_IDLE != 0) == idle {
                    return None;
                }
                Some((old.wrapping_add(4) & !3) | CLIENT_OBSERVED | u64::from(idle))
            });
        if changed.is_ok() {
            self.reader.wake();
        }
    }
}

pub(crate) struct TimeoutIo<T> {
    inner: T,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
    read_timer: Option<Pin<Box<Sleep>>>,
    write_timer: Option<Pin<Box<Sleep>>>,
    client_read: Arc<ClientReadActivity>,
    read_phase: u64,
}
impl<T> TimeoutIo<T> {
    pub(crate) fn new(inner: T, read: Option<Duration>, write: Option<Duration>) -> Self {
        Self {
            inner,
            read_timeout: read.filter(|d| !d.is_zero()),
            write_timeout: write.filter(|d| !d.is_zero()),
            read_timer: None,
            write_timer: None,
            client_read: Arc::new(ClientReadActivity::default()),
            read_phase: 0,
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
    timed_with_expiry(inner, timer, timeout, cx, operation).0
}
fn timed_with_expiry<T, R>(
    inner: Pin<&mut T>,
    timer: &mut Option<Pin<Box<Sleep>>>,
    timeout: Option<Duration>,
    cx: &mut Context<'_>,
    operation: impl FnOnce(Pin<&mut T>, &mut Context<'_>) -> Poll<io::Result<R>>,
) -> (Poll<io::Result<R>>, bool) {
    let expired = timer
        .as_mut()
        .is_some_and(|sleep| sleep.as_mut().poll(cx).is_ready());
    if expired {
        *timer = None;
        return (
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "upstream I/O deadline exceeded",
            ))),
            true,
        );
    }
    match operation(inner, cx) {
        Poll::Ready(result) => {
            *timer = None;
            (Poll::Ready(result), false)
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
                (
                    Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "upstream I/O deadline exceeded",
                    ))),
                    true,
                )
            } else {
                (Poll::Pending, false)
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
            client_read,
            read_phase,
            ..
        } = self.get_mut();
        // Register before sampling: a phase transition must wake a read already
        // asleep on its socket/timer, including TLS-owned background reads.
        client_read.reader.register(cx.waker());
        let phase = client_read.phase.load(Ordering::Acquire);
        if phase != *read_phase {
            *read_timer = None;
            *read_phase = phase;
        }
        let timeout = if phase & (CLIENT_OBSERVED | CLIENT_IDLE) == (CLIENT_OBSERVED | CLIENT_IDLE)
        {
            None
        } else {
            *read_timeout
        };
        let (result, expired) =
            timed_with_expiry(Pin::new(inner), read_timer, timeout, cx, |inner, cx| {
                inner.poll_read(cx, buf)
            });
        let after = client_read.phase.load(Ordering::Acquire);
        if after != phase {
            *read_timer = None;
            *read_phase = after;
            // Only our old-epoch deadline can be discarded. Preserve actual
            // IO failures and bytes already consumed by a successful read.
            if expired || result.is_pending() {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        }
        result
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
        let activity = self.client_read.clone();
        self.inner
            .connected()
            .native_client_activity(hyper::ext::NativeClientActivity::new(move |idle| {
                activity.notify(idle);
            }))
    }
}
