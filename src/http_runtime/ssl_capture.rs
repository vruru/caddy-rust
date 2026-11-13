//! A temporary exact-wire ClientHello replay for the alternate SSL engine.
//! Rustls keeps its own authoritative Accepted state. The ordinary path drops
//! this duplicate immediately after policy selection, before continuing TLS.
use std::{
    io,
    pin::Pin,
    sync::atomic::{AtomicUsize, Ordering},
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
const MAX_PREFIX: usize = 1024 * 1024;
const CAPACITY: usize = 64 * 1024 * 1024;
static USED: AtomicUsize = AtomicUsize::new(0);
struct Credit(usize);
impl Credit {
    fn reserve(n: usize) -> io::Result<Self> {
        USED.try_update(Ordering::AcqRel, Ordering::Acquire, |old| {
            old.checked_add(n).filter(|v| *v <= CAPACITY)
        })
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::OutOfMemory,
                "TLS ClientHello replay capacity exhausted",
            )
        })?;
        Ok(Self(n))
    }
}
impl Drop for Credit {
    fn drop(&mut self) {
        USED.fetch_sub(self.0, Ordering::AcqRel);
    }
}
struct Storage {
    bytes: Vec<u8>,
    _credit: Credit,
}
#[derive(Clone, Copy)]
enum Mode {
    Record,
    Replay(usize),
    Off,
}
pub(super) struct CaptureIo<I> {
    inner: I,
    mode: Mode,
    storage: Option<Storage>,
}
impl<I> CaptureIo<I> {
    pub(super) fn new(inner: I) -> Self {
        Self {
            inner,
            mode: Mode::Record,
            storage: None,
        }
    }
    pub(super) fn discard(&mut self) {
        self.mode = Mode::Off;
        drop(self.storage.take())
    }
    pub(super) fn replay(mut self) -> Self {
        self.mode = if self.storage.is_some() {
            Mode::Replay(0)
        } else {
            Mode::Off
        };
        self
    }
    fn record(&mut self, data: &[u8]) -> io::Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        let old = self.storage.as_ref().map_or(0, |v| v.bytes.len());
        let size = old
            .checked_add(data.len())
            .filter(|v| *v <= MAX_PREFIX)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::OutOfMemory,
                    "TLS ClientHello replay prefix outside bounds",
                )
            })?;
        if self
            .storage
            .as_ref()
            .is_some_and(|v| v.bytes.capacity() >= size)
        {
            self.storage
                .as_mut()
                .expect("storage checked")
                .bytes
                .extend_from_slice(data);
            return Ok(());
        }
        let capacity = size.next_power_of_two().min(MAX_PREFIX);
        let credit = Credit::reserve(capacity + 64)?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(capacity).map_err(|_| {
            io::Error::new(
                io::ErrorKind::OutOfMemory,
                "TLS ClientHello replay allocation failed",
            )
        })?;
        if let Some(old) = &self.storage {
            bytes.extend_from_slice(&old.bytes)
        }
        bytes.extend_from_slice(data);
        // A new full allocation is prepaid while the old allocation is still live.
        // Destroy old data before its own credit; no realloc peak is hidden.
        let previous = self.storage.replace(Storage {
            bytes,
            _credit: credit,
        });
        drop(previous);
        Ok(())
    }
}
impl<I: AsyncRead + Unpin> AsyncRead for CaptureIo<I> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if let Mode::Replay(offset) = self.mode {
            let storage = self.storage.as_ref().expect("replay owner");
            let n = out.remaining().min(storage.bytes.len() - offset);
            out.put_slice(&storage.bytes[offset..offset + n]);
            let next = offset + n;
            if next == storage.bytes.len() {
                self.discard()
            } else {
                self.mode = Mode::Replay(next)
            }
            return Poll::Ready(Ok(()));
        }
        let before = out.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, out);
        if matches!(self.mode, Mode::Record) && matches!(result, Poll::Ready(Ok(()))) {
            if let Err(e) = self.record(&out.filled()[before..]) {
                out.filled_mut()[before..].fill(0);
                out.set_filled(before);
                return Poll::Ready(Err(e));
            }
        }
        result
    }
}
impl<I: AsyncWrite + Unpin> AsyncWrite for CaptureIo<I> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, data)
    }
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
    fn poll_write_vectored(
        mut self: Pin<&mut Self>, cx: &mut Context<'_>, bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
