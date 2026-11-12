//! Owned, cancel-safe PROXY header classification. Bytes consumed by a timed-out
//! optional classifier remain charged until replayed or the connection drops.
use super::frame::{self, Parsed};
use std::{
    io,
    pin::Pin,
    sync::{Arc, LazyLock},
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf},
    sync::{OwnedSemaphorePermit, Semaphore},
    time::Instant,
};
use tokio_util::sync::CancellationToken;
const SIGNATURE: &[u8; 12] = b"\r\n\r\n\0\r\nQUIT\n";
const POOL_BYTES: usize = 32 << 20;
static POOL: LazyLock<Arc<Semaphore>> = LazyLock::new(|| Arc::new(Semaphore::new(POOL_BYTES)));
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Policy {
    Ignore,
    Use,
    Reject,
    Require,
    Skip,
}
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid PROXY header")
}
fn overloaded() -> io::Error {
    io::Error::new(io::ErrorKind::OutOfMemory, "PROXY header resource limit")
}
struct Buffer {
    bytes: Vec<u8>,
    charge: Option<OwnedSemaphorePermit>,
}
impl Buffer {
    fn empty() -> Self {
        Self {
            bytes: Vec::new(),
            charge: None,
        }
    }
    fn reserve(&mut self, target: usize) -> io::Result<()> {
        let target = target.max(128);
        let peak = target
            .max(self.bytes.capacity())
            .checked_mul(2)
            .and_then(|n| n.checked_add(512))
            .ok_or_else(overloaded)?;
        let held = self
            .charge
            .as_ref()
            .map_or(0, OwnedSemaphorePermit::num_permits);
        if peak > held {
            let charge = POOL
                .clone()
                .try_acquire_many_owned(u32::try_from(peak - held).map_err(|_| overloaded())?)
                .map_err(|_| overloaded())?;
            if let Some(current) = &mut self.charge {
                current.merge(charge);
            } else {
                self.charge = Some(charge);
            }
        }
        self.bytes
            .try_reserve_exact(target.saturating_sub(self.bytes.len()))
            .map_err(|_| overloaded())?;
        Ok(())
    }
    fn release(&mut self) {
        drop(std::mem::take(&mut self.bytes));
        self.charge = None;
    }
}
pub struct Replay<I> {
    buffer: Buffer,
    offset: usize,
    inner: I,
}
impl<I: AsyncRead + Unpin> AsyncRead for Replay<I> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if this.offset < this.buffer.bytes.len() {
            let n = out.remaining().min(this.buffer.bytes.len() - this.offset);
            out.put_slice(&this.buffer.bytes[this.offset..this.offset + n]);
            this.offset += n;
            if this.offset == this.buffer.bytes.len() {
                this.buffer.release();
                this.offset = 0;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, out)
    }
}
impl<I: AsyncWrite + Unpin> AsyncWrite for Replay<I> {
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffers: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, buffers)
    }
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
pub struct Prepared<I> {
    pub io: Replay<I>,
    pub header: Option<Parsed>,
}
async fn fill<I: AsyncRead + Unpin>(
    io: &mut I,
    buffer: &mut Buffer,
    target: usize,
) -> io::Result<bool> {
    buffer.reserve(target)?;
    let mut scratch = [0u8; 4096];
    while buffer.bytes.len() < target {
        let n = (target - buffer.bytes.len()).min(scratch.len());
        let read = io.read(&mut scratch[..n]).await?;
        if read == 0 {
            return Ok(false);
        }
        buffer.bytes.extend_from_slice(&scratch[..read]);
    }
    Ok(true)
}
async fn inspect<I: AsyncRead + Unpin>(
    io: &mut I,
    buffer: &mut Buffer,
) -> io::Result<Option<Parsed>> {
    if !fill(io, buffer, 1).await? {
        return Ok(None);
    }
    match buffer.bytes[0] {
        b'P' => {
            if !fill(io, buffer, 5).await? || buffer.bytes != b"PROXY" {
                return Ok(None);
            }
            loop {
                let n = buffer.bytes.len();
                if n >= 107 {
                    return Err(invalid());
                }
                if !fill(io, buffer, n + 1).await? {
                    return Err(invalid());
                }
                if buffer.bytes.last() == Some(&b'\n') {
                    return frame::v1(&buffer.bytes).map(Some).map_err(|_| invalid());
                }
            }
        }
        b'\r' => {
            if !fill(io, buffer, 5).await? || buffer.bytes != SIGNATURE[..5] {
                return Ok(None);
            }
            if !fill(io, buffer, 12).await? || buffer.bytes != *SIGNATURE {
                return Ok(None);
            }
            if !fill(io, buffer, 16).await? {
                return Err(invalid());
            }
            let length = u16::from_be_bytes([buffer.bytes[14], buffer.bytes[15]]) as usize;
            if !fill(io, buffer, 16 + length).await? {
                return Err(invalid());
            }
            frame::v2(&buffer.bytes).map(Some).map_err(|_| invalid())
        }
        _ => Ok(None),
    }
}
pub async fn prepare<I: AsyncRead + AsyncWrite + Unpin>(
    mut io: I,
    policy: Policy,
    deadline: Option<Instant>,
    cancel: CancellationToken,
) -> io::Result<Prepared<I>> {
    if cancel.is_cancelled() {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "PROXY listener stopped",
        ));
    }
    let mut buffer = Buffer::empty();
    if policy == Policy::Skip {
        return Ok(Prepared {
            io: Replay {
                buffer,
                offset: 0,
                inner: io,
            },
            header: None,
        });
    }
    let deadline = async move {
        match deadline {
            Some(deadline) => tokio::time::sleep_until(deadline).await,
            None => std::future::pending::<()>().await,
        }
    };
    let parsed = tokio::select! {biased;
     _=cancel.cancelled()=>return Err(io::Error::new(io::ErrorKind::Interrupted,"PROXY listener stopped")),
     result=inspect(&mut io,&mut buffer)=>result?,
     _=deadline=>{if policy==Policy::Require{return Err(io::Error::new(io::ErrorKind::TimedOut,"required PROXY header timed out"));}None},
    };
    let header = if parsed.is_some() {
        if policy == Policy::Reject {
            return Err(invalid());
        }
        buffer.release();
        if matches!(policy, Policy::Use | Policy::Require) {
            parsed
        } else {
            None
        }
    } else {
        if policy == Policy::Require {
            return Err(invalid());
        }
        None
    };
    Ok(Prepared {
        io: Replay {
            buffer,
            offset: 0,
            inner: io,
        },
        header,
    })
}
