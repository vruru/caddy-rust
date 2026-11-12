use std::future::Future;
use std::io::Cursor;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, Bytes};
use futures_channel::{mpsc, oneshot};
use futures_core::{ready, Stream};
use h2::{Reason, RecvStream, SendStream};
use pin_project_lite::pin_project;

use super::ping::Recorder;
use super::SendBuf;
use crate::rt::{Read, ReadBufCursor, Write};

pub(super) fn pair<B: Buf>(
    send_stream: SendStream<SendBuf<B>>,
    recv_stream: RecvStream,
    ping: Recorder,
) -> (H2Upgraded, UpgradedSendStreamTask<B>) {
    let (tx, rx) = mpsc::channel(1);
    let (error_tx, error_rx) = oneshot::channel();
    let (cancel_tx,cancel_rx) = oneshot::channel();

    (
        H2Upgraded {
            send_stream: UpgradedSendStreamBridge { tx, error_rx: Some(error_rx), error: None, done: false, flush: None },
            recv_stream,
            ping,
            buf: Bytes::new(),
            _retention: None,
            cancel: Some(cancel_tx),
        },
        UpgradedSendStreamTask {
            h2_tx: send_stream,
            rx,
            buffered: None,
            error_tx: Some(error_tx),
            controlled: Default::default(),
            cancel_rx,
            _retention: None,
            upgrade: Default::default(),
        },
    )
}

pub(super) struct H2Upgraded {
    ping: Recorder,
    send_stream: UpgradedSendStreamBridge,
    recv_stream: RecvStream,
    buf: Bytes,
    _retention: Option<Bytes>,
    cancel: Option<oneshot::Sender<()>>,
}

enum WriteItem { Data(Cursor<Box<[u8]>>), Flush(oneshot::Sender<()>) }
impl Drop for H2Upgraded {
    fn drop(&mut self) {
        // An unfinished IO drop is cancellation, not an application half-close.
        // The actor polls this concrete channel even while a receipt is blocked.
        if let Some(cancel)=self.cancel.take(){let _=cancel.send(());}
    }
}
struct UpgradedSendStreamBridge {
    tx: mpsc::Sender<WriteItem>,
    error_rx: Option<oneshot::Receiver<crate::Error>>,
    error: Option<std::sync::Arc<crate::Error>>,
    done: bool,
    flush: Option<oneshot::Receiver<()>>,
}
impl UpgradedSendStreamBridge {
    fn poll_error(&mut self, cx: &mut Context<'_>) -> Option<std::io::Error> {
        if let Some(rx) = self.error_rx.as_mut() {
            match Pin::new(rx).poll(cx) {
                Poll::Ready(result) => {
                    self.done = true;
                    self.error_rx = None;
                    self.error = result.ok().map(std::sync::Arc::new);
                }
                Poll::Pending => {}
            }
        }
        self.error.as_ref().map(|e|std::io::Error::new(std::io::ErrorKind::Other,e.clone()))
    }
}

#[cfg(feature="server")]
type DeferredUpgrade = Option<(crate::upgrade::Pending,H2Upgraded)>;
#[cfg(not(feature="server"))]
type DeferredUpgrade = ();

pin_project! {
    #[must_use = "futures do nothing unless polled"]
    pub struct UpgradedSendStreamTask<B>
    where B: Buf,
    {
        #[pin]
        h2_tx: SendStream<SendBuf<B>>,
        #[pin]
        rx: mpsc::Receiver<WriteItem>,
        buffered: Option<Cursor<Box<[u8]>>>,
        error_tx: Option<oneshot::Sender<crate::Error>>,
        controlled: super::OptControlled<B>,
        cancel_rx: oneshot::Receiver<()>,
        _retention: Option<Bytes>,
        upgrade: DeferredUpgrade,
    }
}

// ===== impl UpgradedSendStreamTask =====

impl<B> UpgradedSendStreamTask<B>
where
    B: Buf,
{
    #[cfg(feature="server")]
    pub(super) fn with_controlled(mut self, controlled: Box<super::response_write::Controlled<B>>, pending: crate::upgrade::Pending, mut upgraded: H2Upgraded) -> Self {
        let retention = controlled.owner().retention();
        upgraded._retention = retention.clone();
        self._retention = retention;
        self.controlled = Some(controlled);
        self.upgrade = Some((pending,upgraded));
        self
    }
    fn tick(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), crate::Error>> {
        let mut me = self.project();

        // this is a manual `select()` over 3 "futures", so we always need
        // to be sure they are ready and/or we are waiting notification of
        // one of the sides hanging up, so the task doesn't live around
        // longer than it's meant to.
        loop {
            if Pin::new(&mut *me.cancel_rx).poll(cx).is_ready() {
                me.h2_tx.send_reset(Reason::CANCEL);
                return Poll::Ready(Err(crate::Error::new_body_write("CONNECT upgraded IO cancelled")));
            }
            #[cfg(feature="server")]
            if let Some(writer) = me.controlled.as_mut() {
                // Header and payload use the same unique owner. The existing
                // upgrade actor is the only producer; no per-frame task exists.
                if me.upgrade.as_mut().is_some_and(|(pending,_)|pending.poll_closed(cx).is_ready()) {
                    return Poll::Ready(Err(crate::Error::new_body_write("CONNECT upgrade consumer cancelled")));
                }
                if ready!(writer.poll_output(&mut me.h2_tx, cx))? { return Poll::Ready(Ok(())); }
                if let Some((pending,upgraded)) = me.upgrade.take() {
                    if !pending.fulfill_checked(crate::upgrade::Upgraded::new(upgraded,Bytes::new())) {
                        return Poll::Ready(Err(crate::Error::new_body_write("CONNECT upgrade consumer cancelled")));
                    }
                }
                match me.rx.as_mut().poll_next(cx) {
                    Poll::Ready(Some(WriteItem::Data(cursor))) => writer.queue_output(Bytes::from(cursor.into_inner()),false),
                    Poll::Ready(Some(WriteItem::Flush(ack))) => { let _ = ack.send(()); },
                    Poll::Ready(None) => writer.queue_output(Bytes::new(),true),
                    Poll::Pending => return Poll::Pending,
                }
                continue;
            }
            match me.h2_tx.poll_reset(cx) {
                Poll::Ready(Ok(reason)) => {
                    trace!("stream received RST_STREAM: {:?}", reason);
                    return Poll::Ready(Err(crate::Error::new_body_write(::h2::Error::from(
                        reason,
                    ))));
                }
                Poll::Ready(Err(err)) => {
                    return Poll::Ready(Err(crate::Error::new_body_write(err)))
                }
                Poll::Pending => (),
            }

            // A write taken from the mpsc receiver waits here for h2 capacity,
            // and the next one isn't pulled until it has been handed to h2, so
            // the writer still sees h2 backpressure.
            if me.buffered.is_some() {
                // poll_capacity oddly needs a loop
                while me.h2_tx.capacity() == 0 {
                    match ready!(me.h2_tx.poll_capacity(cx)) {
                        Some(Ok(0)) => {}
                        Some(Ok(_)) => break,
                        Some(Err(e)) => return Poll::Ready(Err(crate::Error::new_body_write(e))),
                        None => {
                            // None means the stream is no longer in a
                            // streaming state, we either finished it
                            // somehow, or the remote reset us.
                            return Poll::Ready(Err(crate::Error::new_body_write(
                                "send stream capacity unexpectedly closed",
                            )));
                        }
                    }
                }

                let cursor = me.buffered.take().expect("checked is_some above");
                me.h2_tx
                    .send_data(SendBuf::Cursor(cursor), false)
                    .map_err(crate::Error::new_body_write)?;
                continue;
            }

            match me.rx.as_mut().poll_next(cx) {
                Poll::Ready(Some(WriteItem::Flush(ack))) => { let _ = ack.send(()); }
                Poll::Ready(Some(WriteItem::Data(cursor))) => {
                    // Only reserve capacity once there is something to send.
                    // Reserving while idle, even a single byte, pins that
                    // capacity on the connection-level window (#4003). As in
                    // `PipeToSendStream`, h2 raises the request to the
                    // buffered length inside `send_data`.
                    me.h2_tx.reserve_capacity(1);
                    *me.buffered = Some(cursor);
                }
                Poll::Ready(None) => {
                    me.h2_tx
                        .send_data(SendBuf::None, true)
                        .map_err(crate::Error::new_body_write)?;
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending => {
                    return Poll::Pending;
                }
            }
        }
    }
}

impl<B> Future for UpgradedSendStreamTask<B>
where
    B: Buf,
{
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.as_mut().tick(cx) {
            Poll::Ready(Ok(())) => {
                // Successful write-half completion is observable even if an
                // executor retains the completed future and its allocation.
                drop(self.error_tx.take());
                Poll::Ready(())
            },
            Poll::Ready(Err(err)) => {
                #[cfg(feature="server")]
                if self.controlled.is_some() {
                    self.h2_tx.send_reset(Reason::CANCEL);
                    // Receipt and payload guards are dropped after the store
                    // operation returns; codec tails retain their own owners.
                    self.controlled = None;
                    self.upgrade = None;
                }
                if let Some(tx) = self.error_tx.take() {
                    let _oh_well = tx.send(err);
                }
                Poll::Ready(())
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

// ===== impl H2Upgraded =====

impl Read for H2Upgraded {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut read_buf: ReadBufCursor<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        if let Some(error) = self.send_stream.poll_error(cx) { return Poll::Ready(Err(error)); }
        if self.buf.is_empty() {
            self.buf = loop {
                match ready!(self.recv_stream.poll_data(cx)) {
                    None => return Poll::Ready(Ok(())),
                    Some(Ok(buf)) if buf.is_empty() && !self.recv_stream.is_end_stream() => {}
                    Some(Ok(buf)) => {
                        self.ping.record_data(buf.len());
                        break buf;
                    }
                    Some(Err(e)) => {
                        return Poll::Ready(match e.reason() {
                            Some(Reason::NO_ERROR) | Some(Reason::CANCEL) => Ok(()),
                            Some(Reason::STREAM_CLOSED) => {
                                Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, e))
                            }
                            _ => Err(h2_to_io_error(e)),
                        })
                    }
                }
            };
        }
        let cnt = std::cmp::min(self.buf.len(), read_buf.remaining());
        read_buf.put_slice(&self.buf[..cnt]);
        self.buf.advance(cnt);
        let _ = self.recv_stream.flow_control().release_capacity(cnt);
        Poll::Ready(Ok(()))
    }
}

impl Write for H2Upgraded {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize,std::io::Error>> {
        if let Some(error) = self.send_stream.poll_error(cx) { return Poll::Ready(Err(error)); }
        if buf.is_empty() { return Poll::Ready(Ok(0)); }
        match self.send_stream.tx.poll_ready(cx) {
            Poll::Ready(Ok(())) => {},
            Poll::Ready(Err(_)) => return Poll::Ready(Err(self.send_stream.poll_error(cx).unwrap_or_else(||std::io::ErrorKind::BrokenPipe.into()))),
            Poll::Pending => return Poll::Pending,
        }
        // AsyncWrite may return a partial write. This also bounds every raw
        // mpsc payload; the one sender has at most two reserved queue slots.
        let n = buf.len().min(16 << 10);
        match self.send_stream.tx.start_send(WriteItem::Data(Cursor::new(buf[..n].into()))) {
            Ok(()) => Poll::Ready(Ok(n)),
            Err(_) => Poll::Ready(Err(self.send_stream.poll_error(cx).unwrap_or_else(||std::io::ErrorKind::BrokenPipe.into()))),
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(),std::io::Error>> {
        if let Some(error) = self.send_stream.poll_error(cx) { return Poll::Ready(Err(error)); }
        if self.send_stream.done { return Poll::Ready(Ok(())); }
        if self.send_stream.flush.is_none() {
            match self.send_stream.tx.poll_ready(cx) {
                Poll::Ready(Ok(())) => {},
                Poll::Ready(Err(_)) => return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into())),
                Poll::Pending => return Poll::Pending,
            }
            let (send,recv) = oneshot::channel();
            if self.send_stream.tx.start_send(WriteItem::Flush(send)).is_err() { return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into())); }
            self.send_stream.flush = Some(recv);
        }
        match Pin::new(self.send_stream.flush.as_mut().expect("flush installed")).poll(cx) {
            Poll::Ready(Ok(())) => { self.send_stream.flush = None; Poll::Ready(Ok(())) },
            Poll::Ready(Err(_)) => { self.send_stream.flush = None; Poll::Ready(Err(self.send_stream.poll_error(cx).unwrap_or_else(||std::io::ErrorKind::BrokenPipe.into()))) },
            Poll::Pending => Poll::Pending,
        }
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(),std::io::Error>> {
        self.send_stream.tx.close_channel();
        if let Some(error) = self.send_stream.poll_error(cx) { return Poll::Ready(Err(error)); }
        if self.send_stream.done { Poll::Ready(Ok(())) } else { Poll::Pending }
    }
}

fn h2_to_io_error(e: h2::Error) -> std::io::Error {
    if e.is_io() {
        e.into_io()
            .expect("h2 error reported io cause without an underlying io error")
    } else {
        std::io::Error::new(std::io::ErrorKind::Other, e)
    }
}
