//! One opt-in protocol owner, polled by the existing H2 stream future.
use super::SendBuf;
use crate::{body::Body, common::time::Time, ext::ResponseWriteOwner, rt::Sleep};
use bytes::{Buf, Bytes};
use std::{
    any::Any,
    error::Error as StdError,
    pin::Pin,
    task::{Context, Poll},
    time::Instant,
};

pub(super) fn deadline_policy(owner: &ResponseWriteOwner) -> h2::ext::DataWriteDeadline {
    let p = owner.policy();
    let s = owner.snapshot();
    h2::ext::DataWriteDeadline {
        installed: p.installed,
        idle: p.idle,
        minimum_rate: p.minimum_rate,
        hard: p.hard,
        pending_since: s.pending_since.expect("actual transport boundary"),
        last_flush: s.last_flush,
        flushed_before: s.flushed_bytes,
    }
}
pub(super) fn compiled_policy(owner:&ResponseWriteOwner)->Result<h2::ext::DataWritePolicy,crate::ext::WriteControlError>{
    Ok(match owner.scoped_boundary()?{Some(scope)=>h2::ext::DataWritePolicy::Scoped(scope),None=>h2::ext::DataWritePolicy::Scalar(deadline_policy(owner))})
}
pub(super) struct Controlled<D: Buf> {
    owner: ResponseWriteOwner,
    take_bytes: fn(&mut D) -> Option<Bytes>,
    timer: Time,
    sleep: Option<Pin<Box<dyn Sleep>>>,
    sleep_at: Option<Instant>,
    receipt: Option<h2::ext::DataWriteReceipt<SendBuf<D>>>,
    reported: usize,
    wire_seen: Option<Instant>,
    chunk: Option<(Bytes, bool)>,
    ended: bool,
}
impl<D: Buf> Controlled<D> {
    pub(super) fn new(
        owner: ResponseWriteOwner,
        timer: Time,
        header: Option<h2::ext::DataWriteReceipt<SendBuf<D>>>,
        ended: bool,
    ) -> Self
    where
        D: 'static,
    {
        fn take<D: 'static>(data: &mut D) -> Option<Bytes> {
            (data as &mut dyn Any)
                .downcast_mut::<Bytes>()
                .map(std::mem::take)
        }
        Self {
            owner,
            take_bytes: take::<D>,
            timer,
            sleep: None,
            sleep_at: None,
            receipt: header,
            reported: 0,
            wire_seen: None,
            chunk: None,
            ended,
        }
    }
    fn error(e: impl Into<Box<dyn StdError + Send + Sync>>) -> crate::Error {
        crate::Error::new_body_write(e)
    }
    fn poll_deadline(&mut self, cx: &mut Context<'_>) -> Poll<crate::Result<()>> {
        let at = match self.owner.deadline() {
            Ok(at) => at,
            Err(e) => return Poll::Ready(Err(Self::error(e))),
        };
        let Some(at) = at else {
            self.sleep = None;
            self.sleep_at = None;
            return Poll::Pending;
        };
        if self.timer.now() >= at {
            self.owner.expire();
            return Poll::Ready(Err(Self::error("HTTP/2 response write deadline expired")));
        }
        if self.sleep_at != Some(at) {
            match &self.timer {
                Time::Empty => {
                    self.owner.abandon();
                    return Poll::Ready(Err(Self::error(
                        "HTTP/2 response write policy requires a timer",
                    )));
                }
                Time::Timer(timer) => {
                    if let Some(sleep) = self.sleep.as_mut() {
                        timer.reset(sleep, at)
                    } else {
                        self.sleep = Some(timer.sleep_until(at));
                    }
                }
            }
            self.sleep_at = Some(at);
        }
        if self
            .sleep
            .as_mut()
            .expect("armed timer")
            .as_mut()
            .poll(cx)
            .is_ready()
        {
            self.owner.expire();
            return Poll::Ready(Err(Self::error("HTTP/2 response write deadline expired")));
        }
        Poll::Pending
    }
    pub(super) fn owner(&self) -> &ResponseWriteOwner { &self.owner }
    pub(super) fn set_header(&mut self, receipt: h2::ext::DataWriteReceipt<SendBuf<D>>, ended: bool) {
        debug_assert!(self.receipt.is_none());
        self.receipt = Some(receipt); self.ended = ended;
    }
    /// A header-only wait uses the existing stream task and its one timer.
    pub(super) fn poll_header(&mut self, cx: &mut Context<'_>) -> Poll<crate::Result<()>> {
            if let Some(receipt) = self.receipt.as_ref() {
                let mut state = receipt.snapshot();
                // Register before checking the absolute deadline, then re-read to
                // account for a physical flush racing timer wakeup.
                if state.outcome.is_none() {
                    if let Poll::Ready(next) = receipt.poll_progress(cx, state.version) {
                        state = next;
                    }
                }
                if state.expired {
                    self.owner.expire();
                }
                let new_wire = state
                    .last_flush
                    .is_some_and(|at| self.wire_seen.is_none_or(|old| at > old));
                if state.flushed_bytes > self.reported {
                    self.owner
                        .flushed(
                            state.flushed_bytes - self.reported,
                            state.last_flush.expect("physical payload progress"),
                        )
                        .map_err(Self::error)?;
                    self.reported = state.flushed_bytes;
                } else if new_wire && self.owner.snapshot().pending_since.is_some() {
                    self.owner
                        .wire_flushed(state.last_flush.expect("actual wire progress"))
                        .map_err(Self::error)?;
                }
                self.wire_seen = state.last_flush;
                if state.expired {
                    return Poll::Ready(Err(Self::error(
                        "HTTP/2 actual flush exceeded response deadline",
                    )));
                }
                if state.wire_complete {
                    if self.owner.snapshot().pending_since.is_some() {
                        self.owner
                            .flushed(0, state.last_flush.expect("completed wire boundary"))
                            .map_err(Self::error)?;
                    }
                    self.receipt = None;
                    self.reported = 0;
                    self.wire_seen = None;
                    return Poll::Ready(Ok(()));
                } else {
                    if matches!(state.outcome, Some(h2::ext::SendOutcome::Abandoned)) {
                        return Poll::Ready(Err(Self::error("HTTP/2 response boundary abandoned")));
                    }
                    // Payload may finish before framing (e.g. a continuation or
                    // future padding). Keep that real zero-payload tail pending.
                    if self.owner.snapshot().pending_since.is_none() {
                        self.owner
                            .start_boundary(0, state.last_flush.unwrap_or_else(|| self.timer.now()))
                            .map_err(Self::error)?;
                    }
                    if let Poll::Ready(result) = self.poll_deadline(cx) {
                        return Poll::Ready(result);
                    }
                    return Poll::Pending;
                }
            }

        if let Poll::Ready(result) = self.poll_deadline(cx) { return Poll::Ready(result); }
        Poll::Ready(Ok(()))
    }
    pub(super) fn poll<S>(
        &mut self,
        mut body: Pin<&mut S>,
        tx: &mut h2::SendStream<SendBuf<D>>,
        cx: &mut Context<'_>,
    ) -> Poll<crate::Result<()>>
    where
        S: Body<Data = D>,
        S::Error: Into<Box<dyn StdError + Send + Sync>>,
    {
        let result = self.poll_inner(body.as_mut(), tx, cx);
        if matches!(&result, Poll::Ready(Err(_))) {
            // Drop the receipt only after send_reset releases its stream/store lock.
            // Actual queued/codec tails retain payload and metadata independently.
            tx.send_reset(h2::Reason::CANCEL);
            self.receipt = None;
            self.chunk = None;
            self.owner.abandon();
        }
        result
    }
    fn poll_inner<S>(
        &mut self,
        mut body: Pin<&mut S>,
        tx: &mut h2::SendStream<SendBuf<D>>,
        cx: &mut Context<'_>,
    ) -> Poll<crate::Result<()>>
    where
        S: Body<Data = D>,
        S::Error: Into<Box<dyn StdError + Send + Sync>>,
    {
        loop {
            if let Poll::Ready(reset) = tx.poll_reset(cx).map_err(Self::error)? {
                return Poll::Ready(Err(Self::error(h2::Error::from(reset))));
            }
            match self.poll_header(cx) {
                Poll::Ready(Ok(())) => {},
                result => return result,
            }
            if self.ended {
                self.owner.finish().map_err(Self::error)?;
                return Poll::Ready(Ok(()));
            }

            if let Poll::Ready(result) = self.poll_deadline(cx) {
                return Poll::Ready(result);
            }
            if let Some((chunk, is_eos)) = self.chunk.as_mut() {
                // A bounded DATA operation begins before flow-control wait. It
                // remains pending across partial physical fragments.
                let n = chunk.len().min(16 << 10);
                if self.owner.snapshot().pending_since.is_none() {
                    self.owner
                        .start_boundary(n, self.timer.now())
                        .map_err(Self::error)?;
                }
                if n != 0 {
                    tx.reserve_capacity(1);
                    while tx.capacity() == 0 {
                        match tx.poll_capacity(cx) {
                            Poll::Ready(Some(Ok(0))) => {}
                            Poll::Ready(Some(Ok(_))) => break,
                            Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(Self::error(e))),
                            Poll::Ready(None) => {
                                return Poll::Ready(Err(Self::error(
                                    "HTTP/2 response capacity closed",
                                )))
                            }
                            Poll::Pending => {
                                if let Poll::Ready(result) = self.poll_deadline(cx) {
                                    return Poll::Ready(result);
                                }
                                return Poll::Pending;
                            }
                        }
                    }
                }
                let data = chunk.split_to(n);
                let end = *is_eos && chunk.is_empty();
                if chunk.is_empty() {
                    self.chunk = None;
                }
                let receipt = tx
                    .send_data_observed_with_policy(
                        SendBuf::Observed(data.clone()),
                        end,
                        data,
                        self.owner.retention(),
                        Some(compiled_policy(&self.owner).map_err(Self::error)?),
                    )
                    .map_err(Self::error)?;
                self.receipt = Some(receipt);
                self.ended = end;
                continue;
            }
            match body.as_mut().poll_frame(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(crate::Error::new_user_body(e)))
                }
                Poll::Ready(Some(Ok(frame))) => {
                    match frame.into_data() {
                        Ok(mut data) => {
                            // Only concrete Bytes ownership can be retained with
                            // no speculative copy or arbitrary Buf destructor.
                            let Some(data) = (self.take_bytes)(&mut data) else {
                                return Poll::Ready(Err(Self::error(
                                    "HTTP/2 controlled response requires Bytes data",
                                )));
                            };
                            let end = body.is_end_stream();
                            self.chunk = Some((data, end));
                        }
                        Err(frame) => {
                            if let Ok(trailers) = frame.into_trailers() {
                                self.owner
                                    .start_boundary(0, self.timer.now())
                                    .map_err(Self::error)?;
                                self.receipt = Some(
                                    tx.send_trailers_observed_with_policy(
                                        trailers,
                                        self.owner.retention(),
                                        Some(compiled_policy(&self.owner).map_err(Self::error)?),
                                    )
                                    .map_err(Self::error)?,
                                );
                                self.ended = true;
                            }
                        }
                    }
                }
                Poll::Ready(None) => {
                    self.chunk = Some((Bytes::new(), true));
                }
            }
        }
    }
}
