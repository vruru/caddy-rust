// Copyright 2015 Matthew Holt and The Caddy Authors.
// SPDX-License-Identifier: Apache-2.0
//! Bounded positive flush buffering. The reader belongs to the downstream body;
//! cancellation drops the reader and its credit without a detached pump.
use super::{Body, BoxError, Bytes};
use bytes::BytesMut;
use http_body_util::BodyExt;
use hyper::body::{Body as HttpBody, Frame, SizeHint};
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::sync::OwnedSemaphorePermit;
use tokio::time::Instant;

const CAPACITY: usize = 32 * 1024;

enum Next {
    Headers,
    Frame(Option<Result<Frame<Bytes>, BoxError>>),
}

struct Reader {
    body: Body,
    interval: Duration,
    deadline: Option<Instant>,
    buffer: BytesMut,
    tail: Option<Bytes>,
    pending: Option<Result<Frame<Bytes>, BoxError>>,
    eof: bool,
    _credit: OwnedSemaphorePermit,
}

impl Reader {
    fn take_data(&mut self) -> Next {
        self.deadline = None;
        Next::Frame(Some(Ok(Frame::data(self.buffer.split().freeze()))))
    }

    async fn next(&mut self, gate: bool) -> Next {
        let mut frames = 0usize;
        loop {
            if self.buffer.len() == CAPACITY {
                return self.take_data();
            }
            if self.pending.is_some() || self.eof {
                if !self.buffer.is_empty() {
                    return self.take_data();
                }
                return Next::Frame(self.pending.take());
            }
            if let Some(mut data) = self.tail.take()
                && !data.is_empty()
            {
                if self.buffer.is_empty() && self.deadline.is_none() {
                    self.deadline = Some(Instant::now() + self.interval);
                }
                let count = data.len().min(CAPACITY - self.buffer.len());
                self.buffer.extend_from_slice(&data.split_to(count));
                if !data.is_empty() {
                    self.tail = Some(data);
                }
                continue;
            }
            let next = if let Some(deadline) = self.deadline {
                tokio::select! {
                    biased;
                    _ = tokio::time::sleep_until(deadline) => {
                        self.deadline = None;
                        if !self.buffer.is_empty() {
                            return self.take_data();
                        }
                        if gate {
                            return Next::Headers;
                        }
                        continue;
                    }
                    next = self.body.frame() => next,
                }
            } else {
                self.body.frame().await
            };
            match next {
                None => self.eof = true,
                Some(Err(error)) => {
                    self.eof = true;
                    self.pending = Some(Err(error));
                }
                Some(Ok(frame)) => match frame.into_data() {
                    Ok(data) => self.tail = Some(data),
                    Err(frame) => self.pending = Some(Ok(frame)),
                },
            }
            frames += 1;
            if frames == 32 {
                frames = 0;
                tokio::task::yield_now().await;
            }
        }
    }
}

type Driver = Pin<Box<dyn Future<Output = (Reader, Next)> + Send>>;

struct FlushBody {
    reader: Option<Reader>,
    driver: Option<Driver>,
    first: Option<Next>,
    hint: SizeHint,
    done: bool,
}

impl FlushBody {
    fn deliver(&mut self, next: Next) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        match next {
            Next::Headers => unreachable!("header gate consumed before response body polling"),
            Next::Frame(None) => {
                self.done = true;
                self.hint = SizeHint::with_exact(0);
                Poll::Ready(None)
            }
            Next::Frame(Some(result)) => {
                if let Ok(frame) = &result {
                    let length = frame.data_ref().map_or(0, |data| data.len()) as u64;
                    let lower = self.hint.lower().saturating_sub(length);
                    let upper = self.hint.upper().map(|n| n.saturating_sub(length));
                    self.hint = SizeHint::new();
                    if let Some(upper) = upper {
                        self.hint.set_upper(upper);
                    }
                    self.hint.set_lower(lower);
                } else {
                    self.done = true;
                    self.hint = SizeHint::with_exact(0);
                }
                Poll::Ready(Some(result))
            }
        }
    }
}

impl HttpBody for FlushBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let this = self.get_mut();
        if this.done {
            return Poll::Ready(None);
        }
        if let Some(first) = this.first.take() {
            return this.deliver(first);
        }
        if this.driver.is_none() {
            let Some(mut reader) = this.reader.take() else {
                this.done = true;
                return Poll::Ready(None);
            };
            this.driver = Some(Box::pin(async move {
                let next = reader.next(false).await;
                (reader, next)
            }));
        }
        let Poll::Ready((reader, next)) = this
            .driver
            .as_mut()
            .expect("driver exists")
            .as_mut()
            .poll(cx)
        else {
            return Poll::Pending;
        };
        this.driver = None;
        this.reader = Some(reader);
        this.deliver(next)
    }

    fn is_end_stream(&self) -> bool {
        self.done
    }
    fn size_hint(&self) -> SizeHint {
        self.hint
    }
}

pub(super) async fn prepare(
    body: Body,
    interval: Duration,
    credit: OwnedSemaphorePermit,
) -> Result<(Body, bool), BoxError> {
    let hint = body.size_hint();
    let mut reader = Reader {
        body,
        interval,
        deadline: Some(Instant::now() + interval),
        buffer: BytesMut::with_capacity(CAPACITY),
        tail: None,
        pending: None,
        eof: false,
        _credit: credit,
    };
    let mut headers_only = false;
    let first = match reader.next(true).await {
        Next::Headers => {
            headers_only = true;
            None
        }
        next => Some(next),
    };
    Ok((
        FlushBody {
            reader: Some(reader),
            driver: None,
            first,
            hint,
            done: false,
        }
        .boxed_unsync(),
        headers_only,
    ))
}
