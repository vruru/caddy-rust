//! Buffers outgoing proxy request bodies for replay, with Go `io.CopyN` semantics.
//!
//! - `limit == 0`: never buffers.
//! - `limit < 0`: buffers to EOS.
//! - `limit > 0`: reads at most `limit` data bytes. Reaching the limit always
//!   yields a one-shot Partial, even when the size hint says EOS is there. Only
//!   a real EOS before the limit yields a replayable Full.
//!
//! No frame is lost. Over-read bytes, the remaining stream and its trailers are
//! delivered in order by the rest body.
//!
//! Memory: up to `MEMORY_PREFIX` data bytes stay in memory. They are charged,
//! together with trailers, at 2x logical size in `MEMORY_UNIT` units against the
//! process-wide prefix pool, and the charge is never awaited. The permit is owned
//! by whatever owns the buffered bytes: the Full buffer and every body it
//! produces, or the Partial rest body. It is released on the last drop, not when
//! `prepare` returns. Larger prefixes spill to an anonymous `Spool`, whose file,
//! FD and byte credits live as long as its readers.

// Paths follow the existing runtime layout; adjust if the modules live elsewhere.
use super::proxy_replay::{ReplayBuffer, ReplaySource};
use crate::http_runtime::{
    Body, BoxError, Bytes,
    fastcgi::{
        admission::MEMORY_UNIT,
        spool::{MEMORY_PREFIX, Spool, SpoolReader},
    },
    request::{Context, budget_failure, failure},
    request_body::limit_error,
    resource_budget::BudgetError,
};
use anyhow::Result;
use bytes::BytesMut;
use http::{HeaderMap, StatusCode};
use http_body_util::BodyExt;
use hyper::body::{Body as HttpBody, Frame, SizeHint};
use std::{
    collections::VecDeque,
    pin::Pin,
    sync::Arc,
    task::{self, Poll},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Upper bound for buffered trailer metadata; exceeding it is an error, never a truncation.
const MAX_TRAILERS: usize = 64 * 1024;

pub(super) async fn prepare(ctx: &mut Context, mut body: Body, limit: i64) -> Result<ReplaySource> {
    // Only a confirmed end of stream means "no body"; a zero size hint does not.
    if body.is_end_stream() {
        return Ok(ReplaySource::empty());
    }
    if limit == 0 {
        return Ok(ReplaySource::new(body));
    }
    let cap = u64::try_from(limit).ok(); // negative: read to EOS
    let mut acc = Acc {
        mem: BytesMut::new(),
        spool: None,
        len: 0,
        trailers: None,
        trailer_bytes: 0,
        charge: Charge {
            pool: ctx.resources.fastcgi_admission.prefix_memory.clone(),
            held: None,
            units: 0,
        },
    };
    loop {
        let frame = match body.frame().await {
            None => return Ok(acc.full()),
            Some(Ok(frame)) => frame,
            Some(Err(error)) => return Err(read_failure(&error)),
        };
        let mut data = match frame.into_data() {
            Ok(data) => data,
            Err(frame) => {
                acc.trailers(ctx, frame)?;
                continue;
            }
        };
        if acc.trailers.is_some() {
            // Data after trailers is not a valid HTTP body.
            return Err(failure(StatusCode::BAD_REQUEST));
        }
        if data.is_empty() {
            continue;
        }
        // Invariant: acc.len < cap, so room >= 1.
        let room = cap.map_or(u64::MAX, |cap| cap - acc.len);
        if (data.len() as u64) < room {
            acc.push(ctx, data).await?;
            continue;
        }
        // Limit reached (CopyN): keep exactly `room` bytes, hand the rest onward.
        let over = data.split_off(room as usize);
        acc.push(ctx, data).await?;
        return Ok(acc.partial(over, body));
    }
}

fn read_failure(error: &BoxError) -> anyhow::Error {
    failure(if limit_error(error.as_ref()) {
        StatusCode::PAYLOAD_TOO_LARGE
    } else {
        StatusCode::BAD_REQUEST
    })
}

/// RAII share of the process-wide prefix memory pool. Dropping it releases all credits.
struct Charge {
    pool: Arc<Semaphore>,
    held: Option<OwnedSemaphorePermit>,
    units: u64,
}

impl Charge {
    /// Grows the reservation to cover `logical` bytes at 2x. Never waits.
    fn cover(&mut self, ctx: &mut Context, logical: u64) -> Result<()> {
        let units = logical.saturating_mul(2).div_ceil(MEMORY_UNIT);
        if units <= self.units {
            return Ok(());
        }
        let permit = u32::try_from(units - self.units)
            .ok()
            .and_then(|n| self.pool.clone().try_acquire_many_owned(n).ok())
            .ok_or_else(|| budget_failure(ctx, BudgetError::Overloaded))?;
        match self.held.as_mut() {
            Some(held) => held.merge(permit),
            None => self.held = Some(permit),
        }
        self.units = units;
        Ok(())
    }

    fn release(&mut self) {
        self.held = None;
        self.units = 0;
    }
}

struct Acc {
    mem: BytesMut,
    spool: Option<Spool>,
    len: u64,
    trailers: Option<HeaderMap>,
    trailer_bytes: u64,
    charge: Charge,
}

impl Acc {
    async fn push(&mut self, ctx: &mut Context, data: Bytes) -> Result<()> {
        self.len = self
            .len
            .checked_add(data.len() as u64)
            .ok_or_else(|| failure(StatusCode::PAYLOAD_TOO_LARGE))?;
        let need = self.mem.len() + data.len();
        let spool = match &mut self.spool {
            Some(spool) => spool,
            None if need <= MEMORY_PREFIX => {
                // No trailers can exist yet: data after trailers was rejected.
                self.charge.cover(ctx, need as u64)?;
                grow(&mut self.mem, need);
                self.mem.extend_from_slice(&data);
                return Ok(());
            }
            slot => {
                let mut spool = Spool::create(ctx).await?;
                let prefix = std::mem::take(&mut self.mem).freeze();
                if !prefix.is_empty() {
                    spool.append(ctx, prefix).await?;
                }
                // The in-memory copy is gone; spool credits now account for it.
                self.charge.release();
                slot.insert(spool)
            }
        };
        spool.append(ctx, data).await
    }

    fn trailers(&mut self, ctx: &mut Context, frame: Frame<Bytes>) -> Result<()> {
        // A valid body carries at most one trailers frame, and it is the final frame.
        let Ok(map) = frame.into_trailers() else {
            return Err(failure(StatusCode::BAD_REQUEST));
        };
        if self.trailers.is_some() {
            return Err(failure(StatusCode::BAD_REQUEST));
        }
        let size = map.iter().fold(0usize, |n, (k, v)| {
            n.saturating_add(k.as_str().len() + v.len())
        });
        if size > MAX_TRAILERS {
            return Err(failure(StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE));
        }
        self.trailer_bytes = size as u64;
        self.charge
            .cover(ctx, self.mem.len() as u64 + self.trailer_bytes)?;
        self.trailers = Some(map);
        Ok(())
    }

    /// A real EOS arrived before the limit, so the entity is complete and replayable.
    fn full(self) -> ReplaySource {
        let data = match self.spool {
            Some(spool) => Data::Spool(spool.reader()),
            None => Data::Memory(self.mem.freeze()),
        };
        ReplaySource::buffered(Arc::new(Full {
            data,
            len: self.len,
            trailers: self.trailers,
            credit: Arc::new(self.charge),
        }))
    }

    /// The limit was reached. Returns a one-shot source: prefix, then over-read
    /// bytes, then the rest of the original stream (including its trailers).
    fn partial(self, over: Bytes, rest: Body) -> ReplaySource {
        match self.spool {
            None => {
                let rest = Seq::boxed(
                    [Part::Data(over), Part::Body(rest, None)].into(),
                    Some(Arc::new(self.charge)),
                );
                ReplaySource::partial(self.mem.freeze(), rest)
            }
            Some(spool) => {
                // Spilled prefix: the reader owns the file and spool credits.
                let reader = spool.reader();
                let len = reader.len();
                ReplaySource::new(Seq::boxed(
                    [
                        Part::Body(reader.into_body(), Some(len)),
                        Part::Data(over),
                        Part::Body(rest, None),
                    ]
                    .into(),
                    None,
                ))
            }
        }
    }
}

/// Grows by doubling, up to `MEMORY_PREFIX`. Capacity stays at or below 2x the
/// logical length, which is what `Charge` pays for.
fn grow(mem: &mut BytesMut, need: usize) {
    if need > mem.capacity() {
        let mut next = BytesMut::with_capacity((mem.capacity() * 2).clamp(need, MEMORY_PREFIX));
        next.extend_from_slice(mem);
        *mem = next;
    }
}

enum Data {
    Memory(Bytes),
    Spool(SpoolReader),
}

/// Complete entity: the data plus at most one trailers frame. `len` counts data bytes only.
struct Full {
    data: Data,
    len: u64,
    trailers: Option<HeaderMap>,
    credit: Arc<Charge>,
}

impl ReplayBuffer for Full {
    fn len(&self) -> u64 {
        self.len
    }

    /// Builds a fresh body for each attempt. Each body keeps the memory charge alive.
    fn body(&self) -> Body {
        let mut parts = VecDeque::with_capacity(2);
        parts.push_back(match &self.data {
            Data::Memory(bytes) => Part::Data(bytes.clone()),
            Data::Spool(reader) => Part::Body(reader.clone().into_body(), Some(self.len)),
        });
        parts.extend(self.trailers.clone().map(Part::Trailers));
        Seq::boxed(parts, Some(self.credit.clone()))
    }

    fn memory_snapshot(&self) -> Option<Bytes> {
        match (&self.data, &self.trailers) {
            (Data::Memory(bytes), _) => Some(bytes.clone()),
            // A spooled entity needs an explicit asynchronous snapshot.
            _ => None,
        }
    }
}

enum Part {
    Data(Bytes),
    /// Inner body. `Some(n)` overrides its hint with the known remaining length.
    Body(Body, Option<u64>),
    Trailers(HeaderMap),
}

/// Bounded, ordered frame sequence. It holds the memory charge until dropped.
struct Seq {
    parts: VecDeque<Part>,
    _credit: Option<Arc<Charge>>,
}

impl Seq {
    fn boxed(parts: VecDeque<Part>, credit: Option<Arc<Charge>>) -> Body {
        Seq {
            parts,
            _credit: credit,
        }
        .boxed_unsync()
    }
}

impl HttpBody for Seq {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let this = self.get_mut();
        loop {
            let Some(front) = this.parts.front_mut() else {
                return Poll::Ready(None);
            };
            if let Part::Body(body, known) = front {
                match Pin::new(body).poll_frame(cx) {
                    Poll::Ready(None) => {
                        this.parts.pop_front();
                        continue;
                    }
                    Poll::Ready(Some(Ok(frame))) => {
                        if let (Some(n), Some(d)) = (known.as_mut(), frame.data_ref()) {
                            *n = n.saturating_sub(d.len() as u64);
                        }
                        return Poll::Ready(Some(Ok(frame)));
                    }
                    other => return other,
                }
            }
            match this.parts.pop_front() {
                Some(Part::Data(data)) if !data.is_empty() => {
                    return Poll::Ready(Some(Ok(Frame::data(data))));
                }
                Some(Part::Trailers(map)) => return Poll::Ready(Some(Ok(Frame::trailers(map)))),
                _ => {}
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.parts.iter().all(|part| match part {
            Part::Data(data) => data.is_empty(),
            Part::Body(body, _) => body.is_end_stream(),
            Part::Trailers(_) => false,
        })
    }

    fn size_hint(&self) -> SizeHint {
        let (mut lower, mut upper) = (0u64, Some(0u64));
        for part in &self.parts {
            let (l, u) = match part {
                Part::Data(data) => (data.len() as u64, Some(data.len() as u64)),
                Part::Body(_, Some(n)) => (*n, Some(*n)),
                Part::Body(body, None) => {
                    let hint = body.size_hint();
                    (hint.lower(), hint.upper())
                }
                Part::Trailers(_) => (0, Some(0)),
            };
            lower = lower.saturating_add(l);
            upper = upper.zip(u).and_then(|(a, b)| a.checked_add(b));
        }
        let mut hint = SizeHint::new();
        hint.set_lower(lower);
        if let Some(upper) = upper {
            hint.set_upper(upper.max(lower));
        }
        hint
    }
}
