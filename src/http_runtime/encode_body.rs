//! Pull-driven gzip/zstd body with bounded CPU jobs and one input prefix.
use super::accepted_encodings::Coding;
use super::resource_budget::{BlockingBudget, BudgetSnapshot};
use super::{Body, BoxError, Bytes, gzip_codec::GzipCodec, zstd_codec::ZstdCodec};
use bytes::BytesMut;
use http_body_util::{BodyExt, StreamBody};
use hyper::body::{Body as _, Frame, SizeHint};
use std::{
    future::poll_fn,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

const CHUNK: usize = 65_536;

#[derive(Clone, Copy, Debug)]
pub(crate) enum CodecPlan {
    Gzip(i32),
    Zstd {
        level: &'static str,
        checksum: Option<bool>,
    },
}

impl CodecPlan {
    pub(crate) const fn coding(self) -> Coding {
        match self {
            Self::Gzip(_) => Coding::Gzip,
            Self::Zstd { .. } => Coding::Zstd,
        }
    }

    fn admission_units(self) -> u32 {
        match self {
            Self::Gzip(_) => 1,
            Self::Zstd { .. } => 4,
        }
    }
}

enum Codec {
    Gzip(Box<GzipCodec>),
    Zstd(Box<ZstdCodec>),
}

impl Codec {
    fn new(plan: CodecPlan) -> std::io::Result<Self> {
        Ok(match plan {
            CodecPlan::Gzip(level) => Self::Gzip(Box::new(GzipCodec::new(level)?)),
            CodecPlan::Zstd { level, checksum } => {
                Self::Zstd(Box::new(ZstdCodec::new(level, checksum)?))
            }
        })
    }

    fn write(&mut self, data: &[u8], flush: bool) -> std::io::Result<Vec<u8>> {
        match self {
            Self::Gzip(codec) => codec.write(data, flush),
            Self::Zstd(codec) => codec.write(data, flush),
        }
    }

    fn finish(self) -> std::io::Result<Vec<u8>> {
        match self {
            Self::Gzip(codec) => codec.finish(),
            Self::Zstd(codec) => codec.finish(),
        }
    }
}

pub(super) struct CompressionBudget {
    live: Arc<Semaphore>,
    live_limit: usize,
    blocks: BlockingBudget,
    skipped: AtomicU64,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct CompressionDiagnostics {
    pub used_units: usize,
    pub unit_limit: usize,
    pub skipped: u64,
    pub cpu: BudgetSnapshot,
}

impl CompressionBudget {
    pub(super) fn new(cpu: usize, established: usize) -> anyhow::Result<Self> {
        let live_limit = cpu.saturating_mul(16).clamp(32, 256);
        // Account for the other HTTP worker lanes when sharing Tokio's
        // process blocking pool. This is a job cap, never a CPU affinity.
        let remaining = crate::runtime::BLOCKING_POOL_MAX.saturating_sub(established);
        let running = cpu.div_ceil(2).clamp(1, 64).min((remaining / 2).max(1));
        Ok(Self {
            live: Arc::new(Semaphore::new(live_limit)),
            live_limit,
            // At most one CPU job per admission, including an initialization
            // or a cancelled body whose real worker has not returned yet.
            blocks: BlockingBudget::new(running, live_limit, Duration::ZERO)?,
            skipped: AtomicU64::new(0),
        })
    }

    pub(super) async fn admit(&self, plan: CodecPlan) -> Option<Admitted> {
        let admitted = async {
            let lease = Arc::new(
                self.live
                    .clone()
                    .try_acquire_many_owned(plan.admission_units())
                    .ok()?,
            );
            let job_lease = lease.clone();
            let codec = self
                .blocks
                .run(move || {
                    let _lease = job_lease;
                    Codec::new(plan)
                })
                .await
                .ok()?
                .ok()?;
            Some(Admitted {
                codec,
                lease,
                blocks: self.blocks.clone(),
            })
        }
        .await;
        if admitted.is_none() {
            self.skipped.fetch_add(1, Ordering::Relaxed);
        }
        admitted
    }

    pub(super) fn close(&self) {
        self.blocks.tasks().close();
    }

    pub(super) async fn wait(&self) {
        self.blocks.tasks().wait().await;
    }

    pub(super) fn snapshot(&self) -> CompressionDiagnostics {
        CompressionDiagnostics {
            used_units: self.live_limit - self.live.available_permits(),
            unit_limit: self.live_limit,
            skipped: self.skipped.load(Ordering::Relaxed),
            cpu: self.blocks.snapshot(),
        }
    }
}

pub(super) struct Admitted {
    codec: Codec,
    lease: Arc<OwnedSemaphorePermit>,
    blocks: BlockingBudget,
}

pub(super) fn with_prefix(inner: Body, first: Option<Frame<Bytes>>) -> Body {
    if first.is_some() {
        Prefix { first, inner }.boxed_unsync()
    } else {
        inner
    }
}

struct Prefix {
    first: Option<Frame<Bytes>>,
    inner: Body,
}

impl hyper::body::Body for Prefix {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        if let Some(frame) = self.first.take() {
            return Poll::Ready(Some(Ok(frame)));
        }
        Pin::new(&mut self.inner).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.first.is_none() && self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        let extra = self
            .first
            .as_ref()
            .and_then(Frame::data_ref)
            .map_or(0, |data| data.len() as u64);
        let inner = self.inner.size_hint();
        let mut hint = SizeHint::new();
        hint.set_lower(inner.lower().saturating_add(extra));
        if let Some(upper) = inner.upper().and_then(|size| size.checked_add(extra)) {
            hint.set_upper(upper);
        }
        hint
    }
}

pub(super) fn compressed(admitted: Admitted, inner: Body, incremental: bool) -> Body {
    let state = Encoded {
        inner,
        incremental,
        codec: Some(admitted.codec),
        lease: admitted.lease,
        blocks: admitted.blocks,
        input: Bytes::new(),
        gathering: BytesMut::new(),
        end: false,
        trailers: None,
    };
    StreamBody::new(futures_util::stream::try_unfold(state, Encoded::frame)).boxed_unsync()
}

struct Encoded {
    inner: Body,
    incremental: bool,
    codec: Option<Codec>,
    lease: Arc<OwnedSemaphorePermit>,
    blocks: BlockingBudget,
    input: Bytes,
    gathering: BytesMut,
    end: bool,
    trailers: Option<Frame<Bytes>>,
}

impl Encoded {
    async fn frame(mut self) -> Result<Option<(Frame<Bytes>, Self)>, BoxError> {
        loop {
            // Always-ready empty frames must not monopolize a reactor worker.
            tokio::task::consume_budget().await;
            if self.codec.is_none() {
                return Ok(self.trailers.take().map(|tail| (tail, self)));
            }
            if self.gathering.len() < CHUNK && !self.input.is_empty() {
                let length = (CHUNK - self.gathering.len()).min(self.input.len());
                let chunk = self.input.split_to(length);
                if self.gathering.is_empty() && (self.incremental || length == CHUNK) {
                    if let Some(out) = self.write(chunk, true).await? {
                        return Ok(Some((out, self)));
                    }
                    continue;
                }
                self.gathering.extend_from_slice(&chunk);
            }
            if self.gathering.len() == CHUNK || (self.end && !self.gathering.is_empty()) {
                let data = self.gathering.split().freeze();
                if let Some(out) = self.write(data, !self.end).await? {
                    return Ok(Some((out, self)));
                }
                continue;
            }
            if self.end {
                let codec = self.codec.take().expect("encoder already checked");
                let lease = self.lease.clone();
                let encoded = self
                    .blocks
                    .run(move || {
                        let _lease = lease;
                        codec.finish()
                    })
                    .await
                    .map_err(|_| anyhow::anyhow!("compression worker unavailable"))??;
                if !encoded.is_empty() {
                    return Ok(Some((Frame::data(Bytes::from(encoded)), self)));
                }
                continue;
            }

            // Probe only when there is already a bounded buffered prefix.
            // A pending origin must not delay those bytes until a full chunk.
            let frame = if self.gathering.is_empty() {
                self.inner.frame().await
            } else {
                let probe = poll_fn(|cx| Poll::Ready(Pin::new(&mut self.inner).poll_frame(cx))).await;
                match probe {
                    Poll::Ready(frame) => frame,
                    Poll::Pending => {
                        let data = self.gathering.split().freeze();
                        if let Some(out) = self.write(data, true).await? {
                            return Ok(Some((out, self)));
                        }
                        continue;
                    }
                }
            };
            match frame {
                None => self.end = true,
                Some(Err(error)) => return Err(error),
                Some(Ok(frame)) => match frame.into_data() {
                    Ok(data) => self.input = data,
                    Err(trailers) if trailers.is_trailers() => {
                        self.trailers = Some(trailers);
                        self.end = true;
                    }
                    Err(_) => {}
                },
            }
        }
    }

    async fn write(
        &mut self,
        data: Bytes,
        flush: bool,
    ) -> Result<Option<Frame<Bytes>>, BoxError> {
        let mut codec = self.codec.take().expect("encoder already checked");
        let lease = self.lease.clone();
        let (codec, result) = self
            .blocks
            .run(move || {
                let _lease = lease;
                let result = codec.write(&data, flush);
                (codec, result)
            })
            .await
            .map_err(|_| anyhow::anyhow!("compression worker unavailable"))?;
        let encoded = result?;
        self.codec = Some(codec);
        Ok((!encoded.is_empty()).then(|| Frame::data(Bytes::from(encoded))))
    }
}
