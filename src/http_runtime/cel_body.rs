//! Full request-body placeholders with real ownership, poison-on-cancel and credits.
use super::{
    BoxError,
    proxy_replay::{ReplaySource, SnapshotView},
    request::{Context, failure},
};
use anyhow::Result;
use bytes::Bytes;
use http::{HeaderMap, StatusCode};
use http_body_util::BodyExt;
use hyper::body::{Body as _, Frame, SizeHint};
use std::{
    pin::Pin,
    task::{Context as TaskContext, Poll},
    time::Duration,
};
use tokio::sync::OwnedSemaphorePermit;
pub(super) const UNIT: usize = 1024;
pub(super) const MAX_BYTES: usize = 8 << 20;
pub(super) const POOL_UNITS: usize = (64 << 20) / UNIT;
struct OwnedCapture {
    bytes: Vec<u8>,
    _credit: OwnedSemaphorePermit,
}
impl AsRef<[u8]> for OwnedCapture {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}
#[derive(Debug)]
struct CaptureFailed;
impl std::fmt::Display for CaptureFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("request body capture incomplete")
    }
}
impl std::error::Error for CaptureFailed {}
/// A moved body is never represented as an empty body, even if the capture
/// future is dropped by an outer timeout before it can restore the request.
struct Poison;
impl hyper::body::Body for Poison {
    type Data = Bytes;
    type Error = BoxError;
    fn poll_frame(
        self: Pin<&mut Self>,
        _: &mut TaskContext<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        Poll::Ready(Some(Err(Box::new(CaptureFailed))))
    }
    fn size_hint(&self) -> SizeHint {
        SizeHint::new()
    }
}
struct Replay {
    data: Option<Bytes>,
    trailers: Option<HeaderMap>,
    unknown: bool,
    truncated: bool,
}
impl hyper::body::Body for Replay {
    type Data = Bytes;
    type Error = BoxError;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        _: &mut TaskContext<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        if let Some(data) = self.data.take().filter(|d| !d.is_empty()) {
            return Poll::Ready(Some(Ok(Frame::data(data))));
        }
        if self.truncated {
            return Poll::Ready(Some(Err(Box::new(CaptureFailed))));
        }
        Poll::Ready(self.trailers.take().map(|t| Ok(Frame::trailers(t))))
    }
    fn is_end_stream(&self) -> bool {
        !self.truncated && self.data.as_ref().is_none_or(Bytes::is_empty) && self.trailers.is_none()
    }
    fn size_hint(&self) -> SizeHint {
        let mut h = SizeHint::new();
        let n = self.data.as_ref().map_or(0, Bytes::len) as u64;
        h.set_lower(n);
        if !self.unknown && !self.truncated {
            h.set_upper(n);
        }
        h
    }
}
fn failed(ctx: &mut Context, status: StatusCode) -> anyhow::Error {
    ctx.cel_body_failure = Some(status);
    failure(status)
}
fn finish(mut bytes: Vec<u8>, mut credit: OwnedSemaphorePermit) -> Bytes {
    bytes.shrink_to_fit();
    let keep = bytes.capacity().max(1).div_ceil(UNIT);
    if credit.num_permits() > keep {
        let excess = credit.num_permits() - keep;
        drop(credit.split(excess));
    }
    Bytes::from_owner(OwnedCapture {
        bytes,
        _credit: credit,
    })
}
pub(super) async fn capture(ctx: &mut Context) -> Result<Bytes> {
    if let Some(status) = ctx.cel_body_failure {
        return Err(failure(status));
    }
    if let Some(cached) = &ctx.cel_body {
        return Ok(cached.clone());
    }
    let source = ctx.req().extensions().get::<ReplaySource>().cloned();
    if source.is_none() && ctx.fastcgi_body_claimed {
        return Err(failed(ctx, StatusCode::INTERNAL_SERVER_ERROR));
    }
    let hint = source
        .as_ref()
        .map_or_else(|| ctx.req().body().size_hint(), ReplaySource::size_hint);
    if hint.lower() > MAX_BYTES as u64 {
        return Err(failed(ctx, StatusCode::PAYLOAD_TOO_LARGE));
    }
    let expected = source
        .as_ref()
        .and_then(ReplaySource::complete_length)
        .or_else(|| hint.exact());
    let reserve = expected.map_or(MAX_BYTES, |n| (n as usize).min(MAX_BYTES));
    let credit = tokio::select! {biased;
     _=ctx.drain.cancelled()=>return Err(failed(ctx,StatusCode::SERVICE_UNAVAILABLE)),
     credit=tokio::time::timeout(Duration::from_secs(2),ctx.resources.cel_body_bytes.clone().acquire_many_owned(reserve.max(1).div_ceil(UNIT)as u32))=>match credit{Ok(Ok(p))=>p,_=>return Err(failed(ctx,StatusCode::SERVICE_UNAVAILABLE))},
    };
    // Install the failure state before any ownership transfer or suspension. It
    // doubles as a drop guard: cancellation cannot turn a moved owner into Empty.
    ctx.cel_body_failure = Some(StatusCode::SERVICE_UNAVAILABLE);
    let (mut reader, independent) = if let Some(source) = source {
        if let SnapshotView::Complete(bytes) = source.snapshot() {
            if bytes.len() > MAX_BYTES {
                return Err(failed(ctx, StatusCode::PAYLOAD_TOO_LARGE));
            }
            let bytes = finish(bytes.to_vec(), credit);
            ctx.cel_body = Some(bytes.clone());
            ctx.cel_body_failure = None;
            return Ok(bytes);
        }
        if let Some(reader) = source.complete_snapshot_body() {
            (reader, true)
        } else {
            *ctx.req_mut().body_mut() = Poison.boxed_unsync();
            (
                match source.take_unconsumed() {
                    Ok(body) => body,
                    Err(_) => return Err(failed(ctx, StatusCode::INTERNAL_SERVER_ERROR)),
                },
                false,
            )
        }
    } else {
        (
            std::mem::replace(ctx.req_mut().body_mut(), Poison.boxed_unsync()),
            false,
        )
    };
    let unknown = hint.exact().is_none();
    let mut bytes = Vec::with_capacity(reserve);
    let mut trailers = None;
    let mut truncated = false;
    loop {
        let frame = tokio::select! {biased;
         _=ctx.drain.cancelled()=>return Err(failed(ctx,StatusCode::SERVICE_UNAVAILABLE)),
         frame=tokio::time::timeout(Duration::from_secs(5),reader.frame())=>match frame{Ok(f)=>f,Err(_)=>return Err(failed(ctx,StatusCode::REQUEST_TIMEOUT))},
        };
        match frame {
            Some(Ok(frame)) => match frame.into_data() {
                Ok(data) => {
                    if data.len() > MAX_BYTES - bytes.len() {
                        return Err(failed(ctx, StatusCode::PAYLOAD_TOO_LARGE));
                    }
                    if data.len() > reserve - bytes.len() {
                        truncated = true;
                        break;
                    }
                    bytes.extend_from_slice(&data);
                }
                Err(frame) => {
                    trailers = frame.into_trailers().ok();
                    break;
                }
            },
            Some(Err(error)) => {
                if super::request_body::limit_error(error.as_ref())
                    || super::request_body::limit_hit(ctx.body_limit.as_deref())
                {
                    return Err(failed(ctx, StatusCode::PAYLOAD_TOO_LARGE));
                }
                truncated = true;
                break;
            }
            None => break,
        }
    }
    if expected.is_some_and(|expected| expected != bytes.len() as u64) {
        truncated = true;
    }
    let bytes = finish(bytes, credit);
    if !independent {
        *ctx.req_mut().body_mut() = Replay {
            data: Some(bytes.clone()),
            unknown: unknown || trailers.is_some() || truncated,
            trailers,
            truncated,
        }
        .boxed_unsync();
        ctx.req_mut().extensions_mut().remove::<ReplaySource>();
        ctx.req_mut()
            .extensions_mut()
            .remove::<super::fastcgi::PreparedLength>();
        ctx.fastcgi_body_claimed = false;
        ctx.body_limit = None;
    }
    ctx.cel_body = Some(bytes.clone());
    ctx.cel_body_failure = None;
    Ok(bytes)
}
