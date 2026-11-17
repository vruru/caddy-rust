//! Source validation and bounded copies; no file or task ownership lives here.
use super::super::{Body, BoxError, Bytes};
use http::StatusCode;
use http_body_util::BodyExt;
use hyper::body::{Body as HttpBody, Frame, SizeHint};
use std::{
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU16, Ordering},
    },
    task::{Context, Poll, ready},
};

const COPY_BUFFER: usize = 32 * 1024;
const MAX_TRAILERS: usize = 64 * 1024;

#[derive(Debug)]
pub(super) struct ReadFailure(pub(super) StatusCode);
impl std::fmt::Display for ReadFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self.0 {
            StatusCode::PAYLOAD_TOO_LARGE => "bounded_body: request body too large",
            StatusCode::SERVICE_UNAVAILABLE => "bounded_body: buffering request body failed",
            _ => "bounded_body: reading request body failed",
        })
    }
}
impl std::error::Error for ReadFailure {}

struct Poison;
impl HttpBody for Poison {
    type Data = Bytes;
    type Error = BoxError;
    fn poll_frame(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        Poll::Ready(Some(Err(Box::new(ReadFailure(StatusCode::BAD_REQUEST)))))
    }
}
pub(super) fn poison() -> Body {
    Poison.boxed_unsync()
}

pub(super) struct Checked {
    inner: Body,
    maximum: u64,
    declared: i64,
    read: u64,
    pending: Bytes,
    trailers: bool,
    ended: bool,
    status: Arc<AtomicU16>,
}
impl Checked {
    pub(super) fn new(inner: Body, maximum: u64, declared: i64, status: Arc<AtomicU16>) -> Self {
        Self {
            inner,
            maximum,
            declared,
            read: 0,
            pending: Bytes::new(),
            trailers: false,
            ended: false,
            status,
        }
    }
    fn fail(&mut self, status: StatusCode) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        self.status.store(status.as_u16(), Ordering::Release);
        self.ended = true;
        self.pending = Bytes::new();
        Poll::Ready(Some(Err(Box::new(ReadFailure(status)))))
    }
}
impl HttpBody for Checked {
    type Data = Bytes;
    type Error = BoxError;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        if self.ended {
            return Poll::Ready(None);
        }
        if !self.pending.is_empty() {
            let count = self.pending.len().min(COPY_BUFFER);
            // A slice would retain a potentially large input allocation in an
            // asynchronous file worker. Only copy one bounded block instead.
            let bytes = Bytes::copy_from_slice(&self.pending[..count]);
            let _ = self.pending.split_to(count);
            if self.pending.is_empty() {
                self.pending = Bytes::new();
            }
            return Poll::Ready(Some(Ok(Frame::data(bytes))));
        }
        let frame = match ready!(Pin::new(&mut self.inner).poll_frame(cx)) {
            None => {
                if self.declared >= 0 && self.read != self.declared as u64 {
                    return self.fail(StatusCode::BAD_REQUEST);
                }
                self.ended = true;
                return Poll::Ready(None);
            }
            Some(Err(error)) => {
                let limited = super::super::request_body::limit_error(error.as_ref());
                let error = anyhow::Error::from_boxed(error);
                let status = if limited
                    || super::super::request::proxy_error_status(&error, None)
                        == StatusCode::PAYLOAD_TOO_LARGE
                {
                    StatusCode::PAYLOAD_TOO_LARGE
                } else {
                    StatusCode::BAD_REQUEST
                };
                return self.fail(status);
            }
            Some(Ok(frame)) => frame,
        };
        match frame.into_data() {
            Ok(data) => {
                if self.trailers {
                    return self.fail(StatusCode::BAD_REQUEST);
                }
                if data.len() as u64 > self.maximum - self.read {
                    // Detect the first byte beyond maximum without buffering
                    // it; equality still requires polling a real EOS.
                    return self.fail(StatusCode::PAYLOAD_TOO_LARGE);
                }
                self.read += data.len() as u64;
                let count = data.len().min(COPY_BUFFER);
                let bytes = Bytes::copy_from_slice(&data[..count]);
                self.pending = if count == data.len() {
                    Bytes::new()
                } else {
                    data.slice(count..)
                };
                Poll::Ready(Some(Ok(Frame::data(bytes))))
            }
            Err(frame) => {
                let Ok(trailers) = frame.into_trailers() else {
                    return self.fail(StatusCode::BAD_REQUEST);
                };
                let size = trailers.iter().fold(0usize, |n, (name, value)| {
                    n.saturating_add(name.as_str().len())
                        .saturating_add(value.len())
                });
                if self.trailers || size > MAX_TRAILERS {
                    return self.fail(StatusCode::BAD_REQUEST);
                }
                self.trailers = true;
                Poll::Ready(Some(Ok(Frame::trailers(trailers))))
            }
        }
    }
    // The wrapped source's hint/is_end_stream cannot establish completeness.
    fn size_hint(&self) -> SizeHint {
        SizeHint::new()
    }
    fn is_end_stream(&self) -> bool {
        self.ended
    }
}
