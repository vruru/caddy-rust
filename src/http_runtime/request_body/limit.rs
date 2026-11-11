use super::super::{Body, BoxError};
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::{Body as HttpBody, Frame, SizeHint};
use std::{
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::{Context, Poll, ready},
};

pub struct State {
    remaining: AtomicU64,
    bypass: AtomicBool,
    hit: AtomicBool,
}
impl State {
    pub(super) fn tighten(&self, maximum: u64) {
        // Each nested Go reader subtracts the same consumed bytes. The
        // minimum of their remaining limits is one counter, not a stack.
        self.remaining.fetch_min(maximum, Ordering::AcqRel);
    }
    pub(super) fn bypass(&self) {
        self.bypass.store(true, Ordering::Release);
    }
    pub(super) fn exceeded(&self) -> bool {
        self.hit.load(Ordering::Acquire)
    }
}

#[derive(Debug)]
struct LimitExceeded;
impl std::fmt::Display for LimitExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("request body exceeded limit")
    }
}
impl std::error::Error for LimitExceeded {}

struct LimitBody {
    inner: Body,
    state: Arc<State>,
}
impl HttpBody for LimitBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        if self.state.bypass.load(Ordering::Acquire) {
            return Pin::new(&mut self.inner).poll_frame(cx);
        }
        if self.state.exceeded() {
            return Poll::Ready(Some(Err(Box::new(LimitExceeded))));
        }
        let frame = match ready!(Pin::new(&mut self.inner).poll_frame(cx)) {
            Some(Ok(frame)) => frame,
            other => return Poll::Ready(other),
        };
        let mut data = match frame.into_data() {
            Ok(data) => data,
            Err(trailers) => return Poll::Ready(Some(Ok(trailers))),
        };
        let length = data.len() as u64;
        let remaining = self
            .state
            .remaining
            .try_update(Ordering::AcqRel, Ordering::Acquire, |remaining| {
                Some(remaining.saturating_sub(length))
            })
            .expect("infallible accounting");
        if length > remaining {
            self.state.hit.store(true, Ordering::Release);
            if remaining == 0 {
                return Poll::Ready(Some(Err(Box::new(LimitExceeded))));
            }
            // Unlike Go's Reader, a Body frame cannot deliver bytes and an
            // error together. Return the allowed prefix, then the sticky error.
            data = data.split_to(remaining as usize);
        }
        Poll::Ready(Some(Ok(Frame::data(data))))
    }

    fn is_end_stream(&self) -> bool {
        (self.state.bypass.load(Ordering::Acquire) || !self.state.exceeded())
            && self.inner.is_end_stream()
    }
    fn size_hint(&self) -> SizeHint {
        if self.state.bypass.load(Ordering::Acquire) || !self.state.exceeded() {
            self.inner.size_hint()
        } else {
            SizeHint::new()
        }
    }
}

pub(super) fn wrap(body: Body, maximum: u64) -> (Body, Arc<State>) {
    let state = Arc::new(State {
        remaining: AtomicU64::new(maximum),
        bypass: AtomicBool::new(false),
        hit: AtomicBool::new(false),
    });
    (
        LimitBody {
            inner: body,
            state: state.clone(),
        }
        .boxed_unsync(),
        state,
    )
}

pub(super) fn is_limit(mut error: &(dyn std::error::Error + 'static)) -> bool {
    for _ in 0..64 {
        if error.is::<LimitExceeded>() {
            return true;
        }
        let Some(next) = error.source() else {
            return false;
        };
        error = next;
    }
    false
}
