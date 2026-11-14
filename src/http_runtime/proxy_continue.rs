//! The 100-continue interval begins at the actual request-head flush.
use super::{Body, BoxError};
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::{Body as HttpBody, Frame, SizeHint};
use hyper::ext::{SendCompletion, SendOutcome};
use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    sync::{Notify, futures::OwnedNotified},
    time::Sleep,
};
pub(super) struct Continue {
    allowed: AtomicBool,
    notify: Arc<Notify>,
}
impl Continue {
    pub(super) fn allow(&self) {
        self.allowed.store(true, Ordering::Release);
        self.notify.notify_one();
    }
}
pub(super) fn gate(inner: Body, wait: Duration) -> (Body, Arc<Continue>, SendCompletion) {
    let shared = Arc::new(Continue {
        allowed: AtomicBool::new(false),
        notify: Arc::new(Notify::new()),
    });
    let notified = Box::pin(shared.notify.clone().notified_owned());
    let head = SendCompletion::new();
    let gate = Gate {
        inner,
        shared: shared.clone(),
        head: head.clone(),
        notified,
        sleep: None,
        wait,
        allowed: false,
        failed: false,
    };
    (gate.boxed_unsync(), shared, head)
}
struct Gate {
    inner: Body,
    shared: Arc<Continue>,
    head: SendCompletion,
    notified: Pin<Box<OwnedNotified>>,
    sleep: Option<Pin<Box<Sleep>>>,
    wait: Duration,
    allowed: bool,
    failed: bool,
}
impl HttpBody for Gate {
    type Data = Bytes;
    type Error = BoxError;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        if self.failed {
            return Poll::Ready(None);
        }
        if !self.allowed {
            let _ = self.notified.as_mut().poll(cx);
            self.allowed = self.shared.allowed.load(Ordering::Acquire);
            if !self.allowed {
                match self.head.poll_outcome(cx) {
                    Poll::Ready(SendOutcome::Abandoned) => {
                        self.failed = true;
                        return Poll::Ready(Some(Err(std::io::Error::new(
                            std::io::ErrorKind::BrokenPipe,
                            "request head abandoned before continue",
                        )
                        .into())));
                    }
                    Poll::Ready(SendOutcome::Flushed(at)) => {
                        if self.sleep.is_none() {
                            let Some(at) = at.checked_add(self.wait) else {
                                self.failed = true;
                                return Poll::Ready(Some(Err(std::io::Error::other(
                                    "continue deadline out of range",
                                )
                                .into())));
                            };
                            self.sleep = Some(Box::pin(tokio::time::sleep_until(at.into())));
                        }
                        self.allowed = self
                            .sleep
                            .as_mut()
                            .expect("installed timer")
                            .as_mut()
                            .poll(cx)
                            .is_ready();
                    }
                    Poll::Pending => {}
                }
            }
            if !self.allowed {
                return Poll::Pending;
            }
        }
        Pin::new(&mut self.inner).poll_frame(cx)
    }
    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
    fn is_end_stream(&self) -> bool {
        self.failed || self.inner.is_end_stream()
    }
}
