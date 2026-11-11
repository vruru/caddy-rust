//! Shared send-completion signal. HTTP/1-only builds do not pull in h2.

#[cfg(feature = "http2")]
pub use h2::ext::{SendCompletion, SendOutcome};
#[cfg(all(feature = "http2", feature = "http1", feature = "client"))]
pub(crate) use h2::ext::SendCompletionOwner;

#[cfg(not(feature = "http2"))]
mod http1_only {
    use atomic_waker::AtomicWaker;
    use std::fmt;
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll};
    use std::time::Instant;

    /// A single-consumer notification of a successful HTTP/1 request write.
    /// Insert a clone into client request extensions to observe the final flush.
    /// A failed or discarded write may be abandoned before flushing.
    #[derive(Clone, Default)]
    pub struct SendCompletion(Arc<State>);

    /// The terminal outcome of a transport write observation.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SendOutcome {
        /// The monotonic time when the requested boundary was successfully flushed.
        Flushed(Instant),
        /// The writer discarded the boundary before observing a successful flush.
        Abandoned,
    }

    #[derive(Default)]
    struct State {
        outcome: Mutex<Option<(SendOutcome, Option<http::Version>)>>,
        waiter: AtomicWaker,
    }

    impl fmt::Debug for SendCompletion {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("SendCompletion").finish_non_exhaustive()
        }
    }

    impl SendCompletion {
        /// Creates an unsignalled, single-consumer notification.
        pub fn new() -> Self {
            Self::default()
        }

        /// Returns the monotonic time of a successful flush, when known.
        pub fn sent_at(&self) -> Option<Instant> {
            match self.outcome()? {
                SendOutcome::Flushed(now) => Some(now),
                SendOutcome::Abandoned => None,
            }
        }

        /// Polls for success or abandonment. Only one task should poll it.
        pub fn poll_outcome(&self, cx: &mut Context<'_>) -> Poll<SendOutcome> {
            if let Some(outcome) = self.outcome() {
                return Poll::Ready(outcome);
            }
            self.0.waiter.register(cx.waker());
            self.outcome().map_or(Poll::Pending, Poll::Ready)
        }

        /// Transfers a signal clone to the unique transport writer.
        #[doc(hidden)]
        pub fn into_owner(self) -> SendCompletionOwner {
            SendCompletionOwner(Some(self))
        }

        /// Reports the HTTP protocol that flushed the observed bytes.
        pub fn flushed_version(&self) -> Option<http::Version> {
            self.terminal().and_then(|(_, version)| version)
        }

        fn outcome(&self) -> Option<SendOutcome> {
            self.terminal().map(|(outcome, _)| outcome)
        }

        fn terminal(&self) -> Option<(SendOutcome, Option<http::Version>)> {
            *self
                .0
                .outcome
                .lock()
                .unwrap_or_else(|error| error.into_inner())
        }

        fn finish(&self, outcome: SendOutcome, version: Option<http::Version>) {
            let mut stored = self
                .0
                .outcome
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if stored.is_some() {
                return;
            }
            *stored = Some((outcome, version));
            drop(stored);
            self.0.waiter.wake();
        }
    }

    /// The unique producer held by the stream or codec, independent of receivers.
    #[doc(hidden)]
    #[derive(Debug)]
    pub struct SendCompletionOwner(Option<SendCompletion>);

    impl SendCompletionOwner {
        /// Resolves the signal after a successful write flush.
        pub fn mark_flushed(mut self, now: Instant, version: http::Version) {
            let completion = self.0.take().expect("live write observation");
            completion.finish(SendOutcome::Flushed(now), Some(version));
        }
    }

    impl Drop for SendCompletionOwner {
        fn drop(&mut self) {
            if let Some(completion) = self.0.take() {
                completion.finish(SendOutcome::Abandoned, None);
            }
        }
    }
}
#[cfg(not(feature = "http2"))]
pub use http1_only::{SendCompletion, SendOutcome};
#[cfg(not(feature = "http2"))]
pub(crate) use http1_only::SendCompletionOwner;
