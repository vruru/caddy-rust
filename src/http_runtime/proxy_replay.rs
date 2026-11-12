//! Ownership core for replayable outgoing request bodies.
//!
//! This module only arbitrates who owns the request body for which attempt.
//! It does not spawn tasks, cache data, read spool files, classify failures,
//! or decide retry policy.

use std::error::Error;
use std::fmt;
use std::mem;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};

use http_body_util::BodyExt;
use hyper::body::{Body as HttpBody, Frame, SizeHint};

use super::{Body, BoxError, Bytes, full};

/// A fully buffered body that can produce a fresh `Body` for every attempt.
pub(super) trait ReplayBuffer: Send + Sync {
    fn len(&self) -> u64;
    fn body(&self) -> Body;
    fn memory_snapshot(&self) -> Option<Bytes>;
}

/// Returned by `ReplaySource::begin` when the one-shot body was already taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Spent;

impl fmt::Display for Spent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("request body already consumed by a previous attempt")
    }
}

impl Error for Spent {}

/// Yielded by an attempt body whose epoch was superseded or aborted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Aborted;

impl fmt::Display for Aborted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("request body attempt aborted")
    }
}

impl Error for Aborted {}

#[derive(Debug, Clone)]
pub(super) enum SnapshotView {
    Complete(Bytes),
    Unavailable,
}

/// Records failures while reading the locally owned upload body.
#[derive(Debug, Default)]
pub(super) struct BodyObs {
    upload_failed: AtomicBool,
}

impl BodyObs {
    pub(super) fn upload_failed(&self) -> bool {
        self.upload_failed.load(Ordering::Acquire)
    }
}

pub(super) struct Attempt {
    pub body: Body,
    pub observation: Arc<BodyObs>,
    pub guard: AttemptGuard,
}

enum Slot {
    Empty,
    Stream(Body),
    Partial { prefix: Bytes, rest: Body },
    Buffered(Arc<dyn ReplayBuffer>),
    Spent,
}

struct UnissuedPrefix {
    prefix: Option<Bytes>,
    rest: Body,
}
impl HttpBody for UnissuedPrefix {
    type Data = Bytes;
    type Error = BoxError;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        if let Some(prefix) = self.prefix.take().filter(|v| !v.is_empty()) {
            return Poll::Ready(Some(Ok(Frame::data(prefix))));
        }
        Pin::new(&mut self.rest).poll_frame(cx)
    }
    fn size_hint(&self) -> SizeHint {
        make_hint(add_len(
            self.prefix.as_ref().map_or(0, |p| p.len() as u64),
            hint_parts(&self.rest.size_hint()),
        ))
    }
    fn is_end_stream(&self) -> bool {
        self.prefix.as_ref().is_none_or(|p| p.is_empty()) && self.rest.is_end_stream()
    }
}

type HintParts = (u64, Option<u64>);

struct State {
    slot: Slot,
    epoch: u64,
    waker: Option<(u64, Waker)>,
    hint: HintParts,
}

struct Shared {
    state: Mutex<State>,
}

fn lock(shared: &Shared) -> MutexGuard<'_, State> {
    shared
        .state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn hint_parts(h: &SizeHint) -> HintParts {
    (h.lower(), h.upper())
}

fn add_len(n: u64, (lower, upper): HintParts) -> HintParts {
    (
        lower.saturating_add(n),
        upper.and_then(|u| u.checked_add(n)),
    )
}

fn make_hint((lower, upper): HintParts) -> SizeHint {
    let mut h = SizeHint::new();
    match upper {
        Some(u) => {
            // Upper first (lower is 0), then a lower clamped to upper: never panics.
            h.set_upper(u);
            h.set_lower(lower.min(u));
        }
        None => h.set_lower(lower),
    }
    h
}

/// Invalidates `epoch` if it is still current and wakes its driver outside the lock.
fn invalidate(shared: &Shared, epoch: u64) {
    let waker = {
        let mut st = lock(shared);
        if st.epoch != epoch {
            return;
        }
        st.epoch = st.epoch.wrapping_add(1);
        st.waker.take().map(|(_, w)| w)
    };
    if let Some(w) = waker {
        w.wake();
    }
}

#[derive(Clone)]
pub(super) struct ReplaySource {
    shared: Arc<Shared>,
}

enum Kind {
    Empty,
    Buffered(Arc<dyn ReplayBuffer>),
    Lazy,
}

impl ReplaySource {
    /// Replacing a consumed entity does not require replaying it. Invalidate
    /// its upload epoch and release any still-unissued bytes outside the lock.
    pub(super) fn discard(&self) {
        let (slot, waker) = {
            let mut state = lock(&self.shared);
            let slot = mem::replace(&mut state.slot, Slot::Spent);
            state.epoch = state.epoch.wrapping_add(1);
            (slot, state.waker.take().map(|(_, waker)| waker))
        };
        if let Some(waker) = waker {
            waker.wake();
        }
        drop(slot);
    }
    /// Transfer actual body ownership to the next local handler or preflight.
    /// Taking the slot and superseding its epoch are atomic. A transport that
    /// already polled a one-shot source has left Spent and cannot be recovered.
    pub(super) fn take_unconsumed(&self) -> Result<Body, Spent> {
        let (slot, waker) = {
            let mut state = lock(&self.shared);
            if matches!(state.slot, Slot::Spent) {
                return Err(Spent);
            }
            let slot = match &state.slot {
                Slot::Buffered(buffer) => Slot::Buffered(buffer.clone()),
                Slot::Empty => Slot::Empty,
                _ => mem::replace(&mut state.slot, Slot::Spent),
            };
            state.epoch = state.epoch.wrapping_add(1);
            (slot, state.waker.take().map(|(_, waker)| waker))
        };
        if let Some(waker) = waker {
            waker.wake();
        }
        match slot {
            Slot::Stream(body) => Ok(body),
            Slot::Partial { prefix, rest } => Ok(UnissuedPrefix {
                prefix: Some(prefix),
                rest,
            }
            .boxed_unsync()),
            Slot::Buffered(buffer) => Ok(buffer.body()),
            Slot::Empty => Ok(full(Bytes::new())),
            Slot::Spent => Err(Spent),
        }
    }
    fn from_slot(slot: Slot, hint: HintParts) -> Self {
        Self {
            shared: Arc::new(Shared {
                state: Mutex::new(State {
                    slot,
                    epoch: 0,
                    waker: None,
                    hint,
                }),
            }),
        }
    }

    /// One-shot streaming body. Never treated as complete, even if its hint is 0.
    pub(super) fn new(body: Body) -> Self {
        let hint = hint_parts(&body.size_hint());
        Self::from_slot(Slot::Stream(body), hint)
    }

    /// One-shot body whose first bytes were already read into `prefix`.
    pub(super) fn partial(prefix: Bytes, rest: Body) -> Self {
        let hint = add_len(prefix.len() as u64, hint_parts(&rest.size_hint()));
        Self::from_slot(Slot::Partial { prefix, rest }, hint)
    }

    pub(super) fn buffered(buffer: Arc<dyn ReplayBuffer>) -> Self {
        let len = buffer.len();
        Self::from_slot(Slot::Buffered(buffer), (len, Some(len)))
    }

    /// Explicitly known to carry no body.
    pub(super) fn empty() -> Self {
        Self::from_slot(Slot::Empty, (0, Some(0)))
    }

    pub(super) fn size_hint(&self) -> SizeHint { make_hint(lock(&self.shared).hint) }

    pub(super) fn complete_length(&self) -> Option<u64> {
        let st = lock(&self.shared);
        match st.slot {
            Slot::Empty | Slot::Buffered(_) => Some(st.hint.0),
            _ => None,
        }
    }
    pub(super) fn replayable(&self) -> bool {
        let st = lock(&self.shared);
        !matches!(st.slot, Slot::Spent)
    }

    pub(super) fn snapshot(&self) -> SnapshotView {
        let buffer = {
            let st = lock(&self.shared);
            match &st.slot {
                Slot::Empty => return SnapshotView::Complete(Bytes::new()),
                Slot::Buffered(b) => Arc::clone(b),
                Slot::Stream(_) | Slot::Partial { .. } | Slot::Spent => {
                    return SnapshotView::Unavailable;
                }
            }
        };
        match buffer.memory_snapshot() {
            Some(bytes) if bytes.len() as u64 == buffer.len() => SnapshotView::Complete(bytes),
            _ => SnapshotView::Unavailable,
        }
    }

    /// An independent complete snapshot reader, including disk-backed Full.
    /// Reading it does not supersede an upload that is still in progress.
    pub(super) fn complete_snapshot_body(&self) -> Option<Body> {
        let buffer = {
            let state = lock(&self.shared);
            match &state.slot {
                Slot::Empty => return Some(full(Bytes::new())),
                Slot::Buffered(buffer) => buffer.clone(),
                Slot::Stream(_) | Slot::Partial { .. } | Slot::Spent => return None,
            }
        };
        Some(buffer.body())
    }

    pub(super) fn begin(&self) -> Result<Attempt, Spent> {
        let (epoch, kind, old_waker, hint) = {
            let mut st = lock(&self.shared);
            let kind = match &st.slot {
                Slot::Spent => return Err(Spent),
                Slot::Empty => Kind::Empty,
                Slot::Buffered(b) => Kind::Buffered(Arc::clone(b)),
                Slot::Stream(_) | Slot::Partial { .. } => Kind::Lazy,
            };
            st.epoch = st.epoch.wrapping_add(1);
            let epoch = st.epoch;
            let old = st.waker.take().map(|(_, w)| w);
            (epoch, kind, old, st.hint)
        };
        if let Some(w) = old_waker {
            w.wake();
        }

        // Buffer factory is invoked outside the lock, fresh per attempt.
        let stage = match kind {
            Kind::Empty => Stage::Inner(full(Bytes::new())),
            Kind::Buffered(buffer) => Stage::Inner(buffer.body()),
            Kind::Lazy => Stage::Lazy,
        };

        let body = AttemptBody {
            shared: Arc::clone(&self.shared),
            epoch,
            stage,
            initial_hint: hint,
        }
        .boxed_unsync();

        Ok(Attempt {
            body,
            observation: Arc::new(BodyObs::default()),
            guard: AttemptGuard {
                shared: Arc::clone(&self.shared),
                epoch,
                armed: true,
            },
        })
    }
}

pub(super) struct AttemptGuard {
    shared: Arc<Shared>,
    epoch: u64,
    armed: bool,
}

impl AttemptGuard {
    /// Invalidates this attempt's epoch; its driver yields `Aborted` on next poll.
    pub(super) fn abort(&mut self) {
        if self.armed {
            self.armed = false;
            invalidate(&self.shared, self.epoch);
        }
    }

    /// Keeps the upload pump alive (e.g. after a successful response).
    /// A later `begin` still supersedes this epoch.
    pub(super) fn disarm(mut self) {
        self.armed = false;
    }
}

impl Drop for AttemptGuard {
    fn drop(&mut self) {
        self.abort();
    }
}

enum Stage {
    /// Not yet polled; the one-shot body still lives in the shared slot.
    Lazy,
    Prefix {
        prefix: Option<Bytes>,
        rest: Body,
    },
    Inner(Body),
    Done,
    Aborted,
}

struct AttemptBody {
    shared: Arc<Shared>,
    epoch: u64,
    stage: Stage,
    initial_hint: HintParts,
}

impl HttpBody for AttemptBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();

        match this.stage {
            Stage::Done => return Poll::Ready(None),
            Stage::Aborted => return Poll::Ready(Some(Err(Box::new(Aborted)))),
            _ => {}
        }

        // Single lock per poll: fence check, waker registration, initial take.
        {
            let mut st = lock(&this.shared);
            if st.epoch != this.epoch {
                drop(st);
                this.stage = Stage::Aborted;
                return Poll::Ready(Some(Err(Box::new(Aborted))));
            }

            let fresh = match &st.waker {
                Some((e, w)) => *e != this.epoch || !w.will_wake(cx.waker()),
                None => true,
            };
            if fresh {
                st.waker = Some((this.epoch, cx.waker().clone()));
            }

            if matches!(this.stage, Stage::Lazy) {
                // Taken (and marked Spent) before the inner poll, even if it pends.
                match mem::replace(&mut st.slot, Slot::Spent) {
                    Slot::Stream(body) => this.stage = Stage::Inner(body),
                    Slot::Partial { prefix, rest } => {
                        this.stage = Stage::Prefix {
                            prefix: (!prefix.is_empty()).then_some(prefix),
                            rest,
                        };
                    }
                    other => {
                        st.slot = other;
                        drop(st);
                        this.stage = Stage::Aborted;
                        return Poll::Ready(Some(Err(Box::new(Spent))));
                    }
                }
            }
        }

        let out = match &mut this.stage {
            Stage::Inner(body) => Pin::new(body).poll_frame(cx),
            Stage::Prefix { prefix, rest } => {
                if let Some(p) = prefix.take() {
                    return Poll::Ready(Some(Ok(Frame::data(p))));
                }
                Pin::new(rest).poll_frame(cx)
            }
            Stage::Done => return Poll::Ready(None),
            Stage::Lazy | Stage::Aborted => {
                return Poll::Ready(Some(Err(Box::new(Aborted))));
            }
        };

        if matches!(out, Poll::Ready(None)) {
            this.stage = Stage::Done;
        }
        out
    }

    fn is_end_stream(&self) -> bool {
        match &self.stage {
            Stage::Inner(body) => body.is_end_stream(),
            Stage::Prefix { prefix, rest } => prefix.is_none() && rest.is_end_stream(),
            Stage::Done => true,
            Stage::Lazy | Stage::Aborted => false,
        }
    }

    fn size_hint(&self) -> SizeHint {
        match &self.stage {
            Stage::Lazy => make_hint(self.initial_hint),
            Stage::Inner(body) => body.size_hint(),
            Stage::Prefix { prefix, rest } => {
                let n = prefix.as_ref().map_or(0, |p| p.len() as u64);
                make_hint(add_len(n, hint_parts(&rest.size_hint())))
            }
            Stage::Done => SizeHint::with_exact(0),
            Stage::Aborted => SizeHint::new(),
        }
    }
}

impl Drop for AttemptBody {
    fn drop(&mut self) {
        let mut st = lock(&self.shared);
        if matches!(&st.waker, Some((e, _)) if *e == self.epoch) {
            st.waker = None;
        }
    }
}

struct Observed {
    inner: Body,
    obs: Arc<BodyObs>,
}

impl HttpBody for Observed {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        let out = Pin::new(&mut this.inner).poll_frame(cx);
        if matches!(&out, Poll::Ready(Some(Err(error))) if !error.is::<Aborted>()) {
            this.obs.upload_failed.store(true, Ordering::Release);
        }
        out
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// Observe local upload failures without classifying any frame as a socket write.
pub(super) fn observe(body: Body, obs: Arc<BodyObs>) -> Body {
    Observed { inner: body, obs }.boxed_unsync()
}
