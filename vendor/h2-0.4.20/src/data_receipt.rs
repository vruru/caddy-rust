//! Concrete, bounded DATA receipts. Queued ownership has no foreign waker or
//! destructor: retained byte owners are retired into a fixed-capacity queue and
//! dropped by the protocol driver only after leaving stream/store locks.
use crate::{ext::SendOutcome, proto::StreamRef};
use bytes::{Buf, Bytes};
use std::{
    fmt,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex, Weak,
    },
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};
/// Immutable concrete write policy copied before queuing an observed boundary.
/// There are no callbacks; only the successful codec flush owner evaluates it.
#[derive(Clone, Copy, Debug)]
pub struct DataWriteDeadline {
    /// Fixed write-policy epoch.
    pub installed: Instant,
    /// Idle/grace duration; zero/None disables rate and idle checks.
    pub idle: Option<Duration>,
    /// Optional nonzero payload bytes/second, earned before the current flush.
    pub minimum_rate: Option<std::num::NonZeroU64>,
    /// Absolute ceiling, independent of source progress.
    pub hard: Option<Instant>,
    /// Start of this actual boundary, not a body source poll.
    pub pending_since: Instant,
    /// Previous successful physical flush, if any.
    pub last_flush: Option<Instant>,
    /// Successfully flushed payload before this boundary.
    pub flushed_before: u64,
}
impl DataWriteDeadline {
    /// Tests a physical flush before earning the current fragment's payload.
    /// Equality expires, matching the stream timer's `now >= deadline` rule.
    /// Checked arithmetic exhaustion is also expiration.
    pub fn is_expired_at(&self, bytes: usize, last: Option<Instant>, now: Instant) -> bool {
        if self.hard.is_some_and(|hard| now >= hard) {
            return true;
        }
        let Some(idle) = self.idle.filter(|d| !d.is_zero()) else {
            return false;
        };
        let deadline = if let Some(rate) = self.minimum_rate {
            let Some(bytes) = u64::try_from(bytes)
                .ok()
                .and_then(|n| self.flushed_before.checked_add(n))
            else {
                return true;
            };
            let ns = u128::from(bytes) * 1_000_000_000 / u128::from(rate.get());
            let Ok(secs) = u64::try_from(ns / 1_000_000_000) else {
                return true;
            };
            self.installed
                .checked_add(idle)
                .and_then(|t| t.checked_add(Duration::new(secs, (ns % 1_000_000_000) as u32)))
        } else {
            let last = last
                .or(self.last_flush)
                .map_or(self.pending_since, |t| t.max(self.pending_since));
            last.checked_add(idle)
        };
        deadline.is_none_or(|at| now >= at)
    }
}
/// Exact immutable write constraints whose prepaid owner follows the real
/// receipt State. The scoped form contains only scalar clocks and an Arc to
/// concrete allocation ownership, never foreign callbacks or a stream handle.
#[derive(Clone,Debug)]
pub enum DataWritePolicy {
    /// Legacy single-clause API, retained without changing its Copy DTO.
    Scalar(DataWriteDeadline),
    /// Independently anchored server and route clauses.
    Scoped(native_write_policy::Boundary),
}
impl DataWritePolicy {
    fn is_expired_at(&self,bytes:usize,last:Option<Instant>,now:Instant)->bool {
        match self{Self::Scalar(p)=>p.is_expired_at(bytes,last,now),Self::Scoped(p)=>p.expired_at(bytes,last,now)}
    }
}
impl From<DataWriteDeadline> for DataWritePolicy {fn from(p:DataWriteDeadline)->Self{Self::Scalar(p)}}
/// Conservative opt-in metadata credit, including the entire lazily allocated
/// 256-slot connection retirement table, its slot counter, one live receipt,
/// first platform mutex allocations, and the fixed-capacity codec wire-span deque.
/// Payload storage and the existing codec frame/header buffers are separate.
/// The first response's concrete credit remains with the connection-wide table.
pub const DATA_WRITE_ALLOCATION_UPPER_BYTES: usize = 64 << 10;
// 256 retired payload/credit bundles plus256 preallocated wire spans;
// one queue/slot counter, one State/Relay, native platform mutex first-use
// allocations and allocator alignment/last-Arc teardown slack. Deque capacity
// is fixed at256 (no growth overlap). No user payload
// or pre-existing HTTP frame-store slab is represented by this extra credit.
const DATA_WRITE_LAYOUT_UPPER_BYTES: usize = MAX_DATA_RECEIPTS
    * std::mem::size_of::<RetiredBytes>()
    + MAX_DATA_RECEIPTS * std::mem::size_of::<crate::codec::wire_progress::Span>()
    + std::mem::size_of::<crate::codec::wire_progress::WireProgress>()
    + std::mem::size_of::<DeferredData>()
    + std::mem::size_of::<State>()
    + std::mem::size_of::<Relay>()
    + std::mem::size_of::<AtomicUsize>()
    + 8 * std::mem::size_of::<usize>()
    + 1024;
const _: () = assert!(DATA_WRITE_LAYOUT_UPPER_BYTES <= DATA_WRITE_ALLOCATION_UPPER_BYTES);

pub(crate) const MAX_DATA_RECEIPTS: usize = 256;
pub(crate) const MAX_DATA_BOUNDARY: usize = 16 << 10;

pub(crate) struct DeferredData {
    slots: Arc<AtomicUsize>,
    retired: Mutex<Vec<RetiredBytes>>,
    // The first opted-in response prepays the connection-wide fixed tables.
    // This concrete guard follows the real last queue/codec/connection owner.
    _retained: Option<Bytes>,
}
struct Slot(Arc<AtomicUsize>);
impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}
struct RetiredBytes {
    bytes: Option<Bytes>,
    credit: Option<Bytes>,
    slot: Option<Slot>,
    relay: Weak<Relay>,
}
impl Drop for RetiredBytes {
    fn drop(&mut self) {
        drop(self.bytes.take());
        drop(self.credit.take());
        drop(self.slot.take());
        if let Some(relay) = self.relay.upgrade() {
            relay.notify();
        }
    }
}
impl DeferredData {
    pub(crate) fn new(retained: Option<Bytes>) -> Arc<Self> {
        Arc::new(Self {
            _retained: retained,
            slots: Arc::new(AtomicUsize::new(0)),
            retired: Mutex::new(Vec::with_capacity(MAX_DATA_RECEIPTS)),
        })
    }
    fn reserve(&self) -> Option<Slot> {
        self.slots
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < MAX_DATA_RECEIPTS).then_some(n + 1)
            })
            .ok()
            .map(|_| Slot(self.slots.clone()))
    }
    fn retire(&self, bytes: Bytes, credit: Option<Bytes>, slot: Slot, relay: Weak<Relay>) {
        let mut retired = self.retired.lock().unwrap_or_else(|e| e.into_inner());
        assert!(
            retired.len() < MAX_DATA_RECEIPTS,
            "bounded DATA release queue"
        );
        retired.push(RetiredBytes {
            bytes: Some(bytes),
            credit,
            slot: Some(slot),
            relay,
        });
    }
    /// No stream/store lock may be held by the caller. Pop before running a
    /// byte owner's Drop, so reentrant owners never run under this mutex either.
    pub(crate) fn drain(&self) {
        loop {
            let next = self.retired.lock().unwrap_or_else(|e| e.into_inner()).pop();
            match next {
                Some(next) => drop(next),
                None => break,
            }
        }
    }
}
impl fmt::Debug for DeferredData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeferredData")
            .field("reserved", &self.slots.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

struct Relay(Mutex<Option<Waker>>);
impl Relay {
    fn register(&self, cx: &Context<'_>) {
        let incoming = cx.waker().clone();
        let old = self
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .replace(incoming);
        drop(old);
    }
    fn notify(&self) {
        let waiter = self.0.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(waiter) = waiter {
            waiter.wake();
        }
    }
}
struct Progress {
    version: u64,
    owners: usize,
    wire_owners: usize,
    abandoned: bool,
    flushed: usize,
    last: Option<Instant>,
    total: usize,
    retained: Option<(Bytes, Option<Bytes>, Slot)>,
    deadline: Option<DataWritePolicy>,
    expired: bool,
}
struct State {
    progress: Mutex<Progress>,
    queue: Arc<DeferredData>,
    relay: Weak<Relay>,
}
impl State {
    fn snapshot(&self) -> DataWriteSnapshot {
        let p = self.progress.lock().unwrap_or_else(|e| e.into_inner());
        DataWriteSnapshot {
            version: p.version,
            expired: p.expired,
            wire_complete: p.wire_owners == 0 && !p.abandoned,
            flushed_bytes: p.flushed,
            last_flush: p.last,
            outcome: if p.owners != 0 {
                None
            } else if p.abandoned {
                Some(SendOutcome::Abandoned)
            } else {
                Some(SendOutcome::Flushed(p.last.expect("completed DATA flush")))
            },
        }
    }
    fn retire_owner(&self) {
        self.release(true, true);
    }
    fn release_source(&self) {
        self.release(false, false);
    }
    // A final physical event publishes bytes, timestamp and completion under
    // one mutex. A timer cannot observe "final progress, not complete yet".
    fn progress(&self, bytes: usize, now: Instant, complete: bool) {
        let mut p = self.progress.lock().unwrap_or_else(|e| e.into_inner());
        if p.deadline.as_ref()
            .is_some_and(|policy| policy.is_expired_at(p.flushed, p.last, now))
        {
            p.expired = true;
        }
        p.flushed = p
            .flushed
            .checked_add(bytes)
            .filter(|n| *n <= p.total)
            .expect("bounded payload progress");
        p.last = Some(p.last.map_or(now, |last| last.max(now)));
        if complete {
            assert!(p.owners > 0 && p.wire_owners > 0);
            p.owners -= 1;
            p.wire_owners -= 1;
        }
        p.version += 1;
    }
    fn release(&self, abandon: bool, wire: bool) {
        let mut p = self.progress.lock().unwrap_or_else(|e| e.into_inner());
        assert!(p.owners > 0, "unique DATA owner");
        p.owners -= 1;
        if wire {
            assert!(p.wire_owners > 0);
            p.wire_owners -= 1;
        }
        p.abandoned |= abandon;
        p.version += 1;
        // Logical completion is not a metadata/payload allocation fence.
        // The retained bundle and admission slot stay until the real last Arc.
    }
}
impl Drop for State {
    fn drop(&mut self) {
        let p = self.progress.get_mut().unwrap_or_else(|e| e.into_inner());
        if let Some((bytes, credit, slot)) = p.retained.take() {
            // Last Arc may die under the stream/store lock. Move ownership to
            // the already-reserved queue without invoking foreign destructors.
            self.queue.retire(bytes, credit, slot, self.relay.clone());
        }
    }
}

/// Observed payload progress for one bounded application DATA boundary.
#[derive(Clone, Copy, Debug)]
pub struct DataWriteSnapshot {
    /// All concrete wire owners retired, independently of source Buf reclaim.
    pub wire_complete: bool,
    /// A physical flush exceeded its precompiled deadline. Sticky even when the
    /// stream future was not polled promptly; actual payload accounting remains.
    pub expired: bool,
    /// Monotonic bounded-receipt revision.
    pub version: u64,
    /// Actual payload bytes that passed successful transport flush.
    pub flushed_bytes: usize,
    /// Last physical fragment flush time.
    pub last_flush: Option<Instant>,
    /// Whole-boundary terminal outcome, after every fragment owner retires.
    pub outcome: Option<SendOutcome>,
}
/// Single consumer for a bounded DATA boundary. Keep polling the send stream's
/// reset notification as usual; abandonment also follows that existing wakeup.
/// Dropping this receiver cancels only its stream. A terminal result does not
/// refund retained DATA until the connection driver drains actual owners.
pub struct DataWriteReceipt<B: Buf> {
    sender: StreamRef<B>,
    state: Option<Arc<State>>,
    relay: Arc<Relay>,
}
impl<B: Buf> fmt::Debug for DataWriteReceipt<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DataWriteReceipt")
            .field("snapshot", &self.snapshot())
            .finish_non_exhaustive()
    }
}
impl<B: Buf> DataWriteReceipt<B> {
    pub(crate) fn new(
        sender: StreamRef<B>,
        bytes: Bytes,
        credit: Option<Bytes>,
        queue: Arc<DeferredData>,
        deadline: Option<DataWritePolicy>,
    ) -> Option<(Self, QueuedDataOwner, SourceDataOwner)> {
        queue.drain(); // caller is outside stream/store locks, before reserve
        let slot = queue.reserve()?;
        let relay = Arc::new(Relay(Mutex::new(None)));
        let total = bytes.len();
        let state = Arc::new(State {
            progress: Mutex::new(Progress {
                version: 0,
                deadline,
                expired: false,
                owners: 2,
                wire_owners: 1,
                abandoned: false,
                flushed: 0,
                last: None,
                total,
                retained: Some((bytes, credit, slot)),
            }),
            queue,
            relay: Arc::downgrade(&relay),
        });
        Some((
            Self {
                sender,
                state: Some(state.clone()),
                relay,
            },
            QueuedDataOwner {
                state: state.clone(),
                active: true,
            },
            SourceDataOwner { state },
        ))
    }
    /// Returns the currently known physical progress without waiting.
    pub fn snapshot(&self) -> DataWriteSnapshot {
        self.state.as_ref().expect("live receipt").snapshot()
    }
    /// One task may poll. Registration, replacement and destruction of foreign
    /// wakers happen outside the h2 stream/store locks and the progress mutex.
    pub fn poll_progress(&self, cx: &mut Context<'_>, version: u64) -> Poll<DataWriteSnapshot> {
        let now = self.snapshot();
        if now.version != version || now.outcome.is_some() {
            return Poll::Ready(now);
        }
        self.relay.register(cx);
        let now = self.snapshot();
        if now.version != version || now.outcome.is_some() {
            Poll::Ready(now)
        } else {
            Poll::Pending
        }
    }
}
impl<B: Buf> Drop for DataWriteReceipt<B> {
    fn drop(&mut self) {
        let state = self.state.take().expect("live receipt");
        let queue = state.queue.clone();
        if !state.snapshot().wire_complete {
            self.sender.send_reset(crate::Reason::CANCEL);
        }
        drop(state); // real last Arc can enqueue its retained bundle here
        queue.drain(); // never while send_reset holds its stream/store lock
    }
}

#[derive(Debug)]
pub(crate) struct QueuedDataOwner {
    state: Arc<State>,
    active: bool,
}
impl fmt::Debug for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DataReceiptState").finish_non_exhaustive()
    }
}
impl QueuedDataOwner {
    pub(crate) fn fork(&self, bytes: usize) -> DataFragmentOwner {
        // Cancellation can retire the receiver and an earlier codec fragment
        // before an in-flight split tail is reclaimed/rescheduled. Notification
        // is optional; the concrete state/payload/credit owners are not.
        let relay = self.state.relay.upgrade();
        let mut p = self
            .state
            .progress
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        assert!(
            p.owners <= MAX_DATA_RECEIPTS + 1,
            "bounded DATA fragment owners"
        );
        p.owners += 1;
        p.wire_owners += 1;
        drop(p);
        DataFragmentOwner {
            state: self.state.clone(),
            relay,
            bytes,
            reported: 0,
            active: true,
        }
    }
    pub(crate) fn last(mut self, bytes: usize) -> DataFragmentOwner {
        // Cancellation can retire the receiver and an earlier codec fragment
        // before an in-flight split tail is reclaimed/rescheduled. Notification
        // is optional; the concrete state/payload/credit owners are not.
        let relay = self.state.relay.upgrade();
        self.active = false;
        DataFragmentOwner {
            state: self.state.clone(),
            relay,
            bytes,
            reported: 0,
            active: true,
        }
    }
}
impl Drop for QueuedDataOwner {
    fn drop(&mut self) {
        if self.active {
            self.state.retire_owner();
        }
    }
}
/// Stays with the original Buf through split/map/reclaim. Even an empty
/// Bytes::from_owner may retain its owner until that Buf itself is dropped.
#[derive(Debug)]
pub(crate) struct SourceDataOwner {
    state: Arc<State>,
}
impl Drop for SourceDataOwner {
    fn drop(&mut self) {
        self.state.release_source();
    }
}

/// Lives in the codec's bounded receipt array, including copied tiny payloads.
pub(crate) struct DataFragmentOwner {
    state: Arc<State>,
    relay: Option<Arc<Relay>>,
    bytes: usize,
    reported: usize,
    active: bool,
}
impl fmt::Debug for DataFragmentOwner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DataFragmentOwner")
            .field("bytes", &self.bytes)
            .finish_non_exhaustive()
    }
}
impl DataFragmentOwner {
    pub(crate) fn retirement_queue(&self) -> Arc<DeferredData> {
        self.state.queue.clone()
    }
    /// Genuine physical progress; an unfinished span retains all its owners.
    pub(crate) fn progress(&mut self, bytes: usize, at: Instant) {
        self.reported = self
            .reported
            .checked_add(bytes)
            .filter(|n| *n <= self.bytes)
            .expect("bounded fragment progress");
        self.state.progress(bytes, at, false);
        if let Some(relay) = self.relay.as_ref() {
            relay.notify();
        }
    }
    pub(crate) fn finish_wire(mut self, bytes: usize, at: Instant) {
        self.reported = self
            .reported
            .checked_add(bytes)
            .expect("bounded final payload");
        assert_eq!(self.reported, self.bytes, "complete physical payload");
        self.active = false;
        self.state.progress(bytes, at, true);
        if let Some(relay) = self.relay.as_ref() {
            relay.notify();
        }
        let queue = self.state.queue.clone();
        drop(self); // release actual metadata Arc/relay before retiring credit
        queue.drain();
    }
}
impl Drop for DataFragmentOwner {
    fn drop(&mut self) {
        if self.active {
            self.state.retire_owner();
        }
    }
}
