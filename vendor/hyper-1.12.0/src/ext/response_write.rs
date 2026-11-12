//! Concrete, opt-in response-write policy and progress, independent of timers.
//! Protocol owners report actual flushes. No user callbacks or wakers are
//! installed in this state; a terminal result is not an allocation-release fence.
use bytes::Bytes;
use std::{
    fmt,
    num::NonZeroU64,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

/// Compile route and server settings before handing the response to a transport.
/// A minimum rate is applied only when a nonzero idle/grace duration is present.
#[derive(Clone, Copy, Debug)]
pub struct WritePolicy {
    /// Fixed monotonic response-write installation epoch.
    pub installed: Instant,
    /// Idle/grace allowance, inactive when absent or zero.
    pub idle: Option<Duration>,
    /// Payload bytes per second earned from successful physical flushes.
    pub minimum_rate: Option<NonZeroU64>,
    /// Independent absolute ceiling, including source pauses.
    pub hard: Option<Instant>,
}
/// Logical transport-producer outcome; never an allocation-release fence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteTerminal {
    /// All required output boundaries flushed successfully.
    Success,
    /// The producer or stream was cancelled or failed.
    Abandoned,
    /// The configured write deadline expired.
    Expired,
}
/// Progress known by the concrete transport owner. Retained frame copies can
/// outlive an expired/abandoned producer; these fields do not refund their credit.
#[derive(Clone, Copy, Debug)]
pub struct WriteSnapshot {
    /// Checked revision of the progress snapshot.
    pub version: u64,
    /// Payload bytes in the current logical pending operation.
    pub pending_bytes: usize,
    /// Time the current nonempty DATA operation started.
    pub pending_since: Option<Instant>,
    /// Total actual payload bytes reported as successfully flushed.
    pub flushed_bytes: u64,
    /// Most recent successful payload flush, independent of flow grants.
    pub last_flush: Option<Instant>,
    /// Logical outcome, without implying retained frame owners are gone.
    pub terminal: Option<WriteTerminal>,
}
/// Native-only prepaid ownership for a bounded successful CONNECT bridge.
/// The bytes carry the actual allocation lease, not a placeholder allocation.
/// When no response-write control is installed, the server uses receipts with
/// no idle, hard or rate rule. An existing control is always reused unchanged.
/// The retained token prepays the bounded raw bridge; concrete protocol
/// tables independently retain allocation-pool credit through their last owner.
#[derive(Clone,Debug)]
pub struct ConnectWriteAllocation {
    /// Actual native session metadata reservation; never a dummy payload buffer.
    pub retained: Bytes,
    /// The same process pool used by scoped route controls on this connection.
    pub pool: native_write_policy::Pool,
}

/// Cloneable observation handle with a single claimable protocol producer.
#[derive(Clone)]
pub struct ResponseWriteControl(Arc<Mutex<State>>);
#[derive(Debug)]
struct State {
    claimed: bool,
    policy: WritePolicy,
    policies: Option<Arc<native_write_policy::PolicySet>>,
    snapshot: WriteSnapshot,
    retained: Option<Bytes>,
}
/// Invalid state, duplicate claim, or checked arithmetic exhaustion.
#[derive(Clone, Copy, Debug)]
pub struct WriteControlError;
impl fmt::Display for WriteControlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("response write policy state invalid or exhausted")
    }
}
impl std::error::Error for WriteControlError {}
impl fmt::Debug for ResponseWriteControl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResponseWriteControl")
            .field("snapshot", &self.snapshot())
            .finish_non_exhaustive()
    }
}
impl ResponseWriteControl {
    /// Conservative credit for the cell, first platform-mutex use, and a
    /// short last-Arc teardown overlap. Linux/macOS clones add no heap cell.
    pub const ALLOCATION_UPPER_BYTES: usize = 2
        * (std::mem::size_of::<Mutex<State>>()
            + 2 * std::mem::size_of::<usize>()
            + std::mem::align_of::<Mutex<State>>())
        + 128;
    /// Additional native HTTP/2 credit to prepay before installing this opt-in
    /// control. Includes h2's fixed connection tables/receipt and this protocol
    /// owner's bounded box/timer storage for the native Tokio timer. Payload,
    /// body producer and existing HTTP frame/header buffers remain separate.
    /// The first response's guard can live until the real connection closes.
    #[cfg(feature = "http2")]
    pub const H2_PROTOCOL_ALLOCATION_UPPER_BYTES: usize =
        h2::ext::DATA_WRITE_ALLOCATION_UPPER_BYTES + 4096;
    /// Native HTTP/2 allowance including its one bounded ready-final slot.
    /// Also reserves 64KiB for a claimed CONNECT bridge: two queued 16KiB
    /// payloads, one actor payload and one actual codec tail. Guards remain
    /// retained until the actual last frame/bridge owner is released.
    /// The generic body is moved, never duplicated; its pre-existing payload
    /// and header allocations remain separately owned and prepaid by the caller.
    #[cfg(feature = "http2")]
    pub fn native_h2_protocol_allocation_upper_bytes<B: crate::body::Body<Data = Bytes>>() -> Option<usize> {
        Self::H2_PROTOCOL_ALLOCATION_UPPER_BYTES
            .checked_add(64usize << 10)?
            .checked_add(std::mem::size_of::<http::Response<B>>())?
            .checked_add(std::mem::align_of::<http::Response<B>>())
    }
    /// Additional native HTTP/1 allowance for Bytes encoding, the native
    /// bounded timer/owner, and one queued final response while an interim or
    /// automatic 100 boundary is still flushing. Existing payload/header
    /// storage and the separately prepaid policy set are not included. Generic
    /// Buf implementations and arbitrary host timers need their own bounds.
    #[cfg(feature="http1")]
    pub fn native_h1_protocol_allocation_upper_bytes<B:crate::body::Body<Data=Bytes>>()->Option<usize>{
        (64usize<<10).checked_add(std::mem::size_of::<(crate::proto::MessageHead<http::StatusCode>,B)>())?.checked_add(128)
    }
    /// Creates an observation cell without an external allocation-retention guard.
    pub fn new(policy: WritePolicy) -> Self {
        Self::create(policy, None, None)
    }
    /// Creates a cell whose real last Arc and protocol receipts retain the
    /// concrete owned byte guard. The guard must not reference this cell.
    pub fn new_with_retention(policy: WritePolicy, guard: Bytes) -> Self {
        Self::create(policy, Some(guard), None)
    }
    /// Creates a uniquely claimable transport control with exact prepaid route
    /// and server clauses. The fallback scalar remains for legacy integrations;
    /// scoped transports must use `scoped_boundary` when one is present.
    pub fn new_with_policies(policy:WritePolicy, policies:Arc<native_write_policy::PolicySet>, retained:Option<Bytes>)->Self {
        Self::create(policy,retained,Some(policies))
    }
    fn create(policy: WritePolicy, retained: Option<Bytes>, policies:Option<Arc<native_write_policy::PolicySet>>) -> Self {
        Self(Arc::new(Mutex::new(State {
            claimed: false,
            retained,
            policy,
            policies,
            snapshot: WriteSnapshot {
                version: 0,
                pending_bytes: 0,
                pending_since: None,
                flushed_bytes: 0,
                last_flush: None,
                terminal: None,
            },
        })))
    }
    /// Concrete scoped allocation pool, if one was explicitly installed. Native
    /// transports may prepay their own named metadata before allocating it.
    pub fn allocation_pool(&self)->Option<native_write_policy::Pool>{
        self.0.lock().unwrap_or_else(|e|e.into_inner()).policies.as_ref().map(|p|p.allocation_pool())
    }
    /// Replace the complete compiled native clause set between physical
    /// boundaries, before any response payload has been transmitted. This is
    /// for the same producer adding nested route settings after an acknowledged
    /// interim response; callers must retain all earlier active constraints.
    /// The concrete allocation pool cannot change, and failed replacement does
    /// not mutate the current policy. No external configuration wake is provided.
    pub fn replace_scoped_policies(&self,policies:Arc<native_write_policy::PolicySet>)->Result<(),WriteControlError>{
        let old={
            let mut state=self.0.lock().unwrap_or_else(|e|e.into_inner());
            let current=state.policies.as_ref().ok_or(WriteControlError)?;
            if state.snapshot.terminal.is_some() || state.snapshot.pending_since.is_some()
                || state.snapshot.flushed_bytes!=0
                || !current.allocation_pool().same_owner(&policies.allocation_pool()) {
                return Err(WriteControlError);
            }
            bump(&mut state.snapshot)?;
            state.policies.replace(policies)
        };
        drop(old);Ok(())
    }
    /// Whether both handles refer to the same concrete response scope.
    pub fn same_control(&self,other:&Self)->bool{Arc::ptr_eq(&self.0,&other.0)}
    /// Returns the immutable compiled policy.
    pub fn policy(&self) -> WritePolicy {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).policy
    }
    /// Returns known producer progress.
    pub fn snapshot(&self) -> WriteSnapshot {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).snapshot
    }
    /// Claims the unique protocol producer. Reusing this observation handle on
    /// another response fails without modifying the already-claimed stream.
    pub fn claim(&self) -> Result<ResponseWriteOwner, WriteControlError> {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if state.claimed || state.snapshot.terminal.is_some() {
            return Err(WriteControlError);
        }
        state.claimed = true;
        bump(&mut state.snapshot)?;
        drop(state);
        Ok(ResponseWriteOwner {
            control: self.clone(),
        })
    }
    /// Pure checked deadline calculation. The protocol supplies and polls its
    /// own timer. A configured hard ceiling remains active during source pauses.
    pub fn deadline(&self) -> Result<Option<Instant>, WriteControlError> {
        let state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if state.snapshot.terminal.is_some(){return Ok(None)}
        if let Some(policies)=&state.policies {
            return policies.deadline(state.snapshot.flushed_bytes,state.snapshot.pending_since,state.snapshot.last_flush).map_err(|_|WriteControlError)
        }
        deadline(state.policy, state.snapshot)
    }
    fn scoped_boundary(&self)->Result<Option<native_write_policy::Boundary>,WriteControlError>{
        let state=self.0.lock().unwrap_or_else(|e|e.into_inner());
        state.policies.as_ref().map(|policies| {
            let pending=state.snapshot.pending_since.ok_or(WriteControlError)?;
            Ok(policies.boundary(pending,state.snapshot.last_flush,state.snapshot.flushed_bytes))
        }).transpose()
    }
}
/// The single concrete transport producer. It is intentionally not Clone.
#[must_use]
#[derive(Debug)]
pub struct ResponseWriteOwner {
    control: ResponseWriteControl,
}
impl ResponseWriteOwner {
    /// Returns the immutable compiled policy.
    pub fn policy(&self) -> WritePolicy {
        self.control.policy()
    }
    /// Tests identity without reclaiming the unique producer, so interim and
    /// final response boundaries can share one control safely.
    pub fn same_control(&self,control:&ResponseWriteControl)->bool{Arc::ptr_eq(&self.control.0,&control.0)}

    /// Returns known producer progress.
    pub fn snapshot(&self) -> WriteSnapshot {
        self.control.snapshot()
    }
    /// Exact immutable active clauses anchored to this pending physical boundary.
    /// Clones retain their own concrete allocation lease through protocol tails.
    pub fn scoped_boundary(&self)->Result<Option<native_write_policy::Boundary>,WriteControlError>{
        self.control.scoped_boundary()
    }

    /// Calculates the current checked deadline without owning a timer.
    pub fn deadline(&self) -> Result<Option<Instant>, WriteControlError> {
        self.control.deadline()
    }
    /// Retains prepaid native allocation ownership through actual codec tails.
    pub fn retention(&self) -> Option<Bytes> {
        self.control
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retained
            .clone()
    }
    /// Called after acquiring a nonempty body chunk, before waiting for flow
    /// control. Merely polling an empty/SSE source does not start an idle clock.
    pub fn start_data(&self, bytes: usize, now: Instant) -> Result<(), WriteControlError> {
        if bytes == 0 {
            return Ok(());
        }
        self.start_boundary(bytes, now)
    }
    /// Starts a concrete transport boundary, including zero-payload FIN or
    /// headers. Never call this merely because an SSE/body source is Pending.
    pub fn start_boundary(&self, bytes: usize, now: Instant) -> Result<(), WriteControlError> {
        let mut state = self.control.0.lock().unwrap_or_else(|e| e.into_inner());
        if state.snapshot.terminal.is_some() || state.snapshot.pending_since.is_some() {
            return Err(WriteControlError);
        }
        state.snapshot.pending_bytes = bytes;
        state.snapshot.pending_since = Some(now);
        bump(&mut state.snapshot)
    }
    /// Withdraw a zero-payload boundary only when the protocol rejected its
    /// encoding before accepting any wire bytes. The exact start revision must
    /// still match, so this cannot erase a reported physical flush or deadline.
    /// This is not progress and earns no time or payload credit.
    pub fn discard_unwritten_boundary(&self, start_revision:u64)->Result<(),WriteControlError>{
        let mut state=self.control.0.lock().unwrap_or_else(|e|e.into_inner());
        let snapshot=&mut state.snapshot;
        if snapshot.terminal.is_some() || snapshot.pending_since.is_none()
            || snapshot.pending_bytes!=0 || snapshot.version!=start_revision {
            return Err(WriteControlError);
        }
        snapshot.pending_since=None;
        bump(snapshot)
    }
    /// Only the successful transport-flush owner reports payload progress.
    /// WINDOW_UPDATE, send_data acceptance, and body polling are not progress.
    pub fn flushed(&self, bytes: usize, now: Instant) -> Result<(), WriteControlError> {
        let mut state = self.control.0.lock().unwrap_or_else(|e| e.into_inner());
        let snapshot = &mut state.snapshot;
        let next = u64::try_from(bytes)
            .ok()
            .and_then(|n| snapshot.flushed_bytes.checked_add(n));
        if bytes > snapshot.pending_bytes
            || next.is_none()
            || (bytes == 0 && snapshot.pending_bytes != 0)

        {
            snapshot.terminal = Some(WriteTerminal::Abandoned);
            return Err(WriteControlError);
        }
        snapshot.pending_bytes -= bytes;
        snapshot.flushed_bytes = next.expect("checked payload total");
        if bytes != 0 || snapshot.pending_since.is_some() {
            snapshot.last_flush = Some(now);
        }
        if snapshot.pending_bytes == 0 {
            snapshot.pending_since = None;
        }
        bump(snapshot)
    }
    /// Records actual non-payload wire progress within an existing boundary.
    /// The transport must have successfully flushed real header/chunk framing
    /// bytes. This updates idle progress only: payload count, pending length,
    /// boundary completion and fixed rate earnings are unchanged.
    pub fn wire_flushed(&self, now:Instant)->Result<(),WriteControlError>{
        let mut state=self.control.0.lock().unwrap_or_else(|e|e.into_inner());
        let snapshot=&mut state.snapshot;
        if snapshot.pending_since.is_none(){return Err(WriteControlError)}
        snapshot.last_flush=Some(snapshot.last_flush.map_or(now,|last|last.max(now)));
        bump(snapshot)
    }
    /// Success requires the final body/end boundary to have actually flushed.
    pub fn finish(&self) -> Result<(), WriteControlError> {
        let mut state = self.control.0.lock().unwrap_or_else(|e| e.into_inner());
        let snapshot = &mut state.snapshot;
        if snapshot.pending_since.is_some()
            || snapshot
                .terminal
                .is_some_and(|v| v != WriteTerminal::Success)
        {
            return Err(WriteControlError);
        }
        if snapshot.terminal.is_none() {
            snapshot.terminal = Some(WriteTerminal::Success);
            bump(snapshot)?;
        }
        Ok(())
    }
    /// Marks logical abandonment without refunding the retained owner.
    pub fn abandon(&self) {
        self.terminal(WriteTerminal::Abandoned);
    }
    /// Marks expiry; later tail progress cannot turn it into success.
    pub fn expire(&self) {
        self.terminal(WriteTerminal::Expired);
    }
    fn terminal(&self, value: WriteTerminal) {
        let mut state = self.control.0.lock().unwrap_or_else(|e| e.into_inner());
        if state.snapshot.terminal.is_none() {
            state.snapshot.terminal = Some(value);
            let _ = bump(&mut state.snapshot);
        }
    }
}
impl Drop for ResponseWriteOwner {
    fn drop(&mut self) {
        self.abandon();
    }
}

fn bump(snapshot: &mut WriteSnapshot) -> Result<(), WriteControlError> {
    if let Some(next) = snapshot.version.checked_add(1) {
        snapshot.version = next;
        Ok(())
    } else {
        snapshot.terminal = Some(WriteTerminal::Abandoned);
        Err(WriteControlError)
    }
}
fn deadline(
    policy: WritePolicy,
    snapshot: WriteSnapshot,
) -> Result<Option<Instant>, WriteControlError> {
    if snapshot.terminal.is_some() {
        return Ok(None);
    }
    let Some(pending) = snapshot.pending_since else {
        return Ok(policy.hard);
    };
    let Some(idle) = policy.idle.filter(|idle| !idle.is_zero()) else {
        return Ok(policy.hard);
    };
    let at = if let Some(rate) = policy.minimum_rate {
        let nanos = u128::from(snapshot.flushed_bytes)
            .checked_mul(1_000_000_000)
            .ok_or(WriteControlError)?
            / u128::from(rate.get());
        let seconds = u64::try_from(nanos / 1_000_000_000).map_err(|_| WriteControlError)?;
        let earned = Duration::new(seconds, (nanos % 1_000_000_000) as u32);
        policy
            .installed
            .checked_add(idle)
            .and_then(|at| at.checked_add(earned))
            .ok_or(WriteControlError)?
    } else {
        snapshot
            .last_flush
            .map_or(pending, |last| last.max(pending))
            .checked_add(idle)
            .ok_or(WriteControlError)?
    };
    Ok(Some(policy.hard.map_or(at, |hard| hard.min(at))))
}
