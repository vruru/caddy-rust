//! Generation-owned business activity and read-only retirement completion.
//! A waiter owns signals only: it cannot keep a listener or runtime alive.
use crate::http_config::HttpShutdownPolicy;
use anyhow::{Result, ensure};
use std::sync::{
    Arc, OnceLock,
    atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

const STAGED: u8 = 0;
const PUBLISHED: u8 = 1;
const CLOSED: u8 = 2;
const ABORTED: u8 = 3;
const FORCED: u8 = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetirementOutcome {
    AcceptanceClosed,
    Aborted,
    Forced,
}

#[derive(Clone)]
pub struct HttpRetirement {
    from_generation: u64,
    to_generation: Option<u64>,
    signals: Arc<Signals>,
}
struct Signals {
    state: AtomicU8,
    done: CancellationToken,
    ready: CancellationToken,
    published: AtomicBool,
}
impl HttpRetirement {
    pub(super) fn staged(from_generation: u64, to_generation: Option<u64>) -> Self {
        Self {
            from_generation,
            to_generation,
            signals: Arc::new(Signals {
                state: AtomicU8::new(STAGED),
                done: CancellationToken::new(),
                ready: CancellationToken::new(),
                published: AtomicBool::new(false),
            }),
        }
    }
    pub fn from_generation(&self) -> u64 {
        self.from_generation
    }
    pub fn to_generation(&self) -> Option<u64> {
        self.to_generation
    }
    /// Completion concerns old business admission, not closure of a shared FD.
    /// A discarded candidate yields Aborted; runtime force also wakes waiters.
    pub async fn acceptance_closed(&self) -> Result<RetirementOutcome> {
        self.signals.done.cancelled().await;
        match self.signals.state.load(Ordering::Acquire) {
            CLOSED => Ok(RetirementOutcome::AcceptanceClosed),
            ABORTED => Ok(RetirementOutcome::Aborted),
            FORCED => Ok(RetirementOutcome::Forced),
            _ => anyhow::bail!("HTTP retirement completion state unavailable"),
        }
    }
    pub(super) async fn activated(&self) -> bool {
        self.signals.ready.cancelled().await;
        matches!(
            self.signals.state.load(Ordering::Acquire),
            PUBLISHED | CLOSED
        )
    }
    pub(super) fn is_aborted(&self) -> bool {
        self.signals.state.load(Ordering::Acquire) == ABORTED
    }
    pub(super) fn is_published(&self) -> bool {
        self.signals.published.load(Ordering::Acquire)
    }
    /// Claim publication before mutating the view, but do not wake the actor
    /// until the new snapshot and ownership map have both been installed.
    pub(super) fn reserve_publication(&self) -> bool {
        if self
            .signals
            .state
            .compare_exchange(STAGED, PUBLISHED, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.signals.published.store(true, Ordering::Release);
            true
        } else {
            false
        }
    }
    pub(super) fn published(&self) {
        let _ = self.reserve_publication();
        self.signals.ready.cancel();
    }
    pub(super) fn complete(&self, outcome: RetirementOutcome) {
        let target = match outcome {
            RetirementOutcome::AcceptanceClosed => CLOSED,
            RetirementOutcome::Aborted => ABORTED,
            RetirementOutcome::Forced => FORCED,
        };
        if self
            .signals
            .state
            .try_update(Ordering::AcqRel, Ordering::Acquire, |state| {
                (state < CLOSED).then_some(target)
            })
            .is_ok()
        {
            self.signals.ready.cancel();
            self.signals.done.cancel();
        }
    }
}

pub(super) struct AdmissionGroup {
    pub signal: HttpRetirement,
    pub activity: Arc<BusinessGeneration>,
    remaining: AtomicUsize,
}
impl AdmissionGroup {
    pub fn new(
        signal: HttpRetirement,
        activity: Arc<BusinessGeneration>,
        bindings: usize,
    ) -> Arc<Self> {
        Arc::new(Self {
            signal,
            activity,
            remaining: AtomicUsize::new(bindings),
        })
    }
    pub fn publish(&self) {
        self.signal.published();
        if self.remaining.load(Ordering::Acquire) == 0 {
            self.activity.close_admission();
            self.signal.complete(RetirementOutcome::AcceptanceClosed);
        }
    }
    /// Each binding calls this only after its one true->false admission change.
    pub fn member_closed(&self) {
        let before = self.remaining.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(before > 0);
        if before == 1 {
            self.activity.close_admission();
            self.signal.complete(RetirementOutcome::AcceptanceClosed);
        }
    }
}

struct DelayClock {
    started: Instant,
    duration: Duration,
}
/// Shared by all requests of one HTTP app generation. A connection can own
/// simultaneous requests from multiple generations; never close by accept age.
pub(super) struct BusinessGeneration {
    pub id: u64,
    pub policy: HttpShutdownPolicy,
    pub superseded: CancellationToken,
    pub admission_closed: CancellationToken,
    pub drain: CancellationToken,
    pub hard_stop: CancellationToken,
    active: AtomicUsize,
    admitting: AtomicBool,
    changed: Notify,
    clock: OnceLock<DelayClock>,
}
impl BusinessGeneration {
    pub fn new(id: u64, policy: HttpShutdownPolicy) -> Arc<Self> {
        Arc::new(Self {
            id,
            policy,
            superseded: CancellationToken::new(),
            admission_closed: CancellationToken::new(),
            drain: CancellationToken::new(),
            hard_stop: CancellationToken::new(),
            active: AtomicUsize::new(0),
            admitting: AtomicBool::new(true),
            changed: Notify::new(),
            clock: OnceLock::new(),
        })
    }
    /// Increment before rechecking the latest binding view. This prevents a
    /// retirement from observing zero between admission and a live request.
    pub fn begin(self: &Arc<Self>) -> Result<Arc<BusinessGuard>> {
        self.active
            .try_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                count.checked_add(1)
            })
            .map_err(|_| anyhow::anyhow!("HTTP activity capacity exhausted"))?;
        let guard = Arc::new(BusinessGuard {
            generation: self.clone(),
        });
        ensure!(
            self.admitting.load(Ordering::Acquire) && !self.hard_stop.is_cancelled(),
            "HTTP business generation stopped"
        );
        Ok(guard)
    }
    pub fn start_delay(&self, duration: Duration) {
        if !duration.is_zero() {
            let _ = self.clock.set(DelayClock {
                started: Instant::now(),
                duration,
            });
        }
    }
    pub fn shutting_down(&self) -> bool {
        self.clock.get().is_some()
    }
    pub fn time_until_shutdown(&self) -> Option<String> {
        let clock = self.clock.get()?;
        let nanos = clock.duration.as_nanos() as i128 - clock.started.elapsed().as_nanos() as i128;
        Some(format_duration(
            nanos.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64,
        ))
    }
    pub async fn wait_delay(&self) {
        let Some(clock) = self.clock.get() else {
            return;
        };
        loop {
            let remaining = clock.duration.saturating_sub(clock.started.elapsed());
            if remaining.is_zero() {
                return;
            }
            // Avoid timer-wheel maximum-range assumptions for valid very long
            // Go durations. Force remains immediately observable in each chunk.
            tokio::select! {biased;
                _=self.hard_stop.cancelled()=>return,
                _=tokio::time::sleep(remaining.min(Duration::from_secs(86400)))=>{},
            }
        }
    }
    pub async fn wait_idle(&self) {
        loop {
            let notified = self.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.active.load(Ordering::Acquire) == 0 {
                return;
            }
            notified.await;
        }
    }
    pub fn is_admitting(&self) -> bool {
        self.admitting.load(Ordering::Acquire)
    }
    pub fn close_admission(&self) {
        self.admitting.store(false, Ordering::Release);
        self.admission_closed.cancel();
    }
    pub fn force(&self) {
        self.close_admission();
        self.hard_stop.cancel();
        self.drain.cancel();
    }
}
pub(super) struct BusinessGuard {
    generation: Arc<BusinessGeneration>,
}
impl BusinessGuard {
    /// Sharing this guard retains the same business request through its body
    /// and optional WS upgrade; the final owner performs the single decrement.
    pub fn generation(&self) -> &Arc<BusinessGeneration> {
        &self.generation
    }
}

impl Drop for BusinessGuard {
    fn drop(&mut self) {
        if self.generation.active.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.generation.changed.notify_waiters();
        }
    }
}

/// Canonical time.Duration display; arithmetic is integer-only, including MIN.
pub(super) fn format_duration(nanos: i64) -> String {
    if nanos == 0 {
        return "0s".into();
    }
    let sign = if nanos < 0 { "-" } else { "" };
    let n = nanos.unsigned_abs();
    if n < 1_000_000_000 {
        let (divisor, unit) = if n < 1_000 {
            (1, "ns")
        } else if n < 1_000_000 {
            (1_000, "µs")
        } else {
            (1_000_000, "ms")
        };
        return format!("{sign}{}{}", decimal(n, divisor), unit);
    }
    let hours = n / 3_600_000_000_000;
    let minutes = n / 60_000_000_000 % 60;
    let seconds = n % 60_000_000_000;
    if hours > 0 {
        format!(
            "{sign}{hours}h{minutes}m{}s",
            decimal(seconds, 1_000_000_000)
        )
    } else if minutes > 0 {
        format!("{sign}{minutes}m{}s", decimal(seconds, 1_000_000_000))
    } else {
        format!("{sign}{}s", decimal(seconds, 1_000_000_000))
    }
}
fn decimal(value: u64, divisor: u64) -> String {
    let whole = value / divisor;
    let remainder = value % divisor;
    if remainder == 0 {
        return whole.to_string();
    }
    let width = divisor.ilog10() as usize;
    let fraction = format!("{remainder:0width$}");
    format!("{whole}.{}", fraction.trim_end_matches('0'))
}
