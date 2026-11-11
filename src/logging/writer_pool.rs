//! Per-physical-writer actors. Lease counts and generations, not Arc/Weak
//! guesses, decide when a writer retires. No table lock is held across await/I/O.
use super::activity::{Activity, Token};
use anyhow::{Result, anyhow, ensure};
use std::{
    collections::HashMap,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{Arc, Mutex, Weak, mpsc},
    thread,
    time::Instant,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, oneshot, watch};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    Closed,
    Full,
    Open,
    Panicked,
    Abandoned,
    Write,
    Flush,
    Encode,
    EncodingQueue,
    EncodingBytes,
    DestinationBytes,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Written {
    Bytes(usize),
    Fallback(usize),
}
pub(super) trait WriterIo: Send + 'static {
    fn write(&mut self, bytes: &[u8]) -> std::result::Result<Written, Error>;
    fn flush(&mut self) -> std::result::Result<(), Error>;
    fn idle_deadline(&self) -> Option<Instant> {
        None
    }
    fn idle(&mut self) {}
}
pub(super) type Factory =
    Box<dyn FnOnce() -> std::result::Result<Box<dyn WriterIo>, Error> + Send + 'static>;
pub(super) struct Frame {
    pub bytes: Vec<u8>,
    pub credit: OwnedSemaphorePermit,
    pub writer_credit: Option<(OwnedSemaphorePermit, OwnedSemaphorePermit)>,
}
pub(super) struct Work {
    pub frame: oneshot::Receiver<std::result::Result<Frame, Error>>,
    pub result: oneshot::Sender<std::result::Result<Written, Error>>,
    /// Owns the plan scope, record and global job credit through actual I/O.
    pub hold: Box<dyn Send>,
}
enum Message {
    Write(Work, OwnedSemaphorePermit),
    Flush(
        oneshot::Sender<std::result::Result<(), Error>>,
        OwnedSemaphorePermit,
    ),
}
type Ready = Option<std::result::Result<Arc<Core>, Error>>;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Exit {
    Clean,
    Failed(Error),
}
pub(super) type Done = watch::Receiver<Option<Exit>>;
struct Table {
    closed: bool,
    next: u64,
    keys: HashMap<Arc<str>, Slot>,
    key_bytes: usize,
    exits: [usize; 3],
}
enum Slot {
    Opening {
        generation: u64,
        leases: usize,
        ready: watch::Receiver<Ready>,
        done: Done,
        key: Arc<str>,
    },
    Open {
        generation: u64,
        leases: usize,
        pinned: bool,
        core: Arc<Core>,
        done: Done,
        key: Arc<str>,
    },
    Closing {
        generation: u64,
        done: Done,
        key: Arc<str>,
    },
}
impl Slot {
    fn generation(&self) -> u64 {
        match self {
            Self::Opening { generation, .. }
            | Self::Open { generation, .. }
            | Self::Closing { generation, .. } => *generation,
        }
    }
    fn key(&self) -> &Arc<str> {
        match self {
            Self::Opening { key, .. } | Self::Open { key, .. } | Self::Closing { key, .. } => key,
        }
    }
    fn done(&self) -> &Done {
        match self {
            Self::Opening { done, .. } | Self::Open { done, .. } | Self::Closing { done, .. } => {
                done
            }
        }
    }
}
pub(super) struct Pool {
    table: Mutex<Table>,
    actors: Arc<Semaphore>,
    activity: Arc<Activity>,
    queue: usize,
    budgets: Budgets,
    max_keys: usize,
    max_key_bytes: usize,
}
/// Attributed work and allocation headroom for one physical generation.
#[derive(Clone, Copy)]
pub(super) struct Budgets {
    pub buffered: usize,
    pub event: usize,
    pub jobs: usize,
    pub workspace: usize,
}
pub(super) struct WorkCredits {
    _event: OwnedSemaphorePermit,
    _job: OwnedSemaphorePermit,
}
pub(super) struct Core {
    sender: Mutex<Option<mpsc::SyncSender<Message>>>,
    capacity: Arc<Semaphore>,
    buffered: Arc<Semaphore>,
    event: Arc<Semaphore>,
    jobs: Arc<Semaphore>,
    workspace: Arc<Semaphore>,
    pub generation: u64,
    pub options: [u8; 32],
    done: Done,
}
struct Claim {
    pool: Arc<Pool>,
    key: Arc<str>,
    generation: u64,
    live: bool,
}
pub(super) struct Lease {
    _claim: Claim,
    pub core: Arc<Core>,
    pub reused: bool,
    pub changed_options: bool,
}
pub(super) struct Reservation {
    core: Arc<Core>,
    credit: OwnedSemaphorePermit,
}
impl Lease {
    /// Wait only for a physical actor which is actually retiring; another
    /// live plan (or process stdio) can keep this writer open indefinitely.
    pub(super) fn retire(mut self) -> Option<Done> {
        debug_assert_eq!(self._claim.generation, self.core.generation);
        self._claim.live = false;
        self._claim
            .pool
            .release(&self._claim.key, self._claim.generation)
            .unwrap_or_else(|()| Some(self.core.completion()))
    }
}
impl Core {
    pub(super) fn reserve_frame(
        &self,
        bytes: usize,
    ) -> std::result::Result<OwnedSemaphorePermit, Error> {
        reserve_credit(&self.buffered, bytes)
    }
    pub(super) fn reserve_work(
        &self,
        event_bytes: usize,
    ) -> std::result::Result<WorkCredits, Error> {
        let job = reserve_credit(&self.jobs, 1)?;
        let event = reserve_credit(&self.event, event_bytes)?;
        Ok(WorkCredits {
            _event: event,
            _job: job,
        })
    }
    pub(super) fn reserve_workspace(
        &self,
        bytes: usize,
    ) -> std::result::Result<OwnedSemaphorePermit, Error> {
        reserve_credit(&self.workspace, bytes)
    }
    pub(super) fn exit(&self) -> Option<Exit> {
        *self.done.borrow()
    }
    pub(super) fn completion(&self) -> Done {
        self.done.clone()
    }
    pub(super) fn reserve(self: &Arc<Self>) -> std::result::Result<Reservation, Error> {
        let credit = self
            .capacity
            .clone()
            .try_acquire_owned()
            .map_err(|error| match error {
                tokio::sync::TryAcquireError::Closed => Error::Closed,
                tokio::sync::TryAcquireError::NoPermits => Error::Full,
            })?;
        Ok(Reservation {
            core: self.clone(),
            credit,
        })
    }
    fn send(&self, message: Message) -> std::result::Result<(), Error> {
        let mut message = Some(message);
        let guard = self.sender.lock().unwrap_or_else(|e| e.into_inner());
        let result = guard
            .as_ref()
            .map(|sender| sender.try_send(message.take().expect("message taken once")));
        // Rejected work can release a Scope -> Lease -> Pool. Destruct it only after
        // releasing this mutex, including the already-closed branch.
        drop(guard);
        match result {
            Some(Ok(())) => Ok(()),
            Some(Err(mpsc::TrySendError::Full(_))) => Err(Error::Full),
            Some(Err(mpsc::TrySendError::Disconnected(_))) | None => Err(Error::Closed),
        }
    }
    fn close(&self) {
        let sender = self.sender.lock().unwrap_or_else(|e| e.into_inner()).take();
        drop(sender);
        self.capacity.close();
        self.buffered.close();
        self.event.close();
        self.jobs.close();
        self.workspace.close();
    }
}
fn reserve_credit(
    semaphore: &Arc<Semaphore>,
    count: usize,
) -> std::result::Result<OwnedSemaphorePermit, Error> {
    let count = u32::try_from(count).map_err(|_| Error::Full)?;
    semaphore
        .clone()
        .try_acquire_many_owned(count)
        .map_err(|error| match error {
            tokio::sync::TryAcquireError::Closed => Error::Closed,
            tokio::sync::TryAcquireError::NoPermits => Error::Full,
        })
}
impl Reservation {
    pub(super) fn write(self, work: Work) -> std::result::Result<(), Error> {
        let Self { core, credit } = self;
        core.send(Message::Write(work, credit))
    }
    pub(super) fn flush(
        self,
    ) -> std::result::Result<oneshot::Receiver<std::result::Result<(), Error>>, Error> {
        let (send, receive) = oneshot::channel();
        let Self { core, credit } = self;
        core.send(Message::Flush(send, credit))?;
        Ok(receive)
    }
}
impl Pool {
    pub(super) fn new(
        max_actors: usize,
        queue: usize,
        max_key_bytes: usize,
        budgets: Budgets,
    ) -> Result<Arc<Self>> {
        ensure!(
            max_actors > 0
                && max_actors <= Semaphore::MAX_PERMITS
                && queue > 0
                && max_key_bytes > 0
                && [
                    budgets.buffered,
                    budgets.event,
                    budgets.jobs,
                    budgets.workspace
                ]
                .into_iter()
                .all(|limit| limit > 0
                    && limit <= Semaphore::MAX_PERMITS
                    && limit <= u32::MAX as usize),
            "invalid logging writer pool limit"
        );
        Ok(Arc::new(Self {
            table: Mutex::new(Table {
                closed: false,
                next: 0,
                keys: HashMap::new(),
                key_bytes: 0,
                exits: [0; 3],
            }),
            actors: Arc::new(Semaphore::new(max_actors)),
            // The semaphore alone limits live actors. This drain counter also
            // covers the short tail after a permit/done is returned, and must
            // not impose a second independently-released capacity limit.
            activity: Activity::new(usize::MAX)?,
            queue,
            budgets,
            max_keys: max_actors
                .checked_mul(2)
                .and_then(|n| n.checked_add(3))
                .ok_or_else(|| anyhow!("log writer key limit overflow"))?,
            max_key_bytes,
        }))
    }
    pub(super) async fn acquire(
        self: &Arc<Self>,
        key: String,
        options: [u8; 32],
        pinned: bool,
        factory: Factory,
    ) -> std::result::Result<Lease, Error> {
        enum Next {
            Wait(Done),
            Ready(Claim, Arc<Core>, bool),
            Opening(Claim, watch::Receiver<Ready>),
            Start(
                Claim,
                watch::Receiver<Ready>,
                watch::Sender<Ready>,
                watch::Sender<Option<Exit>>,
                OwnedSemaphorePermit,
                Arc<Token>,
                Factory,
            ),
        }
        let mut factory = Some(factory);
        loop {
            let next = {
                let mut table = self.table.lock().unwrap_or_else(|e| e.into_inner());
                if table.closed {
                    return Err(Error::Closed);
                }
                if let Some(slot) = table.keys.get_mut(key.as_str()) {
                    match slot {
                        Slot::Open {
                            generation,
                            leases,
                            core,
                            key,
                            ..
                        } => {
                            *leases = leases.checked_add(1).ok_or(Error::Full)?;
                            Next::Ready(
                                Claim {
                                    pool: self.clone(),
                                    key: key.clone(),
                                    generation: *generation,
                                    live: true,
                                },
                                core.clone(),
                                core.options != options,
                            )
                        }
                        Slot::Opening {
                            generation,
                            leases,
                            ready,
                            key,
                            ..
                        } => {
                            *leases = leases.checked_add(1).ok_or(Error::Full)?;
                            Next::Opening(
                                Claim {
                                    pool: self.clone(),
                                    key: key.clone(),
                                    generation: *generation,
                                    live: true,
                                },
                                ready.clone(),
                            )
                        }
                        Slot::Closing { done, .. } => Next::Wait(done.clone()),
                    }
                } else {
                    if table.keys.len() >= self.max_keys
                        || table
                            .key_bytes
                            .checked_add(key.len())
                            .is_none_or(|n| n > self.max_key_bytes)
                    {
                        return Err(Error::Full);
                    }
                    let permit = self
                        .actors
                        .clone()
                        .try_acquire_owned()
                        .map_err(|_| Error::Full)?;
                    let token = self.activity.begin().map_err(|_| Error::Closed)?;
                    let generation = table.next.checked_add(1).ok_or(Error::Full)?;
                    table.keys.try_reserve(1).map_err(|_| Error::Full)?;
                    let make = factory.take().ok_or(Error::Open)?;
                    table.next = generation;
                    let key: Arc<str> = Arc::from(key.as_str());
                    let (ready, receiver) = watch::channel(None);
                    let (done, exit) = watch::channel(None);
                    table.key_bytes += key.len();
                    table.keys.insert(
                        key.clone(),
                        Slot::Opening {
                            generation,
                            leases: 1,
                            ready: receiver.clone(),
                            done: exit,
                            key: key.clone(),
                        },
                    );
                    Next::Start(
                        Claim {
                            pool: self.clone(),
                            key,
                            generation,
                            live: true,
                        },
                        receiver,
                        ready,
                        done,
                        permit,
                        token,
                        make,
                    )
                }
            };
            match next {
                Next::Wait(mut done) => {
                    wait_done(&mut done).await;
                }
                Next::Ready(claim, core, changed_options) => {
                    drop(factory.take());
                    return Ok(Lease {
                        _claim: claim,
                        core,
                        reused: true,
                        changed_options,
                    });
                }
                Next::Opening(claim, ready) => {
                    drop(factory.take());
                    return ready_lease(claim, ready, true, options).await;
                }
                Next::Start(claim, ready, signal, done, permit, token, make) => {
                    let pool = Arc::downgrade(self);
                    let key = claim.key.clone();
                    let generation = claim.generation;
                    let queue = self.queue;
                    let budgets = self.budgets;
                    // This entire insertion/spawn sequence is synchronous: cancellation cannot
                    // leave an unstarted Opening. The actor, not this waiter, publishes ready.
                    let failure = self.clone();
                    let failure_key = key.clone();
                    let failure_signal = signal.clone();
                    let failure_done = done.clone();
                    let result = thread::Builder::new()
                        .name(format!("caddy-log-io-{generation}"))
                        .spawn(move || {
                            actor(ActorStart {
                                pool,
                                key,
                                generation,
                                options,
                                pinned,
                                queue,
                                budgets,
                                factory: make,
                                ready: signal,
                                done,
                                permit,
                                token,
                            })
                        });
                    if result.is_err() {
                        failure.finish(&failure_key, generation, Exit::Failed(Error::Open));
                        failure_signal.send_replace(Some(Err(Error::Open)));
                        failure_done.send_replace(Some(Exit::Failed(Error::Open)));
                    }
                    // These fallback senders must not survive the await: an
                    // early factory error drops the actor's sender without a
                    // ready value, and that must wake this receiver as closed.
                    drop(failure_signal);
                    drop(failure_done);
                    drop(failure);
                    drop(result);
                    return ready_lease(claim, ready, false, options).await;
                }
            }
        }
    }
    fn begin_exit(&self, key: &str, generation: u64) {
        let old = {
            let mut table = self.table.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(slot) = table.keys.get_mut(key) {
                if slot.generation() == generation && !matches!(slot, Slot::Closing { .. }) {
                    let next = Slot::Closing {
                        generation,
                        done: slot.done().clone(),
                        key: slot.key().clone(),
                    };
                    Some(std::mem::replace(slot, next))
                } else {
                    None
                }
            } else {
                None
            }
        };
        if let Some(Slot::Open { core, .. }) = &old {
            core.close();
        }
        drop(old);
    }
    fn finish(&self, key: &str, generation: u64, exit: Exit) {
        let removed = {
            let mut table = self.table.lock().unwrap_or_else(|e| e.into_inner());
            if table
                .keys
                .get(key)
                .is_some_and(|s| s.generation() == generation)
            {
                let index = match exit {
                    Exit::Clean => 0,
                    Exit::Failed(Error::Panicked) => 2,
                    Exit::Failed(Error::Closed | Error::Abandoned) => 0,
                    _ => 1,
                };
                table.exits[index] = table.exits[index].saturating_add(1);
                let slot = table.keys.remove(key);
                if let Some(slot) = &slot {
                    table.key_bytes -= slot.key().len();
                }
                slot
            } else {
                None
            }
        };
        drop(removed);
    }
    fn release(&self, key: &str, generation: u64) -> std::result::Result<Option<Done>, ()> {
        let removed = {
            let mut table = self.table.lock().unwrap_or_else(|e| e.into_inner());
            let Some(slot) = table.keys.get_mut(key) else {
                return Err(());
            };
            if slot.generation() != generation {
                return Err(());
            }
            match slot {
                Slot::Opening { leases, .. } => {
                    *leases = leases.saturating_sub(1);
                    None
                }
                Slot::Open { leases, pinned, .. } => {
                    *leases = leases.saturating_sub(1);
                    if *leases == 0 && !*pinned {
                        let new = Slot::Closing {
                            generation,
                            done: slot.done().clone(),
                            key: slot.key().clone(),
                        };
                        Some(std::mem::replace(slot, new))
                    } else {
                        None
                    }
                }
                Slot::Closing { done, .. } => return Ok(Some(done.clone())),
            }
        };
        if let Some(Slot::Open { core, .. }) = &removed {
            core.close();
        }
        let done = removed.as_ref().map(|slot| slot.done().clone());
        drop(removed);
        Ok(done)
    }
    /// Close admission immediately. Existing plans should first close their own
    /// gates and drain accepted Scope-owned work. This backstop closes all actors.
    pub(super) fn close(&self) {
        let cores = {
            let mut table = self.table.lock().unwrap_or_else(|e| e.into_inner());
            table.closed = true;
            let mut cores = Vec::new();
            for slot in table.keys.values_mut() {
                if let Slot::Open {
                    generation,
                    core: _,
                    done,
                    key,
                    ..
                } = slot
                {
                    let next = Slot::Closing {
                        generation: *generation,
                        done: done.clone(),
                        key: key.clone(),
                    };
                    let old = std::mem::replace(slot, next);
                    if let Slot::Open { core, .. } = old {
                        cores.push(core);
                    }
                }
            }
            cores
        };
        for core in cores {
            core.close();
        }
    }
    pub(super) async fn drained(&self) {
        self.activity.drained().await;
    }
    pub(super) fn active(&self) -> usize {
        self.activity.active()
    }
    pub(super) fn keys(&self) -> usize {
        self.table
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .keys
            .len()
    }
    /// Clean/failed/panicked actor generations. Contains no filenames/endpoints.
    pub(super) fn exits(&self) -> [usize; 3] {
        self.table.lock().unwrap_or_else(|e| e.into_inner()).exits
    }
    pub(super) fn allowance(&self) -> usize {
        self.actors.available_permits()
    }
}
async fn ready_lease(
    claim: Claim,
    mut ready: watch::Receiver<Ready>,
    reused: bool,
    options: [u8; 32],
) -> std::result::Result<Lease, Error> {
    loop {
        if let Some(result) = ready.borrow_and_update().clone() {
            let core = result?;
            return Ok(Lease {
                _claim: claim,
                changed_options: core.options != options,
                core,
                reused,
            });
        }
        ready.changed().await.map_err(|_| Error::Open)?;
    }
}
async fn wait_done(done: &mut Done) {
    loop {
        if done.borrow_and_update().is_some() {
            return;
        }
        if done.changed().await.is_err() {
            return;
        }
    }
}
impl Drop for Claim {
    fn drop(&mut self) {
        if self.live {
            let _ = self.pool.release(&self.key, self.generation);
        }
    }
}
struct ActorStart {
    pool: Weak<Pool>,
    key: Arc<str>,
    generation: u64,
    options: [u8; 32],
    pinned: bool,
    queue: usize,
    budgets: Budgets,
    factory: Factory,
    ready: watch::Sender<Ready>,
    done: watch::Sender<Option<Exit>>,
    permit: OwnedSemaphorePermit,
    token: Arc<Token>,
}
fn actor(start: ActorStart) {
    let ActorStart {
        pool,
        key,
        generation,
        options,
        pinned,
        queue,
        budgets,
        factory,
        ready,
        done,
        permit,
        token,
    } = start;
    let mut live_core: Option<Weak<Core>> = None;
    let mut current_hold: Option<Box<dyn Send>> = None;
    let mut output = None;
    let mut receiver = None;
    let mut outcome = catch_unwind(AssertUnwindSafe(|| {
        let io = factory()?;
        output = Some(io);
        let (sender, receive) = mpsc::sync_channel(queue);
        receiver = Some(receive);
        let core = Arc::new(Core {
            sender: Mutex::new(Some(sender)),
            capacity: Arc::new(Semaphore::new(queue)),
            buffered: Arc::new(Semaphore::new(budgets.buffered)),
            event: Arc::new(Semaphore::new(budgets.event)),
            jobs: Arc::new(Semaphore::new(budgets.jobs)),
            workspace: Arc::new(Semaphore::new(budgets.workspace)),
            generation,
            options,
            done: done.subscribe(),
        });
        live_core = Some(Arc::downgrade(&core));
        let Some(pool) = pool.upgrade() else {
            core.close();
            ready.send_replace(Some(Err(Error::Closed)));
            return Err(Error::Closed);
        };
        let (accepted, old) = {
            let mut table = pool.table.lock().unwrap_or_else(|e| e.into_inner());
            let closed = table.closed;
            if let Some(slot) = table.keys.get_mut(key.as_ref()) {
                if let Slot::Opening {
                    generation: g,
                    leases,
                    done,
                    key: slot_key,
                    ..
                } = slot
                {
                    if *g == generation {
                        let leases = *leases;
                        let next = if leases > 0 && !closed {
                            Slot::Open {
                                generation,
                                leases,
                                pinned,
                                core: core.clone(),
                                done: done.clone(),
                                key: slot_key.clone(),
                            }
                        } else {
                            Slot::Closing {
                                generation,
                                done: done.clone(),
                                key: slot_key.clone(),
                            }
                        };
                        let old = std::mem::replace(slot, next);
                        (leases > 0 && !closed, Some(old))
                    } else {
                        (false, None)
                    }
                } else {
                    (false, None)
                }
            } else {
                (false, None)
            }
        };
        drop(old);
        drop(pool);
        if !accepted {
            core.close();
            ready.send_replace(Some(Err(Error::Abandoned)));
            return Err(Error::Abandoned);
        }
        ready.send_replace(Some(Ok(core)));
        drop(ready);
        let receiver = receiver.as_ref().ok_or(Error::Open)?;
        let output = output.as_mut().ok_or(Error::Open)?;
        loop {
            let message = if let Some(deadline) = output.idle_deadline() {
                match receiver.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
                    Ok(message) => message,
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        output.idle();
                        continue;
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                }
            } else if let Ok(message) = receiver.recv() {
                message
            } else {
                break;
            };
            match message {
                Message::Write(work, _credit) => {
                    let Work {
                        frame,
                        result,
                        hold,
                    } = work;
                    current_hold = Some(hold);
                    let write = match frame.blocking_recv() {
                        Ok(Ok(Frame {
                            bytes,
                            credit,
                            writer_credit,
                        })) => {
                            let written = output.write(&bytes);
                            drop(bytes);
                            drop(credit);
                            drop(writer_credit);
                            written
                        }
                        Ok(Err(error)) => Err(error),
                        Err(_) => Err(Error::Closed),
                    };
                    let _ = result.send(write);
                    if catch_unwind(AssertUnwindSafe(|| drop(current_hold.take()))).is_err() {
                        return Err(Error::Panicked);
                    }
                }
                Message::Flush(result, _credit) => {
                    let _ = result.send(output.flush());
                }
            }
        }
        output.flush()?;
        Ok(())
    }))
    .unwrap_or(Err(Error::Panicked));
    // Publish Closing before teardown, so same-key acquisitions wait. Closing
    // takes the sole std SyncSender under the same mutex used by Core::send;
    // no producer can append after it returns. Then drain jobs, close the FD,
    // return the actor permit, remove the table slot and publish completion.
    // The activity token remains live through the final bookkeeping.
    if let Some(pool) = pool.upgrade() {
        pool.begin_exit(&key, generation);
    }
    if let Some(core) = live_core.and_then(|core| core.upgrade()) {
        core.close();
    }
    if catch_unwind(AssertUnwindSafe(|| drop(current_hold.take()))).is_err() {
        outcome = Err(Error::Panicked);
    }
    if let Some(receiver) = receiver.take() {
        while let Ok(message) = receiver.try_recv() {
            if catch_unwind(AssertUnwindSafe(|| drop(message))).is_err() {
                outcome = Err(Error::Panicked);
            }
        }
        if catch_unwind(AssertUnwindSafe(|| drop(receiver))).is_err() {
            outcome = Err(Error::Panicked);
        }
    }
    if catch_unwind(AssertUnwindSafe(|| drop(output.take()))).is_err() {
        outcome = Err(Error::Panicked);
    }
    drop(permit);
    let exit = match outcome {
        Ok(()) => Exit::Clean,
        Err(error) => Exit::Failed(error),
    };
    if let Some(pool) = pool.upgrade() {
        pool.finish(&key, generation, exit);
    }
    done.send_replace(Some(exit));
    drop(token);
}
impl Drop for Pool {
    fn drop(&mut self) {
        self.close();
    }
}
