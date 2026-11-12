// Copyright 2015 Matthew Holt and The Caddy Authors.
// SPDX-License-Identifier: Apache-2.0
use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::Semaphore;
use tokio::time::MissedTickBehavior;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum StartError {
    ZeroInterval,
    TooManyStates,
}

pub(super) struct ActiveState {
    healthy: AtomicBool,
    counters: Mutex<Counters>,
    busy: AtomicBool,
}

#[derive(Debug, Default, Clone, Copy)]
struct Counters {
    passes: u64,
    fails: u64,
}

impl Default for ActiveState {
    fn default() -> Self {
        Self {
            healthy: AtomicBool::new(true),
            counters: Mutex::new(Counters {
                passes: 0,
                fails: 0,
            }),
            busy: AtomicBool::new(false),
        }
    }
}

impl ActiveState {
    pub(super) fn healthy(&self) -> bool {
        self.healthy.load(Ordering::Acquire)
    }

    pub(super) fn observe(&self, success: bool, passes: u32, fails: u32) -> Option<bool> {
        let mut c = self.counters.lock().unwrap_or_else(|e| e.into_inner());
        if success {
            c.passes = c.passes.saturating_add(1);
            if !self.healthy.load(Ordering::Acquire) {
                if c.passes >= passes as u64 {
                    self.healthy.store(true, Ordering::Release);
                    c.passes = 0;
                    c.fails = 0;
                    return Some(true);
                }
            } else {
                return None;
            }
        } else {
            c.fails = c.fails.saturating_add(1);
            if self.healthy.load(Ordering::Acquire) {
                if c.fails >= fails as u64 {
                    self.healthy.store(false, Ordering::Release);
                    c.passes = 0;
                    c.fails = 0;
                    return Some(false);
                }
            } else {
                return None;
            }
        }
        None
    }
}

pub(super) trait Probe: Send + Sync + 'static {
    fn run(&self, index: usize) -> Pin<Box<dyn Future<Output = Option<bool>> + Send + '_>>;
    fn transition_dropped(&self, _index: usize) {}
    fn changed(
        &self,
        _index: usize,
        _healthy: bool,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        Box::pin(async {})
    }
}

type Transition = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;
#[derive(Default)]
struct Transitions {
    queue: VecDeque<Transition>,
    running: bool,
}
#[derive(Default)]
struct TransitionQueue {
    state: Mutex<Transitions>,
}
struct TransitionGuard {
    owner: Arc<TransitionQueue>,
    armed: bool,
}
impl Drop for TransitionGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let mut held = self.owner.state.lock().unwrap_or_else(|e| e.into_inner());
        held.running = false;
        held.queue.clear();
    }
}
impl TransitionQueue {
    fn enqueue(
        self: &Arc<Self>,
        future: Transition,
        tasks: &TaskTracker,
        stop: CancellationToken,
        global: CancellationToken,
    ) -> bool {
        let mut held = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let replaced = held.queue.len() >= 4;
        if replaced {
            held.queue.pop_back();
        }
        held.queue.push_back(future);
        if !held.running {
            held.running = true;
            let owner = self.clone();
            tasks.spawn(async move {
                let mut guard = TransitionGuard { owner: owner.clone(), armed: true };
                loop {
                    let future = { let mut held = owner.state.lock().unwrap_or_else(|e| e.into_inner());
                        match held.queue.pop_front() { Some(future) => future, None => { held.running = false; guard.armed = false; return; } }
                    };
                    tokio::select! { biased; _ = stop.cancelled() => return, _ = global.cancelled() => return, _ = future => {} }
                }
            });
        }
        replaced
    }
}
struct BusyGuard {
    state: Arc<ActiveState>,
}

impl Drop for BusyGuard {
    fn drop(&mut self) {
        self.state.busy.store(false, Ordering::Release);
    }
}

pub(super) struct Schedule {
    pub(super) states: Vec<Arc<ActiveState>>,
    pub(super) interval: Duration,
    pub(super) passes: u32,
    pub(super) fails: u32,
}

/// Deterministic per-configuration admission, independent of machine CPU count.
pub(super) const MAX_SCHEDULERS: usize = 1024;

pub(super) fn start(
    tasks: TaskTracker,
    stop: CancellationToken,
    global_stop: CancellationToken,
    slots: Arc<Semaphore>,
    schedule: Schedule,
    probe: Arc<dyn Probe>,
) -> Result<(), StartError> {
    let Schedule {
        states,
        interval,
        passes,
        fails,
    } = schedule;
    if interval == Duration::ZERO {
        return Err(StartError::ZeroInterval);
    }
    if states.len() > 4096 {
        return Err(StartError::TooManyStates);
    }

    let transitions: Vec<_> = states
        .iter()
        .map(|_| Arc::new(TransitionQueue::default()))
        .collect();
    let mut tick = tokio::time::interval(interval);
    let scheduler_tasks = tasks.clone();
    tick.set_missed_tick_behavior(MissedTickBehavior::Skip);

    scheduler_tasks.spawn(async move {
        let mut count = 0usize;
        loop {
            tokio::select! {
                biased;
                _ = stop.cancelled() => return,
                _ = global_stop.cancelled() => return,
                _ = tick.tick() => {}
            }

            for (idx, state) in states.iter().enumerate() {
                if stop.is_cancelled() || global_stop.is_cancelled() {
                    return;
                }

                if state
                    .busy
                    .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                    .is_err()
                {
                    continue;
                }

                // Own the busy flag even while waiting for a global slot, so
                // cancellation restores it before this state can be reused.
                let busy_guard = BusyGuard {
                    state: state.clone(),
                };
                let permit = tokio::select! { biased;
                    _ = stop.cancelled() => return,
                    _ = global_stop.cancelled() => return,
                    permit = slots.clone().acquire_owned() => match permit {
                        Ok(permit) => permit,
                        Err(_) => return,
                    },
                };

                let probe = probe.clone();
                let state_clone = state.clone();
                let transitions = transitions[idx].clone();
                let event_tasks = tasks.clone();

                let stop = stop.clone();
                let global_stop = global_stop.clone();
                tasks.spawn(async move {
                    let _busy_guard = busy_guard;
                    let _permit = permit;

                    let fut = probe.run(idx);
                    tokio::pin!(fut);

                    let result = tokio::select! {
                        biased;
                        _ = stop.cancelled() => return,
                        _ = global_stop.cancelled() => return,
                        r = &mut fut => r,
                    };

                    if let Some(ok) = result
                        && let Some(new_health) = state_clone.observe(ok, passes, fails)
                    {
                        // Snapshot the transition before releasing per-host observation
                        // ownership. Slow subscribers cannot freeze subsequent probes.
                        let transition = probe.changed(idx, new_health);
                        if transitions.enqueue(
                            transition,
                            &event_tasks,
                            stop.clone(),
                            global_stop.clone(),
                        ) {
                            probe.transition_dropped(idx);
                        }
                        drop(_permit);
                    }
                });

                count += 1;
                if count >= 64 {
                    count = 0;
                    tokio::task::yield_now().await;
                }
            }
        }
    });

    Ok(())
}
