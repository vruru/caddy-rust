//! Bounded encoding work on dedicated workers, separate from the network
//! reactor, file writers and symbol resolver. The process CPU allowance is
//! measured at construction, never copied from QA affinity or hard-coded.
use anyhow::{Result, anyhow, ensure};
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{Arc, Mutex, mpsc},
    thread,
};
use tokio::sync::{oneshot, watch};
type Job = Box<dyn FnOnce() + Send + 'static>;
#[derive(Clone, Copy)]
enum JoinState {
    Joined(bool),
    HandoffFailed,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Rejected {
    Full,
    Closed,
}
pub(super) struct Cpu {
    sender: Mutex<Option<mpsc::SyncSender<Job>>>,
    workers: Mutex<Option<Vec<thread::JoinHandle<()>>>>,
    joined: watch::Sender<Option<JoinState>>,
    joiner: Mutex<Option<mpsc::Sender<Vec<thread::JoinHandle<()>>>>>,
    ids: Vec<thread::ThreadId>,
    count: usize,
}
impl Cpu {
    pub(super) fn new(queue: usize) -> Result<Arc<Self>> {
        Self::new_named(queue, "caddy-log-encode")
    }
    /// Separate pools share lifecycle mechanics, not workers or queues.
    pub(super) fn new_named(queue: usize, name: &'static str) -> Result<Arc<Self>> {
        Self::new_capped(queue, name, usize::MAX)
    }
    pub(super) fn new_capped(queue: usize, name: &'static str, cap: usize) -> Result<Arc<Self>> {
        ensure!(
            queue > 0 && cap > 0,
            "invalid log encoding queue or worker limit"
        );
        let count = thread::available_parallelism()?.get().min(cap);
        let (sender, receiver) = mpsc::sync_channel::<Job>(queue);
        let receiver = Arc::new(Mutex::new(receiver));
        let mut workers = Vec::with_capacity(count);
        for index in 0..count {
            let receiver = receiver.clone();
            match thread::Builder::new()
                .name(format!("{name}-{index}"))
                .spawn(move || {
                    loop {
                        let next = receiver.lock().unwrap_or_else(|e| e.into_inner()).recv();
                        let Ok(job) = next else {
                            break;
                        };
                        // The receiver mutex is gone before executing work. Encoding
                        // panic is isolated by the submitted closure below.
                        job();
                    }
                }) {
                Ok(worker) => workers.push(worker),
                Err(error) => {
                    drop(sender);
                    for worker in workers {
                        let _ = worker.join();
                    }
                    return Err(error.into());
                }
            }
        }
        let ids = workers.iter().map(|worker| worker.thread().id()).collect();
        let joined = watch::channel(None).0;
        let signal = joined.clone();
        let (join_send, join_recv) = mpsc::channel::<Vec<thread::JoinHandle<()>>>();
        // Reserve the joiner during preparation. Shutdown then requires no
        // reactor/spawn_blocking service and never loses handles on spawn error.
        match thread::Builder::new()
            .name(format!("{name}-join"))
            .spawn(move || {
                if let Ok(workers) = join_recv.recv() {
                    let mut ok = true;
                    for worker in workers {
                        ok &= worker.join().is_ok();
                    }
                    signal.send_replace(Some(JoinState::Joined(ok)));
                }
            }) {
            Ok(joiner) => drop(joiner),
            Err(error) => {
                drop(sender);
                for worker in workers {
                    let _ = worker.join();
                }
                return Err(error.into());
            }
        }
        Ok(Arc::new(Self {
            sender: Mutex::new(Some(sender)),
            workers: Mutex::new(Some(workers)),
            joined,
            joiner: Mutex::new(Some(join_send)),
            ids,
            count,
        }))
    }
    pub(super) fn workers(&self) -> usize {
        self.count
    }
    /// A dropped receiver does not abort the real closure or release anything
    /// captured by it. The accepted job owns all its credits until it returns.
    pub(super) fn try_submit<T: Send + 'static>(
        &self,
        operation: impl FnOnce() -> Result<T> + Send + 'static,
    ) -> std::result::Result<oneshot::Receiver<Result<T>>, Rejected> {
        let (send, receive) = oneshot::channel();
        let job: Job = Box::new(move || {
            let result = catch_unwind(AssertUnwindSafe(operation))
                .unwrap_or_else(|_| Err(anyhow!("log encoding worker panicked")));
            let _ = send.send(result);
        });
        let sender = self.sender.lock().unwrap_or_else(|e| e.into_inner());
        let result = if let Some(sender) = sender.as_ref() {
            Some(sender.try_send(job))
        } else {
            None
        };
        // A rejected job may drop a plan scope and take the registry lock.
        // Never destroy its captured resources while holding this mutex.
        drop(sender);
        match result {
            Some(Ok(())) => Ok(receive),
            Some(Err(mpsc::TrySendError::Full(_))) => Err(Rejected::Full),
            Some(Err(mpsc::TrySendError::Disconnected(_))) | None => Err(Rejected::Closed),
        }
    }

    pub(super) fn close(&self) {
        let sender = self.sender.lock().unwrap_or_else(|e| e.into_inner()).take();
        drop(sender);
    }
    /// Stopping admission drains accepted work. Joining is task-owned, so a
    /// cancelled first shutdown waiter does not detach the completion signal.
    pub(super) async fn shutdown(&self) -> Result<()> {
        ensure!(
            !self.ids.contains(&thread::current().id()),
            "log encoding worker cannot await its own shutdown"
        );
        self.close();
        self.begin_join();
        let mut receiver = self.joined.subscribe();
        loop {
            if let Some(state) = *receiver.borrow_and_update() {
                return match state {
                    JoinState::Joined(true) => Ok(()),
                    JoinState::Joined(false) => Err(anyhow!(
                        "log encoding worker stopped unexpectedly; all workers joined"
                    )),
                    JoinState::HandoffFailed => Err(anyhow!(
                        "log encoding join handoff failed; workers not joined"
                    )),
                };
            }
            receiver
                .changed()
                .await
                .map_err(|_| anyhow!("log encoding shutdown unavailable"))?;
        }
    }
    /// An error from shutdown alone does not imply quiescence. In the unlikely
    /// handoff-failure branch actual worker handles remain owned by this Cpu.
    pub(super) fn quiesced(&self) -> bool {
        matches!(*self.joined.borrow(), Some(JoinState::Joined(_)))
    }
    fn begin_join(&self) {
        let workers = self
            .workers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(workers) = workers {
            let joiner = self.joiner.lock().unwrap_or_else(|e| e.into_inner()).take();
            match joiner {
                Some(joiner) => {
                    if let Err(failed) = joiner.send(workers) {
                        // The constructor-created joiner has no fallible work before
                        // recv. Keep actual handles if that invariant ever breaks;
                        // report failure rather than falsely reporting completion.
                        *self.workers.lock().unwrap_or_else(|e| e.into_inner()) = Some(failed.0);
                        self.joined.send_replace(Some(JoinState::HandoffFailed));
                    }
                }
                None => {
                    *self.workers.lock().unwrap_or_else(|e| e.into_inner()) = Some(workers);
                    self.joined.send_replace(Some(JoinState::HandoffFailed));
                }
            }
        }
    }
}
impl Drop for Cpu {
    fn drop(&mut self) {
        self.close();
        self.begin_join();
    }
}
