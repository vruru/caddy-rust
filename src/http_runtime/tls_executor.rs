//! Dedicated, bounded handshake scheduling. Signing must not run on HTTP workers.
use anyhow::{Result, anyhow};
use std::{
    future::Future,
    io,
    sync::{Arc, Mutex, mpsc},
    thread,
};
use tokio::{
    runtime::Handle,
    sync::{Semaphore, oneshot, watch},
    time::Instant,
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

pub struct TlsExecutor {
    handle: Handle,
    shared: Arc<Shared>,
    supervisor: Mutex<Option<thread::JoinHandle<()>>>,
    joined: watch::Sender<Option<bool>>,
}
/// Independent snapshots of handshake concurrency, not CPU execution quotas.
#[derive(Clone, Debug, serde::Serialize)]
pub struct TlsHandshakeDiagnostics {
    pub business_running: usize,
    pub business_running_limit: usize,
    pub business_waiting: usize,
    pub business_waiting_limit: usize,
    pub proof_running: usize,
    pub proof_running_limit: usize,
    pub proof_waiting: usize,
    pub proof_waiting_limit: usize,
    pub proof_normal_running: usize,
    pub proof_normal_running_limit: usize,
    pub proof_reserved_running: usize,
    pub proof_reserved_running_limit: usize,
    pub proof_replacements: usize,
    pub proof_replacement_limit: usize,
}
struct Shared {
    stop: CancellationToken,
    tasks: TaskTracker,
    admission_closed: Mutex<bool>,
    running: Arc<Semaphore>,
    waiting: Arc<Semaphore>,
    proof_running: Arc<Semaphore>,
    proof_waiting: Arc<Semaphore>,
    proof_pressure: Arc<Semaphore>,
    proof_reserved: Arc<Semaphore>,
    proof_reserved_live: Arc<super::pressure::Registry>,
    capacities: [usize; 7],
}
struct ProofVictim {
    cancel: CancellationToken,
    active: std::sync::atomic::AtomicBool,
    completed: Arc<super::pressure::Completion>,
}
impl super::pressure::Victim for ProofVictim {
    fn completion(&self) -> Option<Arc<super::pressure::Completion>> {
        Some(self.completed.clone())
    }
    fn try_cancel(&self) -> bool {
        if self.active.swap(false, std::sync::atomic::Ordering::AcqRel) {
            self.cancel.cancel();
            true
        } else {
            false
        }
    }
}
struct ProofRunning {
    victim: Arc<ProofVictim>,
    _registration: super::pressure::Registration,
}
impl ProofRunning {
    fn register(
        registry: &Arc<super::pressure::Registry>,
        cancel: CancellationToken,
    ) -> Result<Self> {
        let victim = Arc::new(ProofVictim {
            cancel,
            active: std::sync::atomic::AtomicBool::new(true),
            completed: super::pressure::Completion::new(),
        });
        let erased: Arc<dyn super::pressure::Victim> = victim.clone();
        Ok(Self {
            victim,
            _registration: registry.register(&erased)?,
        })
    }
}
impl Drop for ProofRunning {
    fn drop(&mut self) {
        self.victim
            .active
            .store(false, std::sync::atomic::Ordering::Release);
        // HandshakeJob declares future, permit, then this guard, preserving the
        // same completion order even if dropping the future unwinds.
        self.victim.completed.finish();
    }
}
struct HandshakeJob<F> {
    future: Option<std::pin::Pin<Box<F>>>,
    permit: Option<tokio::sync::OwnedSemaphorePermit>,
    proof: Option<ProofRunning>,
}
impl<F> Drop for HandshakeJob<F> {
    fn drop(&mut self) {
        if let Some(proof) = &self.proof {
            proof
                .victim
                .active
                .store(false, std::sync::atomic::Ordering::Release);
        }
        // The same order also runs on panic/caller cancellation. A completion
        // receipt never races ahead of the real future's IO or its lane permit.
        drop(self.future.take());
        drop(self.permit.take());
        drop(self.proof.take());
    }
}
async fn wait_deadline(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending::<()>().await,
    }
}
struct CancelOnDrop(CancellationToken);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}
impl Shared {
    fn close(&self) {
        let mut closed = self
            .admission_closed
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        *closed = true;
        self.tasks.close();
        self.stop.cancel();
    }
}
impl TlsExecutor {
    pub fn diagnostics(&self) -> TlsHandshakeDiagnostics {
        let c = self.shared.capacities;
        TlsHandshakeDiagnostics {
            business_running: c[0] - self.shared.running.available_permits(),
            business_running_limit: c[0],
            business_waiting: c[1] - self.shared.waiting.available_permits(),
            business_waiting_limit: c[1],
            proof_running: c[5] - self.shared.proof_running.available_permits() + c[6]
                - self.shared.proof_reserved.available_permits(),
            proof_running_limit: c[2],
            proof_normal_running: c[5] - self.shared.proof_running.available_permits(),
            proof_normal_running_limit: c[5],
            proof_reserved_running: c[6] - self.shared.proof_reserved.available_permits(),
            proof_reserved_running_limit: c[6],
            proof_waiting: c[3] - self.shared.proof_waiting.available_permits(),
            proof_waiting_limit: c[3],
            proof_replacements: c[4] - self.shared.proof_pressure.available_permits(),
            proof_replacement_limit: c[4],
        }
    }
    pub fn new() -> io::Result<Self> {
        let cpus = thread::available_parallelism()?.get();
        let proof_total = cpus.saturating_mul(4).clamp(1, 256);
        let proof_reserved = (proof_total / 4).max(1);
        let proof_normal = proof_total - proof_reserved;
        let shared = Arc::new(Shared {
            stop: CancellationToken::new(),
            tasks: TaskTracker::new(),
            admission_closed: Mutex::new(false),
            running: Arc::new(Semaphore::new(cpus.saturating_mul(32).clamp(1, 4096))),
            waiting: Arc::new(Semaphore::new(cpus.saturating_mul(64).clamp(128, 4096))),
            proof_running: Arc::new(Semaphore::new(proof_normal)),
            proof_waiting: Arc::new(Semaphore::new(cpus.saturating_mul(8).clamp(1, 512))),
            proof_pressure: Arc::new(Semaphore::new(cpus.saturating_mul(2).clamp(1, 128))),
            proof_reserved: Arc::new(Semaphore::new(proof_reserved)),
            proof_reserved_live: super::pressure::Registry::new(),
            capacities: [
                cpus.saturating_mul(32).clamp(1, 4096),
                cpus.saturating_mul(64).clamp(128, 4096),
                cpus.saturating_mul(4).clamp(1, 256),
                cpus.saturating_mul(8).clamp(1, 512),
                cpus.saturating_mul(2).clamp(1, 128),
                proof_normal,
                proof_reserved,
            ],
        });
        let (send, receive) = mpsc::sync_channel(1);
        let worker = shared.clone();
        let supervisor = thread::Builder::new()
            .name("caddy-tls-control".into())
            .spawn(move || {
                let runtime = match crate::runtime::build() {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        let _ = send.send(Err(error));
                        return;
                    }
                };
                if send.send(Ok(runtime.handle().clone())).is_err() {
                    return;
                }
                runtime.block_on(async {
                    worker.stop.cancelled().await;
                    worker.close();
                    worker.tasks.wait().await;
                });
                // Only tracked handshake futures run here. They must not spawn
                // untracked blocking jobs or retain runtime handles after return.
                drop(runtime);
            })?;
        let handle = match receive.recv() {
            Ok(Ok(handle)) => handle,
            Ok(Err(error)) => {
                let _ = supervisor.join();
                return Err(error);
            }
            Err(_) => {
                shared.close();
                let _ = supervisor.join();
                return Err(io::Error::other("TLS executor startup failed"));
            }
        };
        Ok(Self {
            handle,
            shared,
            supervisor: Mutex::new(Some(supervisor)),
            joined: watch::channel(None).0,
        })
    }
    /// Cancellation drops the real worker future before returning its running
    /// permit. Dropping the caller future signals that same owned worker.
    pub async fn execute<T: Send + 'static>(
        &self,
        future: impl Future<Output = Result<T>> + Send + 'static,
        caller_cancel: CancellationToken,
        deadline: Option<Instant>,
    ) -> Result<T> {
        self.execute_lane(future, caller_cancel, deadline, false)
            .await
    }
    /// CA validation has its own admission budget: ordinary clients waiting for
    /// Finished cannot consume every slot needed to obtain their certificate.
    pub async fn execute_proof<T: Send + 'static>(
        &self,
        future: impl Future<Output = Result<T>> + Send + 'static,
        caller_cancel: CancellationToken,
        deadline: Option<Instant>,
    ) -> Result<T> {
        self.execute_lane(future, caller_cancel, deadline, true)
            .await
    }
    async fn execute_lane<T: Send + 'static>(
        &self,
        future: impl Future<Output = Result<T>> + Send + 'static,
        caller_cancel: CancellationToken,
        deadline: Option<Instant>,
        proof: bool,
    ) -> Result<T> {
        let (running, waiting) = if proof {
            (&self.shared.proof_running, &self.shared.proof_waiting)
        } else {
            (&self.shared.running, &self.shared.waiting)
        };
        if self.shared.stop.is_cancelled() {
            return Err(anyhow!("TLS executor stopped"));
        }
        let cancel = caller_cancel.child_token();
        let _cancel_on_drop = CancelOnDrop(cancel.clone());
        self.check_live(&cancel, deadline)?;
        let (waiting, reserved) = match waiting.clone().try_acquire_owned() {
            Ok(ticket) => (ticket, false),
            Err(_) if proof => {
                let ticket = self
                    .shared
                    .proof_pressure
                    .clone()
                    .try_acquire_owned()
                    .map_err(|_| anyhow!("TLS proof replacement queue full"))?;
                (ticket, true)
            }
            Err(_) => return Err(anyhow!("TLS handshake queue full")),
        };
        let running = if reserved {
            &self.shared.proof_reserved
        } else {
            running
        };
        let permit = if reserved {
            match running.clone().try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => {
                    self.check_live(&cancel, deadline)?;
                    // Only this one bounded semaphore operation bypasses
                    // cooperative yielding; the handshake future does not.
                    let mut acquisition =
                        Box::pin(tokio::task::unconstrained(running.clone().acquire_owned()));
                    // Queue the bounded replacement before cancelling a victim.
                    // Tokio assigns returned permits to already registered FIFO
                    // waiters, so a later try_acquire cannot steal that slot in
                    // the gap between real Drop and completion notification.
                    let queued = std::future::poll_fn(|cx| {
                        std::task::Poll::Ready(acquisition.as_mut().poll(cx))
                    })
                    .await;
                    if let std::task::Poll::Ready(permit) = queued {
                        // The lane freed naturally before we entered its queue.
                        // No existing proof needs to be cancelled in this case.
                        permit.map_err(|_| anyhow!("TLS executor stopped"))?
                    } else {
                        self.check_live(&cancel, deadline)?;
                        let completed = self
                            .shared
                            .proof_reserved_live
                            .evict_oldest_with_completion()
                            .ok_or_else(|| {
                                anyhow!("TLS proof reserve full; no reclaimable worker")
                            })?;
                        // Unlike normal proof FIFO waiters, this reserve only has
                        // bounded fresh validation waiters. A stale normal queue
                        // cannot steal the victim's returned reserve slot.
                        tokio::select! {biased;
                            _=self.shared.stop.cancelled()=>return Err(anyhow!("TLS executor stopped")),
                            _=cancel.cancelled()=>return Err(anyhow!("TLS handshake cancelled")),
                            _=wait_deadline(deadline)=>return Err(anyhow!("TLS handshake deadline elapsed")),
                            result=completed.wait()=>result?,
                        }
                        tokio::select! {biased;
                            _=self.shared.stop.cancelled()=>return Err(anyhow!("TLS executor stopped")),
                            _=cancel.cancelled()=>return Err(anyhow!("TLS handshake cancelled")),
                            _=wait_deadline(deadline)=>return Err(anyhow!("TLS handshake deadline elapsed")),
                            result=&mut acquisition=>result.map_err(|_|anyhow!("TLS executor stopped"))?,
                        }
                    }
                }
            }
        } else {
            tokio::select! { biased;
                _ = self.shared.stop.cancelled() => return Err(anyhow!("TLS executor stopped")),
                _ = cancel.cancelled() => return Err(anyhow!("TLS handshake cancelled")),
                _ = wait_deadline(deadline) => return Err(anyhow!("TLS handshake deadline elapsed")),
                permit = running.clone().acquire_owned() => permit.map_err(|_| anyhow!("TLS executor stopped"))?,
            }
        };
        drop(waiting);
        let (send, receive) = oneshot::channel();
        {
            let closed = self
                .shared
                .admission_closed
                .lock()
                .map_err(|_| anyhow!("TLS executor admission failed"))?;
            if *closed {
                return Err(anyhow!("TLS executor stopped"));
            }
            let shared = self.shared.clone();
            let worker_cancel = cancel.clone();
            self.shared.tasks.spawn_on(async move {
                let mut job=HandshakeJob{future:Some(Box::pin(future)),permit:Some(permit),proof:None};
                let registered=if reserved {ProofRunning::register(&shared.proof_reserved_live,worker_cancel.clone()).map(Some)}else{Ok(None)};
                let result=match registered {
                    Ok(proof)=>{job.proof=proof;tokio::select! { biased;
                        _ = shared.stop.cancelled() => Err(anyhow!("TLS executor stopped")),
                        _ = worker_cancel.cancelled() => Err(anyhow!("TLS handshake cancelled")),
                        _ = wait_deadline(deadline) => Err(anyhow!("TLS handshake deadline elapsed")),
                        result = job.future.as_mut().expect("live handshake job") => result,
                    }},
                    Err(_)=>Err(anyhow!("TLS proof cancellation registry unavailable")),
                };
                drop(job);
                let _ = send.send(result);
            }, &self.handle);
        }
        tokio::select! { biased;
            _ = self.shared.stop.cancelled() => Err(anyhow!("TLS executor stopped")),
            _ = cancel.cancelled() => Err(anyhow!("TLS handshake cancelled")),
            _ = wait_deadline(deadline) => Err(anyhow!("TLS handshake deadline elapsed")),
            result = receive => result.map_err(|_| anyhow!("TLS handshake worker failed"))?,
        }
    }
    fn check_live(&self, cancel: &CancellationToken, deadline: Option<Instant>) -> Result<()> {
        anyhow::ensure!(!self.shared.stop.is_cancelled(), "TLS executor stopped");
        anyhow::ensure!(!cancel.is_cancelled(), "TLS handshake cancelled");
        anyhow::ensure!(
            deadline.is_none_or(|deadline| deadline > Instant::now()),
            "TLS handshake deadline elapsed"
        );
        Ok(())
    }
    /// Synchronous admission/force fence; actual workers retain their permits
    /// until they finish. Explicit shutdown, unlike Drop, also joins the thread.
    pub fn close(&self) {
        self.shared.close();
    }
    pub async fn shutdown(&self) -> Result<()> {
        self.close();
        let supervisor = self
            .supervisor
            .lock()
            .map_err(|_| anyhow!("TLS supervisor state failed"))?
            .take();
        if let Some(supervisor) = supervisor {
            let joined = self.joined.clone();
            // Completion is published by the blocking job, even if this
            // shutdown caller is cancelled before its next poll.
            tokio::task::spawn_blocking(move || {
                joined.send_replace(Some(supervisor.join().is_ok()));
            });
        }
        let mut receiver = self.joined.subscribe();
        loop {
            if let Some(joined) = *receiver.borrow_and_update() {
                return if joined {
                    Ok(())
                } else {
                    Err(anyhow!("TLS supervisor failed"))
                };
            }
            receiver
                .changed()
                .await
                .map_err(|_| anyhow!("TLS supervisor completion unavailable"))?;
        }
    }
}
impl Drop for TlsExecutor {
    fn drop(&mut self) {
        self.close();
    }
}
