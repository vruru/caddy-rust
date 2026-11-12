//! CPU ownership for the public OpenSSL retry-verification boundary.
use std::{
    io,
    sync::{Arc, Mutex, OnceLock},
};
use tokio::sync::Semaphore;
use tokio_util::{
    sync::CancellationToken,
    task::{TaskTracker, task_tracker::TaskTrackerToken},
};
struct Budget {
    running: Arc<Semaphore>,
    waiting: Arc<Semaphore>,
}
fn budget() -> &'static Budget {
    static B: OnceLock<Budget> = OnceLock::new();
    B.get_or_init(|| {
        let cpu = std::thread::available_parallelism().map_or(1, |n| n.get());
        Budget {
            running: Arc::new(Semaphore::new(cpu.clamp(1, 32))),
            waiting: Arc::new(Semaphore::new(cpu.saturating_mul(8).clamp(32, 256))),
        }
    })
}
/// A runtime/service lifetime. CPU/queue capacity is process-shared, not created
/// per config, connection, authority or scope. Close prevents new admission;
/// wait includes real workers and abandoned completed outputs.
pub struct VerificationScope {
    tasks: TaskTracker,
    closed: Mutex<bool>,
    stop: CancellationToken,
}
impl VerificationScope {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            tasks: TaskTracker::new(),
            closed: Mutex::new(false),
            stop: CancellationToken::new(),
        })
    }
    pub fn close(&self) {
        {
            let mut c = self.closed.lock().unwrap_or_else(|e| e.into_inner());
            *c = true;
        }
        // Both operations may synchronously wake external tasks. Admission is
        // already fenced; never invoke a possibly reentrant Waker under it.
        self.stop.cancel();
        self.tasks.close();
    }
    pub async fn wait(&self) {
        self.tasks.wait().await;
    }
    pub(crate) fn enter(&self) -> io::Result<TaskTrackerToken> {
        let c = self.closed.lock().unwrap_or_else(|e| e.into_inner());
        if *c {
            return Err(io::Error::other("TLS verification scope closed"));
        }
        Ok(self.tasks.token())
    }
    pub(crate) async fn run<T: Send + 'static>(
        &self,
        f: impl FnOnce() -> T + Send + 'static,
    ) -> io::Result<T> {
        // Held from before waiting until the actual result is consumed/dropped.
        // The caller also owns an entry token across the complete handshake,
        // so close+wait cannot miss late worker registration.
        let entry = self.enter()?;
        let b = budget();
        let queue = b.waiting.clone().try_acquire_owned().map_err(|_| {
            io::Error::new(io::ErrorKind::WouldBlock, "TLS verification queue full")
        })?;
        let permit = tokio::select! {biased;_=self.stop.cancelled()=>return Err(io::Error::other("TLS verification scope closed")),p=b.running.clone().acquire_owned()=>p.map_err(io::Error::other)?};
        drop(queue);
        let worker = {
            let c = self.closed.lock().unwrap_or_else(|e| e.into_inner());
            if *c {
                return Err(io::Error::other("TLS verification scope closed"));
            }
            // Move the *whole* envelope, not individual closure fields. Panic,
            // unconsumed JoinHandle output and future drop keep real ownership.
            tokio::task::spawn_blocking(move || {
                let token = entry;
                let permit = permit;
                let value = f();
                Output {
                    value,
                    _permit: permit,
                    _token: token,
                }
            })
        };
        let output = worker.await.map_err(io::Error::other)?;
        Ok(output.value)
    }
}
struct Output<T> {
    value: T,
    _permit: tokio::sync::OwnedSemaphorePermit,
    _token: TaskTrackerToken,
}
