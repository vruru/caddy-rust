use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::Duration;
use tokio_util::task::TaskTracker;

/// ResourceLimits represents admission control quotas for concurrent operations.
/// These are NOT fixed CPU worker threads; they are upper bounds on in-flight resources.
/// CPU worker threads are detected from the process's available CPUs at startup.
/// `for_parallelism` is pure; `automatic` additionally reserves descriptor headroom.
/// `None` disables an independent deadline; `Some(Duration::ZERO)` is rejected.
/// Counts remain bounded even when no independent deadline is configured.
/// `HttpRuntime::with_resource_limits` validates custom limits before use.
#[derive(Clone, Debug)]
pub struct ResourceLimits {
    pub auth_running: usize,
    pub auth_waiting: usize,
    pub metadata_running: usize,
    pub metadata_waiting: usize,
    pub file_streams: usize,
    pub file_stream_waiting: usize,
    pub file_read_running: usize,
    pub file_read_waiting: usize,
    pub auth_followers: usize,
    pub auth_queue_timeout: Option<Duration>,
    pub io_queue_timeout: Option<Duration>,
    pub file_read_timeout: Option<Duration>,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self::automatic()
    }
}

impl ResourceLimits {
    pub fn automatic() -> Self {
        let cpu = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        let mut limits = Self::for_parallelism(cpu);
        if let Some(soft) = descriptor_limit() {
            // Most descriptors belong to network connections and other services.
            limits.file_streams = file_body_limit(cpu, Some(soft));
        }
        limits
    }

    pub fn for_parallelism(cpu: usize) -> Self {
        let c = cpu.clamp(1, Semaphore::MAX_PERMITS);
        let ar = c.saturating_sub(1).clamp(1, 256);
        let meta_run = c.clamp(4, 64);
        let stream = file_body_limit(c, None);
        let reads = c.saturating_mul(4).clamp(8, 128);
        let auth_wait = ar.saturating_mul(8).clamp(32, 512);
        let meta_wait = c.saturating_mul(64).clamp(256, 1024);
        let stream_wait = stream.saturating_mul(16).clamp(128, 1024);
        let followers = c.saturating_mul(32).clamp(64, 4096);

        Self {
            auth_running: ar,
            auth_waiting: auth_wait,
            metadata_running: meta_run,
            metadata_waiting: meta_wait,
            file_streams: stream,
            file_stream_waiting: stream_wait,
            file_read_running: reads,
            file_read_waiting: reads.saturating_mul(16).clamp(128, 1024),
            auth_followers: followers,
            auth_queue_timeout: None,
            io_queue_timeout: Some(Duration::from_secs(2)),
            file_read_timeout: Some(Duration::from_secs(30)),
        }
    }
}

use tokio::sync::Semaphore;

pub(crate) fn file_body_limit(cpu: usize, soft: Option<usize>) -> usize {
    let base = cpu.max(1).saturating_mul(16).clamp(128, 512);
    soft.map_or(base, |n| base.min((n / 8).max(1)))
}

fn descriptor_limit() -> Option<usize> {
    #[cfg(unix)]
    {
        let mut value = std::mem::MaybeUninit::<libc::rlimit>::uninit();
        // getrlimit initializes the supplied structure on success.
        if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, value.as_mut_ptr()) } == 0 {
            let value = unsafe { value.assume_init() };
            if value.rlim_cur != libc::RLIM_INFINITY {
                return Some(usize::try_from(value.rlim_cur).unwrap_or(usize::MAX));
            }
        } else {
            eprintln!("HTTP descriptor limit unavailable; using operation budget fallback");
        }
    }
    None
}

#[derive(Clone)]
pub(crate) struct BlockingBudget {
    running: Arc<Semaphore>,
    waiting: Arc<Semaphore>,
    running_limit: usize,
    waiting_limit: usize,
    wait: Duration,
    tasks: TaskTracker,
    rejected: Arc<AtomicU64>,
}

#[derive(Debug)]
pub(crate) enum BudgetError {
    Overloaded,
    WorkerFailed,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct BudgetSnapshot {
    pub running_limit: usize,
    pub waiting_limit: usize,
    pub running: usize,
    pub waiting: usize,
    pub rejected: u64,
}

impl BlockingBudget {
    pub(crate) fn new(running: usize, waiting: usize, wait: Duration) -> anyhow::Result<Self> {
        anyhow::ensure!(running > 0, "running limit must be > 0");
        anyhow::ensure!(
            running <= Semaphore::MAX_PERMITS,
            "running limit exceeds Semaphore::MAX_PERMITS"
        );
        anyhow::ensure!(
            waiting <= Semaphore::MAX_PERMITS,
            "waiting limit exceeds Semaphore::MAX_PERMITS"
        );
        Ok(Self {
            running: Arc::new(Semaphore::new(running)),
            waiting: Arc::new(Semaphore::new(waiting)),
            running_limit: running,
            waiting_limit: waiting,
            wait,
            tasks: TaskTracker::new(),
            rejected: Arc::new(AtomicU64::new(0)),
        })
    }

    pub(crate) async fn acquire(&self) -> Result<tokio::sync::OwnedSemaphorePermit, BudgetError> {
        if let Ok(permit) = self.running.clone().try_acquire_owned() {
            return Ok(permit);
        }
        let queue_permit = match self.waiting.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                self.rejected.fetch_add(1, Ordering::Relaxed);
                return Err(BudgetError::Overloaded);
            }
        };
        if self.wait.is_zero() {
            let permit = self
                .running
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| BudgetError::WorkerFailed)?;
            drop(queue_permit);
            return Ok(permit);
        }
        match tokio::time::timeout(self.wait, self.running.clone().acquire_owned()).await {
            Ok(Ok(running_permit)) => {
                drop(queue_permit);
                Ok(running_permit)
            }
            Ok(Err(_)) => Err(BudgetError::WorkerFailed),
            Err(_) => {
                self.rejected.fetch_add(1, Ordering::Relaxed);
                Err(BudgetError::Overloaded)
            }
        }
    }

    pub(crate) async fn run<T, F>(&self, f: F) -> Result<T, BudgetError>
    where
        T: Send + 'static,
        F: FnOnce() -> T + Send + 'static,
    {
        let permit = self.acquire().await?;
        run_owned(self.tasks.clone(), permit, f).await
    }

    pub(crate) fn tasks(&self) -> TaskTracker {
        self.tasks.clone()
    }
    pub(crate) fn snapshot(&self) -> BudgetSnapshot {
        BudgetSnapshot {
            running_limit: self.running_limit,
            waiting_limit: self.waiting_limit,
            running: self.running_limit - self.running.available_permits(),
            waiting: self.waiting_limit - self.waiting.available_permits(),
            rejected: self.rejected.load(Ordering::Relaxed),
        }
    }
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct ResourceDiagnostics {
    pub auth: BudgetSnapshot,
    pub auth_comparisons: u64,
    pub auth_cache_rejected: u64,
    pub auth_leaders: usize,
    pub auth_leader_limit: usize,
    pub auth_followers: usize,
    pub auth_follower_limit: usize,
    pub metadata: BudgetSnapshot,
    pub file_streams: BudgetSnapshot,
    pub file_reads: BudgetSnapshot,
}

pub(crate) struct Resources {
    pub auth: BlockingBudget,
    pub auth_leaders: Arc<Semaphore>,
    pub auth_followers: Arc<Semaphore>,
    pub auth_comparisons: Arc<AtomicU64>,
    pub auth_cache_rejected: Arc<AtomicU64>,
    pub auth_tasks: TaskTracker,
    auth_leader_limit: usize,
    auth_follower_limit: usize,
    pub metadata: BlockingBudget,
    pub streams: BlockingBudget,
    pub reads: BlockingBudget,
    pub read_timeout: Duration,
}

impl Resources {
    pub(crate) fn automatic() -> Self {
        Self::from_limits(ResourceLimits::automatic()).expect("valid automatic HTTP limits")
    }
    pub(crate) fn from_limits(limits: ResourceLimits) -> anyhow::Result<Self> {
        // The process runtime sets this shared blocking ceiling explicitly.
        // Reserve headroom for other services; this is not physical isolation.
        for timeout in [
            limits.auth_queue_timeout,
            limits.io_queue_timeout,
            limits.file_read_timeout,
        ] {
            anyhow::ensure!(
                !timeout.is_some_and(|duration| duration.is_zero()),
                "zero resource deadline is ambiguous; use None to disable it"
            );
        }
        anyhow::ensure!(
            limits.file_read_waiting >= limits.file_streams,
            "file read queue must accommodate every admitted body"
        );
        anyhow::ensure!(
            limits
                .auth_running
                .checked_add(limits.metadata_running)
                .and_then(|n| n.checked_add(limits.file_read_running))
                .is_some_and(|n| n <= crate::runtime::BLOCKING_POOL_MAX.saturating_sub(32)),
            "HTTP blocking budgets exceed shared worker headroom"
        );
        anyhow::ensure!(
            limits.auth_followers > 0 && limits.auth_followers <= Semaphore::MAX_PERMITS,
            "authentication follower limit outside bounds"
        );
        let auth = BlockingBudget::new(
            limits.auth_running,
            limits.auth_waiting,
            limits.auth_queue_timeout.unwrap_or(Duration::ZERO),
        )?;
        let metadata = BlockingBudget::new(
            limits.metadata_running,
            limits.metadata_waiting,
            limits.io_queue_timeout.unwrap_or(Duration::ZERO),
        )?;
        let streams = BlockingBudget::new(
            limits.file_streams,
            limits.file_stream_waiting,
            limits.io_queue_timeout.unwrap_or(Duration::ZERO),
        )?;
        let reads = BlockingBudget::new(
            limits.file_read_running,
            limits.file_read_waiting,
            limits.io_queue_timeout.unwrap_or(Duration::ZERO),
        )?;
        let auth_leader_limit = limits
            .auth_running
            .saturating_add(limits.auth_waiting)
            .min(Semaphore::MAX_PERMITS);
        Ok(Self {
            auth,
            metadata,
            streams,
            reads,
            auth_leaders: Arc::new(Semaphore::new(auth_leader_limit)),
            auth_followers: Arc::new(Semaphore::new(limits.auth_followers)),
            auth_comparisons: Arc::new(AtomicU64::new(0)),
            auth_cache_rejected: Arc::new(AtomicU64::new(0)),
            auth_tasks: TaskTracker::new(),
            auth_leader_limit,
            auth_follower_limit: limits.auth_followers,
            read_timeout: limits.file_read_timeout.unwrap_or(Duration::ZERO),
        })
    }
    pub(crate) fn close(&self) {
        self.auth_tasks.close();
        self.auth.tasks.close();
        self.metadata.tasks.close();
        self.streams.tasks.close();
        self.reads.tasks.close();
    }
    pub(crate) async fn wait(&self) {
        // Parents complete before children: a cache leader may still submit a
        // bcrypt worker after graceful stop, and existing file bodies may read.
        self.auth_tasks.wait().await;
        self.auth.tasks.wait().await;
        self.metadata.tasks.wait().await;
        self.streams.tasks.wait().await;
        self.reads.tasks.wait().await;
    }
    pub(crate) fn snapshot(&self) -> ResourceDiagnostics {
        ResourceDiagnostics {
            auth: self.auth.snapshot(),
            auth_comparisons: self.auth_comparisons.load(Ordering::Relaxed),
            auth_cache_rejected: self.auth_cache_rejected.load(Ordering::Relaxed),
            auth_leaders: self.auth_leader_limit - self.auth_leaders.available_permits(),
            auth_leader_limit: self.auth_leader_limit,
            auth_followers: self.auth_follower_limit - self.auth_followers.available_permits(),
            auth_follower_limit: self.auth_follower_limit,
            metadata: self.metadata.snapshot(),
            file_streams: self.streams.snapshot(),
            file_reads: self.reads.snapshot(),
        }
    }
}

/// Both per-operation permits and shared stream permits belong to the actual
/// blocking job, including when its asynchronous caller stops waiting.
pub(crate) async fn run_owned<G, T, F>(
    tasks: TaskTracker,
    guard: G,
    operation: F,
) -> Result<T, BudgetError>
where
    G: Send + 'static,
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    tasks
        .spawn_blocking(move || {
            let _guard = guard;
            operation()
        })
        .await
        .map_err(|_| BudgetError::WorkerFailed)
}

/// A body retains descriptor admission, independently from read-worker admission.
/// Each read releases its worker slot before network writes. Detached syscalls
/// retain both their descriptor reference and real worker slot until completion.
pub(crate) async fn read_chunk(
    file: Arc<std::fs::File>,
    admission: Arc<tokio::sync::OwnedSemaphorePermit>,
    budget: BlockingBudget,
    offset: u64,
    length: usize,
    timeout: Duration,
) -> std::io::Result<Vec<u8>> {
    let job = async move {
        let read_permit = budget.acquire().await.map_err(|error| match error {
            BudgetError::Overloaded => {
                std::io::Error::new(std::io::ErrorKind::WouldBlock, "file read budget busy")
            }
            BudgetError::WorkerFailed => std::io::Error::other("file read worker unavailable"),
        })?;
        run_owned(budget.tasks(), (admission, read_permit), move || {
            let mut bytes = vec![0; length];
            #[cfg(unix)]
            let read = {
                use std::os::unix::fs::FileExt;
                retry_interrupted(|| file.read_at(&mut bytes, offset))?
            };
            #[cfg(windows)]
            let read = {
                use std::os::windows::fs::FileExt;
                retry_interrupted(|| file.seek_read(&mut bytes, offset))?
            };
            #[cfg(not(any(unix, windows)))]
            let read = {
                let _ = (file, offset);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "positional file reads unavailable",
                ));
            };
            bytes.truncate(read);
            Ok::<_, std::io::Error>(bytes)
        })
        .await
        .map_err(|_| std::io::Error::other("file read worker failed"))?
    };
    if timeout.is_zero() {
        return job.await;
    }
    tokio::time::timeout(timeout, job).await.map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::TimedOut, "file read deadline elapsed")
    })?
}

pub(crate) fn retry_interrupted<T>(
    mut operation: impl FnMut() -> std::io::Result<T>,
) -> std::io::Result<T> {
    loop {
        match operation() {
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            result => return result,
        }
    }
}
