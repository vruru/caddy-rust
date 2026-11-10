//! Process runtime construction after synchronous startup and inherited-FD capture.
//! Derive workers from this process's available CPUs on every startup; do not
//! inherit a test worker count or a machine-specific thread environment override.

/// Explicit blocking-pool ceiling. Individual components must bound their own
/// running work and queues below this ceiling; it is not a CPU affinity limit.
pub const BLOCKING_POOL_MAX: usize = 512;

/// Build the application runtime using every CPU available to this process.
/// OS affinity and cgroup quotas are respected by `available_parallelism`.
/// The read-only inspector does not need or create this runtime.
pub fn build() -> std::io::Result<tokio::runtime::Runtime> {
    let workers = std::thread::available_parallelism()?.get();
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .max_blocking_threads(BLOCKING_POOL_MAX)
        .enable_all()
        .build()
}
