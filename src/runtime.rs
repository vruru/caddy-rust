//! Process runtime construction after synchronous startup and inherited-FD capture.
//! Derive workers from this process's available CPUs on every startup; do not
//! inherit a test worker count or a machine-specific thread environment override.

/// Build the application runtime using every CPU available to this process.
/// OS affinity and cgroup quotas are respected by `available_parallelism`.
/// The read-only inspector does not need or create this runtime.
pub fn build() -> std::io::Result<tokio::runtime::Runtime> {
    let workers = std::thread::available_parallelism()?.get();
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_all()
        .build()
}
