//! Shared owned blocking dispatch; callers supply their existing work budget.
use anyhow::{Result, anyhow, bail, ensure};
use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

/// Admission remains held by the actual blocking job, including when its
/// caller is cancelled. Await completion before reporting cancellation.
pub(crate) async fn run<T: Send + 'static>(
    slots: Arc<Semaphore>,
    cancel: CancellationToken,
    operation: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    dispatch(slots, cancel, operation, false).await
}

/// Only for a worker with its own final cancellation check immediately before
/// an atomic publication. Preserve that worker's actual commit result when a
/// caller cancels during its mandatory join.
pub(crate) async fn run_committed<T: Send + 'static>(
    slots: Arc<Semaphore>,
    cancel: CancellationToken,
    operation: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    dispatch(slots, cancel, operation, true).await
}

async fn dispatch<T: Send + 'static>(
    slots: Arc<Semaphore>,
    cancel: CancellationToken,
    operation: impl FnOnce() -> Result<T> + Send + 'static,
    keep_result: bool,
) -> Result<T> {
    let permit = tokio::select! { biased;
        _ = cancel.cancelled() => bail!("certificate operation cancelled"),
        permit = slots.acquire_owned() => permit.map_err(|_| anyhow!("certificate operations stopped"))?,
    };
    let worker_cancel = cancel.clone();
    let mut worker = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        ensure!(
            !worker_cancel.is_cancelled(),
            "certificate operation cancelled"
        );
        operation()
    });
    tokio::select! { biased;
        _ = cancel.cancelled() => {
            let result = worker.await;
            if keep_result {
                result.map_err(|_| anyhow!("certificate worker failed"))?
            } else {
                Err(anyhow!("certificate operation cancelled"))
            }
        }
        result = &mut worker => result.map_err(|_| anyhow!("certificate worker failed"))?,
    }
}
