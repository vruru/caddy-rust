//! Shared owned blocking dispatch; callers supply their existing work budget.
use std::sync::Arc;
use anyhow::{Result,anyhow,bail,ensure};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

/// Admission remains held by the actual blocking job, including when its
/// caller is cancelled. Await completion before reporting cancellation.
pub(crate) async fn run<T: Send + 'static>(
    slots: Arc<Semaphore>, cancel: CancellationToken,
    operation: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    let permit = tokio::select! { biased;
        _ = cancel.cancelled() => bail!("certificate operation cancelled"),
        permit = slots.acquire_owned() => permit.map_err(|_| anyhow!("certificate operations stopped"))?,
    };
    let worker_cancel = cancel.clone();
    let mut worker = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        ensure!(!worker_cancel.is_cancelled(), "certificate operation cancelled");
        operation()
    });
    tokio::select! { biased;
        _ = cancel.cancelled() => { let _ = worker.await; Err(anyhow!("certificate operation cancelled")) }
        result = &mut worker => result.map_err(|_| anyhow!("certificate worker failed"))?,
    }
}
