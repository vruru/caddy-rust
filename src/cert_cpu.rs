//! Shared owned blocking dispatch; callers supply their existing work budget.
use anyhow::{Result, anyhow, bail, ensure};
use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

/// Closed native material producers prepay through their actual operation
/// owner. This is not an allocator/admission hook for an opaque host object.
pub(crate) trait MaterialOwner:Send+Sync {
    fn reserve(&self,bytes:usize)->Result<()>;
}

/// Field order is intentional: the allocation retires before its last credit.
/// No method extracts an unaccompanied raw Vec from a retained result.
pub(crate) struct RetainedBytes {
    bytes:Vec<u8>,
    owner:Arc<dyn MaterialOwner>,
}
impl RetainedBytes {
    pub(crate) fn copy(bytes:&[u8],owner:Arc<dyn MaterialOwner>)->Result<Self> {
        owner.reserve(bytes.len())?;
        let mut copied=Vec::new();copied.try_reserve_exact(bytes.len()).map_err(|_|anyhow!("retained material capacity exceeded"))?;
        copied.extend_from_slice(bytes);Ok(Self{bytes:copied,owner})
    }
    pub(crate) fn as_bytes(&self)->&[u8] {&self.bytes}
    pub(crate) fn owner(&self)->Arc<dyn MaterialOwner> {self.owner.clone()}
    pub(crate) fn into_error(self,error:anyhow::Error)->anyhow::Error {
        let Self{bytes,owner}=self;drop(bytes);retained_error(error,owner)
    }
}

struct RetainedJob<F> {operation:F,owner:Arc<dyn MaterialOwner>}
struct RetainedError {error:anyhow::Error,owner:Arc<dyn MaterialOwner>}
impl std::fmt::Debug for RetainedError {
    fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result {f.debug_tuple("RetainedMaterialError").field(&self.error).finish()}
}
impl std::fmt::Display for RetainedError {
    fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result {self.error.fmt(f)}
}
impl std::error::Error for RetainedError {
    fn source(&self)->Option<&(dyn std::error::Error+'static)> {Some(self.error.as_ref())}
}
pub(crate) fn retained_error(error:anyhow::Error,owner:Arc<dyn MaterialOwner>)->anyhow::Error {
    anyhow::Error::new(RetainedError{error,owner})
}
impl<F:FnOnce()->Result<Vec<u8>>> RetainedJob<F> {
    // Calling a consuming method forces capture of the WHOLE job. Destructuring
    // in the outer closure could permit Rust's disjoint field captures instead.
    fn execute(self)->Result<RetainedBytes> {
        let Self{operation,owner}=self;
        match operation() {
            Ok(bytes)=>Ok(RetainedBytes{bytes,owner}),
            Err(error)=>Err(retained_error(error,owner)),
        }
    }
}

/// This is deliberately a non-async constructor: even a future dropped before
/// its first poll contains one job whose input captures retire BEFORE its owner.
/// A spawned worker and its actual output retain the same credit independently
/// of the waiting caller. The producer must reserve all output/scratch BEFORE
/// creating it; wrapping a completed Vec is not a preallocation gate.
pub(crate) fn run_retained(
    slots:Arc<Semaphore>,cancel:CancellationToken,owner:Arc<dyn MaterialOwner>,
    operation:impl FnOnce()->Result<Vec<u8>>+Send+'static,
) -> impl std::future::Future<Output=Result<RetainedBytes>>+Send {
    let job=RetainedJob{operation,owner};
    async move {
        let guard=job.owner.clone();
        match run(slots,cancel,move||job.execute()).await {
            Ok(bytes)=>Ok(bytes),
            Err(error)=>Err(retained_error(error,guard)),
        }
    }
}

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

pub(crate) mod sign;
