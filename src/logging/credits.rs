//! Independent global admission and encoding budgets, owned by real work.
use super::{
    limits::{self, RuntimeLimits},
    types::Event,
};
use anyhow::{Result, anyhow, ensure};
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionError {
    Closed,
    EventLimit,
    PendingBytes,
    PendingJobs,
    EncodingBytes,
    DestinationFull,
    EncodingQueue,
}
pub(super) struct Credits {
    events: Arc<Semaphore>,
    jobs: Arc<Semaphore>,
    workspace: Arc<Semaphore>,
}
pub(super) struct Record {
    pub event: Event,
    _bytes: OwnedSemaphorePermit,
}
impl Credits {
    pub(super) fn new(limits: &RuntimeLimits) -> Result<Arc<Self>> {
        limits.validate()?;
        ensure!(
            limits.max_encoding_workspace_bytes > 0
                && limits.max_encoding_workspace_bytes <= u32::MAX as usize
                && limits.max_encoding_workspace_bytes <= Semaphore::MAX_PERMITS,
            "invalid logging encoding byte limit"
        );
        Ok(Arc::new(Self {
            events: Arc::new(Semaphore::new(limits.max_pending_event_bytes)),
            jobs: Arc::new(Semaphore::new(limits.max_queued_jobs)),
            workspace: Arc::new(Semaphore::new(limits.max_encoding_workspace_bytes)),
        }))
    }
    pub(super) fn admit(
        &self,
        event: Event,
        cost: limits::EventCost,
    ) -> std::result::Result<Arc<Record>, AdmissionError> {
        let bytes = self
            .events
            .clone()
            .try_acquire_many_owned(cost.bytes)
            .map_err(|e| map(e, AdmissionError::PendingBytes))?;
        Ok(Arc::new(Record {
            event,
            _bytes: bytes,
        }))
    }
    pub(super) fn job(&self) -> std::result::Result<OwnedSemaphorePermit, AdmissionError> {
        self.jobs
            .clone()
            .try_acquire_owned()
            .map_err(|e| map(e, AdmissionError::PendingJobs))
    }
    pub(super) fn encoding(
        &self,
        bytes: usize,
    ) -> std::result::Result<OwnedSemaphorePermit, AdmissionError> {
        let bytes = u32::try_from(bytes).map_err(|_| AdmissionError::EncodingBytes)?;
        self.workspace
            .clone()
            .try_acquire_many_owned(bytes)
            .map_err(|e| map(e, AdmissionError::EncodingBytes))
    }
    pub(super) fn close(&self) {
        self.events.close();
        self.jobs.close();
        self.workspace.close();
    }
    pub(super) fn available(&self) -> (usize, usize, usize) {
        (
            self.events.available_permits(),
            self.jobs.available_permits(),
            self.workspace.available_permits(),
        )
    }
}
fn map(error: TryAcquireError, full: AdmissionError) -> AdmissionError {
    match error {
        TryAcquireError::Closed => AdmissionError::Closed,
        TryAcquireError::NoPermits => full,
    }
}
pub(super) fn encoding_reservation(frame_bytes: usize) -> Result<usize> {
    // Includes final line, intermediate console/Query buffers, owned transformed
    // fields and bounded wrapper workspace. Every encoder checks its own cap too.
    frame_bytes
        .checked_mul(8)
        .ok_or_else(|| anyhow!("logging encoding reservation overflow"))
}
