//! Closed concrete payload storage. All large values stay CPU-owned.
use super::{Backing, ControlCredit, Domain, Memory, WorkError};
use crate::metrics::{distributed_trace::processor, transport};
use std::{future::Future, pin::Pin, sync::Arc};
#[derive(Default)]
pub(in crate::metrics) struct TraceResident {
    pub(in crate::metrics) future: Option<Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send>>>,
    pub(in crate::metrics) unary: Option<http::Request<tonic::body::Body>>,
    pub(in crate::metrics) prepared: Option<http::Request<tonic::body::Body>>,
    pub(in crate::metrics) console: Option<crate::metrics::console_writer::Batch>,
    pub(in crate::metrics) items: Vec<processor::Item>,
    pub(in crate::metrics) source_weight: usize,
    pub(in crate::metrics) pending: Option<processor::Item>,
    pub(in crate::metrics) ingress: Option<processor::Item>,
    pub(in crate::metrics) receiver: Option<processor::Receiver>,
    pub(in crate::metrics) result: Option<anyhow::Result<()>>,
    pub(in crate::metrics) encode_error: Option<tonic::Status>,
    pub(in crate::metrics) backing: Option<Arc<Backing>>,
    pub(in crate::metrics) owners: Vec<Arc<processor::Credit>>,
    pub(in crate::metrics) batch_credit: Option<Arc<processor::Credit>>,
    pub(in crate::metrics) future_credit: Option<ControlCredit>,
    pub(in crate::metrics) transport_credit: Option<Arc<transport::Credit>>,
    pub(in crate::metrics) memory: Option<Memory>,
}
#[derive(Default)]
pub(in crate::metrics) struct MetricResident {
    pub(in crate::metrics) future: Option<Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send>>>,
    pub(in crate::metrics) unary: Option<http::Request<tonic::body::Body>>,
    pub(in crate::metrics) prepared: Option<http::Request<tonic::body::Body>>,
    pub(in crate::metrics) console: Option<crate::metrics::console_writer::Batch>,
    pub(in crate::metrics) snapshot: Option<opentelemetry_sdk::metrics::data::ResourceMetrics>,
    pub(in crate::metrics) result: Option<anyhow::Result<()>>,
    pub(in crate::metrics) encode_error: Option<tonic::Status>,
    pub(in crate::metrics) backing: Option<Arc<Backing>>,
    pub(in crate::metrics) future_credit: Option<ControlCredit>,
    pub(in crate::metrics) transport_credit: Option<Arc<transport::Credit>>,
    pub(in crate::metrics) memory: Option<Memory>,
}
pub(in crate::metrics) enum Resident {
    Trace(TraceResident),
    Metrics(MetricResident),
}
impl Resident {
    pub(in crate::metrics) fn empty(domain: Domain) -> Self {
        match domain {
            Domain::Trace => Self::Trace(Default::default()),
            Domain::Metrics => Self::Metrics(Default::default()),
        }
    }
    pub(in crate::metrics) fn domain(&self) -> Domain {
        match self {
            Self::Trace(_) => Domain::Trace,
            Self::Metrics(_) => Domain::Metrics,
        }
    }
    pub(in crate::metrics) fn trace(&self) -> Result<&TraceResident, WorkError> {
        match self {
            Self::Trace(v) => Ok(v),
            Self::Metrics(_) => Err(WorkError::Stopped),
        }
    }
    pub(in crate::metrics) fn trace_mut(&mut self) -> Result<&mut TraceResident, WorkError> {
        match self {
            Self::Trace(v) => Ok(v),
            Self::Metrics(_) => Err(WorkError::Stopped),
        }
    }
    pub(in crate::metrics) fn metric_mut(&mut self) -> Result<&mut MetricResident, WorkError> {
        match self {
            Self::Metrics(v) => Ok(v),
            Self::Trace(_) => Err(WorkError::Stopped),
        }
    }
    pub(in crate::metrics) fn take_for_retirement(&mut self, final_close: bool) -> Self {
        let domain = self.domain();
        let mut data = std::mem::replace(self, Self::empty(domain));
        if !final_close {
            if let (Self::Trace(source), Self::Trace(target)) = (&mut data, self) {
                target.pending = source.pending.take();
            }
        }
        data
    }
    pub(in crate::metrics) fn has_ingress(&self) -> bool {
        matches!(self,Self::Trace(v)if v.ingress.is_some())
    }
    pub(in crate::metrics) fn has_pending(&self) -> bool {
        matches!(self,Self::Trace(v)if v.pending.is_some())
    }
    pub(in crate::metrics) fn is_empty(&self) -> bool {
        match self {
            Self::Trace(v) => {
                v.future.is_none()
                    && v.unary.is_none()
                    && v.prepared.is_none()
                    && v.console.is_none()
                    && v.items.capacity() == 0
                    && v.pending.is_none()
                    && v.ingress.is_none()
                    && v.receiver.is_none()
                    && v.result.is_none()
                    && v.encode_error.is_none()
                    && v.backing.is_none()
                    && v.owners.capacity() == 0
                    && v.batch_credit.is_none()
                    && v.future_credit.is_none()
                    && v.transport_credit.is_none()
                    && v.memory.is_none()
            }
            Self::Metrics(v) => {
                v.future.is_none()
                    && v.unary.is_none()
                    && v.prepared.is_none()
                    && v.console.is_none()
                    && v.snapshot.is_none()
                    && v.result.is_none()
                    && v.encode_error.is_none()
                    && v.backing.is_none()
                    && v.future_credit.is_none()
                    && v.transport_credit.is_none()
                    && v.memory.is_none()
            }
        }
    }
    pub(in crate::metrics) fn future_mut(
        &mut self,
    ) -> &mut Option<Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send>>> {
        match self {
            Self::Trace(v) => &mut v.future,
            Self::Metrics(v) => &mut v.future,
        }
    }
    pub(in crate::metrics) fn unary_mut(
        &mut self,
    ) -> &mut Option<http::Request<tonic::body::Body>> {
        match self {
            Self::Trace(v) => &mut v.unary,
            Self::Metrics(v) => &mut v.unary,
        }
    }
    pub(in crate::metrics) fn prepared_mut(
        &mut self,
    ) -> &mut Option<http::Request<tonic::body::Body>> {
        match self {
            Self::Trace(v) => &mut v.prepared,
            Self::Metrics(v) => &mut v.prepared,
        }
    }
    pub(in crate::metrics) fn encode_error_mut(&mut self) -> &mut Option<tonic::Status> {
        match self {
            Self::Trace(v) => &mut v.encode_error,
            Self::Metrics(v) => &mut v.encode_error,
        }
    }
    pub(in crate::metrics) fn backing_ref(&self) -> Option<&Arc<Backing>> {
        match self {
            Self::Trace(v) => v.backing.as_ref(),
            Self::Metrics(v) => v.backing.as_ref(),
        }
    }
    pub(in crate::metrics) fn backing_mut(&mut self) -> &mut Option<Arc<Backing>> {
        match self {
            Self::Trace(v) => &mut v.backing,
            Self::Metrics(v) => &mut v.backing,
        }
    }
    pub(in crate::metrics) fn memory_mut(&mut self) -> &mut Option<Memory> {
        match self {
            Self::Trace(v) => &mut v.memory,
            Self::Metrics(v) => &mut v.memory,
        }
    }
    pub(in crate::metrics) fn future_credit_mut(&mut self) -> &mut Option<ControlCredit> {
        match self {
            Self::Trace(v) => &mut v.future_credit,
            Self::Metrics(v) => &mut v.future_credit,
        }
    }
    pub(in crate::metrics) fn transport_credit_mut(
        &mut self,
    ) -> &mut Option<Arc<transport::Credit>> {
        match self {
            Self::Trace(v) => &mut v.transport_credit,
            Self::Metrics(v) => &mut v.transport_credit,
        }
    }
    pub(in crate::metrics) fn memory_ref(&self) -> Option<&Memory> {
        match self {
            Self::Trace(v) => v.memory.as_ref(),
            Self::Metrics(v) => v.memory.as_ref(),
        }
    }
    pub(in crate::metrics) fn clear_completed(&mut self) {
        // Explicit order: actual SDK/data first, all loans after those objects.
        match self {
            Self::Trace(v) => {
                drop(v.future.take());
                drop(std::mem::take(&mut v.items));
                drop(std::mem::take(&mut v.owners));
                drop(v.future_credit.take());
                drop(v.batch_credit.take());
                drop(v.transport_credit.take());
                drop(v.memory.take());
            }
            Self::Metrics(v) => {
                drop(v.future.take());
                drop(v.snapshot.take());
                drop(v.future_credit.take());
                drop(v.transport_credit.take());
                drop(v.memory.take());
            }
        }
    }
}
