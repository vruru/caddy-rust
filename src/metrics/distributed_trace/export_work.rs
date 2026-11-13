//! Trace-specific source, receiver and export commands. Shared residence is closed.
use super::processor;
use crate::metrics::export_retirement::resident::TraceResident as ResidentData;
use crate::metrics::export_retirement::*;
pub(in crate::metrics) use crate::metrics::export_retirement::{
    ActorCell, BatchGuard, Step, WorkError,
};
pub(crate) use crate::metrics::export_retirement::{
    ByteKind, ExportContext as TraceContext, RetirementOwner as TraceRetirementOwner,
};
use anyhow::{Result, anyhow};
use std::sync::atomic::Ordering;
use std::{
    future::Future,
    sync::{Arc, Weak},
    task::{Context, Poll, Waker},
};
use tokio::sync::Semaphore;
pub(in crate::metrics) struct ItemSummary {
    pub(in crate::metrics) weight: usize,
}
#[derive(Clone, Copy)]
pub(in crate::metrics) struct BatchSummary {
    pub(in crate::metrics) len: usize,
    pub(in crate::metrics) weight: usize,
}
pub(in crate::metrics) struct ExportInputs {
    pub(in crate::metrics) plan: Weak<super::export::Plan>,
    pub(in crate::metrics) metadata: Arc<crate::metrics::Metadata>,
    pub(in crate::metrics) scratch: tokio::sync::OwnedSemaphorePermit,
    pub(in crate::metrics) timer: tokio::sync::OwnedSemaphorePermit,
    pub(in crate::metrics) output: Arc<Semaphore>,
    pub(in crate::metrics) created: tokio::time::Instant,
}
pub(in crate::metrics) enum TraceCommand {
    Begin(usize),
    Export(ExportInputs),
    Console {
        plan: Weak<super::export::Plan>,
        output: Arc<Semaphore>,
        serial: tokio::sync::OwnedSemaphorePermit,
    },
}

impl ActorCell {
    pub(in crate::metrics) fn ticket(&self) -> Result<TraceSubmitTicket> {
        let owner = self
            .shared
            .upgrade()
            .ok_or_else(|| anyhow!("trace source stopped"))?;
        anyhow::ensure!(
            owner.source.domain() == Domain::Trace,
            "trace source capability domain mismatch"
        );
        Ok(TraceSubmitTicket {
            inner: self.submission_ticket()?,
        })
    }

    pub(in crate::metrics) fn promote_pending(&self) -> Option<ItemSummary> {
        let mut state = self.cell.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.closed
            || state.retire
            || state.polling
            || state.retiring
            || state
                .data
                .trace_mut()
                .expect("trace-only source capability")
                .ingress
                .is_some()
        {
            return None;
        }
        let item = state
            .data
            .trace_mut()
            .expect("trace-only source capability")
            .pending
            .take()?;
        let summary = ItemSummary {
            weight: item.credit.held(),
        };
        state
            .data
            .trace_mut()
            .expect("trace-only source capability")
            .ingress = Some(item);
        Some(summary)
    }
    pub(in crate::metrics) fn pending_count(&self) -> usize {
        usize::from(
            self.cell
                .state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .data
                .trace()
                .expect("trace source")
                .pending
                .is_some(),
        )
    }
    pub(in crate::metrics) fn source_summary(&self) -> BatchSummary {
        let state = self.cell.state.lock().unwrap_or_else(|e| e.into_inner());
        BatchSummary {
            len: state
                .data
                .trace()
                .expect("trace-only source capability")
                .items
                .len(),
            weight: state
                .data
                .trace()
                .expect("trace-only source capability")
                .source_weight,
        }
    }
    /// Only ownership moves into an already-prepaid Vec occur here. No heap
    /// growth, large drop, formatting, callback or await under this fence.
    pub(in crate::metrics) fn append_ingress(
        &self,
        weight_limit: usize,
    ) -> std::result::Result<bool, WorkError> {
        let mut state = self.cell.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.closed || state.retire || state.polling || state.retiring {
            return Err(WorkError::Stopped);
        }
        let current = state
            .data
            .trace_mut()
            .expect("trace-only source capability")
            .source_weight;
        let weight = state
            .data
            .trace()
            .expect("trace source")
            .ingress
            .as_ref()
            .ok_or(WorkError::Stopped)?
            .credit
            .held();
        if current
            .checked_add(weight)
            .is_none_or(|value| value > weight_limit)
        {
            debug_assert!(
                state
                    .data
                    .trace_mut()
                    .expect("trace-only source capability")
                    .pending
                    .is_none()
            );
            state
                .data
                .trace_mut()
                .expect("trace-only source capability")
                .pending = state
                .data
                .trace_mut()
                .expect("trace-only source capability")
                .ingress
                .take();
            return Ok(false);
        }
        if state
            .data
            .trace_mut()
            .expect("trace-only source capability")
            .items
            .len()
            == state
                .data
                .trace_mut()
                .expect("trace-only source capability")
                .items
                .capacity()
        {
            return Err(WorkError::Busy);
        }
        let item = state
            .data
            .trace_mut()
            .expect("trace-only source capability")
            .ingress
            .take()
            .ok_or(WorkError::Stopped)?;
        state
            .data
            .trace_mut()
            .expect("trace-only source capability")
            .items
            .push(item);
        state
            .data
            .trace_mut()
            .expect("trace-only source capability")
            .source_weight = current + weight;
        Ok(true)
    }
    pub(in crate::metrics) async fn begin_source(
        &self,
        budget: &crate::http_runtime::resource_budget::BlockingBudget,
        count: usize,
    ) -> std::result::Result<Step, WorkError> {
        self.execute(budget, Command::Trace(TraceCommand::Begin(count)))
            .await
    }
    pub(in crate::metrics) async fn begin_export(
        &self,
        budget: &crate::http_runtime::resource_budget::BlockingBudget,
        inputs: ExportInputs,
    ) -> std::result::Result<Step, WorkError> {
        self.execute(budget, Command::Trace(TraceCommand::Export(inputs)))
            .await
    }
    pub(in crate::metrics) async fn begin_console(
        &self,
        budget: &crate::http_runtime::resource_budget::BlockingBudget,
        plan: Weak<super::export::Plan>,
        output: Arc<Semaphore>,
        serial: tokio::sync::OwnedSemaphorePermit,
    ) -> std::result::Result<Step, WorkError> {
        self.execute(
            budget,
            Command::Trace(TraceCommand::Console {
                plan,
                output,
                serial,
            }),
        )
        .await
    }
    /// The async output is small. A dequeued Item cannot be suspended between
    /// Receiver::poll_recv and residence, including a concurrent close.
    pub(in crate::metrics) async fn receive(
        &self,
        input: &Arc<tokio::sync::Mutex<OwnedReceiver>>,
        try_only: bool,
    ) -> Result<Option<ItemSummary>> {
        let mut ticket = Some(self.ticket()?);
        // A dedicated close notification is never consumed by normal step
        // wakes. notify_waiters also covers a close between construction and
        // first poll without allocating a cancellation-token tree.
        let closed = self.cell.closed_notify.notified();
        tokio::pin!(closed);
        closed.as_mut().enable();
        let mut input = Some(input.lock().await);
        std::future::poll_fn(|cx| {
            let globally_closed = self
                .shared
                .upgrade()
                .is_none_or(|shared| shared.closed.load(Ordering::Acquire));
            if globally_closed || closed.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Err(anyhow!("trace source residence stopped")));
            }
            let next = if try_only {
                match input.as_mut().expect("resident input lock").receiver_mut() {
                    Some(receiver) => match receiver.inner.try_recv() {
                        Ok(item) => Poll::Ready(Some(item)),
                        Err(_) => Poll::Ready(None),
                    },
                    None => Poll::Ready(None),
                }
            } else {
                match input.as_mut().expect("resident input lock").receiver_mut() {
                    Some(receiver) => receiver.inner.poll_recv(cx),
                    None => Poll::Ready(None),
                }
            };
            match next {
                Poll::Ready(Some(item)) => {
                    let summary = ItemSummary {
                        weight: item.credit.held(),
                    };
                    let signal = ticket
                        .take()
                        .expect("one resident source receipt")
                        .store_quiet(item);
                    // The Item is resident before unlocking; signal only after
                    // releasing even the asynchronous receiver mutex.
                    drop(input.take());
                    drop(signal);
                    Poll::Ready(Ok(Some(summary)))
                }
                Poll::Ready(None) => Poll::Ready(Ok(None)),
                Poll::Pending => Poll::Pending,
            }
        })
        .await
    }
}
pub(in crate::metrics) struct TraceSubmitTicket {
    inner: SubmitTicket,
}
impl TraceSubmitTicket {
    /// Receiver polling must store a Ready item synchronously before returning.
    /// A pre-registered ticket still accepts its item after close, for retirement.
    pub(in crate::metrics) fn store(self, item: processor::Item) {
        drop(self.store_quiet(item));
    }
    pub(in crate::metrics) fn store_quiet(self, item: processor::Item) -> StoredSignal {
        let mut ticket = self.inner;
        {
            let mut state = ticket.cell.state.lock().unwrap_or_else(|e| e.into_inner());
            // There is exactly one ticket, ingress was empty at admission and
            // poll/reap cannot take data while submitters != 0.
            debug_assert!(
                state
                    .data
                    .trace_mut()
                    .expect("trace-only source capability")
                    .ingress
                    .is_none()
            );
            state
                .data
                .trace_mut()
                .expect("trace-only source capability")
                .ingress = Some(item);
            state.submitters = 0;
            ticket.active = false;
        }
        StoredSignal {
            cell: ticket.cell.clone(),
            shared: ticket.shared.clone(),
        }
    }
    pub(in crate::metrics) fn store_receiver(
        self,
        receiver: processor::Receiver,
    ) -> StoredSignal {
        let mut ticket=self.inner;
        {
            let mut state = ticket.cell.state.lock().unwrap_or_else(|e| e.into_inner());
            debug_assert!(
                state
                    .data
                    .trace_mut()
                    .expect("trace-only source capability")
                    .receiver
                    .is_none()
            );
            state
                .data
                .trace_mut()
                .expect("trace-only source capability")
                .receiver = Some(receiver);
            state.submitters = 0;
            ticket.active = false;
        }
        StoredSignal {
            cell: ticket.cell.clone(),
            shared: ticket.shared.clone(),
        }
    }
}

impl RetirementOwner {
    pub(in crate::metrics) fn receiver_slot(&self) -> Result<ReceiverSlot> {
        let cell = self.register()?;
        let ticket = cell.ticket()?;
        let layout = std::mem::size_of::<OwnedReceiver>()
            .checked_add(std::mem::size_of::<tokio::sync::Mutex<OwnedReceiver>>())
            .and_then(|n| {
                n.checked_add(
                    std::mem::size_of::<ReceiverSlot>() + 6 * std::mem::size_of::<usize>(),
                )
            })
            .ok_or_else(|| anyhow!("trace receiver owner layout overflow"))?;
        let credit = self.shared.source.trace_source()?.metadata(layout)?;
        // The admitted ticket keeps this closed disposal cell pinned, including
        // when the external Process owner closes before the receiver is dropped.
        cell.retire(true);
        Ok(ReceiverSlot {
            ticket: Some(ticket),
            credit,
        })
    }
}
pub(in crate::metrics) struct ReceiverSlot {
    ticket: Option<TraceSubmitTicket>,
    credit: Arc<processor::Credit>,
}
impl ReceiverSlot {
    pub(in crate::metrics) fn wrap(mut self, receiver: processor::Receiver) -> OwnedReceiver {
        OwnedReceiver {
            inner: Some(receiver),
            disposal: self.ticket.take(),
            _credit: self.credit.clone(),
        }
    }
}
pub(in crate::metrics) struct OwnedReceiver {
    inner: Option<processor::Receiver>,
    disposal: Option<TraceSubmitTicket>,
    _credit: Arc<processor::Credit>,
}
impl OwnedReceiver {
    pub(in crate::metrics) fn receiver_mut(&mut self) -> Option<&mut processor::Receiver> {
        self.inner.as_mut()
    }
    /// Move the whole channel before waking. Callers drop the returned small
    /// signal after releasing the outer asynchronous receiver mutex.
    pub(in crate::metrics) fn retire_queue(&mut self) -> (usize, Option<StoredSignal>) {
        let Some(receiver) = self.inner.take() else {
            return (0, None);
        };
        let count = receiver.inner.len();
        let signal = self
            .disposal
            .take()
            .expect("registered receiver disposal ticket")
            .store_receiver(receiver);
        (count, Some(signal))
    }
}
impl Drop for OwnedReceiver {
    fn drop(&mut self) {
        let (_, signal) = self.retire_queue();
        drop(signal);
    }
}

pub(in crate::metrics) fn apply_command(
    data: &mut ResidentData,
    reference: &CellRef,
    cpu: &crate::http_runtime::resource_budget::BlockingBudget,
    command: TraceCommand,
) -> std::result::Result<Step, WorkError> {
    match command {
        TraceCommand::Begin(count) => {
            let shared = reference.shared.upgrade().ok_or(WorkError::Stopped)?;
            let bytes = count
                .checked_mul(std::mem::size_of::<processor::Item>() * 2 + 128)
                .and_then(|n| n.checked_add(4096))
                .ok_or(WorkError::Busy)?;
            data.batch_credit = Some(
                shared
                    .source
                    .trace_source()
                    .map_err(|_| WorkError::Stopped)?
                    .metadata(bytes)
                    .map_err(|_| WorkError::Busy)?,
            );
            data.items
                .try_reserve_exact(count)
                .map_err(|_| WorkError::Busy)?;
            let first = data.ingress.take().ok_or(WorkError::Stopped)?;
            data.source_weight = first.credit.held();
            data.items.push(first);
            Ok(Step::Started)
        }
        TraceCommand::Export(inputs) => {
            let shared = reference.shared.upgrade().ok_or(WorkError::Stopped)?;
            let plan = inputs.plan.upgrade().ok_or(WorkError::Stopped)?;
            let credit = Arc::new(
                crate::metrics::transport::Credit::trace(
                    inputs.scratch,
                    inputs.metadata,
                    inputs.timer,
                    shared
                        .source
                        .trace_source()
                        .map_err(|_| WorkError::Stopped)?,
                    inputs.created,
                    reference.shared.clone(),
                )
                .map_err(|_| WorkError::Busy)?,
            );
            data.memory = Some(credit.memory().map_err(|_| WorkError::Busy)?);
            if let Some(writer) = plan.console() {
                data.transport_credit = Some(credit);
                return Ok(Step::Console {
                    writer,
                    deadline: inputs
                        .created
                        .checked_add(plan.timeout)
                        .ok_or(WorkError::Busy)?,
                });
            }
            let context = reference.context().map_err(|_| WorkError::Busy)?;
            let (spans, parents, children) = take_spans(data)?;
            drop(parents);
            drop(children);
            let cpu = cpu.clone();
            let future = async move { plan.export_with_context(spans, credit, context, cpu).await };
            install_future(
                data,
                shared
                    .source
                    .trace_source()
                    .map_err(|_| WorkError::Stopped)?,
                future,
            )?;
            Ok(Step::Started)
        }
        TraceCommand::Console {
            plan,
            output,
            serial,
        } => {
            let shared = reference.shared.upgrade().ok_or(WorkError::Stopped)?;
            let plan = plan.upgrade().ok_or(WorkError::Stopped)?;
            let writer = plan.console().ok_or(WorkError::Stopped)?;
            let context = reference.context().map_err(|_| WorkError::Busy)?;
            let credit = data.transport_credit.take().ok_or(WorkError::Stopped)?;
            let memory = data.memory.as_ref().ok_or(WorkError::Stopped)?.clone();
            let output = output
                .try_acquire_many_owned(64 << 20)
                .map_err(|_| WorkError::Busy)?;
            let (spans, parents, children) = take_spans(data)?;
            let bytes = super::console::encode(&spans, &parents, &children, plan.resource())
                .map_err(|_| WorkError::Busy)?;
            drop(spans);
            drop(parents);
            drop(children);
            let timeout = plan.timeout;
            let input = PinInput {
                data: bytes.into(),
                output: Some(output),
                memory,
            };
            let future = async move {
                let bytes = context.pin_input(ByteKind::Console, input).await?;
                writer
                    .send(
                        crate::metrics::console_writer::Batch {
                            bytes,
                            output: None,
                            credit,
                            serial,
                        },
                        timeout,
                    )
                    .await
            };
            install_future(
                data,
                shared
                    .source
                    .trace_source()
                    .map_err(|_| WorkError::Stopped)?,
                future,
            )?;
            Ok(Step::Started)
        }
    }
}

fn take_spans(
    data: &mut ResidentData,
) -> std::result::Result<
    (
        Vec<opentelemetry_sdk::trace::SpanData>,
        Vec<opentelemetry::trace::SpanContext>,
        Vec<u64>,
    ),
    WorkError,
> {
    let count = data.items.len();
    let mut spans = Vec::new();
    let mut parents = Vec::new();
    let mut children = Vec::new();
    spans
        .try_reserve_exact(count)
        .map_err(|_| WorkError::Busy)?;
    parents
        .try_reserve_exact(count)
        .map_err(|_| WorkError::Busy)?;
    children
        .try_reserve_exact(count)
        .map_err(|_| WorkError::Busy)?;
    data.owners
        .try_reserve_exact(count)
        .map_err(|_| WorkError::Busy)?;
    for item in std::mem::take(&mut data.items) {
        spans.push(item.span);
        parents.push(item.parent);
        children.push(item.children);
        data.owners.push(item.credit);
    }
    Ok((spans, parents, children))
}

// Private constructors above are the only callers; this does not expose a
// generic future scheduler or user callback surface.
fn install_future<F: Future<Output = Result<()>> + Send + 'static>(
    data: &mut ResidentData,
    source: &Arc<processor::Process>,
    future: F,
) -> std::result::Result<(), WorkError> {
    let layout = std::mem::size_of_val(&future)
        .checked_add(std::mem::size_of::<processor::Credit>() + 6 * std::mem::size_of::<usize>())
        .ok_or(WorkError::Busy)?;
    data.future_credit = Some(ControlCredit::Trace(
        source.metadata(layout).map_err(|_| WorkError::Busy)?,
    ));
    data.future = Some(Box::pin(future));
    Ok(())
}
