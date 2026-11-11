//! Bounded fanout, metadata work and encoding never wait on writer actors.
use super::{
    caller::{self, Captured, Options},
    cpu::{Cpu, Rejected},
    credits::{self, AdmissionError, Record},
    encoder, limits,
    registry::Scope,
    types::{Entry, Event, FieldValue, Origin, Timestamp},
    writer_pool::{Core, Error, Frame, Work, WorkCredits, Written},
};
use anyhow::Result;
use futures_util::future::join_all;
use std::{
    panic::Location,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::sync::{OwnedSemaphorePermit, oneshot};

const MAX_STACK_BYTES: usize = 32 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Delivery {
    Filtered,
    Sampled,
    Discarded,
    Written(usize),
    Fallback(usize),
    Rejected(AdmissionError),
    EncodingFailed,
    WriterFailed,
    Interrupted,
}
pub struct DestinationReport {
    pub name: Arc<str>,
    pub outcome: Delivery,
    pub caller_incomplete: bool,
}
pub struct DeliveryReport {
    pub destinations: Vec<DestinationReport>,
}
pub struct DeliveryTicket {
    destinations: Vec<Ticket>,
}
struct Ticket {
    name: Arc<str>,
    stage: Stage,
}
enum Stage {
    Done(Delivery),
    Pending {
        result: oneshot::Receiver<std::result::Result<Written, Error>>,
        incomplete: Arc<AtomicBool>,
    },
}
impl DeliveryTicket {
    /// Dropping this ticket drops only its response waiters.
    pub async fn wait(self) -> DeliveryReport {
        let destinations = join_all(self.destinations.into_iter().map(|ticket| async move {
            let (outcome, caller_incomplete) = match ticket.stage {
                Stage::Done(outcome) => (outcome, false),
                Stage::Pending { result, incomplete } => {
                    let delivery = match result.await {
                        Ok(Ok(Written::Bytes(n))) => Delivery::Written(n),
                        Ok(Ok(Written::Fallback(n))) => Delivery::Fallback(n),
                        Ok(Err(Error::Encode)) => Delivery::EncodingFailed,
                        Ok(Err(Error::EncodingQueue)) => {
                            Delivery::Rejected(AdmissionError::EncodingQueue)
                        }
                        Ok(Err(Error::EncodingBytes)) => {
                            Delivery::Rejected(AdmissionError::EncodingBytes)
                        }
                        Ok(Err(Error::DestinationBytes)) => {
                            Delivery::Rejected(AdmissionError::DestinationFull)
                        }
                        Ok(Err(Error::Write | Error::Flush | Error::Open)) => {
                            Delivery::WriterFailed
                        }
                        _ => Delivery::Interrupted,
                    };
                    (delivery, incomplete.load(Ordering::Relaxed))
                }
            };
            DestinationReport {
                name: ticket.name,
                outcome,
                caller_incomplete,
            }
        }))
        .await;
        DeliveryReport { destinations }
    }
}

struct Hold {
    record: Arc<Record>,
    _job: OwnedSemaphorePermit,
    _attribution: WorkCredits,
    // Release permits/record before this can retire the final writer lease.
    scope: Arc<Scope>,
}
type FrameResult = std::result::Result<Frame, Error>;
type FrameSender = Arc<Mutex<Option<oneshot::Sender<FrameResult>>>>;
struct Render {
    hold: Arc<Hold>,
    index: usize,
    sender: FrameSender,
    cap: usize,
    reserved_cap: usize,
    workspace: Workspace,
    capture: Option<Arc<Captured>>,
    site: &'static Location<'static>,
    options: Options,
    metadata: Option<caller::Resolved>,
    placeholder: Option<encoder::Resolved>,
    incomplete: Arc<AtomicBool>,
}

#[inline(never)]
pub(super) fn emit(
    scope: Arc<Scope>,
    event: Event,
    site: &'static Location<'static>,
) -> std::result::Result<DeliveryTicket, AdmissionError> {
    let cost =
        limits::measure(&event, &scope.registry.limits).map_err(|_| AdmissionError::EventLimit)?;
    let selected: Vec<_> = match &event.origin {
        Origin::Core => vec![scope.default],
        Origin::Sink => scope.sink.into_iter().collect(),
        Origin::Module { module_id } => scope
            .logs
            .iter()
            .enumerate()
            .filter_map(|(index, destination)| {
                destination
                    .routing
                    .as_ref()
                    .is_some_and(|routing| routing.allows(module_id, true))
                    .then_some(index)
            })
            .collect(),
    };
    let no_options = Options {
        with_caller: false,
        caller_skip: 0,
        stacktrace: None,
    };
    let options = match &event.origin {
        Origin::Core | Origin::Sink => selected
            .first()
            .map_or(no_options, |&index| scope.logs[index].options),
        Origin::Module { .. } => selected
            .iter()
            .find_map(|&index| {
                let log = &scope.logs[index];
                (log.options.nonempty()
                    && log
                        .routing
                        .as_ref()
                        .is_some_and(|routing| routing.has_filters()))
                .then_some(log.options)
            })
            .unwrap_or(no_options),
    };
    let selected: Vec<_> = selected
        .into_iter()
        .map(|index| {
            let destination = &scope.logs[index];
            let outcome = if event.level < destination.level
                || destination
                    .routing
                    .as_ref()
                    .is_some_and(|routing| !routing.allows(&event.logger, false))
            {
                Some(Delivery::Filtered)
            } else if destination.discard {
                Some(Delivery::Discarded)
            } else if destination
                .sampler
                .as_ref()
                .is_some_and(|sampler| !sampler.keep(event.level, &event.message, event.time))
            {
                Some(Delivery::Sampled)
            } else {
                None
            };
            (index, outcome)
        })
        .collect();
    // Sampling and namespace rejection precede unwind or filesystem work.
    let capture =
        if selected.iter().any(|(_, outcome)| outcome.is_none()) && options.needed(event.level) {
            Captured::capture()
                .ok()
                .map(|capture| Arc::new(capture.with_site(site)))
        } else {
            None
        };
    let capture_failed = options.needed(event.level) && capture.is_none();
    let mut fanout = Fanout {
        scope,
        event: Some(event),
        record: None,
        cost,
        capture,
        site,
        options,
        capture_failed,
    };
    let mut destinations = Vec::with_capacity(selected.len());
    for (index, outcome) in selected {
        let name = fanout.scope.logs[index].name.clone();
        let stage = match outcome {
            Some(outcome) => Stage::Done(outcome),
            None => match fanout.start(index) {
                Ok(stage) => stage,
                Err(AdmissionError::PendingBytes) => return Err(AdmissionError::PendingBytes),
                Err(error) => Stage::Done(Delivery::Rejected(error)),
            },
        };
        destinations.push(Ticket { name, stage });
    }
    Ok(DeliveryTicket { destinations })
}
/// The ingress owns a shared record only after a branch can enter a physical
/// writer. The synchronous fanout is the only temporary holder without a
/// destination attribution; every queued or running holder is a Hold.
struct Fanout {
    scope: Arc<Scope>,
    event: Option<Event>,
    record: Option<Arc<Record>>,
    cost: limits::EventCost,
    capture: Option<Arc<Captured>>,
    site: &'static Location<'static>,
    options: Options,
    capture_failed: bool,
}
impl Fanout {
    fn start(&mut self, index: usize) -> std::result::Result<Stage, AdmissionError> {
        let registry = &self.scope.registry;
        let destination = &self.scope.logs[index];
        let core = &self.scope.writers[destination.writer].core;
        let event_bytes = self.cost.bytes as usize;
        // Finish all physical admissions before touching the global ledgers.
        let attribution = core.reserve_work(event_bytes).map_err(admission)?;
        let reservation = core.reserve().map_err(admission)?;
        let base = event_bytes
            .saturating_mul(6)
            .saturating_add(destination.static_bytes.saturating_mul(8))
            .saturating_add(512)
            .saturating_add(
                self.capture
                    .as_ref()
                    .map_or(0, |captured| captured.byte_cost() + MAX_STACK_BYTES),
            );
        // Each dynamic file provider has a 1 MiB read bound. Keep an extra
        // provider's workspace charged even when the final encoded cap is tiny.
        let provider = destination.dynamic_count.saturating_mul((1 << 20) + 256);
        let cap = registry
            .limits
            .max_encoded_bytes
            .min(base.saturating_add(provider));
        let reserve_cap = if provider > 0 { cap.max(1 << 20) } else { cap };
        let bytes = credits::encoding_reservation(reserve_cap)
            .ok()
            .and_then(|bytes| bytes.checked_add(destination.regexp_search))
            .ok_or(AdmissionError::EncodingBytes)?;
        let local = core.reserve_workspace(bytes).map_err(admission)?;
        let job = registry.credits.job()?;
        let workspace = Workspace {
            destination: local,
            global: registry.credits.encoding(bytes)?,
        };
        if let Some(event) = self.event.take() {
            self.record = Some(registry.credits.admit(event, self.cost)?);
        }
        let record = self.record.as_ref().ok_or(AdmissionError::Closed)?.clone();
        let (frame, receive) = oneshot::channel();
        let (send_result, result) = oneshot::channel();
        let hold = Arc::new(Hold {
            scope: self.scope.clone(),
            record,
            _job: job,
            _attribution: attribution,
        });
        reservation
            .write(Work {
                frame: receive,
                result: send_result,
                hold: Box::new(hold.clone()),
            })
            .map_err(admission)?;
        let incomplete = Arc::new(AtomicBool::new(self.capture_failed));
        let render = Render {
            hold,
            index,
            sender: Arc::new(Mutex::new(Some(frame))),
            cap,
            reserved_cap: reserve_cap,
            workspace,
            capture: self.capture.clone(),
            site: self.site,
            options: self.options,
            metadata: None,
            placeholder: None,
            incomplete: incomplete.clone(),
        };
        render.schedule_prep();
        Ok(Stage::Pending { result, incomplete })
    }
}
fn admission(error: Error) -> AdmissionError {
    if error == Error::Closed {
        AdmissionError::Closed
    } else {
        AdmissionError::DestinationFull
    }
}
struct Workspace {
    destination: OwnedSemaphorePermit,
    global: OwnedSemaphorePermit,
}
impl Workspace {
    fn reserve(
        core: &Core,
        credits: &credits::Credits,
        bytes: usize,
    ) -> std::result::Result<Self, AdmissionError> {
        // Local first: a saturated destination never takes global headroom.
        let destination = core.reserve_workspace(bytes).map_err(admission)?;
        let global = credits.encoding(bytes)?;
        Ok(Self {
            destination,
            global,
        })
    }
    fn add(&mut self, extra: Self) {
        self.destination.merge(extra.destination);
        self.global.merge(extra.global);
    }
    fn retain(
        &mut self,
        bytes: usize,
    ) -> std::result::Result<(OwnedSemaphorePermit, OwnedSemaphorePermit), Error> {
        if bytes > self.destination.num_permits() {
            return Err(Error::DestinationBytes);
        }
        if bytes > self.global.num_permits() {
            return Err(Error::EncodingBytes);
        }
        let global = self.global.split(bytes).ok_or(Error::EncodingBytes)?;
        let destination = self.destination.split(bytes).ok_or(Error::EncodingBytes)?;
        Ok((global, destination))
    }
}
impl Render {
    fn submit(self, cpu: Arc<Cpu>, step: impl FnOnce(Self) + Send + 'static) {
        let sender = self.sender.clone();
        if let Err(error) = cpu.try_submit(move || {
            step(self);
            Ok(())
        }) {
            send(
                &sender,
                Err(match error {
                    Rejected::Closed => Error::Closed,
                    Rejected::Full => Error::EncodingQueue,
                }),
            );
        }
    }
    fn schedule_prep(self) {
        if self.hold.scope.logs[self.index].dynamic_count == 0 {
            self.schedule_symbols();
        } else {
            let lane = self.hold.scope.registry.prep.clone();
            self.submit(lane, |mut job| {
                let prepared = job.hold.scope.logs[job.index].encoder.resolve(&mut lookup);
                match prepared {
                    Ok(placeholder) => {
                        job.placeholder = Some(placeholder);
                        job.schedule_symbols();
                    }
                    Err(_) => send(&job.sender, Err(Error::Encode)),
                }
            });
        }
    }
    fn schedule_symbols(mut self) {
        if self.capture.is_none() {
            let level = self.hold.record.event.level;
            if self.options.needed(level) {
                self.metadata = Some(caller::Resolved::unresolved(
                    Some(self.site),
                    self.options,
                    level,
                    MAX_STACK_BYTES,
                ));
            }
            self.schedule_encode();
        } else {
            let lane = self.hold.scope.registry.symbols.clone();
            self.submit(lane, |mut job| {
                if let Some(capture) = job.capture.take() {
                    let level = job.hold.record.event.level;
                    let cache = &job.hold.scope.registry.symbol_cache;
                    match cache
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .resolve(&capture, job.options, level, MAX_STACK_BYTES)
                    {
                        Ok(metadata) => {
                            if metadata.incomplete {
                                job.incomplete.store(true, Ordering::Relaxed);
                            }
                            job.metadata = Some(metadata);
                        }
                        Err(_) => {
                            job.incomplete.store(true, Ordering::Relaxed);
                            job.metadata = Some(caller::Resolved::unresolved(
                                Some(job.site),
                                job.options,
                                level,
                                MAX_STACK_BYTES,
                            ));
                        }
                    }
                }
                job.schedule_encode();
            });
        }
    }
    fn schedule_encode(self) {
        let lane = self.hold.scope.registry.cpu.clone();
        self.submit(lane, |job| job.encode());
    }
    fn encode(mut self) {
        let event = &self.hold.record.event;
        let registry = &self.hold.scope.registry;
        let destination = &self.hold.scope.logs[self.index];
        let encoder = &destination.encoder;
        let placeholder = match self.placeholder.take() {
            Some(placeholder) => placeholder,
            None => match encoder.resolve(&mut |_| Ok(None)) {
                Ok(placeholder) => placeholder,
                Err(_) => {
                    send(&self.sender, Err(Error::Encode));
                    return;
                }
            },
        };
        let mut entry = Entry::from(event);
        if let Some(metadata) = &self.metadata {
            if self.options.with_caller {
                entry.caller = metadata.caller.as_ref();
            }
            if self
                .options
                .stacktrace
                .is_some_and(|minimum| event.level >= minimum)
            {
                entry.stacktrace = metadata.stacktrace.as_deref();
            }
        }
        let mut encoded = encoder.encode_entry(
            entry,
            &[],
            &placeholder,
            crate::http_config::helpers::local_zone_info,
            self.cap,
        );
        if self.cap < registry.limits.max_encoded_bytes
            && encoded
                .as_ref()
                .is_err_and(|e| e.is::<super::bounded::ByteLimit>())
        {
            let full = registry.limits.max_encoded_bytes;
            let current = self.reserved_cap;
            let additional = full.saturating_sub(current);
            let writer = &self.hold.scope.writers[destination.writer].core;
            let extra = credits::encoding_reservation(additional)
                .map_err(|_| AdmissionError::EncodingBytes)
                .and_then(|bytes| Workspace::reserve(writer, &registry.credits, bytes));
            if let Ok(extra) = extra {
                self.workspace.add(extra);
                encoded = encoder.encode_entry(
                    entry,
                    &[],
                    &placeholder,
                    crate::http_config::helpers::local_zone_info,
                    full,
                );
            } else {
                let error = match extra {
                    Err(AdmissionError::DestinationFull) => Error::DestinationBytes,
                    Err(AdmissionError::Closed) => Error::Closed,
                    _ => Error::EncodingBytes,
                };
                send(&self.sender, Err(error));
                return;
            }
        }
        let result = encoded.map_err(|_| Error::Encode).and_then(|bytes| {
            // Once encoding is done only the actual Vec allocation follows a
            // blocked writer. The short-lived working credit is returned now.
            let retained = bytes.capacity();
            let writer = &self.hold.scope.writers[destination.writer].core;
            let writer_credit = writer.reserve_frame(retained).map_err(|error| {
                if error == Error::Closed {
                    error
                } else {
                    Error::DestinationBytes
                }
            })?;
            let (credit, writer_workspace) = self.workspace.retain(retained)?;
            Ok(Frame {
                bytes,
                credit,
                writer_credit: Some((writer_credit, writer_workspace)),
            })
        });
        send(&self.sender, result);
    }
}
fn send(sender: &FrameSender, result: FrameResult) {
    let channel = sender
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
    if let Some(channel) = channel {
        let _ = channel.send(result);
    }
}
fn lookup(key: &str) -> Result<Option<FieldValue>> {
    use crate::http_config::helpers::{global_lookup, prepare_file_lookup};
    if key == "time.now" {
        return Ok(Some(FieldValue::Time(Timestamp::now()?)));
    }
    if let Some(file) = prepare_file_lookup(key) {
        return file.map(|value| Some(FieldValue::String(value)));
    }
    Ok(global_lookup(key).map(FieldValue::String))
}
