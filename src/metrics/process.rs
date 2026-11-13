use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
const LABEL_BYTES: usize = 128 << 20;
const GENERATION_HEADROOM: usize = 8 << 20;
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
pub(super) struct AdminKey {
    pub path: &'static str,
    pub method: Arc<str>,
    pub status: Option<u16>,
}
pub(super) struct AdminSeries {
    pub value: AtomicU64,
    _credit: OwnedSemaphorePermit,
}
pub struct Process {
    connections: super::connection::Connections,
    pub(super) traces: Arc<super::distributed_trace::processor::Process>,
    pub(super) trace_workspace: Arc<Semaphore>,
    pub(super) trace_output: Arc<Semaphore>,
    pub(super) trace_cpu: crate::http_runtime::resource_budget::BlockingBudget,
    pub(super) discarded_bodies: Arc<Semaphore>,
    pub(super) prom_servers: super::prometheus::Servers,
    pub(super) prom_listeners: Arc<Semaphore>,
    pub(super) prom_connections: Arc<Semaphore>,
    pub(super) collection: crate::http_runtime::resource_budget::BlockingBudget,
    pub(super) scratch: Arc<Semaphore>,
    pub(super) output: Arc<Semaphore>,
    pub(super) reload_success: AtomicU64,
    pub(super) reload_time: AtomicU64,
    pub(super) admin: Mutex<BTreeMap<AdminKey, Arc<AdminSeries>>>,
    pub(super) labels: Arc<Semaphore>,
    pub(super) request_bytes: Arc<Semaphore>,
    pub(super) dropped: AtomicU64,
    pub(super) export_errors: AtomicU64,
    generation_headroom: Mutex<Option<OwnedSemaphorePermit>>,
    _fixed_credit: OwnedSemaphorePermit,
}
impl Process {
    pub(crate) fn connection_factory(&self) -> anyhow::Result<crate::outgoing_tls::ScopeFactory> {
        self.connections.factory()
    }
    pub(crate) fn close_connections(&self) { self.connections.close(); }
    pub(crate) async fn shutdown_connections(&self) -> anyhow::Result<()> {
        self.connections.shutdown().await
    }

    pub fn tracing_diagnostics(&self)->super::TracingDiagnostics{
        super::TracingDiagnostics{
            retained_source_bytes:self.traces.used(),
            live_span_owners:self.traces.retained_spans(),
            workspace_remaining_bytes:self.trace_workspace.available_permits(),
            encoded_output_remaining_bytes:self.trace_output.available_permits(),
            observations_dropped:self.traces.dropped.load(Ordering::Relaxed),
            exports_failed:self.traces.errors.load(Ordering::Relaxed),
        }
    }
    pub fn diagnostics(&self) -> super::Diagnostics {
        let reserved = self
            .generation_headroom
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map_or(0, OwnedSemaphorePermit::num_permits);
        let available = self.labels.available_permits();
        super::Diagnostics {
            labels_remaining_bytes: available + reserved,
            label_admission_remaining_bytes: available,
            reserved_for_generation_bytes: reserved,
            request_state_remaining_bytes: self.request_bytes.available_permits(),
            snapshot_workspace_remaining_bytes: self.scratch.available_permits(),
            encoded_output_remaining_bytes: self.output.available_permits(),
            observations_dropped: self.dropped.load(Ordering::Relaxed),
            exports_failed: self.export_errors.load(Ordering::Relaxed),
        }
    }
    fn replenish_headroom(&self) {
        let mut held = self
            .generation_headroom
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let previous = held.as_ref().map_or(0, OwnedSemaphorePermit::num_permits);
        if previous < GENERATION_HEADROOM
            && let Ok(credit) = self
                .labels
                .clone()
                .try_acquire_many_owned((GENERATION_HEADROOM - previous) as u32)
        {
            if let Some(held) = held.as_mut() {
                held.merge(credit);
            } else {
                *held = Some(credit);
            }
        }
    }
    pub(super) fn pay_labels(&self, bytes: u32) -> Option<OwnedSemaphorePermit> {
        self.replenish_headroom();
        self.labels.clone().try_acquire_many_owned(bytes).ok()
    }
    pub(super) fn pay_generation(&self, bytes: u32) -> Option<OwnedSemaphorePermit> {
        self.replenish_headroom();
        if let Ok(credit) = self.labels.clone().try_acquire_many_owned(bytes) {
            return Some(credit);
        }
        // Borrow reserved permits only for a candidate's mandatory metadata.
        // The same global 128 MiB total still applies across retained generations.
        let mut held = self
            .generation_headroom
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let previous = held.as_ref()?.num_permits();
        let wanted = bytes as usize;
        if previous >= wanted {
            return held.as_mut()?.split(wanted);
        }
        let extra = self
            .labels
            .clone()
            .try_acquire_many_owned((wanted - previous) as u32)
            .ok()?;
        let mut credit = held.take()?;
        credit.merge(extra);
        Some(credit)
    }
    pub fn new() -> Arc<Self> {
        let cpu = std::thread::available_parallelism().map_or(1, usize::from);
        let labels = Arc::new(Semaphore::new(LABEL_BYTES));
        let fixed = labels
            .clone()
            .try_acquire_many_owned(256 << 10)
            .expect("fresh process metrics budget");
        let headroom = labels
            .clone()
            .try_acquire_many_owned(GENERATION_HEADROOM as u32)
            .expect("fresh generation headroom");
        Arc::new(Self {
            connections: Default::default(),
            traces: super::distributed_trace::processor::Process::new(),
            trace_workspace: Arc::new(Semaphore::new(512<<20)),
            trace_output: Arc::new(Semaphore::new(128<<20)),
            trace_cpu: crate::http_runtime::resource_budget::BlockingBudget::new(cpu.clamp(1,4),32,std::time::Duration::from_secs(2)).expect("valid trace CPU lane"),
            discarded_bodies: Arc::new(Semaphore::new(cpu.clamp(1, 4))),
            prom_servers: Default::default(),
            prom_listeners: Arc::new(Semaphore::new(16)),
            prom_connections: Arc::new(Semaphore::new(128)),
            collection: crate::http_runtime::resource_budget::BlockingBudget::new(
                cpu.clamp(1, 4),
                32,
                std::time::Duration::from_secs(2),
            )
            .expect("valid metrics collection limits"),
            scratch: Arc::new(Semaphore::new(512 << 20)),
            output: Arc::new(Semaphore::new(128 << 20)),
            reload_success: AtomicU64::new(0),
            reload_time: AtomicU64::new(0f64.to_bits()),
            admin: Mutex::new(BTreeMap::new()),
            labels,
            request_bytes: Arc::new(Semaphore::new(64 << 20)),
            dropped: AtomicU64::new(0),
            export_errors: AtomicU64::new(0),
            generation_headroom: Mutex::new(Some(headroom)),
            _fixed_credit: fixed,
        })
    }
    pub fn reload(&self, successful: bool) {
        self.reload_success
            .store(u64::from(successful), Ordering::Relaxed);
        if successful {
            let time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0., |d| d.as_secs_f64());
            self.reload_time.store(time.to_bits(), Ordering::Relaxed);
        }
    }
    pub fn admin(&self, path: &'static str, method: &str, status: Option<u16>) {
        // The error vector historically uses upper-case original method names;
        // the ordinary Admin counter uses the bounded standard method map.
        let method = if status.is_some() {
            super::config::method(method).to_owned()
        } else {
            method.to_ascii_uppercase()
        };
        let key = AdminKey {
            path,
            method: Arc::from(method),
            status,
        };
        let mut map = self.admin.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(series) = map.get(&key) {
            series.value.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if map.len() >= super::SERIES_LIMIT {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        // Charge a full BTree leaf/branch upper bound plus key and Arc allocation.
        let Some(bytes) = key
            .method
            .len()
            .checked_mul(16)
            .and_then(|n| n.checked_add(8192))
            .and_then(|n| u32::try_from(n).ok())
        else {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        };
        let Some(credit) = self.pay_labels(bytes) else {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        };
        map.insert(
            key,
            Arc::new(AdminSeries {
                value: AtomicU64::new(1),
                _credit: credit,
            }),
        );
    }
}

pub(crate) struct ReloadAttempt {
    process: Arc<Process>,
    done: bool,
}
impl ReloadAttempt {
    pub fn new(process: Arc<Process>) -> Self {
        Self {
            process,
            done: false,
        }
    }
    pub fn success(&mut self) {
        self.process.reload(true);
        self.done = true;
    }
}
impl Drop for ReloadAttempt {
    fn drop(&mut self) {
        if !self.done {
            self.process.reload(false);
        }
    }
}
