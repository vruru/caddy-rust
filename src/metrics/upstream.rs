use super::process::Process;
use opentelemetry::{
    KeyValue,
    metrics::{Meter, ObservableGauge},
};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, atomic::Ordering},
};
use tokio::sync::OwnedSemaphorePermit;
pub(crate) type Probe = Arc<dyn Fn() -> bool + Send + Sync>;
struct Entry {
    probe: Probe,
    attrs: [KeyValue; 1],
    _credit: OwnedSemaphorePermit,
}
#[derive(Default)]
pub(super) struct Upstreams(Mutex<BTreeMap<Arc<str>, Arc<Entry>>>);
impl Upstreams {
    pub fn attach(self: &Arc<Self>, meter: &Meter) -> ObservableGauge<u64> {
        let weak = Arc::downgrade(self);
        meter
            .u64_observable_gauge("caddy_reverse_proxy_upstreams_healthy")
            .with_description("Health status of reverse proxy upstreams.")
            .with_callback(move |observer| {
                let Some(values) = weak.upgrade() else {
                    return;
                };
                let values = values
                    .0
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .values()
                    .cloned()
                    .collect::<Vec<_>>();
                for entry in values {
                    observer.observe(u64::from((entry.probe)()), &entry.attrs);
                }
            })
            .build()
    }
    pub fn insert(&self, process: &Process, address: Arc<str>, probe: Probe) {
        let Some(bytes) = address
            .len()
            .checked_mul(16)
            .and_then(|n| n.checked_add(8192))
            .and_then(|n| u32::try_from(n).ok())
        else {
            process.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        };
        let mut entries = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if entries.len() >= super::SERIES_LIMIT && !entries.contains_key(&address) {
            process.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let credit = match process.pay_labels(bytes) {
            Some(credit) => credit,
            None => {
                process.dropped.fetch_add(1, Ordering::Relaxed);
                return;
            }
        };
        entries.insert(
            address.clone(),
            Arc::new(Entry {
                probe,
                attrs: [KeyValue::new("upstream", address)],
                _credit: credit,
            }),
        );
    }
}
