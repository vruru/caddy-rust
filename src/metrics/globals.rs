use super::{
    facts,
    process::{AdminKey, Process},
};
use opentelemetry::{
    KeyValue,
    metrics::{Meter, ObservableCounter, ObservableGauge},
};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, atomic::Ordering},
    time::{Duration, Instant},
};
use tokio::sync::OwnedSemaphorePermit;
struct Admission {
    process: Arc<Process>,
    keys: Mutex<BTreeMap<AdminKey, OwnedSemaphorePermit>>,
}
impl Admission {
    fn allow(&self, key: &AdminKey) -> bool {
        let mut keys = self.keys.lock().unwrap_or_else(|e| e.into_inner());
        if keys.contains_key(key) {
            return true;
        }
        let Some(credit) = self.process.pay_labels(4096) else {
            self.process.dropped.fetch_add(1, Ordering::Relaxed);
            return false;
        };
        keys.insert(key.clone(), credit);
        true
    }
}
struct Facts(Mutex<Option<(Instant, Arc<Vec<(&'static str, f64)>>)>>);
impl Facts {
    fn get(&self) -> Arc<Vec<(&'static str, f64)>> {
        {
            let current = self.0.lock().unwrap_or_else(|e| e.into_inner());
            if let Some((time, values)) = &*current
                && time.elapsed() < Duration::from_millis(10)
            {
                return values.clone();
            }
        }
        // OS reads occur outside the cache lock and only in a blocking collection job.
        let started = Instant::now();
        let values = Arc::new(facts::values());
        let mut current = self.0.lock().unwrap_or_else(|e| e.into_inner());
        // An overlapping older sample must not replace a newer CPU observation.
        if let Some((time, existing)) = &*current
            && *time > started
        {
            return existing.clone();
        }
        *current = Some((started, values.clone()));
        values
    }
}
pub(super) struct Collectors {
    _admin: ObservableCounter<u64>,
    _errors: ObservableCounter<u64>,
    _gauges: Vec<ObservableGauge<f64>>,
    _runtime: RuntimeCollectors,
    _export_errors: ObservableCounter<u64>,
    _admission: Arc<Admission>,
}
pub(super) fn attach(meter: &Meter, process: &Arc<Process>) -> Collectors {
    let admission = Arc::new(Admission {
        process: process.clone(),
        keys: Mutex::new(BTreeMap::new()),
    });
    let counter = |name: &'static str, description: &'static str, error: bool| {
        let weak = Arc::downgrade(process);
        let admit = Arc::downgrade(&admission);
        meter
            .u64_observable_counter(name)
            .with_description(description)
            .with_callback(move |observer| {
                let (Some(process), Some(admit)) = (weak.upgrade(), admit.upgrade()) else {
                    return;
                };
                let values = process
                    .admin
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .iter()
                    .filter(|(key, _)| key.status.is_none() == error)
                    .map(|(key, value)| (key.clone(), value.value.load(Ordering::Relaxed)))
                    .collect::<Vec<_>>();
                for (key, value) in values {
                    if !admit.allow(&key) {
                        continue;
                    }
                    let mut attrs = vec![
                        KeyValue::new("handler", "admin"),
                        KeyValue::new("path", key.path),
                        KeyValue::new("method", key.method.clone()),
                    ];
                    if let Some(status) = key.status {
                        attrs.push(KeyValue::new(
                            "code",
                            Arc::<str>::from(if status == 0 {
                                "200".to_owned()
                            } else {
                                status.to_string()
                            }),
                        ));
                    }
                    observer.observe(value, &attrs);
                }
            })
            .build()
    };
    let admin = counter(
        "caddy_admin_http_requests_total",
        "Counter of requests made to the Admin API's HTTP endpoints.",
        false,
    );
    let errors = counter(
        "caddy_admin_http_request_errors_total",
        "Number of requests resulting in middleware errors.",
        true,
    );
    let mut gauges = Vec::new();
    let weak = Arc::downgrade(process);
    gauges.push(
        meter
            .f64_observable_gauge("caddy_config_last_reload_successful")
            .with_description("Whether the last configuration reload attempt was successful.")
            .with_callback(move |observer| {
                if let Some(process) = weak.upgrade() {
                    observer.observe(process.reload_success.load(Ordering::Relaxed) as f64, &[]);
                }
            })
            .build(),
    );
    let weak = Arc::downgrade(process);
    gauges.push(
        meter
            .f64_observable_gauge("caddy_config_last_reload_success_timestamp_seconds")
            .with_description("Timestamp of the last successful configuration reload.")
            .with_callback(move |observer| {
                if let Some(process) = weak.upgrade() {
                    observer.observe(
                        f64::from_bits(process.reload_time.load(Ordering::Relaxed)),
                        &[],
                    );
                }
            })
            .build(),
    );
    let weak = Arc::downgrade(process);
    let export_errors = meter
        .u64_observable_counter("caddy_metrics_export_errors_total")
        .with_description("Native metrics export attempts that failed.")
        .with_callback(move |observer| {
            if let Some(process) = weak.upgrade() {
                observer.observe(process.export_errors.load(Ordering::Relaxed), &[]);
            }
        })
        .build();
    let runtime = attach_runtime(meter);
    Collectors {
        _admin: admin,
        _errors: errors,
        _gauges: gauges,
        _admission: admission,
        _runtime: runtime,
        _export_errors: export_errors,
    }
}
pub(super) struct RuntimeCollectors {
    _gauges: Vec<ObservableGauge<f64>>,
    _cpu: ObservableCounter<f64>,
    _network: Vec<ObservableCounter<f64>>,
    _build: ObservableGauge<u64>,
    _parallel: ObservableGauge<u64>,
}
pub(super) fn attach_runtime(meter: &Meter) -> RuntimeCollectors {
    let mut gauges = Vec::new();
    let facts = Arc::new(Facts(Mutex::new(None)));
    let network = [
        (
            "process_network_receive_bytes_total",
            "Number of bytes received by the process over the network.",
        ),
        (
            "process_network_transmit_bytes_total",
            "Number of bytes sent by the process over the network.",
        ),
    ]
    .into_iter()
    .map(|(name, description)| {
        let facts = facts.clone();
        meter
            .f64_observable_counter(name)
            .with_description(description)
            .with_callback(move |observer| {
                if let Some((_, value)) = facts.get().iter().find(|(key, _)| *key == name) {
                    observer.observe(*value, &[]);
                }
            })
            .build()
    })
    .collect();
    let cpu_facts = facts.clone();
    let cpu = meter
        .f64_observable_counter("process_cpu_seconds_total")
        .with_description("Total user and system CPU time spent in seconds.")
        .with_callback(move |observer| {
            if let Some((_, value)) = cpu_facts
                .get()
                .iter()
                .find(|(key, _)| *key == "process_cpu_seconds_total")
            {
                observer.observe(*value, &[]);
            }
        })
        .build();
    for (name, help) in [
        (
            "process_resident_memory_bytes",
            "Resident memory size in bytes.",
        ),
        (
            "process_virtual_memory_bytes",
            "Virtual memory size in bytes.",
        ),
        (
            "process_virtual_memory_max_bytes",
            "Maximum amount of virtual memory available in bytes.",
        ),
        (
            "process_start_time_seconds",
            "Start time of the process since unix epoch in seconds.",
        ),
        ("process_open_fds", "Number of open file descriptors."),
        (
            "process_max_fds",
            "Maximum number of open file descriptors.",
        ),
    ] {
        let facts = facts.clone();
        gauges.push(
            meter
                .f64_observable_gauge(name)
                .with_description(help)
                .with_callback(move |observer| {
                    if let Some((_, value)) = facts.get().iter().find(|(key, _)| *key == name) {
                        observer.observe(*value, &[]);
                    }
                })
                .build(),
        );
    }
    let build = meter
        .u64_observable_gauge("caddy_rust_build_info")
        .with_description("Native Rust build information; no Go runtime is embedded.")
        .with_callback(|observer| {
            let mut attrs = vec![
                KeyValue::new("package", env!("CARGO_PKG_NAME")),
                KeyValue::new("version", env!("CARGO_PKG_VERSION")),
            ];
            if let Some(version) = option_env!("CARGO_PKG_RUST_VERSION") {
                attrs.push(KeyValue::new("rust_version_min", version));
            }
            observer.observe(1, &attrs);
        })
        .build();
    let parallel = meter
        .u64_observable_gauge("caddy_runtime_available_parallelism")
        .with_description("Current OS-available parallelism for native execution.")
        .with_callback(|observer| {
            if let Ok(count) = std::thread::available_parallelism() {
                observer.observe(count.get() as u64, &[]);
            }
        })
        .build();
    RuntimeCollectors {
        _gauges: gauges,
        _cpu: cpu,
        _network: network,
        _build: build,
        _parallel: parallel,
    }
}
