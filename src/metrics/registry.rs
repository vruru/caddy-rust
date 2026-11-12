use super::{budget::Lease, config::Config, process::Process, reader::Reader};
use opentelemetry::{
    KeyValue,
    metrics::{
        BoundCounter, BoundHistogram, Counter, Histogram, MeterProvider, ObservableCounter,
        ObservableGauge,
    },
};
use opentelemetry_sdk::metrics::{SdkMeterProvider, Stream};
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicI64, Ordering},
    },
};
use tokio::sync::OwnedSemaphorePermit;
pub(super) const DURATIONS: &[f64] = &[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1., 2.5, 5., 10.];
pub(super) const SIZES: &[f64] = &[
    256., 1024., 4096., 16384., 65536., 262144., 1048576., 4194304.,
];
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
pub(super) struct BaseKey {
    pub server: Arc<str>,
    pub handler: Arc<str>,
    pub host: Option<Arc<str>>,
}
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
struct StatusKey {
    base: BaseKey,
    method: &'static str,
    code: u16,
}
pub(super) struct Base {
    pub key: BaseKey,
    pub attrs: Arc<[KeyValue]>,
    pub in_flight: AtomicI64,
    count: OnceLock<BoundCounter<u64>>,
    errors: OnceLock<BoundCounter<u64>>,
    _credit: OwnedSemaphorePermit,
}
pub(super) struct Status {
    attrs: Arc<[KeyValue]>,
    hist: [OnceLock<BoundHistogram<f64>>; 4],
    _credit: OwnedSemaphorePermit,
}
struct Instruments {
    count: Counter<u64>,
    errors: Counter<u64>,
    hist: [Histogram<f64>; 4],
    _inflight: ObservableGauge<i64>,
    _dropped: ObservableCounter<u64>,
    _globals: super::globals::Collectors,
    _upstreams: ObservableGauge<u64>,
}
type Bases = Mutex<BTreeMap<BaseKey, Arc<Base>>>;
/// The provider/factories drop before admitted series and their credits. A
/// generation never borrows the process-global OpenTelemetry meter provider.
pub struct Registry {
    pub(super) export_plan: Option<Arc<super::export::Plan>>,
    pub(super) export_driver: OnceLock<super::export::Driver>,
    provider: SdkMeterProvider,
    pub(super) resource: opentelemetry_sdk::Resource,
    pub(super) automatic_errors: [std::sync::atomic::AtomicU64; 2],
    pub(super) scrape_stats: Arc<super::scrape::Stats>,
    collection: Mutex<()>,
    instruments: Instruments,
    pub(super) reader: Reader,
    pub(super) process: Arc<Process>,
    pub(super) config: Option<Config>,
    allowed: super::allowed::Allowed,
    has_https: bool,
    upstreams: Arc<super::upstream::Upstreams>,
    statuses: Mutex<BTreeMap<StatusKey, Arc<Status>>>,
    bases: Arc<Bases>,
    _fixed_credit: Arc<super::budget::Metadata>,
}
impl Registry {
    /// A control-plane registry for embedding without an HTTP application.
    pub fn admin_only(process: Arc<Process>) -> anyhow::Result<Arc<Self>> {
        Self::prepare(process, None, Default::default(), false)
    }
    pub fn diagnostics(&self) -> super::Diagnostics {
        self.process.diagnostics()
    }

    pub(crate) fn upstreams(
        &self,
        probes: impl IntoIterator<Item = (Arc<str>, super::upstream::Probe)>,
    ) {
        for (address, probe) in probes {
            self.upstreams.insert(&self.process, address, probe);
        }
    }

    pub(crate) fn admin(&self, path: &'static str, method: &str, status: Option<u16>) {
        self.process.admin(path, method, status);
    }

    /// The unpublished initial runtime must not parse exporter environment or
    /// panic before fallible candidate preparation has an opportunity to run.
    pub(crate) fn initial(process: Arc<Process>) -> Arc<Self> {
        let credit = Arc::new(super::budget::Metadata::new(
            process
                .pay_generation(4 << 20)
                .expect("fresh initial metrics budget"),
        ));
        Self::assemble(
            process,
            None,
            Default::default(),
            false,
            None,
            credit,
            opentelemetry_sdk::Resource::builder_empty().build(),
        )
    }
    pub(crate) fn prepare(
        process: Arc<Process>,
        config: Option<Config>,
        allowed: super::allowed::Allowed,
        has_https: bool,
    ) -> anyhow::Result<Arc<Self>> {
        let mut mandatory = process
            .pay_generation(4 << 20)
            .ok_or_else(|| anyhow::anyhow!("metrics generation metadata unavailable"))?;
        let environment = std::env::var("OTEL_RESOURCE_ATTRIBUTES")
            .map_or(0, |s| s.len())
            .saturating_add(std::env::var("OTEL_SERVICE_NAME").map_or(0, |s| s.len()));
        anyhow::ensure!(
            environment <= 128 << 10,
            "metrics resource attributes exceed 128 KiB"
        );
        super::export::settings(config.is_some_and(|c| c.otlp))?;
        let extra = environment * 32;
        if extra > 0 {
            mandatory.merge(
                process
                    .pay_generation(extra as u32)
                    .ok_or_else(|| anyhow::anyhow!("metrics generation metadata unavailable"))?,
            );
        }
        let credit = Arc::new(super::budget::Metadata::new(mandatory));
        let resource = super::export::resource();
        let plan = super::export::Plan::prepare(
            config.is_some_and(|c| c.otlp),
            &process,
            credit.clone(),
            &resource,
        )?;
        Ok(Self::assemble(
            process, config, allowed, has_https, plan, credit, resource,
        ))
    }
    fn assemble(
        process: Arc<Process>,
        config: Option<Config>,
        allowed: super::allowed::Allowed,
        has_https: bool,
        plan: Option<Arc<super::export::Plan>>,
        credit: Arc<super::budget::Metadata>,
        resource: opentelemetry_sdk::Resource,
    ) -> Arc<Self> {
        let reader = Reader::cumulative();
        let bases = Arc::new(Mutex::new(BTreeMap::<BaseKey, Arc<Base>>::new()));
        let provider = SdkMeterProvider::builder()
            .with_resource(resource.clone())
            .with_reader(reader.clone())
            .with_view(|instrument| {
                let name = instrument.name();
                let limit = if name.starts_with("caddy_http_")
                    || name.starts_with("caddy_admin_")
                    || name == "caddy_reverse_proxy_upstreams_healthy"
                {
                    super::SERIES_LIMIT
                } else if name == "promhttp_metric_handler_requests_total" {
                    3
                } else {
                    1
                };
                Stream::builder().with_cardinality_limit(limit).build().ok()
            })
            .build();
        let meter = provider.meter("caddy");
        let globals = super::globals::attach(&meter, &process);
        let upstreams = Arc::new(super::upstream::Upstreams::default());
        let upstream_gauge = upstreams.attach(&meter);
        let scrape_stats = super::scrape::Stats::attach(&meter);
        let weak = Arc::downgrade(&bases);
        let inflight = meter
            .i64_observable_gauge("caddy_http_requests_in_flight")
            .with_description("Number of requests currently handled by this server.")
            .with_callback(move |observer| {
                if let Some(bases) = weak.upgrade() {
                    let values = bases
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .values()
                        .cloned()
                        .collect::<Vec<_>>();
                    for base in values {
                        observer.observe(base.in_flight.load(Ordering::Relaxed), &base.attrs);
                    }
                }
            })
            .build();
        let weak = Arc::downgrade(&process);
        let dropped = meter
            .u64_observable_counter("caddy_metrics_observations_dropped_total")
            .with_description(
                "Metrics observations omitted by native admission or incomplete response bodies.",
            )
            .with_callback(move |observer| {
                if let Some(process) = weak.upgrade() {
                    observer.observe(process.dropped.load(Ordering::Relaxed), &[]);
                }
            })
            .build();
        let count = meter
            .u64_counter("caddy_http_requests_total")
            .with_description("Counter of HTTP(S) requests made.")
            .build();
        let errors = meter
            .u64_counter("caddy_http_request_errors_total")
            .with_description("Number of requests resulting in middleware errors.")
            .build();
        let hist = [
            meter
                .f64_histogram("caddy_http_request_duration_seconds")
                .with_description("Histogram of round-trip request durations.")
                .with_boundaries(DURATIONS.to_vec())
                .build(),
            meter
                .f64_histogram("caddy_http_request_size_bytes")
                .with_description("Total size of the request. Includes body")
                .with_boundaries(SIZES.to_vec())
                .build(),
            meter
                .f64_histogram("caddy_http_response_size_bytes")
                .with_description("Size of the returned response.")
                .with_boundaries(SIZES.to_vec())
                .build(),
            meter
                .f64_histogram("caddy_http_response_duration_seconds")
                .with_description("Histogram of times to first byte in response bodies.")
                .with_boundaries(DURATIONS.to_vec())
                .build(),
        ];
        Arc::new(Self {
            provider,
            resource,
            automatic_errors: Default::default(),
            export_plan: plan,
            export_driver: OnceLock::new(),
            scrape_stats,
            collection: Mutex::new(()),
            instruments: Instruments {
                count,
                errors,
                hist,
                _inflight: inflight,
                _dropped: dropped,
                _globals: globals,
                _upstreams: upstream_gauge,
            },
            reader,
            process,
            config,
            allowed,
            has_https,
            upstreams,
            statuses: Mutex::new(BTreeMap::new()),
            bases,
            _fixed_credit: credit,
        })
    }
    pub(super) fn key(
        &self,
        server: Arc<str>,
        handler: Arc<str>,
        host: &str,
        tls: bool,
    ) -> BaseKey {
        let host = self.config.filter(|c| c.per_host).map(|config| {
            let lower: String = host
                .chars()
                .map(|ch| ch.to_lowercase().next().unwrap_or(ch))
                .collect();
            if config.observe_catchall_hosts
                || tls && self.has_https
                || self.allowed.contains(&lower)
            {
                Arc::from(lower)
            } else {
                Arc::from("_other")
            }
        });
        BaseKey {
            server,
            handler,
            host,
        }
    }
    pub(super) fn enabled(&self) -> bool {
        self.config.is_some()
    }
    fn pay(&self, constant: usize, payload: usize, factor: usize) -> Option<OwnedSemaphorePermit> {
        let bytes = payload.checked_mul(factor)?.checked_add(constant)?;
        self.process.pay_labels(u32::try_from(bytes).ok()?)
    }
    pub(super) fn base(&self, key: BaseKey) -> Option<Arc<Base>> {
        if let Some(base) = self
            .bases
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&key)
            .cloned()
        {
            return Some(base);
        }
        let payload =
            key.server.len() + key.handler.len() + key.host.as_ref().map_or(0, |s| s.len());
        let Some(credit) = self.pay(8192, payload, 8) else {
            let result = self
                .bases
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(&key)
                .cloned();
            if result.is_none() {
                self.process.dropped.fetch_add(1, Ordering::Relaxed);
            }
            return result;
        };
        let mut attrs = vec![
            KeyValue::new("server", key.server.clone()),
            KeyValue::new("handler", key.handler.clone()),
        ];
        if let Some(host) = &key.host {
            attrs.push(KeyValue::new("host", host.clone()));
        }
        let candidate = Arc::new(Base {
            key: key.clone(),
            attrs: attrs.into(),
            in_flight: AtomicI64::new(0),
            count: OnceLock::new(),
            errors: OnceLock::new(),
            _credit: credit,
        });
        let mut entries = self.bases.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(existing) = entries.get(&key) {
            return Some(existing.clone());
        }
        if entries.len() >= super::SERIES_LIMIT {
            self.process.dropped.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        entries.insert(key, candidate.clone());
        Some(candidate)
    }
    fn status(&self, base: &Base, method: &'static str, code: u16) -> Option<Arc<Status>> {
        let key = StatusKey {
            base: base.key.clone(),
            method,
            code,
        };
        if let Some(status) = self
            .statuses
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&key)
            .cloned()
        {
            return Some(status);
        }
        let payload = key.base.server.len()
            + key.base.handler.len()
            + key.base.host.as_ref().map_or(0, |s| s.len())
            + method.len()
            + 3;
        let Some(credit) = self.pay(16384, payload, 128) else {
            let result = self
                .statuses
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(&key)
                .cloned();
            if result.is_none() {
                self.process.dropped.fetch_add(1, Ordering::Relaxed);
            }
            return result;
        };
        let mut attrs = base.attrs.to_vec();
        attrs.extend([
            KeyValue::new("method", method),
            KeyValue::new(
                "code",
                Arc::<str>::from(if code == 0 {
                    "200".to_owned()
                } else {
                    code.to_string()
                }),
            ),
        ]);
        let candidate = Arc::new(Status {
            attrs: attrs.into(),
            hist: std::array::from_fn(|_| OnceLock::new()),
            _credit: credit,
        });
        let mut entries = self.statuses.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(existing) = entries.get(&key) {
            return Some(existing.clone());
        }
        if entries.len() >= super::SERIES_LIMIT {
            self.process.dropped.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        entries.insert(key, candidate.clone());
        Some(candidate)
    }
    pub(super) fn histogram(
        &self,
        base: &Base,
        method: &'static str,
        code: u16,
        kind: usize,
        value: f64,
    ) {
        if let Some(status) = self.status(base, method, code) {
            status.hist[kind]
                .get_or_init(|| self.instruments.hist[kind].bind(&status.attrs))
                .record(value);
        }
    }
    pub(super) fn finish(
        &self,
        base: &Base,
        method: &'static str,
        code: Option<u16>,
        duration: f64,
        request: u64,
        response: u64,
        error: bool,
    ) {
        base.count
            .get_or_init(|| self.instruments.count.bind(&base.attrs))
            .add(1);
        if error {
            base.errors
                .get_or_init(|| self.instruments.errors.bind(&base.attrs))
                .add(1);
        }
        if let Some(code) = code {
            self.histogram(base, method, code, 0, duration);
            self.histogram(base, method, code, 1, request as f64);
            self.histogram(base, method, code, 2, response as f64);
        }
        base.in_flight.fetch_sub(1, Ordering::Relaxed);
    }
    pub fn snapshot(&self) -> anyhow::Result<opentelemetry_sdk::metrics::data::ResourceMetrics> {
        let _collection = self.collection.lock().unwrap_or_else(|e| e.into_inner());
        Ok(self.reader.snapshot()?)
    }
    pub fn shutdown(&self) -> anyhow::Result<()> {
        self.provider.shutdown()?;
        Ok(())
    }
    pub(super) fn request_lease(&self) -> Option<Lease> {
        let result = Lease::new(self.process.request_bytes.clone(), 256);
        if result.is_none() {
            self.process.dropped.fetch_add(1, Ordering::Relaxed);
        }
        result
    }
}
