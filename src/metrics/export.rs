//! Generation-owned exporters. Preparation creates no collection worker; only
//! committed generations activate one. Exports never hold the request map lock.
use super::Registry;
use anyhow::{Result, ensure};
use opentelemetry_otlp::{MetricExporter, Protocol, WithExportConfig, WithHttpConfig};
use opentelemetry_sdk::metrics::{Temporality, exporter::PushMetricExporter};
use std::{io::Read, sync::Arc, time::Duration};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
#[derive(Clone, Copy, Debug)]
enum Source {
    Context,
    None,
    Process,
}
struct ProcessOnly {
    _provider: opentelemetry_sdk::metrics::SdkMeterProvider,
    reader: super::reader::Reader,
    _instruments: Option<super::globals::RuntimeCollectors>,
}
enum Sink {
    Otlp(
        MetricExporter,
        Arc<std::sync::Mutex<Option<Arc<super::transport::Credit>>>>,
        Arc<super::transport::Transport>,
        TraceActive,
    ),
    Grpc(super::grpc::Grpc),
    Console(Arc<super::console_writer::Writer>),
    Prometheus(Arc<super::prometheus::Server>),
}
pub(super) struct Plan {
    sink: Sink,
    owner: Arc<()>,
    interval: Duration,
    timeout: Duration,
    source: Source,
    process: Option<ProcessOnly>,
    _credit: Arc<super::budget::Metadata>,
}
pub(super) struct Driver {
    cancel: CancellationToken,
    tasks: TaskTracker,
}
impl Drop for Driver {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}
fn env(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.is_empty())
}
fn signal(suffix: &str) -> Option<String> {
    env(&format!("OTEL_EXPORTER_OTLP_METRICS_{suffix}"))
        .or_else(|| env(&format!("OTEL_EXPORTER_OTLP_{suffix}")))
}
fn duration(key: &str, default: Duration) -> Duration {
    env(key)
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| *v > 0)
        .map(Duration::from_millis)
        .unwrap_or(default)
}
fn file(
    name: &str,
    remaining: &mut usize,
    process: &super::Process,
    credit: &super::budget::Metadata,
) -> Result<Option<Vec<u8>>> {
    let Some(path) = signal(name) else {
        return Ok(None);
    };
    let mut file = std::fs::File::open(path)?;
    ensure!(
        file.metadata()?.is_file(),
        "OTLP TLS material must be a regular file"
    );
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 8192];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        ensure!(
            bytes.len() + n <= 1 << 20 && n <= *remaining,
            "OTLP TLS material exceeds 1 MiB per file or 3 MiB total"
        );
        // Stack reads allocate no input container. Pay before every heap growth
        // and before any certificate/key parser can construct retained state.
        credit.pay(process, (n * 32) as u32)?;
        bytes.try_reserve(n)?;
        bytes.extend_from_slice(&buffer[..n]);
        *remaining -= n;
    }
    Ok(Some(bytes))
}
pub(super) fn settings(enabled: bool) -> Result<()> {
    if !enabled || env("OTEL_METRICS_EXPORTER").as_deref() == Some("none") {
        return Ok(());
    }
    let mut bytes = 0usize;
    for key in [
        "OTEL_METRICS_EXPORTER",
        "OTEL_METRICS_PRODUCERS",
        "OTEL_METRIC_EXPORT_INTERVAL",
        "OTEL_METRIC_EXPORT_TIMEOUT",
        "OTEL_EXPORTER_PROMETHEUS_HOST",
        "OTEL_EXPORTER_PROMETHEUS_PORT",
        "HTTP_PROXY",
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
        "NO_PROXY",
        "no_proxy",
    ] {
        bytes = bytes.saturating_add(std::env::var_os(key).map_or(0, |v| v.len()));
    }
    for prefix in ["OTEL_EXPORTER_OTLP_", "OTEL_EXPORTER_OTLP_METRICS_"] {
        for suffix in [
            "ENDPOINT",
            "PROTOCOL",
            "HEADERS",
            "COMPRESSION",
            "TIMEOUT",
            "INSECURE",
            "CERTIFICATE",
            "CLIENT_CERTIFICATE",
            "CLIENT_KEY",
        ] {
            bytes = bytes.saturating_add(
                std::env::var_os(format!("{prefix}{suffix}")).map_or(0, |v| v.len()),
            );
        }
    }
    ensure!(bytes <= 16 << 10, "metrics exporter settings exceed 16 KiB");
    Ok(())
}
impl Plan {
    pub fn prepare(
        enabled: bool,
        process_state: &Arc<super::Process>,
        credit: Arc<super::budget::Metadata>,
        resource: &opentelemetry_sdk::Resource,
    ) -> Result<Option<Arc<Self>>> {
        if !enabled {
            return Ok(None);
        }
        let name = env("OTEL_METRICS_EXPORTER").unwrap_or_else(|| "otlp".into());
        if name == "none" {
            return Ok(None);
        }
        ensure!(
            matches!(name.as_str(), "otlp" | "console" | "prometheus"),
            "unsupported metrics exporter {name}"
        );
        // Start the one concrete retirement thread during preparation, before
        // this generation accepts snapshot data. Failure is a prepare error.
        if name != "prometheus" {
            process_state.metrics_retirement()?;
        }
        let source = match env("OTEL_METRICS_PRODUCERS") {
            None => Source::Context,
            Some(value) => {
                let mut process = false;
                for name in value.split(',') {
                    match name {
                        "prometheus" => process = true,
                        "none" => {}
                        _ => anyhow::bail!("unknown metrics producer"),
                    }
                }
                if process {
                    Source::Process
                } else {
                    Source::None
                }
            }
        };
        let interval = duration("OTEL_METRIC_EXPORT_INTERVAL", Duration::from_secs(60));
        let timeout = duration("OTEL_METRIC_EXPORT_TIMEOUT", Duration::from_secs(30)).min(
            signal("TIMEOUT")
                .and_then(|v| v.parse::<u64>().ok())
                .filter(|v| *v > 0)
                .map(Duration::from_millis)
                .unwrap_or(Duration::from_secs(10)),
        );
        ensure!(
            tokio::time::Instant::now().checked_add(interval).is_some()
                && tokio::time::Instant::now().checked_add(timeout).is_some(),
            "OTLP timeout exceeds platform range"
        );
        let sink = if name == "console" {
            Sink::Console(super::console_writer::Writer::prepare()?)
        } else if name == "prometheus" {
            Sink::Prometheus(process_state.prom_servers.prepare(process_state)?)
        } else {
            let mut material_budget = 3 << 20;
            let ca = file("CERTIFICATE", &mut material_budget, process_state, &credit)?;
            let cert = file(
                "CLIENT_CERTIFICATE",
                &mut material_budget,
                process_state,
                &credit,
            )?;
            let key = file("CLIENT_KEY", &mut material_budget, process_state, &credit)?;
            ensure!(
                cert.is_some() == key.is_some(),
                "OTLP client certificate and key must be configured together"
            );
            let protocol = signal("PROTOCOL").unwrap_or_else(|| "http/protobuf".into());
            // Caddy's Prometheus bridge reports cumulative data independently of
            // OTLP temporality preferences. Preserve the source's real temporality.
            let builder = MetricExporter::builder().with_temporality(Temporality::Cumulative);
            match protocol.as_str() {
                "http/protobuf" => {
                    let endpoint =
                        signal("ENDPOINT").unwrap_or_else(|| "http://localhost:4318".into());
                    let endpoint: http::Uri = endpoint.parse()?;
                    let connector = crate::http_runtime::metrics_client::Connector::prepare(
                        endpoint,
                        ca.as_deref(),
                        cert.as_deref().zip(key.as_deref()),
                        timeout,
                        CancellationToken::new(),
                        credit.clone(),
                        false,
                        process_state,
                    )?;
                    let transport = super::transport::Transport::new(connector, timeout, false);
                    let active = Arc::new(std::sync::Mutex::new(None));
                    let context = Arc::new(std::sync::Mutex::new(None));
                    Sink::Otlp(
                        builder
                            .with_http()
                            .with_protocol(Protocol::HttpBinary)
                            .with_timeout(timeout)
                            .with_http_client(Client {
                                transport: transport.clone(),
                                active: active.clone(),
                                previous: Default::default(),
                                trace_context: Some(context.clone()),
                            })
                            .with_max_request_body_size(32 << 20)
                            .build()?,
                        active,
                        transport,
                        context,
                    )
                }
                "grpc" => {
                    let endpoint =
                        signal("ENDPOINT").unwrap_or_else(|| "http://localhost:4317".into());
                    let endpoint =
                        if endpoint.starts_with("http://") || endpoint.starts_with("https://") {
                            endpoint
                        } else {
                            format!(
                                "{}://{endpoint}",
                                if signal("INSECURE").is_some_and(|v| v == "true") {
                                    "http"
                                } else {
                                    "https"
                                }
                            )
                        };
                    Sink::Grpc(super::grpc::Grpc::prepare(
                        endpoint,
                        signal("HEADERS"),
                        signal("COMPRESSION"),
                        ca.as_deref(),
                        cert.as_deref().zip(key.as_deref()),
                        timeout,
                        credit.clone(),
                        process_state,
                    )?)
                }
                _ => anyhow::bail!("unknown OTLP metrics protocol"),
            }
        };
        let process = if matches!(source, Source::Process | Source::None) {
            use opentelemetry::metrics::MeterProvider;
            let reader = super::reader::Reader::cumulative();
            let provider = opentelemetry_sdk::metrics::SdkMeterProvider::builder()
                .with_reader(reader.clone())
                .with_resource(resource.clone())
                .with_view(|_| {
                    opentelemetry_sdk::metrics::Stream::builder()
                        .with_cardinality_limit(1)
                        .build()
                        .ok()
                })
                .build();
            let instruments = if matches!(source, Source::Process) {
                Some(super::globals::attach_runtime(&provider.meter("caddy")))
            } else {
                None
            };
            Some(ProcessOnly {
                _provider: provider,
                reader,
                _instruments: instruments,
            })
        } else {
            None
        };
        Ok(Some(Arc::new(Self {
            sink,
            owner: Arc::new(()),
            interval,
            timeout,
            source,
            process,
            _credit: credit,
        })))
    }
    async fn once(self: &Arc<Self>, registry: &Arc<Registry>) -> Result<()> {
        use super::export_retirement::{Command, Step};
        let serial = match &self.sink {
            Sink::Console(writer) => Some(writer.admit()?),
            _ => None,
        };
        let retirement = registry.process.metrics_retirement()?;
        let cell = retirement.register()?;
        let mut guard = cell.worker_batch_guard();
        if let Some(driver) = registry.export_driver.get() {
            cell.attach_token(driver.tasks.token())?;
        }
        let scratch = registry
            .process
            .scratch
            .clone()
            .try_acquire_many_owned(256 << 20)
            .map_err(|_| anyhow::anyhow!("OTLP collection busy"))?;
        let timer = registry
            .process
            .request_bytes
            .clone()
            .try_acquire_many_owned(1024)?;
        let created = tokio::time::Instant::now();
        let deadline = created
            .checked_add(self.timeout)
            .ok_or_else(|| anyhow::anyhow!("OTLP deadline overflow"))?;
        let inputs = MetricInputs {
            plan: Arc::downgrade(self),
            registry: Arc::downgrade(registry),
            scratch,
            timer,
            serial,
            created,
        };
        let result = async {
            let mut step = cell
                .execute(&registry.process.collection, Command::Metrics(inputs))
                .await
                .map_err(|_| anyhow::anyhow!("OTLP collection worker unavailable"))?;
            loop {
                match step {
                    Step::Complete(true) => return Ok(()),
                    Step::Complete(false) => return Err(anyhow::anyhow!("OTLP export failed")),
                    Step::Started => {}
                    Step::Pending => {
                        anyhow::ensure!(
                            cell.wait_wake(deadline).await,
                            "OTLP export deadline exceeded"
                        );
                    }
                    Step::Console { .. } => {
                        return Err(anyhow::anyhow!("unexpected metrics export step"));
                    }
                }
                anyhow::ensure!(
                    tokio::time::Instant::now() < deadline,
                    "OTLP export deadline exceeded"
                );
                step = cell
                    .poll_export(&registry.process.collection)
                    .await
                    .map_err(|_| anyhow::anyhow!("OTLP collection worker unavailable"))?;
            }
        }
        .await;
        cell.finish_batch().await;
        guard.disarm();
        result
    }
}
struct Active(Arc<std::sync::Mutex<Option<Arc<super::transport::Credit>>>>);
impl Drop for Active {
    fn drop(&mut self) {
        let credit = self.0.lock().unwrap_or_else(|e| e.into_inner()).take();
        drop(credit);
    }
}
pub(super) fn native_client(
    transport: Arc<super::transport::Transport>,
    active: Arc<std::sync::Mutex<Option<Arc<super::transport::Credit>>>>,
) -> impl opentelemetry_http::HttpClient {
    Client {
        transport,
        active,
        previous: Default::default(),
        trace_context: None,
    }
}
pub(super) type TraceActive =
    Arc<std::sync::Mutex<Option<Arc<super::distributed_trace::export_work::TraceContext>>>>;
pub(super) fn native_trace_client(
    transport: Arc<super::transport::Transport>,
    active: Arc<std::sync::Mutex<Option<Arc<super::transport::Credit>>>>,
    context: TraceActive,
) -> impl opentelemetry_http::HttpClient {
    Client {
        transport,
        active,
        previous: Default::default(),
        trace_context: Some(context),
    }
}
struct Client {
    transport: Arc<super::transport::Transport>,
    active: Arc<std::sync::Mutex<Option<Arc<super::transport::Credit>>>>,
    previous: std::sync::Mutex<std::sync::Weak<()>>,
    trace_context: Option<TraceActive>,
}
impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NativeMetricsHttpClient")
    }
}
#[async_trait::async_trait]
impl opentelemetry_http::HttpClient for Client {
    async fn send_bytes(
        &self,
        request: http::Request<bytes::Bytes>,
    ) -> Result<http::Response<bytes::Bytes>, opentelemetry_http::HttpError> {
        let credit = self
            .active
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .cloned()
            .ok_or_else(|| std::io::Error::other("OTLP export credit unavailable"))?;
        let attempt = Arc::new(());
        {
            let mut previous = self.previous.lock().unwrap_or_else(|e| e.into_inner());
            if previous.strong_count() > 0 {
                // This is native observability admission, not a collector response:
                // do not put another request on the wire behind retained DATA.
                return Ok(http::Response::builder()
                    .status(http::StatusCode::INSUFFICIENT_STORAGE)
                    .body(bytes::Bytes::from_static(
                        b"previous OTLP request DATA remains owned",
                    ))
                    .expect("static pressure response"));
            }
            *previous = Arc::downgrade(&attempt);
        }
        let (mut parts, body) = request.into_parts();
        // Keep the original attempt guard on actual DATA only. A backing pin
        // owns immutable bytes/credit, never this attempt token.
        let trace_context = self
            .trace_context
            .as_ref()
            .and_then(|active| active.lock().unwrap_or_else(|e| e.into_inner()).clone());
        let body = if let Some(context) = trace_context {
            context
                .pin_bytes(
                    super::distributed_trace::export_work::ByteKind::Http,
                    body,
                    credit.memory().map_err(|e| e.into_boxed_dyn_error())?,
                )
                .await
                .map_err(|e| e.into_boxed_dyn_error())?
        } else {
            body
        };
        if let Some(auth) = self.transport.proxy_authorization() {
            parts
                .headers
                .insert(http::header::PROXY_AUTHORIZATION, auth);
        }
        let body = bytes::Bytes::from_owner(super::transport::OwnedBytes {
            data: body,
            _credit: credit.clone(),
            _attempt: Some(attempt),
        });
        let request = http::Request::from_parts(
            parts,
            tonic::body::Body::new(http_body_util::Full::new(body)),
        );
        let response = self.transport.send(request, credit).await?;
        let (parts, body) = response.into_parts();
        ensure_response_length(body.size_hint().exact())?;
        use http_body_util::BodyExt;
        use hyper::body::Body as _;
        let mut body = body;
        let mut bytes = Vec::new();
        while let Some(frame) = body.frame().await {
            if let Ok(chunk) = frame?.into_data() {
                let length = bytes
                    .len()
                    .checked_add(chunk.len())
                    .filter(|n| *n <= 4 << 20)
                    .ok_or_else(|| std::io::Error::other("OTLP response exceeds 4 MiB"))?;
                bytes.try_reserve_exact(length - bytes.len())?;
                bytes.extend_from_slice(&chunk);
            }
        }
        let status = parts.status;
        let headers = parts.headers;
        let mut result = http::Response::new(bytes::Bytes::from(bytes));
        *result.status_mut() = status;
        *result.headers_mut() = headers;
        Ok(result)
    }
}

fn ensure_response_length(length: Option<u64>) -> std::io::Result<()> {
    if length.is_some_and(|n| n > 4 << 20) {
        Err(std::io::Error::other("OTLP response exceeds 4 MiB"))
    } else {
        Ok(())
    }
}
impl Registry {
    pub fn activate(self: &Arc<Self>) {
        let Some(plan) = self.export_plan.as_ref().cloned() else {
            return;
        };
        if let Sink::Prometheus(server) = &plan.sink {
            server.activate(&plan.owner, self);
            return;
        }
        self.export_driver.get_or_init(|| {
            let cancel = CancellationToken::new();
            let tasks = TaskTracker::new();
            let token = cancel.clone();
            let weak = Arc::downgrade(self);
            tasks.spawn(async move {
                let mut interval = tokio::time::interval(plan.interval);
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                interval.tick().await;
                loop {
                    let stopping =
                        tokio::select! {biased;_=token.cancelled()=>true,_=interval.tick()=>false};
                    let Some(registry) = weak.upgrade() else {
                        break;
                    };
                    if let Err(_error) = plan.once(&registry).await {
                        registry
                            .process
                            .export_errors
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    if stopping {
                        match &plan.sink {
                            Sink::Otlp(exporter, _, transport, _) => {
                                let _ = exporter.force_flush();
                                let _ = exporter.shutdown();
                                transport.shutdown().await;
                            }
                            Sink::Grpc(exporter) => exporter.shutdown().await,
                            Sink::Console(writer) => writer.shutdown().await,
                            _ => {}
                        }
                        break;
                    }
                }
            });
            Driver { cancel, tasks }
        });
    }
    pub(crate) async fn stop_exporter(&self) {
        if let Some(plan) = &self.export_plan
            && let Sink::Prometheus(server) = &plan.sink
        {
            server.retire(&plan.owner).await;
        }
        if let Some(driver) = self.export_driver.get() {
            driver.cancel.cancel();
            if let Some(plan) = &self.export_plan
                && let Sink::Console(writer) = &plan.sink
            {
                writer.cancel_active();
            }
            driver.tasks.close();
            driver.tasks.wait().await;
        }
    }
}

pub(super) fn resource() -> opentelemetry_sdk::Resource {
    let builder = opentelemetry_sdk::Resource::builder().with_attributes([
        opentelemetry::KeyValue::new("webengine.name", "Caddy"),
        opentelemetry::KeyValue::new("webengine.version", env!("CARGO_PKG_VERSION")),
    ]);
    // OTEL_SERVICE_NAME takes precedence over service.name in resource attrs,
    // as the OTEL contract and the original Caddy Go SDK require.
    if let Some(name) = env("OTEL_SERVICE_NAME") {
        builder.with_service_name(name).build()
    } else {
        builder.build()
    }
}
impl Registry {
    pub(super) fn automatic_snapshot(
        &self,
    ) -> Result<Option<opentelemetry_sdk::metrics::data::ResourceMetrics>> {
        let Some(plan) = &self.export_plan else {
            return Ok(None);
        };
        match plan.source {
            Source::Context => Ok(Some(self.snapshot()?)),
            Source::Process => Ok(Some(
                plan.process
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("process metrics source missing"))?
                    .reader
                    .snapshot()?,
            )),
            Source::None => Ok(None),
        }
    }
}

/// Closed input contains only small handles and pre-existing permits.
pub(in crate::metrics) struct MetricInputs {
    plan: std::sync::Weak<Plan>,
    registry: std::sync::Weak<Registry>,
    scratch: tokio::sync::OwnedSemaphorePermit,
    timer: tokio::sync::OwnedSemaphorePermit,
    serial: Option<tokio::sync::OwnedSemaphorePermit>,
    created: tokio::time::Instant,
}
pub(in crate::metrics) fn apply_command(
    data: &mut super::export_retirement::resident::MetricResident,
    reference: &super::export_retirement::CellRef,
    cpu: &crate::http_runtime::resource_budget::BlockingBudget,
    inputs: MetricInputs,
) -> std::result::Result<super::export_retirement::Step, super::export_retirement::WorkError> {
    use super::export_retirement::{ByteKind, PinInput, Step, WorkError};
    let shared = reference.shared.upgrade().ok_or(WorkError::Stopped)?;
    let plan = inputs.plan.upgrade().ok_or(WorkError::Stopped)?;
    let registry = inputs.registry.upgrade().ok_or(WorkError::Stopped)?;
    let snapshot = if let Some(process) = &plan.process {
        process.reader.snapshot().map_err(anyhow::Error::from)
    } else {
        registry.snapshot()
    }
    .map_err(|_| WorkError::Worker)?;
    let output = registry.process.output.clone();
    // A temporary last Registry/Process owner is dropped here on this real CPU
    // thread, after snapshot's collection lock has been released; never in State.
    drop(registry);
    let credit = Arc::new(
        super::transport::Credit::metrics_owned(
            inputs.scratch,
            plan._credit.clone(),
            inputs.timer,
            &shared.source,
            inputs.created,
            reference.shared.clone(),
        )
        .map_err(|_| WorkError::Workspace)?,
    );
    data.memory = Some(credit.memory().map_err(|_| WorkError::Workspace)?);
    let context = reference.context().map_err(|_| WorkError::Busy)?;
    let cpu = cpu.clone();
    let future = async move {
        match &plan.sink {
            Sink::Otlp(exporter, active, _, slot) => {
                let previous_context = slot
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .replace(context);
                let previous_credit = active
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .replace(credit);
                drop(previous_context);
                drop(previous_credit);
                let _active = Active(active.clone());
                let _context = ContextActive(slot.clone());
                tokio::time::timeout(plan.timeout, exporter.export(&snapshot)).await??;
            }
            Sink::Grpc(exporter) => {
                tokio::time::timeout(
                    plan.timeout,
                    exporter.export_with_context(&snapshot, credit, context, cpu),
                )
                .await??;
            }
            Sink::Console(writer) => {
                let output = output.try_acquire_many_owned(64 << 20)?;
                let bytes = super::encode::console(&snapshot)?;
                let input = PinInput {
                    data: bytes.into(),
                    output: Some(output),
                    memory: credit.memory()?,
                };
                let bytes = context.pin_input(ByteKind::Console, input).await?;
                writer
                    .send(
                        super::console_writer::Batch {
                            bytes,
                            output: None,
                            credit,
                            serial: inputs
                                .serial
                                .ok_or_else(|| anyhow::anyhow!("console admission missing"))?,
                        },
                        plan.timeout,
                    )
                    .await?;
            }
            Sink::Prometheus(_) => {}
        }
        Ok(())
    };
    let layout = std::mem::size_of_val(&future)
        .checked_add(6 * std::mem::size_of::<usize>())
        .ok_or(WorkError::Busy)?;
    data.future_credit = Some(shared.source.reserve(layout).map_err(|_| WorkError::Busy)?);
    data.future = Some(Box::pin(future));
    Ok(Step::Started)
}
struct ContextActive(TraceActive);
impl Drop for ContextActive {
    fn drop(&mut self) {
        let old = self.0.lock().unwrap_or_else(|e| e.into_inner()).take();
        drop(old);
    }
}
