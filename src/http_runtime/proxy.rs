use super::proxy_policy::{HostRegistry, PreparedSelection, SelectionInput};
use super::request::{Context, apply_headers, apply_response_headers};
use super::upstream_tls::{FixedDialConnector, PreparedTransport};
use super::*;
use http::{HeaderMap, HeaderName, HeaderValue, Uri, Version};
use http_body_util::BodyStream;
use hyper_util::client::legacy::Client;
use rustls::pki_types::ServerName;
use std::{
    collections::VecDeque,
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::sync::Notify;
type HyperClient = Client<FixedDialConnector, Body>;
#[derive(Clone)]
pub(super) struct ProxyClient {
    selection: Arc<PreparedSelection>,
    connector: PreparedTransport,
    http1_connector: PreparedTransport,
    http2_only: bool,
    cache: Arc<std::sync::Mutex<ClientCache>>,
    pub(super) config: Arc<ProxyConfig>,
    dynamic: Option<Arc<super::proxy_dynamic::DynamicUpstreams>>,
    pub(super) passive: Option<Arc<super::proxy_hosts::PassiveOwner>>,
}
struct ClientCache {
    clock: u64,
    clients: HashMap<String, (HyperClient, u64)>,
}
impl ProxyClient {
    pub(super) fn metric_probes(&self)->Vec<(Arc<str>,crate::metrics::upstream::Probe)>{self.selection.metric_probes()}

    pub(super) fn client_for(
        &self,
        dial: &str,
        family: super::http_dial::Family,
        force_http1: bool,
        server_name: Option<ServerName<'static>>,
        unix_path:Option<&str>,
    ) -> Result<HyperClient> {
        let cache_key = format!("{family:?}|{dial}|{force_http1}|{server_name:?}|{unix_path:?}");
        let mut cache = self
            .cache
            .lock()
            .map_err(|_| anyhow::anyhow!("upstream client cache unavailable"))?;
        cache.clock = cache.clock.wrapping_add(1);
        let clock = cache.clock;
        if let Some((client, last)) = cache.clients.get_mut(&cache_key) {
            *last = clock;
            return Ok(client.clone());
        }
        drop(cache);
        let uri = dial.parse::<Uri>()?;
        let mut builder = Client::builder(TokioExecutor::new());
        // Go's transfer reader requires the whole HTTP/1 trailer block to fit
        // the default 4096-byte bufio reader. Do not cap ordinary headers here.
        builder.http1_max_trailer_size(4096);
        builder.http1_allow_obsolete_multiline_trailers(true);
        builder.http2_only(self.http2_only && !force_http1);
        // Pinned Caddy HTTPTransport defaults, not Hyper's unbounded idle pool.
        builder.pool_max_idle_per_host(32);
        builder.pool_idle_timeout(Duration::from_secs(120));
        builder.pool_timer(TokioTimer::new());
        let transport = if force_http1 {
            &self.http1_connector
        } else {
            &self.connector
        };
        let client = builder.build(transport.connector(uri, family, server_name,unix_path));
        // Building a pool must not hold the shared cache lock. Another request
        // may have populated the same key meanwhile; keep that existing pool.
        let mut cache = self
            .cache
            .lock()
            .map_err(|_| anyhow::anyhow!("upstream client cache unavailable"))?;
        cache.clock = cache.clock.wrapping_add(1);
        let clock = cache.clock;
        if let Some((existing, last)) = cache.clients.get_mut(&cache_key) {
            *last = clock;
            return Ok(existing.clone());
        }
        let evicted = if cache.clients.len() >= 1024 {
            let oldest = cache
                .clients
                .iter()
                .min_by_key(|(_, (_, last))| *last)
                .map(|(key, _)| key.clone());
            oldest.and_then(|key| cache.clients.remove(&key))
        } else {
            None
        };
        cache.clients.insert(cache_key, (client.clone(), clock));
        drop(cache);
        drop(evicted);
        Ok(client)
    }
}
pub(super) fn prepare_clients(
    routes: &[Route],
    output: &mut HashMap<usize, ProxyClient>,
    hosts: &HostRegistry,
    dns: &Arc<super::proxy_dynamic::DnsShared>,
    logging_available: bool,
) -> Result<()> {
    crate::http_config::helpers::initialize_globals();
    for route in routes {
        for handler in &route.handlers {
            match handler {
                Handler::Subroute { routes, errors, .. } => {
                    prepare_clients(routes, output, hosts, dns, logging_available)?;
                    prepare_clients(errors, output, hosts, dns, logging_available)?;
                }
                Handler::Intercept(response) => {
                    prepare_response_clients(response, output, hosts, dns, logging_available)?;
                }
                Handler::FileServer { .. } => {
                    super::mime::initialize();
                }
                Handler::ReverseProxy(config) => {
                    let owned_config = config.clone();
                    let config = config.as_ref();
                    prepare_response_clients(
                        &config.response_routes,
                        output,
                        hosts,
                        dns,
                        logging_available,
                    )?;
                    if let Some(fastcgi) = &config.fastcgi {
                        ensure!(
                            !fastcgi.capture_stderr || logging_available,
                            "FastCGI capture_stderr requires generation logging"
                        );
                    }
                    let connector = PreparedTransport::prepare(config)?;
                    let http1_connector = connector.http1();
                    output.insert(
                        config as *const ProxyConfig as usize,
                        ProxyClient {
                            selection: Arc::new(PreparedSelection::new_health(
                                hosts,
                                &config.selection,
                                &config.upstreams,
                                config.ext.health.passive.clone(),
                            )),
                            passive: config.ext.health.passive.as_ref().map(|cfg| {
                                super::proxy_hosts::PassiveOwner::new(Duration::from_nanos(
                                    cfg.fail_duration.max(0) as u64,
                                ))
                            }),
                            config: owned_config.into(),
                            dynamic: config
                                .ext
                                .dynamic
                                .as_ref()
                                .map(|cfg| {
                                    super::proxy_dynamic::DynamicUpstreams::new(cfg, dns)
                                        .map(Arc::new)
                                })
                                .transpose()?,
                            connector,
                            http1_connector,
                            http2_only: config.http2_only,
                            cache: Arc::new(std::sync::Mutex::new(ClientCache {
                                clock: 0,
                                clients: HashMap::new(),
                            })),
                        },
                    );
                }
                _ => {}
            }
        }
    }
    Ok(())
}
fn prepare_response_clients(
    entries: &[crate::http_config::types::ResponseRoute],
    output: &mut HashMap<usize, ProxyClient>,
    hosts: &HostRegistry,
    dns: &Arc<super::proxy_dynamic::DnsShared>,
    logging_available: bool,
) -> Result<()> {
    for entry in entries {
        if let Some(routes) = &entry.routes {
            prepare_clients(routes, output, hosts, dns, logging_available)?;
        }
    }
    Ok(())
}

pub(super) struct PreparedResponse {
    pub(super) response: Response<Body>,
    pub(super) status_text: String,
    headers: Arc<crate::http_config::types::HeaderOps>,
    protocol: Option<Version>,
    sniff: bool,
    flush_interval: i64,
    force_immediate: bool,
    upgrade: Option<Upgrade>,
    lease: Option<Arc<super::proxy_policy::RequestLease>>,
}

struct Upgrade {
    upstream: hyper::upgrade::OnUpgrade,
    downstream: Option<hyper::upgrade::OnUpgrade>,
    expected: Option<HeaderValue>,
    client: HyperClient,
    close_delay: Option<Duration>,
}

impl PreparedResponse {
    pub(super) fn fastcgi(
        response: Response<Body>,
        headers: Arc<crate::http_config::types::HeaderOps>,
        sniff: bool,
        flush_interval: i64,
    ) -> Self {
        let status_text = response
            .headers()
            .get("status")
            .and_then(|value| value.to_str().ok())
            .and_then(|text| text.split_once(' ').map(|(_, phrase)| phrase))
            .unwrap_or_default()
            .to_owned();
        let force_immediate = super::incremental::is_enabled(response.headers());
        Self {
            response,
            status_text,
            headers,
            protocol: None,
            sniff,
            flush_interval,
            force_immediate,
            upgrade: None,
            lease: None,
        }
    }

    pub(super) async fn finish(
        mut self,
        ctx: &mut Context,
        inner: &Arc<Inner>,
    ) -> Result<Response<Body>> {
        let upgrade = self.response.status() == StatusCode::SWITCHING_PROTOCOLS;
        if upgrade {
            let setup = self
                .upgrade
                .take()
                .ok_or_else(|| anyhow::anyhow!("unsolicited upstream upgrade"))?;
            ensure!(
                header_has_token(self.response.headers(), http::header::CONNECTION, "upgrade"),
                "upstream upgrade connection token missing"
            );
            ensure!(
                self.response
                    .headers()
                    .get(http::header::UPGRADE)
                    .zip(setup.expected.as_ref())
                    .is_some_and(|(received, expected)| received
                        .as_bytes()
                        .eq_ignore_ascii_case(expected.as_bytes())),
                "upstream upgrade protocol mismatch"
            );
            let downstream = setup
                .downstream
                .ok_or_else(|| anyhow::anyhow!("missing downstream upgrade"))?;
            let drain = ctx.drain.clone();
            let business = ctx.business.clone();
            let metrics=ctx.metrics.as_ref().map(|group|(group.clone(),group.retain_tunnel()));
            let hard_stop = business.generation().hard_stop.clone();
            let admission = self.lease.take().expect("HTTP upgrade lease");
            inner.upgrades.spawn(async move {
                let _admission = admission;
                let _hold_client = setup.client;
                let _business = business;
                let _metrics=metrics;
                let tunnel = async {
                    if let (Ok(downstream), Ok(upstream)) = tokio::join!(downstream, setup.upstream)
                    {
                        let mut downstream = TokioIo::new(downstream);
                        let mut upstream = TokioIo::new(upstream);
                        let copy = tokio::io::copy_bidirectional(&mut downstream, &mut upstream);
                        tokio::pin!(copy);
                        if let Some(delay) = setup.close_delay {
                            tokio::select! { _ = &mut copy => {}, _ = drain.cancelled() => {
                                let _ = tokio::time::timeout(delay, copy).await;
                            } }
                        } else {
                            let _ = copy.await;
                        }
                    }
                };
                tokio::select! { biased; _ = hard_stop.cancelled() => {}, _ = tunnel => {} }
            });
        }

        let content_type = self
            .response
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        let event_stream = content_type
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .eq_ignore_ascii_case("text/event-stream");
        let can_flush = self.flush_interval > 0
            && !upgrade
            && !event_stream
            && !self.force_immediate
            && !super::incremental::is_enabled(self.response.headers())
            && self
                .response
                .headers()
                .get(http::header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok())
                .is_some_and(|n| n > 0)
            && ctx.req().method() != http::Method::HEAD
            && !matches!(
                self.response.status(),
                StatusCode::NO_CONTENT | StatusCode::NOT_MODIFIED
            );
        if can_flush && let Ok(credit) = ctx.resources.proxy_flush.clone().try_acquire_owned() {
            let body = std::mem::replace(self.response.body_mut(), full(Bytes::new()));
            let (body, headers_only) = super::proxy_flush::prepare(
                body,
                Duration::from_nanos(self.flush_interval as u64),
                credit,
            )
            .await
            .map_err(anyhow::Error::from_boxed)?;
            *self.response.body_mut() = body;
            if headers_only {
                self.sniff = false;
            }
        }
        // Without buffering credit, retain the successful upstream response
        // and forward it immediately under ordinary downstream backpressure.

        if self.sniff {
            let mut body = std::mem::replace(self.response.body_mut(), full(Bytes::new()));
            if let Some(first) = body.frame().await {
                if let Some(bytes) = first.as_ref().ok().and_then(hyper::body::Frame::data_ref) {
                    self.response.headers_mut().insert(
                        http::header::CONTENT_TYPE,
                        HeaderValue::from_static(super::sniff::detect_content_type(bytes)),
                    );
                }
                let stream = futures_util::stream::once(async move { first });
                *self.response.body_mut() = http_body_util::StreamBody::new(
                    futures_util::StreamExt::chain(stream, BodyStream::new(body)),
                )
                .boxed_unsync();
            }
        }
        remove_hop_headers(self.response.headers_mut(), upgrade, false);
        if !upgrade {
            ctx.immediate.remove(http::header::SERVER);
            let via = match self.protocol {
                Some(Version::HTTP_10) => "1.0 Caddy",
                Some(Version::HTTP_2) => "2.0 Caddy",
                Some(_) => "1.1 Caddy",
                None => "0.0 Caddy",
            };
            ctx.immediate
                .append(http::header::VIA, HeaderValue::from_static(via));
            let status = self.response.status().as_u16();
            apply_response_headers(self.response.headers_mut(), status, &self.headers, ctx)?;
        }
        *self.response.version_mut() = ctx.req().version();
        // A copied or intercepted response may move just its body. Keep
        // upstream admission with the stream rather than the header object.
        if let Some(lease) = self.lease.take() {
            return Ok(self
                .response
                .map(|body| super::proxy_policy::with_lease(body, lease)));
        }
        Ok(self.response)
    }
}

#[derive(Default)]
struct AttemptProgress {
    observation: Option<Arc<super::proxy_replay::BodyObs>>,
    guard: Option<super::proxy_replay::AttemptGuard>,
    fetch_started: bool,
    response_received: bool,
    host: Option<Arc<super::proxy_hosts::HostState>>,
}

pub(super) async fn serve(
    ctx: &mut Context,
    config: &ProxyConfig,
    server: &Arc<ActiveServer>,
) -> Result<PreparedResponse> {
    let previous = ctx
        .req()
        .extensions()
        .get::<super::proxy_replay::ReplaySource>()
        .cloned();
    let mut source = if ctx.fastcgi_body_claimed {
        let source =
            previous.ok_or_else(|| anyhow::anyhow!("request body ownership unavailable"))?;
        ensure!(source.replayable(), "proxy request body already consumed");
        source
    } else {
        let request = ctx
            .request
            .take()
            .ok_or_else(|| anyhow::anyhow!("request body already consumed"))?;
        let (parts, body) = request.into_parts();
        ctx.fastcgi_body_claimed = true;
        ctx.request = Some(Request::from_parts(parts, full(Bytes::new())));
        ctx.body_limit = None;
        super::proxy_buffer::prepare(ctx, body, config.ext.request_buffers).await?
    };
    if source.complete_length().is_none()
        && let Some(transport) = &config.fastcgi
    {
        let body = source.take_unconsumed()?;
        source = super::fastcgi::prepare_source(ctx, config, transport, body).await?;
    }
    ctx.req_mut().extensions_mut().insert(source.clone());
    let start = std::time::Instant::now();
    let mut retries = 0;
    loop {
        ctx.values
            .insert("http.reverse_proxy.retries".into(), retries.to_string());
        let mut progress = AttemptProgress::default();
        let result = serve_once(ctx, config, server, Some(&source), &mut progress).await;
        if result.is_ok() {
            if let Some(guard) = progress.guard.take() {
                guard.disarm();
            }
            return result;
        }
        if let Some(mut guard) = progress.guard.take() {
            guard.abort();
        }
        let error = result.err().expect("failed attempt");
        if progress.response_received || error.is::<DownstreamFailure>() {
            return Err(error);
        }
        // Client upload, body limit and local spool failures do not describe
        // upstream health and cannot be repaired by replaying another attempt.
        if progress
            .observation
            .as_ref()
            .is_some_and(|obs| obs.upload_failed())
        {
            return Err(error);
        }
        if progress.fetch_started {
            if let Some(host) = progress.host {
                record_failure(ctx, config, server, host).await;
            }
        } else if !error.is::<super::proxy_retry::NoUpstream>() {
            return Err(error);
        }
        let allowed =
            super::proxy_retry::allowed(ctx, &config.ext.retry, start, retries, &error, &source)
                .await;
        if !matches!(allowed, Ok(true)) {
            return Err(error);
        }
        retries = retries
            .checked_add(1)
            .ok_or_else(|| super::request::failure(StatusCode::SERVICE_UNAVAILABLE))?;
    }
}

async fn record_failure(
    ctx: &mut Context,
    config: &ProxyConfig,
    server: &ActiveServer,
    host: Arc<super::proxy_hosts::HostState>,
) {
    let Some(owner) = server
        .clients
        .get(&(config as *const ProxyConfig as usize))
        .and_then(|state| state.passive.clone())
    else {
        return;
    };
    let result = if host.work_units() < 128 {
        owner
            .record(&host, tokio::time::Instant::now())
            .map_err(|_| ())
    } else {
        ctx.resources
            .proxy_selection
            .clone()
            .run(move || owner.record(&host, tokio::time::Instant::now()))
            .await
            .map_err(|_| ())
            .and_then(|result| result.map_err(|_| ()))
    };
    if result.is_err() && ctx.resources.proxy_hosts.record_dropped_failure() {
        proxy_log(
            server.logging.as_ref(),
            "passive failure accounting budget exhausted",
            "failure counter dropped; upstream response preserved",
        );
    }
}

async fn serve_once(
    ctx: &mut Context,
    config: &ProxyConfig,
    server: &Arc<ActiveServer>,
    replay: Option<&super::proxy_replay::ReplaySource>,
    progress: &mut AttemptProgress,
) -> Result<PreparedResponse> {
    let trailer_metadata = ctx
        .req()
        .extensions()
        .get::<super::trailer_policy::RequestMetadata>()
        .cloned()
        .unwrap_or_default();
    ensure!(
        !trailer_metadata.invalid_upstream,
        "invalid outgoing trailer declaration"
    );
    let state = server
        .clients
        .get(&(config as *const ProxyConfig as usize))
        .ok_or_else(|| anyhow::anyhow!("proxy transport not provisioned"))?;
    let secure_cookie = ctx.tls
        || ctx.trusted
            && ctx
                .req()
                .headers()
                .get_all("x-forwarded-proto")
                .iter()
                .next_back()
                .is_some_and(|v| v.as_bytes() == b"https");
    let policy = if let Some(dynamic) = &state.dynamic {
        if ctx
            .values
            .get("http.reverse_proxy.retries")
            .is_some_and(|v| v != "0")
        {
            let _ = dynamic.reset_cache(Some(&|value| ctx.expand(value)));
        }
        let pending = dynamic.get(&|value| ctx.expand(value));
        match pending.await {
            Ok(upstreams) => {
                let base = state.selection.clone();
                let hosts = ctx.resources.proxy_hosts.clone();
                Arc::new(
                    ctx.resources
                        .proxy_selection
                        .clone()
                        .run(move || base.with_upstreams(&hosts, &upstreams))
                        .await
                        .map_err(|error| super::request::budget_failure(ctx, error))?
                        .map_err(|_| {
                            super::request::budget_failure(
                                ctx,
                                super::resource_budget::BudgetError::Overloaded,
                            )
                        })?,
                )
            }
            Err(error) => {
                proxy_log(
                    server.logging.as_ref(),
                    "dynamic upstream lookup failed; falling back to static upstreams",
                    &error.to_string(),
                );
                state.selection.clone()
            }
        }
    } else {
        state.selection.clone()
    };
    let selection = {
        let peer_ip=ctx.peer.raw_host();let client_ip=ctx.client_ip.map_or_else(String::new,|ip|ip.to_string());
        let input = SelectionInput {
            authority: &ctx.authority,
            uri: ctx.req().uri(),
            version: ctx.req().version(),
            headers: ctx.req().headers(),
            peer_ip: &peer_ip,
            client_ip: &client_ip,
            secure: secure_cookie,
        };
        if policy.needs_worker(&input) {
            let owned = input.owned();
            let policy = policy.clone();
            ctx.resources
                .proxy_selection
                .run(move || policy.select(&owned.borrowed()))
                .await
                .map_err(|error| super::request::budget_failure(ctx, error))??
        } else {
            policy.select(&input)?
        }
    }
    .ok_or_else(|| {
        super::request::failure(StatusCode::SERVICE_UNAVAILABLE)
            .context(super::proxy_retry::NoUpstream)
    })?;
    progress.host = Some(selection.host.clone());
    let lease = selection.lease;
    for value in selection.cookies {
        ctx.immediate.append(http::header::SET_COOKIE, value);
    }
    let dial = ctx.expand(&selection.dial)?;
    for (name, value) in [
        (
            "http.reverse_proxy.upstream.requests",
            selection.prior_requests.to_string(),
        ),
        (
            "http.reverse_proxy.upstream.max_requests",
            selection.max_requests.to_string(),
        ),
        (
            "http.reverse_proxy.upstream.fails",
            selection.fails.to_string(),
        ),
    ] {
        ctx.values.insert(name.into(), value);
    }
    let status_address=if let Some(path)=super::http_dial::unix_path(&dial)? {path.to_owned()} else {
        let (_,address)=super::http_dial::Family::parse(&dial)?;address.to_owned()
    };
    lease.bind_address(&ctx.resources.proxy_hosts,&status_address)?;
    if let Some(transport) = &config.fastcgi {
        let attempt = replay
            .ok_or_else(|| anyhow::anyhow!("FastCGI replay source missing"))?
            .begin()?;
        progress.observation = Some(attempt.observation.clone());
        progress.guard = Some(attempt.guard);
        let metadata = ctx
            .request
            .take()
            .ok_or_else(|| anyhow::anyhow!("request metadata unavailable"))?;
        let (parts, _) = metadata.into_parts();
        let body = super::proxy_replay::observe(attempt.body, attempt.observation.clone());
        ctx.request = Some(Request::from_parts(
            parts,
            super::proxy_policy::with_lease(body, lease.clone()),
        ));
        let mut exchange =
            super::fastcgi::ExchangeState::new(replay.and_then(|source| source.complete_length()));
        let response = super::fastcgi::serve(
            ctx,
            config,
            transport,
            dial,
            server.logging.as_ref(),
            &mut exchange,
        )
        .await;
        progress.fetch_started = exchange.transport_started;
        if response.is_err()
            && let Some(request) = ctx.request.take()
        {
            let (parts, _body) = request.into_parts();
            ctx.request = Some(Request::from_parts(parts, full(Bytes::new())));
        }
        let mut prepared = response?;
        progress.response_received = true;
        count_response_failure(
            ctx,
            config,
            server,
            progress.host.clone(),
            prepared.response.status(),
            exchange
                .transport_began
                .map_or(Duration::ZERO, |began| began.elapsed()),
        )
        .await;
        prepared.lease = Some(lease);
        return Ok(prepared);
    }
    let unix_path=super::http_dial::unix_path(&dial)?;
    let (family, dial_address) = if unix_path.is_some(){(super::http_dial::Family::Any,"localhost:0")}else{super::http_dial::Family::parse(&dial)?};
    let parsed: Uri = format!("http://{dial_address}").parse()?;
    let authority = parsed
        .authority()
        .ok_or_else(|| anyhow::anyhow!("upstream authority required"))?;
    let host = authority
        .host()
        .trim_start_matches('[')
        .trim_end_matches(']');
    let port = authority.port_u16().unwrap_or(0).to_string();
    let effective_tls = config.tls_for_port(&port);
    let scheme = if effective_tls.is_some() {
        "https"
    } else {
        "http"
    };
    let uri_hostport = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let hostport=unix_path.unwrap_or(&uri_hostport).to_owned();
    for (key, value) in [
        ("address", format!("{}/{hostport}",if unix_path.is_some(){"unix"}else{family.name()})),
        ("hostport", hostport.clone()),
        ("host", unix_path.unwrap_or(host).to_owned()),
        ("port", port),
    ] {
        ctx.values
            .insert(format!("http.reverse_proxy.upstream.{key}"), value);
    }
    // Caddy network addresses without an explicit port use port zero, not the
    // URL scheme's implicit 80/443. The adapter supplies normal HTTP defaults.
    let connection_uri = format!("{scheme}://{uri_hostport}");
    let downstream_version = ctx.req().version();
    let is_upgrade = ctx.req().version() == Version::HTTP_11
        && header_has_token(ctx.req().headers(), http::header::CONNECTION, "upgrade")
        && ctx
            .req()
            .headers()
            .get(http::header::UPGRADE)
            .is_some_and(|v| !v.is_empty());
    let expected_upgrade = ctx.req().headers().get(http::header::UPGRADE).cloned();
    let server_name = if let Some(tls) = effective_tls {
        match tls.server_name.as_ref() {
            Some(template) => {
                let name = ctx.expand(template)?;
                if name.is_empty() && template.contains('{') {
                    // Caddy's dynamic DialTLS path passes the expanded config
                    // directly to tls.Client; unlike the static net/http path
                    // an empty name is not replaced with the dial host.
                    ensure!(
                        tls.insecure_skip_verify,
                        "empty dynamic upstream TLS server name"
                    );
                    // IP names omit the SNI extension. Chain/name checks are
                    // explicitly disabled here, but handshake signatures remain.
                    Some(ServerName::from(std::net::IpAddr::V4(
                        std::net::Ipv4Addr::UNSPECIFIED,
                    )))
                } else if name.is_empty() {
                    None
                } else {
                    Some(ServerName::try_from(super::http_dial::tls_host(&name).to_owned()).map_err(|_| {
                        anyhow::anyhow!("invalid expanded upstream TLS server name")
                    })?)
                }
            }
            None => None,
        }
    } else {
        None
    };
    let unix_host = (unix_path.is_some() && config.tls.is_some())
        .then(|| super::http_dial::unix_tls_host(server_name.as_ref()));
    let client = state.client_for(&connection_uri, family, is_upgrade, server_name,unix_path)?;
    let mut headers = proxy_headers(ctx, config, ctx.req().headers().clone(), is_upgrade, false, unix_host.as_deref())?;
    trailer_metadata.write_upstream_declaration(&mut headers);
    let replacement = ctx
        .req()
        .extensions()
        .get::<super::request_body::Replacement>()
        .cloned();
    super::request_body::outgoing_headers(
        replacement.as_ref(),
        &mut headers,
        config.http2_only && !is_upgrade,
    );
    // Go's empty UA is a sentinel that suppresses serialization. Hyper has
    // no automatic default UA, so absence is the equivalent wire behavior.
    if headers
        .get(http::header::USER_AGENT)
        .is_some_and(|v| v.is_empty())
    {
        headers.remove(http::header::USER_AGENT);
    }
    if downstream_version == Version::HTTP_2 {
        let cookies = headers
            .get_all(http::header::COOKIE)
            .iter()
            .map(|v| v.as_bytes())
            .collect::<Vec<_>>();
        if cookies.len() > 1 {
            let cookie = HeaderValue::from_bytes(&cookies.join(&b"; "[..]))?;
            headers.insert(http::header::COOKIE, cookie);
        }
    }
    let automatically_gzip = config.compression
        && ctx.req().method() != http::Method::HEAD
        && headers
            .get(http::header::ACCEPT_ENCODING)
            .is_none_or(|v| v.is_empty())
        && headers
            .get(http::header::RANGE)
            .is_none_or(|v| v.is_empty());
    if automatically_gzip {
        headers.insert(
            http::header::ACCEPT_ENCODING,
            HeaderValue::from_static("gzip"),
        );
    }
    let outgoing_host = headers
        .get_all(http::header::HOST)
        .iter()
        .next_back()
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty())
        .unwrap_or(dial_address);
    let outgoing_host = outgoing_host.to_owned();
    headers.insert(http::header::HOST, HeaderValue::from_str(&outgoing_host)?);
    let uri = format!(
        "{scheme}://{outgoing_host}{}",
        ctx.req()
            .uri()
            .path_and_query()
            .map(|x| x.as_str())
            .unwrap_or("/")
    )
    .parse::<Uri>()
    .map_err(|_| anyhow::anyhow!("invalid expanded upstream authority"))?;
    let source = replay.ok_or_else(|| anyhow::anyhow!("HTTP replay source missing"))?;
    let attempt = source.begin()?;
    progress.observation = Some(attempt.observation.clone());
    progress.guard = Some(attempt.guard);
    let mut request = Request::new(attempt.body);
    *request.method_mut() = ctx.req().method().clone();
    *request.version_mut() = ctx.req().version();
    *request.extensions_mut() = ctx.req().extensions().clone();
    // The downstream upgrade belongs to the inbound request until an
    // upstream actually accepts the upgrade. Failed attempts must preserve it.
    request
        .extensions_mut()
        .remove::<hyper::upgrade::OnUpgrade>();
    *request.uri_mut() = uri;
    *request.headers_mut() = headers;
    *request.version_mut() = if config.http2_only && !is_upgrade {
        Version::HTTP_2
    } else {
        Version::HTTP_11
    };
    // Pinned Caddy clones the request's trailer map before reading its body;
    // values received later do not enter the outgoing request. Apply this
    // policy before either HTTP version can serialize a trailer frame.
    request = request.map(|body| {
        super::proxy_policy::with_lease(
            super::proxy_replay::observe(
                super::request_body::outgoing_body(body, replacement),
                progress
                    .observation
                    .as_ref()
                    .expect("attempt observation")
                    .clone(),
            ),
            lease.clone(),
        )
    });
    // Keep the bounded upstream-event waiter out of the outer route
    // future, which shares its allocation with non-proxy handlers.
    progress.fetch_started = true;
    let began = std::time::Instant::now();
    let mut response = Box::pin(fetch_with_informational(
        ctx,
        &client,
        request,
        config.response_header_timeout,
    ))
    .await?;
    progress.response_received = true;
    count_response_failure(
        ctx,
        config,
        server,
        progress.host.clone(),
        response.status(),
        began.elapsed(),
    )
    .await;
    let reason = response
        .extensions_mut()
        .remove::<hyper::ext::ReasonPhrase>();
    let status = response.status();
    let status_text = format!(
        "{} {}",
        status.as_str(),
        reason
            .as_ref()
            .map(|reason| String::from_utf8_lossy(reason.as_bytes()))
            .unwrap_or_else(|| status.canonical_reason().unwrap_or_default().into()),
    );
    let protocol = response.version();
    let upgrade = (status == StatusCode::SWITCHING_PROTOCOLS).then(|| Upgrade {
        upstream: hyper::upgrade::on(&mut response),
        downstream: is_upgrade.then(|| hyper::upgrade::on(ctx.req_mut())),
        expected: expected_upgrade,
        client: client.clone(),
        close_delay: config.stream_close_delay,
    });
    let has_body = !hyper::body::Body::is_end_stream(response.body())
        && response.status() != StatusCode::NO_CONTENT
        && response.status() != StatusCode::NOT_MODIFIED
        && response
            .headers()
            .get(http::header::CONTENT_LENGTH)
            .is_none_or(|v| v.as_bytes() != b"0");
    let decompress = automatically_gzip
        && has_body
        && response
            .headers()
            .get(http::header::CONTENT_ENCODING)
            .is_some_and(|value| value.as_bytes().eq_ignore_ascii_case(b"gzip"));
    if decompress {
        response
            .headers_mut()
            .remove(http::header::CONTENT_ENCODING);
        response.headers_mut().remove(http::header::CONTENT_LENGTH);
    }
    let force_immediate = super::incremental::is_enabled(response.headers());
    let response = response.map(|body| {
        let body = ProxyBody { body, client };
        let body = if decompress {
            gzip_decode(body)
        } else {
            body.map_err(|e| -> BoxError { e.into() }).boxed_unsync()
        };
        super::trailer_policy::policy(body, false)
    });
    Ok(PreparedResponse {
        response,
        status_text,
        headers: config.response_headers.clone(),
        protocol: Some(protocol),
        sniff: false,
        flush_interval: config.flush_interval,
        force_immediate,
        upgrade,
        lease: Some(lease),
    })
}
async fn fetch_with_informational(
    ctx: &mut Context,
    client: &HyperClient,
    mut request: Request<Body>,
    timeout: Option<i64>,
) -> Result<Response<Incoming>> {
    use super::request::accepts_informational;
    let interim = if accepts_informational(ctx) {
        // Callbacks run on the transport's driver, not the current handler.
        // Allocate the queue's storage only when there is an actual hint.
        let receive = Arc::new(ProxyInterim::default());
        let send = receive.clone();
        hyper::ext::on_informational(&mut request, move |head| {
            send.enqueue(head.status(), head.headers());
        });
        Some(receive)
    } else {
        None
    };
    request
        .extensions_mut()
        .remove::<hyper::ext::SendCompletion>();
    let sent = timeout.map(|_| hyper::ext::SendCompletion::new());
    if let Some(sent) = &sent {
        request.extensions_mut().insert(sent.clone());
    }
    let fetch = async {
        let pending = client.request(request);
        tokio::pin!(pending);
        let Some((timeout, sent)) = timeout.zip(sent) else {
            return anyhow::Ok(pending.await?);
        };
        // The transport signals its actual successful final write/flush, not
        // Body EOS or HTTP/2 queue admission. A peer may send final headers
        // before finishing the upload; that response must remain immediately
        // available and its subsequent body has no response-header deadline.
        let completed = std::future::poll_fn(|cx| sent.poll_outcome(cx));
        tokio::pin!(completed);
        tokio::select! { biased;
            result = &mut pending => anyhow::Ok(result?),
            outcome = &mut completed => {
                let hyper::ext::SendOutcome::Flushed(sent_at) = outcome else {
                    return anyhow::Ok(pending.await?);
                };
                let deadline = if timeout > 0 {
                    sent_at.checked_add(Duration::from_nanos(timeout as u64))
                } else if sent.flushed_version() == Some(Version::HTTP_2) {
                    Some(sent_at)
                } else {
                    None
                };
                let Some(deadline) = deadline else {
                    return anyhow::Ok(pending.await?);
                };
                let response = tokio::time::timeout_at(deadline.into(), &mut pending)
                    .await
                    .map_err(|_| super::request::failure(StatusCode::GATEWAY_TIMEOUT))??;
                anyhow::Ok(response)
            }
        }
    };
    let Some(receive) = interim else {
        return fetch.await;
    };
    tokio::pin!(fetch);
    loop {
        tokio::select! {biased;
            result = &mut fetch => {
                // The transport delivers callbacks before resolving final
                // headers (or an error). Send those already committed first.
                while let Some(head) = receive.try_pop() {
                    deliver_proxy_hint(ctx, head).await?;
                }
                return result;
            }
            head = receive.next() => {
                // Forwarding a hint can itself wait for a slow downstream
                // flush. Keep polling the upstream response/deadline while
                // that acknowledgment is pending, so a stalled hint cannot
                // postpone cancellation of an expired upstream operation.
                let completed = {
                    let delivery = deliver_proxy_hint(ctx, head);
                    tokio::pin!(delivery);
                    tokio::select! { biased;
                        result = &mut fetch => {
                            let response = result?;
                            // A successful final response does not overtake a
                            // hint already being delivered. Once final headers
                            // exist there is no response-header timer to extend.
                            delivery.await?;
                            Some(response)
                        }
                        result = &mut delivery => { result?; None },
                    }
                };
                if let Some(response) = completed {
                    while let Some(head) = receive.try_pop() {
                        deliver_proxy_hint(ctx, head).await?;
                    }
                    return Ok(response);
                }
            },
        }
    }
}

type ProxyHint = (StatusCode, HeaderMap);

#[derive(Default)]
struct ProxyInterim {
    state: Mutex<HintState>,
    nonempty: AtomicBool,
    ready: Notify,
}

#[derive(Default)]
struct HintState {
    heads: u16,
    bytes: usize,
    queue: VecDeque<ProxyHint>,
}

impl ProxyInterim {
    fn enqueue(&self, status: StatusCode, headers: &HeaderMap) {
        use super::request::{
            MAX_INFORMATIONAL_BYTES, MAX_INFORMATIONAL_HEADS, record_suppressed_informational,
        };
        if !status.is_informational() || status == StatusCode::SWITCHING_PROTOCOLS {
            return;
        }
        let bytes = headers.iter().try_fold(48usize, |size, (name, value)| {
            size.checked_add(name.as_str().len())?
                .checked_add(value.as_bytes().len())?
                .checked_add(32)
                .filter(|size| *size <= MAX_INFORMATIONAL_BYTES)
        });
        let Some(bytes) = bytes else {
            record_suppressed_informational();
            return;
        };
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if state.heads == MAX_INFORMATIONAL_HEADS
            || state.bytes.saturating_add(bytes) > MAX_INFORMATIONAL_BYTES
        {
            record_suppressed_informational();
            return;
        }
        state.heads += 1;
        state.bytes += bytes;
        let first = state.queue.is_empty();
        state.queue.push_back((status, headers.clone()));
        if first {
            self.nonempty.store(true, Ordering::Release);
        }
        drop(state);
        if first {
            // Only one consumer. notify_one retains a permit even when no
            // waiter has yet polled, closing the try_pop/register race.
            self.ready.notify_one();
        }
    }

    fn try_pop(&self) -> Option<ProxyHint> {
        if !self.nonempty.load(Ordering::Acquire) {
            return None;
        }
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let value = state.queue.pop_front();
        if state.queue.is_empty() {
            self.nonempty.store(false, Ordering::Release);
        }
        value
    }

    async fn next(&self) -> ProxyHint {
        loop {
            if let Some(head) = self.try_pop() {
                return head;
            }
            self.ready.notified().await;
        }
    }
}

async fn deliver_proxy_hint(ctx: &mut Context, (status, mut headers): ProxyHint) -> Result<()> {
    remove_hop_headers(&mut headers, false, false);
    headers.remove(http::header::CONTENT_LENGTH);
    headers.remove(http::header::TRAILER);
    super::request::forward_informational(ctx, status, headers)
        .await
        .map_err(|error| error.context(DownstreamFailure))
}

#[derive(Debug)]
struct DownstreamFailure;
impl std::fmt::Display for DownstreamFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("forwarding upstream informational response downstream failed")
    }
}

pub(super) fn proxy_headers(
    ctx: &Context,
    config: &ProxyConfig,
    mut headers: HeaderMap,
    is_upgrade: bool,
    fastcgi: bool,
    http_host_override: Option<&str>,
) -> Result<HeaderMap> {
    let original_host = ctx.authority.clone();
    let old_xff = if ctx.trusted {
        headers
            .get_all("x-forwarded-for")
            .iter()
            .filter_map(|h| h.to_str().ok())
            .collect::<Vec<_>>()
            .join(", ")
    } else {
        String::new()
    };
    let forwarded_host = if ctx.trusted {
        headers.get("x-forwarded-host").cloned()
    } else {
        None
    };
    let forwarded_proto = if ctx.trusted {
        headers.get("x-forwarded-proto").cloned()
    } else {
        None
    };
    remove_hop_headers(&mut headers, is_upgrade, true);
    if let Some((peer_host,_))=ctx.peer.host_port_bytes().filter(|(host,_)|!host.is_empty()) {
        let peer_host=peer_host.split(|b|*b==b'%').next().unwrap_or_default();
        let mut xff=Vec::with_capacity(old_xff.len()+peer_host.len()+2);
        if !old_xff.is_empty(){xff.extend_from_slice(old_xff.as_bytes());xff.extend_from_slice(b", ");}
        xff.extend_from_slice(peer_host);
        headers.insert("x-forwarded-for",HeaderValue::from_bytes(&xff)?);
        headers.insert("x-forwarded-host",forwarded_host.unwrap_or(HeaderValue::from_str(&original_host)?));
        headers.insert("x-forwarded-proto",forwarded_proto.unwrap_or(HeaderValue::from_static(if ctx.tls{"https"}else{"http"})));
    } else {
        // An absent or unparseable peer host cannot authenticate supplied
        // forwarding headers. Never substitute the physical proxy's IP.
        for name in ["x-forwarded-for","x-forwarded-host","x-forwarded-proto"]{headers.remove(name);}
    }
    if !headers.contains_key(http::header::HOST) {
        headers.insert(http::header::HOST, HeaderValue::from_str(&original_host)?);
    }
    // Caddy HTTPTransport supplies this default before the handler's user ops.
    if !fastcgi
        && config.tls.is_some()
        && let Some(hostport) = ctx.lookup("http.reverse_proxy.upstream.hostport")
    {
        headers.insert(http::header::HOST, HeaderValue::from_str(http_host_override.unwrap_or(&hostport))?);
    }
    if fastcgi {
        let via = match ctx.req().version() {
            Version::HTTP_10 => "1.0 Caddy",
            Version::HTTP_2 => "2.0 Caddy",
            Version::HTTP_3 => "3.0 Caddy",
            _ => "1.1 Caddy",
        };
        headers.append(http::header::VIA, HeaderValue::from_static(via));
        if !headers.contains_key(http::header::USER_AGENT) {
            headers.insert(http::header::USER_AGENT, HeaderValue::from_static(""));
        }
    }
    apply_headers(&mut headers, &config.request_headers, ctx)?;
    if !fastcgi && let Some(host) = headers.get(http::header::HOST).and_then(|v| v.to_str().ok())
        && let std::borrow::Cow::Owned(host) = super::http_dial::wire_host(host) {
        headers.insert(http::header::HOST, HeaderValue::from_str(&host)?);
    }
    Ok(headers)
}

pub(super) fn header_has_token(headers: &HeaderMap, name: HeaderName, token: &str) -> bool {
    headers
        .get_all(name)
        .iter()
        .filter_map(|h| h.to_str().ok())
        .any(|v| v.split(',').any(|v| v.trim().eq_ignore_ascii_case(token)))
}
pub(super) fn remove_hop_headers(headers: &mut HeaderMap, upgrade: bool, preserve_te: bool) {
    let connection = headers
        .get_all(http::header::CONNECTION)
        .iter()
        .filter_map(|h| h.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|name| HeaderName::try_from(name.trim()).ok())
        .collect::<Vec<_>>();
    for name in connection {
        if !(upgrade && name == http::header::UPGRADE) {
            headers.remove(name);
        }
    }
    let trailers = preserve_te && header_has_token(headers, http::header::TE, "trailers");
    for name in [
        "alt-svc",
        "connection",
        "proxy-connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "transfer-encoding",
    ] {
        headers.remove(name);
    }
    if trailers {
        headers.insert(http::header::TE, HeaderValue::from_static("trailers"));
    }
    if upgrade {
        headers.insert(
            http::header::CONNECTION,
            HeaderValue::from_static("upgrade"),
        );
    } else {
        headers.remove(http::header::UPGRADE);
    }
}

struct ProxyBody {
    body: hyper::body::Incoming,
    client: HyperClient,
}
impl hyper::body::Body for ProxyBody {
    type Data = Bytes;
    type Error = hyper::Error;
    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<std::result::Result<hyper::body::Frame<Bytes>, hyper::Error>>> {
        let _client = &self.client;
        std::pin::Pin::new(&mut self.body).poll_frame(cx)
    }
    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }
    fn size_hint(&self) -> hyper::body::SizeHint {
        self.body.size_hint()
    }
}

// Decode only gzip that the transport requested itself. A caller-specified
// Accept-Encoding is passed through untouched, matching Go's HTTP transport.
// Capture trailer frames separately while the decoder consumes data as AsyncRead;
// append them only after gzip's checksum and all members have been validated.
pub(super) fn gzip_decode<B>(body: B) -> Body
where
    B: hyper::body::Body<Data = Bytes> + Unpin + Send + 'static,
    B::Error: Into<BoxError>,
{
    use futures_util::{StreamExt, TryStreamExt};
    let trailers = Arc::new(std::sync::Mutex::new(None::<HeaderMap>));
    let capture = trailers.clone();
    let data = futures_util::stream::unfold((body, capture), |(mut body, capture)| async move {
        loop {
            match body.frame().await {
                Some(Ok(frame)) => match frame.into_data() {
                    Ok(data) => return Some((Ok::<_, std::io::Error>(data), (body, capture))),
                    Err(frame) => {
                        if let Ok(headers) = frame.into_trailers() {
                            *capture.lock().expect("trailer lock not poisoned") = Some(headers);
                        }
                    }
                },
                Some(Err(error)) => {
                    return Some((Err(std::io::Error::other(error.into())), (body, capture)));
                }
                None => return None,
            }
        }
    });
    let reader = tokio_util::io::StreamReader::new(Box::pin(data));
    let mut decoder = async_compression::tokio::bufread::GzipDecoder::new(reader);
    decoder.multiple_members(true);
    let data = tokio_util::io::ReaderStream::new(decoder)
        .map_ok(hyper::body::Frame::data)
        .map_err(|error| -> BoxError { error.into() });
    let final_trailers = futures_util::stream::once(async move {
        trailers
            .lock()
            .expect("trailer lock not poisoned")
            .take()
            .map(|headers| Ok::<_, BoxError>(hyper::body::Frame::trailers(headers)))
    })
    .filter_map(futures_util::future::ready);
    http_body_util::StreamBody::new(data.chain(final_trailers)).boxed_unsync()
}

fn proxy_log(logging: Option<&Arc<crate::logging::Logging>>, message: &str, reason: &str) {
    use crate::logging::{Event, Field, FieldValue, Level, Origin};
    if let Some(logging) = logging {
        let module = "http.handlers.reverse_proxy";
        if let Ok(mut event) = Event::new(
            Origin::Module {
                module_id: module.into(),
            },
            module,
            Level::Error,
            message,
        ) {
            event.fields.push(Field::new(
                "error",
                FieldValue::String(reason.chars().take(4096).collect()),
            ));
            let _ = logging.try_emit(event);
        }
    }
}

async fn count_response_failure(
    ctx: &mut Context,
    config: &ProxyConfig,
    server: &ActiveServer,
    host: Option<Arc<super::proxy_hosts::HostState>>,
    status: StatusCode,
    elapsed: Duration,
) {
    if let Some(passive) = &config.ext.health.passive {
        let status = i64::from(status.as_u16());
        let failures = passive
            .unhealthy_status
            .iter()
            .filter(|code| **code == status || ((1..=9).contains(*code) && status / 100 == **code))
            .count()
            + usize::from(
                passive.unhealthy_latency > 0
                    && elapsed >= Duration::from_nanos(passive.unhealthy_latency as u64),
            );
        if failures != 0
            && let Some(host) = host
        {
            for _ in 0..failures {
                record_failure(ctx, config, server, host.clone()).await;
            }
        }
    }
}

pub(super) async fn prepare_health(
    inner: &Arc<Inner>,
    generation: &Arc<Generation>,
    publication: HttpRetirement,
) -> Result<()> {
    let mut maps = std::collections::HashSet::new();
    let mut prepared = Vec::new();
    for server in generation.servers.values() {
        if !maps.insert(Arc::as_ptr(&server.clients) as usize) {
            continue;
        }
        for client in server.clients.values() {
            if !client
                .config
                .ext
                .health
                .active
                .as_ref()
                .is_some_and(|cfg| cfg.enabled())
            {
                continue;
            }
            prepared.push((client.clone(), server.logging.clone(), server.events.clone()));
            anyhow::ensure!(
                prepared.len() <= super::proxy_health::MAX_SCHEDULERS,
                "active health schedulers exceed per-configuration limit {}",
                super::proxy_health::MAX_SCHEDULERS,
            );
        }
    }
    // Reserve a whole generation atomically: concurrent staged generations
    // must not each hold a partial reservation and wait on one another.
    // Two complete generations fit; later reloads await retired tasks dropping
    // their credits rather than rejecting the same valid configuration.
    let mut credits = tokio::select! { biased;
        _ = inner.stopped.cancelled() => anyhow::bail!("HTTP runtime stopped"),
        credits = inner.resources.proxy_health_schedulers.clone()
            .acquire_many_owned(prepared.len() as u32) =>
            credits.map_err(|_| anyhow::anyhow!("active health scheduler budget closed"))?,
    };
    for (client, logging, events) in prepared {
        let credit = credits.split(1).expect("whole generation credits reserved");
        let active = client
            .config
            .ext
            .health
            .active
            .as_ref()
            .expect("enabled health configuration");
        let interval = active.interval;
        let passes = active.passes;
        let fails = active.fails;
        let states = client.selection.active_states();
        let probe = super::proxy_health_probe::build(
            client.clone(),
            client.config.clone(),
            inner.resources.clone(),
            logging.clone(),
            credit,
            events,
            generation.activity.superseded.clone(),
        );
        let global = inner.stopped.clone();
        let superseded = generation.activity.superseded.clone();
        let slots = inner.resources.proxy_health.clone();
        let tasks = inner.tasks.clone();
        let publication = publication.clone();
        inner.tasks.spawn(async move {
            let activated = tokio::select! {biased;
                _=global.cancelled()=>false,
                ready=publication.activated()=>ready,
            };
            if !activated {
                return;
            }
            if super::proxy_health::start(
                tasks,
                superseded,
                global,
                slots,
                super::proxy_health::Schedule {
                    states,
                    interval,
                    passes,
                    fails,
                },
                probe,
            )
            .is_err()
            {
                proxy_log(
                    logging.as_ref(),
                    "active health scheduler failed to start",
                    "invalid scheduler limits",
                );
            }
        });
    }
    Ok(())
}
