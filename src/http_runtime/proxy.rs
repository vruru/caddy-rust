use super::proxy_policy::{HostRegistry, PreparedSelection, SelectionInput};
use super::request::{Context, apply_headers, apply_response_headers};
use super::upstream_tls::{FixedDialConnector, PreparedTransport};
use super::*;
use http::{HeaderMap, HeaderName, HeaderValue, Uri, Version};
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
pub(super) struct ProxyClient {
    selection: Arc<PreparedSelection>,
    connector: PreparedTransport,
    http1_connector: PreparedTransport,
    http2_only: bool,
    cache: std::sync::Mutex<ClientCache>,
}
struct ClientCache {
    clock: u64,
    clients: HashMap<String, (HyperClient, u64)>,
}
impl ProxyClient {
    fn client_for(
        &self,
        dial: &str,
        force_http1: bool,
        server_name: Option<ServerName<'static>>,
    ) -> Result<HyperClient> {
        let cache_key = format!("{dial}|{force_http1}|{server_name:?}");
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
        let client = builder.build(transport.connector(uri, server_name));
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
    logging_available: bool,
) -> Result<()> {
    crate::http_config::helpers::initialize_globals();
    for route in routes {
        for handler in &route.handlers {
            match handler {
                Handler::Subroute { routes, errors, .. } => {
                    prepare_clients(routes, output, hosts, logging_available)?;
                    prepare_clients(errors, output, hosts, logging_available)?;
                }
                Handler::FileServer { .. } => {
                    super::mime::initialize();
                }
                Handler::ReverseProxy(config) => {
                    let config = config.as_ref();
                    if let Some(fastcgi) = &config.fastcgi {
                        ensure!(!fastcgi.capture_stderr || logging_available,
                            "FastCGI capture_stderr requires generation logging");
                        continue;
                    }
                    let connector = PreparedTransport::prepare(config)?;
                    let http1_connector = connector.http1();
                    output.insert(
                        config as *const ProxyConfig as usize,
                        ProxyClient {
                            selection: Arc::new(PreparedSelection::new(hosts, &config.selection, &config.upstreams)),
                            connector,
                            http1_connector,
                            http2_only: config.http2_only,
                            cache: std::sync::Mutex::new(ClientCache {
                                clock: 0,
                                clients: HashMap::new(),
                            }),
                        },
                    );
                }
                _ => {}
            }
        }
    }
    Ok(())
}
pub(super) async fn serve(
    ctx: &mut Context,
    config: &ProxyConfig,
    server: &Arc<ActiveServer>,
    inner: &Arc<Inner>,
) -> Result<Response<Body>> {
    ensure!(
        !ctx.fastcgi_body_claimed,
        "FastCGI request body cannot be replayed"
    );
    ensure!(
        config.flush_interval <= 0,
        "positive proxy flush intervals are not implemented"
    );
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
    if let Some(transport) = &config.fastcgi {
        let index = super::proxy_policy::random_below(config.upstreams.len())?;
        let dial = ctx.expand(&config.upstreams[index].dial)?;
        return super::fastcgi::serve(ctx, config, transport, dial, server.logging.as_ref()).await;
    }
    let state = server.clients.get(&(config as *const ProxyConfig as usize))
        .ok_or_else(|| anyhow::anyhow!("proxy transport not provisioned"))?;
    let secure_cookie = ctx.tls || ctx.trusted && ctx.req().headers()
        .get_all("x-forwarded-proto").iter().next_back().is_some_and(|v| v.as_bytes() == b"https");
    let selection = {
        let input = SelectionInput {
            authority: &ctx.authority,
            uri: ctx.req().uri(),
            version: ctx.req().version(),
            headers: ctx.req().headers(),
            peer_ip: ctx.peer.ip(),
            client_ip: ctx.client_ip,
            secure: secure_cookie,
        };
        if state.selection.needs_worker(&input) {
            let owned = input.owned();
            let policy = state.selection.clone();
            ctx.resources.proxy_selection.run(move || policy.select(&owned.borrowed())).await
                .map_err(|error| super::request::budget_failure(ctx, error))??
        } else {
            state.selection.select(&input)?
        }
    }.ok_or_else(|| super::request::failure(StatusCode::SERVICE_UNAVAILABLE))?;
    let mut lease = Some(selection.lease);
    for value in selection.cookies {
        ctx.immediate.append(http::header::SET_COOKIE, value);
    }
    let dial = ctx.expand(&config.upstreams[selection.index].dial)?;
    for (name, value) in [
        ("http.reverse_proxy.upstream.requests", selection.prior_requests.to_string()),
        ("http.reverse_proxy.upstream.max_requests", selection.max_requests.to_string()),
        ("http.reverse_proxy.upstream.fails", "0".to_owned()),
    ] {
        ctx.values.insert(name.into(), value);
    }
    let scheme = if config.tls.is_some() {
        "https"
    } else {
        "http"
    };
    ensure!(
        !dial.contains(['@', '#', '?', '/', '\r', '\n']),
        "invalid expanded upstream dial"
    );
    let parsed: Uri = format!("{scheme}://{dial}").parse()?;
    let authority = parsed
        .authority()
        .ok_or_else(|| anyhow::anyhow!("upstream authority required"))?;
    let host = authority
        .host()
        .trim_start_matches('[')
        .trim_end_matches(']');
    let port = authority.port_u16().unwrap_or(0).to_string();
    let hostport = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    for (key, value) in [
        ("address", format!("tcp/{hostport}")),
        ("hostport", hostport.clone()),
        ("host", host.to_owned()),
        ("port", port),
    ] {
        ctx.values
            .insert(format!("http.reverse_proxy.upstream.{key}"), value);
    }
    // Caddy network addresses without an explicit port use port zero, not the
    // URL scheme's implicit 80/443. The adapter supplies normal HTTP defaults.
    let connection_uri = format!("{scheme}://{hostport}");
    let downstream_version = ctx.req().version();
    let is_upgrade = ctx.req().version() == Version::HTTP_11
        && header_has_token(ctx.req().headers(), http::header::CONNECTION, "upgrade")
        && ctx
            .req()
            .headers()
            .get(http::header::UPGRADE)
            .is_some_and(|v| !v.is_empty());
    let expected_upgrade = ctx.req().headers().get(http::header::UPGRADE).cloned();
    let server_name = if let Some(tls) = config.tls.as_ref() {
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
                    Some(ServerName::try_from(name).map_err(|_| {
                        anyhow::anyhow!("invalid expanded upstream TLS server name")
                    })?)
                }
            }
            None => None,
        }
    } else {
        None
    };
    let client = state.client_for(&connection_uri, is_upgrade, server_name)?;
    let downstream_upgrade = if is_upgrade {
        Some(hyper::upgrade::on(ctx.req_mut()))
    } else {
        None
    };
    let mut headers = proxy_headers(ctx, config, ctx.req().headers().clone(), is_upgrade, false)?;
    trailer_metadata.write_upstream_declaration(&mut headers);
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
        .unwrap_or(&dial);
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
    let mut request = ctx
        .request
        .take()
        .ok_or_else(|| anyhow::anyhow!("request body already consumed"))?;
    // Retain request metadata for response-phase placeholders without retaining
    // or cloning its streaming body.
    let mut metadata = Request::new(full(Bytes::new()));
    *metadata.method_mut() = request.method().clone();
    *metadata.uri_mut() = request.uri().clone();
    *metadata.version_mut() = request.version();
    *metadata.headers_mut() = request.headers().clone();
    *metadata.extensions_mut() = request.extensions().clone();
    ctx.request = Some(metadata);
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
    request = request.map(|body| super::proxy_policy::with_lease(
        super::trailer_policy::policy(body, true), lease.as_ref().expect("attempt lease").clone(),
    ));
    // Keep the bounded upstream-event waiter out of the outer route
    // future, which shares its allocation with non-proxy handlers.
    let mut response = Box::pin(fetch_with_informational(
        ctx,
        &client,
        request,
        config.response_header_timeout.filter(|d| !d.is_zero()),
    ))
    .await?;
    if response.status() == StatusCode::SWITCHING_PROTOCOLS {
        ensure!(is_upgrade, "unsolicited upstream upgrade");
        ensure!(
            header_has_token(response.headers(), http::header::CONNECTION, "upgrade"),
            "upstream upgrade connection token missing"
        );
        ensure!(
            response
                .headers()
                .get(http::header::UPGRADE)
                .zip(expected_upgrade.as_ref())
                .is_some_and(|(received, expected)| received
                    .as_bytes()
                    .eq_ignore_ascii_case(expected.as_bytes())),
            "upstream upgrade protocol mismatch"
        );
        let upstream_upgrade = hyper::upgrade::on(&mut response);
        let downstream_upgrade =
            downstream_upgrade.ok_or_else(|| anyhow::anyhow!("missing downstream upgrade"))?;
        let upgrades = inner.upgrades.clone();
        let drain = ctx.drain.clone();
        let delay = config.stream_close_delay;
        let hold_client = client.clone();
        let business = ctx.business.clone();
        let hard_stop = business.generation().hard_stop.clone();
        let admission = lease.take().expect("upgrade attempt lease");
        upgrades.spawn(async move {
            let _admission = admission;
            let _hold_client=hold_client;
            let _business=business;
            let tunnel=async {
            if let (Ok(downstream),Ok(upstream))=tokio::join!(downstream_upgrade,upstream_upgrade){
                let mut downstream=TokioIo::new(downstream);let mut upstream=TokioIo::new(upstream);
                let copy=tokio::io::copy_bidirectional(&mut downstream,&mut upstream);tokio::pin!(copy);
                if let Some(delay)=delay {
                    tokio::select!{_=&mut copy=>{},_=drain.cancelled()=>{let _=tokio::time::timeout(delay,copy).await;}}
                } else { let _=copy.await; }
            }
            };
            tokio::select! {biased; _=hard_stop.cancelled()=>{},_=tunnel=>{}}
        });
    }
    let upgrade = response.status() == StatusCode::SWITCHING_PROTOCOLS;
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
    remove_hop_headers(response.headers_mut(), upgrade, false);
    if !upgrade {
        // Go finalizes normal responses before copying upstream fields. Via
        // belongs to the downstream writer, outside the require matcher input.
        ctx.immediate.remove(http::header::SERVER);
        let via = match response.version() {
            Version::HTTP_10 => "1.0 Caddy",
            Version::HTTP_2 => "2.0 Caddy",
            _ => "1.1 Caddy",
        };
        ctx.immediate
            .append(http::header::VIA, HeaderValue::from_static(via));
        let status = response.status().as_u16();
        apply_response_headers(
            response.headers_mut(),
            status,
            &config.response_headers,
            ctx,
        )?;
    }
    *response.version_mut() = downstream_version;
    if let Some(lease) = lease { response.extensions_mut().insert(lease); }
    Ok(response.map(|body| {
        let body = ProxyBody { body, client };
        let body = if decompress {
            gzip_decode(body)
        } else {
            body.map_err(|e| -> BoxError { e.into() }).boxed_unsync()
        };
        super::trailer_policy::policy(body, false)
    }))
}
async fn fetch_with_informational(
    ctx: &mut Context,
    client: &HyperClient,
    mut request: Request<Body>,
    timeout: Option<Duration>,
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
    let fetch = async {
        let pending = client.request(request);
        let response = if let Some(timeout) = timeout {
            tokio::time::timeout(timeout, pending)
                .await
                .map_err(|_| super::request::failure(StatusCode::GATEWAY_TIMEOUT))??
        } else {
            pending.await?
        };
        anyhow::Ok(response)
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
            head = receive.next() => deliver_proxy_hint(ctx, head).await?,
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
    super::request::forward_informational(ctx, status, headers).await
}

pub(super) fn proxy_headers(
    ctx: &Context,
    config: &ProxyConfig,
    mut headers: HeaderMap,
    is_upgrade: bool,
    fastcgi: bool,
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
    headers.insert(
        "x-forwarded-for",
        HeaderValue::from_str(&if old_xff.is_empty() {
            ctx.peer.ip().to_string()
        } else {
            format!("{old_xff}, {}", ctx.peer.ip())
        })?,
    );
    headers.insert(
        "x-forwarded-host",
        forwarded_host.unwrap_or(HeaderValue::from_str(&original_host)?),
    );
    headers.insert(
        "x-forwarded-proto",
        forwarded_proto.unwrap_or(HeaderValue::from_static(if ctx.tls {
            "https"
        } else {
            "http"
        })),
    );
    if !headers.contains_key(http::header::HOST) {
        headers.insert(http::header::HOST, HeaderValue::from_str(&original_host)?);
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
    Ok(headers)
}

fn header_has_token(headers: &HeaderMap, name: HeaderName, token: &str) -> bool {
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
fn gzip_decode(body: ProxyBody) -> Body {
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
                    return Some((Err(std::io::Error::other(error)), (body, capture)));
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
