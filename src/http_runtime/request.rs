use super::*;
use crate::http_config::{helpers::replace, types::*};
use base64::Engine;
use http::{HeaderMap, HeaderName, HeaderValue, Method, Uri, Version};
use std::{
    collections::{HashMap, HashSet},
    future::Future,
    net::IpAddr,
    path::{Path, PathBuf},
    pin::Pin,
};

struct LazyMap {
    source: String,
    destinations: Vec<String>,
    mappings: Vec<MapEntry>,
    defaults: Vec<serde_json::Value>,
}
pub(super) struct Context {
    pub request: Option<Request<Body>>,
    pub resources: Arc<super::resource_budget::Resources>,
    pub peer: SocketAddr,
    pub local: SocketAddr,
    pub tls: bool,
    pub authority: String,
    pub client_ip: IpAddr,
    pub trusted: bool,
    pub drain: CancellationToken,
    pub business: Arc<BusinessGuard>,
    pub original_uri: Uri,
    pub values: HashMap<String, String>,
    pub immediate: HeaderMap,
    deferred: Vec<HeaderOps>,
    groups: HashSet<String>,
    maps: Vec<LazyMap>,
}
impl Context {
    pub fn req(&self) -> &Request<Body> {
        self.request
            .as_ref()
            .expect("request is consumed only by terminal proxy")
    }
    pub fn req_mut(&mut self) -> &mut Request<Body> {
        self.request
            .as_mut()
            .expect("request is consumed only by terminal proxy")
    }
    pub fn expand(&self, s: &str) -> Result<String> {
        replace(s, true, |name| self.lookup(name))
    }
    pub fn lookup(&self, name: &str) -> Option<String> {
        self.lookup_depth(name, 0)
    }
    fn expand_depth(&self, input: &str, depth: usize) -> Option<String> {
        replace(input, true, |key| self.lookup_depth(key, depth + 1)).ok()
    }
    fn lookup_depth(&self, name: &str, depth: usize) -> Option<String> {
        if let Some(value) = crate::http_config::helpers::global_lookup(name) {
            return Some(value);
        }
        if depth > 64 {
            return None;
        }
        if let Some(value) = self.values.get(name) {
            return Some(value.clone());
        }
        let req = self.request.as_ref();
        Some(match name {
            "http.shutting_down" => self.business.generation().shutting_down().to_string(),
            "http.time_until_shutdown" => self
                .business
                .generation()
                .time_until_shutdown()
                .unwrap_or_default(),
            "http.request.hostport" => self.authority.clone(),
            "http.request.host" => hostname(&self.authority),
            "http.request.port" => self
                .authority
                .parse::<http::uri::Authority>()
                .ok()
                .and_then(|a| a.port_u16())
                .map(|p| p.to_string())
                .unwrap_or_default(),
            "http.request.remote" => self.peer.to_string(),
            "http.request.remote.host" => self.peer.ip().to_string(),
            "http.request.remote.port" => self.peer.port().to_string(),
            "http.request.local" => self.local.to_string(),
            "http.request.local.host" => self.local.ip().to_string(),
            "http.request.local.port" => self.local.port().to_string(),
            "http.request.client_ip" => self.client_ip.to_string(),
            "http.request.scheme" => {
                if self.tls {
                    "https".into()
                } else {
                    "http".into()
                }
            }
            "http.request.method" => req?.method().to_string(),
            "http.request.uri" => req?
                .uri()
                .path_and_query()
                .map(|x| x.as_str())
                .unwrap_or("/")
                .to_owned(),
            "http.request.uri.path" => decoded_path(req?.uri().path()).ok()?,
            "http.request.uri.query" => req?.uri().query().unwrap_or_default().to_owned(),
            "http.request.orig_uri" => self
                .original_uri
                .path_and_query()
                .map(|x| x.as_str())
                .unwrap_or("/")
                .to_owned(),
            "http.request.orig_uri.path" => decoded_path(self.original_uri.path()).ok()?,
            "http.request.orig_uri.query" => {
                self.original_uri.query().unwrap_or_default().to_owned()
            }
            "http.request.proto" => match req?.version() {
                Version::HTTP_2 => "HTTP/2.0",
                Version::HTTP_10 => "HTTP/1.0",
                _ => "HTTP/1.1",
            }
            .into(),
            "http.vars.root" => ".".into(),
            _ if name.starts_with("http.request.header.") => {
                let field = &name[20..];
                if field.eq_ignore_ascii_case("Host") {
                    self.authority.clone()
                } else {
                    req?.headers()
                        .get(field)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or_default()
                        .to_owned()
                }
            }
            _ if name.starts_with("http.request.uri.query.") => {
                url::form_urlencoded::parse(req?.uri().query().unwrap_or_default().as_bytes())
                    .find(|(key, _)| key == &name[23..])
                    .map(|(_, v)| v.into_owned())
                    .unwrap_or_default()
            }
            _ => {
                for map in &self.maps {
                    let Some(index) = map.destinations.iter().position(|dest| dest == name) else {
                        continue;
                    };
                    let input = self.expand_depth(&map.source, depth)?;
                    for entry in &map.mappings {
                        let Some(output) = entry.outputs.get(index).filter(|v| !v.is_null()) else {
                            continue;
                        };
                        let output = if let serde_json::Value::String(s) = output {
                            s.clone()
                        } else {
                            crate::http_config::helpers::value_string(output)
                        };
                        if let Some(regex) = &entry.regex {
                            if let Some(captures) = regex.captures(&input) {
                                let mut expanded = String::new();
                                captures.expand(&output, &mut expanded);
                                return Some(expanded);
                            }
                        } else if entry.input.as_deref().unwrap_or_default() == input {
                            return self.expand_depth(&output, depth);
                        }
                    }
                    return Some(
                        map.defaults
                            .get(index)
                            .and_then(|v| v.as_str())
                            .and_then(|s| self.expand_depth(s, depth))
                            .unwrap_or_default(),
                    );
                }
                return None;
            }
        })
    }
}
fn request_authority<B>(request: &Request<B>) -> Result<String, ()> {
    let authority = request
        .uri()
        .authority()
        .map(|a| a.as_str())
        .or_else(|| {
            request
                .headers()
                .get(http::header::HOST)
                .and_then(|v| v.to_str().ok())
        })
        .unwrap_or_default()
        .to_owned();
    if (request.version() != Version::HTTP_10 && authority.is_empty())
        || authority.contains(['@', '/', '\r', '\n', ' ', '\t'])
    {
        return Err(());
    }
    if request.headers().get_all(http::header::HOST).iter().count() > 1 {
        return Err(());
    }
    Ok(authority)
}
pub(super) fn proof_response<B>(
    registry: &ChallengeRegistry,
    request: &Request<B>,
) -> Result<Option<Response<Body>>, ()> {
    let authority = request_authority(request)?;
    Ok(proof_for_authority(registry, request, &authority))
}
fn proof_for_authority<B>(
    registry: &ChallengeRegistry,
    request: &Request<B>,
    authority: &str,
) -> Option<Response<Body>> {
    if let Some(token) = request
        .uri()
        .path()
        .strip_prefix("/.well-known/acme-challenge/")
        && let Some(proof) = registry.lookup_http(authority, token)
    {
        let mut response = simple(StatusCode::OK, proof);
        response
            .headers_mut()
            .insert(http::header::SERVER, HeaderValue::from_static("Caddy"));
        response.headers_mut().insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain"),
        );
        return Some(response);
    }
    None
}
pub(super) async fn handle(
    inner: Arc<Inner>,
    server: Arc<ActiveServer>,
    request: Request<Incoming>,
    peer: SocketAddr,
    local: SocketAddr,
    tls: bool,
    business: Arc<BusinessGuard>,
) -> Response<Body> {
    let authority = match request_authority(&request) {
        Ok(authority) => authority,
        Err(()) => return simple(StatusCode::BAD_REQUEST, "Bad Request\n"),
    };
    if let Some(response) = proof_for_authority(&inner.registry, &request, &authority) {
        return response;
    }
    let trusted = server
        .plan
        .trusted_proxies
        .iter()
        .any(|range| range.contains(&peer.ip()));
    let client_ip = client_ip(request.headers(), peer.ip(), trusted, &server.plan);
    let original_uri = request.uri().clone();
    let trailer_metadata = request
        .extensions()
        .get::<super::trailer_policy::RequestMetadata>()
        .cloned()
        .unwrap_or_default();
    let (parts, body) = request.into_parts();
    let body = super::trailer_policy::validate_incoming(body, &trailer_metadata);
    let body = IdleBody::new(body, server.plan.read_idle_timeout).boxed_unsync();
    let mut ctx = Context {
        request: Some(Request::from_parts(parts, body)),
        resources: inner.resources.clone(),
        peer,
        local,
        tls,
        authority,
        client_ip,
        trusted,
        drain: business.generation().drain.clone(),
        business,
        original_uri,
        values: HashMap::new(),
        immediate: {
            let mut h = HeaderMap::new();
            h.insert(http::header::SERVER, HeaderValue::from_static("Caddy"));
            h
        },
        deferred: Vec::new(),
        groups: HashSet::new(),
        maps: Vec::new(),
    };
    let result = routes(&server.plan.routes, &mut ctx, &inner, &server).await;
    let mut response = match result {
        Ok(Flow::Response(response)) => response,
        Ok(Flow::Continue | Flow::Stop) => simple(StatusCode::OK, Bytes::new()),
        Err(error) => {
            let status = populate_error(&mut ctx, &error);
            // The failed handler stack has unwound. Its deferred writers did
            // not commit headers and must not wrap the server error routes.
            ctx.deferred.clear();
            ctx.groups.clear();
            match routes(&server.plan.errors, &mut ctx, &inner, &server).await {
                Ok(Flow::Response(response)) => response,
                _ => simple(status, Bytes::new()),
            }
        }
    };
    // Non-deferred writer headers exist before a terminal handler copies its
    // headers; terminal headers append, matching Caddy's shared writer model.
    let mut headers = std::mem::take(&mut ctx.immediate);
    for (name, value) in response.headers().iter() {
        headers.append(name, value.clone());
    }
    for operations in ctx.deferred.iter().rev() {
        if apply_headers(&mut headers, operations, &ctx).is_err() {
            return simple(StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error\n");
        }
    }
    *response.headers_mut() = headers;
    if ctx
        .request
        .as_ref()
        .is_some_and(|r| r.method() == Method::HEAD)
    {
        *response.body_mut() = full(Bytes::new());
    }
    response
}
enum Flow {
    Continue,
    Stop,
    Response(Response<Body>),
}
pub(super) fn descriptor_exhausted(error: &std::io::Error) -> bool {
    #[cfg(unix)]
    {
        matches!(
            error.raw_os_error(),
            Some(libc::EMFILE) | Some(libc::ENFILE)
        )
    }
    #[cfg(not(unix))]
    {
        let _ = error;
        false
    }
}
pub(super) fn file_io_failure(ctx: &mut Context, error: &std::io::Error) -> anyhow::Error {
    if descriptor_exhausted(error) {
        return budget_failure(ctx, super::resource_budget::BudgetError::Overloaded);
    }
    if error.kind() == std::io::ErrorKind::PermissionDenied {
        return failure(StatusCode::FORBIDDEN);
    }
    anyhow::anyhow!("file operation unavailable")
}
pub(super) fn budget_failure(
    ctx: &mut Context,
    error: super::resource_budget::BudgetError,
) -> anyhow::Error {
    match error {
        super::resource_budget::BudgetError::Overloaded => {
            ctx.immediate
                .insert(http::header::RETRY_AFTER, HeaderValue::from_static("1"));
            failure(StatusCode::SERVICE_UNAVAILABLE)
        }
        super::resource_budget::BudgetError::WorkerFailed => {
            failure(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}
#[derive(Debug)]
struct HttpError {
    status: StatusCode,
    id: String,
    trace: String,
}
impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{{id={}}} {}: HTTP {}",
            self.id,
            self.trace,
            self.status.as_u16()
        )
    }
}
impl std::error::Error for HttpError {}
#[track_caller]
pub(super) fn failure(status: StatusCode) -> anyhow::Error {
    let origin = std::panic::Location::caller();
    let mut random = [0u8; 9];
    if rustls::crypto::ring::default_provider()
        .secure_random
        .fill(&mut random)
        .is_err()
    {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        let counter = SEQ
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            .to_le_bytes();
        random[..8].copy_from_slice(&counter);
    }
    let chars = b"abcdefghijkmnpqrstuvwxyz23456789";
    HttpError {
        status,
        id: random
            .into_iter()
            .map(|b| chars[b as usize % chars.len()] as char)
            .collect(),
        trace: format!(
            "http_runtime ({}:{})",
            std::path::Path::new(origin.file())
                .file_name()
                .unwrap_or_default()
                .to_string_lossy(),
            origin.line()
        ),
    }
    .into()
}
fn populate_error(ctx: &mut Context, error: &anyhow::Error) -> StatusCode {
    let fallback = failure(StatusCode::INTERNAL_SERVER_ERROR);
    let error = error.downcast_ref::<HttpError>().unwrap_or_else(|| {
        fallback
            .downcast_ref::<HttpError>()
            .expect("structured fallback error")
    });
    for (key, value) in [
        ("http.error", error.to_string()),
        ("http.error.status_code", error.status.as_u16().to_string()),
        (
            "http.error.status_text",
            error
                .status
                .canonical_reason()
                .unwrap_or("Error")
                .to_owned(),
        ),
        (
            "http.error.message",
            error
                .status
                .canonical_reason()
                .unwrap_or("Error")
                .to_owned(),
        ),
        ("http.error.id", error.id.clone()),
        ("http.error.trace", error.trace.clone()),
    ] {
        ctx.values.insert(key.into(), value);
    }
    error.status
}
type ResponseFuture<'a> = Pin<Box<dyn Future<Output = Result<Flow>> + Send + 'a>>;
fn routes<'a>(
    list: &'a [Route],
    ctx: &'a mut Context,
    inner: &'a Arc<Inner>,
    server: &'a Arc<ActiveServer>,
) -> ResponseFuture<'a> {
    Box::pin(async move {
        for route in list {
            if route.group.as_ref().is_some_and(|g| ctx.groups.contains(g)) {
                continue;
            }
            if !match_sets(&route.matchers, ctx).await? {
                continue;
            }
            if let Some(group) = &route.group {
                ctx.groups.insert(group.clone());
            }
            match handlers(&route.handlers, ctx, inner, server).await? {
                Flow::Continue if route.terminal => return Ok(Flow::Stop),
                Flow::Continue => {}
                flow => return Ok(flow),
            }
        }
        Ok(Flow::Continue)
    })
}
fn handlers<'a>(
    list: &'a [Handler],
    ctx: &'a mut Context,
    inner: &'a Arc<Inner>,
    server: &'a Arc<ActiveServer>,
) -> ResponseFuture<'a> {
    Box::pin(async move {
        for handler in list {
            match handler {
                Handler::StaticResponse {
                    status,
                    body,
                    headers,
                    close,
                } => {
                    let status = if status.is_empty() {
                        ctx.values
                            .get("http.error.status_code")
                            .and_then(|s| s.parse::<u16>().ok())
                            .and_then(|s| StatusCode::from_u16(s).ok())
                            .unwrap_or(StatusCode::OK)
                    } else {
                        StatusCode::from_u16(ctx.expand(status)?.parse()?)
                            .map_err(|_| failure(StatusCode::INTERNAL_SERVER_ERROR))?
                    };
                    let bytes = replace(body, false, |name| ctx.lookup(name))?;
                    let mut response = simple(status, bytes.clone());
                    *response.headers_mut() = std::mem::take(&mut ctx.immediate);
                    for (name, values) in &headers.set {
                        let name =
                            HeaderName::try_from(replace(name, false, |name| ctx.lookup(name))?)?;
                        response.headers_mut().remove(&name);
                        for value in values {
                            response.headers_mut().append(
                                name.clone(),
                                HeaderValue::from_str(&replace(value, false, |name| {
                                    ctx.lookup(name)
                                })?)?,
                            );
                        }
                    }
                    if !bytes.is_empty()
                        && response
                            .headers()
                            .get(http::header::CONTENT_TYPE)
                            .is_none_or(|v| v.is_empty())
                    {
                        let trimmed = bytes.trim();
                        let json = trimmed.len() > 2
                            && ((trimmed.starts_with('{') && trimmed.ends_with('}'))
                                || (trimmed.starts_with('[') && trimmed.ends_with(']')))
                            && serde_json::from_str::<serde_json::Value>(trimmed).is_ok();
                        response.headers_mut().insert(
                            http::header::CONTENT_TYPE,
                            HeaderValue::from_static(if json {
                                "application/json"
                            } else {
                                "text/plain; charset=utf-8"
                            }),
                        );
                    }
                    response
                        .headers_mut()
                        .entry(http::header::CONTENT_LENGTH)
                        .or_insert(HeaderValue::from_str(&bytes.len().to_string())?);
                    if *close && ctx.req().version() != Version::HTTP_2 {
                        response
                            .headers_mut()
                            .insert(http::header::CONNECTION, HeaderValue::from_static("close"));
                    }
                    return Ok(Flow::Response(response));
                }
                Handler::Headers {
                    request,
                    response,
                    deferred,
                } => {
                    let mut headers = ctx.req().headers().clone();
                    // Go stores Host outside Header. Mirror ApplyToRequest:
                    // append the authority, run ordinary operations, retain
                    // the final Host value as the request authority.
                    headers.remove(http::header::HOST);
                    headers.append(http::header::HOST, HeaderValue::from_str(&ctx.authority)?);
                    apply_headers(&mut headers, request, ctx)?;
                    ctx.authority = headers
                        .get_all(http::header::HOST)
                        .iter()
                        .next_back()
                        .map(|value| value.to_str().map(str::to_owned))
                        .transpose()?
                        .unwrap_or_default();
                    headers.remove(http::header::HOST);
                    *ctx.req_mut().headers_mut() = headers;
                    if *deferred {
                        ctx.deferred.push(response.clone());
                    } else {
                        let mut headers = std::mem::take(&mut ctx.immediate);
                        apply_headers(&mut headers, response, ctx)?;
                        ctx.immediate = headers;
                    }
                }
                Handler::Subroute {
                    routes: list,
                    errors,
                    errors_configured,
                } => {
                    let pending_headers = ctx.deferred.len();
                    let result = routes(list, ctx, inner, server).await;
                    match result {
                        Ok(Flow::Continue) => {}
                        Ok(flow) => return Ok(flow),
                        Err(error) if *errors_configured => {
                            // Keep wrappers outside this subroute, while
                            // dropping the failed inner route's deferred work.
                            ctx.deferred.truncate(pending_headers);
                            populate_error(ctx, &error);
                            match routes(errors, ctx, inner, server).await? {
                                Flow::Continue => {}
                                flow => return Ok(flow),
                            }
                        }
                        Err(error) => return Err(error),
                    }
                }
                Handler::Rewrite {
                    uri,
                    method,
                    strip_path_prefix,
                    strip_path_suffix,
                } => {
                    if let Some(method) = method {
                        let method = ctx.expand(method)?.to_uppercase().parse::<Method>()?;
                        *ctx.req_mut().method_mut() = method;
                    }
                    let mut target = ctx
                        .req()
                        .uri()
                        .path_and_query()
                        .map(|x| x.as_str())
                        .unwrap_or("/")
                        .to_owned();
                    if let Some(uri) = uri {
                        target = super::rewrite_uri::rewrite_uri(uri, ctx.req().uri(), |name| {
                            ctx.lookup(name)
                        })?;
                    }
                    if strip_path_prefix.is_some() || strip_path_suffix.is_some() {
                        let (path, query) = target
                            .split_once('?')
                            .map_or((target.as_str(), None), |(p, q)| (p, Some(q)));
                        let query = query.map(str::to_owned);
                        let mut path = decoded_path(path)?;
                        if let Some(prefix) = strip_path_prefix {
                            let prefix = ctx.expand(prefix)?;
                            if let Some(rest) = path.strip_prefix(&prefix) {
                                path = rest.to_owned();
                            }
                        }
                        if let Some(suffix) = strip_path_suffix {
                            let suffix = ctx.expand(suffix)?;
                            if let Some(rest) = path.strip_suffix(&suffix) {
                                path = rest.to_owned();
                            }
                        }
                        if !path.starts_with('/') {
                            path.insert(0, '/');
                        }
                        target = path;
                        if let Some(query) = query {
                            target.push('?');
                            target.push_str(&query);
                        }
                    }
                    ensure!(
                        !target.contains(['\r', '\n', '\0']),
                        "invalid rewritten request URI"
                    );
                    let url = url::Url::parse(&format!("http://rewrite.invalid{target}"))?;
                    let target = match url.query() {
                        Some(q) => format!("{}?{q}", url.path()),
                        None => url.path().to_owned(),
                    };
                    *ctx.req_mut().uri_mut() = target.parse()?;
                }
                Handler::Vars(vars) => {
                    for (name, value) in vars {
                        let value = match value {
                            serde_json::Value::String(s) => ctx.expand(s)?,
                            serde_json::Value::Null => String::new(),
                            other => crate::http_config::helpers::value_string(other),
                        };
                        ctx.values.insert(format!("http.vars.{name}"), value);
                    }
                }
                Handler::Map {
                    source,
                    destinations,
                    mappings,
                    defaults,
                } => {
                    // Caddy maps are lazy replacer providers; source and literal
                    // outputs must observe mutations made by later middleware.
                    ctx.maps.push(LazyMap {
                        source: source.clone(),
                        destinations: destinations.clone(),
                        mappings: mappings.clone(),
                        defaults: defaults.clone(),
                    });
                }
                Handler::Authentication {
                    accounts,
                    realm,
                    cache,
                } => {
                    let authorization = ctx
                        .req()
                        .headers()
                        .get(http::header::AUTHORIZATION)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or_default();
                    let decoded = authorization
                        .get(..6)
                        .filter(|prefix| prefix.eq_ignore_ascii_case("Basic "))
                        .and_then(|_| {
                            base64::engine::GeneralPurpose::new(
                                &base64::alphabet::STANDARD,
                                base64::engine::general_purpose::GeneralPurposeConfig::new()
                                    .with_decode_allow_trailing_bits(true),
                            )
                            .decode(&authorization[6..])
                            .ok()
                        })
                        .map(zeroize::Zeroizing::new);
                    let credentials = decoded.as_ref().and_then(|bytes| {
                        let colon = bytes.iter().position(|b| *b == b':')?;
                        let user = String::from_utf8(bytes[..colon].to_vec()).ok();
                        Some((user, zeroize::Zeroizing::new(bytes[colon + 1..].to_vec())))
                    });
                    drop(decoded);
                    let mut authenticated = None;
                    if let Some((username, password)) = credentials {
                        let account = username
                            .as_deref()
                            .and_then(|name| accounts.iter().find(|a| a.username == name));
                        let exists = account.is_some();
                        let hash = account
                            .map(|a| a.password.as_str())
                            .unwrap_or(super::auth_cache::FAKE_BCRYPT_HASH)
                            .to_owned();
                        let result = if let Some(cache) = cache {
                            cache.verify(ctx.resources.clone(), hash, password).await
                        } else {
                            let count = ctx.resources.auth_comparisons.clone();
                            ctx.resources
                                .auth
                                .run(move || {
                                    count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    bcrypt::verify(password.as_slice(), &hash)
                                        .map_err(|_| super::auth_cache::AuthError::HashInvalid)
                                })
                                .await
                                .map_err(|e| match e {
                                    super::resource_budget::BudgetError::Overloaded => {
                                        super::auth_cache::AuthError::Overloaded
                                    }
                                    super::resource_budget::BudgetError::WorkerFailed => {
                                        super::auth_cache::AuthError::WorkerFailed
                                    }
                                })
                                .and_then(std::convert::identity)
                        };
                        let accepted = match result {
                            Ok(value) => value,
                            Err(super::auth_cache::AuthError::HashInvalid) => false,
                            Err(super::auth_cache::AuthError::Overloaded) => {
                                return Err(budget_failure(
                                    ctx,
                                    super::resource_budget::BudgetError::Overloaded,
                                ));
                            }
                            Err(super::auth_cache::AuthError::WorkerFailed) => {
                                return Err(failure(StatusCode::INTERNAL_SERVER_ERROR));
                            }
                        };
                        if accepted && exists {
                            authenticated = username;
                        }
                    }
                    if let Some(username) = authenticated {
                        ctx.values.insert("http.auth.user.id".into(), username);
                    } else {
                        ensure!(
                            !realm.contains(['\r', '\n', '\0']),
                            "invalid authentication realm"
                        );
                        let realm = realm.replace('\\', "\\\\").replace('"', "\\\"");
                        ctx.immediate.insert(
                            http::header::WWW_AUTHENTICATE,
                            HeaderValue::from_str(&format!("Basic realm=\"{realm}\""))?,
                        );
                        return Err(failure(StatusCode::UNAUTHORIZED));
                    }
                }
                Handler::FileServer {
                    root,
                    hide,
                    index_names,
                    pass_thru,
                } => match super::files::serve(ctx, root.as_deref(), hide, index_names).await? {
                    Some(response) => return Ok(Flow::Response(response)),
                    None if *pass_thru => {}
                    None => return Err(failure(StatusCode::NOT_FOUND)),
                },
                Handler::ReverseProxy(config) => {
                    return Ok(Flow::Response(
                        super::proxy::serve(ctx, config, server, inner)
                            .await
                            .map_err(|error| {
                                if error.is::<HttpError>() {
                                    error
                                } else if error.chain().any(|source| {
                                    source
                                        .downcast_ref::<std::io::Error>()
                                        .is_some_and(|e| e.kind() == std::io::ErrorKind::TimedOut)
                                        || source
                                            .downcast_ref::<hyper::Error>()
                                            .is_some_and(hyper::Error::is_timeout)
                                }) {
                                    failure(StatusCode::GATEWAY_TIMEOUT)
                                } else {
                                    failure(StatusCode::BAD_GATEWAY)
                                }
                            })?,
                    ));
                }
            }
        }
        Ok(Flow::Continue)
    })
}
fn match_sets<'a>(
    sets: &'a [MatcherSet],
    ctx: &'a mut Context,
) -> Pin<Box<dyn Future<Output = Result<bool>> + Send + 'a>> {
    Box::pin(async move {
        if sets.is_empty() {
            return Ok(true);
        }
        for set in sets {
            let mut all = true;
            for matcher in set {
                if !matches(matcher, ctx).await? {
                    all = false;
                    break;
                }
            }
            if all {
                return Ok(true);
            }
        }
        Ok(false)
    })
}
fn matches<'a>(
    matcher: &'a Matcher,
    ctx: &'a mut Context,
) -> Pin<Box<dyn Future<Output = Result<bool>> + Send + 'a>> {
    Box::pin(async move {
        Ok(match matcher {
            Matcher::Host(hosts) => hosts.iter().any(|host| {
                ctx.expand(host)
                    .is_ok_and(|host| host_match(&host, &hostname(&ctx.authority)))
            }),
            Matcher::Path(patterns) => {
                let path = decoded_path(ctx.req().uri().path())?.to_lowercase();
                let mut found = false;
                for pattern in patterns {
                    let pattern = ctx.expand(pattern)?;
                    if path_match(&pattern, &path) {
                        found = true;
                        break;
                    }
                }
                found
            }
            Matcher::PathRegex { name, regex } => {
                let path = decoded_path(ctx.req().uri().path())?;
                if let Some(captures) = regex.captures(&path) {
                    for (i, value) in captures.iter().enumerate() {
                        if let Some(value) = value {
                            ctx.values
                                .insert(format!("http.regexp.{i}"), value.as_str().to_owned());
                            if !name.is_empty() {
                                ctx.values.insert(
                                    format!("http.regexp.{name}.{i}"),
                                    value.as_str().to_owned(),
                                );
                            }
                        }
                    }
                    for named in regex.capture_names().flatten() {
                        if let Some(value) = captures.name(named) {
                            ctx.values
                                .insert(format!("http.regexp.{named}"), value.as_str().to_owned());
                            if !name.is_empty() {
                                ctx.values.insert(
                                    format!("http.regexp.{name}.{named}"),
                                    value.as_str().to_owned(),
                                );
                            }
                        }
                    }
                    true
                } else {
                    false
                }
            }
            Matcher::Method(methods) => methods.iter().any(|m| m == ctx.req().method().as_str()),
            Matcher::Header(headers) => {
                let mut all = true;
                for (name, patterns) in headers {
                    let values = if name.eq_ignore_ascii_case("host") {
                        vec![ctx.authority.as_bytes()]
                    } else {
                        ctx.req()
                            .headers()
                            .get_all(name)
                            .iter()
                            .map(HeaderValue::as_bytes)
                            .collect::<Vec<_>>()
                    };
                    let matched = match patterns {
                        None => values.is_empty(),
                        Some(patterns) if patterns.is_empty() => !values.is_empty(),
                        Some(patterns) => patterns.iter().any(|p| {
                            ctx.expand(p).is_ok_and(|p| {
                                values
                                    .iter()
                                    .any(|v| header_value_bytes_pattern(p.as_bytes(), v))
                            })
                        }),
                    };
                    if !matched {
                        all = false;
                        break;
                    }
                }
                all
            }
            Matcher::Not(sets) => !match_sets(sets, ctx).await?,
            Matcher::RemoteIp(ranges) => ranges.iter().any(|r| r.contains(&ctx.peer.ip())),
            Matcher::ClientIp(ranges) => ranges.iter().any(|r| r.contains(&ctx.client_ip)),
            Matcher::Protocol(protocol) => match protocol.as_str() {
                "http" => !ctx.tls,
                "https" => ctx.tls,
                "grpc" => ctx
                    .req()
                    .headers()
                    .get(http::header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .is_some_and(|v| v.starts_with("application/grpc")),
                "http/2" => ctx.req().version() == Version::HTTP_2,
                "http/1.0" => ctx.req().version() == Version::HTTP_10,
                _ => ctx.req().version() == Version::HTTP_11,
            },
            Matcher::File { root, try_files } => {
                let base = ctx.expand(root.as_deref().unwrap_or("{http.vars.root}"))?;
                let mut found = false;
                for candidate in try_files {
                    let candidate = ctx.expand(candidate)?;
                    let path = safe_join(Path::new(&base), &candidate)?;
                    let lookup_path = path.clone();
                    let lookup = ctx
                        .resources
                        .metadata
                        .run(move || std::fs::metadata(lookup_path))
                        .await
                        .map_err(|error| budget_failure(ctx, error))?;
                    if let Err(error) = &lookup
                        && descriptor_exhausted(error)
                    {
                        return Err(file_io_failure(ctx, error));
                    }
                    if let Ok(metadata) = lookup {
                        if metadata.is_dir() != candidate.ends_with('/') {
                            continue;
                        }
                        ctx.values
                            .insert("http.matchers.file.relative".into(), candidate);
                        ctx.values.insert(
                            "http.matchers.file.absolute".into(),
                            path.to_string_lossy().into_owned(),
                        );
                        ctx.values.insert(
                            "http.matchers.file.type".into(),
                            if metadata.is_dir() {
                                "directory"
                            } else {
                                "file"
                            }
                            .into(),
                        );
                        found = true;
                        break;
                    }
                }
                found
            }
        })
    })
}
pub(super) fn apply_headers(
    headers: &mut HeaderMap,
    operations: &HeaderOps,
    ctx: &Context,
) -> Result<()> {
    let expand = |value: &str| replace(value, false, |name| ctx.lookup(name));
    // Caddy clears '*' first, then adds, sets, and finally deletes matching
    // names. Unknown placeholders are preserved by ReplaceKnown.
    if operations
        .delete
        .iter()
        .map(|s| expand(s))
        .collect::<Result<Vec<_>>>()?
        .iter()
        .any(|s| s == "*")
    {
        headers.clear();
    }
    for (name, values) in &operations.add {
        let name = HeaderName::try_from(expand(name)?)?;
        for value in values {
            headers.append(name.clone(), HeaderValue::from_str(&expand(value)?)?);
        }
    }
    for (name, values) in &operations.set {
        let name = HeaderName::try_from(expand(name)?)?;
        let values = values
            .iter()
            .map(|s| expand(s))
            .collect::<Result<Vec<_>>>()?;
        headers.remove(&name);
        if name == http::header::SET_COOKIE && values.len() > 1 {
            for value in values {
                headers.append(name.clone(), HeaderValue::from_str(&value)?);
            }
        } else {
            headers.insert(name, HeaderValue::from_str(&values.join(","))?);
        }
    }
    for pattern in &operations.delete {
        let pattern = expand(pattern)?;
        if pattern == "*" {
            continue;
        }
        let names = headers
            .keys()
            .filter(|name| header_pattern(&pattern, name.as_str()))
            .cloned()
            .collect::<Vec<_>>();
        for name in names {
            headers.remove(name);
        }
    }
    Ok(())
}
pub(super) fn hostname(authority: &str) -> String {
    authority
        .parse::<http::uri::Authority>()
        .map(|v| v.host().trim_end_matches('.').to_ascii_lowercase())
        .unwrap_or_else(|_| authority.trim_end_matches('.').to_ascii_lowercase())
}
fn host_match(pattern: &str, host: &str) -> bool {
    let p = pattern.trim_end_matches('.').split('.').collect::<Vec<_>>();
    let h = host.trim_end_matches('.').split('.').collect::<Vec<_>>();
    p.len() == h.len()
        && p.iter()
            .zip(h)
            .all(|(p, h)| *p == "*" || p.eq_ignore_ascii_case(h))
}
pub(super) fn decoded_path(path: &str) -> Result<String> {
    percent_encoding::percent_decode_str(path)
        .decode_utf8()
        .map(|s| s.into_owned())
        .map_err(|_| failure(StatusCode::BAD_REQUEST))
}
pub(super) fn clean_path(path: &str, merge_slashes: bool) -> String {
    let trailing = path.ends_with('/');
    let mut pieces = Vec::new();
    for part in path.split('/') {
        match part {
            "." => {}
            ".." => {
                pieces.pop();
            }
            "" if merge_slashes => {}
            part => pieces.push(part),
        }
    }
    let mut result = pieces.join("/");
    if !result.starts_with('/') {
        result.insert(0, '/');
    }
    if trailing && !result.ends_with('/') {
        result.push('/');
    }
    result
}
pub(super) fn safe_join(root: &Path, path: &str) -> Result<PathBuf> {
    ensure!(!path.contains('\0'), "NUL in file path");
    Ok(root.join(clean_path(path, true).trim_start_matches('/')))
}
fn path_match(pattern: &str, path: &str) -> bool {
    let path = clean_path(path, !pattern.contains("//"));
    let count = pattern.matches('*').count();
    if pattern == "*" {
        return true;
    }
    if count == 2 && pattern.starts_with('*') && pattern.ends_with('*') {
        return path.contains(&pattern[1..pattern.len() - 1]);
    }
    if count == 1 {
        if let Some(p) = pattern.strip_prefix('*') {
            return path.ends_with(p);
        }
        if let Some(p) = pattern.strip_suffix('*') {
            return path.starts_with(p);
        }
    }
    go_path_glob(pattern, &path)
}
pub(super) fn header_value_pattern(pattern: &str, value: &str) -> bool {
    header_value_bytes_pattern(pattern.as_bytes(), value.as_bytes())
}
// Behavioral reference: Caddy v2.11.7 modules/caddyhttp/matchers.go::matchHeaders.
pub(super) fn header_value_bytes_pattern(pattern: &[u8], value: &[u8]) -> bool {
    // Go matches raw header bytes, including obs-text, with stars only at the
    // ends. Middle stars and '?' remain literal; this is not a regular glob.
    if pattern == b"*" {
        true
    } else if pattern.starts_with(b"*") && pattern.ends_with(b"*") {
        let needle = &pattern[1..pattern.len() - 1];
        needle.is_empty() || value.windows(needle.len()).any(|window| window == needle)
    } else if let Some(suffix) = pattern.strip_prefix(b"*") {
        value.ends_with(suffix)
    } else if let Some(prefix) = pattern.strip_suffix(b"*") {
        value.starts_with(prefix)
    } else {
        pattern == value
    }
}
fn client_ip(headers: &HeaderMap, peer: IpAddr, trusted: bool, server: &ServerConfig) -> IpAddr {
    if !trusted {
        return peer;
    }
    if server.trusted_strict {
        for name in &server.client_ip_headers {
            let all = headers
                .get_all(name)
                .iter()
                .filter_map(|v| v.to_str().ok())
                .collect::<Vec<_>>()
                .join(",");
            for part in all.split(',').rev() {
                if let Some(ip) = parse_forwarded_ip(part)
                    && !server.trusted_proxies.iter().any(|r| r.contains(&ip))
                {
                    return ip;
                }
            }
        }
    } else {
        for name in &server.client_ip_headers {
            for value in headers.get_all(name).iter().filter_map(|v| v.to_str().ok()) {
                for part in value.split(',') {
                    if let Some(ip) = parse_forwarded_ip(part) {
                        return ip;
                    }
                }
            }
        }
    }
    peer
}
fn parse_forwarded_ip(raw: &str) -> Option<IpAddr> {
    let raw = raw.trim();
    if let Ok(addr) = raw.parse::<SocketAddr>() {
        return Some(addr.ip());
    }
    let raw = raw.split('%').next()?;
    raw.parse().ok()
}

struct IdleBody<B> {
    inner: Pin<Box<B>>,
    timer: Option<Pin<Box<tokio::time::Sleep>>>,
    timeout: Duration,
    failed: bool,
}
impl<B> IdleBody<B> {
    fn new(inner: B, timeout: Duration) -> Self {
        Self {
            inner: Box::pin(inner),
            timer: None,
            timeout,
            failed: false,
        }
    }
}
impl<B> hyper::body::Body for IdleBody<B>
where
    B: hyper::body::Body<Data = Bytes>,
    B::Error: Into<BoxError>,
{
    type Data = Bytes;
    type Error = BoxError;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, BoxError>>> {
        if self.failed {
            return std::task::Poll::Ready(None);
        }
        match self.inner.as_mut().poll_frame(cx) {
            std::task::Poll::Ready(Some(frame)) => {
                self.timer = None;
                std::task::Poll::Ready(Some(frame.map_err(Into::into)))
            }
            std::task::Poll::Ready(None) => {
                self.timer = None;
                std::task::Poll::Ready(None)
            }
            std::task::Poll::Pending => {
                if !self.timeout.is_zero() && self.timer.is_none() {
                    self.timer = Some(Box::pin(tokio::time::sleep(self.timeout)));
                }
                if self
                    .timer
                    .as_mut()
                    .is_some_and(|timer| timer.as_mut().poll(cx).is_ready())
                {
                    self.failed = true;
                    std::task::Poll::Ready(Some(Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "request body idle timeout",
                    )
                    .into())))
                } else {
                    std::task::Poll::Pending
                }
            }
        }
    }
    fn is_end_stream(&self) -> bool {
        self.failed || self.inner.is_end_stream()
    }
    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}

fn header_pattern(pattern: &str, value: &str) -> bool {
    header_value_pattern(&pattern.to_ascii_lowercase(), &value.to_ascii_lowercase())
}
