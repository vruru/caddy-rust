use crate::net_address::NetAddress;
use super::*;
#[path = "log_append.rs"]
mod log_append;
use crate::http_config::types::*;
use base64::Engine;
use http::{HeaderMap, HeaderName, HeaderValue, Method, Uri, Version};
use hyper::body::Body as _;
use std::{
    collections::{HashMap, HashSet},
    future::Future,
    net::IpAddr,
    path::{Path, PathBuf},
    pin::Pin,
};

#[path="request_replacer.rs"]mod request_replacer;
pub(super) use request_replacer::View as ReplacerView;
pub(super) type LazyMap=Arc<crate::http_config::types::MapPlan>;

pub(super) struct Context {
    pub(super) trace_context: Option<opentelemetry::Context>,
    pub(super) timeouts:Option<Box<super::route_timeouts::RequestTimeouts>>,
    pub(super) metrics: Option<Arc<crate::metrics::observe::Group>>,
    pub(super) request_started: std::time::Instant,
    pub(super) typed_vars: HashMap<String, Arc<serde_json::Value>>,
    pub(super) cel_body: Option<Bytes>,
    pub(super) cel_body_failure: Option<StatusCode>,
    pub request: Option<Request<Body>>,
    pub fastcgi_body_claimed: bool,
    pub(super) body_limit: Option<Arc<super::request_body::LimitState>>,
    pub(super) await_h2_response_head: bool,
    pub(super) original_framing: super::request_body::OriginalFraming,
    pub resources: Arc<super::resource_budget::Resources>,
    pub peer: NetAddress,
    pub local: NetAddress,
    pub tls: bool,
    pub(super) push_sni:Option<String>,
    access_names: Option<Vec<String>>,
    skip_access: bool,
    pub authority: String,
    pub client_ip: Option<IpAddr>,
    pub trusted: bool,
    pub drain: CancellationToken,
    pub business: Arc<BusinessGuard>,
    pub original_uri: Uri,
    request_content_length:i64,
    original_method: Method,
    error_status: Option<StatusCode>,
    access_start: Option<std::time::Instant>,
    log_fields: Option<Box<log_append::LogFields>>,
    pub values: HashMap<String, String>,
    pub(super) raw_regex_captures:super::request_regex::RawCaptures,
    pub(super) regex_capture_budget: usize,
    pub immediate: HeaderMap,
    informational: Option<InformationalOutput>,
    pub(super) close_after_response: bool,
    deferred: Vec<DeferredResponse>,
    groups: HashSet<String>,
    invoke_depth: u8,
    response_route_depth: u8,
    proxy_response: Option<Box<super::proxy::PreparedResponse>>,
    maps: Vec<LazyMap>,
    pub(super) probe: bool,
    // Last field: additional attempt metadata drops before its atomic credit.
    _map_text:std::sync::OnceLock<Arc<super::map_runtime::TextRetentions>>,
    _map_registration_credit:Option<native_write_policy::Lease>,
    _rewrite_view_credit:Option<Arc<native_write_policy::Lease>>,
}
#[path = "response_routes.rs"]
mod response_routes;

pub(super) struct UpstreamView<'a>{parent:&'a mut Context,view:Option<Context>,return_body:bool}
impl std::ops::Deref for UpstreamView<'_>{type Target=Context;fn deref(&self)->&Context{self.view.as_ref().expect("live upstream view")}}
impl std::ops::DerefMut for UpstreamView<'_>{fn deref_mut(&mut self)->&mut Context{self.view.as_mut().expect("live upstream view")}}
impl Drop for UpstreamView<'_>{fn drop(&mut self){if let Some(view)=self.view.take(){self.parent.merge_upstream(view,self.return_body);}}}

enum DeferredResponse {
    Push(Arc<super::push::LinkPlan>),
    Headers(HeaderOps),
    Encode(super::encode_response::ResponseEncoding),
    LogBody(usize),
    Metrics(Arc<crate::metrics::observe::Observation>),
    Trace(Arc<super::tracing::Observation>),
}
impl Context {
    pub(super) fn trace_tunnel(&self)->Option<Arc<super::tracing::Tunnel>>{
        super::tracing::Tunnel::capture(self.deferred.iter().filter_map(|entry|match entry{
            DeferredResponse::Trace(observation)=>Some(observation.clone()),_=>None,
        }))
    }
    // 保留 id：永不分配给配置 generation；类型按 BusinessGeneration::new 调整
    const PROBE_GENERATION_ID: u64 = u64::MAX;

    /// Go: 健康请求只携带 globals replacer、无 RemoteAddr/LocalAddr、无 access log。
    pub(super) fn for_probe(
        request: Request<Body>,
        resources: Arc<super::resource_budget::Resources>,
    ) -> Result<Self> {
        // 合成 generation：不计入真实业务请求；guard 随 ctx/诊断 owner 释放
        let generation = BusinessGeneration::new(
            Self::PROBE_GENERATION_ID,
            crate::http_config::HttpShutdownPolicy::default(),
        );
        let business = generation.begin()?;
        let (mut parts, body) = request.into_parts();
        // 绝对 URL → authority 进 ctx.authority；URI 规范成 origin-form，
        // 使 REQUEST_URI == Go origReq.URL.RequestURI()
        let authority = parts
            .uri
            .authority()
            .map(|a| a.as_str().to_owned())
            .unwrap_or_default();
        let origin: Uri = parts
            .uri
            .path_and_query()
            .map_or("/", |pq| pq.as_str())
            .parse()?;
        parts.uri = origin;
        let request = Request::from_parts(parts, body);
        let original_framing = super::request_body::original_framing(&request);
        let request_content_length=request.headers().get(http::header::CONTENT_LENGTH).and_then(|v|v.to_str().ok()).and_then(|v|v.parse().ok()).unwrap_or(if original_framing.chunked || !request.body().is_end_stream(){-1}else{0});
        let zero = SocketAddr::from(([0, 0, 0, 0], 0));
        Ok(Context {
            timeouts:None,
            metrics: None,
            trace_context: None,
            request_started: std::time::Instant::now(),
            raw_regex_captures:Default::default(),
        typed_vars: HashMap::new(),
            cel_body: None,
            cel_body_failure: None,
            original_uri: request.uri().clone(),
            original_method: request.method().clone(),
            request: Some(request),
            fastcgi_body_claimed: false,
            body_limit: None,
            await_h2_response_head: false,
            original_framing,
            request_content_length,
            resources,
            peer: zero.into(), // 占位；REMOTE_* 由 D2 置空，SERVER_ADDR 由 D3 移除
            local: zero.into(),
            push_sni:None,
            tls: false, // FastCGI 健康 scheme 恒为 http：无 HTTPS/SSL_*
            access_names: None,
            skip_access: true,
            authority,
            client_ip: Some(zero.ip()),
            trusted: false,
            drain: business.generation().drain.clone(),
            business,
            error_status: None,
            access_start: None,
            log_fields: None,
            values: HashMap::new(),
            regex_capture_budget: super::request_regex::CAPTURE_BYTES,
            immediate: HeaderMap::new(),
            informational: None,
            close_after_response: false,
            deferred: Vec::new(),
            groups: HashSet::new(),
            invoke_depth: 0,
            response_route_depth: 0,
            proxy_response: None,
            maps: Vec::new(),
            probe: true,
            _map_text:Default::default(),
            _map_registration_credit:None,
            _rewrite_view_credit:None,
        })
    }
    pub(super) fn upstream_view<'a>(&'a mut self,rewritten:&super::rewrite_runtime::Upstream)->Result<UpstreamView<'a>>{let view=self.fork_upstream(rewritten,None)?;Ok(UpstreamView{parent:self,view:Some(view),return_body:true})}
    pub(super) fn upstream_view_with_body<'a>(&'a mut self,rewritten:&super::rewrite_runtime::Upstream,body:Body)->Result<UpstreamView<'a>>{let view=self.fork_upstream(rewritten,Some(body))?;Ok(UpstreamView{parent:self,view:Some(view),return_body:false})}
    /// Independent proxy transport/matcher view. The inbound metadata is never
    /// modified, including while this owned view is suspended or cancelled.
    /// Exclusively borrowed replacer values/providers move to the view until
    /// Drop merges them back; no other task can borrow those mutable fields.
    fn fork_upstream(&mut self,rewritten:&super::rewrite_runtime::Upstream,body:Option<Body>)->Result<Self>{
        let header_bytes=self.req().headers().iter().map(|(k,v)|k.as_str().len()+v.as_bytes().len()+512).sum::<usize>();
        let bytes=header_bytes.checked_mul(4).and_then(|n|n.checked_add(rewritten.projection.state.bytes().saturating_mul(8))).and_then(|n|n.checked_add(self.authority.len()*2+self.req().extensions().len()*2048+16384)).ok_or_else(||failure(StatusCode::SERVICE_UNAVAILABLE))?;
        let credit=Arc::new(self.resources.rewrite_bytes.reserve(bytes).map_err(|_|failure(StatusCode::SERVICE_UNAVAILABLE))?);
        let mut request=Request::new(full(Bytes::new()));*request.method_mut()=Method::from_bytes(rewritten.method.as_str().as_bytes())?;*request.uri_mut()=rewritten.uri()?;*request.version_mut()=self.req().version();for(name,value)in self.req().headers(){let mut copy=HeaderValue::from_bytes(value.as_bytes())?;copy.set_sensitive(value.is_sensitive());request.headers_mut().append(HeaderName::from_bytes(name.as_str().as_bytes())?,copy);}*request.extensions_mut()=self.req().extensions().clone();
        request.extensions_mut().insert(super::rewrite_runtime::Original{uri:self.req().uri().clone(),method:self.req().method().clone(),projection:super::rewrite_runtime::projection(self.req()).cloned()});
        request.extensions_mut().insert(rewritten.projection.clone());
        *request.body_mut()=body.unwrap_or_else(||std::mem::replace(self.req_mut().body_mut(),full(Bytes::new())));
        Ok(Self{metrics:self.metrics.clone(),request_started:self.request_started,push_sni:self.push_sni.clone(),trace_context:self.trace_context.clone(),timeouts:self.timeouts.take(),raw_regex_captures:std::mem::take(&mut self.raw_regex_captures),typed_vars:std::mem::take(&mut self.typed_vars),cel_body:self.cel_body.take(),cel_body_failure:self.cel_body_failure,request:Some(request),fastcgi_body_claimed:self.fastcgi_body_claimed,body_limit:self.body_limit.clone(),await_h2_response_head:self.await_h2_response_head,original_framing:self.original_framing,resources:self.resources.clone(),peer:self.peer.clone(),local:self.local.clone(),tls:self.tls,access_names:None,skip_access:true,authority:self.authority.clone(),client_ip:self.client_ip,trusted:self.trusted,drain:self.drain.clone(),business:self.business.clone(),original_uri:self.original_uri.clone(),request_content_length:self.request_content_length,original_method:self.original_method.clone(),error_status:self.error_status,access_start:None,log_fields:None,values:std::mem::take(&mut self.values),regex_capture_budget:self.regex_capture_budget,immediate:std::mem::take(&mut self.immediate),informational:None,close_after_response:self.close_after_response,deferred:Vec::new(),groups:HashSet::new(),invoke_depth:self.invoke_depth,response_route_depth:self.response_route_depth,proxy_response:None,maps:std::mem::take(&mut self.maps),probe:self.probe,_map_text:std::mem::take(&mut self._map_text),_map_registration_credit:self._map_registration_credit.take(),_rewrite_view_credit:Some(credit)})
    }
    fn merge_upstream(&mut self,mut view:Self,return_body:bool){
        self.timeouts=view.timeouts.take();
        self.raw_regex_captures=std::mem::take(&mut view.raw_regex_captures);
        if return_body&&let Some(mut request)=view.request.take(){*self.req_mut().body_mut()=std::mem::replace(request.body_mut(),full(Bytes::new()));}
        self.maps=std::mem::take(&mut view.maps);self._map_registration_credit=view._map_registration_credit.take();self._map_text=std::mem::take(&mut view._map_text);self.values=std::mem::take(&mut view.values);self.typed_vars=std::mem::take(&mut view.typed_vars);self.cel_body=view.cel_body.take();self.cel_body_failure=view.cel_body_failure;if return_body{self.body_limit=view.body_limit.take();self.fastcgi_body_claimed=view.fastcgi_body_claimed;}self.regex_capture_budget=view.regex_capture_budget;self.immediate=std::mem::take(&mut view.immediate);self.close_after_response|=view.close_after_response;
        // Existing values/maps were moved, never copied. Their original
        // owners/budgets remain in force. The additional request/header/view
        // allocations die here before view._rewrite_view_credit drops last.
    }
    pub(super) fn template_original_method(&self)->&Method {&self.original_method}
    pub(super) fn template_content_length(&self)->i64 {
        self.req().extensions().get::<super::request_body::Replacement>().map_or(self.request_content_length,|replacement|replacement.length as i64)
    }
    pub(super) fn template_map_destinations(&self)->impl Iterator<Item=&str> {self.maps.iter().flat_map(|map|map.destinations.iter().map(String::as_str))}

    pub(super) fn bind_timeout_control(&mut self,control:hyper::ext::ResponseWriteControl)->Result<()> {
        match self.informational.as_mut(){
            Some(InformationalOutput::Http(sender))=>sender.bind_write_control(control)?,
            Some(InformationalOutput::Quic(sender))=>sender.bind_write_control(control)?,
            _=>{},
        }
        Ok(())
    }
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
        self.lookup_view().expand_primitive_text(s,true,false)
    }
    pub fn expand_bytes(&self,s:&str)->Result<Vec<u8>>{
        self.lookup_view().expand_primitive_bytes(s,true)
    }
    pub(super) fn lookup_view(&self)->ReplacerView<'_>{ReplacerView::new(self)}
    pub fn lookup_bytes(&self,name:&str)->Option<Vec<u8>>{self.lookup_view().lookup_bytes(name)}
    pub(super) fn replacer_uri(&self)->&Uri{let req=self.req();req.extensions().get::<super::rewrite_runtime::Original>().map_or_else(||req.uri(),|v|&v.uri)}
    pub(super) fn replacer_query(&self)->&[u8]{let req=self.req();if let Some(p)=super::rewrite_runtime::lookup_projection(req){&p.state.query}else{let uri=req.extensions().get::<super::rewrite_runtime::Original>().map_or_else(||req.uri(),|v|&v.uri);uri.query().unwrap_or_default().as_bytes()}}
    pub fn lookup(&self,name:&str)->Option<String>{self.lookup_view().lookup(name)}
    pub(super) fn text_owner(&self)->Option<Arc<super::map_runtime::TextRetentions>>{self._map_text.get().cloned()}
    pub(super) fn reserve_text_copy(&self,bytes:usize)->Result<()>{self.lookup_view().reserve_text_copy(bytes)}
    pub(super) fn root_resolved<'a>(&'a self,text:&'a str)->impl Future<Output=Result<String>>+Send+'a{let view=self.lookup_view();async move{view.root_resolved(text).await}}
    pub(super) fn lookup_text_resolved<'a>(&'a self,name:&'a str)->impl Future<Output=Result<Option<String>>>+Send+'a{let view=self.lookup_view();async move{view.lookup_text_resolved(name).await}}
    pub(super) fn expand_text_resolved<'a>(&'a self,text:&'a str,unknown_empty:bool)->impl Future<Output=Result<String>>+Send+'a{let view=self.lookup_view();async move{view.expand_text_resolved(text,unknown_empty).await}}
    pub(super) fn lookup_typed_resolved<'a>(&'a self,name:&'a str)->impl Future<Output=Result<Option<request_replacer::ResolvedValue>>>+Send+'a{let view=self.lookup_view();async move{view.lookup_typed_resolved(name).await}}
    pub(super) fn lookup_resolved<'a>(&'a self,name:&'a str)->impl Future<Output=Result<Option<Bytes>>>+Send+'a{let view=self.lookup_view();async move{view.lookup_resolved(name).await}}
    pub(super) fn expand_resolved<'a>(&'a self,text:&'a str,unknown_empty:bool)->impl Future<Output=Result<Bytes>>+Send+'a{let view=self.lookup_view();async move{view.expand_resolved(text,unknown_empty).await}}


}
// Match Caddy's SplitHostPort fallback: an absent or malformed port leaves
// the original authority intact, and valid bracketed hosts lose the brackets.
fn strict_host_matches(authority: &str, sni: &str) -> bool {
    let host = if let Some((host_port, port)) = authority.rsplit_once(':') {
        let host = if let Some(bracketed) = host_port.strip_prefix('[') {
            bracketed.strip_suffix(']')
        } else if !host_port.contains(':') {
            Some(host_port)
        } else {
            None
        };
        host.filter(|host| !host.contains(['[', ']']) && !port.contains(['[', ']']))
            .unwrap_or(authority)
    } else {
        authority
    };
    host.eq_ignore_ascii_case(sni)
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
pub(super) struct RequestOrigin<'a> {
    pub peer: NetAddress,
    pub local: NetAddress,
    pub tls: bool,
    pub sni: Option<&'a str>,
}

pub(super) async fn handle_business<B>(
    inner: Arc<Inner>,
    server: Arc<ActiveServer>,
    mut request: Request<B>,
    origin: RequestOrigin<'_>,
    business: Arc<BusinessGuard>,
    informational: Option<InformationalOutput>,
) -> Response<Body>
where
    B: hyper::body::Body<Data = Bytes> + Unpin + Send + 'static,
    B::Error: Into<BoxError>,
{
    let RequestOrigin {
        peer,
        local,
        tls,
        sni,
    } = origin;
    let authority = match request_authority(&request) {
        Ok(authority) => authority,
        Err(()) => return simple(StatusCode::BAD_REQUEST, "Bad Request\n"),
    };
    // net/http's general server OPTIONS handler sits outside the application
    // route stack. Preserve explicit authority/SNI validation while keeping
    // this server-wide capability response out of templates and access logs.
    if request.method()==Method::OPTIONS
        && request.uri().path_and_query().is_some_and(|path|path.as_str()=="*")
        && !(tls && server.plan.strict_sni_host
            && !strict_host_matches(&authority,sni.unwrap_or_default()))
    {
        let mut response=simple(StatusCode::OK,Bytes::new());
        response.headers_mut().insert(http::header::CONTENT_LENGTH,HeaderValue::from_static("0"));
        if matches!(request.version(),Version::HTTP_10|Version::HTTP_11)
            && !request.body().is_end_stream()
        {
            // Do not reproduce an unbounded post-handler body drain. Closing
            // only this H1 connection lets an unfinished sender receive the
            // capability response immediately without holding a socket forever.
            response.headers_mut().insert(http::header::CONNECTION,HeaderValue::from_static("close"));
        }
        return response;
    }
    let trusted = server
        .plan
        .trusted_proxies
        .iter()
        .any(|range| peer.ip().is_some_and(|ip|range.contains(&ip)));
    let client_ip = peer.ip().map(|ip|client_ip(request.headers(), ip, trusted, &server.plan));
    let access = server
        .plan
        .access_logs
        .as_ref()
        .zip(server.logging.as_ref())
        .and_then(|(config, logging)| {
            super::access_log::Access::start(
                logging.clone(),
                config,
                &request,
                &authority,
                &peer,
                client_ip,
                &inner.resources.access_capture,
            )
        })
        .map(Box::new);
    let original_framing = super::request_body::original_framing(&request);
    let request_content_length=request.headers().get(http::header::CONTENT_LENGTH).and_then(|value|value.to_str().ok()).and_then(|value|value.parse::<i64>().ok()).unwrap_or_else(||if original_framing.chunked||!request.body().is_end_stream(){-1}else{0});
    server.plan.header_aliases.sanitize(request.headers_mut());
    let original_uri = request.uri().clone();
    let original_method = request.method().clone();
    let trailer_metadata = request
        .extensions()
        .get::<super::trailer_policy::RequestMetadata>()
        .cloned()
        .unwrap_or_default();
    let push_seed=request.extensions_mut().remove::<super::route_timeouts::PushSeed>();
    let http3 = request.version() == Version::HTTP_3;
    let alt_svc = request.extensions().get::<super::h3::AltSvc>().cloned();
    let (parts, body) = request.into_parts();
    let body = super::trailer_policy::validate_incoming(body, &trailer_metadata);
    let body = if let Some(access) = &access {
        super::access_log::ReadCount {
            body,
            bytes: access.read.clone(),
        }
        .boxed_unsync()
    } else {
        body.boxed_unsync()
    };
    let mut ctx = Context {
        timeouts:push_seed.as_ref().and_then(|seed|seed.take()),
        metrics: crate::metrics::observe::Group::new(server.metrics.clone(),0),
        request_started: push_seed.as_ref().map_or_else(std::time::Instant::now,|seed|seed.started),
        raw_regex_captures:Default::default(),
        typed_vars: HashMap::new(),
        cel_body: None,
        cel_body_failure: None,
        request: Some(Request::from_parts(parts, body)),
        fastcgi_body_claimed: false,
        body_limit: None,
        await_h2_response_head: false,
        original_framing,
        resources: inner.resources.clone(),
        peer,
        local,
        tls,
        push_sni:sni.map(str::to_owned),
        access_names: None,
        skip_access: false,
        authority,
        client_ip,
        trusted,
        drain: business.generation().drain.clone(),
        business,
        original_uri,
        request_content_length,
        trace_context: None,
        original_method,
        error_status: None,
        access_start: access.as_ref().map(|access| access.started_at()),
        log_fields: None,
        values: HashMap::new(),
        regex_capture_budget: super::request_regex::CAPTURE_BYTES,
        immediate: {
            let mut h = HeaderMap::new();
            h.insert(http::header::SERVER, HeaderValue::from_static("Caddy"));
            if let Some(alt_svc) = alt_svc {
                h.insert(http::header::ALT_SVC, alt_svc.0);
            }
            h
        },
        informational,
        close_after_response: false,
        deferred: Vec::new(),
        groups: HashSet::new(),
        invoke_depth: 0,
        response_route_depth: 0,
        proxy_response: None,
        maps: Vec::new(),
        probe: false,
        _map_text:Default::default(),
            _map_registration_credit:None,
            _rewrite_view_credit:None,
    };
    let timeout_setup=if push_seed.is_some(){if let Some(control)=ctx.timeouts.as_deref().and_then(|state|state.control()){ctx.bind_timeout_control(control)}else{Err(anyhow::anyhow!("pushed timeout seed already consumed"))}}else{super::route_timeouts::install_server(&mut ctx,&server.plan)};
    let result = if timeout_setup.is_err(){
        ctx.close_after_response=true;
        Err(budget_failure(&mut ctx,super::resource_budget::BudgetError::Overloaded))
    } else if tls
        && server.plan.strict_sni_host
        && !strict_host_matches(&ctx.authority, sni.unwrap_or_default())
    {
        ctx.close_after_response = true;
        Err(failure(StatusCode::MISDIRECTED_REQUEST))
    } else {
        routes(&server.plan.routes, &mut ctx, &inner, &server).await
    };
    let result=if result.is_err() && ctx.timeouts.as_ref().is_some_and(|state|state.read_expired()){Err(failure(StatusCode::REQUEST_TIMEOUT))}else{result};
    let (mut response, explicit_headers) = match result {
        Ok(Flow::Response(response)) => (response, true),
        Ok(Flow::ImplicitResponse(response)) => (response, false),
        Ok(Flow::Continue | Flow::Stop) => (simple(StatusCode::OK, Bytes::new()), false),
        Err(error) => {
            log_append::unwind(&mut ctx, 0, None).await;
            // The server error chain uses the original request target and
            // method. Ordinary middleware above it already unwound.
            if let Some(request) = &mut ctx.request {
                *request.uri_mut() = ctx.original_uri.clone();
                *request.method_mut() = ctx.original_method.clone();
            }
            let status = populate_error(&mut ctx, &error);
            // The failed handler stack has unwound. Its deferred writers did
            // not commit headers and must not wrap the server error routes.
            ctx.deferred.clear();
            ctx.groups.clear();
            if server.plan.errors.is_empty() {
                (simple(status, Bytes::new()), true)
            } else {
                match routes(&server.plan.errors, &mut ctx, &inner, &server).await {
                    Ok(Flow::Response(response)) => (response, true),
                    Ok(Flow::ImplicitResponse(response)) => (response, false),
                    Ok(Flow::Continue | Flow::Stop) => (simple(status, Bytes::new()), true),
                    Err(_) => {
                        log_append::unwind(&mut ctx, 0, None).await;
                        ctx.deferred.clear();
                        (simple(status, Bytes::new()), true)
                    }
                }
            }
        }
    };
    let mut headers = take_writer_headers(&mut response, &mut ctx);
    let any_transform = ctx
        .deferred
        .iter()
        .any(|step| !matches!(step, DeferredResponse::Headers(_)));
    if any_transform {
        if finalize_transforms(&mut headers, &mut response, explicit_headers, 0, &mut ctx)
            .await
            .is_err()
        {
            let response = simple(StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error\n");
            return super::request_body::mark_response(response, ctx.await_h2_response_head);
        }
    } else if explicit_headers
        && apply_deferred_headers(&mut headers, response.status(), &mut ctx).await.is_err()
    {
        let response = simple(StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error\n");
        return super::request_body::mark_response(response, ctx.await_h2_response_head);
    }
    if ctx.timeouts.as_ref().is_some_and(|state|state.close_unread_h1()){ctx.close_after_response=true;}
    if ctx.close_after_response {
        headers.insert(http::header::CONNECTION, HeaderValue::from_static("close"));
    }
    log_append::unwind(&mut ctx, 0, Some(&headers)).await;
    *response.headers_mut() = headers;
    let final_method=ctx.request.as_ref().map(|request|request.method()).unwrap_or(&ctx.original_method);
    let is_head=final_method==Method::HEAD;
    let is_connect=final_method==Method::CONNECT;
    if response.status().is_informational()
        || matches!(response.status(),StatusCode::NO_CONTENT|StatusCode::NOT_MODIFIED)
    {
        // Entity-free statuses have no body. A successful CONNECT instead
        // keeps handler output unless an application actually claims upgrade.
        *response.body_mut()=full(Bytes::new());
    }
    if is_head    {
        if (ctx.metrics.is_some()||response.extensions().get::<super::tracing::TracedResponse>().is_some()) && response.extensions().get::<StaticHeadLength>().is_some(){
            // Count the finite logical writes of a static HEAD representation,
            // including its selected codec, while sending no response body.
            while let Some(frame)=response.body_mut().frame().await{if frame.is_err(){break;}tokio::task::consume_budget().await;}
        }
        let rendered_head=response.extensions().get::<RenderedTemplateHead>().is_some();
        if rendered_head {
            // Rendering with HEAD can differ from GET and can have side
            // effects. Do not rerun it as GET or infer a representation length.
            response.headers_mut().remove(http::header::CONTENT_LENGTH);
        }
        if !rendered_head && !response
            .headers()
            .contains_key(http::header::CONTENT_LENGTH)
            && !response
                .headers()
                .contains_key(http::header::CONTENT_ENCODING)
            && !response
                .headers()
                .contains_key(http::header::TRANSFER_ENCODING)
            && !matches!(
                response.status(),
                StatusCode::NO_CONTENT | StatusCode::NOT_MODIFIED
            )
            && !response.status().is_informational()
            && let Some(length) = response
                .extensions()
                .get::<StaticHeadLength>()
                .map(|length| length.0 as u64)
                .or_else(|| {
                    if http3 {
                        response.body().size_hint().exact()
                    } else {
                        None
                    }
                })
            && let Ok(value) = HeaderValue::from_str(&length.to_string())
        {
            response
                .headers_mut()
                .insert(http::header::CONTENT_LENGTH, value);
        }
        *response.body_mut() = full(Bytes::new());
    }
    let exact=response.body().size_hint().exact();let status=response.status();
    super::response_length::apply(response.headers_mut(),status,is_head,is_connect,exact);
    response = super::request_body::mark_response(response, ctx.await_h2_response_head);
    if super::route_timeouts::attach(ctx.timeouts.as_deref(),&mut response,&ctx.resources.transfer_deadlines).is_err(){
        return simple(StatusCode::SERVICE_UNAVAILABLE,"Response deadline budget unavailable\n");
    }
    if let Some(access) = access.filter(|_| !ctx.skip_access) {
        return (*access).attach(
            response,
            ctx.access_names,
            ctx.values.remove("http.auth.user.id").unwrap_or_default(),
            ctx.log_fields
                .take()
                .map(|log| log.output)
                .unwrap_or_default(),
        );
    }
    response
}
enum Flow {
    Continue,
    Stop,
    Response(Response<Body>),
    // The underlying server finishes an untouched 200 without calling an
    // application writer's WriteHeader; deferred wrappers do not run again.
    ImplicitResponse(Response<Body>),
}

fn take_writer_headers(response: &mut Response<Body>, ctx: &mut Context) -> HeaderMap {
    // Terminal headers append to the shared writer's existing fields.
    let mut headers = std::mem::take(&mut ctx.immediate);
    if headers.is_empty() {
        return std::mem::take(response.headers_mut());
    }
    for (name, value) in response.headers().iter() {
        headers.append(name, value.clone());
    }
    headers
}

#[derive(Clone, Copy)]
pub(super) struct StaticHeadLength(pub(super) usize);
// Finite rendered bytes remain available to enclosing templates, but their
// HEAD-dependent length cannot establish the selected GET representation length.
#[derive(Clone, Copy)]
pub(super) struct RenderedTemplateHead;

#[derive(Clone, Copy)]
struct StaticInterimStatus(u16);
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
    message: Option<String>,
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
        )?;
        if let Some(message) = &self.message {
            if message.is_empty() {
                f.write_str(":")?;
            } else {
                write!(f, ": {message}")?;
            }
        }
        Ok(())
    }
}
impl std::error::Error for HttpError {}
#[track_caller]
pub(super) fn failure(status: StatusCode) -> anyhow::Error {
    failure_with_message(status, None)
}

#[track_caller]
fn failure_with_message(status: StatusCode, message: Option<String>) -> anyhow::Error {
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
        message,
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
#[derive(Debug)]
struct MissingNamedRoute(String);
impl std::fmt::Display for MissingNamedRoute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invoke: route '{}' not found", self.0)
    }
}
impl std::error::Error for MissingNamedRoute {}

fn populate_error(ctx: &mut Context, error: &anyhow::Error) -> StatusCode {
    if let Some(error) = error.downcast_ref::<MissingNamedRoute>() {
        // A missing name is an ordinary Go error, so WithError adds only
        // the error object. It does not fabricate the HandlerError fields.
        ctx.values.insert("http.error".into(), error.to_string());
        ctx.error_status = None;
        return StatusCode::INTERNAL_SERVER_ERROR;
    }
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
                .unwrap_or_default()
                .to_owned(),
        ),
        (
            "http.error.message",
            error.message.clone().unwrap_or_else(|| {
                error
                    .status
                    .canonical_reason()
                    .unwrap_or_default()
                    .to_owned()
            }),
        ),
        ("http.error.id", error.id.clone()),
        ("http.error.trace", error.trace.clone()),
    ] {
        ctx.values.insert(key.into(), value);
    }
    ctx.error_status = Some(error.status);
    error.status
}
type ResponseFuture<'a> = Pin<Box<dyn Future<Output = Result<Flow>> + Send + 'a>>;

// Borrowed tails preserve middleware's next handler without allocating a
// future or stack frame for each ordinary handler in a flat route.
#[derive(Clone, Copy)]
enum Next<'a> {
    End,
    Stop,
    Routes(&'a [Route], &'a Next<'a>),
    Handlers(&'a [Handler], &'a [super::handler_trace::Module], &'a Next<'a>),
}

fn routes<'a>(
    list: &'a [Route],
    ctx: &'a mut Context,
    inner: &'a Arc<Inner>,
    server: &'a Arc<ActiveServer>,
) -> ResponseFuture<'a> {
    chained_routes(list, ctx, inner, server, &Next::End)
}

fn continue_chain<'a>(
    mut step: Next<'a>,
    ctx: &'a mut Context,
    inner: &'a Arc<Inner>,
    server: &'a Arc<ActiveServer>,
) -> ResponseFuture<'a> {
    Box::pin(async move {
        loop {
            let (flow, after) = match step {
                Next::End => return Ok(Flow::Continue),
                Next::Stop => return Ok(Flow::Stop),
                Next::Routes(list, after) => (
                    chained_routes(list, ctx, inner, server, after).await?,
                    after,
                ),
                Next::Handlers(list, traces, after) => {
                    (handlers(list, traces, ctx, inner, server, after).await?, after)
                }
            };
            if !matches!(flow, Flow::Continue) {
                return Ok(flow);
            }
            step = *after;
        }
    })
}

fn chained_routes<'a>(
    list: &'a [Route],
    ctx: &'a mut Context,
    inner: &'a Arc<Inner>,
    server: &'a Arc<ActiveServer>,
    next: &'a Next<'a>,
) -> ResponseFuture<'a> {
    Box::pin(async move {
        for (index, route) in list.iter().enumerate() {
            if route.group.as_ref().is_some_and(|g| ctx.groups.contains(g)) {
                continue;
            }
            if !match_sets(&route.matchers, ctx).await? {
                continue;
            }
            if let Some(group) = &route.group {
                ctx.groups.insert(group.clone());
            }
            let after = if route.terminal {
                Next::Stop
            } else {
                Next::Routes(&list[index + 1..], next)
            };
            let observed=if route.metrics {ctx.metrics.as_ref().and_then(|group|group.begin(server.plan.name.clone(),route.trace_modules.first().map_or_else(||Arc::from(""),|m|m.metric_name()),&ctx.authority,ctx.tls,ctx.req().method().as_str()))}else{None};
            if let Some((_,observation))=&observed{ctx.deferred.push(DeferredResponse::Metrics(observation.clone()));}
            let result=handlers(&route.handlers, &route.trace_modules, ctx, inner, server, &after).await;
            if let Err(error)=&result && let Some(group)=&ctx.metrics {
                group.error_from(observed.as_ref().map(|(marker,_)|*marker),error.downcast_ref::<HttpError>().map(|e|e.status.as_u16()),approximate_request_size(ctx));
            }
            if result.is_ok() && let Some((_,observation))=&observed{observation.returned(approximate_request_size(ctx));}
            match result? {
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
    traces: &'a [super::handler_trace::Module],
    ctx: &'a mut Context,
    inner: &'a Arc<Inner>,
    server: &'a Arc<ActiveServer>,
    next: &'a Next<'a>,
) -> ResponseFuture<'a> {
    Box::pin(async move {
        for (index, handler) in list.iter().enumerate() {
            if server.plan.access_logs.as_ref().is_some_and(|logs|logs.trace)
                && let Some(logging)=server.logging.as_deref()
                && let Some(module)=traces.get(index) {module.emit(logging);}
            match handler {
                Handler::Push(plan)=>{
                    if let Ok(Some(push))=super::push::LinkPlan::new(ctx,plan,inner,server).await{
                        for resource in &plan.resources{
                            let Ok((target,_target_scratch))=super::push::expand_target(ctx,&resource.target).await else{break};
                            if push.dispatch_bytes(&target,&resource.method,&ctx.authority).await.is_err(){break}
                        }
                        ctx.deferred.push(DeferredResponse::Push(push));
                    }
                }
                Handler::Tracing(plan)=>{
                    let Some(provider)=server.tracing.as_ref()else{continue};
                    let entered=super::tracing::enter(ctx,provider,plan).await;
                    let previous=ctx.trace_context.replace(entered.context.clone());
                    log_append::trace_fields(ctx,&entered.context);
                    ctx.deferred.push(DeferredResponse::Trace(entered.clone()));
                    let after=Next::Handlers(&list[index+1..],traces.get(index+1..).unwrap_or_default(),next);
                    let result=continue_chain(after,ctx,inner,server).await;
                    super::tracing::attributes(ctx,&entered,plan).await;
                    ctx.trace_context=previous;
                    if let Err(error)=&result {entered.failed(error.downcast_ref::<HttpError>().map_or(500,|e|e.status.as_u16()));}
                    return result;
                }
                Handler::Timeouts(plan)=>{
                    let mark=super::route_timeouts::mark(ctx.timeouts.as_deref());
                    if super::route_timeouts::install(ctx,plan).is_err(){ctx.close_after_response=true;return Err(budget_failure(ctx,super::resource_budget::BudgetError::Overloaded));}
                    let after=Next::Handlers(&list[index+1..],traces.get(index+1..).unwrap_or_default(),next);
                    let result=continue_chain(after,ctx,inner,server).await;
                    if result.is_err() && super::route_timeouts::unwind(ctx,mark).is_err(){ctx.close_after_response=true;}
                    return result;
                }
                Handler::AcmeServer(config)=>{
                    let controller=server.acme_servers.get(&(Arc::as_ptr(config)as usize))
                        .ok_or_else(||anyhow::anyhow!("ACME server was not prepared"))?;
                    if !controller.matches(ctx.req().uri().path()) {continue;}
                    // Admission drain only rejects new requests. An accepted
                    // proof/signing request may continue until its real grace
                    // deadline or explicit force closes this business owner.
                    let cancel=ctx.business.generation().hard_stop.child_token();
                    let response=controller.handle(ctx.request.as_mut().expect("request owned"),&ctx.authority,cancel).await?;
                    return Ok(Flow::Response(response));
                }
                Handler::Metrics{disable_openmetrics}=>{
                    let mut response=server.metrics.scrape(ctx.req().headers(),!*disable_openmetrics).await;
                    response.extensions_mut().insert(crate::metrics::discarded::PreparedEntity);
                    // A scrape is already a bounded, encoded in-memory entity.
                    // Mark it so HEAD observes these logical bytes without
                    // polling an arbitrary streaming response.
                    if ctx.req().method()==Method::HEAD && let Some(length)=response.body().size_hint().exact().and_then(|n|usize::try_from(n).ok()){
                        response.extensions_mut().insert(StaticHeadLength(length));
                    }
                    return Ok(Flow::Response(response));
                }
                Handler::StaticError { status, message } => {
                    let code = if status.is_empty() {
                        StatusCode::INTERNAL_SERVER_ERROR
                    } else {
                        let raw = ctx.expand_text_resolved(status,true).await?;
                        let code = raw.parse::<i64>().map_err(|error| {
                            let reason = match error.kind() {
                                std::num::IntErrorKind::PosOverflow
                                | std::num::IntErrorKind::NegOverflow => "value out of range",
                                _ => "invalid syntax",
                            };
                            failure_with_message(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                Some(format!("strconv.Atoi: parsing {raw:?}: {reason}")),
                            )
                        })?;
                        u16::try_from(code)
                            .ok()
                            .and_then(|code| StatusCode::from_u16(code).ok())
                            .filter(|status| !status.is_informational())
                            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
                    };
                    let message = ctx.expand_text_resolved(message,false).await?;
                    return Err(failure_with_message(code, Some(message)));
                }
                Handler::Invoke(name) => {
                    let route = server
                        .plan
                        .named_routes
                        .get(name)
                        .ok_or_else(|| MissingNamedRoute(name.clone()))?;
                    if ctx.invoke_depth >= 64 {
                        return Err(failure(StatusCode::INTERNAL_SERVER_ERROR));
                    }
                    ctx.invoke_depth += 1;
                    let after = Next::Handlers(&list[index + 1..], traces.get(index+1..).unwrap_or_default(), next);
                    let result =
                        chained_routes(std::slice::from_ref(route), ctx, inner, server, &after)
                            .await;
                    ctx.invoke_depth -= 1;
                    match result? {
                        Flow::Continue => {}
                        flow => return Ok(flow),
                    }
                }
                Handler::LogAppend(plan) => {
                    if let Some(index) = log_append::enter(ctx, plan).await {
                        ctx.deferred.push(DeferredResponse::LogBody(index));
                    }
                }
                Handler::StaticResponse {
                    status,
                    body,
                    headers,
                    close,
                } => {
                    let bytes = ctx.expand_resolved(body,false).await?;
                    let mut fields = std::mem::take(&mut ctx.immediate);
                    if *close && ctx.req().version() != Version::HTTP_2 {
                        ctx.close_after_response = true;
                        fields.insert(http::header::CONNECTION, HeaderValue::from_static("close"));
                    }
                    let prepared = apply_static_headers(&mut fields, headers, ctx.lookup_view(), &bytes).await;
                    ctx.immediate = fields;
                    prepared?;
                    let status = if status.is_empty() {
                        ctx.error_status.unwrap_or(StatusCode::OK)
                    } else {
                        StatusCode::from_u16(ctx.expand_text_resolved(status,true).await?.parse()?)
                            .map_err(|_| failure(StatusCode::INTERNAL_SERVER_ERROR))?
                    };
                    if status.is_informational() {
                        match static_informational(ctx, status, bytes).await? {
                            Flow::Continue => continue,
                            result => return Ok(result),
                        }
                    }
                    let head_length = static_head_length(ctx, &bytes);
                    let mut response = simple(status, bytes);
                    response.extensions_mut().insert(crate::metrics::discarded::PreparedEntity);
                    *response.headers_mut() = std::mem::take(&mut ctx.immediate);
                    // Framing comes after response writers have examined the
                    // actual application headers. Hyper can use the exact
                    // static body length without inserting a premature field.
                    if let Some(head_length) = head_length {
                        response.extensions_mut().insert(head_length);
                    }
                    return Ok(Flow::Response(response));
                }
                Handler::RequestBody(plan) => {
                    Box::pin(super::request_body::apply(ctx, plan)).await?;
                }
                Handler::Templates(plan) => {
                    let deferred_mark=ctx.deferred.len();let log_mark=log_append::mark(ctx);
                    let after=Next::Handlers(&list[index+1..],traces.get(index+1..).unwrap_or_default(),next);
                    let flow=continue_chain(after,ctx,inner,server).await?;
                    let(mut response,explicit)=match flow{
                        Flow::Response(response)=>(response,true),
                        Flow::ImplicitResponse(response)=>(response,false),
                        Flow::Continue|Flow::Stop=>(simple(StatusCode::OK,Bytes::new()),false),
                    };
                    let mut headers=take_writer_headers(&mut response,ctx);
                    if explicit{
                        if let Err(error)=finalize_transforms(&mut headers,&mut response,true,deferred_mark,ctx).await{
                            ctx.immediate=headers;return Err(error);
                        }
                        log_append::unwind(ctx,log_mark,Some(&headers)).await;
                        let finite_head=response.extensions().get::<StaticHeadLength>().is_some();
                        let body=std::mem::replace(response.body_mut(),full(Bytes::new()));
                        match super::templates::finish(plan,&mut headers,body,ctx,inner,server,finite_head).await{
                            Ok(finished)=>{
                                let body=finished.body;
                                if finished.rendered_head {
                                    response.extensions_mut().insert(RenderedTemplateHead);
                                    headers.remove(http::header::CONTENT_LENGTH);
                                }
                                if finite_head{
                                    if let Some(length)=body.size_hint().exact().and_then(|n|usize::try_from(n).ok()){
                                        response.extensions_mut().insert(StaticHeadLength(length));
                                    }else{response.extensions_mut().remove::<StaticHeadLength>();}
                                }
                                *response.body_mut()=body;
                            },
                            Err(error)=>{ctx.immediate=headers;return Err(failure(error.0));}
                        }
                    }else{
                        // An untouched Go recorder starts buffered. Its empty
                        // WriteResponse bypasses inner deferred writers.
                        ctx.deferred.truncate(deferred_mark);
                        log_append::unwind(ctx,log_mark,Some(&headers)).await;
                        *response.status_mut()=StatusCode::OK;
                        *response.body_mut()=super::templates::finish_empty(&mut headers);
                    }
                    *response.headers_mut()=headers;
                    return Ok(Flow::Response(response));
                }
                Handler::Encode(plan) => {
                    if let Some(codec) = plan.select(ctx.req_mut().headers_mut()) {
                        ctx.deferred.push(DeferredResponse::Encode(
                            super::encode_response::ResponseEncoding {
                                plan: plan.clone(),
                                codec,
                                method: ctx.req().method().clone(),
                            },
                        ));
                    }
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
                    apply_request_headers(&mut headers, request, ctx).await?;
                    super::headers_replace::apply(&mut headers,request,ctx,super::headers_replace::Scope::Request,None).await?;
                    ctx.authority = headers
                        .get_all(http::header::HOST)
                        .iter()
                        .next_back()
                        .map(|value| value.to_str().map(str::to_owned))
                        .transpose()?
                        .unwrap_or_default();
                    headers.remove(http::header::HOST);
                    *ctx.req_mut().headers_mut() = headers;
                    if *deferred || response.require.is_some() {
                        ctx.deferred
                            .push(DeferredResponse::Headers(response.clone()));
                    } else {
                        let mut headers = std::mem::take(&mut ctx.immediate);
                        apply_headers(&mut headers, response, ctx).await?;
                        super::headers_replace::apply(&mut headers,response,ctx,super::headers_replace::Scope::Original,None).await?;
                        ctx.immediate = headers;
                    }
                }
                Handler::Subroute {
                    routes: nested,
                    errors,
                    errors_configured,
                } => {
                    let pending_headers = ctx.deferred.len();
                    let pending_logs = log_append::mark(ctx);
                    let after = Next::Handlers(&list[index + 1..], traces.get(index+1..).unwrap_or_default(), next);
                    let result = chained_routes(nested, ctx, inner, server, &after).await;
                    match result {
                        Ok(Flow::Continue) => {}
                        Ok(flow) => return Ok(flow),
                        Err(error) if *errors_configured => {
                            let error=if ctx.timeouts.as_ref().is_some_and(|state|state.read_expired()){failure(StatusCode::REQUEST_TIMEOUT)}else{error};
                            // Keep wrappers outside this subroute, while
                            // dropping the failed inner route's deferred work.
                            log_append::unwind(ctx, pending_logs, None).await;
                            ctx.deferred.truncate(pending_headers);
                            populate_error(ctx, &error);
                            match chained_routes(errors, ctx, inner, server, &after).await? {
                                Flow::Continue => {}
                                flow => return Ok(flow),
                            }
                        }
                        Err(error) => return Err(error),
                    }
                }
                Handler::Rewrite(plan) => super::rewrite_runtime::apply(plan,ctx).await?,
                Handler::Vars(vars) => {
                    for (name, value) in vars {
                        let name = ctx.expand_text_resolved(name,true).await?;
                        log_append::remember_var(ctx, &name, value);
                        if name == "log_skip" {
                            ctx.skip_access = value.as_bool() == Some(true);
                        } else if name == "access_logger_names" {
                            ctx.access_names = value
                                .as_array()
                                .filter(|names| names.len() <= 16)
                                .and_then(|names| {
                                    names
                                        .iter()
                                        .map(|value| {
                                            value
                                                .as_str()
                                                .filter(|name| name.len() <= 128)
                                                .map(str::to_owned)
                                        })
                                        .collect()
                                });
                        }
                        let value = match value.as_ref() {
                            serde_json::Value::String(s) => ctx.expand_text_resolved(s,true).await?,
                            serde_json::Value::Null => String::new(),
                            other => crate::http_config::helpers::value_string(other),
                        };
                        if name == "http.auth.user.id" {
                            ctx.lookup_view().reserve_text_copy(name.len().saturating_add(value.len()))?;
                            ctx.values.insert(name.clone(), value.clone());
                        }
                        ctx.lookup_view().reserve_text_copy(name.len().saturating_add(16))?;
                        ctx.values.insert(format!("http.vars.{name}"), value);
                    }
                }
                Handler::Map(plan) => {
                    if ctx.maps.len()==ctx.maps.capacity(){
                        let capacity=ctx.maps.capacity().saturating_mul(2).max(4);
                        let credit=ctx.resources.map_bytes.reserve(capacity.saturating_mul(std::mem::size_of::<LazyMap>()*2)+1024).map_err(|_|failure(StatusCode::SERVICE_UNAVAILABLE))?;
                        ctx.maps.try_reserve_exact(capacity-ctx.maps.len())?;
                        ctx._map_registration_credit=Some(credit);
                    }
                    ctx.maps.push(plan.clone());
                }
                Handler::Authentication {
                    algorithm,
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
                            .unwrap_or(algorithm.fake())
                            .to_owned();
                        let result = if let Some(cache) = cache {
                            cache.verify_with_algorithm(ctx.resources.clone(), *algorithm, hash, password).await
                        } else {
                            let count = ctx.resources.auth_comparisons.clone();
                            let algorithm=*algorithm;
                            ctx.resources
                                .auth
                                .run(move || {
                                    count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    algorithm.compare(&hash,password.as_slice())
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
                    canonical_uris,
                    sidecars,
                    browse,
                } => match super::files::serve(
                    ctx,
                    inner,
                    server,
                    root.as_deref(),
                    hide,
                    index_names,
                    *canonical_uris,
                    sidecars,
                    browse.as_ref(),
                )
                .await?
                {
                    Some(response) => return Ok(Flow::Response(response)),
                    None if *pass_thru => {}
                    None => return Err(failure(StatusCode::NOT_FOUND)),
                },
                Handler::Intercept(rules) => {
                    if !rules.is_empty() {
                        return response_routes::intercept(
                            rules,
                            Next::Handlers(&list[index + 1..], traces.get(index+1..).unwrap_or_default(), next),
                            ctx,
                            inner,
                            server,
                        )
                        .await;
                    }
                }
                Handler::CopyResponse(status) => {
                    return response_routes::copy_response(ctx, status, inner).await;
                }
                Handler::CopyResponseHeaders(filter) => {
                    response_routes::copy_headers(ctx, filter)?;
                }
                Handler::ReverseProxy(config) => {
                    let body_limit = ctx.body_limit.clone();
                    let response =
                        super::proxy::serve(ctx, config, server)
                            .await
                            .map_err(|error| {
                                if error.is::<HttpError>() {
                                    error
                                } else if super::request_body::limit_error(error.as_ref())
                                    || super::request_body::limit_hit(body_limit.as_deref())
                                {
                                    failure(StatusCode::PAYLOAD_TOO_LARGE)
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
                            })?;
                    return response_routes::reverse_proxy(
                        response,
                        &config.response_routes,
                        Next::Handlers(&list[index + 1..], traces.get(index+1..).unwrap_or_default(), next),
                        ctx,
                        inner,
                        server,
                    )
                    .await;
                }
            }
        }
        Ok(Flow::Continue)
    })
}
pub(super) fn match_sets<'a>(
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
async fn var_match_value(ctx: &mut Context, key: &str) -> Result<String> {
    if matches!(key, "{http.request.body}" | "{http.request.body_base64}") {
        let bytes = super::cel_body::capture(ctx).await?;
        return Ok(if key.ends_with("_base64}") { base64::engine::general_purpose::STANDARD.encode(&bytes) } else { String::from_utf8_lossy(&bytes).into_owned() });
    }
    Ok(
    if let Some(key) = key
        .strip_prefix('{')
        .and_then(|key| key.strip_suffix('}'))
        .filter(|key| !key.contains('{'))
    {
        ctx.lookup_text_resolved(key).await?
    } else {
        ctx.values.get(&format!("http.vars.{key}")).cloned()
    }
    .unwrap_or_default())
}

fn rewritten_path(ctx:&Context)->Result<String>{if let Some(p)=super::rewrite_runtime::projection(ctx.req()){Ok(String::from_utf8(p.state.path.clone())?)}else{decoded_path(ctx.req().uri().path_and_query().map_or("",|p|p.raw_path()))}}

pub(super) fn matches<'a>(
    matcher: &'a Matcher,
    ctx: &'a mut Context,
) -> Pin<Box<dyn Future<Output = Result<bool>> + Send + 'a>> {
    Box::pin(async move {
        Ok(match matcher {
            Matcher::Expression(plan) => plan.matches(ctx).await?,
            Matcher::Host(hosts) => {
                let mut found=false;
                for host in hosts{let host=ctx.expand_text_resolved(host,true).await?;if host_match(&host,&hostname(&ctx.authority)){found=true;break;}}
                found
            },
            Matcher::Path(patterns) => {
                let escaped=ctx.req().uri().path().to_owned();
                let mut expanded=Vec::with_capacity(patterns.len());
                for pattern in patterns{expanded.push(ctx.expand_text_resolved(pattern,true).await?);}
                let patterns=expanded;
                let result=if super::path_match::fast(&patterns,&escaped){super::path_match::matches(&patterns,&escaped)}else{
                    ctx.resources.request_regexp.run(move||super::path_match::matches(&patterns,&escaped)).await
                        .map_err(|_|failure(StatusCode::SERVICE_UNAVAILABLE))?
                };result.map_err(|_|failure(StatusCode::SERVICE_UNAVAILABLE))?
            }
            Matcher::PathRegex(plan) => {
                let path_bytes=super::rewrite_runtime::projection(ctx.req()).map_or_else(||ctx.req().uri().path_and_query().map_or(0,|p|p.raw_path().len()),|p|p.state.path.len());
                let input_credit=ctx.resources.rewrite_bytes.reserve(path_bytes.saturating_mul(2).saturating_add(4096)).map_err(|_|failure(StatusCode::SERVICE_UNAVAILABLE))?;
                let path=if let Some(p)=super::rewrite_runtime::projection(ctx.req()){p.state.path.clone()}else{
                    super::http_redirect::url::template_decode_bytes(ctx.req().uri().path_and_query().map_or("",|p|p.raw_path()).as_bytes()).map_err(|_|failure(StatusCode::BAD_REQUEST))?
                };
                #[cfg(windows)]
                let path={let text=String::from_utf8(path)?;text.replace('\\',"/").split('/').map(|part|if matches!(part,"."|".."){part}else{part.trim_end_matches(['.',' '])}).collect::<Vec<_>>().join("/").into_bytes()};
                super::request_regex::matches_bytes(plan,path,input_credit,ctx).await?
            }
            Matcher::HeaderRegex(rules) => {
                let mut all = true;
                for (header, plan) in rules {
                    let values = if header == http::header::HOST {
                        vec![ctx.authority.clone()]
                    } else {
                        let values = ctx
                            .req()
                            .headers()
                            .get_all(header)
                            .iter()
                            .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
                            .collect::<Vec<_>>();
                        if values.is_empty()
                            && header == http::header::TRANSFER_ENCODING
                            && ctx.original_framing.chunked
                        {
                            vec!["chunked".into()]
                        } else {
                            values
                        }
                    };
                    if !super::request_regex::matches(plan, values, ctx).await? {
                        all = false;
                        break;
                    }
                }
                all
            }
            Matcher::VarsRegex(rules) => {
                let mut matched = false;
                for (key, plan) in rules {
                    let value = var_match_value(ctx, key).await?;
                    if super::request_regex::matches(plan, vec![value], ctx).await? {
                        matched = true;
                        break;
                    }
                }
                matched
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
                        Some(patterns) => {
                            let mut found=false;
                            for pattern in patterns{
                                let pattern=ctx.expand_resolved(pattern,true).await?;
                                if values.iter().any(|v|header_value_bytes_pattern(&pattern,v)){found=true;break;}
                            }
                            found
                        },
                    };
                    if !matched {
                        all = false;
                        break;
                    }
                }
                all
            }
            Matcher::Query(rules) => super::query_match::matches(
                ctx.req().uri().query().unwrap_or_default(),
                rules,
                ctx.lookup_view(),
            ).await?,
            Matcher::Vars(rules) => {
                let mut matched = rules.is_empty();
                'variables: for (key, values) in rules {
                    let actual = var_match_value(ctx, key).await?;
                    for value in values {
                        if actual == ctx.expand_text_resolved(value,true).await? {
                            matched = true;
                            break 'variables;
                        }
                    }
                }
                matched
            }
            // All currently admitted TLS requests have completed a handshake.
            Matcher::Tls(complete) => ctx.tls && *complete != Some(false),
            Matcher::UrlPattern(plan) => plan.matches(ctx).await?,
            Matcher::Not(sets) => !match_sets(sets, ctx).await?,
            Matcher::RemoteIp(ranges) => ctx.peer.matcher_ip().is_some_and(|ip|ranges.iter().any(|r|r.contains(&ip))),
            Matcher::ClientIp(ranges) => ctx.client_ip.is_some_and(|ip|ranges.iter().any(|r|r.contains(&ip))),
            Matcher::Protocol(protocol) => match protocol.as_str() {
                "http" => !ctx.tls,
                "https" => ctx.tls,
                "grpc" => ctx
                    .req()
                    .headers()
                    .get(http::header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .is_some_and(|v| v.starts_with("application/grpc")),
                "http/1.0+" => matches!(
                    ctx.req().version(),
                    Version::HTTP_10 | Version::HTTP_11 | Version::HTTP_2 | Version::HTTP_3
                ),
                "http/1.1+" => matches!(
                    ctx.req().version(),
                    Version::HTTP_11 | Version::HTTP_2 | Version::HTTP_3
                ),
                "http/2" => ctx.req().version() == Version::HTTP_2,
                "http/2+" => matches!(ctx.req().version(), Version::HTTP_2 | Version::HTTP_3),
                "http/3" | "http/3+" => ctx.req().version() == Version::HTTP_3,
                "http/1.0" => ctx.req().version() == Version::HTTP_10,
                _ => ctx.req().version() == Version::HTTP_11,
            },
            Matcher::File {
                root,
                try_files,
                split_path,
                policy,
            } => {
                super::file_match::matches(ctx, root.as_deref(), try_files, split_path, *policy)
                    .await?
            }
        })
    })
}
// A rare interim response can wait for socket flush. Keep its suspended
// state out of every ordinary route future's allocation.
#[cold]
fn static_informational<'a>(
    ctx: &'a mut Context,
    status: StatusCode,
    bytes: Bytes,
) -> ResponseFuture<'a> {
    Box::pin(async move {
        if status == StatusCode::SWITCHING_PROTOCOLS && ctx.req().version() != Version::HTTP_11 {
            // 101 is an HTTP/1.1 switch, not an HTTP/2 extended
            // CONNECT. A malformed static response must not break
            // neighboring streams or confuse HTTP/1.0 framing.
            return Err(failure(StatusCode::INTERNAL_SERVER_ERROR));
        }
        let mut fields = std::mem::take(&mut ctx.immediate);
        let mut final_status = status;
        if status.is_informational() && status != StatusCode::SWITCHING_PROTOCOLS {
            apply_deferred_headers(&mut fields, status, ctx).await?;
            ctx.immediate = fields;
            emit_informational(ctx, status).await?;
            if status == StatusCode::EARLY_HINTS {
                // A 103 does not write this handler's body. Keep its
                // shared headers and continue at this chain level.
                return Ok(Flow::Continue);
            }
            final_status = StatusCode::OK;
            fields = std::mem::take(&mut ctx.immediate);
        }
        let empty_implicit = status.is_informational()
            && status != StatusCode::SWITCHING_PROTOCOLS
            && bytes.is_empty();
        let body = if status == StatusCode::SWITCHING_PROTOCOLS {
            fields.remove(http::header::CONTENT_LENGTH);
            fields.remove(http::header::TRANSFER_ENCODING);
            Bytes::new()
        } else {
            bytes
        };
        let head_length = static_head_length(ctx, &body);
        let mut response = simple(final_status, body);
        response.extensions_mut().insert(crate::metrics::discarded::PreparedEntity);
        if let Some(head_length) = head_length {
            response.extensions_mut().insert(head_length);
        }
        if !empty_implicit && status != StatusCode::SWITCHING_PROTOCOLS {
            response
                .extensions_mut()
                .insert(StaticInterimStatus(status.as_u16()));
        }
        *response.headers_mut() = fields;
        Ok(if empty_implicit {
            Flow::ImplicitResponse(response)
        } else {
            Flow::Response(response)
        })
    })
}

fn static_head_length(ctx: &Context, body: &[u8]) -> Option<StaticHeadLength> {
    (ctx.req().method() == Method::HEAD && !body.is_empty()).then_some(StaticHeadLength(body.len()))
}

#[inline]
async fn apply_static_headers(
    fields: &mut HeaderMap,
    operations: &HeaderOps,
    view: ReplacerView<'_>,
    body: &[u8],
) -> Result<()> {
    for (name, values) in &operations.set {
        let name_bytes=view.expand_resolved(name,false).await?;
        let name = HeaderName::from_bytes(&name_bytes)?;
        fields.remove(&name);
        for value in values {
            fields.append(
                name.clone(),
                HeaderValue::from_maybe_shared(view.expand_resolved(value,false).await?)?,
            );
        }
    }
    if !body.is_empty()
        && fields
            .get(http::header::CONTENT_TYPE)
            .is_none_or(|value| value.is_empty())
    {
        let json=std::str::from_utf8(body).is_ok_and(|text|{
            let trimmed=text.trim();trimmed.len()>2 && ((trimmed.starts_with('{')&&trimmed.ends_with('}'))||(trimmed.starts_with('[')&&trimmed.ends_with(']'))) && serde_json::from_str::<serde_json::Value>(trimmed).is_ok()
        });
        fields.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static(if json {
                "application/json"
            } else {
                "text/plain; charset=utf-8"
            }),
        );
    }
    Ok(())
}

fn push_links_unseen(ctx:&Context)->bool{
    const KEY:&str="http.handlers.push.pushed_link";
    match ctx.typed_vars.get(KEY){Some(value)=>value.is_null(),None=>!ctx.values.contains_key("http.vars.http.handlers.push.pushed_link")}
}
fn mark_push_links(ctx:&mut Context){
    ctx.typed_vars.insert("http.handlers.push.pushed_link".into(),Arc::new(serde_json::Value::Bool(true)));
    ctx.values.insert("http.vars.http.handlers.push.pushed_link".into(),"true".into());
}
async fn apply_deferred_headers(fields:&mut HeaderMap,status:StatusCode,ctx:&mut Context)->Result<()> {
    for index in (0..ctx.deferred.len()).rev(){
        match &ctx.deferred[index]{
            DeferredResponse::Headers(operations)=>apply_response_headers(fields,status.as_u16(),operations,ctx).await?,
            DeferredResponse::Push(push)=>{
                if fields.contains_key(http::header::LINK)&&push_links_unseen(ctx){
                    let push=push.clone();mark_push_links(ctx);
                    push.links(fields,&ctx.authority).await;
                }
            },_=>{}
        }
    }
    Ok(())
}

pub(super) const MAX_INFORMATIONAL_HEADS: u16 = 64;
pub(super) const MAX_INFORMATIONAL_BYTES: usize = 64 * 1024;
static SUPPRESSED_INFORMATIONAL: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

pub(super) fn suppressed_informational() -> u64 {
    SUPPRESSED_INFORMATIONAL.load(std::sync::atomic::Ordering::Relaxed)
}

pub(super) fn record_suppressed_informational() {
    SUPPRESSED_INFORMATIONAL.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

pub(super) enum InformationalOutput {
    Http(hyper::ext::InformationalSender),
    Quic(super::h3::stream::InterimWriter),
}

pub(super) fn accepts_informational(ctx: &Context) -> bool {
    match ctx.informational.as_ref(){
        Some(InformationalOutput::Http(sender))=>sender.allows_informational(),
        Some(InformationalOutput::Quic(_))=>true,
        None=>false,
    }
}

pub(super) async fn forward_informational(
    ctx: &mut Context,
    status: StatusCode,
    fields: HeaderMap,
) -> Result<()> {
    if !accepts_informational(ctx) {
        return Ok(());
    }
    let mut snapshot = ctx.immediate.clone();
    for (name, value) in fields.iter() {
        snapshot.append(name, value.clone());
    }
    apply_deferred_headers(&mut snapshot, status, ctx).await?;
    // Upstream interim headers are not part of the final response. Preserve
    // prior application headers; never clear the underlying writer map.
    write_informational(ctx, status, snapshot).await
}

async fn emit_informational(ctx: &mut Context, status: StatusCode) -> Result<()> {
    if !accepts_informational(ctx) {
        return Ok(());
    }
    write_informational(ctx,status,ctx.immediate.clone()).await
}

async fn write_informational(
    ctx: &mut Context,
    status: StatusCode,
    fields: HeaderMap,
) -> Result<()> {
    if !accepts_informational(ctx){return Ok(())}
    let Some(sender) = &mut ctx.informational else {
        // In particular, RFC 9110 forbids a 1xx to an HTTP/1.0 client.
        // Continue the handler semantics without sending that head.
        return Ok(());
    };
    let mut response = Response::new(());
    *response.status_mut() = status;
    *response.headers_mut() = fields;
    // Interim responses use the same protocol field rules as final responses.
    super::response_length::apply(response.headers_mut(),status,false,false,None);
    if let Some(control)=ctx.timeouts.as_deref().and_then(|state|state.control()){response.extensions_mut().insert(control);}
    let suppressed = match sender {
        InformationalOutput::Http(sender) => match sender.send(response).await {
            Ok(()) => false,
            Err(error) if error.is_limit() => true,
            Err(error) => return Err(error.into()),
        },
        InformationalOutput::Quic(sender) => sender.send(response).await?,
    };
    if suppressed {
        record_suppressed_informational();
    }
    Ok(())
}

pub(super) fn apply_response_headers<'a>(headers:&'a mut HeaderMap,status:u16,operations:&'a HeaderOps,ctx:&'a Context)
    ->Pin<Box<dyn Future<Output=Result<()>>+Send+'a>>{
    if operations.require.as_ref().is_some_and(|matcher|!matcher.matches(status,headers)){return Box::pin(async{Ok(())})}
    let view=ctx.lookup_view();
    let prepared=super::headers_replace::prepare_owned(operations,ctx,super::headers_replace::Scope::Original);
    Box::pin(async move{
        apply_headers_view(headers,operations,view).await?;
        super::headers_replace::apply_owned(headers,operations,prepared?,None).await
    })
}
pub(super) fn file_split<'a>(path: &'a str, extensions: &[String]) -> (&'a str, &'a str) {
    for extension in extensions.iter().filter(|value| !value.is_empty()) {
        let Some(at) = path
            .as_bytes()
            .windows(extension.len())
            .position(|value| value.eq_ignore_ascii_case(extension.as_bytes()))
        else {
            continue;
        };
        let end = at + extension.len();
        if end < path.len() && path.as_bytes()[end] == b'/' {
            return path.split_at(end);
        }
    }
    (path, "")
}

pub(super) fn apply_headers<'a>(headers:&'a mut HeaderMap,operations:&'a HeaderOps,ctx:&'a Context)
    ->impl Future<Output=Result<()>>+Send+'a{
    apply_headers_view(headers,operations,ctx.lookup_view())
}
pub(super) fn apply_headers_view<'a>(headers:&'a mut HeaderMap,operations:&'a HeaderOps,view:ReplacerView<'a>)
    ->impl Future<Output=Result<()>>+Send+'a{apply_headers_with(headers,operations,view,false,None)}
fn apply_request_headers<'a>(headers:&'a mut HeaderMap,operations:&'a HeaderOps,ctx:&'a Context)
    ->impl Future<Output=Result<()>>+Send+'a{
    apply_headers_with(headers,operations,ctx.lookup_view(),true,None)
}
pub(super) fn apply_push_headers<'a>(headers:&'a mut HeaderMap,operations:&'a HeaderOps,ctx:&'a Context)
    ->impl Future<Output=Result<()>>+Send+'a{
    apply_push_headers_view(headers,operations,ctx.lookup_view(),ctx.resources.transfer_deadlines.clone())
}
pub(super) fn apply_push_headers_view<'a>(headers:&'a mut HeaderMap,operations:&'a HeaderOps,view:ReplacerView<'a>,pool:native_write_policy::Pool)
    ->impl Future<Output=Result<()>>+Send+'a{
    async move{
        let entries=operations.delete.len().checked_add(operations.add.iter().chain(&operations.set).try_fold(0usize,|n,(_,v)|n.checked_add(v.len()).and_then(|n|n.checked_add(1))).ok_or_else(||anyhow::anyhow!("push header count overflow"))?).ok_or_else(||anyhow::anyhow!("push header count overflow"))?;
        if entries==0{return Ok(())}
        let scratch=entries.checked_mul(128).and_then(|n|n.checked_add(8<<20)).ok_or_else(||anyhow::anyhow!("push header allocation overflow"))?;
        let _scratch=pool.reserve(scratch)?;
        apply_headers_with(headers,operations,view,false,Some(65536)).await
    }
}
async fn header_expand(view:&ReplacerView<'_>,fields:&HeaderMap,request:bool,text:&str)->Result<Bytes>{
    if request{view.with_headers(fields).expand_resolved(text,false).await}else{view.expand_resolved(text,false).await}
}
struct HeaderValueOwner{bytes:Bytes,_name:Bytes,_name_credit:Arc<native_write_policy::Lease>}
impl AsRef<[u8]> for HeaderValueOwner{fn as_ref(&self)->&[u8]{&self.bytes}}
fn owned_header(bytes:Bytes,name:&Bytes,credit:&Arc<native_write_policy::Lease>)->Result<HeaderValue>{
    Ok(HeaderValue::from_maybe_shared(Bytes::from_owner(HeaderValueOwner{bytes,_name:name.clone(),_name_credit:credit.clone()}))?)
}
async fn apply_headers_with(headers:&mut HeaderMap,operations:&HeaderOps,view:ReplacerView<'_>,request:bool,maximum:Option<usize>)->Result<()>{
    let checked=|fields:&HeaderMap|->Result<()>{if let Some(maximum)=maximum{
        let bytes=fields.iter().try_fold(0usize,|n,(name,value)|n.checked_add(name.as_str().len()+value.len()+32)).ok_or_else(||anyhow::anyhow!("header size overflow"))?;
        ensure!(bytes<=maximum,"headers exceed limit");
    }Ok(())};
    for pattern in &operations.delete{
        if header_expand(&view,headers,request,pattern).await?.as_ref()==b"*"{headers.clear();}
    }
    for (name,values) in &operations.add{
        let name_bytes=header_expand(&view,headers,request,name).await?;
        let name_credit=Arc::new(view.pool().reserve(name_bytes.len().saturating_mul(2)+1024)?);
        let name=HeaderName::from_bytes(&name_bytes)?;
        for value in values{
            let value=header_expand(&view,headers,request,value).await?;
            headers.append(name.clone(),owned_header(value,&name_bytes,&name_credit)?);checked(headers)?;
        }
    }
    for (name,values) in &operations.set{
        let name_bytes=header_expand(&view,headers,request,name).await?;
        let name_credit=Arc::new(view.pool().reserve(name_bytes.len().saturating_mul(2)+1024)?);
        let name=HeaderName::from_bytes(&name_bytes)?;
        let _cells=view.pool().reserve(values.len().saturating_mul(std::mem::size_of::<Bytes>()*2)+1024)?;
        let mut expanded=Vec::with_capacity(values.len());
        for value in values{expanded.push(header_expand(&view,headers,request,value).await?);}
        headers.remove(&name);
        if name==http::header::SET_COOKIE&&expanded.len()>1{
            for value in expanded{headers.append(name.clone(),owned_header(value,&name_bytes,&name_credit)?);checked(headers)?;}
        }else{
            let length=expanded.iter().try_fold(expanded.len().saturating_sub(1),|n,v|n.checked_add(v.len())).filter(|n|*n<=4<<20).ok_or_else(||anyhow::anyhow!("header replacement exceeds limit"))?;
            let credit=view.pool().reserve(length.saturating_mul(2)+1024)?;
            let mut joined=Vec::new();joined.try_reserve_exact(length)?;
            for (i,value)in expanded.iter().enumerate(){if i>0{joined.push(b',')}joined.extend_from_slice(value);}
            let value=super::map_runtime::owned(joined,credit);
            headers.insert(name,owned_header(value,&name_bytes,&name_credit)?);checked(headers)?;
        }
    }
    for pattern in &operations.delete{
        let pattern=header_expand(&view,headers,request,pattern).await?;
        let pattern=std::str::from_utf8(&pattern)?;
        if pattern=="*"{continue}
        let _names=view.pool().reserve(headers.len().saturating_mul(std::mem::size_of::<HeaderName>()*2)+1024)?;
        let names=headers.keys().filter(|name|header_pattern(pattern,name.as_str())).cloned().collect::<Vec<_>>();
        for name in names{headers.remove(name);}
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

fn header_pattern(pattern: &str, value: &str) -> bool {
    header_value_pattern(&pattern.to_ascii_lowercase(), &value.to_ascii_lowercase())
}

#[cold]
fn finalize_transforms<'a>(
    headers: &'a mut HeaderMap,
    response: &'a mut Response<Body>,
    explicit: bool,
    start: usize,
    ctx: &'a mut Context,
) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
    Box::pin(async move {
        let status = response.status();
        let observed_head=(ctx.metrics.is_some()||ctx.deferred.iter().any(|v|matches!(v,DeferredResponse::Trace(_)))) && ctx.req().method()==Method::HEAD && response.extensions().get::<StaticHeadLength>().is_some();
        let interim = response
            .extensions()
            .get::<StaticInterimStatus>()
            .map(|code| code.0);
        let mut body = std::mem::replace(response.body_mut(), full(Bytes::new()));
        let deferred = if start == 0 {
            std::mem::take(&mut ctx.deferred)
        } else {
            ctx.deferred.split_off(start)
        };
        for entry in deferred.iter().rev() {
            match entry {
                DeferredResponse::Push(push)=>{
                    if headers.contains_key(http::header::LINK)&&push_links_unseen(ctx){
                        mark_push_links(ctx);push.links(headers,&ctx.authority).await;
                    }
                }
                DeferredResponse::Headers(ops) if explicit => {
                    apply_response_headers(headers, status.as_u16(), ops, ctx).await?;
                }
                DeferredResponse::Headers(_) => {}
                DeferredResponse::Encode(encoding) if explicit => {
                    // Async codecs are not a prepared in-memory entity. A
                    // discarded representation must not start extra work.
                    response.extensions_mut().remove::<crate::metrics::discarded::PreparedEntity>();
                    body = encoding
                        .finish_observed(status, interim, headers, body, &ctx.resources.compression,observed_head)
                        .await;
                }
                DeferredResponse::Encode(_) => {}
                DeferredResponse::LogBody(index) => {
                    log_append::capture_response(ctx, *index, headers, &mut body, explicit).await;
                }
                DeferredResponse::Trace(observation)=>{
                    observation.complete(status.as_u16());
                    let normal_discard=ctx.req().method()==Method::HEAD||status.is_informational()||matches!(status,StatusCode::NO_CONTENT|StatusCode::NOT_MODIFIED);
                    body=super::tracing::attach_body(body,observation.clone(),normal_discard);
                    response.extensions_mut().insert(super::tracing::TracedResponse);
                }
                DeferredResponse::Metrics(observation)=>{
                    observation.complete(status.as_u16(),explicit);
                    body=crate::metrics::observe::attach_body(body,observation.clone());
                }
            }
        }
        *response.body_mut() = body;
        Ok(())
    })
}

fn approximate_request_size(ctx:&Context)->u64 {
    let Some(request)=ctx.request.as_ref() else{return ctx.request_content_length.max(0) as u64};
    let proto=match request.version(){Version::HTTP_09=>8,Version::HTTP_10|Version::HTTP_11=>8,Version::HTTP_2|Version::HTTP_3=>8,_=>8};
    let mut size=request.uri().to_string().len().saturating_add(request.method().as_str().len()).saturating_add(proto).saturating_add(ctx.authority.len()) as u64;
    for name in request.headers().keys(){if name==http::header::HOST{continue;}size=size.saturating_add(name.as_str().len() as u64);for value in request.headers().get_all(name){size=size.saturating_add(value.as_bytes().len() as u64);}}
    size.saturating_add(ctx.request_content_length.max(0) as u64)
}
