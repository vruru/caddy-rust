//! Borrowed, immutable replacer inputs. No request body, clones, mutation, or
//! independently reimplemented placeholder semantics are introduced here.
use super::*;
#[derive(Clone,Copy)]
struct Head<'a> {
    uri: &'a Uri,
    method: &'a Method,
    headers: &'a HeaderMap,
    extensions: &'a http::Extensions,
    version: Version,
    expose_host:bool,
    projection: Option<&'a super::super::rewrite_runtime::Projection>,
}
impl<'a> Head<'a> {
    fn uri(&self) -> &'a Uri {
        self.uri
    }
    fn method(&self) -> &'a Method {
        self.method
    }
    fn headers(&self) -> &'a HeaderMap {
        self.headers
    }
    fn extensions(&self) -> &'a http::Extensions {
        self.extensions
    }
    fn version(&self) -> Version {
        self.version
    }
}
#[derive(Clone,Copy)]
pub(in crate::http_runtime) struct View<'a> {
    request: Option<Head<'a>>,
    values: &'a HashMap<String, String>,
    raw_regex_captures: &'a super::super::request_regex::RawCaptures,
    probe: bool,
    authority: &'a str,
    original_uri: &'a Uri,
    original_method: &'a Method,
    peer: &'a NetAddress,
    local: &'a NetAddress,
    tls: bool,
    client_ip: Option<IpAddr>,
    business: &'a Arc<BusinessGuard>,
    maps: &'a [LazyMap],
    resources: &'a super::super::resource_budget::Resources,
    retentions: &'a std::sync::OnceLock<Arc<super::super::map_runtime::TextRetentions>>,
}
impl<'a> View<'a> {
    pub(super) fn new(ctx: &'a Context) -> Self {
        Self {
            request: ctx.request.as_ref().map(|r| Head {
                uri: r.uri(),
                method: r.method(),
                headers: r.headers(),
                extensions: r.extensions(),
                version: r.version(),
                expose_host:false,
                projection: super::super::rewrite_runtime::lookup_projection(r),
            }),
            values: &ctx.values,
            raw_regex_captures: &ctx.raw_regex_captures,
            probe: ctx.probe,
            authority: &ctx.authority,
            original_uri: &ctx.original_uri,
            original_method: &ctx.original_method,
            peer: &ctx.peer,
            local: &ctx.local,
            tls: ctx.tls,
            client_ip: ctx.client_ip,
            business: &ctx.business,
            maps: &ctx.maps,
            resources: &ctx.resources,
            retentions: &ctx._map_text,
        }
    }
    pub(in crate::http_runtime) fn with_headers<'b>(&'b self,headers:&'b HeaderMap)->View<'b>{
        let mut view=*self;if let Some(head)=view.request.as_mut(){head.headers=headers;head.expose_host=true;}view
    }
    pub(in crate::http_runtime) fn pool(&self)->&native_write_policy::Pool{if self.maps.is_empty(){&self.resources.header_replacements}else{&self.resources.map_bytes}}
    pub(in crate::http_runtime) fn map_plans(&self)->&[LazyMap]{self.maps}
    pub(in crate::http_runtime) fn value(&self, name: &str) -> Option<&'a str> {
        self.values.get(name).map(String::as_str)
    }
    pub(in crate::http_runtime) fn headers(&self) -> Option<&'a HeaderMap> {
        self.request.as_ref().map(Head::headers)
    }
    fn req(&self) -> &Head<'a> {
        self.request
            .as_ref()
            .expect("request is consumed only by terminal proxy")
    }
    pub(in crate::http_runtime) fn lookup_bytes(&self, name: &str) -> Option<Vec<u8>> {
        self.lookup_bytes_inner(name,&std::cell::Cell::new(false))
    }
    fn lookup_bytes_inner(&self,name:&str,missing:&std::cell::Cell<bool>)->Option<Vec<u8>>{
        if let Some(value) = self.raw_regex_captures.get(name) {
            return Some(value.to_vec());
        }
        if !self.values.contains_key(name)
            && let Some(rewrite) = self.request.as_ref().and_then(|r| r.projection)
        {
            if name == "http.request.uri" {
                return Some(rewrite.request_uri.to_vec());
            }
            if name == "http.request.uri.path" {
                return Some(rewrite.state.path.clone());
            }
            if name == "http.request.uri.query" {
                return Some(rewrite.state.query.clone());
            }
        }
        if !self.probe && !self.values.contains_key(name) {
            let address = match name {
                "http.request.remote" | "http.request.remote.host" | "http.request.remote.port" => {
                    Some(self.peer)
                }
                "http.request.local" | "http.request.local.host" | "http.request.local.port" => {
                    Some(self.local)
                }
                _ => None,
            };
            if let Some(address) = address {
                return Some(if name.ends_with(".host") {
                    address.raw_host().into_owned()
                } else if name.ends_with(".port") {
                    address.raw_port().into_owned()
                } else {
                    address.raw_text().into_owned()
                });
            }
        }
        if !self.values.contains_key(name)
            && let Some(req) = self.request.as_ref()
        {
            if matches!(name, "http.request.uri.path" | "http.request.orig_uri.path") {
                let uri = if name == "http.request.orig_uri.path" {
                    &self.original_uri
                } else {
                    req.extensions()
                        .get::<super::super::rewrite_runtime::Original>()
                        .map_or_else(|| req.uri(), |v| &v.uri)
                };
                return super::super::http_redirect::url::template_decode_bytes(
                    uri.path_and_query().map_or("", |p| p.raw_path()).as_bytes(),
                )
                .ok();
            }
            if let Some(field) = name.strip_prefix("http.request.header.") {
                if field.eq_ignore_ascii_case("Host")&&!req.expose_host {
                    return Some(Vec::new());
                }
                let values = req.headers().get_all(field);
                let mut out = Vec::new();
                for (i, value) in values.iter().enumerate() {
                    if i > 0 {
                        out.push(b',');
                    }
                    out.extend_from_slice(value.as_bytes());
                }
                return Some(out);
            }
            if let Some(key) = name.strip_prefix("http.request.uri.query.") {
                let query = self.replacer_query();
                let mut out = Vec::with_capacity(query.len());
                let mut first = true;
                for part in query.split(|b| *b == b'&') {
                    if let Some((k, v)) = super::super::query_match::query_pair(part)
                        && k.as_ref() == key.as_bytes()
                    {
                        if !first {
                            out.push(b',');
                        }
                        first = false;
                        out.extend_from_slice(&v);
                    }
                }
                return Some(out);
            }
        }
        self.lookup_depth(name,0,missing).map(String::into_bytes)
    }
    pub(super) fn replacer_query(&self) -> &[u8] {
        let req = self.req();
        if let Some(p) = req.projection {
            &p.state.query
        } else {
            let uri = req
                .extensions()
                .get::<super::super::rewrite_runtime::Original>()
                .map_or_else(|| req.uri(), |v| &v.uri);
            uri.query().unwrap_or_default().as_bytes()
        }
    }
    pub(in crate::http_runtime) fn lookup(&self, name: &str) -> Option<String> {
        self.lookup_depth(name, 0,&std::cell::Cell::new(false))
    }
    fn lookup_depth(&self, name: &str, depth: usize,missing:&std::cell::Cell<bool>) -> Option<String> {
        if let Some(value) = self.raw_regex_captures.get(name) {
            return std::str::from_utf8(value).ok().map(str::to_owned);
        }
        if let Some(value) = crate::http_config::helpers::global_lookup(name) {
            return Some(value);
        }
        if self.probe {
            return None;
        }
        if depth > 64 {
            return None;
        }
        if let Some(value) = self.values.get(name) {
            return Some(value.clone());
        }
        let req = self.request.as_ref();
        let source = req.and_then(|r| {
            r.extensions()
                .get::<super::super::rewrite_runtime::Original>()
        });
        let lookup_uri = source.map(|s| &s.uri).or_else(|| req.map(Head::uri));
        let lookup_method = source.map(|s| &s.method).or_else(|| req.map(Head::method));
        Some(match name {
            "http.shutting_down" => self.business.generation().shutting_down().to_string(),
            "http.time_until_shutdown" => self
                .business
                .generation()
                .time_until_shutdown()
                .unwrap_or_default(),
            "http.request.hostport" => self.authority.to_owned(),
            "http.request.host" => hostname(&self.authority),
            "http.request.port" => self
                .authority
                .parse::<http::uri::Authority>()
                .ok()
                .and_then(|a| a.port_u16())
                .map(|p| p.to_string())
                .unwrap_or_default(),
            "http.request.remote" => self.peer.to_string(),
            "http.request.remote.host" => self.peer.host(),
            "http.request.remote.port" => self.peer.port_text(),
            "http.request.local" => self.local.to_string(),
            "http.request.local.host" => self.local.host(),
            "http.request.local.port" => self.local.port_text(),
            "http.request.client_ip" | "http.vars.client_ip" => {
                self.client_ip.map_or_else(String::new, |ip| ip.to_string())
            }
            "http.request.scheme" => {
                if self.tls {
                    "https".into()
                } else {
                    "http".into()
                }
            }
            "http.request.method" => lookup_method?.to_string(),
            "http.request.orig_method" => self.original_method.to_string(),
            "http.request.uri" if req.and_then(|r| r.projection).is_some() => {
                String::from_utf8(self.lookup_bytes_inner(name,missing)?).ok()?
            }
            "http.request.uri.query" if req.and_then(|r| r.projection).is_some() => {
                String::from_utf8(self.lookup_bytes_inner(name,missing)?).ok()?
            }
            "http.request.uri" => lookup_uri?
                .path_and_query()
                .map(|x| x.as_str())
                .unwrap_or("/")
                .to_owned(),
            "http.request.uri.path" => String::from_utf8(self.lookup_bytes_inner(name,missing)?).ok()?,
            "http.request.uri.query" => lookup_uri?.query().unwrap_or_default().to_owned(),
            "http.request.orig_uri" => self
                .original_uri
                .path_and_query()
                .map(|x| x.as_str())
                .unwrap_or("/")
                .to_owned(),
            "http.request.orig_uri.path" => String::from_utf8(self.lookup_bytes_inner(name,missing)?).ok()?,
            "http.request.orig_uri.query" => {
                self.original_uri.query().unwrap_or_default().to_owned()
            }
            "http.request.orig_uri.prefixed_query" => self
                .original_uri
                .query()
                .filter(|query| !query.is_empty())
                .map(|query| format!("?{query}"))
                .unwrap_or_default(),
            "http.request.proto" => match req?.version() {
                Version::HTTP_3 => "HTTP/3.0",
                Version::HTTP_2 => "HTTP/2.0",
                Version::HTTP_10 => "HTTP/1.0",
                _ => "HTTP/1.1",
            }
            .into(),
            "http.vars.root" => ".".into(),
            _ if name.starts_with("http.request.header.")
                || name.starts_with("http.request.uri.query.") =>
            {
                String::from_utf8(self.lookup_bytes_inner(name,missing)?).ok()?
            }
            _ => {missing.set(true);return None;}
        })
    }
}

// The lease sits outside the box: even an unpolled/cancelled future frees its
// allocation before returning metadata credit. Rejection allocates no box.
pub(in crate::http_runtime) struct ResolvedValue{pub bytes:Bytes,pub null:bool}
pub(in crate::http_runtime) enum ResolvedFuture<'a>{
    Primitive(Option<(View<'a>,&'a str)>),
    Running{future:Pin<Box<dyn Future<Output=Result<Option<ResolvedValue>>>+Send+'a>>,_frame:native_write_policy::Lease},
    Rejected(Option<anyhow::Error>),
}
impl Future for ResolvedFuture<'_>{
    type Output=Result<Option<ResolvedValue>>;
    fn poll(self:Pin<&mut Self>,cx:&mut std::task::Context<'_>)->std::task::Poll<Self::Output>{
        match self.get_mut(){
            Self::Primitive(input)=>{let(view,name)=input.take().expect("future polled after completion");std::task::Poll::Ready(Ok(view.lookup_bytes(name).map(|bytes|ResolvedValue{bytes:Bytes::from(bytes),null:false})))},
            Self::Running{future,..}=>future.as_mut().poll(cx),Self::Rejected(error)=>std::task::Poll::Ready(Err(error.take().expect("future polled after completion")))
        }
    }
}
struct Depth<'v,'r>{view:&'v View<'r>,depth:usize,deadline:std::time::Instant}
impl super::super::replacer_async::Lookup for Depth<'_,'_>{
    fn lookup<'a>(&'a self,name:&'a str)->impl Future<Output=Result<Option<Bytes>>>+Send+'a{
        async move{Ok(self.view.lookup_resolved_depth(name,self.depth,self.deadline).await?.map(|value|value.bytes))}
    }
}
struct RootLookup<'v,'r>{view:&'v View<'r>,deadline:std::time::Instant}
impl super::super::replacer_async::Lookup for RootLookup<'_,'_>{
    fn lookup<'a>(&'a self,name:&'a str)->impl Future<Output=Result<Option<Bytes>>>+Send+'a{
        async move{Ok(Some(self.view.lookup_resolved_depth(name,0,self.deadline).await?.map(|value|value.bytes).unwrap_or_else(||Bytes::from_static(b"."))))}
    }
}
impl View<'_>{
    pub(in crate::http_runtime) fn lookup_resolved<'a>(&'a self,name:&'a str)->impl Future<Output=Result<Option<Bytes>>>+Send+'a{
        async move{Ok(self.lookup_resolved_depth(name,0,std::time::Instant::now()+std::time::Duration::from_secs(5)).await?.map(|value|value.bytes))}
    }
    pub(in crate::http_runtime) fn lookup_typed_resolved<'a>(&'a self,name:&'a str)->ResolvedFuture<'a>{self.lookup_resolved_depth(name,0,std::time::Instant::now()+std::time::Duration::from_secs(5))}
    fn lookup_resolved_depth<'a>(&'a self,name:&'a str,depth:usize,deadline:std::time::Instant)->ResolvedFuture<'a>{
        if self.maps.is_empty(){return ResolvedFuture::Primitive(Some((*self,name)))}
        let credit=match self.resources.map_bytes.reserve(4096){Ok(credit)=>credit,Err(_)=>return ResolvedFuture::Rejected(Some(failure(http::StatusCode::SERVICE_UNAVAILABLE)))};
        ResolvedFuture::Running{_frame:credit,future:Box::pin(async move{
            ensure!(std::time::Instant::now()<deadline,"map work deadline exceeded");
            if depth>64{
                // The legacy recursion guard precedes request/variable lookup,
                // but follows raw captures and process-global providers.
                let _temporary=self.resources.map_bytes.reserve(8<<20).map_err(|_|failure(http::StatusCode::SERVICE_UNAVAILABLE))?;
                let raw=self.raw_regex_captures.get(name).map(|bytes|bytes.to_vec()).or_else(||crate::http_config::helpers::global_lookup(name).map(String::into_bytes));
                return match raw{Some(bytes)=>{let credit=self.resources.map_bytes.reserve(bytes.len().saturating_mul(2)+1024).map_err(|_|failure(http::StatusCode::SERVICE_UNAVAILABLE))?;Ok(Some(ResolvedValue{bytes:super::super::map_runtime::owned(bytes,credit),null:false}))},None=>Ok(None)}
            }
            let (direct,missing)={
                let _temporary=self.resources.map_bytes.reserve(8<<20).map_err(|_|failure(http::StatusCode::SERVICE_UNAVAILABLE))?;
                let missing=std::cell::Cell::new(false);
                let direct=self.lookup_bytes_inner(name,&missing);
                let direct=if let Some(bytes)=direct{
                    ensure!(bytes.len()<=super::super::map_runtime::CAP,"map placeholder value exceeds limit");
                    let credit=self.resources.map_bytes.reserve(bytes.len().saturating_mul(2)+1024).map_err(|_|failure(http::StatusCode::SERVICE_UNAVAILABLE))?;
                    Some(ResolvedValue{bytes:super::super::map_runtime::owned(bytes,credit),null:false})
                }else{None};
                (direct,missing.get())
            };
            if !missing{return Ok(direct)}
            for (at,map) in self.maps.iter().enumerate(){
                if at>0&&at.is_multiple_of(128){tokio::task::yield_now().await;}
                let mut index=None;
                for (i,dest)in map.destinations.iter().enumerate(){
                    if i>0&&i.is_multiple_of(128){tokio::task::yield_now().await;}
                    if dest==name{index=Some(i);break;}
                }
                let Some(index)=index else{continue};
                let lookup=Depth{view:self,depth:depth+1,deadline};
                let input=super::super::replacer_async::expand(&map.source,true,&lookup,&self.resources.map_bytes).await?;
                let selected=super::super::map_runtime::select_until(self.resources,map,index,input,deadline).await.map_err(|_|failure(http::StatusCode::SERVICE_UNAVAILABLE))?;
                if !selected.expand{return Ok(Some(ResolvedValue{bytes:selected.bytes,null:selected.null}))}
                let text=std::str::from_utf8(&selected.bytes)?;
                return Ok(Some(ResolvedValue{bytes:super::super::replacer_async::expand(text,true,&lookup,&self.resources.map_bytes).await?,null:false}))
            }
            Ok(None)
        })}
    }
    pub(in crate::http_runtime) async fn root_resolved(&self,text:&str)->Result<String>{
        if self.maps.is_empty(){return crate::http_config::helpers::replace(text,true,|name|Some(self.lookup(name).unwrap_or_else(||".".into())))}
        let lookup=RootLookup{view:self,deadline:std::time::Instant::now()+std::time::Duration::from_secs(5)};
        let bytes=super::super::replacer_async::expand(text,true,&lookup,&self.resources.map_bytes).await?;
        let text=std::str::from_utf8(&bytes)?;self.retain_text(bytes.clone())?;Ok(text.to_owned())
    }
    pub(in crate::http_runtime) async fn expand_root_bytes_limited(&self,text:&str,limit:usize)->Result<Bytes>{
        let lookup=RootLookup{view:self,deadline:std::time::Instant::now()+std::time::Duration::from_secs(5)};
        super::super::replacer_async::expand_limited(text,true,&lookup,self.pool(),limit).await
    }
    pub(in crate::http_runtime) fn retain_text(&self,bytes:Bytes)->Result<()>{
        if self.retentions.get().is_none(){let owner=super::super::map_runtime::TextRetentions::new(&self.resources.map_bytes).map_err(|_|failure(http::StatusCode::SERVICE_UNAVAILABLE))?;let _=self.retentions.set(owner);}
        self.retentions.get().expect("initialized map text owner").retain(bytes).map_err(|_|failure(http::StatusCode::SERVICE_UNAVAILABLE))
    }
    pub(in crate::http_runtime) fn reserve_text_copy(&self,bytes:usize)->Result<()>{
        if self.retentions.get().is_none()&&!self.maps.is_empty(){let owner=super::super::map_runtime::TextRetentions::new(&self.resources.map_bytes).map_err(|_|failure(http::StatusCode::SERVICE_UNAVAILABLE))?;let _=self.retentions.set(owner);}
        if let Some(owner)=self.retentions.get(){owner.reserve_copy(bytes).map_err(|_|failure(http::StatusCode::SERVICE_UNAVAILABLE))?;}Ok(())
    }
    pub(in crate::http_runtime) async fn lookup_text_resolved(&self,name:&str)->Result<Option<String>>{
        if self.maps.is_empty(){return Ok(self.lookup(name))}
        let Some(bytes)=self.lookup_resolved(name).await?else{return Ok(None)};
        let Ok(text)=std::str::from_utf8(&bytes)else{return Ok(None)};
        self.retain_text(bytes.clone())?;Ok(Some(text.to_owned()))
    }
    pub(in crate::http_runtime) async fn expand_text_resolved(&self,text:&str,unknown_empty:bool)->Result<String>{
        if self.maps.is_empty(){return crate::http_config::helpers::replace(text,unknown_empty,|name|self.lookup(name))}
        if !text.as_bytes().iter().any(|b|matches!(b,b'{'|b'}')){return Ok(text.to_owned())}
        let value=self.expand_resolved(text,unknown_empty).await?;
        let text=std::str::from_utf8(&value)?;self.retain_text(value.clone())?;Ok(text.to_owned())
    }
    pub(in crate::http_runtime) async fn expand_resolved(&self,text:&str,unknown_empty:bool)->Result<Bytes>{
        if self.maps.is_empty(){return crate::http_config::helpers::replace_bytes(text,unknown_empty,|name|self.lookup_bytes(name)).map(Bytes::from)}
        if !text.as_bytes().iter().any(|b|matches!(b,b'{'|b'}')){return Ok(Bytes::copy_from_slice(text.as_bytes()))}
        let lookup=Depth{view:self,depth:0,deadline:std::time::Instant::now()+std::time::Duration::from_secs(5)};
        super::super::replacer_async::expand(text,unknown_empty,&lookup,&self.resources.map_bytes).await
    }
}
