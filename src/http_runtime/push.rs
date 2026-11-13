//! Native HTTP/2 Push dispatch. Child requests retain the accepted generation;
//! neither a later reload nor the parent's RST can attach them to another one.
use super::*;
use crate::http_config::types::PushConfig;
use super::request::{Context,InformationalOutput,RequestOrigin};
use http::{HeaderMap,HeaderValue,Method,Version};
use hyper::{ext::ServerPush,body::Body as _};
use std::sync::Arc;

pub(super) struct LinkPlan{
    headers:HeaderMap,push:ServerPush,inner:Arc<Inner>,server:Arc<ActiveServer>,
    peer:crate::net_address::NetAddress,local:crate::net_address::NetAddress,tls:bool,sni:Option<String>,
    business:Arc<BusinessGuard>,snapshot:Option<Arc<ConnectionSnapshot>>,
    facts:Option<Arc<client_cert_facts::Cache>>,details:Option<fastcgi::TlsDetails>,
    access_tls:Option<Arc<access_log::Tls>>,
    _credit:Bytes,
}
fn header_bytes(fields:&HeaderMap)->Option<usize>{
    fields.iter().try_fold(0usize,|n,(name,value)|n.checked_add(name.as_str().len())?.checked_add(value.len())?.checked_add(32)).filter(|n|*n<=65536)
}
impl LinkPlan{
 pub(super) fn new<'a>(ctx:&'a Context,config:&'a PushConfig,inner:&Arc<Inner>,server:&Arc<ActiveServer>)->std::pin::Pin<Box<dyn std::future::Future<Output=Result<Option<Arc<Self>>>>+Send+'a>>{
    let prepared=(||->Result<Option<(Self,super::headers_replace::Prepared<'a>)>>{
    let Some(push)=ctx.req().extensions().get::<ServerPush>()else{return Ok(None)};
    if ctx.req().headers().contains_key("caddy-push"){return Ok(None)}
    // Fixed bounded retained head/queue scratch. Prepay before copying fields;
    // children obtain independent admission before their own allocations.
    let credit=inner.resources.transfer_deadlines.reserve(1<<20)?;
    let mut headers=HeaderMap::new();headers.insert("caddy-push",HeaderValue::from_static("1"));
    for name in ["accept-encoding","accept-language","accept","cache-control","user-agent"]{
        for value in ctx.req().headers().get_all(name){
            let before=header_bytes(&headers).ok_or_else(||anyhow::anyhow!("pushed request headers exceed limit"))?;
            anyhow::ensure!(before.saturating_add(name.len()).saturating_add(value.len()).saturating_add(32)<=65536,"pushed request headers exceed limit");
            headers.append(name,HeaderValue::from_bytes(value.as_bytes())?);
        }
    }

    anyhow::ensure!(header_bytes(&headers).is_some(),"pushed request headers exceed limit");
    let replacement=super::headers_replace::prepare_owned(&config.headers,ctx,super::headers_replace::Scope::Original)?;
    Ok(Some((Self{headers,push:push.clone(),inner:inner.clone(),server:server.clone(),peer:ctx.peer.clone(),local:ctx.local.clone(),tls:ctx.tls,sni:ctx.push_sni.clone(),business:ctx.business.clone(),
        snapshot:ctx.req().extensions().get::<Arc<ConnectionSnapshot>>().cloned(),facts:ctx.req().extensions().get::<Arc<client_cert_facts::Cache>>().cloned(),details:ctx.req().extensions().get::<fastcgi::TlsDetails>().cloned(),access_tls:ctx.req().extensions().get::<Arc<access_log::Tls>>().cloned(),_credit:Bytes::from_owner(credit)},replacement)))
    })();
    let view=ctx.lookup_view();let header_pool=ctx.resources.transfer_deadlines.clone();
    Box::pin(async move{let Some((mut plan,replacement))=prepared? else{return Ok(None)};
        super::request::apply_push_headers_view(&mut plan.headers,&config.headers,view,header_pool).await?;
        super::headers_replace::apply_owned(&mut plan.headers,&config.headers,replacement,Some(65536)).await?;
        Ok(Some(Arc::new(plan)))
    })
 }
 pub(super) fn dispatch_bytes<'a>(&'a self,target:&'a [u8],method:&'a str,authority:&'a str)->std::pin::Pin<Box<dyn std::future::Future<Output=Result<()>>+Send+'a>>{
    Box::pin(async move{
    // Go rejects framing and authority fields supplied in PushOptions.Header.
    anyhow::ensure!(!["content-length","content-encoding","trailer","te","expect","host"].iter().any(|key|self.headers.contains_key(*key)),"invalid push request header");
    let method=if method.is_empty(){Method::GET}else{Method::from_bytes(method.as_bytes())?};
    anyhow::ensure!(matches!(method,Method::GET|Method::HEAD),"push method must be GET or HEAD");
    anyhow::ensure!(target.len()<=65536,"push target exceeds limit");
    let credit=self.inner.resources.transfer_deadlines.reserve(1<<20)?;
    let target=crate::go_url_compat::push_target_bytes(target,if self.tls{"https"}else{"http"},authority).map_err(|_|anyhow::anyhow!("invalid push target"))?;
    anyhow::ensure!(target.len()<=65536,"push target exceeds limit");
    let (seed,control)=super::route_timeouts::PushSeed::new(&self.inner.resources.transfer_deadlines,&self.server.plan)?;
    let mut promise=Request::builder().version(Version::HTTP_2).method(method.clone()).uri(&target).body(())?;
    for(name,value)in &self.headers{promise.headers_mut().append(name.clone(),HeaderValue::from_bytes(value.as_bytes())?);}
    let retained=Bytes::from_owner(credit);
    let mut writer=self.push.promise(promise,control,retained.clone()).await?;
    let mut request=Request::builder().version(Version::HTTP_2).method(method).uri(&target).body(Full::new(Bytes::new()))?;
    for(name,value)in &self.headers{request.headers_mut().append(name.clone(),HeaderValue::from_bytes(value.as_bytes())?);}
    request.extensions_mut().insert(seed);
    if let Some(value)=&self.snapshot{request.extensions_mut().insert(value.clone());}
    if let Some(value)=&self.facts{request.extensions_mut().insert(value.clone());}
    if let Some(value)=&self.details{request.extensions_mut().insert(value.clone());}
    if let Some(value)=&self.access_tls{request.extensions_mut().insert(value.clone());}
    let inner=self.inner.clone();let server=self.server.clone();let business=self.business.clone();
    let peer=self.peer.clone();let local=self.local.clone();let tls=self.tls;let sni=self.sni.clone();
    let hard=business.generation().hard_stop.clone();
    let informational=writer.take_informational().map(InformationalOutput::Http);
    tokio::spawn(async move{
        let operation=async move{
            let response=super::request::handle_business(inner,server,request,RequestOrigin{peer,local,tls,sni:sni.as_deref()},business.clone(),informational).await;
            let(parts,mut body)=response.into_parts();let end=body.is_end_stream();
            writer.send_response(Response::from_parts(parts,()),end).await?;
            if !end{
                while let Some(frame)=body.frame().await{
                    let frame=frame.map_err(|error|anyhow::anyhow!("pushed response body failed: {error}"))?;
                    match frame.into_data(){
                        Ok(mut bytes)=>{while !bytes.is_empty(){let data=bytes.split_to(bytes.len().min(16<<10));writer.send_data(data,false).await?;}},
                        Err(frame)=>if let Ok(trailers)=frame.into_trailers(){writer.send_trailers(trailers).await?;return Ok::<_,anyhow::Error>(())},
                    }
                }
                writer.send_data(Bytes::new(),true).await?;
            }
            // Retain request metadata and the original generation through FIN.
            drop(retained);drop(business);Ok::<_,anyhow::Error>(())
        };
        tokio::select!{biased;_ = hard.cancelled()=>{},_ = operation=>{}}
    });
    Ok(())
    })
 }
 pub(super) async fn links(&self,fields:&HeaderMap,authority:&str){
    for field in fields.get_all(http::header::LINK){
        for target in link_targets(field.as_bytes()){if self.dispatch_bytes(target,"",authority).await.is_err(){return}}
    }
 }
}
// Pinned Caddy Link splitting, with malformed-angle panic repaired. The parser
// intentionally does not reinterpret quoting, rel values or parameter casing.
fn link_targets(header:&[u8])->impl Iterator<Item=&[u8]>{
    use crate::logging::trim_go_space_bytes as trim;
    header.split(|b|*b==b',').filter_map(|segment|{
        let li=segment.iter().position(|b|*b==b'<')?;let ri=segment.iter().position(|b|*b==b'>')?;if ri<=li{return None}
        let uri=trim(&segment[li+1..ri]);
        if segment[ri+1..].split(|b|*b==b';').any(|param|{
            let param=trim(param);let key=param.iter().position(|b|*b==b'=').map_or(param,|i|&param[..i]);trim(key)==b"nopush"
        }){return None}
        if uri.starts_with(b"//")||uri.starts_with(b"http://")||uri.starts_with(b"https://"){None}else{Some(uri)}
    })
}

pub(super) fn configured(server:&ServerConfig)->bool{
    fn routes(list:&[crate::http_config::types::Route])->bool{list.iter().any(route)}
    fn route(route:&crate::http_config::types::Route)->bool{route.handlers.iter().any(|handler|match handler{
        Handler::Push(_)=>true,
        Handler::Subroute{routes:list,errors,..}=>routes(list)||routes(errors),
        Handler::ReverseProxy(proxy)=>proxy.response_routes.iter().any(|response|response.routes.as_deref().is_some_and(routes)),
        _=>false,
    })}
    routes(&server.routes)||routes(&server.errors)||server.named_routes.values().any(route)
}

pub(super) fn expand_target<'a>(ctx:&'a Context,raw:&'a str)->impl std::future::Future<Output=Result<(Bytes,native_write_policy::Lease)>>+Send+'a{
    let view=ctx.lookup_view();let pool=ctx.resources.transfer_deadlines.clone();
    async move{
        let credit=pool.reserve(8<<20)?;
        let output=view.expand_root_bytes_limited(raw,65536).await?;
        Ok((output,credit))
    }
}
