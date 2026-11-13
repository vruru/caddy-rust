//! Native HTTP tracing middleware. The SDK context is carried explicitly across
//! async work; no thread-local attachment is held across an await.
use super::{Body,BoxError,request::Context};
use crate::http_config::{PreparedConfig,types::{Route,Handler}};
use crate::metrics::distributed_trace::{config::Config,provider::Provider,processor::Credit};
use opentelemetry::{KeyValue,propagation::{Extractor,Injector,TextMapPropagator},trace::{TraceContextExt,Status}};
use std::{sync::{Arc,atomic::{AtomicBool,AtomicU16,AtomicU64,AtomicUsize,Ordering}},pin::Pin,task::{Context as TaskContext,Poll}};
use http_body_util::BodyExt;
use hyper::body::{Body as _,Frame,SizeHint};
pub(super) fn needed(config:&PreparedConfig)->bool{
 fn routes(list:&[Route])->bool{list.iter().any(|r|r.handlers.iter().any(|h|match h{
  Handler::Tracing(_)=>true,
  Handler::Subroute{routes:r,errors,..}=>routes(r)||routes(errors),
  Handler::ReverseProxy(p)=>p.response_routes.iter().any(|r|r.routes.as_deref().is_some_and(routes)),
  Handler::Intercept(list)=>list.iter().any(|r|r.routes.as_deref().is_some_and(routes)),
  _=>false,
 }))}
 config.servers.iter().any(|s|routes(&s.routes)||routes(&s.errors)||s.named_routes.values().any(|r|routes(std::slice::from_ref(r))))
}
pub(super) struct Observation{
 pub context:opentelemetry::Context,
 credit:Option<Arc<Credit>>,
 _provider:Arc<Provider>,
 bytes:AtomicU64,request_bytes:AtomicU64,status:AtomicU16,finished:AtomicBool,failed:AtomicBool,lifetime:AtomicUsize,
}
impl Observation{
 pub fn complete(&self,status:u16){self.status.store(status,Ordering::Release);}
 pub fn failed(&self,status:u16){self.complete(status);self.failed.store(true,Ordering::Release);self.body_finished();}
 // One atomic state serializes response completion against concrete tunnel
 // owners. No new tunnel may be attached after response completion starts.
 fn retain_tunnel(&self)->bool{
  self.lifetime.fetch_update(Ordering::AcqRel,Ordering::Acquire,|state|{
   (state & BODY_FINISHED==0 && state < BODY_FINISHED-1).then_some(state+1)
  }).is_ok()
 }
 fn body_finished(&self){
  let prior=self.lifetime.fetch_or(BODY_FINISHED,Ordering::AcqRel);
  if prior & !BODY_FINISHED==0{self.finish();}
 }
 fn release_tunnel(&self){
  let prior=self.lifetime.fetch_sub(1,Ordering::AcqRel);
  debug_assert!(prior & !BODY_FINISHED != 0);
  if prior==(BODY_FINISHED|1){self.finish();}
 }
 fn written(&self,count:usize){let _=self.bytes.try_update(Ordering::Relaxed,Ordering::Relaxed,|n|Some(n.saturating_add(count as u64)));}
 fn finish(&self){
  if self.finished.swap(true,Ordering::AcqRel){return}
  let status=self.status.load(Ordering::Acquire);let span=self.context.span();
  if span.is_recording(){
   let read=self.request_bytes.load(Ordering::Relaxed);if read!=0{span.set_attribute(KeyValue::new("http.request.body.size",read.min(i64::MAX as u64)as i64));}
   let written=self.bytes.load(Ordering::Relaxed);if written!=0{span.set_attribute(KeyValue::new("http.response.body.size",written.min(i64::MAX as u64)as i64));}
   if status!=0{span.set_attribute(KeyValue::new("http.response.status_code",status as i64));}
   if status>=500||self.failed.load(Ordering::Acquire){span.set_status(Status::error(""));}
  }
  span.end();
 }
}
impl Drop for Observation{fn drop(&mut self){self.finish();}}
const BODY_FINISHED:usize=1usize<<(usize::BITS-1);
/// Application-owned only: never placed in a transport codec/Quinn owner.
/// Last actor/IO holder releases the span only after response-body completion.
pub(super) struct Tunnel{observations:Vec<Arc<Observation>>,failed:AtomicBool,_credit:Arc<Credit>}
impl Tunnel{
 pub fn capture(observations:impl Iterator<Item=Arc<Observation>>+Clone)->Option<Arc<Self>>{
  let count=observations.clone().filter(|o|o.credit.is_some()).count();
  if count==0{return None}
  let bytes=count.checked_mul(std::mem::size_of::<Arc<Observation>>())?.checked_add(std::mem::size_of::<Self>()+64)?;
  let owner=observations.clone().find_map(|o|o.credit.clone())?;
  if owner.charge(bytes).is_err(){
   for observation in observations{observation._provider.discard(&observation.context);}
   return None
  }
  let mut held=Vec::new();if held.try_reserve_exact(count).is_err(){
   for observation in observations{observation._provider.discard(&observation.context);}
   return None
  }
  for observation in observations{if observation.credit.is_some()&&observation.retain_tunnel(){held.push(observation)}}
  if held.is_empty(){return None}
  Some(Arc::new(Self{observations:held,failed:AtomicBool::new(false),_credit:owner}))
 }
 pub fn failed(&self){self.failed.store(true,Ordering::Release);}
 pub fn written(&self,count:usize){for observation in &self.observations{observation.written(count);}}
 pub fn read(&self,count:usize){for observation in &self.observations{let _=observation.request_bytes.try_update(Ordering::Relaxed,Ordering::Relaxed,|n|Some(n.saturating_add(count as u64)));}}
}
impl Drop for Tunnel{fn drop(&mut self){
 for observation in &self.observations{
  if self.failed.load(Ordering::Acquire){observation.failed.store(true,Ordering::Release);}
  observation.release_tunnel();
 }
}}

struct Carrier<'a>{headers:&'a http::HeaderMap,baggage:Option<String>,capture_baggage:bool}
impl<'a> Carrier<'a>{
 fn new(headers:&'a http::HeaderMap,capture_baggage:bool)->Self{
  let mut baggage=String::new();
  if capture_baggage {for value in headers.get_all("baggage"){
   if baggage.len().saturating_add(value.as_bytes().len()).saturating_add(1)>8192{baggage.clear();break}
   if !baggage.is_empty(){baggage.push(',')}if let Ok(value)=value.to_str(){baggage.push_str(value)}else{baggage.clear();break}
  }}
  Self{headers,baggage:(!baggage.is_empty()).then_some(baggage),capture_baggage}
 }
}
impl Extractor for Carrier<'_>{
 fn get(&self,key:&str)->Option<&str>{
  if key.eq_ignore_ascii_case("baggage"){return self.baggage.as_deref()}
  self.headers.get(key).and_then(|v|v.to_str().ok()).filter(|value|value.len()<=8192)
 }
 fn keys(&self)->Vec<&str>{if self.capture_baggage{self.headers.keys().map(|key|key.as_str()).collect()}else{Vec::new()}}
}
struct HeaderInjector<'a>(&'a mut http::HeaderMap);
impl Injector for HeaderInjector<'_>{
 fn set(&mut self,key:&str,value:String){if let(Ok(key),Ok(value))=(http::HeaderName::from_bytes(key.as_bytes()),http::HeaderValue::try_from(value)){self.0.insert(key,value);}}
}
async fn expand(view:super::request::ReplacerView<'_>,value:&str,credit:&Credit)->anyhow::Result<String>{
 let bytes=view.expand_resolved(value,true).await?;
 credit.charge(bytes.len().saturating_mul(4).saturating_add(8192))?;
 String::from_utf8(bytes.to_vec()).map_err(Into::into)
}
pub(super) async fn enter(ctx:&mut Context,provider:&Arc<Provider>,plan:&Config)->Arc<Observation>{
 let mut credit=provider.admit();
 if let Some(owner)=&credit{
  let request=ctx.req();let input=request.headers().iter().fold(0usize,|n,(key,value)|n.saturating_add(key.as_str().len()+value.as_bytes().len()+64));
  let input=input.saturating_add(request.uri().path_and_query().map_or(0,|p|p.as_str().len())).saturating_add(ctx.authority.len()).saturating_add(plan.span.len());
  if owner.charge(input.saturating_mul(128).saturating_add(32768)).is_err(){provider.process.dropped.fetch_add(1,Ordering::Relaxed);credit=None}
 }
 let parent=ctx.trace_context.clone().unwrap_or_default();
 let parent=provider.propagators.extract_with_context(&parent,&Carrier::new(ctx.req().headers(),credit.is_some()));
 let mut name="handler".to_owned();let mut attributes=Vec::new();
 if let Some(owner)=&credit{
  if let Ok(expanded)=expand(ctx.lookup_view(),&plan.span,owner).await{name=expanded;}
  let request=ctx.req();let scheme=if ctx.tls{"https"}else{"http"};
  let authority=ctx.authority.parse::<http::uri::Authority>().ok();
  let host=authority.as_ref().map_or(ctx.authority.as_str(),|a|a.host()).trim_start_matches('[').trim_end_matches(']');
  let method=request.method().as_str();
  let standard=matches!(method,"CONNECT"|"DELETE"|"GET"|"HEAD"|"OPTIONS"|"PATCH"|"POST"|"PUT"|"TRACE");
  attributes.push(KeyValue::new("server.address",host.to_owned()));
  attributes.push(KeyValue::new("http.request.method",if standard{method.to_owned()}else{"_OTHER".into()}));
  if !standard{attributes.push(KeyValue::new("http.request.method_original",method.to_owned()));}
  attributes.push(KeyValue::new("url.scheme",scheme));
  let port=authority.as_ref().and_then(|a|a.port_u16()).unwrap_or(if ctx.tls{443}else{80});
  if port!=if ctx.tls{443}else{80}{attributes.push(KeyValue::new("server.port",port as i64));}
  let peer=ctx.peer.host();if !peer.is_empty(){attributes.push(KeyValue::new("network.peer.address",peer.clone()));}
  if let Ok(port)=ctx.peer.port_text().parse::<i64>(){if port>0{attributes.push(KeyValue::new("network.peer.port",port));}}
  let client=ctx.client_ip.map_or(peer,|ip|ip.to_string());if !client.is_empty(){attributes.push(KeyValue::new("client.address",client));}
  if let Some(value)=request.headers().get(http::header::USER_AGENT).and_then(|v|v.to_str().ok()){if !value.is_empty(){attributes.push(KeyValue::new("user_agent.original",value.to_owned()));}}
  let path=request.uri().path_and_query().map_or("",|p|p.raw_path());if !path.is_empty(){attributes.push(KeyValue::new("url.path",super::request::decoded_path(path).unwrap_or_else(|_|path.into())));}
  attributes.push(KeyValue::new("network.protocol.version",match request.version(){http::Version::HTTP_10=>"1.0",http::Version::HTTP_2=>"2.0",http::Version::HTTP_3=>"3.0",_=>"1.1"}));
 }
 let context=provider.start(name,attributes,&parent,credit.clone());
 {let span=context.span();let sc=span.span_context();if sc.is_valid(){ctx.values.insert("http.vars.trace_id".into(),sc.trace_id().to_string());ctx.values.insert("http.vars.span_id".into(),sc.span_id().to_string());}}
 provider.propagators.inject_context(&context,&mut HeaderInjector(ctx.req_mut().headers_mut()));
 let observation=Arc::new(Observation{context,credit,_provider:provider.clone(),bytes:AtomicU64::new(0),request_bytes:AtomicU64::new(0),status:AtomicU16::new(0),finished:AtomicBool::new(false),failed:AtomicBool::new(false),lifetime:AtomicUsize::new(0)});
 // Observe actual demand only. No eager read, buffering, task or payload copy.
 let body=std::mem::replace(ctx.req_mut().body_mut(),super::full(bytes::Bytes::new()));
 *ctx.req_mut().body_mut()=RequestTraceBody{body,observation:observation.clone()}.boxed_unsync();
 observation
}
pub(super) fn attributes<'a>(ctx:&'a Context,observation:&'a Observation,plan:&'a Config)->impl std::future::Future<Output=()>+Send+'a{
 let view=ctx.lookup_view();async move{
 let Some(credit)=&observation.credit else{return};let span=observation.context.span();if !span.is_recording(){return}
 for(key,value)in plan.attributes.iter(){
  if credit.charge(key.len()+128).is_err(){break}
  if let Ok(value)=expand(view,value,credit).await{span.set_attribute(KeyValue::new(key.to_string(),value));}
 }
 }}
#[derive(Clone,Copy)]pub(super) struct TracedResponse;
pub(super) fn attach_body(body:Body,observation:Arc<Observation>,normal_discard:bool)->Body{
 TraceBody{body,observation:Some(observation),normal_discard}.boxed_unsync()
}
struct TraceBody{body:Body,observation:Option<Arc<Observation>>,normal_discard:bool}
impl hyper::body::Body for TraceBody{
 type Data=bytes::Bytes;type Error=BoxError;
 fn poll_frame(mut self:Pin<&mut Self>,cx:&mut TaskContext<'_>)->Poll<Option<Result<Frame<Self::Data>,Self::Error>>>{
  match Pin::new(&mut self.body).poll_frame(cx){
   Poll::Ready(Some(Ok(frame)))=>{
    if let Some(obs)=&self.observation{if let Some(data)=frame.data_ref(){if !data.is_empty(){let _=obs.status.compare_exchange(0,200,Ordering::AcqRel,Ordering::Acquire);}let _=obs.bytes.try_update(Ordering::Relaxed,Ordering::Relaxed,|n|Some(n.saturating_add(data.len()as u64)));}}
    if self.body.is_end_stream(){if let Some(obs)=self.observation.take(){obs.body_finished();}}
    Poll::Ready(Some(Ok(frame)))
   }
   Poll::Ready(Some(Err(error)))=>{if let Some(obs)=self.observation.take(){obs.failed.store(true,Ordering::Release);obs.body_finished();}Poll::Ready(Some(Err(error)))}
   Poll::Ready(None)=>{if let Some(obs)=self.observation.take(){obs.body_finished();}Poll::Ready(None)}
   Poll::Pending=>Poll::Pending,
  }
 }
 fn is_end_stream(&self)->bool{self.body.is_end_stream()}
 fn size_hint(&self)->SizeHint{self.body.size_hint()}
}
impl Drop for TraceBody{fn drop(&mut self){if let Some(obs)=self.observation.take(){if !self.normal_discard&&!self.body.is_end_stream(){obs.failed.store(true,Ordering::Release);}obs.body_finished();}}}

struct RequestTraceBody{body:Body,observation:Arc<Observation>}
impl hyper::body::Body for RequestTraceBody{
 type Data=bytes::Bytes;type Error=BoxError;
 fn poll_frame(mut self:Pin<&mut Self>,cx:&mut TaskContext<'_>)->Poll<Option<Result<Frame<Self::Data>,Self::Error>>>{
  let result=Pin::new(&mut self.body).poll_frame(cx);
  if let Poll::Ready(Some(Ok(frame)))=&result{if let Some(data)=frame.data_ref(){let _=self.observation.request_bytes.try_update(Ordering::Relaxed,Ordering::Relaxed,|n|Some(n.saturating_add(data.len()as u64)));}}
  result
 }
 fn is_end_stream(&self)->bool{self.body.is_end_stream()}
 fn size_hint(&self)->SizeHint{self.body.size_hint()}
}

/// A cancelled/dropped application actor is not a successfully closed tunnel.
pub(super) struct TunnelActor{observation:Option<Arc<Tunnel>>,completed:bool}
impl TunnelActor{
 pub fn new(observation:Option<Arc<Tunnel>>)->Self{Self{observation,completed:false}}
 pub fn success(&mut self){self.completed=true;}
}
impl Drop for TunnelActor{fn drop(&mut self){if !self.completed{if let Some(observation)=&self.observation{observation.failed();}}}}

/// The IO is dropped before its observation owner. Count only writes actually
/// accepted by the downstream, never an upstream read or buffered intent.
pub(super) struct ObservedIo<T>{pub inner:T,pub observation:Option<Arc<Tunnel>>}
impl<T:tokio::io::AsyncRead+Unpin> tokio::io::AsyncRead for ObservedIo<T>{
 fn poll_read(self:Pin<&mut Self>,cx:&mut TaskContext<'_>,buf:&mut tokio::io::ReadBuf<'_>)->Poll<std::io::Result<()>>{
  let this=self.get_mut();let before=buf.filled().len();let result=Pin::new(&mut this.inner).poll_read(cx,buf);
  if let Poll::Ready(Ok(()))=&result{if let Some(observation)=&this.observation{observation.read(buf.filled().len().saturating_sub(before));}}
  result
 }
}
impl<T:tokio::io::AsyncWrite+Unpin> tokio::io::AsyncWrite for ObservedIo<T>{
 fn poll_write(self:Pin<&mut Self>,cx:&mut TaskContext<'_>,buf:&[u8])->Poll<std::io::Result<usize>>{
  let this=self.get_mut();let result=Pin::new(&mut this.inner).poll_write(cx,buf);
  if let Poll::Ready(Ok(n))=&result{if let Some(observation)=&this.observation{observation.written(*n);}}
  result
 }
 fn poll_write_vectored(self:Pin<&mut Self>,cx:&mut TaskContext<'_>,bufs:&[std::io::IoSlice<'_>])->Poll<std::io::Result<usize>>{
  let this=self.get_mut();let result=Pin::new(&mut this.inner).poll_write_vectored(cx,bufs);
  if let Poll::Ready(Ok(n))=&result{if let Some(observation)=&this.observation{observation.written(*n);}}
  result
 }
 fn poll_flush(self:Pin<&mut Self>,cx:&mut TaskContext<'_>)->Poll<std::io::Result<()>>{Pin::new(&mut self.get_mut().inner).poll_flush(cx)}
 fn poll_shutdown(self:Pin<&mut Self>,cx:&mut TaskContext<'_>)->Poll<std::io::Result<()>>{Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)}
 fn is_write_vectored(&self)->bool{self.inner.is_write_vectored()}
}
