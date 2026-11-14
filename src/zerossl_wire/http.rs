//! Bounded JSON body ownership. No request/body retry is introduced here.
use super::*;
use serde::{Serialize,de::DeserializeOwned};
use std::{io::Write,mem::{align_of,size_of}};
pub(super) struct BodyBytes {bytes:Vec<u8>,_memory:Lease}
impl AsRef<[u8]> for BodyBytes{fn as_ref(&self)->&[u8]{&self.bytes}}
impl Drop for BodyBytes{fn drop(&mut self){use zeroize::Zeroize;self.bytes.zeroize();}}
struct Count(usize);
impl Write for Count {
 fn write(&mut self,b:&[u8])->std::io::Result<usize>{self.0=self.0.checked_add(b.len()).filter(|n|*n<=BODY_LIMIT).ok_or_else(||std::io::Error::other("ZeroSSL JSON exceeds limit"))?;Ok(b.len())}
 fn flush(&mut self)->std::io::Result<()>{Ok(())}
}
pub(super) fn encode(value:&impl Serialize)->Result<BodyBytes>{
 let mut count=Count(0);serde_json::to_writer(&mut count,value).map_err(|_|anyhow::anyhow!("ZeroSSL request encoding failed"))?;
 let memory=chain_memory::shared().payload.reserve(count.0+size_of::<BodyBytes>()+128)?;
 let mut bytes=Vec::new();bytes.try_reserve_exact(count.0).map_err(|_|crate::cert_transient::ResourceDenied)?;bytes.resize(count.0,0);
 let mut output=bytes.as_mut_slice();serde_json::to_writer(&mut output,value).map_err(|_|anyhow::anyhow!("ZeroSSL request encoding failed"))?;ensure!(output.is_empty(),"ZeroSSL JSON size changed");Ok(BodyBytes{bytes,_memory:memory})
}
struct Collector {bytes:Vec<u8>,memory:Lease}
impl Collector {
 fn new()->Result<Self>{Ok(Self{bytes:Vec::new(),memory:chain_memory::shared().payload.reserve(size_of::<Self>()+128)?})}
 fn append(mut self,chunk:bytes::Bytes)->Result<Self>{
  let required=self.bytes.len().checked_add(chunk.len()).ok_or(crate::cert_transient::ResourceDenied)?;ensure!(required<=BODY_LIMIT,"ZeroSSL response exceeds limit");
  if required>self.bytes.capacity(){
   let capacity=required.checked_next_power_of_two().ok_or(crate::cert_transient::ResourceDenied)?.min(BODY_LIMIT);
   self.memory.resize(capacity+size_of::<Self>()+128)?;let staging=chain_memory::shared().staging.reserve(self.bytes.capacity())?;
   let mut next=Vec::new();next.try_reserve_exact(capacity).map_err(|_|crate::cert_transient::ResourceDenied)?;next.extend_from_slice(&self.bytes);
   let mut old=std::mem::replace(&mut self.bytes,next);use zeroize::Zeroize;old.zeroize();drop(old);drop(staging);
  }
  self.bytes.extend_from_slice(&chunk);Ok(self)
 }
}
impl Drop for Collector{fn drop(&mut self){use zeroize::Zeroize;self.bytes.zeroize();}}
struct Append {collector:Collector,chunk:bytes::Bytes}
impl Append{fn execute(self)->Result<Collector>{self.collector.append(self.chunk)}}
struct Reply {status:u16,body:Collector,_owner:ClientOwner}
fn node_bound<T>()->usize{
 let align=align_of::<T>().max(align_of::<String>()).max(align_of::<usize>());
 let fields=size_of::<Option<std::ptr::NonNull<()>>>()+2*size_of::<u16>()+11*(size_of::<String>()+size_of::<T>());
 (fields+5*align+align-1)/align*align+12*size_of::<usize>()+align
}
fn nodes(n:usize)->usize{if n==0{0}else{1+(n-1)/5}}
fn typed_extra(value:&serde_json::Value)->Result<usize>{
 // This closed model's widest dynamic typed-map value is ValidationObject.
 // Empty/default fields allocate no heap. Moving from Value retains string
 // allocations; Value footprint plus NEW wider nodes bounds the handoff peak.
 let n=value.get("validation").and_then(|v|v.get("other_methods")).and_then(serde_json::Value::as_object).map_or(0,|m|m.len());
 nodes(n).checked_mul(node_bound::<models::ValidationObject>()).and_then(|n|n.checked_add(size_of::<models::CertificateObject>()+4096)).ok_or_else(||crate::cert_transient::ResourceDenied.into())
}
impl Reply {
 fn parse<T:DeserializeOwned>(self)->Result<Owned<T>>{
  let pools=chain_memory::shared();let footprint=crate::cert_json_shape::footprint(&self.body.bytes)?;
  let mut dom_credit=pools.payload.reserve(footprint.owned.checked_add(256).ok_or(crate::cert_transient::ResourceDenied)?)?;
  let _temporary=chain_memory::try_scratch(footprint.temporary.checked_add(4096).ok_or(crate::cert_transient::ResourceDenied)?)?;
  let value:serde_json::Value=match serde_json::from_slice(&self.body.bytes){Ok(value)=>value,Err(_)=>{
   if !(200..300).contains(&self.status){dom_credit.resize(size_of::<models::ApiError>()+128)?;return Err(models::ApiError{http_status:self.status,info:Default::default(),_memory:dom_credit}.into())}
   return Err(InvalidResponse.into())
  }};
  let bytes=footprint.owned.checked_add(typed_extra(&value)?).and_then(|n|n.checked_add(size_of::<T>()+128)).ok_or(crate::cert_transient::ResourceDenied)?;
  let resident=pools.payload.reserve(bytes)?;
  let rejected=match value.get("success") {None|Some(serde_json::Value::Null)=>false,Some(v)=>{
   !match v {serde_json::Value::Bool(v)=>*v,serde_json::Value::Number(v)=>v.as_i64()==Some(1),serde_json::Value::String(v)=>v.eq_ignore_ascii_case("true")||v=="1"||v.eq_ignore_ascii_case("yes")||v.eq_ignore_ascii_case("y"),_=>false}
  }};
  if rejected||!(200..300).contains(&self.status){
   let parsed:models::ApiReplyError=serde_json::from_value(value).map_err(|_|InvalidResponse)?;
   drop(dom_credit);return Err(models::ApiError{http_status:self.status,info:parsed.error,_memory:resident}.into())
  }
  let parsed:T=serde_json::from_value(value).map_err(|_|InvalidResponse)?;drop(dom_credit);Ok(Owned{value:parsed,_memory:resident})
 }
}
impl Wire {
 pub(super) async fn request<T:DeserializeOwned+Send+'static>(&self,method:reqwest::Method,path:&[&str],query:Option<(&str,&str)>,body:Option<BodyBytes>,cancel:&CancellationToken)->Result<Owned<T>>{
  if cancel.is_cancelled(){return Err(Cancelled.into())}
  let url_bytes=path.iter().try_fold(128usize,|n,s|s.len().checked_mul(3).and_then(|m|n.checked_add(m)).ok_or(crate::cert_transient::ResourceDenied))?;
  let _url=chain_memory::try_scratch(url_bytes+128)?;
  let mut url=self.inner.base.clone();url.path_segments_mut().map_err(|_|anyhow::anyhow!("invalid fixed ZeroSSL endpoint"))?.clear().extend(path);
  if let Some((key,value))=query{url.query_pairs_mut().append_pair(key,value);}
  let mut request=self.inner.client.request(method,url);
  if let Some(body)=body {request=request.header(reqwest::header::CONTENT_TYPE,"application/json").body(bytes::Bytes::from_owner(body));}
  let mut response=tokio::select!{biased;_=cancel.cancelled()=>return Err(Cancelled.into()),result=request.send()=>result.map_err(|e|e.without_url())?};
  ensure!(!response.content_length().is_some_and(|n|n>BODY_LIMIT as u64),"ZeroSSL response exceeds limit");let status=response.status().as_u16();
  let mut collector=Collector::new()?;
  loop {
   let chunk=tokio::select!{biased;_=cancel.cancelled()=>return Err(Cancelled.into()),r=response.chunk()=>r.map_err(|e|e.without_url())?};
   let Some(chunk)=chunk else{break};ensure!(collector.bytes.len().checked_add(chunk.len()).is_some_and(|n|n<=BODY_LIMIT),"ZeroSSL response exceeds limit");
   let append=Append{collector,chunk};collector=crate::cert_cpu::run(self.inner.cpu.clone(),cancel.clone(),move||append.execute()).await?;
  }
  let reply=Reply{status,body:collector,_owner:self.inner.owner.clone()};
  crate::cert_cpu::run(self.inner.cpu.clone(),cancel.clone(),move||reply.parse::<T>()).await
 }
}
