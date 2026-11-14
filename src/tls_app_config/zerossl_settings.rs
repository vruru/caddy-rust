//! Stage A only: runtime issuer parsing remains explicitly unsupported.
use super::{decode::Object,schema::ObjectKind};
use crate::acme_wire::chain_memory::{Lease,Pool};
use anyhow::{Result,anyhow,ensure};
use std::{cell::Cell,mem::size_of,sync::Arc};
use tokio::sync::{OnceCell,Semaphore};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;
const FIELD:usize=1024*1024;
const ARC_PADDING:usize=128;
#[derive(Debug)]
pub(crate) struct UnsupportedCnameProvider;
impl std::fmt::Display for UnsupportedCnameProvider{fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{f.write_str("ZeroSSL CNAME provider is not implemented")}}
impl std::error::Error for UnsupportedCnameProvider{}
pub(crate) struct HttpSettings {
 pub listen_host:String,pub validity_days:i64,pub alternate_http_port:i64,
 pub cname_configured:bool,pub ttl:i64,pub propagation_delay:i64,pub propagation_timeout:i64,
 pub resolvers:Vec<String>,pub override_domain:String,
}
impl HttpSettings {
 fn bytes(&self)->Result<usize>{
  self.resolvers.iter().try_fold(self.listen_host.len().checked_add(self.override_domain.len())
   .and_then(|n|self.resolvers.len().checked_mul(size_of::<String>()).and_then(|m|n.checked_add(m))).ok_or(crate::cert_transient::ResourceDenied)?,|n,s|n.checked_add(s.len()).ok_or_else(||crate::cert_transient::ResourceDenied.into()))
 }
 fn copy(&self)->Result<Self>{
  let mut resolvers=Vec::new();resolvers.try_reserve_exact(self.resolvers.len()).map_err(|_|crate::cert_transient::ResourceDenied)?;
  for s in &self.resolvers{resolvers.push(copy_text(s)?);}
  Ok(Self{listen_host:copy_text(&self.listen_host)?,validity_days:self.validity_days,alternate_http_port:self.alternate_http_port,
   cname_configured:self.cname_configured,ttl:self.ttl,propagation_delay:self.propagation_delay,propagation_timeout:self.propagation_timeout,
   resolvers,override_domain:copy_text(&self.override_domain)?})
 }
}
pub(crate) struct Input {
 raw:Zeroizing<String>,settings:HttpSettings,pool:Arc<Pool>,ready:OnceCell<Arc<Prepared>>,
 _memory:Lease,
}
pub(crate) struct Prepared {
 key:Zeroizing<String>,pub settings:HttpSettings,pool:Arc<Pool>,_memory:Lease,
}
impl Prepared {
 pub(crate) fn api_key(&self)->&str{&self.key}
 pub(crate) fn pool(&self)->&Arc<Pool>{&self.pool}
}
fn copy_text(s:&str)->Result<String>{let mut out=String::new();out.try_reserve_exact(s.len()).map_err(|_|crate::cert_transient::ResourceDenied)?;out.push_str(s);Ok(out)}
fn add(a:usize,b:usize)->Result<usize>{a.checked_add(b).ok_or_else(||crate::cert_transient::ResourceDenied.into())}
impl Input {
 /// The pool is explicit in this Stage-A constructor; no production parser caller yet.
 pub(crate) fn decode(value:&serde_json::Value,path:&str,pool:Arc<Pool>)->Result<Arc<Self>>{
  let object=Object::new(Some(value),ObjectKind::ZeroSsl,path)?;
  let raw=object.string("api_key")?;let host=object.string("listen_host")?;
  ensure!(raw.len()<=FIELD&&host.len()<=FIELD,"ZeroSSL configured field exceeds limit");
  let validity=object.integer("validity_days")?.unwrap_or(0);let port=object.integer("alternate_http_port")?.unwrap_or(0);
  let cname=Object::new(object.value("cname_validation"),ObjectKind::DnsChallenge,&object.at("cname_validation"))?;
  if cname.value("provider").is_some(){return Err(UnsupportedCnameProvider.into())}
  let ttl=cname.duration_ns("ttl")?;let delay=cname.duration_ns("propagation_delay")?;let timeout=cname.duration_ns("propagation_timeout")?;
  let over=cname.string("override_domain")?;ensure!(over.len()<=FIELD,"ZeroSSL configured field exceeds limit");
  let array=cname.array("resolvers")?;ensure!(array.len()<=1024,"ZeroSSL resolver count exceeds limit");
  let mut cost=add(size_of::<Self>()+ARC_PADDING,add(raw.len(),add(host.len(),over.len())?)?)?;
  cost=add(cost,array.len().checked_mul(size_of::<String>()).ok_or(crate::cert_transient::ResourceDenied)?)?;
  for v in array {let s=if v.is_null(){""}else{v.as_str().ok_or_else(||anyhow!("invalid ZeroSSL resolver setting"))?};ensure!(s.len()<=FIELD,"ZeroSSL configured field exceeds limit");cost=add(cost,s.len())?;}
  let memory=pool.reserve(cost)?;
  let mut resolvers=Vec::new();resolvers.try_reserve_exact(array.len()).map_err(|_|crate::cert_transient::ResourceDenied)?;
  for v in array {resolvers.push(copy_text(if v.is_null(){""}else{v.as_str().ok_or_else(||anyhow!("invalid ZeroSSL resolver setting"))?})?);}
  Ok(Arc::new(Self{raw:Zeroizing::new(copy_text(raw)?),settings:HttpSettings{listen_host:copy_text(host)?,validity_days:validity,alternate_http_port:port,
   cname_configured:object.value("cname_validation").is_some(),ttl,propagation_delay:delay,propagation_timeout:timeout,resolvers,override_domain:copy_text(over)?},
   pool,ready:OnceCell::new(),_memory:memory}))
 }
 pub(crate) async fn prepare(self:&Arc<Self>,cpu:Arc<Semaphore>,cancel:CancellationToken)->Result<Arc<Prepared>>{
  let value=self.ready.get_or_try_init(||async{
   ensure!(!cancel.is_cancelled(),"ZeroSSL preparation cancelled");
   let cost=add(FIELD,add(self.settings.bytes()?,size_of::<Prepared>()+ARC_PADDING)?)?;
   let memory=self.pool.reserve(cost)?;
   let scratch=crate::acme_wire::chain_memory::try_scratch(16*FIELD+16384)?;
   let job=PrepareJob{input:self.clone(),memory,_scratch:scratch};
   crate::cert_cpu::run(cpu,cancel,move||job.execute()).await
  }).await?;Ok(value.clone())
 }
}
struct PrepareJob {input:Arc<Input>,memory:Lease,_scratch:crate::acme_wire::chain_memory::Scratch}
impl PrepareJob {
 fn execute(mut self)->Result<Arc<Prepared>>{
  let failed=Cell::new(false);
  let key=Zeroizing::new(crate::http_config::helpers::replace_accounted(&self.input.raw,true,|name|{
   match crate::http_config::helpers::prepare_file_lookup(name){
    Some(Ok(value))=>Some(value),Some(Err(_))=>{failed.set(true);None},
    None=>crate::http_config::helpers::global_lookup(name),
   }
  },|capacity|{ensure!(capacity<=2*FIELD,"ZeroSSL configured value exceeds limit");Ok(())})
   .map_err(|_|anyhow!("ZeroSSL API key preparation failed"))?);
  ensure!(!failed.get()&&key.len()<=FIELD,"ZeroSSL API key preparation failed");
  // Shrinking is safe before payload moves: maximum Prepared resident was paid above.
  self.memory.resize(add(key.capacity(),add(self.input.settings.bytes()?,size_of::<Prepared>()+ARC_PADDING)?)?)?;
  let settings=self.input.settings.copy()?;
  Ok(Arc::new(Prepared{key,settings,pool:self.input.pool.clone(),_memory:self.memory}))
 }
}
