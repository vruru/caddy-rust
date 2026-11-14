//! Generation-owned ZeroSSL configuration; resolved credentials never enter raw/export.
use super::{decode::Object,schema::ObjectKind};
use crate::acme_wire::chain_memory::{Lease,Pool};
use anyhow::{Result,anyhow,ensure};
use std::{mem::size_of,sync::Arc};
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
 raw:Zeroizing<String>,settings:HttpSettings,pool:Arc<Pool>,ready:OnceCell<Arc<Prepared>>,id:[u8;32],
 _memory:Lease,
}
pub(crate) struct Prepared {
 key:Zeroizing<String>,pub settings:HttpSettings,pool:Arc<Pool>,_memory:Lease,
}
impl Prepared {
 pub(crate) fn identity(&self)->String {
  use sha2::{Digest,Sha256};
  let mut h=Sha256::new();h.update((self.key.len()as u64).to_be_bytes());h.update(self.key.as_bytes());
  h.update(self.settings.validity_days.to_be_bytes());h.update(self.settings.alternate_http_port.to_be_bytes());h.update(self.settings.listen_host.as_bytes());
  format!("{:x}",h.finalize())
 }
 pub(crate) fn api_key(&self)->&str{&self.key}
 pub(crate) fn pool(&self)->&Arc<Pool>{&self.pool}
}
fn copy_text(s:&str)->Result<String>{let mut out=String::new();out.try_reserve_exact(s.len()).map_err(|_|crate::cert_transient::ResourceDenied)?;out.push_str(s);Ok(out)}
fn add(a:usize,b:usize)->Result<usize>{a.checked_add(b).ok_or_else(||crate::cert_transient::ResourceDenied.into())}
impl Input {
 /// Raw fields are charged to the caller's existing configuration pool.
 pub(crate) fn decode(value:&serde_json::Value,path:&str,pool:Arc<Pool>)->Result<Arc<Self>>{
  let object=Object::new(Some(value),ObjectKind::ZeroSsl,path)?;
  let raw=object.string("api_key")?;let host=object.string("listen_host")?;
  ensure!(raw.len()<=FIELD&&host.len()<=FIELD,"ZeroSSL configured field exceeds limit");
  let validity=object.integer("validity_days")?.unwrap_or(0);let port=object.integer("alternate_http_port")?.unwrap_or(0);
  let cname=Object::new(object.value("cname_validation"),ObjectKind::DnsChallenge,&object.at("cname_validation"))?;
  // Go provisions DNS only for a present RawMessage provider. Explicit
  // provider:null is still present and must not silently select HTTP.
  let cname_configured=cname.raw_value("provider").is_some();
  if cname_configured{return Err(UnsupportedCnameProvider.into())}
  let ttl=cname.duration_ns("ttl")?;let delay=cname.duration_ns("propagation_delay")?;let timeout=cname.duration_ns("propagation_timeout")?;
  let over=cname.string("override_domain")?;ensure!(over.len()<=FIELD,"ZeroSSL configured field exceeds limit");
  let array=cname.array("resolvers")?;ensure!(array.len()<=1024,"ZeroSSL resolver count exceeds limit");
  let mut cost=add(size_of::<Self>()+ARC_PADDING,add(raw.len(),add(host.len(),over.len())?)?)?;
  cost=add(cost,array.len().checked_mul(size_of::<String>()).ok_or(crate::cert_transient::ResourceDenied)?)?;
  for v in array {let s=if v.is_null(){""}else{v.as_str().ok_or_else(||anyhow!("invalid ZeroSSL resolver setting"))?};ensure!(s.len()<=FIELD,"ZeroSSL configured field exceeds limit");cost=add(cost,s.len())?;}
  let memory=pool.reserve(cost)?;
  let mut resolvers=Vec::new();resolvers.try_reserve_exact(array.len()).map_err(|_|crate::cert_transient::ResourceDenied)?;
  for v in array {resolvers.push(copy_text(if v.is_null(){""}else{v.as_str().ok_or_else(||anyhow!("invalid ZeroSSL resolver setting"))?})?);}
  use sha2::{Digest,Sha256};
  struct HashWrite(Sha256);
  impl std::io::Write for HashWrite {
   fn write(&mut self,b:&[u8])->std::io::Result<usize>{self.0.update(b);Ok(b.len())}
   fn flush(&mut self)->std::io::Result<()>{Ok(())}
  }
  let mut hash=HashWrite(Sha256::new());serde_json::to_writer(&mut hash,value)?;let id=hash.0.finalize().into();
  Ok(Arc::new(Self{id,raw:Zeroizing::new(copy_text(raw)?),settings:HttpSettings{listen_host:copy_text(host)?,validity_days:validity,alternate_http_port:port,
   cname_configured,ttl,propagation_delay:delay,propagation_timeout:timeout,resolvers,override_domain:copy_text(over)?},
   pool,ready:OnceCell::new(),_memory:memory}))
 }
 pub(crate) fn listen_host(&self)->&str{&self.settings.listen_host}
 pub(crate) fn id(&self)->[u8;32]{self.id}
 pub(crate) fn get(&self)->Result<Arc<Prepared>>{self.ready.get().cloned().ok_or_else(||anyhow!("ZeroSSL values are not prepared"))}
 pub(crate) fn restore(&self,id:[u8;32],value:Arc<Prepared>)->Result<()>{
  ensure!(self.id==id,"retained ZeroSSL value identity changed");
  self.ready.set(value).map_err(|_|anyhow!("ZeroSSL values already prepared"))
 }
 pub(crate) async fn prepare(self:&Arc<Self>,cpu:Arc<Semaphore>,cancel:CancellationToken)->Result<Arc<Prepared>>{
  let cwd=super::manual_values::cwd(&std::env::current_dir()?)?;
  self.prepare_in_pool(cpu,self.pool.clone(),cwd,cancel).await
 }
 pub(crate) async fn prepare_in_pool(self:&Arc<Self>,lane:Arc<Semaphore>,pool:Arc<Pool>,cwd:Arc<super::manual_values::OwnedPath>,cancel:CancellationToken)->Result<Arc<Prepared>>{
  let value=self.ready.get_or_try_init(||async{
   ensure!(!cancel.is_cancelled(),"ZeroSSL preparation cancelled");
   let cost=add(FIELD,add(self.settings.bytes()?,size_of::<Prepared>()+ARC_PADDING)?)?;
   let memory=pool.reserve(cost)?;
   let scratch=crate::acme_wire::chain_memory::try_scratch(16*FIELD+16384)?;
   let job=PrepareJob{input:self.clone(),pool,cwd,memory,_scratch:scratch};
   crate::cert_cpu::run(lane,cancel,move||job.execute()).await
  }).await?;Ok(value.clone())
 }
}
struct PrepareJob {input:Arc<Input>,pool:Arc<Pool>,cwd:Arc<super::manual_values::OwnedPath>,memory:Lease,_scratch:crate::acme_wire::chain_memory::Scratch}
impl PrepareJob {
 fn execute(mut self)->Result<Arc<Prepared>>{
  let mut bytes=crate::http_config::helpers::replace_secret_bytes_accounted(&self.input.raw,true,FIELD,FIELD,|name|{
   if let Some(path)=name.strip_prefix("file.") {super::manual_values::lookup_file(path,&self.cwd.path)}
   else{super::manual_values::lookup_global(name)}
  },|capacity|{ensure!(capacity<=2*FIELD,"ZeroSSL configured value exceeds limit");Ok(())})
   .map_err(|_|anyhow!("ZeroSSL API key preparation failed"))?;
  ensure!(std::str::from_utf8(&bytes).is_ok(),"ZeroSSL API key is not UTF-8");
  let key=Zeroizing::new(String::from_utf8(std::mem::take(&mut *bytes)).map_err(|error|{
   use zeroize::Zeroize;let mut bytes=error.into_bytes();bytes.zeroize();anyhow!("ZeroSSL API key is not UTF-8")
  })?);
  // Shrinking is safe before payload moves: maximum Prepared resident was paid above.
  self.memory.resize(add(key.capacity(),add(self.input.settings.bytes()?,size_of::<Prepared>()+ARC_PADDING)?)?)?;
  ensure!(!key.is_empty(),"ZeroSSL API key is empty");
  crate::zerossl_wire::validate_api_key(&key)?;
  ensure!(!self.input.settings.cname_configured,"ZeroSSL CNAME validation requires an unavailable DNS provider");
  ensure!(self.input.settings.alternate_http_port<=65535,"ZeroSSL HTTP validation port outside bounds");
  let settings=self.input.settings.copy()?;
  Ok(Arc::new(Prepared{key,settings,pool:self.pool,_memory:self.memory}))
 }
}
