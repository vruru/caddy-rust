//! Occurrence-bound accepted business transport trust and static credentials.
use super::*;
use crate::{cert_transient::ResourceDenied,http_runtime::PreparedOutgoingTrust,tls_policy::prepared_auth::{AuthBudget,BufferCredit}};
use crate::http_config::PreparedConfig;
#[derive(Clone,Copy,PartialEq,Eq)]
struct Key{server:usize,consumer:usize,raw:[u8;32]}
struct Entry{key:Key,ready:std::sync::OnceLock<Arc<PreparedOutgoingTrust>>}
pub(super) struct Inputs{entries:Vec<Entry>,_memory:BufferCredit}
struct Saved{key:Key,value:Arc<PreparedOutgoingTrust>}
pub(super) struct Retained{values:Vec<Saved>,_memory:BufferCredit}
fn credit<T>(count:usize,budget:&AuthBudget,shell:usize)->Result<BufferCredit>{
    budget.reserve_buffer(count.checked_mul(std::mem::size_of::<T>()).and_then(|n|n.checked_add(shell+1024)).ok_or(ResourceDenied)?)
}
fn size_ok<T>(values:&Vec<T>,count:usize)->Result<()>{ensure!(values.capacity().checked_mul(std::mem::size_of::<T>()).ok_or(ResourceDenied)?<=count.checked_mul(std::mem::size_of::<T>()).and_then(|n|n.checked_add(1024)).ok_or(ResourceDenied)?,ResourceDenied);Ok(())}
fn key(s:usize,c:usize,t:&crate::http_config::types::ProxyTls)->Key{Key{server:s,consumer:c,raw:t.source_identity}}
impl Inputs{
    fn new(config:&PreparedConfig,budget:&AuthBudget)->Result<Option<Arc<Self>>>{
        let mut count=0usize;super::ca_consumers::each_proxy_tls(config,&mut|_,_,_|{count=count.checked_add(1).ok_or(ResourceDenied)?;Ok(())})?;
        if count==0{return Ok(None)}let memory=credit::<Entry>(count,budget,std::mem::size_of::<Self>())?;
        let mut entries=Vec::new();entries.try_reserve_exact(count).map_err(|_|ResourceDenied)?;size_ok(&entries,count)?;
        super::ca_consumers::each_proxy_tls(config,&mut|s,c,t|{entries.push(Entry{key:key(s,c,t),ready:std::sync::OnceLock::new()});Ok(())})?;
        Ok(Some(Arc::new(Self{entries,_memory:memory})))
    }
    fn validate(&self,config:&PreparedConfig)->Result<()>{let mut next=self.entries.iter();super::ca_consumers::each_proxy_tls(config,&mut|s,c,t|{ensure!(next.next().is_some_and(|e|e.key==key(s,c,t)),"outgoing trust input topology differs");Ok(())})?;ensure!(next.next().is_none(),"outgoing trust input entry extra");Ok(())}
    fn install_ready(&self,config:&mut PreparedConfig)->Result<()>{self.validate(config)?;let mut next=self.entries.iter();super::ca_consumers::each_proxy_tls_mut(config,&mut|_,_,t|{let e=next.next().expect("validated outgoing topology");if let Some(value)=e.ready.get(){t.prepared_trust=Some(value.clone());}Ok(())})}
    // Only configuration preparation is serial. Each completed small material
    // trims its working loan before the next; request/client concurrency is
    // unchanged. This prevents four 64MiB working claims competing in the
    // existing 256MiB external pool for otherwise small transport inputs.
    fn finish(&self,config:&mut PreparedConfig,pool:Arc<tokio::sync::Semaphore>)->Result<()>{
        self.validate(config)?;let mut next=self.entries.iter();super::ca_consumers::each_proxy_tls_mut(config,&mut|_,_,t|{
            let e=next.next().expect("validated outgoing topology");let value=if let Some(value)=e.ready.get(){value.clone()}else{
                let value=PreparedOutgoingTrust::prepare_root(t,pool.clone())?;
                e.ready.set(value.clone()).map_err(|_|anyhow!("outgoing trust initialization raced"))?;value
            };t.prepared_trust=Some(value);t.prepared_ca=None;Ok(())
        })
    }
    fn retain(&self,budget:&AuthBudget)->Result<Arc<Retained>>{
        let memory=credit::<Saved>(self.entries.len(),budget,std::mem::size_of::<Retained>())?;let mut values=Vec::new();values.try_reserve_exact(self.entries.len()).map_err(|_|ResourceDenied)?;size_ok(&values,self.entries.len())?;
        for e in &self.entries{values.push(Saved{key:e.key,value:e.ready.get().cloned().ok_or_else(||anyhow!("outgoing trust snapshot incomplete"))?});}
        Ok(Arc::new(Retained{values,_memory:memory}))
    }
}
impl Retained{
    fn install(&self,config:&mut PreparedConfig)->Result<()>{
        let mut next=self.values.iter();super::ca_consumers::each_proxy_tls(config,&mut|s,c,t|{ensure!(next.next().is_some_and(|e|e.key==key(s,c,t)),"retained outgoing trust topology differs");Ok(())})?;ensure!(next.next().is_none(),"retained outgoing trust entry extra");
        let mut next=self.values.iter();super::ca_consumers::each_proxy_tls_mut(config,&mut|_,_,t|{t.prepared_trust=Some(next.next().expect("validated retained topology").value.clone());Ok(())})
    }
    fn empty(config:&PreparedConfig)->Result<()>{let mut any=false;super::ca_consumers::each_proxy_tls(config,&mut|_,_,_|{any=true;Ok(())})?;ensure!(!any,"retained outgoing trust snapshot missing");Ok(())}
}
impl CertificateServices{
    #[cfg(feature="native-run")]
    pub(super) async fn begin_outgoing_trust(self:&Arc<Self>,config:PreparedConfig,cancel:CancellationToken)->Result<PreparedConfig>{
        let this=self.clone();crate::cert_cpu::run(self.context.resources.cpu.clone(),cancel,move||{
            let mut config=config;
            if let Some(restored)=&this.restore{
                if let Some(saved)=&restored.outgoing_trust{saved.install(&mut config)?;}else{Retained::empty(&config)?;}return Ok(config)
            }
            let budget=AuthBudget::Root(this.context.resources.external_bytes.clone());
            let inputs=if let Some(old)=this.outgoing_inputs.get(){old.clone()}else{
                let value=Inputs::new(&config,&budget)?;this.outgoing_inputs.set(value.clone()).map_err(|_|anyhow!("outgoing trust input publication raced"))?;value
            };
            if let Some(inputs)=inputs{inputs.install_ready(&mut config)?;}Ok(config)
        }).await
    }
    #[cfg(feature="native-run")]
    pub(super) async fn finish_outgoing_trust(self:&Arc<Self>,config:PreparedConfig,cancel:CancellationToken)->Result<PreparedConfig>{
        let this=self.clone();crate::cert_cpu::run(self.context.resources.cpu.clone(),cancel,move||{
            let mut config=config;
            if let Some(restored)=&this.restore{
                if this.outgoing_accepted.get().is_none(){this.outgoing_accepted.set(restored.outgoing_trust.clone()).map_err(|_|anyhow!("outgoing snapshot publication raced"))?;}return Ok(config)
            }
            let budget=AuthBudget::Root(this.context.resources.external_bytes.clone());
            let inputs=this.outgoing_inputs.get().ok_or_else(||anyhow!("outgoing trust inputs not initialized"))?;
            if let Some(inputs)=inputs{inputs.finish(&mut config,this.context.resources.external_bytes.clone())?;}
            if this.outgoing_accepted.get().is_none(){let saved=inputs.as_ref().map(|v|v.retain(&budget)).transpose()?;this.outgoing_accepted.set(saved).map_err(|_|anyhow!("outgoing snapshot publication raced"))?;}
            Ok(config)
        }).await
    }
}
