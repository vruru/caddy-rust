//! Concrete policy-local ready state and immutable rollback capability.
use super::*;
use super::super::{ClientAuth,client_auth::PreparedAuth};
use tokio::sync::OnceCell;
use tokio_util::sync::CancellationToken;

struct RawAuth { value: ClientAuth, _credit: BufferCredit }
impl Drop for RawAuth{fn drop(&mut self){super::super::client_auth::wipe_raw(&mut self.value);}}
impl RawAuth {
    fn copy(raw:&ClientAuth,budget:&AuthBudget)->Result<Arc<Self>>{
        let bytes=super::super::client_auth::raw_clone_cost(raw)?
            .checked_add(std::mem::size_of::<Self>()).and_then(|n|n.checked_add(128)).ok_or(ResourceDenied)?;
        let credit=budget.reserve_buffer(bytes)?;
        Ok(Arc::new(Self{value:raw.clone(),_credit:credit}))
    }
}

pub(crate) struct PreparedSlot {
    key: AuthKey,
    binding: [u8;32],
    material: PreparedAuth,
    _metadata: BufferCredit,
}
impl PreparedSlot {
    fn new(key:AuthKey,raw:&ClientAuth,material:PreparedAuth,budget:&AuthBudget)->Result<Arc<Self>>{
        if raw.is_active(){
            let owner=material.material_credit.as_ref().ok_or_else(||anyhow::anyhow!("client authentication material is not sealed"))?;
            ensure!(owner.is_sealed()?,"client authentication material is not sealed");
        }else{
            ensure!(material.verifier.is_none()&&material.digest==[0;32]&&material.retained_bytes==0,
                "inactive client authentication material differs");
        }
        let binding=input_binding(raw)?;
        let metadata=budget.reserve_buffer(std::mem::size_of::<Self>().checked_add(128).ok_or(ResourceDenied)?)?;
        Ok(Arc::new(Self{key,binding,material,_metadata:metadata}))
    }
    pub(crate) fn material_for(&self,raw_policy:[u8;32],raw:Option<&ClientAuth>)->Result<&PreparedAuth>{
        let raw=raw.ok_or_else(||anyhow::anyhow!("prepared client authentication input is absent"))?;
        ensure!(self.key.raw_policy==raw_policy&&self.binding==input_binding(raw)?,
            "prepared client authentication input differs");
        Ok(&self.material)
    }
    fn check(&self,key:AuthKey,raw:&ClientAuth)->Result<()>{
        ensure!(self.key==key,"retained client authentication topology differs");
        self.material_for(key.raw_policy,Some(raw))?;Ok(())
    }
}

pub(crate) struct AuthEntry {
    key: AuthKey,
    raw: Arc<RawAuth>,
    ready: OnceCell<Arc<PreparedSlot>>,
    _metadata: BufferCredit,
}
impl AuthEntry {
    fn new(key:AuthKey,raw:&ClientAuth,budget:&AuthBudget)->Result<Arc<Self>>{
        let metadata=budget.reserve_buffer(std::mem::size_of::<Self>().checked_add(128).ok_or(ResourceDenied)?)?;
        let raw=RawAuth::copy(raw,budget)?;
        Ok(Arc::new(Self{key,raw,ready:OnceCell::new(),_metadata:metadata}))
    }
    pub(crate) fn key(&self)->AuthKey{self.key}
    pub(crate) fn raw(&self)->&ClientAuth{&self.raw.value}
    pub(crate) fn binding(&self)->Result<[u8;32]>{input_binding(self.raw())}
    pub(crate) fn ready(&self)->Option<Arc<PreparedSlot>>{self.ready.get().cloned()}
    /// Root's closed source path. The source factory contains only already
    /// owned capability/entry Arcs; it MUST NOT capture a produced CA Value.
    /// Ready is checked before either metadata admission or source production.
    /// Call only from CertificateServices' tracked operation: after a source
    /// exists this future must be joined, never abandoned by its owner.
    pub(crate) fn prepare_from<F,Fut>(self:&Arc<Self>,budget:AuthBudget,
        cpu:Arc<Semaphore>,cancel:CancellationToken,source:F)
        ->impl std::future::Future<Output=Result<Arc<PreparedSlot>>>+Send+'static
    where F:FnOnce(Arc<AuthEntry>,CancellationToken)->Fut+Send+'static,
        Fut:std::future::Future<Output=Result<AuthSources>>+Send+'static{
        let entry=self.clone();
        async move{
            let initializer=entry.clone();
            entry.ready.get_or_try_init(||async move{
                let entry=initializer;
                // No resolved source exists on any early-admission branch.
                let mut job=crate::cert_cpu::run(cpu.clone(),cancel.clone(),{
                    let entry=entry.clone();
                    move||InlineJob::new(entry,budget )
                }).await?;
                job.sources=Some(source(entry.clone(),cancel.clone()).await?);
                // Once source data exists, cancellation cannot discard its
                // CPU closure while queued. The tracked Services owner joins
                // the real worker, whose consuming method checks cancellation
                // and destroys all source data on that same CPU lane.
                crate::cert_cpu::run(cpu,CancellationToken::new(),move||job.execute_checked(cancel)).await
            }).await.cloned()
        }
    }
}

struct InlineJob{
    entry:Arc<AuthEntry>,
    sources:Option<AuthSources>,
    budget:AuthBudget,
    _metadata:BufferCredit,
}
impl InlineJob{
    fn new(entry:Arc<AuthEntry>,budget:AuthBudget)->Result<Self>{
        let metadata=budget.reserve_buffer(std::mem::size_of::<Self>().checked_add(2048).ok_or(ResourceDenied)?)?;
        Ok(Self{entry,sources:None,budget,_metadata:metadata})
    }
    fn execute_checked(self,cancel:CancellationToken)->Result<Arc<PreparedSlot>>{
        ensure!(!cancel.is_cancelled(),"client authentication preparation cancelled");
        self.execute()
    }
    fn execute(mut self)->Result<Arc<PreparedSlot>>{
        // Keep this WHOLE envelope through preflight failure/panic. Raw and
        // resolved inputs cannot be detached from their source credits.
        let prepared=if self.entry.raw().is_active(){
            AuthBuildInput::from_sources(self.entry.key,self.entry.raw(),self.sources.take().expect("owned authentication sources"),&self.budget)?.execute()?
        }else{
            drop(self.sources.take());
            super::super::client_auth::prepare(Some(self.entry.raw()))?
        };
        PreparedSlot::new(self.entry.key,self.entry.raw(),prepared,&self.budget)
    }
}

pub(crate) struct AuthInputs{
    entries:Vec<Arc<AuthEntry>>,
    budget:AuthBudget,
    _metadata:BufferCredit,
}
/// No raw/provider cells: each slot is already accepted, immutable material.
pub(crate) struct RetainedAuth{slots:Vec<Arc<PreparedSlot>>,_metadata:BufferCredit}
fn index_credit<T>(count:usize,budget:&AuthBudget,shell:usize)->Result<BufferCredit>{
    budget.reserve_buffer(count.checked_mul(std::mem::size_of::<T>()).and_then(|n|n.checked_add(shell))
        .and_then(|n|n.checked_add(1024)).ok_or(ResourceDenied)?)
}
fn each_auth(config:&crate::http_config::PreparedConfig,mut f:impl FnMut(AuthKey,&ClientAuth)->Result<()>)->Result<usize>{
    let mut count=0usize;
    for(si,server)in config.servers.iter().enumerate(){
        if !server.tls{continue}
        for(pi,policy)in server.tls_policies.iter().enumerate(){if let Some(raw)=&policy.client_auth{
            count=count.checked_add(1).ok_or(ResourceDenied)?;
            f(AuthKey{server_ordinal:si,policy_ordinal:pi,raw_policy:policy.identity},raw)?;
        }}
    }
    Ok(count)
}
fn install(config:&mut crate::http_config::PreparedConfig,slots:&[Arc<PreparedSlot>])->Result<()>{
    // Validate ALL topology/bindings before mutating even the unpublished plan.
    let mut next=slots.iter();
    each_auth(config,|key,raw|next.next().ok_or_else(||anyhow::anyhow!("retained client authentication entry missing"))?.check(key,raw))?;
    ensure!(next.next().is_none(),"retained client authentication entry extra");
    // Do not silently deep-clone the entire ServerConfig (routes/proxies/raw
    // values) under a tiny slot/index loan. Native Root passes its uniquely
    // parsed candidate. Shared standalone plans must be prepared separately.
    for server in &config.servers{if server.tls&&server.tls_policies.iter().any(|p|p.client_auth.is_some()){
        ensure!(Arc::strong_count(server)==1&&Arc::weak_count(server)==0,
            "client authentication installation requires a unique server plan");
    }}
    let mut next=slots.iter();
    for server in &mut config.servers{if server.tls&&server.tls_policies.iter().any(|p|p.client_auth.is_some()){for policy in &mut Arc::get_mut(server).expect("validated unique server plan").tls_policies{if policy.client_auth.is_some(){
        policy.prepared_client_auth=Some(next.next().expect("validated authentication topology").clone());
    }}}}
    Ok(())
}
impl AuthInputs{
    pub(crate) fn from_http(config:&crate::http_config::PreparedConfig,budget:AuthBudget)->Result<Option<Arc<Self>>>{
        let count=each_auth(config,|_,_|Ok(()))?;if count==0{return Ok(None)}
        let metadata=index_credit::<Arc<AuthEntry>>(count,&budget,std::mem::size_of::<Self>())?;
        let mut entries=Vec::new();entries.try_reserve_exact(count).map_err(|_|ResourceDenied)?;
        ensure!(entries.capacity().checked_mul(std::mem::size_of::<Arc<AuthEntry>>()).ok_or(ResourceDenied)?<=count.checked_mul(std::mem::size_of::<Arc<AuthEntry>>()).and_then(|n|n.checked_add(1024)).ok_or(ResourceDenied)?,ResourceDenied);
        each_auth(config,|key,raw|{entries.push(AuthEntry::new(key,raw,&budget)?);Ok(())})?;
        Ok(Some(Arc::new(Self{entries,budget,_metadata:metadata})))
    }
    pub(crate) fn entries(&self)->&[Arc<AuthEntry>]{&self.entries}
    pub(crate) fn install_ready(&self,config:&mut crate::http_config::PreparedConfig)->Result<()>{
        self.validate(config)?;
        ensure!(config.servers.iter().all(|s|Arc::strong_count(s)==1&&Arc::weak_count(s)==0),"client authentication installation requires a unique server plan");
        for entry in &self.entries{if let Some(slot)=entry.ready(){Arc::get_mut(&mut config.servers[entry.key.server_ordinal]).expect("validated unique plan").tls_policies[entry.key.policy_ordinal].prepared_client_auth=Some(slot);}}Ok(())
    }
    pub(crate) fn validate(&self,config:&crate::http_config::PreparedConfig)->Result<()>{
        let mut next=self.entries.iter();
        each_auth(config,|key,raw|{
            let entry=next.next().ok_or_else(||anyhow::anyhow!("client authentication input entry missing"))?;
            ensure!(entry.key==key&&entry.binding()?==input_binding(raw)?,"client authentication input topology differs");Ok(())
        })?;
        ensure!(next.next().is_none(),"client authentication input entry extra");Ok(())
    }
    pub(crate) fn retain(&self)->Result<Arc<RetainedAuth>>{
        let metadata=index_credit::<Arc<PreparedSlot>>(self.entries.len(),&self.budget,std::mem::size_of::<RetainedAuth>())?;
        let mut slots=Vec::new();slots.try_reserve_exact(self.entries.len()).map_err(|_|ResourceDenied)?;
        ensure!(slots.capacity().checked_mul(std::mem::size_of::<Arc<PreparedSlot>>()).ok_or(ResourceDenied)?<=self.entries.len().checked_mul(std::mem::size_of::<Arc<PreparedSlot>>()).and_then(|n|n.checked_add(1024)).ok_or(ResourceDenied)?,ResourceDenied);
        for entry in &self.entries{slots.push(entry.ready().ok_or_else(||anyhow::anyhow!("client authentication snapshot incomplete"))?);}
        Ok(Arc::new(RetainedAuth{slots,_metadata:metadata}))
    }
}
impl RetainedAuth{
    pub(crate) fn install(&self,config:&mut crate::http_config::PreparedConfig)->Result<()>{install(config,&self.slots)}
    pub(crate) fn validate_empty(config:&crate::http_config::PreparedConfig)->Result<()>{
        ensure!(each_auth(config,|_,_|Ok(()))?==0,"retained client authentication snapshot missing");Ok(())
    }
}
