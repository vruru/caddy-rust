//! Authenticated certificate-only graph capabilities. Raw retrievals are shared
//! independently of recursive path state; completion order never orders chains.
use super::{AccountSession,CertificateChain,certificate_links,validate_url,chain_memory as memory,chain_validation as validation};
use anyhow::{Result,anyhow,ensure};
use futures_util::{StreamExt,stream};
use std::{collections::{HashMap,HashSet},future::Future,pin::Pin,sync::{Arc,Mutex,atomic::{AtomicUsize,Ordering}}};
use tokio::{runtime::Handle,sync::{watch,Semaphore,Notify,oneshot},task::JoinSet};
use tokio_util::{sync::CancellationToken,task::{TaskTracker,task_tracker::TaskTrackerToken}};
use url::Url;
const MAX_REQUESTS:usize=32;
const MAX_DEPTH:usize=8;
const MAX_VISITS:usize=128;
const MAX_CHAINS:usize=16;
const CONCURRENCY:usize=4;

struct Endpoint{url:Url,require_https:bool}
impl Endpoint{
    fn declared(base:&Url,raw:&str,require_https:bool,allow_loopback:bool,allowed_http_origin:Option<&str>)->Result<Self>{
        ensure!(raw.len()<=8192,"ACME certificate URL exceeds bounds");
        let url=base.join(raw).map_err(|_|anyhow!("invalid ACME certificate link"))?;
        ensure!(url.as_str().len()<=8192,"ACME resolved certificate URL exceeds bounds");
        validate_url(&url,&HashSet::from([url.origin().ascii_serialization()]),allow_loopback&&!require_https,allowed_http_origin)?;
        ensure!(!require_https||url.scheme()=="https","ACME certificate link downgrades HTTPS");
        Ok(Self{require_https:require_https||url.scheme()=="https",url})
    }
}
struct Node{body:Arc<memory::Buffer>,info:validation::Validated,links:Vec<certificate_links::Link>}
#[derive(Clone,Debug)]
struct SharedFailure(Arc<anyhow::Error>);
impl std::fmt::Display for SharedFailure{fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{std::fmt::Display::fmt(self.0.as_ref(),f)}}
impl std::error::Error for SharedFailure{fn source(&self)->Option<&(dyn std::error::Error+'static)>{Some(&**self.0)}}
type NodeOutcome=Result<Arc<Node>,SharedFailure>;

/// SharedFailure owns an anyhow table whose context payloads are not all
/// downcastable through std::error::Error::source. Unwrap only this closed type.
pub(crate) fn shared_cause(error:&anyhow::Error)->Option<&anyhow::Error>{
    error.downcast_ref::<SharedFailure>()
        .or_else(||error.chain().find_map(|cause|cause.downcast_ref::<SharedFailure>()))
        .map(|failure|failure.0.as_ref())
}
#[derive(Debug)]
struct GraphExecutionFailure;
impl std::fmt::Display for GraphExecutionFailure{
    fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{
        f.write_str("ACME certificate graph execution unavailable")
    }
}
impl std::error::Error for GraphExecutionFailure{}
fn local_failure(error:&anyhow::Error)->bool{
    fn local(error:&anyhow::Error)->bool{
        if error.is::<validation::NamesUnavailable>() || error.is::<GraphExecutionFailure>()
            || error.is::<super::AcmeRequestCancelled>() {return true}
        #[cfg(feature="native-run")]
        if error.is::<crate::outgoing_tls::ConnectionControl>()
            || error.chain().any(|cause|cause.is::<crate::outgoing_tls::ConnectionControl>()) {return true}
        false
    }
    crate::cert_transient::is_resource(error) || local(error)
        || shared_cause(error).is_some_and(local)
}
/// Remote optional branches may be unavailable or invalid. Local execution,
/// resource and wanted-metadata errors must never become an absent branch.
fn optional_branch<T>(result:Result<T>,cancel:&CancellationToken)->Result<Option<T>>{
    match result{
        Ok(value)=>Ok(Some(value)),
        Err(error) if cancel.is_cancelled() || local_failure(&error)=>Err(error),
        Err(_)=>Ok(None),
    }
}

/// The local manager owns abandoned-graph joins; its existing native group
/// tracker also owns that same future, so retirement waits for real completion.
pub(crate) struct Cleanup{local:TaskTracker,parent:Option<TaskTracker>}
impl Default for Cleanup{fn default()->Self{Self{local:TaskTracker::new(),parent:None}}}
impl Cleanup{
    pub(crate) fn with_parent(parent:TaskTracker)->Self{Self{local:TaskTracker::new(),parent:Some(parent)}}
    pub(crate) async fn drain(&self){self.local.close();self.local.wait().await;}
    fn registration(&self)->Registration{let(local,parent)=self.storage_registration();Registration{_local:local,_parent:parent}}
    /// Concrete tokens follow actual storage IO, including a caller that is dropped.
    pub(crate) fn storage_registration(&self)->(TaskTrackerToken,Option<TaskTrackerToken>){
        (self.local.token(),self.parent.as_ref().map(TaskTracker::token))
    }
    /// Adopt exactly one already admitted worker; do not release its real join
    /// merely because the async waiter was aborted. Existing parent retirement
    /// waits for the same reaper, independently of the worker's own tokens.
    pub(crate) fn adopt_storage_worker(&self,worker:tokio::task::JoinHandle<Result<()>>,memory:Arc<super::chain_memory::Scratch>,runtime:&Handle){
        // Consuming the whole concrete envelope prevents disjoint closure
        // capture from discarding credit before the actual join/result drop.
        let future=StorageJoinReaper{worker,_memory:memory}.join();
        match &self.parent{
            Some(parent)=>{self.local.spawn_on(parent.track_future(future),runtime);}
            None=>{self.local.spawn_on(future,runtime);}
        }
    }
    fn spawn_reaper(&self,mut tasks:JoinSet<()>,runtime:&Handle){
        if tasks.is_empty(){return}
        let future=async move{while let Some(result)=tasks.join_next().await{drop(result);}};
        match &self.parent{
            Some(parent)=>{self.local.spawn_on(parent.track_future(future),runtime);}
            None=>{self.local.spawn_on(future,runtime);}
        }
    }
}
// The graph itself stays registered even when its caller is not tracked.
// This field is last in Owner: Drop registers any reaper before these tokens
// can release the last count observed by close()+wait().
struct Registration{_local:TaskTrackerToken,_parent:Option<TaskTrackerToken>}
struct StorageJoinReaper{worker:tokio::task::JoinHandle<Result<()>>,_memory:Arc<super::chain_memory::Scratch>}
impl StorageJoinReaper{
    async fn join(self){drop(self.worker.await);}
}

struct JoinGuard{tasks:Option<JoinSet<()>>,cancel:CancellationToken,cleanup:Arc<Cleanup>,runtime:Handle}
impl JoinGuard{
    async fn join_all(mut self){
        self.cancel.cancel();
        while let Some(result)=self.tasks.as_mut().expect("owned graph tasks").join_next().await{drop(result);}
        self.tasks.take();
    }
}
impl Drop for JoinGuard{
    fn drop(&mut self){self.cancel.cancel();if let Some(tasks)=self.tasks.take(){self.cleanup.spawn_reaper(tasks,&self.runtime);}}
}
struct Progress{active:Mutex<usize>,notify:Notify}
struct Activity{progress:Arc<Progress>}
impl Drop for Activity{
    fn drop(&mut self){
        {let mut active=self.progress.active.lock().unwrap_or_else(|e|e.into_inner());debug_assert!(*active>0);*active=active.saturating_sub(1);}
        self.progress.notify.notify_waiters();
    }
}
struct Admission{credit:Option<super::ChainMemoryLease>,_activity:Activity}
struct Context{
    wire:super::AcmeWire,signer:Arc<super::AccountSigner>,location:Arc<str>,want_names:bool,
    cancel:CancellationToken,http_slots:Arc<Semaphore>,progress:Arc<Progress>,
}
async fn admit(context:&Context)->Result<Admission>{
    loop{
        ensure!(!context.cancel.is_cancelled(),"ACME chain download cancelled");
        let notified=context.progress.notify.notified();tokio::pin!(notified);notified.as_mut().enable();
        let credit={
            let mut active=context.progress.active.lock().map_err(|_|anyhow!("ACME memory scheduling unavailable").context(GraphExecutionFailure))?;
            match context.wire.inner.chain_memory.payload.reserve(super::MAX_BODY){
                Ok(credit)=>{*active+=1;Some(credit)}
                Err(error)=>{if *active==0{return Err(error)}None}
            }
        };
        if let Some(credit)=credit{return Ok(Admission{credit:Some(credit),_activity:Activity{progress:context.progress.clone()}})}
        // Only holders which already acquired credit count as progress. No
        // HTTP slot, CPU slot or scratch loan is owned by this waiting task.
        tokio::select!{biased;
            _=context.cancel.cancelled()=>return Err(anyhow!("ACME chain download cancelled")),
            _=notified=>{},
        }
    }
}
struct Owner{
    context:Arc<Context>,cache:Mutex<HashMap<String,watch::Receiver<Option<NodeOutcome>>>>,
    tasks:Mutex<JoinSet<()>>,visits:AtomicUsize,cleanup:Arc<Cleanup>,runtime:Handle,
    _registration:Registration,
}
impl Owner{
    fn spawn(&self,future:impl Future<Output=()>+Send+'static)->Result<()>{
        // Reap completed () records so long graphs do not retain task handles.
        loop{
            let completed={self.tasks.lock().map_err(|_|anyhow!("ACME graph task state unavailable").context(GraphExecutionFailure))?.try_join_next()};
            if completed.is_none(){break}drop(completed);
        }
        self.tasks.lock().map_err(|_|anyhow!("ACME graph task state unavailable").context(GraphExecutionFailure))?.spawn_on(future,&self.runtime);
        Ok(())
    }
    async fn node(&self,endpoint:&Endpoint)->Result<Arc<Node>>{
        let key=endpoint.url.to_string();
        let(mut receiver,sender)={
            let mut cache=self.cache.lock().map_err(|_|anyhow!("ACME graph cache unavailable").context(GraphExecutionFailure))?;
            if let Some(receiver)=cache.get(&key){(receiver.clone(),None)}else{
                ensure!(cache.len()<MAX_REQUESTS,"ACME certificate request budget exhausted");
                let(sender,receiver)=watch::channel(None);cache.insert(key,receiver.clone());(receiver,Some(sender))
            }
        };
        if let Some(sender)=sender{
            let context=self.context.clone();let url=endpoint.url.clone();
            self.spawn(async move{
                let result=raw_node(context,url).await.map_err(|e|SharedFailure(Arc::new(e)));
                let _=sender.send(Some(result));
            })?;
        }
        loop{
            let ready={receiver.borrow_and_update().clone()};
            if let Some(result)=ready{return result.map_err(anyhow::Error::new)}
            tokio::select!{biased;
                _=self.context.cancel.cancelled()=>return Err(anyhow!("ACME chain download cancelled")),
                changed=receiver.changed()=>{changed.map_err(|_|anyhow!("ACME certificate fetch task ended without a result").context(GraphExecutionFailure))?;},
            }
        }
    }
    async fn cpu<T:Send+'static>(&self,operation:impl FnOnce()->Result<T>+Send+'static)->Result<T>{
        let(sender,receiver)=oneshot::channel();let cpu=self.context.wire.inner.cpu.clone();let cancel=self.context.cancel.clone();
        self.spawn(async move{
            // Separate dispatch failure from the operation's remote validation error.
            let result=crate::cert_cpu::run(cpu,cancel,move||Ok(operation())).await
                .map_err(|error|error.context(GraphExecutionFailure)).and_then(|result|result);
            let _=sender.send(result);
        })?;
        receiver.await.map_err(|_|anyhow!("ACME graph CPU task ended without a result").context(GraphExecutionFailure))?
    }
    fn take_tasks(&self)->JoinSet<()>{
        let mut guard=self.tasks.lock().unwrap_or_else(|e|e.into_inner());std::mem::take(&mut *guard)
    }
    async fn finish(&self){
        JoinGuard{tasks:Some(self.take_tasks()),cancel:self.context.cancel.clone(),cleanup:self.cleanup.clone(),runtime:self.runtime.clone()}.join_all().await;
    }
}
impl Drop for Owner{
    fn drop(&mut self){
        self.context.cancel.cancel();let tasks=self.take_tasks();self.cleanup.spawn_reaper(tasks,&self.runtime);
    }
}
async fn raw_node(context:Arc<Context>,url:Url)->Result<Arc<Node>>{
    let mut admission=admit(&context).await?;
    // The wire acquires HTTP slots after JWS signing, and returns them before
    // this method acquires any parser scratch or starts recursive traversal.
    let response=context.wire.signed_certificate_url(&context.signer,&context.location,url,
        admission.credit.take().expect("prepaid certificate input"),context.http_slots.clone(),&context.cancel).await?;
    let mut links=Vec::new();let mut header_bytes=0usize;
    for header in response.headers.get_all(reqwest::header::LINK){
        header_bytes=header_bytes.saturating_add(header.as_bytes().len());if header_bytes>65536{break}
        if let Ok(raw)=header.to_str(){links.extend(certificate_links::parse(raw).into_iter().take(64-links.len()));}
        if links.len()==64{break}
    }
    let body=Arc::new(memory::Buffer::adopt(response.body,response.body_memory.ok_or_else(||anyhow!("ACME response memory credit missing").context(GraphExecutionFailure))?)?);
    let decode=memory::scratch(validation::decode_cost(body.len())?,context.cancel.clone()).await?;
    let input=body.clone();let pool=context.wire.inner.chain_memory.payload.clone();let want_names=context.want_names;
    let info=crate::cert_cpu::run(context.wire.inner.cpu.clone(),context.cancel.clone(),move||{
        let _decode=decode;Ok(validation::validate(input,pool,want_names))
    }).await.map_err(|error|error.context(GraphExecutionFailure))??;
    Ok(Arc::new(Node{body,info,links}))
}
impl AccountSession{
    pub(crate) async fn download_order_chains(&self,order_url:&str,want_names:bool,want_alternates:bool,
        cleanup:Arc<Cleanup>,cancel:&CancellationToken)->Result<Vec<CertificateChain>>{
        let registration=cleanup.registration();
        let order=self.order(order_url,cancel).await?;
        ensure!(order.value.status=="valid","certificate chain order is not valid");
        let base=self.wire.endpoint(order_url)?;
        let raw=order.value.certificate.as_deref().ok_or_else(||anyhow!("valid order has no certificate URL"))?;
        let endpoint=Endpoint::declared(&base,raw,base.scheme()=="https",self.wire.inner.allow_loopback,self.wire.inner.allowed_http_origin.as_deref())?;
        let context=Arc::new(Context{wire:self.wire.clone(),signer:self.signer.clone(),location:Arc::from(self.location.as_str()),want_names,
            cancel:cancel.child_token(),http_slots:Arc::new(Semaphore::new(CONCURRENCY)),progress:Arc::new(Progress{active:Mutex::new(0),notify:Notify::new()})});
        let owner=Owner{context,cache:Mutex::new(HashMap::new()),tasks:Mutex::new(JoinSet::new()),visits:AtomicUsize::new(0),cleanup,runtime:Handle::current(),_registration:registration};
        let result=self.fetch_chains(endpoint,&owner,Vec::new(),0,want_alternates).await;
        owner.finish().await;
        ensure!(!cancel.is_cancelled(),"ACME chain download cancelled");result
    }
    fn fetch_chains<'a>(&'a self,endpoint:Endpoint,owner:&'a Owner,mut path:Vec<Arc<str>>,depth:usize,want_alternates:bool)
        ->Pin<Box<dyn Future<Output=Result<Vec<CertificateChain>>>+Send+'a>>{
        Box::pin(async move{
            ensure!(!owner.context.cancel.is_cancelled(),"ACME chain download cancelled");
            ensure!(depth<=MAX_DEPTH,"ACME certificate graph depth exceeded");
            owner.visits.fetch_update(Ordering::Relaxed,Ordering::Relaxed,|n|(n<MAX_VISITS).then_some(n+1))
                .map_err(|_|anyhow!("ACME certificate graph visit budget exhausted"))?;
            let key=endpoint.url.to_string();
            ensure!(!path.iter().any(|p|p.as_ref()==key),"ACME certificate graph cycle");
            path.push(Arc::from(key));
            self.fetch_contents(endpoint,owner,path,depth,want_alternates).await
        })
    }
    async fn fetch_contents(&self,endpoint:Endpoint,owner:&Owner,path:Vec<Arc<str>>,depth:usize,want_alternates:bool)->Result<Vec<CertificateChain>>{
        let node=owner.node(&endpoint).await?;let key=endpoint.url.to_string();
        let mut chains=Vec::new();let has_up=node.links.iter().any(|link|link.up);
        if !has_up{chains.push(CertificateChain{url:key.clone(),chain_pem:node.body.clone(),first:node.info.first.clone(),last:node.info.last.clone(),count:node.info.count,names:vec![node.info.names.clone()]});}
        else{
            let mut targets=HashSet::new();
            let mut endpoints=Vec::new();
            for link in node.links.iter().filter(|link|link.up){
                if let Some(target)=optional_branch(Endpoint::declared(&endpoint.url,&link.target,endpoint.require_https,self.wire.inner.allow_loopback,self.wire.inner.allowed_http_origin.as_deref()),&owner.context.cancel)?
                    && targets.insert(target.url.to_string()){endpoints.push(target);}
            }
            let parents=stream::iter(endpoints).map(|issuer|self.fetch_chains(issuer,owner,path.clone(),depth+1,want_alternates)).buffered(CONCURRENCY);
            tokio::pin!(parents);
            while let Some(result)=parents.next().await{
                if let Some(parents)=optional_branch(result,&owner.context.cancel)?{for parent in parents{
                    if chains.len()==MAX_CHAINS{break}
                    let count=node.info.count+parent.count;if count>32{continue}
                    let bridge=memory::scratch(validation::CRYPTO_SCRATCH,owner.context.cancel.clone()).await?;
                    let child=node.info.last.clone();let issuer=parent.first.clone();let input=node.body.clone();let suffix=parent.chain_pem.clone();let pool=self.wire.inner.chain_memory.payload.clone();
                    let result=owner.cpu(move||{
                        let _bridge=bridge;validation::bridge(child,issuer)?;
                        let separator=if input.as_slice().ends_with(b"\n"){&b""[..]}else{&b"\n"[..]};
                        Ok(Arc::new(memory::Buffer::assemble(&pool,&[input.as_slice(),separator,suffix.as_slice()])?))
                    }).await;
                    if let Some(chain_pem)=optional_branch(result,&owner.context.cancel)?{let mut names=vec![node.info.names.clone()];names.extend(parent.names);
                        chains.push(CertificateChain{url:key.clone(),chain_pem,first:node.info.first.clone(),last:parent.last,count,names});}
                }}
                if chains.len()==MAX_CHAINS{break}
            }
        }
        // An intact default chain does not need optional network work. A failed
        // mandatory UP path still permits a complete same-leaf alternate.
        if (want_alternates||chains.is_empty())&&chains.len()<MAX_CHAINS{
            let mut targets=HashSet::new();
            let mut endpoints=Vec::new();
            for link in node.links.iter().filter(|link|link.alternate){
                if let Some(target)=optional_branch(Endpoint::declared(&endpoint.url,&link.target,endpoint.require_https,self.wire.inner.allow_loopback,self.wire.inner.allowed_http_origin.as_deref()),&owner.context.cancel)?
                    && targets.insert(target.url.to_string()){endpoints.push(target);}
            }
            let alternates=stream::iter(endpoints).map(|alternate|self.fetch_chains(alternate,owner,path.clone(),depth+1,want_alternates)).buffered(CONCURRENCY);
            tokio::pin!(alternates);
            while let Some(result)=alternates.next().await{
                if let Some(alternates)=optional_branch(result,&owner.context.cancel)?{for candidate in alternates{
                    if chains.len()==MAX_CHAINS{break}
                    if candidate.first.as_slice()==node.info.first.as_slice(){chains.push(candidate);}
                }}
                if chains.len()==MAX_CHAINS{break}
            }
        }
        ensure!(!owner.context.cancel.is_cancelled(),"ACME chain download cancelled");
        ensure!(!chains.is_empty(),"required ACME issuer chain unavailable");Ok(chains)
    }
}
