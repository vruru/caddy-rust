//! One candidate's immutable hostname choices. Parsing never resolves names.
//! Known Rust payloads have concrete prepaid owners. libc/NSS allocations are
//! opaque provider memory, bounded here by call concurrency, not fictitious RSS.
use super::{Inner,ListenerKey,resource_budget::{BlockingBudget,BudgetError}};
use crate::http_config::{PreparedConfig,ListenSpec,ListenerFamily as Family};
use anyhow::{Result,anyhow,ensure};
use native_write_policy::{Pool,Lease};
use std::{collections::{BTreeMap,BTreeSet,HashSet},net::{SocketAddr,IpAddr},sync::{Arc,Weak,Mutex,atomic::{AtomicUsize,Ordering}},time::{Duration,Instant}};
use futures_util::{stream::FuturesUnordered,StreamExt};
use tokio_util::{sync::CancellationToken,task::{TaskTracker,task_tracker::TaskTrackerToken}};
const PLAN_LIMIT:usize=64<<20;
const LOOKUP_CREDIT:usize=16<<10;
const MAX_HOST_BYTES:usize=2048;
const MAX_ANSWERS:usize=4096;
const DEADLINE:Duration=Duration::from_secs(30);
struct Owner { used:AtomicUsize,limit:usize,_lease:Lease }
impl Owner {
 fn new(pool:&Pool,limit:usize)->Result<Arc<Self>> {let lease=pool.reserve(limit)?;Ok(Arc::new(Self{used:AtomicUsize::new(0),limit,_lease:lease}))}
}
impl crate::cert_cpu::MaterialOwner for Owner {
 fn reserve(&self,bytes:usize)->Result<()> {self.used.try_update(Ordering::AcqRel,Ordering::Acquire,|used|used.checked_add(bytes).filter(|next|*next<=self.limit)).map(|_|()).map_err(|_|anyhow!("listener resolution allocation allowance exhausted"))}
}
#[derive(Clone,Copy)]
struct Answers { v4:Option<SocketAddr>,v6:Option<SocketAddr> }
impl Answers {
 fn select(self,family:Family)->Result<SocketAddr>{match family{Family::Any=>self.v4.or(self.v6),Family::V4=>self.v4,Family::V6=>self.v6}.ok_or_else(||anyhow!("HTTP listener hostname has no address for requested family"))}
}
#[derive(Clone,Copy,Debug)]
enum LookupError { System(i32),NoAddress,TooMany,Cancelled,Unsupported }
impl std::fmt::Display for LookupError {fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{match self{Self::System(code)=>write!(f,"system listener lookup failed ({code})"),Self::NoAddress=>f.write_str("listener hostname has no addresses"),Self::TooMany=>f.write_str("listener resolver answer capacity exceeded"),Self::Cancelled=>f.write_str("listener lookup cancelled or expired"),Self::Unsupported=>f.write_str("system listener resolver unsupported")}}}
impl std::error::Error for LookupError {}
fn check(cancel:&CancellationToken,stop:&CancellationToken,deadline:Instant)->Result<()> {ensure!(!cancel.is_cancelled()&&!stop.is_cancelled()&&Instant::now()<deadline,"listener resolution cancelled or expired");Ok(())}
fn key(host:&str)->Arc<str> {if host.contains('%'){Arc::from(host)}else{Arc::from(host.to_ascii_lowercase())}}
fn find_answer(hosts:&BTreeMap<Arc<str>,Answers>,host:&str)->Result<Answers> {
 ensure!(host.len()<=MAX_HOST_BYTES,"listener hostname capacity exceeded");
 let mut bytes=[0u8;MAX_HOST_BYTES];bytes[..host.len()].copy_from_slice(host.as_bytes());
 if !host.contains('%'){bytes[..host.len()].make_ascii_lowercase();}
 // ASCII case changes preserve the original UTF-8 encoding.
 let name=std::str::from_utf8(&bytes[..host.len()])?;
 hosts.get(name).copied().ok_or_else(||anyhow!("hostname has no candidate listener snapshot"))
}

/// Independent admission; its running slots are allocated from the common
/// blocking headroom by Resources. The input and result outlive the waiter.
/// Closed native listener preparation only. Retained bytes are concrete
/// prepaid known Rust payload allowances, not an NSS or process RSS bound.
#[derive(Clone,Debug,serde::Serialize)]
pub struct ListenerResolutionDiagnostics {
 pub lookup:super::BudgetSnapshot,
 pub retained_bytes:usize,
 pub tracked_jobs:usize,
}
pub(super) struct Resolver { lane:BlockingBudget,pool:Pool,gate:Mutex<bool>,tasks:TaskTracker,stop:CancellationToken }
impl Resolver {
 pub(super) fn snapshot(&self)->ListenerResolutionDiagnostics {ListenerResolutionDiagnostics{lookup:self.lane.snapshot(),retained_bytes:self.pool.used(),tracked_jobs:self.tasks.len()}}

 pub(super) fn new(running:usize)->Result<Self>{let lane=BlockingBudget::new(running,32,Duration::from_secs(2))?;let tasks=lane.tasks();Ok(Self{lane,pool:Pool::new(PLAN_LIMIT),gate:Mutex::new(false),tasks,stop:CancellationToken::new()})}
 pub(super) fn close(&self){let closed={let mut gate=self.gate.lock().unwrap_or_else(|p|p.into_inner());std::mem::replace(&mut *gate,true)};if !closed{self.stop.cancel();self.tasks.close();}}
 pub(super) async fn wait(&self){self.close();self.tasks.wait().await;}
 fn lookup(&self,host:Arc<str>,cancel:CancellationToken,deadline:Instant)->Result<impl std::future::Future<Output=Result<Answers>>+Send+'_>{
  let owner=Owner::new(&self.pool,LOOKUP_CREDIT)?;
  let token={let gate=self.gate.lock().map_err(|_|anyhow!("listener resolver admission poisoned"))?;ensure!(!*gate,"listener resolver closed");self.tasks.token()};
  let job=LookupJob{host,cancel:cancel.clone(),stop:self.stop.clone(),deadline,_token:token};
  let guard=owner.clone();
  Ok(async move {
   check(&cancel,&self.stop,deadline)?;
   let call=self.lane.run_retained(owner,move||job.execute());
   let result=tokio::select!{biased;
    _=cancel.cancelled()=>Err(anyhow!("listener lookup cancelled")),
    _=self.stop.cancelled()=>Err(anyhow!("listener resolver stopped")),
    _=tokio::time::sleep_until(tokio::time::Instant::from_std(deadline))=>Err(anyhow!("listener lookup deadline exceeded")),
    result=call=>match result{Ok(output)=>{let result=*output.get();drop(output);result.map_err(anyhow::Error::new)},Err(error)=>Err(anyhow!(match error{BudgetError::Overloaded=>"listener lookup admission exhausted",BudgetError::WorkerFailed=>"listener lookup worker failed"}))},
   };
   result.map_err(|error|crate::cert_cpu::retained_error(error,guard))
  })
 }
}
struct LookupJob {host:Arc<str>,cancel:CancellationToken,stop:CancellationToken,deadline:Instant,_token:TaskTrackerToken}
impl LookupJob {
 fn execute(self)->std::result::Result<Answers,LookupError>{let result=system(&self.host,&self.cancel,&self.stop,self.deadline);drop(self);result}
}
#[cfg(unix)]
fn system(host:&str,cancel:&CancellationToken,stop:&CancellationToken,deadline:Instant)->std::result::Result<Answers,LookupError>{
 use std::{ffi::CString,ptr,net::{Ipv4Addr,Ipv6Addr,SocketAddrV6}};
 if cancel.is_cancelled()||stop.is_cancelled()||Instant::now()>=deadline{return Err(LookupError::Cancelled);}
 let name=CString::new(host).map_err(|_|LookupError::System(libc::EAI_NONAME))?;
 // SAFETY: zeroed addrinfo is the specified empty hints value. No application
 // callback enters libc. The blocking job retains its admission and credit.
 let mut hints:libc::addrinfo=unsafe{std::mem::zeroed()};hints.ai_family=libc::AF_UNSPEC;hints.ai_socktype=libc::SOCK_STREAM;
 let mut head=ptr::null_mut();
 let status=unsafe{libc::getaddrinfo(name.as_ptr(),ptr::null(),&hints,&mut head)};
 if status!=0{return Err(LookupError::System(status));}
 struct Owned(*mut libc::addrinfo);
 impl Drop for Owned{fn drop(&mut self){if !self.0.is_null(){unsafe{libc::freeaddrinfo(self.0)}}}}
 let _answers=Owned(head);let mut out=Answers{v4:None,v6:None};let mut current=head;let mut count=0;
 while !current.is_null(){
  count+=1;if count>MAX_ANSWERS{return Err(LookupError::TooMany);}
  if count%32==0&&(cancel.is_cancelled()||stop.is_cancelled()||Instant::now()>=deadline){return Err(LookupError::Cancelled);}
  // SAFETY: getaddrinfo owns this linked list until the guard frees it. Family
  // and sockaddr byte lengths are checked before each unaligned field read.
  let item=unsafe{&*current};current=item.ai_next;if item.ai_socktype!=libc::SOCK_STREAM||item.ai_addr.is_null(){continue;}
  if item.ai_family==libc::AF_INET&&item.ai_addrlen as usize>=std::mem::size_of::<libc::sockaddr_in>(){
   let raw=unsafe{ptr::read_unaligned(item.ai_addr.cast::<libc::sockaddr_in>())};if out.v4.is_none(){out.v4=Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(raw.sin_addr.s_addr.to_ne_bytes())),0));}
  }else if item.ai_family==libc::AF_INET6&&item.ai_addrlen as usize>=std::mem::size_of::<libc::sockaddr_in6>(){
   let raw=unsafe{ptr::read_unaligned(item.ai_addr.cast::<libc::sockaddr_in6>())};let ip=Ipv6Addr::from(raw.sin6_addr.s6_addr);
   if let Some(ip)=ip.to_ipv4_mapped(){if out.v4.is_none(){out.v4=Some(SocketAddr::new(IpAddr::V4(ip),0));}}
   else if out.v6.is_none(){out.v6=Some(SocketAddr::V6(SocketAddrV6::new(ip,0,0,raw.sin6_scope_id)));}
  }
 }
 if cancel.is_cancelled()||stop.is_cancelled()||Instant::now()>=deadline{return Err(LookupError::Cancelled);}
 if out.v4.is_none()&&out.v6.is_none(){return Err(LookupError::NoAddress);}Ok(out)
}
#[cfg(not(unix))]
fn system(_host:&str,_cancel:&CancellationToken,_stop:&CancellationToken,_deadline:Instant)->std::result::Result<Answers,LookupError>{Err(LookupError::Unsupported)}
/// Every owned payload precedes the concrete allocation owner. It cannot retain
/// a runtime, service, callback or another mutable configuration generation.
pub(super) struct ResolvedServer {pub(super) addresses:Vec<ListenerKey>,pub(super) v6_only:HashSet<ListenerKey>,_owner:Arc<Owner>}
pub(crate) struct Plan {
 runtime:Weak<Inner>,names:Vec<Arc<str>>,declarations:Vec<Arc<[ListenSpec]>>,
 pub(super) servers:Vec<Arc<ResolvedServer>>,hosts:BTreeMap<Arc<str>,Answers>,_owner:Arc<Owner>,
}
impl Plan {
 pub(super) async fn verify(&self,inner:&Arc<Inner>,config:&PreparedConfig,cancel:&CancellationToken)->Result<()>{
  ensure!(self.runtime.ptr_eq(&Arc::downgrade(inner)),"foreign listener resolution plan");ensure!(self.servers.len()==config.servers.len(),"listener plan server count changed");let mut work=0;
  for (index,server)in config.servers.iter().enumerate(){ensure!(self.names[index]==server.name&&self.declarations[index].len()==server.listen_specs.len(),"listener declarations changed after resolution");for(a,b)in self.declarations[index].iter().zip(&server.listen_specs){ensure!(a==b,"listener declarations changed after resolution");work+=1;if work%128==0{ensure!(!cancel.is_cancelled()&&!inner.stopped.is_cancelled(),"listener plan cancelled");tokio::task::yield_now().await;}}}Ok(())
 }
 pub(super) fn bind_host(&self,host:&str)->Result<Option<SocketAddr>>{if host.is_empty(){return Ok(None);}if let Ok(ip)=host.parse::<IpAddr>(){return Ok(Some(SocketAddr::new(ip,0)));}Ok(Some(find_answer(&self.hosts,host)?.select(Family::Any)?))}
}
async fn resolve_one(resolver:&Resolver,(name,host):(Arc<str>,Arc<str>),cancel:CancellationToken,deadline:Instant)->(Arc<str>,Result<Answers>){
 let result=match resolver.lookup(host,cancel,deadline){Ok(call)=>call.await,Err(error)=>Err(error)};(name,result)
}
/// Resolve all HTTP and effective ACME bind names before provisioning a
/// candidate. Each name is looked up once; all families use the same answer set.
pub(super) async fn prepare<'a>(inner:&Arc<Inner>,config:&PreparedConfig,extra:impl Iterator<Item=&'a str>+Clone,cancel:CancellationToken)->Result<Arc<Plan>>{
 let resolver=&inner.resources.listener_dns;let deadline=Instant::now()+DEADLINE;check(&cancel,&resolver.stop,deadline)?;
 let count=config.servers.iter().try_fold(0usize,|n,s|n.checked_add(s.listen_specs.len())).ok_or_else(||anyhow!("listener metadata overflow"))?;
 let mut bytes=count.checked_mul(768).and_then(|n|n.checked_add(config.servers.len().saturating_mul(1024))).and_then(|n|n.checked_add(65536)).ok_or_else(||anyhow!("listener metadata overflow"))?;
 ensure!(bytes<=PLAN_LIMIT,"listener plan capacity exceeded");
 let mut hosts=BTreeMap::new();let mut extra_count=0usize;let mut named_count=0usize;
 // Count borrowed inputs before any collection or copied name allocation.
 for host in extra.clone(){ensure!(host.len()<=MAX_HOST_BYTES&&!host.bytes().any(|b|matches!(b,0|b'\r'|b'\n')),"invalid challenge bind hostname");bytes=bytes.checked_add(host.len().saturating_mul(4)+768).ok_or_else(||anyhow!("listener metadata overflow"))?;extra_count+=1;ensure!(extra_count<=1024,"challenge bind hostname count exceeded");}
 for server in &config.servers{for spec in &server.listen_specs{if let ListenSpec::Hostname{host,..}=spec{named_count+=1;bytes=bytes.checked_add(host.len().saturating_mul(4)+768).ok_or_else(||anyhow!("listener metadata overflow"))?;}}}
 let owner=Owner::new(&resolver.pool,bytes)?;
 let result:Result<Plan>=async{
  let mut names=Vec::new();let mut declarations=Vec::new();let mut servers=Vec::new();names.try_reserve_exact(config.servers.len())?;declarations.try_reserve_exact(config.servers.len())?;servers.try_reserve_exact(config.servers.len())?;
  let mut work=0;
  // All names and collection capacity are prepaid before collecting work. Keep
  // declaration order, deduplicate once, and never allocate N live futures.
  let upper=named_count.checked_add(extra_count).ok_or_else(||anyhow!("listener work count overflow"))?;
  let mut requests=Vec::new();requests.try_reserve_exact(upper)?;let mut unique=BTreeSet::new();
  for server in &config.servers{for spec in &server.listen_specs{
   if let ListenSpec::Hostname{host,..}=spec{let name=key(host);if unique.insert(name.clone()){requests.push((name,host.clone()));}}
   work+=1;if work%128==0{check(&cancel,&resolver.stop,deadline)?;tokio::task::yield_now().await;}
  }}
  for host in extra {
   if !host.is_empty()&&host.parse::<IpAddr>().is_err(){let name=key(host);if unique.insert(name.clone()){requests.push((name,Arc::from(host)));}}
   work+=1;if work%128==0{check(&cancel,&resolver.stop,deadline)?;tokio::task::yield_now().await;}
  }
  drop(unique);
  let operation=cancel.child_token();let mut inputs=requests.into_iter();
  if let Some(first)=inputs.next(){
   let parallelism=resolver.lane.snapshot().running_limit;
   ensure!((1..=8).contains(&parallelism),"listener lookup concurrency outside prepaid bounds");
   let first=resolve_one(resolver,first,operation.clone(),deadline);
   // The unconditional 64 KiB plan allowance prepays <=8 task nodes, their
   // queue/stub, cancellation metadata and fixed plan bookkeeping. The pinned
   // FuturesUnordered node/Arc/queue overhead is well below 1 KiB per slot;
   // enforce the concrete future's layout before its first node allocation.
   let future_bytes=std::mem::size_of_val(&first);
   ensure!(future_bytes<=4096 && (parallelism+1)*(future_bytes+1024)+2048<=65536,
       "listener lookup future scratch capacity exceeded");
   let mut pending=FuturesUnordered::new();
   // Declared after pending so cancellation happens before future-set Drop on
   // caller abort. Actual libc jobs independently retain their old tracker,
   // input and concrete credit until the real closure/result retires.
   let _cancel_on_drop=operation.clone().drop_guard();
   pending.push(first);
   while pending.len()<parallelism {let Some(input)=inputs.next()else{break};pending.push(resolve_one(resolver,input,operation.clone(),deadline));}
   let mut failure=None;
   while let Some((name,result))=pending.next().await {
    if failure.is_none(){match result{Ok(answer)=>{hosts.insert(name,answer);},Err(error)=>{failure=Some(error);operation.cancel();}}}
    // Never refill after a failure. Drain only the bounded async waiters;
    // uninterruptible libc calls remain visible to global shutdown/credit.
    if failure.is_none(){if let Some(input)=inputs.next(){pending.push(resolve_one(resolver,input,operation.clone(),deadline));}}
    work+=1;if work%128==0{tokio::task::yield_now().await;}
   }
   if let Some(error)=failure {
    for _ in inputs {work+=1;if work%128==0{tokio::task::yield_now().await;}}
    return Err(error);
   }
  }
  for server in &config.servers{
   let mut addresses=Vec::new();let mut v6_only=HashSet::new();addresses.try_reserve_exact(server.listen_specs.len())?;v6_only.try_reserve(server.listen_specs.len())?;
   for spec in &server.listen_specs{let(address,mode)=match spec{ListenSpec::Numeric{address,only_v6,..}=>(*address,*only_v6),ListenSpec::Hostname{host,port,family,..}=>{let mut address=find_answer(&hosts,host)?.select(*family)?;address.set_port(*port);(address,*family==Family::V6)}};let address=ListenerKey{address,identity:spec.identity().clone()};if addresses.contains(&address){ensure!(v6_only.contains(&address)==mode,"resolved listener IPv6 modes conflict");}else{addresses.push(address.clone());if mode{v6_only.insert(address);}}work+=1;if work%128==0{check(&cancel,&resolver.stop,deadline)?;tokio::task::yield_now().await;}}
   names.push(server.name.clone());declarations.push(Arc::from(server.listen_specs.clone()));servers.push(Arc::new(ResolvedServer{addresses,v6_only,_owner:owner.clone()}));
  }
  check(&cancel,&resolver.stop,deadline)?;Ok(Plan{runtime:Arc::downgrade(inner),names,declarations,servers,hosts,_owner:owner.clone()})
 }.await;
 result.map(Arc::new).map_err(|error|crate::cert_cpu::retained_error(error,owner))
}
