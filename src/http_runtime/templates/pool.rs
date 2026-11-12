//! Renderer threads are independent of Tokio's blocking queue: a parent may
//! synchronously wait for a virtual child without occupying its child's pool.
use super::render::Control;
use crate::http_runtime::resource_budget::{BudgetError,BudgetSnapshot};
use std::{sync::{Arc,Mutex,Weak,atomic::{AtomicBool,AtomicU64,AtomicUsize,Ordering}},thread::JoinHandle,time::Duration};
use tokio::sync::{OwnedSemaphorePermit,Semaphore};
use tokio_util::task::TaskTracker;
pub(crate) struct Budget {
    roots:Arc<Semaphore>,numeric:Arc<Semaphore>,numeric_limit:usize,shutdown:tokio_util::sync::CancellationToken,memory:Arc<Semaphore>,waiting:Arc<Semaphore>,running_limit:usize,
    closed:AtomicBool,rejected:AtomicU64,threads:Mutex<Vec<JoinHandle<()>>>,tasks:TaskTracker,
}
const DONE:usize=1<<(usize::BITS-1);
pub(super) struct RootTree(Arc<Tree>);
impl RootTree{pub(super) fn tree(&self)->Arc<Tree>{self.0.clone()} pub(super) fn finish(&self){let previous=self.0.state.fetch_or(DONE,Ordering::AcqRel);self.0.done.cancel();if previous==0{self.0.release_cpu();}}}
pub(super) struct Tree {
    // Scope and backing allocations retire before Control and memory credit.
    formatter_scope:std::sync::OnceLock<gotmpl::OwnedFormatterScope>,
    pub control:Arc<Control>,
    cpu:Mutex<Cpu>,_memory:OwnedSemaphorePermit,
    roots:Arc<Semaphore>,numeric:Arc<Semaphore>,runtime:tokio::runtime::Handle,
    shutdown:tokio_util::sync::CancellationToken,done:tokio_util::sync::CancellationToken,
    state:AtomicUsize,_admission:tokio_util::task::task_tracker::TaskTrackerToken,
}
#[derive(Clone)]
pub(super) struct Inherited {pub tree:Arc<Tree>,pub depth:u8}
struct ActiveThread(Arc<Tree>);
impl Tree{fn release_cpu(&self){let permit=self.cpu.lock().unwrap_or_else(std::sync::PoisonError::into_inner).permit.take();drop(permit);}}
impl Drop for ActiveThread {fn drop(&mut self){if self.0.state.fetch_sub(1,Ordering::AcqRel)==(DONE|1){self.0.release_cpu();}}}
impl Budget {
    pub(crate) fn new(running:usize)->anyhow::Result<Self>{
        anyhow::ensure!((1..=8).contains(&running),"template worker limit outside bounds");
        let numeric_limit=std::thread::available_parallelism().map(|n|n.get()).unwrap_or(1).clamp(1,8);
        Ok(Self{roots:Arc::new(Semaphore::new(running)),numeric:Arc::new(Semaphore::new(numeric_limit)),numeric_limit,shutdown:tokio_util::sync::CancellationToken::new(),memory:Arc::new(Semaphore::new(16)),waiting:Arc::new(Semaphore::new(16)),running_limit:running,closed:AtomicBool::new(false),rejected:AtomicU64::new(0),threads:Mutex::new(Vec::new()),tasks:TaskTracker::new()})
    }
    pub(super) fn reserve(&self)->Result<OwnedSemaphorePermit,BudgetError>{
        if self.closed.load(Ordering::Acquire){return Err(BudgetError::WorkerFailed);}
        self.memory.clone().try_acquire_owned().map_err(|_|{self.rejected.fetch_add(1,Ordering::Relaxed);BudgetError::Overloaded})
    }
    pub(super) async fn admit(&self,control:Arc<Control>,memory:OwnedSemaphorePermit)->Result<RootTree,BudgetError>{self.admit_with_queue(control,memory,true).await}
    // A prepared custom listing still owns directory credit. It must never
    // wait in the ordinary CPU queue while retaining that unrelated resource.
    pub(super) async fn admit_immediate(&self,control:Arc<Control>,memory:OwnedSemaphorePermit)->Result<RootTree,BudgetError>{self.admit_with_queue(control,memory,false).await}
    async fn admit_with_queue(&self,control:Arc<Control>,memory:OwnedSemaphorePermit,queue:bool)->Result<RootTree,BudgetError>{
        // Token precedes the closed check, so wait cannot observe zero while a
        // concurrent accepted root is still between admission and registration.
        let admission=self.tasks.token();
        if self.closed.load(Ordering::Acquire)||control.cancel.is_cancelled(){return Err(BudgetError::WorkerFailed);}
        let root=match self.roots.clone().try_acquire_owned(){
            Ok(permit)=>permit,
            Err(_)=>{
                if !queue {self.rejected.fetch_add(1,Ordering::Relaxed);return Err(BudgetError::Overloaded);}
                let queued=self.waiting.clone().try_acquire_owned().map_err(|_|BudgetError::Overloaded)?;
                let until=(std::time::Instant::now()+Duration::from_secs(2)).min(control.deadline());
                let permit=tokio::select!{
                    permit=self.roots.clone().acquire_owned()=>permit.map_err(|_|BudgetError::WorkerFailed)?,
                    _=control.cancel.cancelled()=>return Err(BudgetError::WorkerFailed),
                    _=tokio::time::sleep_until(tokio::time::Instant::from_std(until))=>return Err(BudgetError::Overloaded),
                };
                drop(queued);permit
            }
        };
        if self.closed.load(Ordering::Acquire)||control.cancel.is_cancelled(){return Err(BudgetError::WorkerFailed);}
        let runtime=tokio::runtime::Handle::try_current().map_err(|_|BudgetError::WorkerFailed)?;
        let tree=Arc::new(Tree{formatter_scope:std::sync::OnceLock::new(),control,cpu:Mutex::new(Cpu{permit:Some(root),numeric_active:false}),roots:self.roots.clone(),numeric:self.numeric.clone(),runtime,shutdown:self.shutdown.clone(),done:tokio_util::sync::CancellationToken::new(),_memory:memory,state:AtomicUsize::new(0),_admission:admission});
        tree.control.bind_worker(Binding{tree:Arc::downgrade(&tree),shutdown:tree.shutdown.clone(),done:tree.done.clone()})?;
        Ok(RootTree(tree))
    }
    pub(super) async fn run<T:Send+'static>(&self,tree:Arc<Tree>,job:impl FnOnce()->T+Send+'static)->Result<T,BudgetError>{
        let control=tree.control.clone();
        let token=self.tasks.token();
        // Register before checking closed. A close/wait racing this call must
        // either see the token or prevent any new OS worker from spawning.
        if self.closed.load(Ordering::Acquire)||control.check().is_err(){return Err(BudgetError::WorkerFailed);}
        let shutdown=tree.shutdown.clone();let done=tree.done.clone();
        tree.state.try_update(Ordering::AcqRel,Ordering::Acquire,|n|(n<4).then_some(n+1)).map_err(|_|BudgetError::Overloaded)?;
        let active=ActiveThread(tree.clone());
        let receiver={
        let mut threads=self.threads.lock().map_err(|_|BudgetError::WorkerFailed)?;
        let mut i=0;while i<threads.len(){if threads[i].is_finished(){let _=threads.swap_remove(i).join();}else{i+=1;}}
        if threads.len()>=(self.running_limit+self.numeric_limit)*4{self.rejected.fetch_add(1,Ordering::Relaxed);return Err(BudgetError::Overloaded);}
        let(sender,receiver)=tokio::sync::oneshot::channel();
        let handle=std::thread::Builder::new().name("caddy-template".into()).stack_size(4<<20).spawn(move||{
            let scope=WorkerScope::enter(&tree);
            let result=std::panic::catch_unwind(std::panic::AssertUnwindSafe(job));
            if result.is_err(){tree.control.cancel.cancel();}
            let _=sender.send(result.map_err(|_|BudgetError::WorkerFailed));
            drop(scope);drop(active);drop(tree);drop(token);
        }).map_err(|_|BudgetError::WorkerFailed)?;
        threads.push(handle);receiver
        };
        tokio::select!{
            result=receiver=>result.map_err(|_|BudgetError::WorkerFailed)?,
            _=shutdown.cancelled()=>Err(BudgetError::WorkerFailed),
            _=done.cancelled()=>Err(BudgetError::WorkerFailed),
            _=control.cancel.cancelled()=>Err(BudgetError::WorkerFailed),
            _=tokio::time::sleep_until(tokio::time::Instant::from_std(control.deadline()))=>{control.cancel.cancel();Err(BudgetError::WorkerFailed)},
        }
    }
    pub(crate) fn close(&self){self.closed.store(true,Ordering::Release);self.shutdown.cancel();self.numeric.close();self.roots.close();self.tasks.close();}
    pub(crate) async fn wait(&self){
        self.tasks.wait().await;
        let threads=self.threads.lock().map(|mut threads|std::mem::take(&mut *threads)).unwrap_or_default();
        // No worker owns a token now. The join only reaps OS thread exit.
        let _=tokio::task::spawn_blocking(move||{for thread in threads{let _=thread.join();}}).await;
    }
    pub(super) fn snapshot(&self)->BudgetSnapshot{BudgetSnapshot{running_limit:self.running_limit,waiting_limit:16,running:self.running_limit.saturating_sub(self.roots.available_permits()),waiting:16-self.waiting.available_permits(),rejected:self.rejected.load(Ordering::Relaxed)}}
}

struct Cpu {permit:Option<OwnedSemaphorePermit>,numeric_active:bool}
std::thread_local!{static WORKER_TREE:std::cell::Cell<Option<usize>>=const{std::cell::Cell::new(None)};}
struct WorkerScope(Option<usize>);
impl WorkerScope {
    fn enter(tree:&Arc<Tree>)->Self{Self(WORKER_TREE.with(|current|current.replace(Some(Arc::as_ptr(tree)as usize))))}
}
impl Drop for WorkerScope{fn drop(&mut self){WORKER_TREE.with(|current|current.set(self.0));}}
/// The backlink is weak. Tokens do not own the Tree or Control.
pub(super) struct Binding {tree:Weak<Tree>,shutdown:tokio_util::sync::CancellationToken,done:tokio_util::sync::CancellationToken}
impl Binding {
 pub(super) fn stopped(&self)->bool{self.shutdown.is_cancelled()||self.done.is_cancelled()}
 pub(super) fn formatter(&self,control:&Arc<Control>)->gotmpl::Result<Arc<gotmpl::FormatterScope>>{
  let tree=self.tree.upgrade().ok_or_else(||gotmpl::TemplateError::Exec("formatter worker owner retired".into()))?;
  if !Arc::ptr_eq(&tree.control,control)||!WORKER_TREE.with(|current|current.get()==Some(Arc::as_ptr(&tree)as usize)){return Err(gotmpl::TemplateError::Exec("formatter requires its admitted worker".into()));}
  control.check()?;
  if let Some(owner)=tree.formatter_scope.get(){return Ok(owner.scope());}
  let meter=control.formatting_meter()?;
  control.reserve_host_bytes(128)?;let weak=Arc::downgrade(control);
  // This is the closed Frame function/factory set. User template/JSON values
  // cannot construct Objects/NamedTypes and CustomFuncs is nil. Public scopes
  // default to rejecting opaque callback formatting paths.
  let host:gotmpl::FormatHostGuard=Arc::new(move|value|{let control=weak.upgrade().ok_or_else(||gotmpl::TemplateError::Exec("formatter host owner retired".into()))?;control.check()?;super::render::formatting_host_cost(value,&control)});
  let owner=gotmpl::FormatterScope::new(meter,Some(host))?;
  let unused=tree.formatter_scope.set(owner);drop(unused);
  tree.formatter_scope.get().map(|owner|owner.scope()).ok_or_else(||gotmpl::TemplateError::Exec("formatter scope unavailable".into()))
 }
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub(super) enum NumericError {Unbound,NotWorker,Overloaded,Stopped,Poisoned,AlreadyActive,AlreadyResumed}
impl NumericError {pub(super) fn message(self)->&'static str{match self{
    Self::Unbound=>"numeric computation requires a live bound template worker",
    Self::NotWorker=>"numeric computation must execute on its bound renderer thread",
    Self::Overloaded=>"numeric computation capacity exhausted",
    Self::Stopped=>"numeric computation cancelled or template worker stopped",
    Self::Poisoned=>"template CPU state poisoned",
    Self::AlreadyActive=>"numeric computation already active for this template tree",
    Self::AlreadyResumed=>"numeric computation already resumed",
}}}
/// A paused ordinary CPU stage, not a detached task. The worker, Tree and
/// memory/admission tokens remain owned until the actual thread exits.
pub(super) struct NumericGuard {tree:Arc<Tree>,permit:Option<OwnedSemaphorePermit>,paused:bool,_not_send:std::marker::PhantomData<std::rc::Rc<()>>}
impl NumericGuard {
    pub(super) fn enter(binding:&Binding)->Result<Self,NumericError>{
        let tree=binding.tree.upgrade().ok_or(NumericError::Unbound)?;
        if !WORKER_TREE.with(|current|current.get()==Some(Arc::as_ptr(&tree)as usize)){return Err(NumericError::NotWorker);}
        if binding.stopped()||tree.control.cancel.is_cancelled()||std::time::Instant::now()>tree.control.deadline(){return Err(NumericError::Stopped);}
        // Never wait for numeric capacity while occupying an ordinary slot.
        let permit=tree.numeric.clone().try_acquire_owned().map_err(|e|match e{tokio::sync::TryAcquireError::Closed=>NumericError::Stopped,tokio::sync::TryAcquireError::NoPermits=>NumericError::Overloaded})?;
        let ordinary={
            let mut cpu=tree.cpu.lock().map_err(|_|NumericError::Poisoned)?;
            let state=tree.state.load(Ordering::Acquire);
            if state&DONE!=0||state&!DONE==0||tree.shutdown.is_cancelled()||tree.control.cancel.is_cancelled()||std::time::Instant::now()>tree.control.deadline(){return Err(NumericError::Stopped);}
            if cpu.numeric_active||cpu.permit.is_none(){return Err(NumericError::AlreadyActive);}
            let ordinary=cpu.permit.take().ok_or(NumericError::AlreadyActive)?;
            cpu.numeric_active=true;ordinary
        };
        let guard=Self{tree,permit:Some(permit),paused:true,_not_send:std::marker::PhantomData};
        // Semaphore release may wake unrelated jobs: keep it outside the lock.
        drop(ordinary);Ok(guard)
    }
    pub(super) fn resume(&mut self)->gotmpl::Result<()>{
        if !self.paused{return Err(gotmpl::TemplateError::Exec(NumericError::AlreadyResumed.message().into()));}
        let result=self.restore();
        if let Err(error)=result{self.abort();return Err(gotmpl::TemplateError::Exec(error.message().into()));}
        drop(self.permit.take());Ok(())
    }
    fn restore(&mut self)->Result<(),NumericError>{
        let tree=&self.tree;
        if tree.control.cancel.is_cancelled()||tree.done.is_cancelled()||tree.shutdown.is_cancelled()||std::time::Instant::now()>tree.control.deadline(){return Err(NumericError::Stopped);}
        // No CPU/number/namespace mutex is held across this fair reacquire.
        let acquired=tree.runtime.block_on(async{tokio::select!{biased;
            _=tree.control.cancel.cancelled()=>Err(NumericError::Stopped),
            _=tree.done.cancelled()=>Err(NumericError::Stopped),
            _=tree.shutdown.cancelled()=>Err(NumericError::Stopped),
            _=tokio::time::sleep_until(tokio::time::Instant::from_std(tree.control.deadline()))=>Err(NumericError::Stopped),
            permit=tree.roots.clone().acquire_owned()=>permit.map_err(|_|NumericError::Stopped),
        }})?;
        let mut incoming=Some(acquired);
        let installed={
            let mut cpu=tree.cpu.lock().map_err(|_|NumericError::Poisoned)?;
            if tree.state.load(Ordering::Acquire)&DONE!=0||tree.done.is_cancelled()||tree.shutdown.is_cancelled()||tree.control.cancel.is_cancelled()||std::time::Instant::now()>tree.control.deadline(){Err(NumericError::Stopped)}
            else if !cpu.numeric_active||cpu.permit.is_some(){Err(NumericError::AlreadyActive)}
            else {cpu.permit=incoming.take();cpu.numeric_active=false;self.paused=false;Ok(())}
        };
        // Cancellation/DONE may win after acquisition; never drop the unused
        // credit while holding the CPU mutex or continue template execution.
        drop(incoming);installed
    }
    fn abort(&mut self){
        if !self.paused{return;}
        self.tree.control.cancel.cancel();
        let ordinary={let mut cpu=self.tree.cpu.lock().unwrap_or_else(std::sync::PoisonError::into_inner);cpu.numeric_active=false;self.paused=false;cpu.permit.take()};
        drop(ordinary);drop(self.permit.take());
    }
}
impl Drop for NumericGuard{fn drop(&mut self){self.abort();}}
