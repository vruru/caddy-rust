//! Renderer threads are independent of Tokio's blocking queue: a parent may
//! synchronously wait for a virtual child without occupying its child's pool.
use super::render::Control;
use crate::http_runtime::resource_budget::{BudgetError,BudgetSnapshot};
use std::{sync::{Arc,Mutex,atomic::{AtomicBool,AtomicU64,AtomicUsize,Ordering}},thread::JoinHandle,time::Duration};
use tokio::sync::{OwnedSemaphorePermit,Semaphore};
use tokio_util::task::TaskTracker;
pub(crate) struct Budget {
    roots:Arc<Semaphore>,memory:Arc<Semaphore>,waiting:Arc<Semaphore>,running_limit:usize,
    closed:AtomicBool,rejected:AtomicU64,threads:Mutex<Vec<JoinHandle<()>>>,tasks:TaskTracker,
}
const DONE:usize=1<<(usize::BITS-1);
pub(super) struct RootTree(Arc<Tree>);
impl RootTree{pub(super) fn tree(&self)->Arc<Tree>{self.0.clone()} pub(super) fn finish(&self){if self.0.state.fetch_or(DONE,Ordering::AcqRel)==0{self.0.release_cpu();}}}
pub(super) struct Tree {
    pub control:Arc<Control>,
    cpu:Mutex<Option<OwnedSemaphorePermit>>,_memory:OwnedSemaphorePermit,
    state:AtomicUsize,_admission:tokio_util::task::task_tracker::TaskTrackerToken,
}
#[derive(Clone)]
pub(super) struct Inherited {pub tree:Arc<Tree>,pub depth:u8}
struct ActiveThread(Arc<Tree>);
impl Tree{fn release_cpu(&self){let permit=self.cpu.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take();drop(permit);}}
impl Drop for ActiveThread {fn drop(&mut self){if self.0.state.fetch_sub(1,Ordering::AcqRel)==(DONE|1){self.0.release_cpu();}}}
impl Budget {
    pub(crate) fn new(running:usize)->anyhow::Result<Self>{
        anyhow::ensure!((1..=8).contains(&running),"template worker limit outside bounds");
        Ok(Self{roots:Arc::new(Semaphore::new(running)),memory:Arc::new(Semaphore::new(16)),waiting:Arc::new(Semaphore::new(16)),running_limit:running,closed:AtomicBool::new(false),rejected:AtomicU64::new(0),threads:Mutex::new(Vec::new()),tasks:TaskTracker::new()})
    }
    pub(super) fn reserve(&self)->Result<OwnedSemaphorePermit,BudgetError>{
        if self.closed.load(Ordering::Acquire){return Err(BudgetError::WorkerFailed);}
        self.memory.clone().try_acquire_owned().map_err(|_|{self.rejected.fetch_add(1,Ordering::Relaxed);BudgetError::Overloaded})
    }
    pub(super) async fn admit(&self,control:Arc<Control>,memory:OwnedSemaphorePermit)->Result<RootTree,BudgetError>{
        // Token precedes the closed check, so wait cannot observe zero while a
        // concurrent accepted root is still between admission and registration.
        let admission=self.tasks.token();
        if self.closed.load(Ordering::Acquire)||control.cancel.is_cancelled(){return Err(BudgetError::WorkerFailed);}
        let root=match self.roots.clone().try_acquire_owned(){
            Ok(permit)=>permit,
            Err(_)=>{
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
        let tree=Arc::new(Tree{control,cpu:Mutex::new(Some(root)),_memory:memory,state:AtomicUsize::new(0),_admission:admission});
        Ok(RootTree(tree))
    }
    pub(super) async fn run<T:Send+'static>(&self,tree:Arc<Tree>,job:impl FnOnce()->T+Send+'static)->Result<T,BudgetError>{
        let control=tree.control.clone();
        let token=self.tasks.token();
        if control.cancel.is_cancelled(){return Err(BudgetError::WorkerFailed);}
        tree.state.try_update(Ordering::AcqRel,Ordering::Acquire,|n|(n<4).then_some(n+1)).map_err(|_|BudgetError::Overloaded)?;
        let active=ActiveThread(tree.clone());
        let receiver={
        let mut threads=self.threads.lock().map_err(|_|BudgetError::WorkerFailed)?;
        let mut i=0;while i<threads.len(){if threads[i].is_finished(){let _=threads.swap_remove(i).join();}else{i+=1;}}
        if threads.len()>=self.running_limit*4{self.rejected.fetch_add(1,Ordering::Relaxed);return Err(BudgetError::Overloaded);}
        let(sender,receiver)=tokio::sync::oneshot::channel();
        let handle=std::thread::Builder::new().name("caddy-template".into()).stack_size(4<<20).spawn(move||{
            let result=std::panic::catch_unwind(std::panic::AssertUnwindSafe(job));
            if result.is_err(){tree.control.cancel.cancel();}
            let _=sender.send(result.map_err(|_|BudgetError::WorkerFailed));
            drop(active);drop(tree);drop(token);
        }).map_err(|_|BudgetError::WorkerFailed)?;
        threads.push(handle);receiver
        };
        tokio::select!{
            result=receiver=>result.map_err(|_|BudgetError::WorkerFailed)?,
            _=control.cancel.cancelled()=>Err(BudgetError::WorkerFailed),
            _=tokio::time::sleep_until(tokio::time::Instant::from_std(control.deadline()))=>{control.cancel.cancel();Err(BudgetError::WorkerFailed)},
        }
    }
    pub(crate) fn close(&self){self.closed.store(true,Ordering::Release);self.roots.close();self.tasks.close();}
    pub(crate) async fn wait(&self){
        self.tasks.wait().await;
        let threads=self.threads.lock().map(|mut threads|std::mem::take(&mut *threads)).unwrap_or_default();
        // No worker owns a token now. The join only reaps OS thread exit.
        let _=tokio::task::spawn_blocking(move||{for thread in threads{let _=thread.join();}}).await;
    }
    pub(super) fn snapshot(&self)->BudgetSnapshot{BudgetSnapshot{running_limit:self.running_limit,waiting_limit:16,running:self.running_limit.saturating_sub(self.roots.available_permits()),waiting:16-self.waiting.available_permits(),rejected:self.rejected.load(Ordering::Relaxed)}}
}
