//! SDK callbacks only transfer concrete, prepaid owners. Exporting happens in
//! the generation's tracked asynchronous driver, never on a request callback.
use opentelemetry::{Context,KeyValue,trace::{Link,Span as _,SpanKind,TraceId,TraceContextExt}};
use opentelemetry_sdk::{error::{OTelSdkError,OTelSdkResult},trace::{ShouldSample,SamplingResult,SamplingDecision,Span,SpanData,SpanProcessor}};
use std::{collections::BTreeMap,sync::{Arc,Mutex,atomic::{AtomicBool,AtomicU64,AtomicUsize,Ordering}},time::Duration};
use tokio::sync::{Semaphore,OwnedSemaphorePermit,mpsc};
const BYTES:usize=128<<20;const SLOTS:usize=4096;
#[derive(Debug)]pub(crate) struct Process {bytes:Arc<Semaphore>,slots:Arc<Semaphore>,pub dropped:AtomicU64,pub errors:AtomicU64}
impl Process {
 pub fn new()->Arc<Self>{Arc::new(Self{bytes:Arc::new(Semaphore::new(BYTES)),slots:Arc::new(Semaphore::new(SLOTS)),dropped:AtomicU64::new(0),errors:AtomicU64::new(0)})}
 pub fn admit(self:&Arc<Self>)->Option<Arc<Credit>>{
  let slot=self.slots.clone().try_acquire_owned().ok()?;
  let fixed=self.bytes.clone().try_acquire_many_owned(8192).ok()?;fixed.forget();
  Some(Arc::new(Credit{process:self.clone(),held:AtomicUsize::new(8192),_slot:Some(slot)}))
 }
 pub fn metadata(self:&Arc<Self>,bytes:usize)->anyhow::Result<Arc<Credit>>{
  let count=u32::try_from(bytes)?;let permit=self.bytes.clone().try_acquire_many_owned(count)?;permit.forget();
  Ok(Arc::new(Credit{process:self.clone(),held:AtomicUsize::new(bytes),_slot:None}))
 }
 pub fn used(&self)->usize{BYTES-self.bytes.available_permits()}
 pub fn retained_spans(&self)->usize{SLOTS-self.slots.available_permits()}
}
#[derive(Debug)]pub(crate) struct Credit{process:Arc<Process>,held:AtomicUsize,_slot:Option<OwnedSemaphorePermit>}
impl Credit {
 pub fn charge(&self,bytes:usize)->anyhow::Result<()> {
  let count=u32::try_from(bytes).map_err(|_|anyhow::anyhow!("trace allocation exceeds quota"))?;
  let permit=self.process.bytes.clone().try_acquire_many_owned(count).map_err(|_|anyhow::anyhow!("trace allocation quota exhausted"))?;
  permit.forget();self.held.fetch_add(bytes,Ordering::Relaxed);Ok(())
 }
 pub fn held(&self)->usize{self.held.load(Ordering::Acquire)}
}
impl Drop for Credit{fn drop(&mut self){self.process.bytes.add_permits(self.held.load(Ordering::Relaxed));}}
#[derive(Clone,Debug)]pub(crate) struct Admission(pub Option<Arc<Credit>>);
pub(crate) struct Item{pub span:SpanData,pub credit:Arc<Credit>,pub children:u64,pub parent:opentelemetry::trace::SpanContext}
#[derive(Debug)]struct Live{credit:Arc<Credit>,children:u64,parent:opentelemetry::trace::SpanContext}
impl std::fmt::Debug for Item{fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{f.write_str("PrepaidTraceItem")}}
pub(crate) struct Receiver{pub inner:mpsc::Receiver<Item>,_metadata:Arc<Credit>}
#[derive(Debug)]pub(crate) struct Shared{
 pub process:Arc<Process>,live:Mutex<BTreeMap<[u8;8],Live>>,sender:mpsc::Sender<Item>,pub closed:AtomicBool,
 _metadata:Arc<Credit>,
}
impl Shared {
 pub fn new(process:Arc<Process>,queue:usize)->anyhow::Result<(Arc<Self>,Receiver)>{
  let bytes=queue.checked_mul(std::mem::size_of::<Item>()+64).and_then(|n|n.checked_add(4096)).ok_or_else(||anyhow::anyhow!("trace queue capacity overflow"))?;
  let metadata=process.metadata(bytes)?;let(sender,receiver)=mpsc::channel(queue);
  Ok((Arc::new(Self{process,live:Mutex::new(BTreeMap::new()),sender,closed:AtomicBool::new(false),_metadata:metadata.clone()}),Receiver{inner:receiver,_metadata:metadata}))
 }
 pub fn discard(&self,id:opentelemetry::trace::SpanId){
  // Drop recording under metadata pressure, rather than exporting a false
  // short tunnel duration. The actual observation still retains its credit.
  let removed=self.live.lock().unwrap_or_else(|e|e.into_inner()).remove(&id.to_bytes());
  if removed.is_some(){self.process.dropped.fetch_add(1,Ordering::Relaxed);}drop(removed);
 }
 pub fn queued(&self)->usize{self.sender.max_capacity()-self.sender.capacity()}
}
#[derive(Clone,Debug)]pub(crate) struct Processor(pub Arc<Shared>);
impl SpanProcessor for Processor {
 fn on_start(&self,span:&mut Span,parent:&Context){
  if self.0.closed.load(Ordering::Acquire){return}
  if let Some(credit)=parent.get::<Admission>().and_then(|a|a.0.clone()){
   // The slot, B-tree node and fixed SDK span/container metadata are prepaid.
   let old={let mut live=self.0.live.lock().unwrap_or_else(|e|e.into_inner());
    let parent_span=parent.span();let parent_sc=parent_span.span_context();
    if !parent_sc.is_remote(){if let Some(parent)=live.get_mut(&parent_sc.span_id().to_bytes()){parent.children=parent.children.saturating_add(1);}}
    live.insert(span.span_context().span_id().to_bytes(),Live{credit,children:0,parent:parent_sc.clone()})
   };drop(old);
  }
 }
 fn on_end(&self,span:SpanData){
  let credit=self.0.live.lock().unwrap_or_else(|e|e.into_inner()).remove(&span.span_context.span_id().to_bytes());
  let Some(Live{credit,children,parent})=credit else{return};
  if self.0.closed.load(Ordering::Acquire){return}
  if self.0.sender.try_send(Item{span,credit,children,parent}).is_err(){self.0.process.dropped.fetch_add(1,Ordering::Relaxed);}
 }
 fn force_flush(&self)->OTelSdkResult{
  // Public runtime cleanup uses the asynchronous driver fence. Never claim a
  // synchronous SDK callback flushed a queue it has not actually drained.
  Err(OTelSdkError::InternalFailure("trace driver flush fence required".into()))
 }
 fn shutdown_with_timeout(&self,_:Duration)->OTelSdkResult{self.0.closed.store(true,Ordering::Release);Ok(())}
}
#[derive(Clone,Debug)]pub(crate) struct AdmittedSampler(pub Box<dyn ShouldSample>);
impl ShouldSample for AdmittedSampler{
 fn should_sample(&self,parent:Option<&Context>,trace_id:TraceId,name:&str,kind:&SpanKind,attributes:&[KeyValue],links:&[Link])->SamplingResult{
  let mut result=self.0.should_sample(parent,trace_id,name,kind,attributes,links);
  if !parent.and_then(|p|p.get::<Admission>()).is_some_and(|a|a.0.is_some()){
   result.decision=SamplingDecision::Drop;result.attributes.clear();
  }
  result
 }
}
