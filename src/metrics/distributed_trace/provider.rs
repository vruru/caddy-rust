//! Generation ownership and independent exporter actors. Requests only enqueue;
//! each actor has a distinct transport so a failed export cannot close another
//! actor's connection epoch. Export workspace is separate from metrics.
use super::{config,processor,export,export_work};
use crate::metrics;
use anyhow::{Result,ensure};
use opentelemetry::{Context,KeyValue,propagation::TextMapCompositePropagator,trace::{TraceContextExt,Tracer,TracerProvider,SpanKind}};
use opentelemetry_sdk::trace::{SdkTracerProvider,SdkTracer};
use std::sync::{Arc,Mutex,atomic::Ordering};
use std::time::Duration;
use tokio_util::{sync::CancellationToken,task::TaskTracker};
const BATCH_WEIGHT:usize=8<<20;
const WORKSPACE:u32=128<<20;
pub(crate) struct Provider{
 pub propagators:TextMapCompositePropagator,
 pub process:Arc<processor::Process>,
 shared:Arc<processor::Shared>,
 sdk:SdkTracerProvider,tracer:SdkTracer,
 lifecycle:Mutex<State>,
 plans:Vec<Arc<export::Plan>>,
 settings:config::Settings,
 metric_process:Arc<metrics::Process>,
 metadata:Arc<metrics::Metadata>,
 cells:Vec<Arc<export_work::ActorCell>>,
 _cell_index:Arc<processor::Credit>,

}
struct State{receiver:Option<export_work::OwnedReceiver>,driver:Option<Arc<Driver>>,stopped:bool}
struct Driver{stop:CancellationToken,tasks:TaskTracker}
impl Drop for Driver{fn drop(&mut self){self.stop.cancel();}}
impl Provider{
 pub fn prepare(metric_process:Arc<metrics::Process>)->Result<Arc<Self>>{
  let settings=config::Settings::read()?;
  let process=metric_process.traces.clone();
  let mandatory=metric_process.pay_generation(1<<20).ok_or_else(||anyhow::anyhow!("trace provider metadata unavailable"))?;
  let metadata=Arc::new(metrics::Metadata::new(mandatory));
  let inputs=export::Inputs::prepare(&settings,&metric_process,&metadata)?;
  let resource=metrics::export::resource();
  let count=if settings.disabled||settings.exporters.is_empty(){1}else{std::thread::available_parallelism().map_or(1,usize::from).clamp(1,4)};
  let retirement=metric_process.trace_retirement()?;
  let receiver_slot=retirement.receiver_slot()?;
  let cell_index=process.metadata(count.checked_mul(std::mem::size_of::<Arc<export_work::ActorCell>>()).and_then(|n|n.checked_add(128)).ok_or_else(||anyhow::anyhow!("trace actor index layout overflow"))?)?;
  let mut cells=Vec::new();cells.try_reserve_exact(count)?;
  for _ in 0..count{cells.push(retirement.register()?);}
  let mut plans=Vec::with_capacity(count);
  for _ in 0..count{plans.push(export::Plan::prepare(&settings,&inputs,metadata.clone(),&resource,&metric_process)?);}
  let(shared,receiver)=processor::Shared::new(process.clone(),settings.queue)?;
  let default=opentelemetry_sdk::trace::Config::default();
  ensure!(default.span_limits.max_attributes_per_span<=65536&&default.span_limits.max_events_per_span<=65536&&default.span_limits.max_links_per_span<=65536,"trace SDK counts exceed native resource boundary");
  let sdk=SdkTracerProvider::builder().with_sampler(processor::AdmittedSampler(default.sampler))
   .with_span_limits(default.span_limits).with_span_processor(processor::Processor(shared.clone())).with_resource(resource).build();
  // Preserve the logical baseline instrumentation scope for existing collector
  // routing; telemetry.sdk.language/version still identify the actual Rust SDK.
  let scope=opentelemetry::InstrumentationScope::builder("go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp").with_version("0.71.0").build();
  let tracer=sdk.tracer_with_scope(scope);
  let propagators=super::propagators::compose(&settings.propagators);
  Ok(Arc::new(Self{propagators,process,shared,sdk,tracer,lifecycle:Mutex::new(State{receiver:Some(receiver_slot.wrap(receiver)),driver:None,stopped:false}),plans,settings,metric_process,metadata,cells,_cell_index:cell_index}))
 }
 pub fn admit(&self)->Option<Arc<processor::Credit>>{
  if self.shared.closed.load(Ordering::Acquire){return None}
  let credit=self.process.admit();if credit.is_none(){self.process.dropped.fetch_add(1,Ordering::Relaxed);}credit
 }
 pub fn start(&self,name:String,attributes:Vec<KeyValue>,parent:&Context,credit:Option<Arc<processor::Credit>>)->Context{
  let parent=parent.with_value(processor::Admission(credit));
  let span=self.tracer.span_builder(name).with_kind(SpanKind::Server).with_attributes(attributes).start_with_context(&self.tracer,&parent);
  parent.with_span(span)
 }
 pub fn discard(&self,context:&Context){self.shared.discard(context.span().span_context().span_id());}
 pub fn activate(&self,logging:Option<&crate::logging::Logging>){
  let Ok(runtime)=tokio::runtime::Handle::try_current()else{return};
  let prepared={
   let mut state=self.lifecycle.lock().unwrap_or_else(|e|e.into_inner());
   if state.stopped||state.driver.is_some(){return}
   let Some(receiver)=state.receiver.take()else{return};
   let stop=CancellationToken::new();let tasks=TaskTracker::new();
   // Keep close+wait nonempty until every admitted worker is registered.
   let activation=tasks.token();
   state.driver=Some(Arc::new(Driver{stop:stop.clone(),tasks:tasks.clone()}));
   (receiver,stop,tasks,activation)
  };
  let(receiver,stop,tasks,activation)=prepared;
  let receiver=Arc::new(tokio::sync::Mutex::new(receiver));
  for(plan,cell)in self.plans.iter().zip(&self.cells){
   let input=receiver.clone();let token=stop.clone();let shared=self.shared.clone();let settings=self.settings.clone();
   let process=self.metric_process.clone();let metadata=self.metadata.clone();let plan=plan.clone();let cell=cell.clone();let group=tasks.clone();
   tasks.spawn_on(async move{worker(input,token,shared,settings,process,metadata,plan,cell,group).await;},&runtime);
  }
  drop(activation);
  if self.settings.unknown_propagators!=0{
   if let(Some(logging),Ok(time))=(logging,crate::logging::Timestamp::now()){
    use crate::logging::{Event,Field,FieldValue,Level,Origin};
    let _=logging.try_emit(Event{origin:Origin::Module{module_id:"http.handlers.tracing".into()},logger:"http.handlers.tracing".into(),level:Level::Warn,message:"unknown tracing propagator entries ignored".into(),time,fields:vec![Field::new("unknown_count",FieldValue::U64(self.settings.unknown_propagators as u64))],caller:None,stacktrace:None});
   }
  }

 }
 pub async fn stop(&self){
  let(pending,driver)={let mut state=self.lifecycle.lock().unwrap_or_else(|e|e.into_inner());state.stopped=true;
   self.shared.closed.store(true,Ordering::Release);(state.receiver.take(),state.driver.clone())};
  drop(pending);
  if let Some(driver)=driver{driver.stop.cancel();driver.tasks.close();driver.tasks.wait().await;}
  else{for plan in &self.plans{plan.shutdown().await;}}
  let _=self.sdk.shutdown();
 }
}

async fn worker(input:Arc<tokio::sync::Mutex<export_work::OwnedReceiver>>,stop:CancellationToken,shared:Arc<processor::Shared>,settings:config::Settings,process:Arc<metrics::Process>,metadata:Arc<metrics::Metadata>,plan:Arc<export::Plan>,cell:Arc<export_work::ActorCell>,group:TaskTracker){
 let mut stopping=None;
 loop{
  if stop.is_cancelled()&&stopping.is_none(){
   stopping=Some(tokio::time::Instant::now()+Duration::from_secs(30));
   if let Some(receiver)=input.lock().await.receiver_mut(){receiver.inner.close();}
  }
  if stopping.is_some_and(|deadline|tokio::time::Instant::now()>=deadline){
   let(count,signal)={let mut input=input.lock().await;input.retire_queue()};drop(signal);
   shared.process.dropped.fetch_add((count+cell.pending_count())as u64,Ordering::Relaxed);break
  }
  let mut batch=cell.worker_batch_guard();
  if cell.attach_token(group.token()).is_err(){break}
  let first=if let Some(item)=cell.promote_pending(){Some(item)}else{
   let next=cell.receive(&input,stopping.is_some());
   let result=if stopping.is_some(){Some(next.await)}else{tokio::select!{biased;_=stop.cancelled()=>None,result=next=>Some(result)}};
   match result{Some(Ok(item))=>item,Some(Err(_))=>{cell.finish_batch().await;batch.disarm();break},None=>{cell.finish_batch().await;batch.disarm();continue}}
  };
  let Some(first)=first else{cell.finish_batch().await;batch.disarm();break};
  if first.weight>BATCH_WEIGHT{shared.process.dropped.fetch_add(1,Ordering::Relaxed);cell.finish_batch().await;batch.disarm();continue}
  let max_count=settings.batch.min(BATCH_WEIGHT/8192).max(1);
  let collect_deadline=tokio::time::Instant::now()+settings.schedule;
  if cell.begin_source(&process.trace_cpu,max_count).await.is_err(){shared.process.dropped.fetch_add(1,Ordering::Relaxed);cell.finish_batch().await;batch.disarm();continue}
  let mut count=1;
  while count<max_count{
   let next=cell.receive(&input,stopping.is_some());
   let result=if stopping.is_some(){Some(next.await)}else{
    tokio::select!{biased;_=stop.cancelled()=>None,result=tokio::time::timeout_at(collect_deadline,next)=>result.ok()}
   };
   let Some(Ok(Some(_)))=result else{break};
   match cell.append_ingress(BATCH_WEIGHT){Ok(true)=>count+=1,Ok(false)|Err(_)=>break}
  }
  let scratch=match process.trace_workspace.clone().try_acquire_many_owned(WORKSPACE){Ok(credit)=>credit,Err(_)=>{shared.process.dropped.fetch_add(count as u64,Ordering::Relaxed);cell.finish_batch().await;batch.disarm();continue}};
  let timer=match process.request_bytes.clone().try_acquire_many_owned(1024){Ok(credit)=>credit,Err(_)=>{shared.process.dropped.fetch_add(count as u64,Ordering::Relaxed);cell.finish_batch().await;batch.disarm();continue}};
  let created=tokio::time::Instant::now();
  let Some(deadline)=created.checked_add(plan.timeout)else{cell.finish_batch().await;batch.disarm();shared.process.errors.fetch_add(1,Ordering::Relaxed);continue};
  let inputs=export_work::ExportInputs{plan:Arc::downgrade(&plan),metadata:metadata.clone(),scratch,timer,output:process.trace_output.clone(),created};
  let start=tokio::time::timeout_at(deadline,cell.begin_export(&process.trace_cpu,inputs)).await;
  let mut ready=matches!(start,Ok(Ok(export_work::Step::Started)));
  if let Ok(Ok(export_work::Step::Console{writer,deadline}))=start{
   if let Ok(serial)=writer.admit_until(deadline).await{
    ready=matches!(tokio::time::timeout_at(deadline,cell.begin_console(&process.trace_cpu,Arc::downgrade(&plan),process.trace_output.clone(),serial)).await,Ok(Ok(export_work::Step::Started)));
   }
  }
  let mut success=false;
  if ready{
   loop{
    match tokio::time::timeout_at(deadline,cell.poll_export(&process.trace_cpu)).await{
     Ok(Ok(export_work::Step::Complete(value)))=>{success=value;break},
     Ok(Ok(export_work::Step::Pending))=>{if !cell.wait_wake(deadline).await{break}},
     _=>break,
    }
   }
  }
  if !success{shared.process.errors.fetch_add(1,Ordering::Relaxed);}
  // CPU input/future receipt only. Independent byte pins must not block the
  // actor's own Plan.shutdown from closing its physical IO below.
  cell.finish_batch().await;batch.disarm();
 }
 plan.shutdown().await;
 cell.retire(true);
}
