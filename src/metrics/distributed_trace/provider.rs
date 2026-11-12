//! Generation ownership and independent exporter actors. Requests only enqueue;
//! each actor has a distinct transport so a failed export cannot close another
//! actor's connection epoch. Export workspace is separate from metrics.
use super::{config,processor,export};
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

}
struct State{receiver:Option<processor::Receiver>,driver:Option<Arc<Driver>>,stopped:bool}
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
  let mut plans=Vec::with_capacity(count);
  for _ in 0..count{plans.push(export::Plan::prepare(&settings,&inputs,metadata.clone(),&resource)?);}
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
  Ok(Arc::new(Self{propagators,process,shared,sdk,tracer,lifecycle:Mutex::new(State{receiver:Some(receiver),driver:None,stopped:false}),plans,settings,metric_process,metadata}))
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
  let mut state=self.lifecycle.lock().unwrap_or_else(|e|e.into_inner());
  if state.stopped||state.driver.is_some(){return}
  let Some(receiver)=state.receiver.take()else{return};
  let stop=CancellationToken::new();let tasks=TaskTracker::new();
  let receiver=Arc::new(tokio::sync::Mutex::new(receiver));
  for plan in &self.plans{
   let input=receiver.clone();let token=stop.clone();let shared=self.shared.clone();let settings=self.settings.clone();
   let process=self.metric_process.clone();let metadata=self.metadata.clone();let plan=plan.clone();
   tasks.spawn(async move{worker(input,token,shared,settings,process,metadata,plan).await;});
  }
  state.driver=Some(Arc::new(Driver{stop,tasks}));
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

async fn worker(input:Arc<tokio::sync::Mutex<processor::Receiver>>,stop:CancellationToken,shared:Arc<processor::Shared>,settings:config::Settings,process:Arc<metrics::Process>,metadata:Arc<metrics::Metadata>,plan:Arc<export::Plan>){
 let mut pending=None;let mut stopping=None;
 loop{
  if stop.is_cancelled()&&stopping.is_none(){
   stopping=Some(tokio::time::Instant::now()+Duration::from_secs(30));input.lock().await.inner.close();
  }
  let expired=stopping.is_some_and(|deadline|tokio::time::Instant::now()>=deadline);
  if expired{if let Some(item)=pending.take(){drop(item);shared.process.dropped.fetch_add(1,Ordering::Relaxed);}let mut input=input.lock().await;while let Ok(item)=input.inner.try_recv(){drop(item);shared.process.dropped.fetch_add(1,Ordering::Relaxed);}break}
  let first=if let Some(item)=pending.take(){Some(item)}else{
   let mut input=input.lock().await;
   if stopping.is_some(){input.inner.try_recv().ok()}
   else{tokio::select!{biased;_=stop.cancelled()=>{drop(input);continue},item=input.inner.recv()=>item}}
  };
  let Some(first)=first else{break};
  if first.credit.held()>BATCH_WEIGHT{shared.process.dropped.fetch_add(1,Ordering::Relaxed);continue}
  let max_count=settings.batch.min(BATCH_WEIGHT/8192).max(1);
  let batch_metadata=match shared.process.metadata(max_count*(std::mem::size_of::<processor::Item>()*2+128)+4096){Ok(credit)=>credit,Err(_)=>{shared.process.dropped.fetch_add(1,Ordering::Relaxed);continue}};
  let mut weight=first.credit.held();let mut items=Vec::with_capacity(max_count);items.push(first);
  let deadline=tokio::time::Instant::now()+settings.schedule;
  while items.len()<max_count{
   let item=if stopping.is_some(){input.lock().await.inner.try_recv().ok()}else{
    let next=async{input.lock().await.inner.recv().await};
    tokio::select!{biased;_=stop.cancelled()=>None,item=tokio::time::timeout_at(deadline,next)=>item.ok().flatten()}
   };
   let Some(item)=item else{break};
   if weight+item.credit.held()>BATCH_WEIGHT{pending=Some(item);break}
   weight+=item.credit.held();items.push(item);
  }
  let scratch=match process.trace_workspace.clone().try_acquire_many_owned(WORKSPACE){Ok(credit)=>credit,Err(_)=>{shared.process.dropped.fetch_add(items.len()as u64,Ordering::Relaxed);continue}};
  let timer=match process.request_bytes.clone().try_acquire_many_owned(1024){Ok(credit)=>credit,Err(_)=>{shared.process.dropped.fetch_add(items.len()as u64,Ordering::Relaxed);continue}};
  let credit=Arc::new(metrics::transport::Credit{_scratch:scratch,_metadata:metadata.clone(),created:tokio::time::Instant::now(),done:CancellationToken::new(),deadline_started:Default::default(),timer_credit:Mutex::new(Some(timer))});
  let console_serial=if let Some(writer)=plan.console(){
   match writer.admit_until(credit.created+plan.timeout).await{Ok(serial)=>Some(serial),Err(_)=>{shared.process.errors.fetch_add(1,Ordering::Relaxed);continue}}
  }else{None};
  let plan2=plan.clone();let process2=process.clone();let handle=tokio::runtime::Handle::current();let count=items.len();
  let result=process.trace_cpu.run(move||{
   let _batch_metadata=batch_metadata;
   let mut data=Vec::with_capacity(count);let mut parents=Vec::with_capacity(count);let mut children=Vec::with_capacity(count);let mut owners=Vec::with_capacity(count);
   for item in items{data.push(item.span);parents.push(item.parent);children.push(item.children);owners.push(item.credit);}
   let _owners=owners;
   if let Some(writer)=plan2.console(){
    let serial=console_serial.ok_or_else(||anyhow::anyhow!("trace console owner missing"))?;let output=process2.trace_output.clone().try_acquire_many_owned(64<<20)?;
    let bytes=super::console::encode(&data,&parents,&children,plan2.resource())?;
    handle.block_on(writer.send(metrics::console_writer::Batch{bytes,output,credit,serial},plan2.timeout))?;
   }else{handle.block_on(async{tokio::time::timeout(plan2.timeout,plan2.export(data,credit)).await??;Ok::<_,anyhow::Error>(())})?;}
   Ok::<_,anyhow::Error>(())
  }).await;
  if !matches!(result,Ok(Ok(()))){shared.process.errors.fetch_add(1,Ordering::Relaxed);}
 }
 plan.shutdown().await;
}
