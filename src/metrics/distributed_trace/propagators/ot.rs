// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0
use opentelemetry::{Context,propagation::{TextMapPropagator,Injector,Extractor,text_map_propagator::FieldIter},trace::{TraceContextExt,SpanContext,TraceFlags,TraceState}};
#[derive(Clone,Debug)]pub(crate) struct Ot{fields:Vec<String>}
impl Ot{pub fn new()->Self{Self{fields:vec!["ot-tracer-traceid".into(),"ot-tracer-spanid".into(),"ot-tracer-sampled".into()]}}}
impl TextMapPropagator for Ot{
 fn inject_context(&self,cx:&Context,injector:&mut dyn Injector){
  let span=cx.span();let sc=span.span_context();if !sc.is_valid(){return}
  let trace=sc.trace_id().to_string();injector.set("ot-tracer-traceid",trace[16..].into());injector.set("ot-tracer-spanid",sc.span_id().to_string());injector.set("ot-tracer-sampled",if sc.is_sampled(){"true"}else{"false"}.into());
  super::baggage::inject_ot(cx,injector);
 }
 fn extract_with_context(&self,cx:&Context,extractor:&dyn Extractor)->Context{
  let sample=extractor.get("ot-tracer-sampled").unwrap_or_default();let flags=match sample.to_ascii_lowercase().as_str(){""|"0"|"false"=>TraceFlags::default(),"1"|"true"=>TraceFlags::SAMPLED,_=>return cx.clone()};
  let raw=extractor.get("ot-tracer-traceid").unwrap_or_default();let trace=if raw.len()==16{format!("0000000000000000{raw}")}else{raw.into()};let Some(trace)=super::b3::parse_trace_id(&trace)else{return cx.clone()};
  let Some(span)=super::b3::parse_span_id(extractor.get("ot-tracer-spanid").unwrap_or_default())else{return cx.clone()};
  let result=super::baggage::extract_ot(cx,extractor);
  result.with_remote_span_context(SpanContext::new(trace,span,flags,true,TraceState::default()))
 }
 fn fields(&self)->FieldIter<'_>{FieldIter::new(&self.fields)}
}
