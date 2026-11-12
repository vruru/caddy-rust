// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0
use opentelemetry::{Context,propagation::{TextMapPropagator,Injector,Extractor,text_map_propagator::FieldIter},trace::{TraceContextExt,SpanContext,TraceId,SpanId,TraceFlags,TraceState}};
#[derive(Clone,Debug)]pub(crate) struct Xray{fields:Vec<String>}
impl Xray{pub fn new()->Self{Self{fields:vec!["X-Amzn-Trace-Id".into()]}}}
impl TextMapPropagator for Xray{
 fn inject_context(&self,cx:&Context,injector:&mut dyn Injector){
  let span=cx.span();let sc=span.span_context();if !sc.is_valid(){return}
  let trace=sc.trace_id().to_string();let sample=if sc.is_sampled(){1}else{0};
  injector.set("X-Amzn-Trace-Id",format!("Root=1-{}-{};Parent={};Sampled={sample}",&trace[..8],&trace[8..],sc.span_id()));
 }
 fn extract_with_context(&self,cx:&Context,extractor:&dyn Extractor)->Context{
  let Some(raw)=extractor.get("X-Amzn-Trace-Id")else{return cx.clone()};
  let(mut trace,mut span,mut flags)=(TraceId::INVALID,SpanId::INVALID,TraceFlags::default());let mut rest=raw;
  while !rest.is_empty(){
   let part=if let Some((part,next))=rest.split_once(';'){rest=next;part}else{let part=rest.trim();rest="";part};
   let Some((_,value))=part.split_once('=')else{return cx.clone()};
   if part.starts_with("Root"){
    let b=value.as_bytes();if b.len()!=35||b[0]!=b'1'||b[1]!=b'-'||b[10]!=b'-'||!value.is_ascii(){return cx.clone()}
    let text=format!("{}{}",&value[2..10],&value[11..]);let Some(id)=super::b3::parse_trace_id(&text)else{return cx.clone()};trace=id;
   }else if part.starts_with("Parent"){let Some(id)=super::b3::parse_span_id(value)else{return cx.clone()};span=id;
   }else if part.starts_with("Sampled"){flags=if value=="1"{TraceFlags::SAMPLED}else{TraceFlags::default()};}
  }
  let sc=SpanContext::new(trace,span,flags,true,TraceState::default());if sc.is_valid(){cx.with_remote_span_context(sc)}else{cx.clone()}
 }
 fn fields(&self)->FieldIter<'_>{FieldIter::new(&self.fields)}
}
