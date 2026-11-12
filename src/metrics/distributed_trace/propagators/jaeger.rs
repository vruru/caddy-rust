// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0
use opentelemetry::{Context,propagation::{TextMapPropagator,Injector,Extractor,text_map_propagator::FieldIter},trace::{TraceContextExt,SpanContext,TraceId,SpanId,TraceFlags,TraceState}};
#[derive(Clone,Debug)]pub(crate) struct Jaeger{fields:Vec<String>}
#[derive(Clone,Debug)]struct DebugFlag(bool);
impl Jaeger{pub fn new()->Self{Self{fields:vec!["uber-trace-id".into()]}}}
fn hex_id(text:&str,width:usize)->Option<String>{
 if text.is_empty()||text.len()>width||!text.bytes().all(|c|c.is_ascii_digit()||(b'a'..=b'f').contains(&c)){return None}
 Some(format!("{text:0>width$}"))
}
impl TextMapPropagator for Jaeger{
 fn inject_context(&self,cx:&Context,injector:&mut dyn Injector){
  let span=cx.span();let sc=span.span_context();if !sc.is_valid(){return}
  let flags=if cx.get::<DebugFlag>().is_some_and(|v|v.0){3}else if sc.is_sampled(){1}else{0};
  injector.set("uber-trace-id",format!("{}:{}:0:{flags:x}",sc.trace_id(),sc.span_id()));
 }
 fn extract_with_context(&self,cx:&Context,extractor:&dyn Extractor)->Context{
  let Some(raw)=extractor.get("uber-trace-id")else{return cx.clone()};
  let mut parts=raw.split(':');let(Some(t),Some(s),Some(_),Some(f))=(parts.next(),parts.next(),parts.next(),parts.next())else{return cx.clone()};if parts.next().is_some(){return cx.clone()}
  let trace=if t.is_empty(){TraceId::INVALID}else{let Some(text)=hex_id(t,32)else{return cx.clone()};let Ok(id)=TraceId::from_hex(&text)else{return cx.clone()};if id==TraceId::INVALID{return cx.clone()}id};
  let span=if s.is_empty(){SpanId::INVALID}else{let Some(text)=hex_id(s,16)else{return cx.clone()};let Ok(id)=SpanId::from_hex(&text)else{return cx.clone()};if id==SpanId::INVALID{return cx.clone()}id};
  let flags=if f.is_empty(){0}else{let Ok(flags)=i64::from_str_radix(f,16)else{return cx.clone()};flags};
  let sampled=flags&1==1;let mut result=cx.clone();if sampled&&flags&2==2{result=result.with_value(DebugFlag(true));}
  let sc=SpanContext::new(trace,span,if sampled{TraceFlags::SAMPLED}else{TraceFlags::default()},true,TraceState::default());
  if sc.is_valid(){result.with_remote_span_context(sc)}else{cx.clone()}
 }
 fn fields(&self)->FieldIter<'_>{FieldIter::new(&self.fields)}
}
