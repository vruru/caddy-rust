// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

use std::time::SystemTime;
use anyhow::{anyhow, Result};
use opentelemetry_sdk::{trace::{SpanData, SpanEvents, SpanLinks}, Resource};
use opentelemetry::trace::Status;
use opentelemetry::trace::{SpanContext, SpanKind};
use opentelemetry::Value;
use opentelemetry::Array;
use opentelemetry::KeyValue;
use opentelemetry::InstrumentationScope;
use serde_json::json;
use serde_json::Value as JsonValue;

/// Maximum size of the output buffer in bytes (64 MiB).
const MAX_OUTPUT_SIZE: usize = 64 * 1024 * 1024;


/// Encodes a slice of SpanData and Resource into a Vec<u8> containing
/// one JSON SpanStub per line (NDJSON).
struct Output(Vec<u8>);
impl std::io::Write for Output{
 fn write(&mut self,bytes:&[u8])->std::io::Result<usize>{
  let end=self.0.len().checked_add(bytes.len()).filter(|n|*n<=MAX_OUTPUT_SIZE).ok_or_else(||std::io::Error::other("trace console output limit exceeded"))?;
  if end>self.0.capacity(){let cap=end.max(self.0.capacity().saturating_mul(2)).min(MAX_OUTPUT_SIZE);self.0.try_reserve_exact(cap-self.0.len()).map_err(std::io::Error::other)?;}
  self.0.extend_from_slice(bytes);Ok(bytes.len())
 }
 fn flush(&mut self)->std::io::Result<()>{Ok(())}
}
pub(super) fn encode(data:&[SpanData],parents:&[SpanContext],children:&[u64],resource:&Resource)->Result<Vec<u8>>{
 anyhow::ensure!(data.len()==parents.len()&&data.len()==children.len(),"trace console metadata length mismatch");
 let mut out=Output(Vec::new());
 for (index,span)in data.iter().enumerate(){let value=encode_span(span,&parents[index],children[index],resource)?;serde_json::to_writer(&mut out,&value)?;std::io::Write::write_all(&mut out,b"\n")?;}
 Ok(out.0)
}

fn encode_span(span: &SpanData,parent:&SpanContext,children:u64, resource: &Resource) -> Result<JsonValue> {
    let sc = encode_span_context(&span.span_context);
    let parent = encode_span_context(parent);
    let kind = encode_span_kind(span.span_kind.clone());
    let start = encode_time(span.start_time)?;
    let end = encode_time(span.end_time)?;
    let attrs = encode_attributes(&span.attributes)?;
    let events = encode_events(&span.events)?;
    let links = encode_links(&span.links)?;
    let status = encode_status(&span.status);
    let scope = encode_scope(&span.instrumentation_scope)?;
    let res_attrs = JsonValue::Array(resource.iter().map(|(key,value)|Ok(json!({"Key":key.as_str(),"Value":encode_value(value)?}))).collect::<Result<Vec<_>>>()?);

    // Go fieldNames schema exact
    let obj = json!({
        "Name": span.name.as_ref(),
        "SpanContext": sc,
        "Parent": parent,
        "SpanKind": kind,
        "StartTime": start,
        "EndTime": end,
        "Attributes": attrs,
        "Events": events,
        "Links": links,
        "Status": status,
        "DroppedAttributes": span.dropped_attributes_count,
        "DroppedEvents": span.events.dropped_count,
        "DroppedLinks": span.links.dropped_count,
        "ChildSpanCount": children,
        "Resource": res_attrs,
        "InstrumentationScope": scope,
        "InstrumentationLibrary": scope.clone()
    });

    Ok(obj)
}

fn encode_span_context(ctx: &SpanContext) -> JsonValue {
    let trace_id = ctx.trace_id();
    let span_id = ctx.span_id();
    let flags = ctx.trace_flags();
    let remote = ctx.is_remote();
    let trace_state = ctx.trace_state();

    json!({
        "TraceID": format!("{:032x}", trace_id),
        "SpanID": format!("{:016x}", span_id),
        "TraceFlags": format!("{:02x}", flags.to_u8()),
        "TraceState": trace_state.header(),
        "Remote": remote
    })
}

fn encode_span_kind(kind: SpanKind) -> i64 {
    match kind {
        SpanKind::Internal => 1,
        SpanKind::Server => 2,
        SpanKind::Client => 3,
        SpanKind::Producer => 4,
        SpanKind::Consumer => 5,
    }
}

fn encode_time(t: SystemTime) -> Result<String> {
    let dur = t
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| anyhow!("Time before epoch"))?;
    let secs = dur.as_secs() as i64;
    let nanos = dur.subsec_nanos();
    // RFC3339Nano UTC with nanofraction trimmed
    // Manual formatting to avoid chrono dependency assumptions
    let dt = chrono::DateTime::<chrono::Utc>::from_timestamp(secs, nanos)
        .ok_or_else(|| anyhow!("Invalid timestamp"))?
        .to_rfc3339_opts(chrono::SecondsFormat::Nanos, true);
    let dt=if let Some(dot)=dt.find('.'){let end=dt.len()-1;let trimmed=dt[dot+1..end].trim_end_matches('0');if trimmed.is_empty(){format!("{}Z",&dt[..dot])}else{format!("{}.{}Z",&dt[..dot],trimmed)}}else{dt};
    Ok(dt)
}

fn encode_attributes(attrs: &[KeyValue]) -> Result<JsonValue> {
    let count = attrs.len();
    let mut arr = Vec::with_capacity(count);
    for kv in attrs.iter() {
        arr.push(json!({
            "Key": kv.key.as_str(),
            "Value": encode_value(&kv.value)?
        }));
    }
    Ok(JsonValue::Array(arr))
}

fn encode_value(val: &Value) -> Result<JsonValue> {
    match val {
        Value::Bool(b) => Ok(json!({"Type": "BOOL", "Value": b})),
        Value::I64(i) => Ok(json!({"Type": "INT64", "Value": i})),
        Value::F64(f) => { anyhow::ensure!(f.is_finite(), "non-finite trace floating-point attribute"); Ok(json!({"Type": "FLOAT64", "Value": f})) },
        Value::String(s) => Ok(json!({"Type": "STRING", "Value": s.as_ref()})),
        Value::Array(arr) => match arr {
            Array::Bool(v) => Ok(json!({"Type": "BOOLSLICE", "Value": v})),
            Array::I64(v) => Ok(json!({"Type": "INT64SLICE", "Value": v})),
            Array::F64(v) => { anyhow::ensure!(v.iter().all(|f|f.is_finite()), "non-finite trace floating-point array attribute"); Ok(json!({"Type": "FLOAT64SLICE", "Value": v})) },
            Array::String(v) => {
                let strs: Vec<&str> = v.iter().map(|s| s.as_ref()).collect();
                Ok(json!({"Type": "STRINGSLICE", "Value": strs}))
            }
            _ => Err(anyhow!("Unsupported array variant")),
        },
        _ => Err(anyhow!("Unsupported Value variant")),
    }
}

fn encode_events(events: &SpanEvents) -> Result<JsonValue> {
    if events.events.is_empty() {
        return Ok(JsonValue::Null);
    }
    let count = events.events.len();
    let mut arr = Vec::with_capacity(count);
    for ev in events.events.iter() {
        let ev_attrs = encode_attributes(&ev.attributes)?;
        let ev_time = encode_time(ev.timestamp)?;
        arr.push(json!({
            "Name": ev.name.as_ref(),
            "Attributes": ev_attrs,
            "Time": ev_time,
            "DroppedAttributeCount": ev.dropped_attributes_count
        }));
    }
    Ok(JsonValue::Array(arr))
}

fn encode_links(links: &SpanLinks) -> Result<JsonValue> {
    if links.links.is_empty() {
        return Ok(JsonValue::Null);
    }
    let count = links.links.len();
    let mut arr = Vec::with_capacity(count);
    for link in links.links.iter() {
        let link_sc = encode_span_context(&link.span_context);
        let link_attrs = encode_attributes(&link.attributes)?;
        arr.push(json!({
            "SpanContext": link_sc,
            "Attributes": link_attrs,
            "DroppedAttributeCount": link.dropped_attributes_count
        }));
    }
    Ok(JsonValue::Array(arr))
}

fn encode_status(status:&Status)->JsonValue{
 let(code,description)=match status{Status::Unset=>("Unset",""),Status::Ok=>("Ok",""),Status::Error{description}=>("Error",description.as_ref())};
 json!({"Code":code,"Description":description})
}
fn encode_scope(scope:&InstrumentationScope)->Result<JsonValue>{
 let values=scope.attributes().map(|kv|Ok(json!({"Key":kv.key.as_str(),"Value":encode_value(&kv.value)?}))).collect::<Result<Vec<_>>>()?;
 let attrs=if values.is_empty(){JsonValue::Null}else{JsonValue::Array(values)};
 Ok(json!({"Name":scope.name(),"Version":scope.version().unwrap_or(""),"SchemaURL":scope.schema_url().unwrap_or(""),"Attributes":attrs}))
}
