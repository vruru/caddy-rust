//! Extra access-log fields and bounded body capture for the log_append handler.
use super::Context;
use crate::{
    http_config::types::LogAppendConfig,
    http_runtime::{Body, BoxError, Bytes, access_log::ExtraFields, full},
    logging::{Field, FieldValue as V},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::BytesMut;
use http::HeaderMap;
use http_body_util::BodyExt;
use hyper::body::{Body as _, Frame, SizeHint};
use serde_json::Value;
use std::{
    collections::HashMap,
    pin::Pin,
    sync::Arc,
    task::{Context as TaskContext, Poll},
};
use tokio::sync::OwnedSemaphorePermit;

const MAX_FIELDS: usize = 128;
const MAX_BODY_BYTES: usize = 64 * 1024;
const MAX_FIELD_BYTES: usize = 128 * 1024;

#[derive(Default)]
pub(super) struct LogFields {
    pub(super) output: ExtraFields,
    pub(super) pending: Vec<Arc<LogAppendConfig>>,
    // Strings already live in the replacer. Keep the original typed values
    // for non-string variables without copying configuration JSON per request.
    variables: HashMap<String, Arc<Value>>,
}

pub(super) fn remember_var(ctx: &mut Context, key: &str, value: &Arc<Value>) {
    if value.is_string() { ctx.typed_vars.remove(key); } else { ctx.typed_vars.insert(key.to_owned(), value.clone()); }
    if ctx.access_start.is_none() {
        return;
    }
    if value.is_string() {
        if let Some(log) = &mut ctx.log_fields {
            log.variables.remove(key);
        }
    } else {
        ctx.log_fields
            .get_or_insert_with(Default::default)
            .variables
            .insert(key.to_owned(), value.clone());
    }
}

pub(super) fn response_body(value: &str) -> bool {
    matches!(
        value,
        "{http.response.body}" | "{http.response.body_base64}"
    )
}

fn request_body(value: &str) -> bool {
    matches!(value, "{http.request.body}" | "{http.request.body_base64}")
}

pub(super) async fn enter(ctx: &mut Context, plan: &Arc<LogAppendConfig>) -> Option<usize> {
    ctx.access_start?;
    let log = ctx.log_fields.get_or_insert_with(Default::default);
    if log.pending.len() + log.output.fields.len() >= MAX_FIELDS {
        ctx.resources.access_capture.record_omitted();
        return None;
    }
    if response_body(&plan.value) {
        let index = log.pending.len();
        log.pending.push(plan.clone());
        return Some(index);
    }
    if plan.early || request_body(&plan.value) {
        append(ctx, plan, None).await;
    }
    if !plan.early {
        ctx.log_fields
            .as_mut()
            .expect("access log state")
            .pending
            .push(plan.clone());
    }
    None
}

pub(super) fn mark(ctx: &Context) -> usize {
    ctx.log_fields.as_ref().map_or(0, |log| log.pending.len())
}

pub(super) async fn unwind(ctx: &mut Context, mark: usize, headers: Option<&HeaderMap>) {
    while self::mark(ctx) > mark {
        let plan = ctx
            .log_fields
            .as_mut()
            .and_then(|log| log.pending.pop())
            .expect("pending log field");
        if !response_body(&plan.value) {
            append(ctx, &plan, headers).await;
        }
    }
}

pub(super) async fn capture_response(
    ctx: &mut Context,
    index: usize,
    headers: &HeaderMap,
    body: &mut Body,
    explicit: bool,
) {
    unwind(ctx, index + 1, Some(headers)).await;
    let Some(plan) = ctx.log_fields.as_mut().and_then(|log| log.pending.pop()) else {
        return;
    };
    if explicit {
        let budget = ctx.resources.access_capture.clone();
        if let Some(bytes) = capture(body, &budget).await {
            push(ctx, &plan.key, body_value(&plan.value, bytes));
        }
    }
}

async fn append(ctx: &mut Context, plan: &LogAppendConfig, headers: Option<&HeaderMap>) {
    if request_body(&plan.value) {
        let budget = ctx.resources.access_capture.clone();
        let bytes = if let Some(request) = &mut ctx.request {
            capture(request.body_mut(), &budget).await
        } else {
            Some(Bytes::new())
        };
        if let Some(bytes) = bytes {
            push(ctx, &plan.key, body_value(&plan.value, bytes));
        }
        return;
    }
    if let Some((value,_temporary)) = lookup(ctx, &plan.value, headers).await {
        push(ctx, &plan.key, value);
    } else {
        ctx.resources.access_capture.record_omitted();
    }
}

fn body_value(placeholder: &str, bytes: Bytes) -> V {
    if placeholder.ends_with("_base64}") {
        V::String(STANDARD.encode(bytes))
    } else {
        V::RawString(bytes.to_vec())
    }
}

fn variable(ctx: &Context, name: &str) -> Option<V> {
    if let Some(value) = ctx
        .log_fields
        .as_ref()
        .and_then(|log| log.variables.get(name))
    {
        return Some(match value.as_ref() {
            Value::Null => V::Null,
            Value::Bool(value) => V::Bool(*value),
            Value::Number(value) => value.as_f64().map_or(V::Null, V::F64),
            other if json_cost(other, 0) <= MAX_FIELD_BYTES => V::Reflected(other.clone()),
            _ => V::Null,
        });
    }
    ctx.values
        .get(&format!("http.vars.{name}"))
        .cloned()
        .map(V::String)
}

fn header_value(headers: &HeaderMap, key: &str) -> V {
    let mut value = Vec::new();
    for (index, field) in headers.get_all(key).iter().enumerate() {
        if index != 0 {
            value.push(b',');
        }
        value.extend_from_slice(field.as_bytes());
    }
    V::RawString(value)
}

async fn lookup(ctx: &mut Context, input: &str, headers: Option<&HeaderMap>) -> Option<(V,Option<OwnedSemaphorePermit>)> {
    // Only the final replacer fallback can run a lazy Map. Typed logging values
    // remain typed, and no Map is touched for a literal or a known primitive.
    let primitive=(|| -> Option<V> {
        if !(input.starts_with('{') && input.ends_with('}') && input.matches('{').count() == 1) {
            return Some(variable(ctx, input).unwrap_or_else(|| V::String(input.to_owned())));
        }
        let name=input.trim_matches(['{','}']);
        if let Some(name)=name.strip_prefix("http.vars.") {
            if let Some(value)=variable(ctx,name){return Some(value)}
        }
        if let Some(name)=name.strip_prefix("http.response.header."){return Some(header_value(headers.unwrap_or(&ctx.immediate),name))}
        if let Some(name)=name.strip_prefix("http.request.header."){
            if name.eq_ignore_ascii_case("host"){return Some(V::String(String::new()))}
            return Some(ctx.request.as_ref().map_or_else(||V::String(String::new()),|request|header_value(request.headers(),name)))
        }
        if name=="http.shutting_down"{return Some(V::Bool(ctx.business.generation().shutting_down()))}
        if let Some(elapsed)=ctx.access_start.map(|start|start.elapsed()){
            match name{
                "http.request.duration"=>return Some(V::Duration(i64::try_from(elapsed.as_nanos()).unwrap_or(i64::MAX))),
                "http.request.duration_ms"=>return Some(V::F64(elapsed.as_secs_f64()*1e3)),_=>{}
            }
        }
        if let Some(key)=name.strip_prefix("http.request.uri.query."){
            let mut joined=String::new();
            if let Some(query)=ctx.request.as_ref().and_then(|request|request.uri().query()){
                for(index,(_,value))in url::form_urlencoded::parse(query.as_bytes()).filter(|(name,_)|name==key).enumerate(){
                    if index>0{joined.push(',')}joined.push_str(&value)
                }
            }
            return Some(V::String(joined))
        }
        None
    })();
    if let Some(value)=primitive{return Some((value,None))}
    let name=input.trim_matches(['{','}']);
    let Some(value)=ctx.lookup_typed_resolved(name).await.ok()? else{return Some((V::Null,None))};
    if value.null{return Some((V::Null,None))}
    // Reserve the copy before allocation. The temporary stays alive until push
    // has acquired the access-log field's own last-owner permit.
    let credit=ctx.resources.access_capture.reserve(value.bytes.len().saturating_add(128))?;
    let value=match std::str::from_utf8(&value.bytes){
        Ok(text) if name=="http.error"=>V::Error(text.to_owned()),
        Ok(text) if matches!(name,"http.error.status_code"|"http.request.port"|"http.request.local.port"|"http.request.remote.port")=>text.parse::<i64>().map_or_else(|_|V::String(text.to_owned()),V::I64),
        Ok(text)=>V::String(text.to_owned()),Err(_)=>V::RawString(value.bytes.to_vec()),
    };
    Some((value,Some(credit)))
}

fn json_cost(value: &Value, depth: usize) -> usize {
    if depth >= 32 {
        return usize::MAX;
    }
    match value {
        Value::String(value) => 64usize.saturating_add(value.len().saturating_mul(2)),
        Value::Object(map) => map.iter().fold(64usize, |cost, (key, value)| {
            cost.saturating_add(key.len() + 32)
                .saturating_add(json_cost(value, depth + 1))
        }),
        Value::Array(array) => array.iter().fold(64usize, |cost, value| {
            cost.saturating_add(json_cost(value, depth + 1))
        }),
        _ => 64,
    }
}

fn push(ctx: &mut Context, key: &str, value: V) {
    let budget = &ctx.resources.access_capture;
    let log = ctx.log_fields.as_mut().expect("access log state");
    if log.output.fields.len() >= MAX_FIELDS {
        budget.record_omitted();
        return;
    }
    let value_cost = match &value {
        V::String(text) | V::Error(text) => text.len(),
        V::RawString(bytes) => bytes.len(),
        V::Reflected(value) => json_cost(value, 0),
        _ => 32,
    };
    let Some(permit) = budget.reserve(key.len().saturating_add(128).saturating_add(value_cost))
    else {
        budget.record_omitted();
        return;
    };
    log.output.fields.push(Field::new(key, value));
    log.output.permits.push(permit);
}

async fn capture(
    body: &mut Body,
    budget: &crate::http_runtime::access_log::CaptureBudget,
) -> Option<Bytes> {
    if body.is_end_stream() {
        return Some(Bytes::new());
    }
    if body.size_hint().lower() > MAX_BODY_BYTES as u64 {
        budget.record_omitted();
        return None;
    }
    let Some(permit) = budget.reserve(MAX_BODY_BYTES) else {
        budget.record_omitted();
        return None;
    };
    let preserve_unknown_size = body.size_hint().exact().is_none();
    let mut inner = std::mem::replace(body, full(Bytes::new()));
    let mut data = BytesMut::new();
    let (tail, complete) = loop {
        match inner.frame().await {
            Some(Ok(frame)) if frame.is_data() => {
                let bytes = frame.data_ref().expect("data frame");
                if data.len().saturating_add(bytes.len()) > MAX_BODY_BYTES {
                    break (Some(Ok(frame)), false);
                }
                data.extend_from_slice(bytes);
            }
            Some(Ok(trailers)) => {
                inner = full(Bytes::new());
                break (Some(Ok(trailers)), true);
            }
            Some(Err(error)) => break (Some(Err(error)), false),
            None => {
                inner = full(Bytes::new());
                break (None, true);
            }
        }
    };
    let data = data.freeze();
    let prefix = (!data.is_empty()).then(|| data.clone());
    let may_have_trailers = tail
        .as_ref()
        .is_some_and(|frame| frame.as_ref().is_ok_and(Frame::is_trailers));
    *body = Replay {
        prefix,
        tail,
        inner,
        preserve_unknown_size: preserve_unknown_size || may_have_trailers,
        _capture: permit,
    }
    .boxed_unsync();
    if !complete {
        budget.record_omitted();
    }
    complete.then_some(data)
}

struct Replay {
    prefix: Option<Bytes>,
    tail: Option<Result<Frame<Bytes>, BoxError>>,
    inner: Body,
    preserve_unknown_size: bool,
    _capture: OwnedSemaphorePermit,
}
impl hyper::body::Body for Replay {
    type Data = Bytes;
    type Error = BoxError;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        if let Some(bytes) = self.prefix.take() {
            return Poll::Ready(Some(Ok(Frame::data(bytes))));
        }
        if let Some(frame) = self.tail.take() {
            return Poll::Ready(Some(frame));
        }
        Pin::new(&mut self.inner).poll_frame(cx)
    }
    fn is_end_stream(&self) -> bool {
        self.prefix.is_none() && self.tail.is_none() && self.inner.is_end_stream()
    }
    fn size_hint(&self) -> SizeHint {
        let prefix = self.prefix.as_ref().map_or(0, Bytes::len);
        let tail = self
            .tail
            .as_ref()
            .and_then(|frame| frame.as_ref().ok())
            .and_then(Frame::data_ref)
            .map_or(0, Bytes::len);
        let bytes = prefix.saturating_add(tail) as u64;
        let inner = self.inner.size_hint();
        let mut hint = SizeHint::new();
        hint.set_lower(inner.lower().saturating_add(bytes));
        if !self.preserve_unknown_size
            && let Some(upper) = inner.upper().and_then(|size| size.checked_add(bytes))
        {
            hint.set_upper(upper);
        }
        hint
    }
}

pub(super) fn trace_fields(ctx:&mut Context,context:&opentelemetry::Context){
 use opentelemetry::trace::TraceContextExt;
 if ctx.access_start.is_none(){return}let span=context.span();let sc=span.span_context();if !sc.is_valid(){return}
 ctx.log_fields.get_or_insert_with(Default::default);
 push(ctx,"traceID",V::String(sc.trace_id().to_string()));push(ctx,"spanID",V::String(sc.span_id().to_string()));
}
