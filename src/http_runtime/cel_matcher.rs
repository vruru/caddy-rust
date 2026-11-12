//! Caddy CEL expressions over the same request matchers and body owner as routes.
#[path = "cel_matcher_data.rs"]
mod data;
use super::request::{Context, failure};
use crate::{
    cel_engine::{
        self,
        eval::{self, EvalError, Host, R, V},
    },
    http_config::types::Matcher,
};
use anyhow::{Result, ensure};
use cel::common::{
    ast::{EntryExpr, Expr, IdedExpr, LiteralValue},
    types::{CelBool, CelDouble, CelInt, CelList, CelMap, CelMapKey, CelNull, CelString, Type},
    value::Val,
};
use http::StatusCode;
use serde_json::{Map, Value, json};
use std::{
    collections::HashMap,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::OwnedSemaphorePermit;
const MAX_DATA: usize = 128 << 10;
const PROGRAM_UNIT: usize = 64 << 10;
const COMPILE_RESERVE: usize = (4 << 20) + MAX_DATA;
const DYNAMIC_ENTRIES: usize = 256;

struct Prepared {
    matcher: Matcher,
    _credit: Option<OwnedSemaphorePermit>,
}
struct Entry {
    prepared: Arc<Prepared>,
    used: u64,
}
#[derive(Default)]
struct Cache {
    entries: HashMap<String, Entry>,
    clock: u64,
}
/// Runtime-wide LRU; every expression competes in one eviction domain.
pub(super) struct DynamicCache {
    cache: Mutex<Cache>,
    programs: Arc<tokio::sync::Semaphore>,
}
impl DynamicCache {
    pub(super) fn snapshot(&self) -> (usize, usize) {
        let held = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        (
            held.entries.len(),
            ((16 << 20) / PROGRAM_UNIT - self.programs.available_permits()) * PROGRAM_UNIT,
        )
    }
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self {
            cache: Mutex::new(Cache::default()),
            programs: Arc::new(tokio::sync::Semaphore::new((16 << 20) / PROGRAM_UNIT)),
        })
    }
}
pub(crate) struct Plan {
    compiled: cel_engine::parse::Compiled,
    name: String,
    constants: HashMap<String, Arc<Prepared>>,
}
impl Plan {
    pub(crate) fn prepare(value: &Value, remaining: &mut usize) -> Result<Self> {
        let (source, name) = if let Some(source) = value.as_str() {
            (source, "")
        } else {
            let obj = value
                .as_object()
                .ok_or_else(|| anyhow::anyhow!("expression string or object required"))?;
            ensure!(
                obj.keys().all(|k| matches!(k.as_str(), "expr" | "name")),
                "unknown expression field"
            );
            let source = obj
                .get("expr")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("expression expr required"))?;
            let name = obj
                .get("name")
                .map(|v| {
                    v.as_str()
                        .ok_or_else(|| anyhow::anyhow!("expression name must be string"))
                })
                .transpose()?
                .unwrap_or_default();
            (source, name)
        };
        ensure!(name.len() <= 256, "expression matcher name too long");
        let mut compiled = cel_engine::parse::compile(source, &[]).map_err(anyhow::Error::msg)?;
        mark_const_membership(&compiled.expression, &mut compiled.checked);
        let mut constants = HashMap::new();
        collect_constants(&compiled.expression, name, remaining, &mut constants)?;
        Ok(Self {
            compiled,
            name: name.to_owned(),
            constants,
        })
    }
    async fn matcher(&self, name: &str, raw: Value, ctx: &mut Context) -> Result<Arc<Prepared>> {
        let normalized = data::matcher_data(name, raw, &self.name)?
            .ok_or_else(|| anyhow::anyhow!("unknown CEL matcher"))?;
        let key = cache_key(name, &normalized)?;
        if let Some(matcher) = self.constants.get(&key) {
            return Ok(matcher.clone());
        }
        {
            let mut cache = ctx
                .resources
                .cel_dynamic
                .cache
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            cache.clock = cache.clock.wrapping_add(1);
            let clock = cache.clock;
            if let Some(entry) = cache.entries.get_mut(&key) {
                entry.used = clock;
                return Ok(entry.prepared.clone());
            }
            if cache.entries.len() >= DYNAMIC_ENTRIES {
                evict(&mut cache);
            }
        }
        // Reserve a complete compile allowance before constructing any programs.
        let units = COMPILE_RESERVE.div_ceil(PROGRAM_UNIT);
        let credit = loop {
            if let Ok(credit) = ctx
                .resources
                .cel_dynamic
                .programs
                .clone()
                .try_acquire_many_owned(units as u32)
            {
                break credit;
            }
            let mut cache = ctx
                .resources
                .cel_dynamic
                .cache
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if cache.entries.is_empty() {
                return Err(failure(StatusCode::SERVICE_UNAVAILABLE));
            }
            evict(&mut cache);
        };
        let name_for_key = key.clone();
        let built = ctx
            .resources
            .cel_compile
            .run(move || {
                let mut remaining = 4 << 20;
                let matcher = build_matcher(normalized, &mut remaining)?;
                let used = (4 << 20) - remaining + name_for_key.len() + 1024;
                let mut credit = credit;
                let keep = used.div_ceil(PROGRAM_UNIT).max(1);
                if credit.num_permits() > keep {
                    let excess = credit.num_permits() - keep;
                    drop(credit.split(excess));
                }
                Ok::<_, anyhow::Error>(Arc::new(Prepared {
                    matcher,
                    _credit: Some(credit),
                }))
            })
            .await
            .map_err(|_| failure(StatusCode::SERVICE_UNAVAILABLE))??;
        let mut cache = ctx
            .resources
            .cel_dynamic
            .cache
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        cache.clock = cache.clock.wrapping_add(1);
        let clock = cache.clock;
        if let Some(existing) = cache.entries.get(&key) {
            return Ok(existing.prepared.clone());
        }
        if cache.entries.len() >= DYNAMIC_ENTRIES {
            evict(&mut cache);
        }
        cache.entries.insert(
            key,
            Entry {
                prepared: built.clone(),
                used: clock,
            },
        );
        Ok(built)
    }
    pub(super) async fn matches(&self, ctx: &mut Context) -> Result<bool> {
        let cancel = ctx.drain.clone();
        let mut host = RequestHost {
            plan: self,
            ctx,
            steps: 0,
            bytes: 0,
            error: None,
            started: Instant::now(),
        };
        let value = tokio::select! { biased;
            _ = cancel.cancelled() => return Err(failure(StatusCode::SERVICE_UNAVAILABLE)),
            result = tokio::time::timeout(Duration::from_secs(30), eval::evaluate(&self.compiled.expression, &self.compiled.checked, &mut host)) => result,
        };
        if let Some(error) = host.error {
            return Err(error);
        }
        let value = value
            .map_err(|_| failure(StatusCode::SERVICE_UNAVAILABLE))?
            .map_err(|e| anyhow::anyhow!("CEL evaluation: {}", e.message))?;
        value
            .downcast_ref::<CelBool>()
            .map(|v| *v.inner())
            .ok_or_else(|| anyhow::anyhow!("CEL result must be bool"))
    }
}
fn evict(cache: &mut Cache) {
    if let Some(key) = cache
        .entries
        .iter()
        .min_by_key(|(_, e)| e.used)
        .map(|(k, _)| k.clone())
    {
        cache.entries.remove(&key);
    }
}
fn cache_key(name: &str, value: &Value) -> Result<String> {
    let text = serde_json::to_string(value)?;
    ensure!(text.len() <= MAX_DATA, "CEL matcher data limit");
    Ok(format!("{name}:{text}"))
}
fn build_matcher(value: Value, remaining: &mut usize) -> Result<Matcher> {
    let mut sets = crate::http_config::parse_matcher_sets(Some(&json!([value])), 0, remaining)?;
    ensure!(sets.len() == 1 && sets[0].len() == 1, "CEL matcher shape");
    Ok(sets.remove(0).remove(0))
}
fn collect_constants(
    node: &IdedExpr,
    default_name: &str,
    remaining: &mut usize,
    out: &mut HashMap<String, Arc<Prepared>>,
) -> Result<()> {
    match &node.expr {
        Expr::Call(call) => {
            let (function, data_node) = if call.func_name == "matches" {
                (
                    "path_regexp_request_string",
                    if call.target.is_some() {
                        call.args.first()
                    } else {
                        call.args.get(1)
                    },
                )
            } else {
                (
                    call.func_name.as_str(),
                    if call.args.len() == 2 && is_matcher(&call.func_name) {
                        call.args.get(1)
                    } else {
                        None
                    },
                )
            };
            if let Some(raw) = data_node.and_then(literal_json) {
                let normalized =
                    data::matcher_data(function, raw, default_name)?.expect("known matcher");
                let key = cache_key(function, &normalized)?;
                if !out.contains_key(&key) {
                    let matcher = build_matcher(normalized, remaining)?;
                    out.insert(
                        key,
                        Arc::new(Prepared {
                            matcher,
                            _credit: None,
                        }),
                    );
                }
            }
            if let Some(target) = &call.target {
                collect_constants(target, default_name, remaining, out)?;
            }
            for arg in &call.args {
                collect_constants(arg, default_name, remaining, out)?;
            }
        }
        Expr::List(list) => {
            for e in &list.elements {
                collect_constants(e, default_name, remaining, out)?;
            }
        }
        Expr::Map(map) => {
            for entry in &map.entries {
                if let EntryExpr::MapEntry(e) = &entry.expr {
                    collect_constants(&e.key, default_name, remaining, out)?;
                    collect_constants(&e.value, default_name, remaining, out)?;
                }
            }
        }
        Expr::Select(select) => collect_constants(&select.operand, default_name, remaining, out)?,
        Expr::Comprehension(c) => {
            for e in [
                &c.iter_range,
                &c.accu_init,
                &c.loop_cond,
                &c.loop_step,
                &c.result,
            ] {
                collect_constants(e, default_name, remaining, out)?;
            }
        }
        _ => {}
    }
    Ok(())
}
/// cel-go OptOptimize turns a constant homogeneous primitive membership list
/// into a typed set. Native names cannot be string keys in that optimized set.
fn mark_const_membership(node: &IdedExpr, checked: &mut cel_engine::checker::Checked) {
    match &node.expr {
        Expr::Call(call) => {
            if call.func_name == "@in" && call.args.len() == 2
                && literal_json(&call.args[1]).is_some_and(|v| v.as_array().is_some_and(|v| v.iter().all(Value::is_string)))
                && let Some(resolved) = checked.calls.get_mut(&node.id) {
                    resolved.name = "@caddy_const_in".into();
                }
            if let Some(target) = &call.target {mark_const_membership(target,checked)}
            for arg in &call.args {mark_const_membership(arg,checked)}
        }
        Expr::List(list) => for item in &list.elements {mark_const_membership(item,checked)},
        Expr::Map(map) => for entry in &map.entries {if let EntryExpr::MapEntry(e)=&entry.expr {mark_const_membership(&e.key,checked);mark_const_membership(&e.value,checked)}},
        Expr::Select(s) => mark_const_membership(&s.operand,checked),
        Expr::Comprehension(c) => for n in [&c.iter_range,&c.accu_init,&c.loop_cond,&c.loop_step,&c.result] {mark_const_membership(n,checked)},
        _ => {}
    }
}
fn literal_json(node: &IdedExpr) -> Option<Value> {
    Some(match &node.expr {
        Expr::Literal(LiteralValue::String(s)) => Value::String(s.inner().to_owned()),
        Expr::List(list) => Value::Array(
            list.elements
                .iter()
                .map(literal_json)
                .collect::<Option<_>>()?,
        ),
        Expr::Map(map) => {
            let mut out = Map::new();
            for entry in &map.entries {
                let EntryExpr::MapEntry(e) = &entry.expr else {
                    return None;
                };
                let key = literal_json(&e.key)?.as_str()?.to_owned();
                out.insert(key, literal_json(&e.value)?);
            }
            Value::Object(out)
        }
        Expr::Call(call) if call.func_name == "string" && call.args.len() == 1 => literal_json(&call.args[0])?,
        Expr::Call(call) if call.func_name == "_+_" && call.args.len() == 2 => {
            let a = literal_json(&call.args[0])?;
            let b = literal_json(&call.args[1])?;
            Value::String(format!("{}{}", a.as_str()?, b.as_str()?))
        }
        _ => return None,
    })
}
fn is_matcher(name: &str) -> bool {
    matches!(
        name,
        "host_match_request_list"
            | "path_match_request_list"
            | "method_request_list"
            | "remote_ip_match_request_list"
            | "client_ip_match_request_list"
            | "protocol_request_string"
            | "path_regexp_request_string"
            | "path_regexp_request_string_string"
            | "header_regexp_request_string_string"
            | "header_regexp_request_string_string_string"
            | "vars_regexp_request_string_string"
            | "vars_regexp_request_string_string_string"
            | "url_pattern_request_string"
            | "url_pattern_request_string_string"
            | "query_matcher_request_map"
            | "header_matcher_request_map"
            | "vars_matcher_request_map"
            | "file"
            | "file_request_map"
    )
}
#[derive(Clone, Debug)]
struct RequestValue(usize);
static REQUEST_TYPE: Type = Type::new_struct_type("http.Request");
impl cel::common::value::StaticVal for RequestValue {}
impl Val for RequestValue {
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }
    fn equals(&self, other: &dyn Val) -> bool {
        other
            .downcast_ref::<RequestValue>()
            .is_some_and(|other| self.0 == other.0)
    }
    fn get_type(&self) -> &Type {
        &REQUEST_TYPE
    }
    fn cel_type() -> &'static Type {
        &REQUEST_TYPE
    }
    fn clone_as_boxed<'v>(&self) -> Box<dyn Val + 'v>
    where
        Self: 'v,
    {
        Box::new(self.clone())
    }
}
struct RequestHost<'a> {
    plan: &'a Plan,
    ctx: &'a mut Context,
    steps: u64,
    bytes: usize,
    error: Option<anyhow::Error>,
    started: Instant,
}
impl RequestHost<'_> {
    fn fail(&mut self, error: anyhow::Error) -> EvalError {
        self.error = Some(error);
        EvalError::fatal("request matcher failed")
    }
    async fn placeholder(&mut self, name: &str) -> R {
        if !self.ctx.values.contains_key(name) {
            if let Some(field)=name.strip_prefix("http.request.header.") {
                if field.eq_ignore_ascii_case("host"){return Ok(eval::string(""))}
                let mut count=0usize;let mut length=0usize;
                for value in self.ctx.req().headers().get_all(field).iter(){length=length.saturating_add(value.as_bytes().len()).saturating_add(usize::from(count>0));count+=1;}
                self.tick(length as u64+count as u64,length.saturating_mul(2).saturating_add(256))?;
                let mut out=Vec::with_capacity(length);
                for (i,value)in self.ctx.req().headers().get_all(field).iter().enumerate(){if i>0{out.push(b',')}out.extend_from_slice(value.as_bytes());}
                return Ok(super::cel_native_string::value(bytes::Bytes::from(out)))
            }
            if let Some(key)=name.strip_prefix("http.request.uri.query.") {
                let len=self.ctx.req().uri().query().map_or(0,str::len);
                self.tick((len as u64).saturating_mul(6).saturating_add(1),len.saturating_mul(4).saturating_add(512))?;
                return Ok(super::cel_native_string::value(super::cel_native_string::query_value(self.ctx.req().uri().query().unwrap_or_default().as_bytes(),key.as_bytes())))
            }
        }
        if matches!(name, "http.request.body" | "http.request.body_base64") {
            let bytes = super::cel_body::capture(self.ctx)
                .await
                .map_err(|e| self.fail(e))?;
            self.tick(
                0,
                bytes
                    .len()
                    .saturating_mul(if name.ends_with("_base64") { 2 } else { 3 })
                    .saturating_add(128),
            )?;
            let value = if name.ends_with("_base64") {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD.encode(&bytes)
            } else {
                return Ok(super::cel_native_string::value(bytes));
            };
            return Ok(Arc::new(CelString::from(value)));
        }
        let projected = if super::placeholder_value::is_global(name) {
            let name = name.to_owned();
            self.ctx
                .resources
                .metadata
                .run(move || super::placeholder_value::global(&name))
                .await
                .map_err(|_| self.fail(failure(StatusCode::SERVICE_UNAVAILABLE)))?
        } else {
            if let Some(value) = self.ctx.values.get(name) {
                let len = value.len();
                self.tick(0, len + 128)?;
            }
            super::placeholder_value::request(self.ctx, name)
        };
        self.project(projected).await
    }
}
impl RequestHost<'_> {
    async fn project(&mut self, projected: Option<super::placeholder_value::Value>) -> R {
        use super::placeholder_value::Value as P;
        Ok(match projected.unwrap_or(P::Null) {
            P::Null => Arc::new(CelNull),
            P::Bool(v) => eval::boolean(v),
            P::Int(v) => Arc::new(CelInt::from(v)),
            P::Double(v) => Arc::new(CelDouble::from(v)),
            P::String(value) => {
                self.tick(0, value.len() + 128)?;
                Arc::new(CelString::from(value))
            }
            P::Json(value) => return json_to_cel(self, &value, 0),
            P::Error(error) | P::Unavailable(error) => return Err(EvalError::new(error)),
            P::Time(time) => {
                self.tick(8, 1024)?;
                let value = chrono::DateTime::from_timestamp(time.unix_seconds, time.nanoseconds)
                    .ok_or_else(|| EvalError::new("invalid timestamp"))?
                    .to_rfc3339_opts(chrono::SecondsFormat::Nanos, true);
                return cel_engine::dispatch::builtin(
                    &self.plan.compiled.env,
                    "timestamp",
                    false,
                    &[eval::string(&value)],
                );
            }
            P::Duration(nanos) => {
                self.tick(8, 1024)?;
                Arc::new(cel::common::types::CelDuration::from(chrono::Duration::nanoseconds(nanos)))
            }
            P::TlsClient { cache, field } => {
                let facts=cache.get(&self.ctx.resources).await.map_err(EvalError::new)?;
                return super::cel_native_cert::project(self,facts.as_ref(),&field);
            }
        })
    }
}

impl Host for RequestHost<'_> {
    fn make_map(&mut self,values:Vec<V>)->R {super::cel_native_map::make(self,values)}
    fn iteration_items(&mut self,value:&V,two_vars:bool)->std::result::Result<eval::Items,EvalError>{super::cel_native_map::items(self,value,two_vars)}
    fn observe_value(&mut self, value:V)->R {super::cel_native_cert::observe(value)}
    fn tick(&mut self, steps: u64, bytes: usize) -> std::result::Result<(), EvalError> {
        self.steps = self
            .steps
            .checked_add(steps)
            .ok_or_else(|| EvalError::fatal("CEL cost overflow"))?;
        self.bytes = self
            .bytes
            .checked_add(bytes)
            .ok_or_else(|| EvalError::fatal("CEL allocation overflow"))?;
        if self.steps > 1_000_000
            || self.bytes > 32 << 20
            || self.started.elapsed() > Duration::from_secs(30)
            || self.ctx.drain.is_cancelled()
        {
            return Err(EvalError::fatal("CEL evaluation budget exceeded"));
        }
        Ok(())
    }
    fn invoke<'a>(
        &'a mut self,
        name: &'a str,
        member: bool,
        args: Vec<V>,
    ) -> Pin<Box<dyn Future<Output = R> + Send + 'a>> {
        let name = if matches!(name, "in" | "_in_") { "@in" } else { name };
        if name == "ph" || name == "matches" || is_matcher(name) {
            // Determine the exact boxed state-machine layout without constructing it.
            // Reserve before Box::pin; cancellation keeps the allocation in this call.
            fn output_size<F, T>(_: F) -> usize where F: FnOnce() -> T {
                std::mem::size_of::<T>()
            }
            let bytes = {
                let receiver = &mut *self;
                output_size(move || receiver.invoke_async(name, member, Vec::new()))
            };
            if let Err(error) = self.tick(0, bytes.saturating_add(64)) {
                return Box::pin(std::future::ready(Err(error)));
            }
            Box::pin(self.invoke_async(name, member, args))
        } else {
            if let Err(error) = self.tick(0, std::mem::size_of::<std::future::Ready<R>>() + 64) {
                return Box::pin(std::future::ready(Err(error)));
            }
            let result = self.invoke_builtin(name, member, args);
            Box::pin(std::future::ready(result))
        }
    }
}
impl RequestHost<'_> {
    async fn invoke_async(&mut self, name: &str, _member: bool, args: Vec<V>) -> R {
            if name == "ph" {
                if args.len() != 2 || args[0].get_type() != &REQUEST_TYPE {
                    return Err(EvalError::new("invalid CEL request"));
                }
                let key = args[1]
                    .downcast_ref::<CelString>()
                    .ok_or_else(|| EvalError::new("placeholder key must be string"))?
                    .inner()
                    .to_owned();
                return self.placeholder(&key).await;
            }
            if name == "matches" {
                let input_value=args.first().ok_or_else(||EvalError::new("matches input must be string"))?;
                let input=super::cel_native_string::bytes(input_value.as_ref()).ok_or_else(||EvalError::new("matches input must be string"))?;
                let pattern = args
                    .get(1)
                    .and_then(|v| v.downcast_ref::<CelString>())
                    .ok_or_else(|| EvalError::new("matches pattern must be string"))?
                    .inner();
                if args.len() != 2 {
                    return Err(EvalError::new("matches expects two strings"));
                }
                self.tick(
                    input.len() as u64 + 1,
                    input
                        .len()
                        .saturating_mul(8)
                        .saturating_add(pattern.len().saturating_mul(2)),
                )?;
                let input = input.to_vec();
                let pattern = pattern.to_owned();
                let compiled = self
                    .plan
                    .matcher(
                        "path_regexp_request_string",
                        Value::String(pattern),
                        self.ctx,
                    )
                    .await
                    .map_err(|e| self.fail(e))?;
                let Matcher::PathRegex(plan) = &compiled.matcher else {
                    return Err(EvalError::fatal("invalid CEL regex plan"));
                };
                let regex = plan.regex.clone();
                self.tick(0, regex.search_memory())?;
                let matched = self
                    .ctx
                    .resources
                    .request_regexp
                    .run(move || {
                        let scratch = regex
                            .search_memory()
                            .saturating_add(input.len().saturating_mul(7))
                            .saturating_add(4096);
                        regex.is_match_bytes(
                            &input,
                            &crate::go_regexp::ReplaceBudget::new(
                                scratch,
                                Some(Instant::now() + Duration::from_millis(150)),
                            ),
                        )
                    })
                    .await
                    .map_err(|_| self.fail(failure(StatusCode::SERVICE_UNAVAILABLE)))?
                    .map_err(|_| self.fail(failure(StatusCode::SERVICE_UNAVAILABLE)))?;
                return Ok(eval::boolean(matched));
            }
            if is_matcher(name) {
                if args.len() != 2 || args[0].get_type() != &REQUEST_TYPE {
                    return Err(EvalError::new("invalid CEL request"));
                }
                validate_matcher_data(args[1].as_ref(), 0, &mut MAX_DATA.clone(), &mut 1024usize)?;
                let raw = cel_to_json(self, args[1].as_ref(), 0)?;
                let prepared = self
                    .plan
                    .matcher(name, raw, self.ctx)
                    .await
                    .map_err(|e| self.fail(e))?;
                let result = super::request::matches(&prepared.matcher, self.ctx)
                    .await
                    .map_err(|e| self.fail(e))?;
                return Ok(eval::boolean(result));
            }
        Err(EvalError::fatal("invalid CEL asynchronous call"))
    }
    fn invoke_builtin(&mut self, name: &str, member: bool, args: Vec<V>) -> R {
            if name == "@ident" {
                let name = args
                    .first()
                    .and_then(|v| v.downcast_ref::<CelString>())
                    .ok_or_else(|| EvalError::new("CEL identifier"))?
                    .inner();
                return if name == "req" {
                    Ok(Arc::new(RequestValue(self.ctx as *mut Context as usize)) as V)
                } else {
                    cel_engine::dispatch::type_constant(name)
                        .ok_or_else(|| EvalError::new("unknown identifier"))
                };
            }
            let plan=self.plan;
            if let Some(value)=super::cel_native_collections::operation(self,&plan.compiled.env,name,member,&args){return value}
            if name=="format"&&member&&let Some(value)=super::cel_native_format::operation(self,&plan.compiled.env,&args){return value}
            if let Some(value)=super::cel_native_map::operation(self,name,&args) {return value.and_then(super::cel_native_cert::observe)}
            let plan=self.plan;
            if let Some(value)=super::cel_native_string::operation(self,&plan.compiled.env,name,member,&args) { return value }
            if let Some(value)=super::cel_native_cert::operation(self,name,&args) { return value }
            let name=if name=="@caddy_const_in" {"@in"} else {name};
            let mut duration_prepaid=false;
            if name=="duration" && !member && args.len()==1 && let Some(text)=args[0].downcast_ref::<CelString>() {
                let length=text.inner().len();
                self.tick(length as u64+1,length.checked_mul(8).and_then(|n|n.checked_add(1024)).ok_or_else(||EvalError::fatal("CEL duration cost overflow"))?)?;
                match crate::duration::parse_cel_nanos(text.inner()) {
                    Ok(nanos)=>return Ok(Arc::new(cel::common::types::CelDuration::from(chrono::Duration::nanoseconds(nanos)))),
                    Err(error) if !crate::duration::cel_extension_syntax(text.inner())=>return Err(EvalError::new(error)),
                    Err(_)=>{
                        self.tick((length as u64).saturating_mul(2).saturating_add(1),length.checked_mul(24).ok_or_else(||EvalError::fatal("CEL duration cost overflow"))?)?;
                        duration_prepaid=true;
                    }
                }
            }
            if !duration_prepaid && cel_engine::builtin_cost::preflight(self,name,member,&args)? == cel_engine::builtin_cost::Pre::Defer {
                for arg in &args {eval::charge_clone(self,arg.as_ref())?;}
            }
            let result=cel_engine::dispatch::builtin(&self.plan.compiled.env, name, member, &args)?;
            super::cel_native_cert::observe(result)
    }
}
fn cel_to_json(
    host: &mut impl Host,
    value: &dyn Val,
    depth: usize,
) -> std::result::Result<Value, EvalError> {
    if depth > 16 {
        return Err(EvalError::fatal("CEL matcher value depth"));
    }
    host.tick(1, 128)?;
    if let Some(s) = value.downcast_ref::<CelString>() {
        host.tick(0, s.inner().len())?;
        if s.inner().len() > MAX_DATA {
            return Err(EvalError::fatal("CEL matcher string limit"));
        }
        return Ok(Value::String(s.inner().to_owned()));
    }
    if let Some(list) = value.downcast_ref::<CelList>() {
        if list.inner().len() > 1024 {
            return Err(EvalError::fatal("CEL matcher list limit"));
        }
        return Ok(Value::Array(
            list.inner()
                .iter()
                .map(|v| cel_to_json(host, v.as_ref(), depth + 1))
                .collect::<std::result::Result<_, _>>()?,
        ));
    }
    if let Some(map) = value.downcast_ref::<CelMap>() {
        if map.inner().len() > 1024 {
            return Err(EvalError::fatal("CEL matcher map limit"));
        }
        let mut out = Map::new();
        for (k, v) in map.inner() {
            let key = k
                .inner()
                .downcast_ref::<CelString>()
                .ok_or_else(|| EvalError::new("CEL matcher map key must be string"))?
                .inner();
            host.tick(0, key.len())?;
            out.insert(key.to_owned(), cel_to_json(host, v.as_ref(), depth + 1)?);
        }
        return Ok(Value::Object(out));
    }
    Err(EvalError::new(
        "CEL matcher data must contain strings, lists or maps",
    ))
}
fn json_to_cel(host: &mut impl Host, value: &Value, depth: usize) -> R {
    json_to_cel_box(host, value, depth).map(Arc::from)
}
fn json_to_cel_box(
    host: &mut impl Host,
    value: &Value,
    depth: usize,
) -> std::result::Result<Box<dyn Val>, EvalError> {
    if depth > 64 {
        return Err(EvalError::fatal("CEL placeholder nesting limit"));
    }
    host.tick(1, 128)?;
    Ok(match value {
        Value::Null => Box::new(CelNull),
        Value::Bool(v) => Box::new(CelBool::from(*v)),
        // JSON interface{} values use Go's float64, including integer lexemes.
        Value::Number(v) => Box::new(CelDouble::from(
            v.as_f64()
                .ok_or_else(|| EvalError::new("invalid JSON number"))?,
        )),
        Value::String(v) => {
            host.tick(0, v.len())?;
            Box::new(CelString::from(v.clone()))
        }
        Value::Array(values) => {
            host.tick(
                0,
                values
                    .len()
                    .saturating_mul(std::mem::size_of::<Box<dyn Val>>())
                    .saturating_add(128),
            )?;
            let mut list = Vec::with_capacity(values.len());
            for value in values {
                list.push(json_to_cel_box(host, value, depth + 1)?);
            }
            Box::new(CelList::from(list))
        }
        Value::Object(values) => {
            let slots = values.len().saturating_mul(3).max(4);
            host.tick(
                0,
                slots
                    .saturating_mul(std::mem::size_of::<(CelMapKey, Box<dyn Val>)>() + 1)
                    .saturating_add(128),
            )?;
            let mut map = HashMap::with_capacity(values.len());
            for (key, value) in values {
                host.tick(0, key.len().saturating_add(128))?;
                let key =
                    CelMapKey::try_from(Box::new(CelString::from(key.clone())) as Box<dyn Val>)
                        .map_err(|_| EvalError::new("CEL map key"))?;
                map.insert(key, json_to_cel_box(host, value, depth + 1)?);
            }
            Box::new(CelMap::from(map))
        }
    })
}

fn validate_matcher_data(
    value: &dyn Val,
    depth: usize,
    remaining: &mut usize,
    nodes: &mut usize,
) -> std::result::Result<(), EvalError> {
    if depth > 16 || *nodes == 0 {
        return Err(EvalError::fatal("CEL matcher data limit"));
    }
    *nodes -= 1;
    let mut charge = |bytes| {
        *remaining = remaining
            .checked_sub(bytes)
            .ok_or_else(|| EvalError::fatal("CEL matcher data byte limit"))?;
        Ok::<_, EvalError>(())
    };
    if let Some(s) = value.downcast_ref::<CelString>() {
        return charge(s.inner().len());
    }
    if let Some(list) = value.downcast_ref::<CelList>() {
        charge(list.inner().len().saturating_mul(8))?;
        for item in list.inner() {
            validate_matcher_data(item.as_ref(), depth + 1, remaining, nodes)?;
        }
        return Ok(());
    }
    if let Some(map) = value.downcast_ref::<CelMap>() {
        charge(map.inner().len().saturating_mul(16))?;
        for (key, item) in map.inner() {
            validate_matcher_data(key.inner(), depth + 1, remaining, nodes)?;
            validate_matcher_data(item.as_ref(), depth + 1, remaining, nodes)?;
        }
        return Ok(());
    }
    Err(EvalError::new("invalid Caddy CEL matcher data type"))
}
