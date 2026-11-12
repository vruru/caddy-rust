//! Generation-owned, synchronous-in-flow Caddy event propagation.
//! Independent emissions run concurrently; each event awaits its handlers in order.
use serde_json::Value as Json;
use std::{
    any::Any,
    collections::{BTreeMap, HashMap},
    future::Future,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;
/// Native event metadata. Opaque objects retain their native identity; their
/// external allocations are outside the dispatcher's metadata byte allowance.
#[derive(Clone)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Uint(u64),
    Float(f64),
    Str(String),
    Time(SystemTime),
    /// Signed Go time.Duration nanoseconds.
    Duration(i64),
    Json(Arc<Json>),
    Bytes(Arc<[u8]>),
    Strings(Arc<[String]>),
    Opaque(Arc<dyn Any + Send + Sync>),
    /// A native identity with an explicit bounded serialization for diagnostics.
    Native {
        value: Arc<dyn Any + Send + Sync>,
        json: Arc<Json>,
    },
    Event(Arc<Event>),
    Data(Arc<SharedData>),
}
/// Metadata shared with the originating emitter and subsequent handlers.
pub type EventData = BTreeMap<String, Value>;
/// A shared metadata view with the same checked update contract as its event.
/// Replacer consumers cannot obtain an unbounded mutable map or hold its lock
/// across an asynchronous callback.
pub struct SharedData {
    inner: Mutex<EventData>,
    limits: Limits,
    nil: AtomicBool,
}
impl SharedData {
    pub fn get(&self, key: &str) -> Option<Value> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(key)
            .cloned()
    }
    pub fn with_data<T>(&self, update: impl FnOnce(&mut EventData) -> T) -> Result<T, Reject> {
        let mut held = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let mut candidate = held.clone();
        let result = update(&mut candidate);
        validate_data(&candidate, &self.limits)?;
        if !candidate.is_empty() {
            self.nil.store(false, Ordering::Release);
        }
        *held = candidate;
        Ok(result)
    }
}
/// A stable event identity and mutable metadata.
pub struct Event {
    pub id: String,
    pub time: SystemTime,
    pub name: String,
    pub origin: String,
    dispatch_name: String,
    data: Arc<SharedData>,
    aborted: AtomicBool,
    random_ok: bool,
    debug_data: Mutex<Option<Arc<Json>>>,
}
impl Event {
    fn new(name: &str, origin: &str, data: EventData, nil: bool, limits: &Limits) -> Self {
        let mut bytes = [0u8; 16];
        let random_ok = rustls::crypto::ring::default_provider()
            .secure_random
            .fill(&mut bytes)
            .is_ok();
        bytes[6] = (bytes[6] & 15) | 64;
        bytes[8] = (bytes[8] & 63) | 128;
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let id = format!(
            "{}-{}-{}-{}-{}",
            &hex[..8],
            &hex[8..12],
            &hex[12..16],
            &hex[16..20],
            &hex[20..]
        );
        Self {
            id,
            time: SystemTime::now(),
            name: name
                .chars()
                .map(|c| c.to_lowercase().next().unwrap_or(c))
                .collect(),
            dispatch_name: name.to_owned(),
            origin: origin.to_owned(),
            data: Arc::new(SharedData {
                inner: Mutex::new(data),
                limits: limits.clone(),
                nil: AtomicBool::new(nil),
            }),
            aborted: AtomicBool::new(false),
            random_ok,
            debug_data: Mutex::new(None),
        }
    }
    /// Export a CloudEvents 1.0 object. Metadata is read at export time; if a
    /// native value cannot be JSON encoded, Go omits the complete data member.
    pub fn cloud_event(&self) -> Json {
        let mut out = serde_json::Map::new();
        out.insert("id".into(), Json::String(self.id.clone()));
        out.insert(
            "source".into(),
            Json::String(if self.origin.is_empty() {
                "caddy".into()
            } else {
                self.origin.clone()
            }),
        );
        out.insert("specversion".into(), Json::String("1.0".into()));
        out.insert("type".into(), Json::String(self.name.clone()));
        out.insert("time".into(), time_json(self.time).unwrap_or(Json::Null));
        out.insert(
            "datacontenttype".into(),
            Json::String("application/json".into()),
        );
        let data = self.data.inner.lock().unwrap_or_else(|e| e.into_inner());
        if self.data.nil.load(Ordering::Acquire) {
            out.insert("data".into(), Json::Null);
        } else if let Some(data) = data
            .iter()
            .map(|(k, v)| cloud_json(v).map(|v| (k.clone(), v)))
            .collect::<Option<serde_json::Map<_, _>>>()
        {
            out.insert("data".into(), Json::Object(data));
        }
        Json::Object(out)
    }
    /// Apply a synchronous metadata update atomically after validating its size.
    /// The closure must not call back into this event or await.
    pub fn with_data<T>(&self, update: impl FnOnce(&mut EventData) -> T) -> Result<T, Reject> {
        self.data.with_data(update)
    }
    /// Read one metadata value while retaining its native type.
    pub fn get(&self, key: &str) -> Option<Value> {
        self.data.get(key)
    }
    /// Whether an aborting handler stopped this event.
    pub fn is_aborted(&self) -> bool {
        self.aborted.load(Ordering::Acquire)
    }
    /// Resolve the event-scoped typed replacer values.
    pub fn placeholder(self: &Arc<Self>, key: &str) -> Option<Value> {
        Some(match key {
            "event" => Value::Event(self.clone()),
            "event.id" => Value::Str(self.id.clone()),
            "event.name" => Value::Str(self.name.clone()),
            "event.time" => Value::Time(self.time),
            "event.time_unix" => Value::Int(
                self.time
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis()
                    .min(i64::MAX as u128) as i64,
            ),
            "event.module" => Value::Str(self.origin.clone()),
            "event.data" => Value::Data(self.data.clone()),
            _ => {
                return key
                    .strip_prefix("event.data.")
                    .and_then(|key| self.get(key));
            }
        })
    }
}
/// Handler result; ordinary failures allow propagation to continue.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HandlerError {
    Aborted(String),
    Other(String),
}
/// An asynchronous callback awaited as part of the emitter's own flow.
pub trait Handler: Send + Sync {
    /// JSON fields exposed by this native module for Caddy's invocation log.
    fn diagnostic(&self) -> Json {
        Json::Object(Default::default())
    }
    fn handle<'a>(
        &'a self,
        context: &'a EmitContext,
        event: &'a Event,
    ) -> Pin<Box<dyn Future<Output = Result<(), HandlerError>> + Send + 'a>>;
}
/// Per-emission cancellation; cancelling it stops waiting and later handlers.
#[derive(Clone, Default)]
pub struct EmitContext {
    pub cancel: CancellationToken,
}
/// Factory receives the inline module configuration with `handler` removed.
pub type Factory = Arc<dyn Fn(&Json) -> Result<Arc<dyn Handler>, String> + Send + Sync>;
/// Explicit native extension registry; no event-handler modules are built into
/// the pinned Caddy distribution, so this registry starts empty.
#[derive(Default)]
pub struct HandlerRegistry {
    factories: Mutex<HashMap<String, Factory>>,
}
impl HandlerRegistry {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn register(&self, name: &str, factory: Factory) -> Result<(), String> {
        if name.is_empty() || name.len() > 1024 {
            return Err("invalid event handler name".into());
        }
        let mut held = self.factories.lock().unwrap_or_else(|e| e.into_inner());
        if held.contains_key(name) {
            return Err("event handler already registered".into());
        }
        held.insert(name.to_owned(), factory);
        Ok(())
    }
    fn build(&self, raw: &Json) -> Result<Arc<dyn Handler>, String> {
        let obj = raw.as_object().ok_or("event handler must be object")?;
        let name = obj
            .get("handler")
            .and_then(Json::as_str)
            .ok_or("event handler name required")?;
        let factory = self
            .factories
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(name)
            .cloned()
            .ok_or_else(|| format!("unregistered events.handlers.{name}"))?;
        let mut config = obj.clone();
        config.remove("handler");
        factory(&Json::Object(config))
    }
}
/// Explicit admission failures are returned to the emitter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reject {
    Overloaded,
    QueueFull,
    DataTooLarge,
    HandlerLimit,
    Recursion,
    InvalidIdentity,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Status {
    Completed,
    Aborted,
    Cancelled,
    Rejected(Reject),
}
pub struct Emitted {
    pub event: Arc<Event>,
    pub status: Status,
    pub errors: Vec<String>,
}
/// Safety bounds, separate from worker-thread parallelism.
#[derive(Clone)]
pub struct Limits {
    pub max_inflight: usize,
    pub max_queue: usize,
    pub queue_wait: Duration,
    pub max_depth: usize,
    pub max_data_bytes: usize,
    pub max_data_keys: usize,
    pub max_slots: usize,
    pub max_handlers: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_inflight: 128,
            max_queue: 256,
            queue_wait: Duration::from_secs(2),
            max_depth: 8,
            max_data_bytes: 1 << 20,
            max_data_keys: 1024,
            max_slots: 4096,
            max_handlers: 8192,
        }
    }
}
#[derive(Clone, Copy, Debug)]
pub struct Snapshot {
    pub rejected: u64,
    pub handler_errors: u64,
    pub running: usize,
    pub waiting: usize,
}
type Index = HashMap<String, HashMap<String, Vec<Arc<dyn Handler>>>>;
struct Subscription {
    events: Vec<String>,
    modules: Vec<String>,
    handlers: Vec<Arc<dyn Handler>>,
}
struct State {
    started: bool,
    index: Arc<Index>,
    configured: Vec<Subscription>,
}
/// One app per configuration generation. Existing emitters retain their Arc
/// through publication, rollback and completion. `stop` follows Caddy's no-op.
pub struct EventsApp {
    id: u64,
    state: Mutex<State>,
    limits: Limits,
    running: Arc<Semaphore>,
    waiting: Arc<Semaphore>,
    rejected: AtomicU64,
    errors: AtomicU64,
    debug: AtomicBool,
    logging: Mutex<Option<Arc<crate::logging::Logging>>>,
}
static IDS: AtomicU64 = AtomicU64::new(1);
tokio::task_local! { static ANCESTRY: Vec<(u64, usize)>; }
impl EventsApp {
    fn log_event(
        &self,
        event: &Event,
        level: crate::logging::Level,
        message: &str,
        error: Option<&str>,
        subscribed_to: Option<&str>,
        handler: Option<&dyn Handler>,
    ) {
        use crate::logging::{Event as LogEvent, Field, FieldValue, Origin};
        let logging = self
            .logging
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let Some(logging) = logging.filter(|l| l.module_enabled("events", "events", level)) else {
            return;
        };
        let Ok(mut record) = LogEvent::new(
            Origin::Module {
                module_id: "events".into(),
            },
            "events",
            level,
            message,
        ) else {
            return;
        };
        record.fields.extend([
            Field::new(
                "name",
                FieldValue::String(event.dispatch_name.clone().into()),
            ),
            Field::new("id", FieldValue::String(event.id.clone().into())),
            Field::new("origin", FieldValue::String(event.origin.clone().into())),
        ]);
        {
            let mut cache = event.debug_data.lock().unwrap_or_else(|e| e.into_inner());
            let json = cache
                .get_or_insert_with(|| {
                    let data = event.data.inner.lock().unwrap_or_else(|e| e.into_inner());
                    Arc::new(if event.data.nil.load(Ordering::Acquire) {
                        Json::Null
                    } else {
                        Json::Object(
                            data.iter()
                                .map(|(k, v)| (k.clone(), diagnostic_json(v)))
                                .collect(),
                        )
                    })
                })
                .clone();
            record.fields.push(Field::new(
                "data",
                FieldValue::Reflected(json.as_ref().clone()),
            ));
        }
        if let Some(handler) = handler {
            record.fields.push(Field::new(
                "handler",
                FieldValue::Reflected(handler.diagnostic()),
            ));
        }
        if let Some(key) = subscribed_to {
            record
                .fields
                .push(Field::new("subscribed_to", FieldValue::String(key.into())));
        }
        if message == "handler error" {
            record
                .fields
                .push(Field::new("aborted", FieldValue::Bool(event.is_aborted())));
        }
        if let Some(error) = error {
            record.fields.push(Field::new(
                "error",
                FieldValue::String(error.chars().take(4096).collect::<String>().into()),
            ));
        }
        let _ = logging.try_emit(record);
    }
    /// Prepare real configured native callbacks without publishing subscriptions.
    pub fn prepare(
        raw: &Json,
        registry: &HandlerRegistry,
        limits: Limits,
    ) -> Result<Arc<Self>, String> {
        if limits.max_inflight == 0
            || limits.max_inflight > Semaphore::MAX_PERMITS
            || limits.max_queue > Semaphore::MAX_PERMITS
            || limits.queue_wait.is_zero()
            || limits.max_depth == 0
            || limits.max_data_bytes == 0
        {
            return Err("invalid event limits".into());
        }
        let obj = raw.as_object().ok_or("events app must be object")?;
        if obj.keys().any(|k| k != "subscriptions") {
            return Err("unknown events app field".into());
        }
        let mut configured = Vec::new();
        if let Some(raw) = obj.get("subscriptions").filter(|v| !v.is_null()) {
            let subs = raw.as_array().ok_or("event subscriptions must be array")?;
            if subs.len() > limits.max_slots {
                return Err("event subscription limit".into());
            }
            for raw in subs {
                let sub = raw.as_object().ok_or("event subscription must be object")?;
                if sub
                    .keys()
                    .any(|k| !matches!(k.as_str(), "events" | "modules" | "handlers"))
                {
                    return Err("unknown event subscription field".into());
                }
                let events = names(sub.get("events"))?;
                let modules = names(sub.get("modules"))?;
                let handlers = match sub.get("handlers").filter(|v| !v.is_null()) {
                    None => Vec::new(),
                    Some(raw) => {
                        let raw_handlers = raw.as_array().ok_or("event handlers array required")?;
                        if raw_handlers.is_empty() || raw_handlers.len() > limits.max_handlers {
                            return Err("event handlers required/limit".into());
                        }
                        raw_handlers
                            .iter()
                            .map(|raw| registry.build(raw))
                            .collect::<Result<Vec<_>, _>>()?
                    }
                };
                configured.push(Subscription {
                    events,
                    modules,
                    handlers,
                });
            }
        }
        // Validate the complete pending expansion before creating the app.
        let mut proposed = Index::new();
        for sub in &configured {
            append(&mut proposed, sub, &limits)?;
        }
        let running = Arc::new(Semaphore::new(limits.max_inflight));
        let waiting = Arc::new(Semaphore::new(limits.max_queue));
        Ok(Arc::new(Self {
            id: IDS.fetch_add(1, Ordering::Relaxed),
            state: Mutex::new(State {
                started: false,
                index: Arc::new(Index::new()),
                configured,
            }),
            limits,
            running,
            waiting,
            rejected: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            debug: AtomicBool::new(false),
            logging: Mutex::new(None),
        }))
    }
    /// Add a native provision-time subscriber; this closes atomically at start.
    pub fn subscribe(
        &self,
        events: &[&str],
        modules: &[&str],
        handler: Arc<dyn Handler>,
    ) -> Result<(), String> {
        let sub = Subscription {
            events: if events.is_empty() {
                vec![String::new()]
            } else {
                events.iter().map(|s| (*s).to_owned()).collect()
            },
            modules: if modules.is_empty() {
                vec![String::new()]
            } else {
                modules.iter().map(|s| (*s).to_owned()).collect()
            },
            handlers: vec![handler],
        };
        let mut held = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if held.started {
            return Err("events already started; new subscriptions closed".into());
        }
        let mut candidate = (*held.index).clone();
        append(&mut candidate, &sub, &self.limits)?;
        let mut complete = candidate.clone();
        for sub in &held.configured {
            append(&mut complete, sub, &self.limits)?;
        }
        held.index = Arc::new(candidate);
        Ok(())
    }
    /// Append configured subscriptions then freeze; failure keeps the old index.
    pub fn start(&self) -> Result<(), String> {
        let mut held = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if held.started {
            return Err("events already started".into());
        }
        let mut candidate = (*held.index).clone();
        for sub in &held.configured {
            append(&mut candidate, sub, &self.limits)?;
        }
        held.index = Arc::new(candidate);
        held.configured.clear();
        held.started = true;
        Ok(())
    }
    pub fn stop(&self) {}
    pub fn should_emit(&self, name: &str) -> bool {
        let held = self.state.lock().unwrap_or_else(|e| e.into_inner());
        held.index.contains_key(name)
            || held.index.contains_key("")
            || self.debug.load(Ordering::Relaxed)
            || self
                .logging
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .as_ref()
                .is_some_and(|log| {
                    log.module_enabled("events", "events", crate::logging::Level::Debug)
                })
    }
    pub(crate) fn set_logging(&self, logging: Arc<crate::logging::Logging>) {
        *self.logging.lock().unwrap_or_else(|e| e.into_inner()) = Some(logging);
    }
    pub fn set_debug(&self, debug: bool) {
        self.debug.store(debug, Ordering::Relaxed);
    }
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            rejected: self.rejected.load(Ordering::Relaxed),
            handler_errors: self.errors.load(Ordering::Relaxed),
            running: self.limits.max_inflight - self.running.available_permits(),
            waiting: self.limits.max_queue - self.waiting.available_permits(),
        }
    }
    /// Await each matching handler with DOM-like namespace propagation. No app
    /// lock is held while waiting for admission or for user callbacks.
    pub async fn emit(
        &self,
        cx: EmitContext,
        name: &str,
        origin: &str,
        data: EventData,
    ) -> Emitted {
        self.emit_optional(cx, name, origin, Some(data)).await
    }
    /// A nil Go map is distinct from an initialized empty map in JSON export.
    pub async fn emit_optional(
        &self,
        cx: EmitContext,
        name: &str,
        origin: &str,
        data: Option<EventData>,
    ) -> Emitted {
        let nil = data.is_none();
        let data = data.unwrap_or_default();
        let invalid = !identity_valid(name) || !identity_valid(origin);
        let validation = validate_data(&data, &self.limits);
        let event = Arc::new(Event::new(name, origin, data, nil, &self.limits));
        if !event.random_ok {
            return self.reject(event, Reject::Overloaded);
        }
        if invalid {
            return self.reject(event, Reject::InvalidIdentity);
        }
        if let Err(reject) = validation {
            return self.reject(event, reject);
        }
        let index = self
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .index
            .clone();
        if !index.contains_key(name) && !index.contains_key("") && !self.should_emit(name) {
            return Emitted {
                event,
                status: Status::Completed,
                errors: vec![],
            };
        }
        self.log_event(
            &event,
            crate::logging::Level::Debug,
            "event",
            None,
            None,
            None,
        );
        let mut ancestry = ANCESTRY.try_with(Clone::clone).unwrap_or_default();
        let current = ancestry.iter().rposition(|(id, _)| *id == self.id);
        let depth = current.map_or(1, |i| ancestry[i].1 + 1);
        if depth > self.limits.max_depth {
            return self.reject(event, Reject::Recursion);
        }
        let permit = if current.is_some() {
            None
        } else {
            match self.admit(&cx).await {
                Ok(permit) => Some(permit),
                Err(Status::Cancelled) => {
                    return Emitted {
                        event,
                        status: Status::Cancelled,
                        errors: vec![],
                    };
                }
                Err(Status::Rejected(reject)) => return self.reject(event, reject),
                _ => unreachable!(),
            }
        };
        ancestry.push((self.id, depth));
        let result = ANCESTRY
            .scope(ancestry, self.dispatch(&cx, event, &index))
            .await;
        drop(permit);
        result
    }
    fn reject(&self, event: Arc<Event>, reject: Reject) -> Emitted {
        self.rejected.fetch_add(1, Ordering::Relaxed);
        self.log_event(
            &event,
            crate::logging::Level::Warn,
            "event dispatch rejected",
            Some(&format!("{reject:?}")),
            None,
            None,
        );
        Emitted {
            event,
            status: Status::Rejected(reject),
            errors: vec![],
        }
    }
    async fn admit(&self, cx: &EmitContext) -> Result<OwnedSemaphorePermit, Status> {
        if cx.cancel.is_cancelled() {
            return Err(Status::Cancelled);
        }
        if let Ok(permit) = self.running.clone().try_acquire_owned() {
            return Ok(permit);
        }
        let queue = self
            .waiting
            .clone()
            .try_acquire_owned()
            .map_err(|_| Status::Rejected(Reject::QueueFull))?;
        let permit = tokio::select! { biased;
            _ = cx.cancel.cancelled() => Err(Status::Cancelled),
            permit = tokio::time::timeout(self.limits.queue_wait, self.running.clone().acquire_owned()) => permit.map_err(|_| Status::Rejected(Reject::Overloaded)).and_then(|v| v.map_err(|_| Status::Rejected(Reject::Overloaded))),
        };
        drop(queue);
        permit
    }
    async fn dispatch(&self, cx: &EmitContext, event: Arc<Event>, index: &Index) -> Emitted {
        let mut errors = Vec::new();
        let mut callbacks = 0usize;
        let mut status = Status::Completed;
        let mut keys = vec![event.dispatch_name.as_str()];
        if !event.dispatch_name.is_empty() {
            keys.push("");
        }
        'events: for key in keys {
            let Some(modules) = index.get(key) else {
                continue;
            };
            let mut origin = event.origin.as_str();
            loop {
                if let Some(handlers) = modules.get(origin) {
                    for handler in handlers {
                        callbacks += 1;
                        if callbacks.is_multiple_of(64) {
                            tokio::task::yield_now().await;
                        }
                        self.log_event(
                            &event,
                            crate::logging::Level::Debug,
                            "invoking subscribed handler",
                            None,
                            Some(key),
                            Some(handler.as_ref()),
                        );
                        let result = tokio::select! { biased; _ = cx.cancel.cancelled() => { self.log_event(&event,crate::logging::Level::Error,"context canceled; event handling stopped",None,None,None); status = Status::Cancelled; break 'events; }, result = handler.handle(cx, &event) => result };
                        match result {
                            Ok(()) => {}
                            Err(HandlerError::Other(message)) => {
                                self.log_event(
                                    &event,
                                    crate::logging::Level::Error,
                                    "handler error",
                                    Some(&message),
                                    None,
                                    None,
                                );
                                self.errors.fetch_add(1, Ordering::Relaxed);
                                errors.push(message);
                            }
                            Err(HandlerError::Aborted(message)) => {
                                event.aborted.store(true, Ordering::Release);
                                self.log_event(
                                    &event,
                                    crate::logging::Level::Error,
                                    "handler error",
                                    Some(&message),
                                    None,
                                    None,
                                );
                                self.errors.fetch_add(1, Ordering::Relaxed);
                                errors.push(message);
                                status = Status::Aborted;
                                break 'events;
                            }
                        }
                    }
                }
                if origin.is_empty() {
                    break;
                }
                origin = origin.rsplit_once('.').map_or("", |(p, _)| p);
            }
        }
        Emitted {
            event,
            status,
            errors,
        }
    }
}
fn time_json(value: SystemTime) -> Option<Json> {
    let ns = match value.duration_since(UNIX_EPOCH) {
        Ok(d) => i128::try_from(d.as_nanos()).ok()?,
        Err(e) => -i128::try_from(e.duration().as_nanos()).ok()?,
    };
    let seconds = i64::try_from(ns.div_euclid(1_000_000_000)).ok()?;
    let nanos = ns.rem_euclid(1_000_000_000) as u32;
    let date = chrono::DateTime::from_timestamp(seconds, nanos)?;
    use chrono::Datelike;
    if !(0..=9999).contains(&date.year()) {
        return None;
    }
    let mut text = date.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true);
    text.pop();
    while text.ends_with('0') {
        text.pop();
    }
    if text.ends_with('.') {
        text.pop();
    }
    text.push('Z');
    Some(Json::String(text))
}
fn cloud_json(value: &Value) -> Option<Json> {
    Some(match value {
        Value::Float(v) => Json::Number(serde_json::Number::from_f64(*v)?),
        Value::Time(v) => return time_json(*v),
        Value::Opaque(v) if v.downcast_ref::<crate::cert_events::Failure>().is_some() => {
            Json::Object(Default::default())
        }
        Value::Opaque(_) | Value::Event(_) | Value::Data(_) => return None,
        _ => diagnostic_json(value),
    })
}
fn diagnostic_json(value: &Value) -> Json {
    match value {
        Value::Null => Json::Null,
        Value::Bool(v) => Json::Bool(*v),
        Value::Int(v) => Json::from(*v),
        Value::Uint(v) => Json::from(*v),
        Value::Float(v) => serde_json::Number::from_f64(*v).map_or(Json::Null, Json::Number),
        Value::Str(v) => Json::String(v.clone()),
        Value::Duration(v) => Json::from(*v),
        Value::Bytes(v) => {
            use base64::Engine;
            Json::String(base64::engine::general_purpose::STANDARD.encode(v))
        }
        Value::Strings(v) => Json::Array(v.iter().cloned().map(Json::String).collect()),
        Value::Json(v) | Value::Native { json: v, .. } => v.as_ref().clone(),
        Value::Time(v) => time_json(*v).unwrap_or(Json::Null),
        // Native error objects normally have no JSON-exported fields in Go.
        Value::Opaque(v) if v.downcast_ref::<crate::cert_events::Failure>().is_some() => {
            Json::Object(Default::default())
        }
        Value::Opaque(_) => Json::String("[unserializable native metadata]".into()),
        Value::Data(_) | Value::Event(_) => Json::Null,
    }
}
fn names(value: Option<&Json>) -> Result<Vec<String>, String> {
    let Some(value) = value.filter(|v| !v.is_null()) else {
        return Ok(vec![String::new()]);
    };
    let list = value
        .as_array()
        .ok_or("event names/modules must be array")?;
    let list = list
        .iter()
        .map(|v| {
            v.as_str()
                .map(str::to_owned)
                .ok_or_else(|| "event name/module must be string".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    if list.iter().any(|s| !identity_valid(s)) {
        return Err("invalid event name/module".into());
    }
    Ok(if list.is_empty() {
        vec![String::new()]
    } else {
        list
    })
}
fn identity_valid(value: &str) -> bool {
    value.len() <= 1024 && value.matches('.').count() < 64
}
fn append(index: &mut Index, sub: &Subscription, limits: &Limits) -> Result<(), String> {
    if sub
        .events
        .iter()
        .chain(sub.modules.iter())
        .any(|s| !identity_valid(s))
    {
        return Err("invalid event subscription identity".into());
    }
    let old_count: usize = index.values().flat_map(|m| m.values()).map(Vec::len).sum();
    let added = sub
        .events
        .len()
        .checked_mul(sub.modules.len())
        .and_then(|n| n.checked_mul(sub.handlers.len()))
        .ok_or("event expansion overflow")?;
    if added > limits.max_handlers.saturating_sub(old_count) {
        return Err("event handler expansion limit".into());
    }
    for event in &sub.events {
        for module in &sub.modules {
            index
                .entry(event.clone())
                .or_default()
                .entry(module.clone())
                .or_default()
                .extend(sub.handlers.iter().cloned());
        }
    }
    if index.values().map(HashMap::len).sum::<usize>() > limits.max_slots {
        return Err("event subscription slot limit".into());
    }
    Ok(())
}
fn validate_data(data: &EventData, limits: &Limits) -> Result<(), Reject> {
    fn json_bytes(value: &Json, depth: usize, remaining: &mut usize) -> Result<(), Reject> {
        if depth > 32 {
            return Err(Reject::DataTooLarge);
        }
        charge(remaining, 64)?;
        if let Json::Object(map) = value {
            charge(
                remaining,
                tree_upper(
                    map.len(),
                    std::mem::size_of::<String>(),
                    std::mem::size_of::<Json>(),
                ),
            )?;
        }
        if let Json::Array(list) = value {
            charge(
                remaining,
                list.len()
                    .saturating_mul(std::mem::size_of::<Json>())
                    .saturating_add(64),
            )?;
        }
        match value {
            Json::String(s) => charge(remaining, s.len())?,
            Json::Array(a) => {
                for v in a {
                    json_bytes(v, depth + 1, remaining)?;
                }
            }
            Json::Object(m) => {
                for (k, v) in m {
                    charge(remaining, k.len())?;
                    json_bytes(v, depth + 1, remaining)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    fn walk(data: &EventData, depth: usize, remaining: &mut usize) -> Result<(), Reject> {
        if depth > 32 {
            return Err(Reject::DataTooLarge);
        }
        charge(
            remaining,
            tree_upper(
                data.len(),
                std::mem::size_of::<String>(),
                std::mem::size_of::<Value>(),
            ),
        )?;
        for (key, value) in data {
            charge(remaining, key.len().saturating_add(128))?;
            match value {
                Value::Str(s) => charge(remaining, s.len())?,
                Value::Bytes(v) => charge(remaining, v.len())?,
                Value::Strings(v) => {
                    charge(
                        remaining,
                        v.len()
                            .saturating_mul(std::mem::size_of::<String>())
                            .saturating_add(128),
                    )?;
                    for s in v.iter() {
                        charge(remaining, s.capacity())?;
                    }
                }
                Value::Json(v) => json_bytes(v, depth + 1, remaining)?,
                Value::Native { json, .. } => json_bytes(json, depth + 1, remaining)?,
                // Placeholder views are not storable: doing so would permit
                // Arc cycles and mutable transitive graphs beyond this budget.
                Value::Data(_) | Value::Event(_) => return Err(Reject::DataTooLarge),
                _ => {}
            }
        }
        Ok(())
    }
    if data.len() > limits.max_data_keys {
        return Err(Reject::DataTooLarge);
    }
    walk(data, 0, &mut limits.max_data_bytes.clone())
}
fn charge(remaining: &mut usize, amount: usize) -> Result<(), Reject> {
    *remaining = remaining.checked_sub(amount).ok_or(Reject::DataTooLarge)?;
    Ok(())
}

// Rust 1.99.1 BTree B=6: at most 11 KV slots and 12 edge slots per node.
// The extra nodes cover the root/allocator/alignment boundary conservatively.
fn tree_upper(len: usize, key: usize, value: usize) -> usize {
    if len == 0 {
        return 0;
    }
    let node = 64usize
        .saturating_add(11usize.saturating_mul(key.saturating_add(value)))
        .saturating_add(12 * std::mem::size_of::<usize>());
    len.div_ceil(5).saturating_add(3).saturating_mul(node)
}
