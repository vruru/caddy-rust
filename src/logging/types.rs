//! Structured records preserve field order and type, including duplicate keys.
//! Values intentionally do not implement Debug: records can contain credentials.
use super::level::Level;
use serde_json::Value;
use std::time::{SystemTime, UNIX_EPOCH};
#[derive(Clone)]
pub enum Origin {
    Core,
    Module { module_id: String },
    Sink,
}
#[derive(Clone, Copy)]
pub struct Timestamp {
    pub seconds: i64,
    pub nanosecond: u32,
}
impl Timestamp {
    pub fn now() -> anyhow::Result<Self> {
        Self::from_system_time(SystemTime::now())
    }
    pub fn from_system_time(time: SystemTime) -> anyhow::Result<Self> {
        let (seconds, nanosecond) = match time.duration_since(UNIX_EPOCH) {
            Ok(d) => (i128::from(d.as_secs()), d.subsec_nanos()),
            Err(e) => {
                let d = e.duration();
                if d.subsec_nanos() == 0 {
                    (-i128::from(d.as_secs()), 0)
                } else {
                    (
                        -i128::from(d.as_secs()) - 1,
                        1_000_000_000 - d.subsec_nanos(),
                    )
                }
            }
        };
        Ok(Self {
            seconds: seconds
                .try_into()
                .map_err(|_| anyhow::anyhow!("log timestamp exceeds signed seconds"))?,
            nanosecond,
        })
    }
}

#[derive(Clone)]
pub struct Caller {
    pub file: String,
    pub line: u32,
    pub function: String,
}
#[derive(Clone)]
pub struct Field {
    pub key: String,
    pub value: FieldValue,
}
impl Field {
    pub fn new(key: impl Into<String>, value: FieldValue) -> Self {
        Self {
            key: key.into(),
            value,
        }
    }
}
#[derive(Clone)]
pub enum FieldValue {
    Null,
    Bool(bool),
    I64(i64),
    U64(u64),
    F32(f32),
    F64(f64),
    String(String),
    /// Go StringType can hold invalid UTF-8; do not replace it before hashing
    /// or escaping. This is distinct from zap's ByteStringType below.
    RawString(Vec<u8>),
    /// Caddy internal.LoggableStringArray (HTTP header values). Unlike a
    /// generic ArrayMarshaler, filters hash/mask each string in this exact type.
    StringArray(Vec<Vec<u8>>),
    Binary(Vec<u8>),
    ByteString(Vec<u8>),
    Duration(i64),
    Time(Timestamp),
    /// Object fields pass through nested field filters, as zap ObjectMarshaler.
    Object(Vec<Field>),
    Array(Vec<FieldValue>),
    /// Reflected JSON preserves the distinction from an ObjectMarshaler.
    Reflected(Value),
    /// A namespace opens an object for subsequent fields in this field list.
    Namespace,
    Error(String),
}
pub struct Event {
    pub origin: Origin,
    pub logger: String,
    pub level: Level,
    pub message: String,
    pub time: Timestamp,
    pub fields: Vec<Field>,
    pub caller: Option<Caller>,
    pub stacktrace: Option<String>,
}
#[derive(Clone, Copy)]
pub(super) struct Entry<'a> {
    pub event: &'a Event,
    pub caller: Option<&'a Caller>,
    pub stacktrace: Option<&'a str>,
}
impl<'a> From<&'a Event> for Entry<'a> {
    fn from(event: &'a Event) -> Self {
        Self {
            event,
            caller: event.caller.as_ref(),
            stacktrace: event.stacktrace.as_deref(),
        }
    }
}
impl std::ops::Deref for Entry<'_> {
    type Target = Event;
    fn deref(&self) -> &Event {
        self.event
    }
}
impl Event {
    pub fn new(
        origin: Origin,
        logger: impl Into<String>,
        level: Level,
        message: impl Into<String>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            origin,
            logger: logger.into(),
            level,
            message: message.into(),
            time: Timestamp::now()?,
            fields: Vec::new(),
            caller: None,
            stacktrace: None,
        })
    }
}
