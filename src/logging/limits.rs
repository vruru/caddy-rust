//! Independent log admission limits. Counts are logical owned bytes, not RSS.
use super::types::{Event, Field, FieldValue, Origin};
use anyhow::{Result, anyhow, ensure};
use serde_json::Value;
#[derive(Clone, Debug)]
pub struct RuntimeLimits {
    pub max_logs: usize,
    pub max_writer_actors: usize,
    pub max_queue_messages_per_writer: usize,
    pub max_buffered_bytes_per_writer: usize,
    pub max_queued_jobs: usize,
    pub max_pending_event_bytes: usize,
    pub max_event_bytes: usize,
    pub max_encoded_bytes: usize,
    pub max_encoding_workspace_bytes: usize,
    pub max_event_nodes: usize,
    pub max_field_depth: usize,
    pub max_config_bytes: usize,
    pub max_config_nodes: usize,
    pub max_config_owned_bytes: usize,
    pub max_routing_comparisons: usize,
}
impl Default for RuntimeLimits {
    fn default() -> Self {
        Self {
            max_logs: 1024,
            max_writer_actors: 128,
            max_queue_messages_per_writer: 1024,
            max_buffered_bytes_per_writer: 32 << 20,
            max_queued_jobs: 8192,
            max_pending_event_bytes: 64 << 20,
            max_event_bytes: 8 << 20,
            max_encoded_bytes: 16 << 20,
            // A destination may charge at most half, including transient
            // scratch and retained frames. This still admits a max-size encode.
            max_encoding_workspace_bytes: 256 << 20,
            max_event_nodes: 65536,
            max_field_depth: 128,
            max_config_bytes: 16 << 20,
            max_config_nodes: 262144,
            max_config_owned_bytes: 64 << 20,
            max_routing_comparisons: 1_000_000,
        }
    }
}
impl RuntimeLimits {
    pub(super) fn validate(&self) -> Result<()> {
        ensure!(
            self.max_logs > 0
                && self.max_writer_actors > 0
                && self.max_writer_actors <= self.max_logs,
            "invalid logging destination limits"
        );
        ensure!(
            self.max_queue_messages_per_writer > 0
                && self.max_buffered_bytes_per_writer > 0
                && self.max_buffered_bytes_per_writer <= self.max_encoding_workspace_bytes
                && self.max_buffered_bytes_per_writer <= u32::MAX as usize
                && self.max_queued_jobs > 0
                && self.max_queued_jobs <= tokio::sync::Semaphore::MAX_PERMITS,
            "invalid logging queue limits"
        );
        ensure!(
            self.max_event_bytes > 0
                && self.max_event_bytes <= self.max_pending_event_bytes
                && self.max_pending_event_bytes <= u32::MAX as usize
                && self.max_pending_event_bytes <= tokio::sync::Semaphore::MAX_PERMITS,
            "invalid logging byte limits"
        );
        ensure!(
            self.max_encoded_bytes > 0
                && self.max_event_nodes > 0
                && self.max_field_depth > 0
                && self.max_field_depth <= 256
                && self.max_config_bytes > 0
                && self.max_config_nodes > 0
                && self.max_config_owned_bytes > 0
                && self.max_routing_comparisons > 0,
            "invalid logging record limits"
        );
        Ok(())
    }
}
#[derive(Clone, Copy)]
pub(super) struct EventCost {
    pub bytes: u32,
}
enum Node<'a> {
    Typed(&'a FieldValue),
    Json(&'a Value),
}
struct Meter<'a> {
    limits: &'a RuntimeLimits,
    bytes: usize,
    nodes: usize,
}
impl Meter<'_> {
    fn bytes(&mut self, n: usize) -> Result<()> {
        self.bytes = self
            .bytes
            .checked_add(n)
            .filter(|v| *v <= self.limits.max_event_bytes)
            .ok_or_else(|| anyhow!("log event byte limit exceeded"))?;
        Ok(())
    }
    fn nodes(&mut self, n: usize) -> Result<()> {
        self.nodes = self
            .nodes
            .checked_add(n)
            .filter(|v| *v <= self.limits.max_event_nodes)
            .ok_or_else(|| anyhow!("log event node limit exceeded"))?;
        Ok(())
    }
}
/// Called before queue admission or fanout; queues retain Arc<Event> instead of
/// cloning payloads. The returned byte permit follows that actual shared event.
pub(super) fn measure(event: &Event, limits: &RuntimeLimits) -> Result<EventCost> {
    let mut m = Meter {
        limits,
        bytes: 0,
        nodes: 0,
    };
    m.bytes(std::mem::size_of::<Event>())?;
    m.bytes(event.logger.len())?;
    m.bytes(event.message.len())?;
    if let Origin::Module { module_id } = &event.origin {
        m.bytes(module_id.len())?;
    }
    ensure!(
        event.time.nanosecond < 1_000_000_000,
        "invalid log timestamp"
    );
    if let Some(caller) = &event.caller {
        m.bytes(caller.file.len())?;
        m.bytes(caller.function.len())?;
    }
    if let Some(stack) = &event.stacktrace {
        m.bytes(stack.len())?;
    }
    m.nodes(event.fields.len())?;
    let mut work = Vec::new();
    for field in &event.fields {
        m.bytes(std::mem::size_of::<Field>())?;
        m.bytes(field.key.len())?;
        work.push((Node::Typed(&field.value), 0usize));
    }
    while let Some((node, depth)) = work.pop() {
        ensure!(
            depth <= limits.max_field_depth,
            "log field depth limit exceeded"
        );
        match node {
            Node::Typed(value) => {
                m.bytes(std::mem::size_of::<FieldValue>())?;
                match value {
                    FieldValue::String(s) | FieldValue::Error(s) => m.bytes(s.len())?,
                    FieldValue::Binary(b)
                    | FieldValue::ByteString(b)
                    | FieldValue::RawString(b) => m.bytes(b.len())?,
                    FieldValue::StringArray(values) => {
                        m.nodes(values.len())?;
                        for value in values {
                            m.bytes(std::mem::size_of::<Vec<u8>>())?;
                            m.bytes(value.len())?;
                        }
                    }
                    FieldValue::Time(t) => {
                        ensure!(t.nanosecond < 1_000_000_000, "invalid log field timestamp")
                    }
                    FieldValue::Object(fields) => {
                        m.nodes(fields.len())?;
                        for field in fields {
                            m.bytes(std::mem::size_of::<Field>())?;
                            m.bytes(field.key.len())?;
                            work.push((Node::Typed(&field.value), depth + 1));
                        }
                    }
                    FieldValue::Array(values) => {
                        m.nodes(values.len())?;
                        for value in values {
                            work.push((Node::Typed(value), depth + 1));
                        }
                    }
                    FieldValue::Reflected(value) => {
                        m.nodes(1)?;
                        work.push((Node::Json(value), depth + 1));
                    }
                    _ => {}
                }
            }
            Node::Json(value) => {
                m.bytes(std::mem::size_of::<Value>())?;
                match value {
                    Value::String(s) => m.bytes(s.len())?,
                    Value::Array(values) => {
                        m.nodes(values.len())?;
                        for value in values {
                            work.push((Node::Json(value), depth + 1));
                        }
                    }
                    Value::Object(fields) => {
                        m.nodes(fields.len())?;
                        for (key, value) in fields {
                            m.bytes(key.len())?;
                            m.bytes(80)?;
                            work.push((Node::Json(value), depth + 1));
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(EventCost {
        bytes: m
            .bytes
            .try_into()
            .map_err(|_| anyhow!("log event permit overflow"))?,
    })
}
