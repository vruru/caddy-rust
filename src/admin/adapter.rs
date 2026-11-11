//! Adapted HTTP output uses the original compact serde JSON representation.
//! The backend ABI returns an owned tree, so output accounting starts once
//! the adapter returns. This does not bound allocations inside that adapter.

use super::{
    AdaptedConfig, AdminError,
    byte_budget::{ADAPT_EGRESS, ADAPTED_CONFIG, Buffer, Credit, Pool},
};
use hyper::body::Bytes;
use serde::Serialize;
use serde_json::Value;
use std::io::{self, Write};

pub(super) enum Prepared {
    Adapt(Bytes),
    Load {
        config: Buffer,
        warnings: Bytes,
        ingress: Credit,
    },
}

#[derive(Serialize)]
struct AdaptReply<'a> {
    result: &'a Value,
    warnings: &'a [Value],
}

#[derive(Serialize)]
struct LoadReply<'a> {
    warnings: &'a [Value],
}

struct Counter {
    length: usize,
    overflow: bool,
}

impl Write for Counter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let Some(length) = self
            .length
            .checked_add(bytes.len())
            .filter(|&length| length <= ADAPT_EGRESS)
        else {
            self.overflow = true;
            return Err(io::Error::other("adapter response byte limit"));
        };
        self.length = length;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn serialization_failed() -> AdminError {
    AdminError::new(500, "admin_adapter_serialization_failed")
}

fn measure_reply(value: &impl Serialize) -> Result<usize, AdminError> {
    let mut count = Counter {
        length: 0,
        overflow: false,
    };
    serde_json::to_writer(&mut count, value).map_err(|_| {
        if count.overflow {
            AdminError::new(413, "admin_adapter_output_too_large")
        } else {
            serialization_failed()
        }
    })?;
    Ok(count.length)
}

fn encode_reply(
    value: &impl Serialize,
    mut buffer: Buffer,
    length: usize,
) -> Result<Bytes, AdminError> {
    serde_json::to_writer(&mut buffer, value).map_err(|_| serialization_failed())?;
    if buffer.as_ref().len() != length {
        return Err(serialization_failed());
    }
    Ok(Bytes::from_owner(buffer))
}

enum Children<'a> {
    Array(std::slice::Iter<'a, Value>),
    Object(serde_json::map::Values<'a>),
}

impl<'a> Iterator for Children<'a> {
    type Item = &'a Value;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Array(values) => values.next(),
            Self::Object(values) => values.next(),
        }
    }
}

/// Bound recursive serialization before calling serde. The traversal keeps
/// one iterator per level, so a wide object does not allocate a copy of its
/// children. The external adapter still owns construction of the result.
fn fits_depth(value: &Value, start: usize) -> bool {
    let mut parents = Vec::<Children<'_>>::new();
    let mut next = Some(value);
    while let Some(value) = next {
        if parents.len() + start > crate::admin_json::MAX_CONFIG_DEPTH {
            return false;
        }
        match value {
            Value::Array(values) => parents.push(Children::Array(values.iter())),
            Value::Object(values) => parents.push(Children::Object(values.values())),
            _ => {}
        }
        next = loop {
            let Some(parent) = parents.last_mut() else {
                break None;
            };
            if let Some(child) = parent.next() {
                break Some(child);
            }
            parents.pop();
        };
    }
    true
}

/// Rejecting a deep result also needs non-recursive destruction. Move one
/// child out of each owned container at a time, without copying wide lists.
enum OwnedChildren {
    Array(std::vec::IntoIter<Value>),
    Object(serde_json::map::IntoIter),
}

impl Iterator for OwnedChildren {
    type Item = Value;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Array(values) => values.next(),
            Self::Object(values) => values.next().map(|(_, value)| value),
        }
    }
}

fn drop_iteratively(root: Value) {
    let mut parents = Vec::<OwnedChildren>::new();
    let mut next = Some(root);
    while let Some(value) = next {
        match value {
            Value::Array(values) => parents.push(OwnedChildren::Array(values.into_iter())),
            Value::Object(values) => parents.push(OwnedChildren::Object(values.into_iter())),
            _ => {}
        }
        next = loop {
            let Some(parent) = parents.last_mut() else {
                break None;
            };
            if let Some(child) = parent.next() {
                break Some(child);
            }
            parents.pop();
        };
    }
}

/// Also protect cancellation before the blocking task starts. Tokio may drop
/// its captured output without calling `prepare` during runtime shutdown.
pub(super) struct Returned(Option<AdaptedConfig>);

impl Returned {
    pub(super) fn new(output: AdaptedConfig) -> Self {
        Self(Some(output))
    }
}

impl Drop for Returned {
    fn drop(&mut self) {
        if let Some(AdaptedConfig { result, warnings }) = self.0.take() {
            drop_iteratively(result);
            for warning in warnings {
                drop_iteratively(warning);
            }
        }
    }
}

pub(super) fn prepare(
    mut adapted: Returned,
    load: bool,
    ingress: Credit,
    egress: &Pool,
    config_pool: &Pool,
) -> Result<Prepared, AdminError> {
    let output = adapted.0.as_ref().expect("owned adapter output");
    let start_depth = usize::from(!load);
    if !fits_depth(&output.result, start_depth)
        || output
            .warnings
            .iter()
            .any(|warning| !fits_depth(warning, 2))
    {
        return Err(AdminError::new(413, "admin_adapter_output_depth_limit"));
    }
    let AdaptedConfig { result, warnings } = adapted.0.take().expect("owned adapter output");
    if !load {
        let reply = AdaptReply {
            result: &result,
            warnings: &warnings,
        };
        let length = measure_reply(&reply)?;
        return encode_reply(&reply, Buffer::new(egress, length)?, length).map(Prepared::Adapt);
    }
    // Count both representations before reserving any pool. An oversized
    // response is permanent, regardless of current egress/queue pressure.
    let reply = LoadReply {
        warnings: &warnings,
    };
    let warning_length = (!warnings.is_empty())
        .then(|| measure_reply(&reply))
        .transpose()?;
    let (data, (credit, warning_buffer)) =
        crate::admin_json::encoded_reserved(&result, ADAPTED_CONFIG, |length| {
            let reserve = || {
                let credit = config_pool.reserve(length)?;
                let warnings = warning_length
                    .map(|length| Buffer::new(egress, length))
                    .transpose()?;
                Ok::<_, AdminError>((credit, warnings))
            };
            reserve().map_err(|error| crate::admin_json::ConfigError {
                status: error.status,
                category: error.category,
            })
        })
        .map_err(|error| AdminError::new(error.status, error.category))?;
    let warnings = match (warning_buffer, warning_length) {
        (Some(buffer), Some(length)) => encode_reply(&reply, buffer, length)?,
        _ => Bytes::new(),
    };
    Ok(Prepared::Load {
        config: Buffer::from_parts(data, credit),
        warnings,
        ingress,
    })
}
