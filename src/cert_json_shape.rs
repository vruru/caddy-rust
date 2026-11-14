//! Allocation-free serde_json::Value footprint for the pinned BTreeMap graph.
//! Rust 1.100.0 alloc/collections/btree/node.rs has B=6, 11 key/value slots,
//! parent pointer + two u16 fields, and 12 child pointers in internal nodes.
//! https://github.com/rust-lang/rust/blob/1.100.0/library/alloc/src/collections/btree/node.rs
//! Update this derivation/allocator checks when changing the Rust toolchain.
use crate::cert_transient::ResourceDenied;
use anyhow::Result;
use serde_json::Value;
use std::mem::{align_of, size_of};

const _: () = assert!(
    size_of::<serde_json::Map<String, Value>>()
        == size_of::<std::collections::BTreeMap<String, Value>>()
);
fn add(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b).ok_or_else(|| ResourceDenied.into())
}
fn mul(a: usize, b: usize) -> Result<usize> {
    a.checked_mul(b).ok_or_else(|| ResourceDenied.into())
}
fn node_bound() -> usize {
    let align = align_of::<String>()
        .max(align_of::<Value>())
        .max(align_of::<usize>());
    let fields = size_of::<Option<std::ptr::NonNull<()>>>()
        + 2 * size_of::<u16>()
        + 11 * (size_of::<String>() + size_of::<Value>());
    // Padding bounded separately for all five leaf fields; inner repr(C)
    // adds twelve pointers. This remains an upper bound without relying on
    // the compiler's actual Rust-field reordering or minimum padding.
    let leaf = (fields + 5 * align + align - 1) / align * align;
    leaf + 12 * size_of::<usize>() + align
}

#[derive(Clone, Copy, Default)]
struct Frame {
    array: bool,
    expecting: bool,
    count: usize,
}
pub(crate) struct Footprint {
    pub owned: usize,
    pub temporary: usize,
}
pub(crate) fn footprint(bytes: &[u8]) -> Result<Footprint> {
    let mut stack = [Frame::default(); 128];
    let mut depth = 0usize;
    let mut i = 0usize;
    let (
        mut nodes,
        mut array_slots,
        mut old_array_slots,
        mut string_bytes,
        mut strings,
        mut numeric_bytes,
    ) = (0usize, 0usize, 0usize, 0usize, 0usize, 0usize);
    fn value(stack: &mut [Frame; 128], depth: usize) -> Result<()> {
        if depth > 0 && stack[depth - 1].array && stack[depth - 1].expecting {
            stack[depth - 1].count = add(stack[depth - 1].count, 1)?;
            stack[depth - 1].expecting = false;
        }
        Ok(())
    }
    fn finish(frame: Frame, nodes: &mut usize, slots: &mut usize, old: &mut usize) -> Result<()> {
        if frame.count == 0 {
            return Ok(());
        }
        if frame.array {
            let capacity = frame
                .count
                .checked_next_power_of_two()
                .ok_or(ResourceDenied)?
                .max(4);
            *slots = add(*slots, capacity)?;
            if capacity > 4 {
                *old = (*old).max(capacity / 2);
            }
        } else {
            // Every non-root BTree node has >=B-1=5 keys. The root has >=1.
            // Duplicated JSON keys only reduce the actual node count.
            *nodes = add(*nodes, 1 + (frame.count - 1) / 5)?;
        }
        Ok(())
    }
    while i < bytes.len() {
        match bytes[i] {
            b'"' => {
                value(&mut stack, depth)?;
                i += 1;
                let start = i;
                while i < bytes.len() {
                    if bytes[i] == b'"' {
                        break;
                    }
                    if bytes[i] == b'\\' {
                        i = add(i, 1)?;
                    }
                    i = add(i, 1)?;
                }
                string_bytes = add(string_bytes, i.min(bytes.len()) - start)?;
                if i.min(bytes.len()) > start {
                    strings = add(strings, 1)?;
                }
                i = i.saturating_add(1);
            }
            b'[' | b'{' => {
                value(&mut stack, depth)?;
                if depth == stack.len() {
                    return Err(ResourceDenied.into());
                }
                stack[depth] = Frame {
                    array: bytes[i] == b'[',
                    expecting: true,
                    count: 0,
                };
                depth += 1;
                i += 1;
            }
            b']' | b'}' => {
                if depth > 0 {
                    depth -= 1;
                    finish(
                        stack[depth],
                        &mut nodes,
                        &mut array_slots,
                        &mut old_array_slots,
                    )?;
                }
                i += 1;
            }
            b',' => {
                if depth > 0 && stack[depth - 1].array {
                    stack[depth - 1].expecting = true
                }
                i += 1;
            }
            b':' => {
                if depth > 0 && !stack[depth - 1].array {
                    stack[depth - 1].count = add(stack[depth - 1].count, 1)?;
                }
                i += 1;
            }
            b' ' | b'\r' | b'\n' | b'\t' => {
                i += 1;
            }
            _ => {
                value(&mut stack, depth)?;
                let start = i;
                i += 1;
                while i < bytes.len()
                    && !matches!(
                        bytes[i],
                        b' ' | b'\r'
                            | b'\n'
                            | b'\t'
                            | b'['
                            | b'{'
                            | b']'
                            | b'}'
                            | b','
                            | b':'
                            | b'"'
                    )
                {
                    i += 1;
                }
                numeric_bytes = add(numeric_bytes, i - start)?;
            }
        }
    }
    // Malformed/truncated JSON may still have allocated a valid prefix.
    for frame in &stack[..depth] {
        finish(*frame, &mut nodes, &mut array_slots, &mut old_array_slots)?;
    }
    let mut owned = mul(nodes, node_bound())?;
    owned = add(owned, mul(array_slots, size_of::<Value>())?)?;
    owned = add(owned, mul(string_bytes, 2)?)?;
    owned = add(owned, mul(strings, 8)?)?;
    // Number is inline in the tested graph. If arbitrary_precision is enabled,
    // its String representation needs_drop and is charged by encoded digits.
    if std::mem::needs_drop::<serde_json::Number>() {
        owned = add(owned, mul(numeric_bytes, 2)?)?;
    }
    // During parsing only one Vec realloc or BTree root split is synchronous
    // at a time; persistent output pays final capacities, scratch pays overlap.
    let mut temporary = add(mul(bytes.len(), 3)?, 8192)?;
    temporary = add(temporary, mul(old_array_slots, size_of::<Value>())?)?;
    temporary = add(temporary, mul(2, node_bound())?)?;
    Ok(Footprint { owned, temporary })
}

/// Fallible preflight for a deep Value clone. No source allocation is cloned
/// until the caller has admitted this result. Vec::clone reserves exact len.
pub(crate) fn clone_cost(value: &Value) -> Result<usize> {
    fn walk(value: &Value, depth: usize) -> Result<usize> {
        if depth > 128 {
            return Err(ResourceDenied.into());
        }
        match value {
            Value::Null | Value::Bool(_) => Ok(0),
            Value::Number(number) => {
                if !std::mem::needs_drop::<serde_json::Number>() {
                    return Ok(0);
                }
                struct Count(usize);
                impl std::io::Write for Count {
                    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                        self.0 = self
                            .0
                            .checked_add(b.len())
                            .ok_or_else(|| std::io::Error::other("number size overflow"))?;
                        Ok(b.len())
                    }
                    fn flush(&mut self) -> std::io::Result<()> {
                        Ok(())
                    }
                }
                let mut count = Count(0);
                serde_json::to_writer(&mut count, number)?;
                add(mul(count.0, 2)?, 8)
            }
            Value::String(text) => Ok(text.len()),
            Value::Array(values) => {
                let mut cost = mul(values.len(), size_of::<Value>())?;
                for value in values {
                    cost = add(cost, walk(value, depth + 1)?)?;
                }
                Ok(cost)
            }
            Value::Object(values) => {
                let nodes = if values.is_empty() {
                    0
                } else {
                    1 + (values.len() - 1) / 5
                };
                let mut cost = mul(nodes, node_bound())?;
                for (key, value) in values {
                    cost = add(cost, add(key.len(), walk(value, depth + 1)?)?)?;
                }
                Ok(cost)
            }
        }
    }
    walk(value, 0)
}
/// ARI inserts at most one outer field, six inner fields and two small maps.
/// Existing issuer map may split along its BTree height; count that path from
/// the actual number of existing entries rather than assuming a flat map.
pub(crate) fn ari_edit_allowance(metadata: &Value, certificate_id_bytes: usize) -> Result<usize> {
    let entries = metadata
        .get("issuer_data")
        .and_then(Value::as_object)
        .map_or(0, |m| m.len());
    let mut height = 2usize;
    let mut remaining = entries;
    while remaining > 0 {
        height = add(height, 1)?;
        remaining /= 5;
    }
    let nodes = add(height, 4)?;
    let strings = add(certificate_id_bytes, 2048)?;
    add(mul(nodes, node_bound())?, mul(strings, 2)?)
}

/// Two small BTreeMap objects, a pre-sized SAN Value array and cloned strings.
/// This shape is built internally; it never constructs an untrusted DOM first.
pub(crate) fn certificate_metadata_bound(names:&[String],url:Option<&str>,ca:&str,account:&str)->Result<usize>{
    let mut cost=add(mul(2,node_bound())?,8192)?;
    cost=add(cost,mul(names.len(),size_of::<Value>())?)?;
    for name in names {cost=add(cost,name.len())?;}
    for text in [url.unwrap_or(""),ca,account]{cost=add(cost,text.len())?;}
    Ok(cost)
}
