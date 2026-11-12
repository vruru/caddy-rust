use super::{err, MAX_BYTES, MAX_ITEMS};
use gotmpl::{Value, MapContext};
use serde_json::value::RawValue;
use std::collections::BTreeMap;
use std::sync::Arc;

pub(super) fn non_must(raw: &RawValue, maps: &MapContext) -> gotmpl::Result<Value> {
    let mut nodes = 0usize;
    decode(raw, maps, 0, &mut nodes)
}

fn decode(raw: &RawValue, maps: &MapContext, depth: usize, nodes: &mut usize) -> gotmpl::Result<Value> {
    if depth > 32 || *nodes >= MAX_ITEMS {
        return Err(err("resource limit exceeded"));
    }
    *nodes += 1;

    let s = raw.get().trim_matches(|ch|matches!(ch,' '|'\t'|'\r'|'\n'));
    let first = s.as_bytes().first().copied().ok_or_else(|| err("empty input"))?;

    match first {
        b'n' => Ok(Value::Nil),
        b't' => Ok(Value::Bool(true)),
        b'f' => Ok(Value::Bool(false)),
        b'"' => {
            let str_val: String = serde_json::from_str(s).map_err(|e| err(e.to_string()))?;
            if str_val.len() > MAX_BYTES {
                return Err(err("string too long"));
            }
            Ok(Value::from(str_val))
        }
        b'[' => {
            let children: Vec<&RawValue> = serde_json::from_str(s).map_err(|e| err(e.to_string()))?;
            let child_len = children.len();
            if child_len > MAX_ITEMS {
                return Err(err("array too long"));
            }
            if *nodes + child_len > MAX_ITEMS {
                return Err(err("resource limit exceeded"));
            }
            let mut vals = Vec::with_capacity(child_len);
            for child in children {
                vals.push(decode(child, maps, depth + 1, nodes)?);
            }
            Ok(Value::List(Arc::from(vals.into_boxed_slice())))
        }
        b'{' => {
            let map: BTreeMap<String, &RawValue> = serde_json::from_str(s).map_err(|e| err(e.to_string()))?;
            if map.len() > MAX_ITEMS {
                return Err(err("object too large"));
            }
            if *nodes + map.len() > MAX_ITEMS {
                return Err(err("resource limit exceeded"));
            }
            let mut total_key_bytes = 0usize;
            for k in map.keys() {
                total_key_bytes += k.len();
                if total_key_bytes > MAX_BYTES {
                    return Err(err("key bytes exceeded"));
                }
            }
            let mut new_map = BTreeMap::new();
            for (k, v_raw) in map {
                let val = decode(v_raw, maps, depth + 1, nodes)?;
                new_map.insert(Arc::from(k), val);
            }
            maps.map(new_map)
        }
        _ => {
            match s.parse::<f64>() {
                Ok(v) if v.is_finite() => Ok(Value::Float(v)),
                _ => Ok(Value::Float(0.0)),
            }
        }
    }
}
