use super::eval::{EvalError, Host, V};
use cel::common::{
    types::{
        CelBool, CelBytes, CelDouble, CelDuration, CelInt, CelList, CelMap, CelNull, CelString,
        CelTimestamp, CelType, CelUInt,
    },
    value::Val,
};
fn overflow() -> EvalError {
    EvalError::fatal("CEL collection cost overflow")
}
fn add(a: usize, b: usize) -> Result<usize, EvalError> {
    a.checked_add(b).ok_or_else(overflow)
}
fn mul(a: usize, b: usize) -> Result<usize, EvalError> {
    a.checked_mul(b).ok_or_else(overflow)
}
pub(super) struct Weight {
    pub(super) units: usize,
    nodes: usize,
}

pub(super) fn weight(host: &mut dyn Host, value: &dyn Val, depth: usize) -> Result<Option<Weight>, EvalError> {
    if depth > 250 {
        return Err(EvalError::fatal("CEL collection depth limit"));
    }
    host.tick(1, 0)?;
    if let Some(s) = value.downcast_ref::<CelString>() {
        return Ok(Some(Weight {
            units: add(s.inner().len().div_ceil(16), 1)?,
            nodes: 1,
        }));
    }
    if let Some(s) = value.downcast_ref::<CelBytes>() {
        return Ok(Some(Weight {
            units: add(s.inner().len().div_ceil(16), 1)?,
            nodes: 1,
        }));
    }
    if value.downcast_ref::<CelBool>().is_some()
        || value.downcast_ref::<CelNull>().is_some()
        || value.downcast_ref::<CelInt>().is_some()
        || value.downcast_ref::<CelUInt>().is_some()
        || value.downcast_ref::<CelDouble>().is_some()
        || value.downcast_ref::<CelDuration>().is_some()
        || value.downcast_ref::<CelTimestamp>().is_some()
    {
        return Ok(Some(Weight { units: 1, nodes: 1 }));
    }
    if let Some(t) = value.downcast_ref::<CelType>() {
        return Ok(Some(Weight {
            units: add(t.name().len().div_ceil(16), 1)?,
            nodes: 1,
        }));
    }
    let mut out = Weight { units: 1, nodes: 1 };
    if let Some(list) = value.downcast_ref::<CelList>() {
        for item in list.inner() {
            let Some(w) = weight(host, item.as_ref(), depth + 1)? else {
                return Ok(None);
            };
            out.units = add(out.units, w.units)?;
            out.nodes = add(out.nodes, w.nodes)?;
        }
        return Ok(Some(out));
    }
    if let Some(map) = value.downcast_ref::<CelMap>() {
        for (key, item) in map.inner() {
            for item in [key.inner(), item.as_ref()] {
                let Some(w) = weight(host, item, depth + 1)? else {
                    return Ok(None);
                };
                out.units = add(out.units, w.units)?;
                out.nodes = add(out.nodes, w.nodes)?;
            }
        }
        return Ok(Some(out));
    }
    // A host value can provide arbitrary trait implementations. Its host must
    // account those; do not apply built-in collection estimates to it.
    Ok(None)
}

pub fn preflight(
    host: &mut dyn Host,
    name: &str,
    member: bool,
    args: &[V],
) -> Result<bool, EvalError> {
    if !member {
        return Ok(false);
    }
    let normal = matches!(name, "reverse" | "sort" | "distinct") && args.len() == 1;
    let flatten = name == "flatten"
        && matches!(args.len(), 1 | 2)
        && (args.len() == 1 || args[1].downcast_ref::<CelInt>().is_some());
    let associated = name == "@sortByAssociatedKeys" && args.len() == 2;
    if !(normal || flatten || associated) {
        return Ok(false);
    }
    let Some(list) = args[0].downcast_ref::<CelList>() else {
        return Ok(false);
    };
    if flatten && args.len() == 2 && *args[1].downcast_ref::<CelInt>().unwrap().inner() < 0 {
        host.tick(1, 512)?;
        return Ok(true);
    }
    let mut nodes = 1;
    let mut largest = 1;
    let mut total_units = 1;
    for item in list.inner() {
        let Some(w) = weight(host, item.as_ref(), 0)? else {
            return Ok(false);
        };
        nodes = add(nodes, w.nodes)?;
        total_units = add(total_units, w.units)?;
        largest = largest.max(w.units);
    }
    let n = list.inner().len();
    let mut same_keys = true;
    let mut key_count = 0;
    if associated {
        let Some(keys) = args[1].downcast_ref::<CelList>() else {
            return Ok(false);
        };
        key_count = keys.inner().len();
        same_keys = key_count == n;
        largest = 1;
        for key in keys.inner() {
            let Some(w) = weight(host, key.as_ref(), 0)? else {
                return Ok(false);
            };
            largest = largest.max(w.units);
            total_units = add(total_units, w.units)?;
        }
    }
    let levels = if n < 2 {
        0
    } else {
        usize::BITS as usize - (n - 1).leading_zeros() as usize
    };
    let operations = match name {
        "distinct" => mul(mul(n, n)?, largest)?,
        "sort" => mul(mul(n, add(mul(levels, 2)?, 1)?)?, largest)?,
        "@sortByAssociatedKeys" if same_keys => mul(mul(n, add(mul(levels, 2)?, 1)?)?, largest)?,
        _ => add(n, total_units)?,
    };
    host.tick(u64::try_from(operations).map_err(|_| overflow())?, 0)?;
    super::eval::charge_clone(host, list)?;
    // Besides the owned element graph: growing unique/output vectors, stable
    // sort scratch, key references and keyed tuples. Charge full capacities.
    let scratch = if associated {
        mul(add(n, key_count)?, 256)?
    } else {
        mul(nodes, 64)?
    };
    host.tick(1, add(scratch, 512)?)?;
    Ok(true)
}
