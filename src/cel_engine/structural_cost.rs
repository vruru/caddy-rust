//! Ordinary container costs. Lookups clone only the selected result; equality
//! and membership pay for recursive comparison work without cloning arguments.
use super::eval::{self, EvalError, Host, V};
use cel::common::{
    types::{CelBool, CelDouble, CelInt, CelList, CelMap, CelString, CelUInt},
    value::Val,
};
fn overflow() -> EvalError {
    EvalError::fatal("CEL structural cost overflow")
}
fn add(a: usize, b: usize) -> Result<usize, EvalError> {
    a.checked_add(b).ok_or_else(overflow)
}
fn mul(a: usize, b: usize) -> Result<usize, EvalError> {
    a.checked_mul(b).ok_or_else(overflow)
}
pub(super) fn valid_list_double(value: &dyn Val) -> bool {
    let Some(d) = value.downcast_ref::<CelDouble>() else {
        return true;
    };
    let d = *d.inner();
    d > i64::MIN as f64 && d < i64::MAX as f64 && (d as i64) as f64 == d
}
pub(super) fn valid_map_key(value: &dyn Val) -> bool {
    value.downcast_ref::<CelBool>().is_some()
        || value.downcast_ref::<CelInt>().is_some()
        || value.downcast_ref::<CelUInt>().is_some()
        || value.downcast_ref::<CelDouble>().is_some()
        || value.downcast_ref::<CelString>().is_some()
}
pub fn preflight(
    host: &mut dyn Host,
    name: &str,
    member: bool,
    args: &[V],
) -> Result<bool, EvalError> {
    if member || args.len() != 2 {
        return Ok(false);
    }
    if matches!(name, "_[_]" | "@has")
        && (args[0].downcast_ref::<CelList>().is_some()
            || args[0].downcast_ref::<CelMap>().is_some())
    {
        let key_len = args[1]
            .downcast_ref::<CelString>()
            .map_or(0, |s| s.inner().len());
        host.tick(
            u64::try_from(add(key_len, 1)?).map_err(|_| overflow())?,
            add(1024, mul(key_len, 8)?)?,
        )?;
        // Invalid composite keys and fractional list indices are rejected by dispatch
        // without converting an entire container into a debug/error representation.
        if args[0].downcast_ref::<CelList>().is_some() && !valid_list_double(args[1].as_ref())
            || args[0].downcast_ref::<CelMap>().is_some() && !valid_map_key(args[1].as_ref())
        {
            return Ok(true);
        }
        if name != "@has"
            && let Some(indexer) = args[0].as_indexer()
            && let Ok(value) = indexer.get(args[1].as_ref())
        {
            eval::charge_clone(host, value.as_ref())?;
        }
        return Ok(true);
    }
    if name == "_+_" && args.iter().all(|a| a.downcast_ref::<CelList>().is_some()) {
        for arg in args {
            if super::collection_cost::weight(host, arg.as_ref(), 0)?.is_none() {
                return Ok(false);
            }
        }
        host.tick(1, 1024)?;
        for arg in args {
            eval::charge_clone(host, arg.as_ref())?
        }
        return Ok(true);
    }
    if matches!(name, "_==_" | "_!=_") {
        let Some(a) = super::collection_cost::weight(host, args[0].as_ref(), 0)? else {
            return Ok(false);
        };
        let Some(b) = super::collection_cost::weight(host, args[1].as_ref(), 0)? else {
            return Ok(false);
        };
        // Concrete maps use hash lookup; list equality compares corresponding items.
        // Pay key hashing and both operand byte scans, not a fictitious deep clone.
        let steps = mul(add(add(a.units, b.units)?, 1)?, 4)?;
        host.tick(u64::try_from(steps).map_err(|_| overflow())?, 1024)?;
        return Ok(true);
    }
    if matches!(name, "@in" | "in" | "_in_") {
        if args[1].downcast_ref::<CelMap>().is_some() {
            if !valid_map_key(args[0].as_ref()) {
                host.tick(1, 1024)?;
                return Ok(true);
            }
            let key = args[0]
                .downcast_ref::<CelString>()
                .map_or(0, |s| s.inner().len());
            host.tick(
                u64::try_from(add(key, 1)?).map_err(|_| overflow())?,
                add(1024, mul(key, 8)?)?,
            )?;
            return Ok(true);
        }
        if args[1].downcast_ref::<CelList>().is_some() {
            let Some(a) = super::collection_cost::weight(host, args[0].as_ref(), 0)? else {
                return Ok(false);
            };
            let Some(b) = super::collection_cost::weight(host, args[1].as_ref(), 0)? else {
                return Ok(false);
            };
            let n = args[1].downcast_ref::<CelList>().unwrap().inner().len();
            let steps = add(mul(add(a.units, 1)?, n)?, mul(add(b.units, 1)?, 2)?)?;
            host.tick(u64::try_from(steps).map_err(|_| overflow())?, 1024)?;
            return Ok(true);
        }
    }
    Ok(false)
}
