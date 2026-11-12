//! Concrete scalar prepayment. Opaque host values keep their host accounting.
use super::eval::{EvalError, Host, V};
use cel::common::{
    types::{
        CelBool, CelBytes, CelDouble, CelDuration, CelInt, CelList, CelMap, CelNull, CelString,
        CelTimestamp, CelType, CelUInt,
    },
    value::Val,
};
fn overflow() -> EvalError {
    EvalError::fatal("CEL scalar cost overflow")
}
fn add(a: usize, b: usize) -> Result<usize, EvalError> {
    a.checked_add(b).ok_or_else(overflow)
}
fn mul(a: usize, b: usize) -> Result<usize, EvalError> {
    a.checked_mul(b).ok_or_else(overflow)
}
fn numeric(v: &dyn Val) -> bool {
    v.downcast_ref::<CelInt>().is_some()
        || v.downcast_ref::<CelUInt>().is_some()
        || v.downcast_ref::<CelDouble>().is_some()
}
fn time(v: &dyn Val) -> bool {
    v.downcast_ref::<CelDuration>().is_some() || v.downcast_ref::<CelTimestamp>().is_some()
}
fn leaf(v: &dyn Val) -> bool {
    numeric(v)
        || time(v)
        || v.downcast_ref::<CelBool>().is_some()
        || v.downcast_ref::<CelBytes>().is_some()
        || v.downcast_ref::<CelNull>().is_some()
        || v.downcast_ref::<CelString>().is_some()
        || v.downcast_ref::<CelType>().is_some()
}
fn len(v: &dyn Val) -> usize {
    v.downcast_ref::<CelString>()
        .map(|s| s.inner().len())
        .or_else(|| v.downcast_ref::<CelBytes>().map(|s| s.inner().len()))
        .or_else(|| v.downcast_ref::<CelType>().map(|s| s.name().len()))
        .unwrap_or(0)
}
fn pay(host: &mut dyn Host, n: usize, factor: usize) -> Result<(), EvalError> {
    host.tick(
        u64::try_from(add(n, 1)?).map_err(|_| overflow())?,
        add(1024, mul(n, factor)?)?,
    )
}
pub fn preflight(
    host: &mut dyn Host,
    name: &str,
    member: bool,
    args: &[V],
) -> Result<bool, EvalError> {
    if !member
        && args.len() == 1
        && matches!(
            name,
            "bool" | "bytes" | "double" | "duration" | "int" | "string" | "timestamp" | "uint"
        )
        && leaf(args[0].as_ref())
    {
        // Duration's parser uses a growing component Vec, not just a scalar output.
        // Its shortest component consumes two bytes; cumulative Vec capacities need
        // fewer than 32 allocated bytes per source byte, including reallocations.
        let length = len(args[0].as_ref());
        match name {
            "duration" => pay(host, length, 32)?,
            "string" | "bytes" => host.tick(
                u64::try_from(length.div_ceil(16) + 1).map_err(|_| overflow())?,
                add(1024, length)?,
            )?,
            "bool" => host.tick(1, 1024)?,
            _ => host.tick(
                u64::try_from(add(length, 1)?).map_err(|_| overflow())?,
                1024,
            )?,
        }
        return Ok(true);
    }
    if member
        && matches!(args.len(), 1 | 2)
        && matches!(
            name,
            "getDate"
                | "getDayOfMonth"
                | "getDayOfWeek"
                | "getDayOfYear"
                | "getFullYear"
                | "getHours"
                | "getMilliseconds"
                | "getMinutes"
                | "getMonth"
                | "getSeconds"
        )
        && time(args[0].as_ref())
    {
        if args.len() == 2 && args[1].downcast_ref::<CelString>().is_none() {
            return Ok(false);
        }
        pay(host, args.get(1).map_or(0, |v| len(v.as_ref())), 8)?;
        return Ok(true);
    }
    if !member && matches!(name, "math.@max" | "math.@min") && matches!(args.len(), 1 | 2) {
        if args.len() == 1
            && let Some(list) = args[0].downcast_ref::<CelList>()
        {
            host.tick(1, 1024)?;
            for v in list.inner() {
                host.tick(1, 0)?;
                if !numeric(v.as_ref()) {
                    // The vendor rejects this type before examining any later
                    // elements. Do not clone or meter an untouched large tail.
                    if matches!(
                        v.get_type().kind(),
                        cel::common::types::Kind::Int
                            | cel::common::types::Kind::UInt
                            | cel::common::types::Kind::Double
                    ) {
                        return Ok(false); // Arbitrary host numeric traits.
                    }
                    pay(host, v.get_type().name().len(), 16)?;
                    return Ok(true);
                }
            }
            return Ok(true);
        }
        if args.iter().all(|v| numeric(v.as_ref())) {
            host.tick(1, 1024)?;
            return Ok(true);
        }
    }
    if !member
        && matches!(args.len(), 1 | 2)
        && matches!(
            name,
            "math.abs"
                | "math.bitAnd"
                | "math.bitNot"
                | "math.bitOr"
                | "math.bitShiftLeft"
                | "math.bitShiftRight"
                | "math.bitXor"
                | "math.ceil"
                | "math.floor"
                | "math.isFinite"
                | "math.isInf"
                | "math.isNaN"
                | "math.round"
                | "math.sign"
                | "math.sqrt"
                | "math.trunc"
        )
        && args.iter().all(|v| leaf(v.as_ref()) || v.downcast_ref::<CelList>().is_some() || v.downcast_ref::<CelMap>().is_some())
    {
        // Known wrong scalar operands fail overload selection by type alone;
        // the dispatcher does not traverse container payloads for that error.
        host.tick(1, 1024)?;
        return Ok(true);
    }
    if !member
        && name == "_+_"
        && args.len() == 2
        && args.iter().all(|v| numeric(v.as_ref()) || time(v.as_ref()))
    {
        host.tick(1, 1024)?;
        return Ok(true);
    }
    if !member
        && matches!(args.len(), 1 | 2)
        && matches!(name, "!_" | "-_" | "_*_" | "_-_" | "_/_" | "_%_")
        && args.iter().all(|v| leaf(v.as_ref()))
    {
        for v in args {
            pay(host, len(v.as_ref()), 16)?
        }
        return Ok(true);
    }
    if !member
        && args.len() == 2
        && matches!(name, "_==_" | "_!=_" | "_<_" | "_<=_" | "_>_" | "_>=_")
        && args.iter().all(|v| leaf(v.as_ref()))
    {
        let length = len(args[0].as_ref()).min(len(args[1].as_ref()));
        // Comparisons borrow operands; only a scalar Bool (or a small ordinary
        // overload error) is allocated. SIMD byte comparison work is metered
        // in the same sixteen-byte units as the other concrete string paths.
        host.tick(
            u64::try_from(length.div_ceil(16) + 1).map_err(|_| overflow())?,
            1024,
        )?;
        return Ok(true);
    }
    Ok(false)
}
