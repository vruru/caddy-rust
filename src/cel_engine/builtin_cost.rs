use super::eval::{EvalError, Host, V};
use cel::common::{
    types::{CelBytes, CelInt, CelList, CelMap, CelString},
    value::Val,
};
use std::mem::size_of;

#[derive(Debug, PartialEq, Eq)]
pub enum Pre {
    Charged,
    Defer,
}

fn overflow() -> EvalError {
    EvalError::fatal("arithmetic overflow")
}

fn add(a: usize, b: usize) -> Result<usize, EvalError> {
    a.checked_add(b).ok_or_else(overflow)
}

fn mul(a: usize, b: usize) -> Result<usize, EvalError> {
    a.checked_mul(b).ok_or_else(overflow)
}

fn work(bytes: usize) -> Result<u64, EvalError> {
    u64::try_from(bytes.div_ceil(16)).map_err(|_| overflow())
}

pub fn preflight(
    host: &mut dyn Host,
    name: &str,
    member: bool,
    args: &[V],
) -> Result<Pre, EvalError> {
    if !member && super::dispatch::shape_error(name,args) {
        host.tick(1,1024)?;
        return Ok(Pre::Charged);
    }
    if super::scalar_cost::preflight(host, name, member, args)? {
        return Ok(Pre::Charged);
    }
    if super::structural_cost::preflight(host, name, member, args)? {
        return Ok(Pre::Charged);
    }
    if super::collection_cost::preflight(host, name, member, args)? {
        return Ok(Pre::Charged);
    }
    if name == "format" && member && super::format_cost::preflight(host, args)? {
        return Ok(Pre::Charged);
    }
    if let Some(result) = linear_strings(host, name, member, args) {
        return result;
    }
    if name == "_+_" && !member && args.len() == 2 {
        let length = if let (Some(a), Some(b)) = (text(&args[0]), text(&args[1])) {
            Some(add(a.len(), b.len())?)
        } else if let (Some(a), Some(b)) = (
            args[0].downcast_ref::<CelBytes>(),
            args[1].downcast_ref::<CelBytes>(),
        ) {
            Some(add(a.inner().len(), b.inner().len())?)
        } else {
            None
        };
        if let Some(length) = length {
            host.tick(
                work(length)?.checked_add(1).ok_or_else(overflow)?,
                add(length, 256)?,
            )?;
            return Ok(Pre::Charged);
        }
    }
    if name == "slice"
        && member
        && args.len() == 3
        && let (Some(list), Some(start), Some(end)) = (
            args[0].downcast_ref::<CelList>(),
            args[1].downcast_ref::<CelInt>(),
            args[2].downcast_ref::<CelInt>(),
        )
    {
        let (start, end) = (*start.inner(), *end.inner());
        if start < 0 || end < start {
            host.tick(1, 512)?;
        } else {
            // The vendor scans all elements but only clones the selected
            // range; an untouched large tail must not cost a full clone.
            host.tick(
                u64::try_from(list.inner().len())
                    .map_err(|_| overflow())?
                    .checked_add(1)
                    .ok_or_else(overflow)?,
                512,
            )?;
            let start = usize::try_from(start)
                .map_err(|_| overflow())?
                .min(list.inner().len());
            let end = usize::try_from(end)
                .map_err(|_| overflow())?
                .min(list.inner().len());
            host.tick(0, mul(end - start, 64)?)?;
            for value in &list.inner()[start..end] {
                super::eval::charge_clone(host, value.as_ref())?;
            }
        }
        return Ok(Pre::Charged);
    }
    if member && matches!(name, "charAt" | "substring" | "indexOf" | "lastIndexOf") {
        return string_positions(host, name, args);
    }
    if member
        && args.len() == 2
        && matches!(name, "contains" | "startsWith" | "endsWith")
        && let (Some(source), Some(needle)) = (text(&args[0]), text(&args[1]))
    {
        host.tick(
            work(add(source.len(), needle.len())?)?
                .checked_add(1)
                .ok_or_else(overflow)?,
            256,
        )?;
        return Ok(Pre::Charged);
    }
    if name == "type" && !member && args.len() == 1 {
        host.tick(1, add(args[0].get_type().name().len(), 256)?)?;
        return Ok(Pre::Charged);
    }
    if name == "size" && args.len() == 1 {
        let value = &args[0];
        let steps = if let Some(text) = value.downcast_ref::<CelString>() {
            work(text.inner().len())?
                .checked_add(1)
                .ok_or_else(overflow)?
        } else if value.downcast_ref::<CelList>().is_some()
            || value.downcast_ref::<CelMap>().is_some()
            || value.downcast_ref::<CelBytes>().is_some()
        {
            1
        } else {
            return Ok(Pre::Defer);
        };
        host.tick(steps, 256)?;
        return Ok(Pre::Charged);
    }
    if name == "replace" && member && matches!(args.len(), 3 | 4) {
        return replace(host, args);
    }
    if name == "join" && member && matches!(args.len(), 1 | 2) {
        return join(host, args);
    }
    if name == "split" && member && matches!(args.len(), 2 | 3) {
        return split(host, args);
    }
    if member || name != "lists.range" {
        return Ok(Pre::Defer);
    }
    if args.len() != 1 {
        return Ok(Pre::Defer);
    }
    let int: &CelInt = match args[0].downcast_ref::<CelInt>() {
        Some(v) => v,
        None => return Ok(Pre::Defer),
    };
    let raw: i64 = *int.inner();
    if raw < 0 {
        // Negative sizes are ordinary CEL errors, with their error allocation
        // prepaid as well. Large nonnegative sizes pay before vendor entry.
        host.tick(1, 1024)?;
        return Ok(Pre::Charged);
    }
    let n: usize = usize::try_from(raw).map_err(|_| overflow())?;
    let unit = add(size_of::<Box<dyn Val>>(), size_of::<CelInt>())?;
    let bytes = add(mul(n, unit)?, 256)?;
    let steps = u64::try_from(n)
        .map_err(|_| overflow())?
        .checked_add(1)
        .ok_or_else(overflow)?;
    host.tick(steps, bytes)?;
    Ok(Pre::Charged)
}

fn linear_strings(
    host: &mut dyn Host,
    name: &str,
    member: bool,
    args: &[V],
) -> Option<Result<Pre, EvalError>> {
    let factor = if member
        && args.len() == 1
        && matches!(name, "lowerAscii" | "upperAscii" | "trim" | "reverse")
    {
        4
    } else if !member && args.len() == 1 && name == "strings.quote" {
        8
    } else {
        return None;
    };
    let source = text(&args[0])?;
    Some((|| {
        let bytes = add(mul(source.len(), factor)?, 256)?;
        let steps = work(source.len())?
            .checked_mul(2)
            .and_then(|n| n.checked_add(1))
            .ok_or_else(overflow)?;
        host.tick(steps, bytes)?;
        Ok(Pre::Charged)
    })())
}

fn text(value: &V) -> Option<&str> {
    value.downcast_ref::<CelString>().map(CelString::inner)
}

fn string_positions(host: &mut dyn Host, name: &str, args: &[V]) -> Result<Pre, EvalError> {
    let Some(source) = args.first().and_then(text) else {
        return Ok(Pre::Defer);
    };
    match name {
        "charAt" if args.len() == 2 && args[1].downcast_ref::<CelInt>().is_some() => {
            host.tick(
                work(source.len())?
                    .checked_mul(2)
                    .and_then(|n| n.checked_add(1))
                    .ok_or_else(overflow)?,
                512,
            )?;
            Ok(Pre::Charged)
        }
        "substring"
            if matches!(args.len(), 2 | 3)
                && args[1..]
                    .iter()
                    .all(|v| v.downcast_ref::<CelInt>().is_some()) =>
        {
            // Pay for the range scan before touching input-sized data. Only the
            // selected byte range can become an owned output String.
            host.tick(
                work(source.len())?
                    .checked_mul(4)
                    .and_then(|n| n.checked_add(1))
                    .ok_or_else(overflow)?,
                0,
            )?;
            let count = source.chars().count();
            let start = *args[1].downcast_ref::<CelInt>().unwrap().inner();
            let end = if args.len() == 3 {
                *args[2].downcast_ref::<CelInt>().unwrap().inner()
            } else {
                i64::try_from(count).map_err(|_| overflow())?
            };
            if start < 0 || end < start || usize::try_from(end).map_or(true, |n| n > count) {
                host.tick(1, 512)?;
                return Ok(Pre::Charged);
            }
            let at = |i: usize| {
                source
                    .char_indices()
                    .nth(i)
                    .map_or(source.len(), |(byte, _)| byte)
            };
            let len = at(end as usize) - at(start as usize);
            host.tick(
                work(len)?.checked_add(1).ok_or_else(overflow)?,
                add(mul(len, 4)?, 256)?,
            )?;
            Ok(Pre::Charged)
        }
        "indexOf" | "lastIndexOf"
            if matches!(args.len(), 2 | 3)
                && args.get(1).and_then(text).is_some()
                && (args.len() == 2 || args[2].downcast_ref::<CelInt>().is_some()) =>
        {
            let needle = text(&args[1]).unwrap();
            let total = add(source.len(), needle.len())?;
            // The vendor currently collects both rune vectors, including when
            // a later offset check fails. Reserve their growth before dispatch.
            host.tick(
                work(total)?.checked_add(1).ok_or_else(overflow)?,
                add(mul(total, 16)?, 512)?,
            )?;
            let n = source.chars().count();
            let m = needle.chars().count();
            let candidates = if m == 0 || m > n { 0 } else { n - m + 1 };
            host.tick(
                work(mul(candidates, m)?)?
                    .checked_add(1)
                    .ok_or_else(overflow)?,
                0,
            )?;
            Ok(Pre::Charged)
        }
        _ => Ok(Pre::Defer),
    }
}

fn replace(host: &mut dyn Host, args: &[V]) -> Result<Pre, EvalError> {
    let (Some(source), Some(from), Some(to)) = (text(&args[0]), text(&args[1]), text(&args[2]))
    else {
        return Ok(Pre::Defer);
    };
    let limit = if args.len() == 4 {
        let Some(n) = args[3].downcast_ref::<CelInt>() else {
            return Ok(Pre::Defer);
        };
        if *n.inner() < 0 {
            None
        } else {
            Some(usize::try_from(*n.inner()).map_err(|_| overflow())?)
        }
    } else {
        None
    };
    let count = if limit == Some(0) {
        0
    } else {
        host.tick(
            work(add(source.len(), from.len())?)?
                .checked_add(1)
                .ok_or_else(overflow)?,
            0,
        )?;
        if from.is_empty() {
            add(source.chars().count(), 1)?.min(limit.unwrap_or(usize::MAX))
        } else {
            source
                .matches(from)
                .take(limit.unwrap_or(usize::MAX))
                .count()
        }
    };
    let length = if to.len() >= from.len() {
        add(source.len(), mul(count, to.len() - from.len())?)?
    } else {
        source
            .len()
            .checked_sub(mul(count, from.len() - to.len())?)
            .ok_or_else(overflow)?
    };
    // Include the old/new String growth allocations, not just final length.
    let bytes = add(mul(source.len().max(length), 4)?, 256)?;
    let steps = work(length)?
        .checked_add(u64::try_from(count).map_err(|_| overflow())?)
        .and_then(|n| n.checked_add(1))
        .ok_or_else(overflow)?;
    host.tick(steps, bytes)?;
    Ok(Pre::Charged)
}

fn join(host: &mut dyn Host, args: &[V]) -> Result<Pre, EvalError> {
    let Some(list) = args[0].downcast_ref::<CelList>() else {
        return Ok(Pre::Defer);
    };
    let separator = if args.len() == 2 {
        let Some(s) = text(&args[1]) else {
            return Ok(Pre::Defer);
        };
        s
    } else {
        ""
    };
    // Preserve the vendor's ordinary type error before output-size accounting.
    if list
        .inner()
        .iter()
        .any(|value| value.downcast_ref::<CelString>().is_none())
    {
        return Ok(Pre::Defer);
    }
    let mut length = 0;
    for value in list.inner() {
        length = add(
            length,
            value
                .downcast_ref::<CelString>()
                .expect("validated string list")
                .inner()
                .len(),
        )?;
    }
    let n = list.inner().len();
    if n > 0 {
        length = add(length, mul(n - 1, separator.len())?)?;
    }
    // Vec<&str> may grow geometrically; charge its cumulative allocations.
    let bytes = add(add(mul(n, 64)?, length)?, 256)?;
    let steps = u64::try_from(n)
        .map_err(|_| overflow())?
        .checked_add(work(length)?)
        .and_then(|n| n.checked_add(1))
        .ok_or_else(overflow)?;
    host.tick(steps, bytes)?;
    Ok(Pre::Charged)
}

fn split(host: &mut dyn Host, args: &[V]) -> Result<Pre, EvalError> {
    let (Some(source), Some(separator)) = (text(&args[0]), text(&args[1])) else {
        return Ok(Pre::Defer);
    };
    let limit = if args.len() == 3 {
        let Some(n) = args[2].downcast_ref::<CelInt>() else {
            return Ok(Pre::Defer);
        };
        if *n.inner() < 0 {
            None
        } else {
            Some(usize::try_from(*n.inner()).map_err(|_| overflow())?)
        }
    } else {
        None
    };
    if limit == Some(0) {
        host.tick(1, 256)?;
        return Ok(Pre::Charged);
    }
    host.tick(
        work(add(source.len(), separator.len())?)?
            .checked_add(1)
            .ok_or_else(overflow)?,
        0,
    )?;
    let count = if separator.is_empty() {
        source.chars().count().min(limit.unwrap_or(usize::MAX))
    } else {
        add(
            source
                .matches(separator)
                .take(limit.map_or(usize::MAX, |n| n - 1))
                .count(),
            1,
        )?
    };
    // The temporary slice vector can cumulatively allocate 64 bytes per part;
    // the result vector and boxed strings add another 40, plus payload bytes.
    let bytes = add(add(mul(count, 104)?, source.len())?, 256)?;
    let steps = u64::try_from(count)
        .map_err(|_| overflow())?
        .checked_add(work(source.len())?)
        .and_then(|n| n.checked_add(1))
        .ok_or_else(overflow)?;
    host.tick(steps, bytes)?;
    Ok(Pre::Charged)
}
