//! Bounds for the concrete vendor formatter: temporary formatted values,
//! collection growth and the final growing String are accounted separately.
use super::eval::{EvalError, Host, V};
use cel::common::{
    types::{
        CelBool, CelBytes, CelDouble, CelInt, CelList, CelMap, CelNull, CelString, CelType, CelUInt,
    },
    value::Val,
};

fn overflow() -> EvalError {
    EvalError::fatal("CEL formatting cost overflow")
}
fn add(a: usize, b: usize) -> Result<usize, EvalError> {
    a.checked_add(b).ok_or_else(overflow)
}
fn mul(a: usize, b: usize) -> Result<usize, EvalError> {
    a.checked_mul(b).ok_or_else(overflow)
}
fn work(n: usize) -> Result<u64, EvalError> {
    u64::try_from(n.div_ceil(16)).map_err(|_| overflow())
}

#[derive(Clone, Copy)]
enum Mode {
    String,
    Hex,
    Numeric(u8, usize),
}
struct Bound {
    output: usize,
    allocations: usize,
}

fn scalar(output: usize, allocations: usize) -> Bound {
    Bound {
        output,
        allocations,
    }
}

fn value_bound(
    host: &mut dyn Host,
    value: &dyn Val,
    mode: Mode,
    depth: usize,
) -> Result<Bound, EvalError> {
    if depth > 250 {
        return Err(EvalError::fatal("CEL formatting depth limit"));
    }
    host.tick(1, 0)?;
    if let Some(s) = value.downcast_ref::<CelString>() {
        return match mode {
            Mode::String => {
                host.tick(work(s.inner().len())?, 0)?;
                Ok(scalar(s.inner().len(), add(s.inner().len(), 256)?))
            }
            Mode::Hex => {
                host.tick(u64::try_from(s.inner().len()).map_err(|_| overflow())?, 0)?;
                Ok(scalar(
                    mul(s.inner().len(), 2)?,
                    add(mul(s.inner().len(), 16)?, 256)?,
                ))
            }
            Mode::Numeric(_, _) => Ok(scalar(0, 1024)),
        };
    }
    if let Some(s) = value.downcast_ref::<CelBytes>() {
        return match mode {
            Mode::String => {
                host.tick(work(s.inner().len())?, 0)?;
                Ok(scalar(
                    mul(s.inner().len(), 3)?,
                    add(mul(s.inner().len(), 16)?, 256)?,
                ))
            }
            Mode::Hex => {
                host.tick(u64::try_from(s.inner().len()).map_err(|_| overflow())?, 0)?;
                Ok(scalar(
                    mul(s.inner().len(), 2)?,
                    add(mul(s.inner().len(), 16)?, 256)?,
                ))
            }
            Mode::Numeric(_, _) => Ok(scalar(0, 1024)),
        };
    }
    if value.downcast_ref::<CelInt>().is_some() || value.downcast_ref::<CelUInt>().is_some() {
        return Ok(match mode {
            Mode::String => scalar(20, 256),
            Mode::Hex => scalar(17, 256),
            Mode::Numeric(verb, precision) => match verb {
                b'd' => scalar(20, 256),
                b'b' => scalar(65, 512),
                b'o' => scalar(23, 256),
                b'f' => {
                    let n = add(precision, 22)?;
                    scalar(n, add(mul(n, 4)?, 256)?)
                }
                b'e' => {
                    let n = add(precision, 12)?;
                    scalar(n, add(mul(n, 8)?, 512)?)
                }
                _ => scalar(0, 1024),
            },
        });
    }
    if value.downcast_ref::<CelDouble>().is_some() {
        return Ok(match mode {
            Mode::String | Mode::Numeric(b'd', _) => scalar(328, 1568),
            Mode::Numeric(b'f', precision) => {
                let n = add(precision, 312)?;
                scalar(n, add(mul(n, 4)?, 256)?)
            }
            Mode::Numeric(b'e', precision) => {
                let n = add(precision, 12)?;
                scalar(n, add(mul(n, 8)?, 512)?)
            }
            _ => scalar(0, 1024),
        });
    }
    if value.downcast_ref::<CelBool>().is_some() || value.downcast_ref::<CelNull>().is_some() {
        return Ok(scalar(5, 1024));
    }
    if let Some(t) = value.downcast_ref::<CelType>() {
        return Ok(scalar(t.name().len(), add(t.name().len(), 1024)?));
    }
    if !matches!(mode, Mode::String) {
        return Ok(scalar(0, 1024));
    }
    if let Some(list) = value.downcast_ref::<CelList>() {
        let mut out = add(2, mul(list.inner().len(), 2)?)?;
        let mut allocations = 0;
        for item in list.inner() {
            let bound = value_bound(host, item.as_ref(), Mode::String, depth + 1)?;
            out = add(out, bound.output)?;
            allocations = add(allocations, bound.allocations)?;
        }
        // Vec<String> growth, joined string, then enclosing bracket String.
        allocations = add(
            allocations,
            add(mul(out, 4)?, add(mul(list.inner().len(), 128)?, 256)?)?,
        )?;
        return Ok(scalar(out, allocations));
    }
    if let Some(map) = value.downcast_ref::<CelMap>() {
        let mut out = add(2, mul(map.inner().len(), 4)?)?;
        let mut allocations = 0;
        let mut largest_pair = 0;
        for (key, item) in map.inner() {
            let key = value_bound(host, key.inner(), Mode::String, depth + 1)?;
            let item = value_bound(host, item.as_ref(), Mode::String, depth + 1)?;
            let pair = add(key.output, item.output)?;
            largest_pair = largest_pair.max(pair);
            out = add(out, pair)?;
            allocations = add(allocations, add(key.allocations, item.allocations)?)?;
        }
        let n = map.inner().len();
        let levels = if n < 2 {
            0
        } else {
            usize::BITS as usize - (n - 1).leading_zeros() as usize
        };
        // Sorting uses formatted keys and values. Reserve an upper comparison
        // bound before the vendor runs, independent of key distribution.
        host.tick(
            work(mul(largest_pair, mul(n, add(mul(levels, 2)?, 1)?)?)?)?,
            0,
        )?;
        // Pair Vec, Vec<String>, pair formatting, joined and enclosed output.
        allocations = add(allocations, add(mul(out, 6)?, add(mul(n, 320)?, 512)?)?)?;
        return Ok(scalar(out, allocations));
    }
    // Duration/Timestamp have fixed-size textual representations. Unsupported
    // host types produce a bounded type error, never render their payload.
    Ok(scalar(
        512,
        add(2048, mul(value.get_type().name().len(), 4)?)?,
    ))
}

fn clause(text: &str) -> Option<(Mode, usize)> {
    let bytes = text.as_bytes();
    let mut i = 0;
    let mut precision: usize = 6;
    if bytes.first() == Some(&b'.') {
        i = 1;
        let begin = i;
        precision = 0;
        while let Some(c @ b'0'..=b'9') = bytes.get(i).copied() {
            precision = precision
                .checked_mul(10)?
                .checked_add(usize::from(c - b'0'))?;
            i += 1;
        }
        if i == begin || precision > 100 {
            return None;
        }
    }
    let mode = match bytes.get(i)? {
        b's' => Mode::String,
        b'x' | b'X' => Mode::Hex,
        c @ (b'd' | b'f' | b'e' | b'b' | b'o') => Mode::Numeric(*c, precision),
        _ => return None,
    };
    Some((mode, i + 1))
}

pub fn preflight(host: &mut dyn Host, args: &[V]) -> Result<bool, EvalError> {
    if args.len() != 2 {
        return Ok(false);
    }
    let (Some(format), Some(values)) = (
        args[0].downcast_ref::<CelString>(),
        args[1].downcast_ref::<CelList>(),
    ) else {
        return Ok(false);
    };
    host.tick(
        work(format.inner().len())?
            .checked_add(1)
            .ok_or_else(overflow)?,
        add(mul(values.inner().len(), 64)?, 512)?,
    )?;
    let mut out = format.inner().len();
    let mut rest = format.inner();
    let mut next = 0;
    while let Some(at) = rest.find('%') {
        rest = &rest[at + 1..];
        if let Some(after) = rest.strip_prefix('%') {
            rest = after;
            continue;
        }
        let Some(value) = values.inner().get(next) else {
            break;
        };
        let Some((mode, consumed)) = clause(rest) else {
            break;
        };
        let bound = value_bound(host, value.as_ref(), mode, 0)?;
        host.tick(
            work(bound.output)?.checked_add(1).ok_or_else(overflow)?,
            bound.allocations,
        )?;
        out = add(out, bound.output)?;
        next += 1;
        rest = &rest[consumed..];
    }
    // Initial capacity and every successful growth, not merely retained size.
    host.tick(
        work(out)?.checked_add(1).ok_or_else(overflow)?,
        add(mul(out, 4)?, 1024)?,
    )?;
    Ok(true)
}
