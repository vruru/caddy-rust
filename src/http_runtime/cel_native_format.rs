//! Formatting only where the standard UTF-8 value cannot retain Go bytes.
//! Ordinary numeric/date clauses keep the shared checked formatter and costs.
use super::{cel_native_map, cel_native_string};
use crate::cel_engine::{
    self,
    eval::{self, EvalError, Host, R, V},
};
use bytes::Bytes;
use cel::common::{
    types::{CelBytes, CelList, CelMap, CelString},
    value::Val,
};
use std::sync::Arc;
fn append(host: &mut impl Host, out: &mut Vec<u8>, value: &[u8]) -> Result<(), EvalError> {
    let size = out
        .len()
        .checked_add(value.len())
        .ok_or_else(|| EvalError::fatal("format size overflow"))?;
    if size > out.capacity() {
        let capacity = out.capacity().saturating_mul(2).max(size);
        host.tick(value.len() as u64, capacity)?;
        out.try_reserve_exact(capacity - out.len())
            .map_err(|_| EvalError::fatal("format allocation"))?;
    } else {
        host.tick(value.len() as u64, 0)?;
    }
    out.extend_from_slice(value);
    Ok(())
}
fn contains_raw(
    host: &mut impl Host,
    v: &(dyn Val + 'static),
    depth: usize,
) -> Result<bool, EvalError> {
    host.tick(1, 0)?;
    if depth > 250 {
        return Err(EvalError::fatal("format value depth"));
    }
    if cel_native_string::bytes(v).is_some() && v.downcast_ref::<CelString>().is_none() {
        return Ok(true);
    }
    if let Some(b) = v.downcast_ref::<CelBytes>() {
        host.tick(b.inner().len() as u64, 0)?;
        return Ok(std::str::from_utf8(b.inner()).is_err());
    }
    if cel_native_map::entries(v).is_some() {
        return Ok(true);
    }
    if let Some(list) = v.downcast_ref::<CelList>() {
        for value in list.inner() {
            if contains_raw(host, value.as_ref(), depth + 1)? {
                return Ok(true);
            }
        }
    }
    if let Some(map) = v.downcast_ref::<CelMap>() {
        for (key, value) in map.inner() {
            if contains_raw(host, key.inner(), depth + 1)?
                || contains_raw(host, value.as_ref(), depth + 1)?
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}
/// Parse the same bounded precision and conversion spelling as the pinned
/// strings library. All syntax failures remain ordinary CEL errors.
fn clause(format: &[u8], at: usize) -> Result<(usize, u8), EvalError> {
    let mut i = at + 1;
    if format.get(i) == Some(&b'.') {
        i += 1;
        let begin = i;
        let mut precision = 0usize;
        while let Some(b'0'..=b'9') = format.get(i) {
            precision = precision
                .checked_mul(10)
                .and_then(|p| p.checked_add((format[i] - b'0') as usize))
                .ok_or_else(|| EvalError::new("format precision overflow"))?;
            i += 1;
        }
        if i == begin || precision > 100 {
            return Err(EvalError::new("invalid format precision"));
        }
    }
    let c = *format
        .get(i)
        .ok_or_else(|| EvalError::new("unexpected end of format"))?;
    if !b"sdfebxXo".contains(&c) {
        return Err(EvalError::new("unrecognized formatting clause"));
    }
    Ok((i + 1, c))
}
fn leaf(
    host: &mut impl Host,
    env: &cel::Env,
    format: &str,
    value: &(dyn Val + 'static),
) -> Result<Vec<u8>, EvalError> {
    host.tick(1, 512 + format.len())?;
    eval::charge_clone(host, value)?;
    let args = vec![
        eval::string(format),
        Arc::new(CelList::from(vec![value.clone_as_boxed()])) as V,
    ];
    if cel_engine::builtin_cost::preflight(host, "format", true, &args)?
        == cel_engine::builtin_cost::Pre::Defer
    {
        for v in &args {
            eval::charge_clone(host, v.as_ref())?;
        }
    }
    let out = cel_engine::dispatch::builtin(env, "format", true, &args)?;
    let out = out
        .downcast_ref::<CelString>()
        .ok_or_else(|| EvalError::fatal("format result type"))?;
    host.tick(out.inner().len() as u64, out.inner().len() + 128)?;
    Ok(out.inner().as_bytes().to_vec())
}
fn string(
    host: &mut impl Host,
    env: &cel::Env,
    value: &(dyn Val + 'static),
    depth: usize,
) -> Result<Vec<u8>, EvalError> {
    host.tick(1, 128)?;
    if depth > 250 {
        return Err(EvalError::fatal("format value depth"));
    }
    if let Some(raw) = cel_native_string::bytes(value)
        .or_else(|| value.downcast_ref::<CelBytes>().map(|b| b.inner()))
    {
        host.tick(raw.len() as u64, raw.len())?;
        return Ok(raw.to_vec());
    }
    if let Some(list) = value.downcast_ref::<CelList>() {
        let mut out = Vec::new();
        append(host, &mut out, b"[")?;
        for (i, v) in list.inner().iter().enumerate() {
            if i > 0 {
                append(host, &mut out, b", ")?
            }
            let child = string(host, env, v.as_ref(), depth + 1)?;
            append(host, &mut out, &child)?;
        }
        append(host, &mut out, b"]")?;
        return Ok(out);
    }
    let native = cel_native_map::entries(value);
    let normal = value.downcast_ref::<CelMap>();
    if native.is_some() || normal.is_some() {
        let n = native.map_or_else(|| normal.map_or(0, |m| m.inner().len()), |m| m.len());
        host.tick(n as u64, n.saturating_mul(48).saturating_add(256))?;
        let mut entries = Vec::<(Vec<u8>, Vec<u8>)>::with_capacity(n);
        if let Some(map) = native {
            for (k, v) in map {
                entries.push((
                    string(host, env, k.as_ref(), depth + 1)?,
                    string(host, env, v.as_ref(), depth + 1)?,
                ));
            }
        }
        if let Some(map) = normal {
            for (k, v) in map.inner() {
                entries.push((
                    string(host, env, k.inner(), depth + 1)?,
                    string(host, env, v.as_ref(), depth + 1)?,
                ));
            }
        }
        let width = entries.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
        host.tick(
            (n as u64)
                .saturating_mul(n.max(1).ilog2() as u64 + 1)
                .saturating_mul(width as u64 + 1),
            0,
        )?;
        host.tick(0, n.saturating_mul(48))?;
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        let mut out = Vec::new();
        append(host, &mut out, b"{")?;
        for (i, (k, v)) in entries.iter().enumerate() {
            if i > 0 {
                append(host, &mut out, b", ")?
            }
            append(host, &mut out, k)?;
            append(host, &mut out, b": ")?;
            append(host, &mut out, v)?;
        }
        append(host, &mut out, b"}")?;
        return Ok(out);
    }
    leaf(host, env, "%s", value)
}
pub(super) fn operation(host: &mut impl Host, env: &cel::Env, args: &[V]) -> Option<R> {
    if args.len() != 2 {
        return None;
    }
    let format = cel_native_string::bytes(args[0].as_ref())?;
    let list = args[1].downcast_ref::<CelList>()?;
    let result: Result<Option<V>, EvalError> = (|| {
        host.tick(format.len() as u64 + 1, 256)?;
        let mut needed = args[0].downcast_ref::<CelString>().is_none();
        let mut at = 0;
        let mut arg = 0;
        while let Some(i) = format[at..].iter().position(|b| *b == b'%').map(|i| i + at) {
            if format.get(i + 1) == Some(&b'%') {
                at = i + 2;
                continue;
            }
            let (end, _) = clause(format, i)?;
            let value = list
                .inner()
                .get(arg)
                .ok_or_else(|| EvalError::new("format argument index out of range"))?;
            needed |= contains_raw(host, value.as_ref(), 0)?;
            arg += 1;
            at = end;
        }
        if !needed {
            return Ok(None);
        }
        let mut out = Vec::new();
        let mut at = 0;
        let mut arg = 0;
        while let Some(i) = format[at..].iter().position(|b| *b == b'%').map(|i| i + at) {
            append(host, &mut out, &format[at..i])?;
            if format.get(i + 1) == Some(&b'%') {
                append(host, &mut out, b"%")?;
                at = i + 2;
                continue;
            }
            let (end, conversion) = clause(format, i)?;
            let value = list
                .inner()
                .get(arg)
                .ok_or_else(|| EvalError::new("format argument index out of range"))?;
            let rendered = if conversion == b's' {
                string(host, env, value.as_ref(), 0)?
            } else if matches!(conversion, b'x' | b'X')
                && let Some(raw) = cel_native_string::bytes(value.as_ref())
                    .or_else(|| value.downcast_ref::<CelBytes>().map(|b| b.inner()))
            {
                let size = raw
                    .len()
                    .checked_mul(2)
                    .ok_or_else(|| EvalError::fatal("format size overflow"))?;
                host.tick(size as u64, size)?;
                let mut bytes = Vec::with_capacity(size);
                let alphabet = if conversion == b'x' {
                    b"0123456789abcdef"
                } else {
                    b"0123456789ABCDEF"
                };
                for b in raw {
                    bytes.push(alphabet[(b >> 4) as usize]);
                    bytes.push(alphabet[(b & 15) as usize]);
                }
                bytes
            } else {
                let fmt = std::str::from_utf8(&format[i..end])
                    .map_err(|_| EvalError::new("invalid format clause"))?;
                leaf(host, env, fmt, value.as_ref())?
            };
            append(host, &mut out, &rendered)?;
            arg += 1;
            at = end;
        }
        append(host, &mut out, &format[at..])?;
        host.tick(0, out.len().saturating_add(128))?;
        Ok(Some(cel_native_string::value(Bytes::from(out))))
    })();
    match result {
        Ok(Some(v)) => Some(Ok(v)),
        Ok(None) => None,
        Err(e) => Some(Err(e)),
    }
}
