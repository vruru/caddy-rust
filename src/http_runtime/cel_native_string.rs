//! Go strings may contain arbitrary bytes. Preserve those bytes at the request
//! boundary instead of changing invalid UTF-8 into a different CEL string.
use crate::cel_engine::eval::{self, EvalError, Host, R, V};
use bytes::Bytes;
use cel::common::{
    types::{CelBytes, CelInt, CelList, CelString, CelType, Type},
    value::{StaticVal, Val},
};
use std::sync::Arc;
#[derive(Clone, Debug)]
pub(super) struct RawString(Bytes);
impl StaticVal for RawString {}
impl Val for RawString {
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }
    fn get_type(&self) -> &Type {
        CelString::cel_type()
    }
    fn cel_type() -> &'static Type {
        CelString::cel_type()
    }
    fn equals(&self, other: &dyn Val) -> bool {
        bytes(other).is_some_and(|b| b == self.0.as_ref())
    }
    fn clone_as_boxed<'v>(&self) -> Box<dyn Val + 'v>
    where
        Self: 'v,
    {
        Box::new(self.clone())
    }
}
pub(super) fn value(data: Bytes) -> V {
    match std::str::from_utf8(&data) {
        Ok(s) => eval::string(s),
        Err(_) => Arc::new(RawString(data)),
    }
}
pub(super) fn bytes(v: &dyn Val) -> Option<&[u8]> {
    if let Some(v) = v.downcast_ref::<RawString>() {
        Some(&v.0)
    } else {
        v.downcast_ref::<CelString>().map(|v| v.inner().as_bytes())
    }
}
/// Go utf8.DecodeRuneInString consumes one byte for every encoding error.
fn rune(input: &[u8]) -> (char, usize) {
    let Some(&b) = input.first() else {
        return ('\0', 0);
    };
    let n = match b {
        0..=127 => 1,
        0xc2..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf4 => 4,
        _ => 0,
    };
    if n > 0
        && input.len() >= n
        && let Ok(s) = std::str::from_utf8(&input[..n])
    {
        return (s.chars().next().unwrap_or('\0'), n);
    }
    ('\u{fffd}', 1)
}
pub(super) fn regex_text(v: &dyn Val) -> Option<String> {
    let bytes = bytes(v)?;
    let mut s = String::with_capacity(bytes.len().saturating_mul(3));
    let mut i = 0;
    while i < bytes.len() {
        let (c, n) = rune(&bytes[i..]);
        s.push(c);
        i += n;
    }
    Some(s)
}
fn int(v: i64) -> R {
    Ok(Arc::new(CelInt::from(v)))
}
fn output(host: &mut impl Host, data: &[u8]) -> R {
    host.tick(data.len().div_ceil(16) as u64 + 1, data.len().saturating_add(256))?;
    Ok(value(Bytes::copy_from_slice(data)))
}
fn scan_cost(host: &mut impl Host, a: &[u8], b: &[u8]) -> Result<(), EvalError> {
    host.tick(
        (a.len() as u64)
            .saturating_mul(b.len().max(1) as u64)
            .saturating_add(1),
        256,
    )
}
pub(super) fn operation(
    host: &mut impl Host,
    env: &cel::Env,
    name: &str,
    member: bool,
    args: &[V],
) -> Option<R> {
    let raw = args.iter().any(|v| v.downcast_ref::<RawString>().is_some())
        || name == "join"
            && args
                .first()
                .and_then(|v| v.downcast_ref::<CelList>())
                .is_some_and(|v| {
                    v.inner()
                        .iter()
                        .any(|v| v.downcast_ref::<RawString>().is_some())
                });
    if !raw {
        return None;
    }
    Some((|| {
        // These CEL extensions explicitly convert []rune in the pinned Go
        // implementation. Only this call-local view replaces invalid octets.
        if matches!(
            name,
            "lowerAscii"
                | "upperAscii"
                | "reverse"
                | "charAt"
                | "substring"
                | "indexOf"
                | "lastIndexOf"
                | "strings.quote"
        ) {
            if name == "lastIndexOf"
                && args.len() == 2
                && let (Some(a), Some(b)) = (bytes(args[0].as_ref()), bytes(args[1].as_ref()))
                && a.len() < b.len()
            {
                return int(-1);
            }
            let mut normalized = Vec::with_capacity(args.len());
            host.tick(
                args.len() as u64,
                args.len().saturating_mul(32).saturating_add(256),
            )?;
            for value in args {
                if let Some(raw) = value.downcast_ref::<RawString>() {
                    host.tick(
                        raw.0.len() as u64,
                        raw.0.len().saturating_mul(6).saturating_add(256),
                    )?;
                    let text = regex_text(value.as_ref())
                        .ok_or_else(|| EvalError::new("string argument"))?;
                    normalized.push(eval::string(&text));
                } else {
                    normalized.push(value.clone())
                }
            }
            if crate::cel_engine::builtin_cost::preflight(host, name, member, &normalized)?
                == crate::cel_engine::builtin_cost::Pre::Defer
            {
                for value in &normalized {
                    eval::charge_clone(host, value.as_ref())?;
                }
            }
            return crate::cel_engine::dispatch::builtin(env, name, member, &normalized);
        }
        if name == "split" {
            return split(host, args);
        }
        if name == "replace" {
            return replace(host, args);
        }
        if name == "join" {
            return join(host, args);
        }
        if matches!(name, "@in" | "@caddy_const_in")
            && args.len() == 2
            && args[1]
                .downcast_ref::<cel::common::types::CelMap>()
                .is_some()
        {
            host.tick(1, 256)?;
            return Ok(eval::boolean(false));
        }
        if matches!(name, "@in" | "@caddy_const_in")
            && args.len() == 2
            && let Some(list) = args[1].downcast_ref::<CelList>()
        {
            host.tick(list.inner().len() as u64 + 1, 256)?;
            for value in list.inner() {
                if let (Some(a), Some(b)) = (bytes(args[0].as_ref()), bytes(value.as_ref())) {
                    host.tick(a.len().min(b.len()) as u64, 0)?;
                    if a == b {
                        return Ok(eval::boolean(true));
                    }
                }
            }
            return Ok(eval::boolean(false));
        }
        if args.len() == 1 {
            let a = bytes(args[0].as_ref())
                .ok_or_else(|| EvalError::new("string argument required"))?;
            match name {
                "type" => {
                    host.tick(1, 256)?;
                    return Ok(Arc::new(CelType::new("string")) as V);
                }
                "string" => {
                    host.tick(1, 256)?;
                    return Ok(args[0].clone());
                }
                "bytes" => {
                    host.tick(a.len().div_ceil(16) as u64 + 1, a.len().saturating_add(256))?;
                    return Ok(Arc::new(CelBytes::from(a.to_vec())) as V);
                }
                "size" => {
                    host.tick(a.len() as u64, 256)?;
                    let (mut i, mut count) = (0, 0);
                    while i < a.len() {
                        i += rune(&a[i..]).1;
                        count += 1;
                    }
                    return int(count);
                }
                "trim" => {
                    host.tick(a.len() as u64, 256)?;
                    let (mut start, mut end, mut i) = (0, 0, 0);
                    let mut leading = true;
                    while i < a.len() {
                        let (c, n) = rune(&a[i..]);
                        if leading && c.is_whitespace() {
                            start = i + n
                        } else {
                            leading = false
                        }
                        if !c.is_whitespace() {
                            end = i + n;
                        }
                        i += n;
                    }
                    return output(host, &a[start..end.max(start)]);
                }
                _ => {}
            }
        }
        if args.len() == 2 && matches!(name, "_==_" | "_!=_") {
            let equal = match (bytes(args[0].as_ref()), bytes(args[1].as_ref())) {
                (Some(a), Some(b)) => {
                    host.tick(a.len().min(b.len()).div_ceil(16) as u64 + 1, 256)?;
                    a == b
                }
                _ => false,
            };
            return Ok(eval::boolean(equal == (name == "_==_")));
        }
        if args.len() == 2 {
            let a = bytes(args[0].as_ref())
                .ok_or_else(|| EvalError::new("string argument required"))?;
            let b = bytes(args[1].as_ref())
                .ok_or_else(|| EvalError::new("string argument required"))?;
            match name {
                "_<_" | "_<=_" | "_>_" | "_>=_" => {
                    host.tick(a.len().min(b.len()).div_ceil(16) as u64 + 1, 256)?;
                    return Ok(eval::boolean(match name {
                        "_<_" => a < b,
                        "_<=_" => a <= b,
                        "_>_" => a > b,
                        _ => a >= b,
                    }));
                }
                "_+_" => {
                    let n = a
                        .len()
                        .checked_add(b.len())
                        .ok_or_else(|| EvalError::fatal("string length overflow"))?;
                    host.tick(n.div_ceil(16) as u64 + 1, n.saturating_add(256))?;
                    let mut out = Vec::with_capacity(n);
                    out.extend_from_slice(a);
                    out.extend_from_slice(b);
                    return Ok(value(Bytes::from(out)));
                }
                "contains" => {
                    scan_cost(host, a, b)?;
                    return Ok(eval::boolean(
                        b.is_empty() || a.windows(b.len()).any(|x| x == b),
                    ));
                }
                "startsWith" | "endsWith" => {
                    host.tick(b.len() as u64 + 1, 256)?;
                    return Ok(eval::boolean(if name == "startsWith" {
                        a.starts_with(b)
                    } else {
                        a.ends_with(b)
                    }));
                }
                _ => {}
            }
        }
        Err(EvalError::new(format!(
            "Go byte string operation {name} not yet implemented"
        )))
    })())
}

fn input(args: &[V], i: usize) -> Result<&[u8], EvalError> {
    args.get(i)
        .and_then(|v| bytes(v.as_ref()))
        .ok_or_else(|| EvalError::new("string argument required"))
}
fn limit(args: &[V], i: usize) -> Result<Option<usize>, EvalError> {
    match args.get(i) {
        None => Ok(None),
        Some(v) => {
            let n = v
                .downcast_ref::<CelInt>()
                .ok_or_else(|| EvalError::new("integer count required"))?
                .inner();
            Ok(usize::try_from(*n).ok())
        }
    }
}
fn find(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() {
        return Some(from);
    };
    hay.get(from..)?
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|i| from + i)
}
fn split(host: &mut impl Host, args: &[V]) -> R {
    if !(2..=3).contains(&args.len()) {
        return Err(EvalError::new("split argument count"));
    }
    let a = input(args, 0)?;
    let sep = input(args, 1)?;
    let cap = limit(args, 2)?.unwrap_or(usize::MAX);
    scan_cost(host, a, sep)?;
    let upper = a.len().saturating_add(1).min(cap);
    host.tick(
        upper as u64,
        upper
            .saturating_mul(192)
            .saturating_add(a.len().saturating_mul(3))
            .saturating_add(256),
    )?;
    let mut list: Vec<Box<dyn Val>> = Vec::new();
    let mut push = |part: &[u8]| {
        list.push(value(Bytes::copy_from_slice(part)).clone_as_boxed());
    };
    if cap > 0 {
        let mut at = 0;
        if sep.is_empty() {
            let mut count = 0;
            while at < a.len() {
                let end = if count + 1 == cap {
                    a.len()
                } else {
                    at + rune(&a[at..]).1
                };
                push(&a[at..end]);
                at = end;
                count += 1;
            }
        } else {
            let mut count = 0;
            while count + 1 < cap {
                let Some(end) = find(a, sep, at) else { break };
                push(&a[at..end]);
                at = end + sep.len();
                count += 1;
            }
            push(&a[at..]);
        }
    }
    Ok(Arc::new(CelList::from(list)))
}
fn replace(host: &mut impl Host, args: &[V]) -> R {
    if !(3..=4).contains(&args.len()) {
        return Err(EvalError::new("replace argument count"));
    }
    let a = input(args, 0)?;
    let old = input(args, 1)?;
    let new = input(args, 2)?;
    let cap = limit(args, 3)?.unwrap_or(usize::MAX);
    scan_cost(host, a, old)?;
    let mut count = 0usize;
    let mut at = 0;
    if old.is_empty() {
        count = 1;
        while at < a.len() && count < cap {
            at += rune(&a[at..]).1;
            count += 1;
        }
        count = count.min(cap)
    } else {
        while count < cap {
            let Some(end) = find(a, old, at) else { break };
            count += 1;
            at = end + old.len();
        }
    }
    let size = a
        .len()
        .checked_sub(
            count
                .checked_mul(old.len())
                .ok_or_else(|| EvalError::fatal("replace overflow"))?,
        )
        .and_then(|n| n.checked_add(count.checked_mul(new.len())?))
        .ok_or_else(|| EvalError::fatal("replace overflow"))?;
    host.tick(size as u64, size.saturating_mul(2).saturating_add(256))?;
    let mut out = Vec::with_capacity(size);
    let mut at = 0;
    for i in 0..count {
        let end = if old.is_empty() {
            if i == 0 { at } else { at + rune(&a[at..]).1 }
        } else {
            find(a, old, at).ok_or_else(|| EvalError::fatal("replace invariant"))?
        };
        out.extend_from_slice(&a[at..end]);
        out.extend_from_slice(new);
        at = end + old.len();
    }
    out.extend_from_slice(&a[at..]);
    Ok(value(Bytes::from(out)))
}
fn join(host: &mut impl Host, args: &[V]) -> R {
    if !(1..=2).contains(&args.len()) {
        return Err(EvalError::new("join argument count"));
    }
    let list = args[0]
        .downcast_ref::<CelList>()
        .ok_or_else(|| EvalError::new("join list required"))?;
    let sep = if args.len() == 2 {
        input(args, 1)?
    } else {
        &[]
    };
    host.tick(list.inner().len() as u64 + 1, 256)?;
    let mut size = sep
        .len()
        .checked_mul(list.inner().len().saturating_sub(1))
        .ok_or_else(|| EvalError::fatal("join overflow"))?;
    for v in list.inner() {
        size = size
            .checked_add(
                bytes(v.as_ref())
                    .ok_or_else(|| EvalError::new("join non-string element"))?
                    .len(),
            )
            .ok_or_else(|| EvalError::fatal("join overflow"))?;
    }
    host.tick(size as u64, size.saturating_mul(2).saturating_add(256))?;
    let mut out = Vec::with_capacity(size);
    for (i, v) in list.inner().iter().enumerate() {
        if i > 0 {
            out.extend_from_slice(sep)
        }
        out.extend_from_slice(
            bytes(v.as_ref()).ok_or_else(|| EvalError::new("join non-string element"))?,
        );
    }
    Ok(value(Bytes::from(out)))
}

/// net/url.ParseQuery semantics: malformed escapes and unescaped semicolons
/// discard their pair; matching decoded values retain bytes and file order.
pub(super) fn query_value(query: &[u8], key: &[u8]) -> Bytes {
    fn unescape(raw: &[u8]) -> Option<Vec<u8>> {
        let mut out = Vec::with_capacity(raw.len());
        let mut i = 0;
        let hex = |b: u8| match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        };
        while i < raw.len() {
            match raw[i] {
                b'+' => out.push(b' '),
                b'%' => {
                    let a = hex(*raw.get(i + 1)?)?;
                    let b = hex(*raw.get(i + 2)?)?;
                    out.push(a * 16 + b);
                    i += 2
                }
                b => out.push(b),
            }
            i += 1;
        }
        Some(out)
    }
    let mut out = Vec::with_capacity(query.len());
    let mut found = false;
    for pair in query.split(|b| *b == b'&') {
        if pair.is_empty() || pair.contains(&b';') {
            continue;
        }
        let (k, v) = pair
            .iter()
            .position(|b| *b == b'=')
            .map_or((pair, &[][..]), |i| (&pair[..i], &pair[i + 1..]));
        if unescape(k).as_deref() != Some(key) {
            continue;
        }
        let Some(value) = unescape(v) else { continue };
        if found {
            out.push(b',')
        }
        out.extend_from_slice(&value);
        found = true;
    }
    Bytes::from(out)
}
