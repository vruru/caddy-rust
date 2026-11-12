//! Map values with Go byte-string keys. The ordinary VM map stays unchanged.
use super::cel_native_string;
use crate::cel_engine::eval::{self, EvalError, Host, Items, R, V};
use cel::common::{
    types::{CelBool, CelBytes, CelInt, CelList, CelMap, CelString, CelType, CelUInt, Type},
    value::{StaticVal, Val},
};
use std::sync::Arc;
#[derive(Clone, Debug)]
pub(super) struct RawMap(Arc<Vec<(V, V)>>);
impl StaticVal for RawMap {}
impl Val for RawMap {
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }
    fn get_type(&self) -> &Type {
        CelMap::cel_type()
    }
    fn cel_type() -> &'static Type {
        CelMap::cel_type()
    }
    fn clone_as_boxed<'v>(&self) -> Box<dyn Val + 'v>
    where
        Self: 'v,
    {
        Box::new(self.clone())
    }
    fn equals(&self, other: &dyn Val) -> bool {
        if let Some(other) = other.downcast_ref::<Self>() {
            return self.0.len() == other.0.len()
                && self.0.iter().all(|(k, v)| {
                    other
                        .0
                        .iter()
                        .any(|(b, w)| key_eq(k.as_ref(), b.as_ref()) && v.equals(w.as_ref()))
                });
        }
        if let Some(other) = other.downcast_ref::<CelMap>() {
            return self.0.len() == other.inner().len()
                && self.0.iter().all(|(k, v)| {
                    other
                        .inner()
                        .iter()
                        .any(|(b, w)| key_eq(k.as_ref(), b.inner()) && v.equals(w.as_ref()))
                });
        }
        false
    }
}
fn key_eq(a: &dyn Val, b: &dyn Val) -> bool {
    match (cel_native_string::bytes(a), cel_native_string::bytes(b)) {
        (Some(a), Some(b)) => a == b,
        _ => a.get_type() == b.get_type() && a.equals(b),
    }
}
fn allowed(key: &dyn Val) -> bool {
    cel_native_string::bytes(key).is_some()
        || key.downcast_ref::<CelBool>().is_some()
        || key.downcast_ref::<CelInt>().is_some()
        || key.downcast_ref::<CelUInt>().is_some()
}
pub(super) fn make(host: &mut impl Host, values: Vec<V>) -> R {
    let raw = values.iter().step_by(2).any(|k| {
        cel_native_string::bytes(k.as_ref()).is_some() && k.downcast_ref::<CelString>().is_none()
    });
    if !raw {
        return eval::default_map(host, values);
    }
    if !values.len().is_multiple_of(2) {
        return Err(EvalError::fatal("CEL map stack underflow"));
    }
    let count = values.len() / 2;
    host.tick(
        (count as u64)
            .saturating_mul(count as u64)
            .saturating_add(1),
        count.saturating_mul(64).saturating_add(256),
    )?;
    let mut map: Vec<(V, V)> = Vec::with_capacity(count);
    let mut values = values.into_iter();
    let mut invalid = false;
    while let Some(key) = values.next() {
        let value = values
            .next()
            .ok_or_else(|| EvalError::fatal("CEL map stack underflow"))?;
        if !allowed(key.as_ref()) {
            invalid = true;
            continue;
        }
        let mut prior = None;
        for (i, (k, _)) in map.iter().enumerate() {
            host.tick(
                cel_native_string::bytes(key.as_ref()).map_or(1, |b| b.len().div_ceil(16).saturating_add(1)) as u64,
                0,
            )?;
            if key_eq(key.as_ref(), k.as_ref()) {
                prior = Some(i);
                break;
            }
        }
        if let Some(i) = prior {
            map[i].1 = value
        } else {
            map.push((key, value))
        }
    }
    if invalid {
        return Err(EvalError::new("invalid CEL map key type"));
    }
    Ok(Arc::new(RawMap(Arc::new(map))))
}
pub(super) fn items(host: &mut impl Host, value: &V, two: bool) -> Result<Items, EvalError> {
    let Some(map) = value.downcast_ref::<RawMap>() else {
        return eval::default_iteration(host, value, two);
    };
    host.tick(
        map.0.len() as u64,
        map.0.len().saturating_mul(64).saturating_add(256),
    )?;
    Ok(Arc::new(
        map.0
            .iter()
            .map(|(k, v)| (k.clone(), two.then(|| v.clone())))
            .collect(),
    ))
}
pub(super) fn operation(host: &mut impl Host, name: &str, args: &[V]) -> Option<R> {
    if args.len() == 2
        && matches!(name, "_==_" | "_!=_")
        && !args.iter().any(|v| {
            v.downcast_ref::<RawMap>().is_some()
                || v.downcast_ref::<CelList>().is_some()
                || v.downcast_ref::<CelMap>().is_some()
        })
    {
        return None;
    }
    if args.len() == 2 && matches!(name, "_==_" | "_!=_") {
        let measured = (|| {
            let a = weight(host, args[0].as_ref(), 0)?;
            let b = weight(host, args[1].as_ref(), 0)?;
            if !a.2 && !b.2 {
                return Ok(None);
            }
            host.tick(
                (if a.3 || b.3 {
                    (a.0 as u64).saturating_mul(b.0 as u64)
                } else {
                    a.0.max(b.0) as u64
                })
                .saturating_mul(a.1.max(b.1).div_ceil(16).saturating_add(1) as u64),
                256,
            )?;
            let equal = if let Some(m) = args[0].downcast_ref::<RawMap>() {
                m.equals(args[1].as_ref())
            } else if let Some(m) = args[1].downcast_ref::<RawMap>() {
                m.equals(args[0].as_ref())
            } else {
                args[0].equals(args[1].as_ref())
            };
            Ok(Some(eval::boolean(equal == (name == "_==_"))))
        })();
        return match measured {
            Ok(None) => None,
            Ok(Some(v)) => Some(Ok(v)),
            Err(e) => Some(Err(e)),
        };
    }
    if args.len() == 2
        && matches!(name, "@in" | "@caddy_const_in")
        && super::cel_native_cert::comparison_width(args[0].as_ref()).is_none()
        && let Some(list) = args[1].downcast_ref::<CelList>()
    {
        let result = (|| {
            let a = weight(host, args[0].as_ref(), 0)?;
            let all = weight(host, args[1].as_ref(), 0)?;
            if !a.2 && !all.2 {
                return Ok(None);
            }
            for value in list.inner() {
                let b = weight(host, value.as_ref(), 0)?;
                let nodes = if a.3 || b.3 {
                    (a.0 as u64).saturating_mul(b.0 as u64)
                } else {
                    a.0.max(b.0) as u64
                };
                host.tick(nodes.saturating_mul(a.1.max(b.1).div_ceil(16) as u64 + 1), 0)?;
                if args[0].equals(value.as_ref()) {
                    return Ok(Some(eval::boolean(true)));
                }
            }
            Ok(Some(eval::boolean(false)))
        })();
        return match result {
            Ok(Some(v)) => Some(Ok(v)),
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        };
    }
    let map = args.first().and_then(|v| v.downcast_ref::<RawMap>());
    let right = args.get(1).and_then(|v| v.downcast_ref::<RawMap>());
    if map.is_none() && right.is_none() {
        return None;
    }
    Some((|| {
        if let Some(map) = map {
            if args.len() == 1 {
                host.tick(1, 256)?;
                if name == "size" {
                    return Ok(Arc::new(CelInt::from(map.0.len() as i64)) as V);
                }
                if name == "type" {
                    return Ok(Arc::new(CelType::new("map")) as V);
                }
            }
            if args.len() == 2 && matches!(name, "_[_]" | "@has") {
                let key = &args[1];
                for (k, v) in map.0.iter() {
                    host.tick(
                        cel_native_string::bytes(key.as_ref()).map_or(1, |b| b.len().div_ceil(16)) as u64 + 1,
                        0,
                    )?;
                    if key_eq(k.as_ref(), key.as_ref()) {
                        return if name == "@has" {
                            Ok(eval::boolean(true))
                        } else {
                            Ok(v.clone())
                        };
                    }
                }
                return if name == "@has" {
                    Ok(eval::boolean(false))
                } else {
                    Err(EvalError::new("no such map key"))
                };
            }
        }
        if args.len() == 2
            && matches!(name, "@in" | "@caddy_const_in")
            && map.is_some()
            && let Some(list) = args[1].downcast_ref::<CelList>()
        {
            let a = weight(host, args[0].as_ref(), 0)?;
            let b = weight(host, args[1].as_ref(), 0)?;
            host.tick(
                (a.0 as u64)
                    .saturating_mul(b.0 as u64)
                    .saturating_mul(a.1.max(b.1).div_ceil(16).saturating_add(1) as u64),
                256,
            )?;
            return Ok(eval::boolean(
                list.inner().iter().any(|v| args[0].equals(v.as_ref())),
            ));
        }
        if args.len() == 2
            && matches!(name, "@in" | "@caddy_const_in")
            && let Some(map) = right
        {
            for (k, _) in map.0.iter() {
                host.tick(
                    cel_native_string::bytes(args[0].as_ref()).map_or(1, |b| b.len().div_ceil(16)) as u64 + 1,
                    0,
                )?;
                if key_eq(k.as_ref(), args[0].as_ref()) {
                    return Ok(eval::boolean(true));
                }
            }
            return Ok(eval::boolean(false));
        }
        Err(EvalError::new(format!(
            "Go byte-key map operation {name} not yet implemented"
        )))
    })())
}

fn weight(
    host: &mut impl Host,
    value: &dyn Val,
    depth: usize,
) -> Result<(usize, usize, bool, bool), EvalError> {
    host.tick(1, 0)?;
    if depth > 250 {
        return Err(EvalError::fatal("CEL comparison depth"));
    }
    let bytes = cel_native_string::bytes(value)
        .map(|b| b.len())
        .or_else(|| value.downcast_ref::<CelBytes>().map(|b| b.inner().len()));
    let native = super::cel_native_cert::comparison_width(value);
    let mut nodes = 1usize;
    let mut width = bytes.or(native).unwrap_or(0);
    let mut maps = value.downcast_ref::<RawMap>().is_some();
    let mut raw = maps
        || native.is_some()
        || (cel_native_string::bytes(value).is_some()
            && value.downcast_ref::<CelString>().is_none());
    let mut add = |v: &dyn Val| -> Result<(), EvalError> {
        let (n, w, r, m) = weight(host, v, depth + 1)?;
        nodes = nodes.saturating_add(n);
        width = width.max(w);
        raw |= r;
        maps |= m;
        Ok(())
    };
    if let Some(map) = value.downcast_ref::<RawMap>() {
        for (k, v) in map.0.iter() {
            add(k.as_ref())?;
            add(v.as_ref())?
        }
    } else if let Some(map) = value.downcast_ref::<CelMap>() {
        for (k, v) in map.inner() {
            add(k.inner())?;
            add(v.as_ref())?
        }
    } else if let Some(list) = value.downcast_ref::<CelList>() {
        for v in list.inner() {
            add(v.as_ref())?
        }
    }
    Ok((nodes, width, raw, maps))
}
pub(super) fn entries(value: &dyn Val) -> Option<&[(V, V)]> {
    value.downcast_ref::<RawMap>().map(|m| m.0.as_slice())
}

pub(super) fn comparison_units(
    host: &mut impl Host,
    value: &dyn Val,
) -> Result<(u64, bool), EvalError> {
    let (n, w, native, maps) = weight(host, value, 0)?;
    let nodes = if maps {
        (n as u64).saturating_mul(n as u64)
    } else {
        n as u64
    };
    Ok((nodes.saturating_mul(w.div_ceil(16) as u64 + 1), native))
}
