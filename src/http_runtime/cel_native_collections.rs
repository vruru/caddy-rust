//! Comparison costs for known Caddy values in CEL collections. Standard values
//! retain the shared core preflight; raw strings sort by original Go bytes.
use super::{cel_native_cert, cel_native_map, cel_native_string};
use crate::cel_engine::{
    self,
    eval::{self, EvalError, Host, R, V},
};
use cel::common::{
    types::{CelList, CelMap, CelString},
    value::Val,
};
use std::sync::Arc;
fn native(host: &mut impl Host, v: &dyn Val, depth: usize) -> Result<bool, EvalError> {
    host.tick(1, 0)?;
    if depth > 250 {
        return Err(EvalError::fatal("collection depth"));
    }
    if cel_native_map::entries(v).is_some()
        || cel_native_cert::comparison_width(v).is_some()
        || (cel_native_string::bytes(v).is_some() && v.downcast_ref::<CelString>().is_none())
    {
        return Ok(true);
    }
    if let Some(list) = v.downcast_ref::<CelList>() {
        for v in list.inner() {
            if native(host, v.as_ref(), depth + 1)? {
                return Ok(true);
            }
        }
    }
    if let Some(map) = v.downcast_ref::<CelMap>() {
        for v in map.inner().values() {
            if native(host, v.as_ref(), depth + 1)? {
                return Ok(true);
            }
        }
    }
    Ok(false)
}
pub(super) fn operation(
    host: &mut impl Host,
    env: &cel::Env,
    name: &str,
    member: bool,
    args: &[V],
) -> Option<R> {
    if !member || !matches!(name, "distinct" | "sort" | "@sortByAssociatedKeys") {
        return None;
    }
    let list = args.first()?.downcast_ref::<CelList>()?;
    let associated = name == "@sortByAssociatedKeys";
    if args.len() != if associated { 2 } else { 1 } {
        return None;
    }
    Some((|| {
        let keys = if associated {
            args[1]
                .downcast_ref::<CelList>()
                .ok_or_else(|| EvalError::new("sort keys must be a list"))?
        } else {
            list
        };
        if keys.inner().len() != list.inner().len() {
            return Err(EvalError::new("sort keys length differs from values"));
        }
        let mut has_native = native(host, args[0].as_ref(), 0)?;
        if associated {
            has_native |= native(host, args[1].as_ref(), 0)?;
        }
        if !has_native {
            return Ok(None);
        }
        if name != "distinct"
            && keys.inner().iter().any(|v| {
                cel_native_map::entries(v.as_ref()).is_some()
                    || cel_native_cert::comparison_width(v.as_ref()).is_some()
            })
        {
            return Err(EvalError::new("sort keys must be comparable"));
        }
        let mut largest = 1u64;
        for key in keys.inner() {
            largest = largest.max(cel_native_map::comparison_units(host, key.as_ref())?.0);
        }
        let n = list.inner().len();
        let levels = if n < 2 {
            0
        } else {
            usize::BITS as u64 - (n - 1).leading_zeros() as u64
        };
        let comparisons = if name == "distinct" {
            (n as u64).saturating_mul(n as u64)
        } else {
            (n as u64).saturating_mul(levels.saturating_mul(2).saturating_add(1))
        };
        host.tick(comparisons.saturating_mul(largest), 0)?;
        eval::charge_clone(host, list)?;
        host.tick(1, n.saturating_mul(256).saturating_add(1024))?;
        if name != "distinct"
            && keys
                .inner()
                .iter()
                .all(|v| cel_native_string::bytes(v.as_ref()).is_some())
        {
            let mut order: Vec<usize> = (0..n).collect();
            order.sort_by(|a, b| {
                cel_native_string::bytes(keys.inner()[*a].as_ref())
                    .cmp(&cel_native_string::bytes(keys.inner()[*b].as_ref()))
            });
            let out = order
                .into_iter()
                .map(|i| list.inner()[i].clone_as_boxed())
                .collect::<Vec<_>>();
            return Ok(Some(Arc::new(CelList::from(out)) as V));
        }
        Ok(Some(cel_engine::dispatch::builtin(
            env, name, member, args,
        )?))
    })())
    .and_then(|result| match result {
        Ok(Some(v)) => Some(Ok(v)),
        Ok(None) => None,
        Err(e) => Some(Err(e)),
    })
}
