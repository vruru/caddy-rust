use super::eval::{EvalError, R, V, boolean};
use cel::common::{
    types::{CelBool, CelDouble, CelType},
    value::{CowVal, Val},
};
use cel::{Env, ExecutionError};
use std::{cmp::Ordering, sync::Arc};

fn own(value: CowVal<'_, 'static>) -> R {
    Ok(Arc::from(value.into_owned()))
}
fn error(e: ExecutionError) -> EvalError {
    EvalError::new(e.to_string())
}
fn unsupported(name: &str) -> EvalError {
    EvalError::new(format!("no matching CEL overload for {name}"))
}
// Concrete builtins cannot handle these operand shapes. Return their ordinary
// overload error without cloning whole operands into a debug error payload.
pub(super) fn shape_error(name:&str,args:&[V])->bool {
    use cel::common::types::{CelBool,CelBytes,CelDouble,CelDuration,CelInt,CelList,CelMap,CelNull,CelString,CelTimestamp,CelType,CelUInt};
    if args.is_empty(){return false;}
    let a=args[0].as_ref();
    if args.len()==1 {
        let known=a.downcast_ref::<CelBool>().is_some()||a.downcast_ref::<CelBytes>().is_some()||a.downcast_ref::<CelDouble>().is_some()||a.downcast_ref::<CelDuration>().is_some()||a.downcast_ref::<CelInt>().is_some()||a.downcast_ref::<CelList>().is_some()||a.downcast_ref::<CelMap>().is_some()||a.downcast_ref::<CelNull>().is_some()||a.downcast_ref::<CelString>().is_some()||a.downcast_ref::<CelTimestamp>().is_some()||a.downcast_ref::<CelType>().is_some()||a.downcast_ref::<CelUInt>().is_some();
        return known && match name {
            "!_"=>a.downcast_ref::<CelBool>().is_none(),
            "-_"=>a.as_negator().is_none(),
            "bool"|"bytes"|"double"|"duration"|"int"|"string"|"timestamp"|"uint"=>a.downcast_ref::<CelList>().is_some()||a.downcast_ref::<CelMap>().is_some(),
            _=>false,
        };
    }
    if args.len()!=2{return false;}
    let b=args[1].as_ref();
    let number=|v:&dyn Val|v.downcast_ref::<CelInt>().is_some()||v.downcast_ref::<CelUInt>().is_some()||v.downcast_ref::<CelDouble>().is_some();
    let time=|v:&dyn Val|v.downcast_ref::<CelDuration>().is_some()||v.downcast_ref::<CelTimestamp>().is_some();
    let string=|v:&dyn Val|v.downcast_ref::<CelString>().is_some();
    let bytes=|v:&dyn Val|v.downcast_ref::<CelBytes>().is_some();
    let boolean=|v:&dyn Val|v.downcast_ref::<CelBool>().is_some();
    let list=a.downcast_ref::<CelList>().is_some();
    let known=number(a)||time(a)||string(a)||bytes(a)||boolean(a)||list||a.downcast_ref::<CelMap>().is_some()||a.downcast_ref::<CelNull>().is_some()||a.downcast_ref::<CelType>().is_some();
    if !known{return false;} // Arbitrary host operator traits remain its contract.
    match name {
        "_+_" if list=>b.as_iterable().is_none(),
        "_+_" if string(a)=>!string(b),
        "_+_" if bytes(a)=>!bytes(b),
        "_+_"|"_-_" if number(a)=>!number(b),
        "_+_"|"_-_" if time(a)=>!time(b),
        "_+_"|"_-_"=>true,
        "_*_"|"_/_"|"_%_"=>!number(a)||!number(b),
        "_<_"|"_<=_"|"_>_"|"_>=_"=>{
            if number(a){!number(b)}else if time(a){!time(b)}else if string(a){!string(b)}else if bytes(a){!bytes(b)}else if boolean(a){!boolean(b)}else{true}
        },
        _=>false,
    }
}
pub fn builtin(env: &Env, name: &str, member: bool, args: &[V]) -> R {
    let name = if matches!(name,"in"|"_in_") { "@in" } else { name };
    if shape_error(name,args) { return Err(unsupported(name)); }
    if name=="int" && !member && args.len()==1 && let Some(duration)=args[0].downcast_ref::<cel::common::types::CelDuration>() {
        return duration.inner().num_nanoseconds().map(|n|Arc::new(cel::common::types::CelInt::from(n)) as V).ok_or_else(||EvalError::new("duration integer overflow"));
    }
    if args.len()==2 && matches!(name,"_[_]"|"@has") {
        if args[0].downcast_ref::<cel::common::types::CelList>().is_some()
            && !super::structural_cost::valid_list_double(args[1].as_ref()) {
            return Err(EvalError::new("invalid CEL list index"));
        }
        if args[0].downcast_ref::<cel::common::types::CelMap>().is_some()
            && !super::structural_cost::valid_map_key(args[1].as_ref()) {
            return Err(EvalError::new("invalid CEL map key"));
        }
    }
    if args.len()==2 && matches!(name,"@in"|"in"|"_in_")
        && args[1].downcast_ref::<cel::common::types::CelMap>().is_some()
        && !super::structural_cost::valid_map_key(args[0].as_ref()) {
        return Err(EvalError::new("invalid CEL map key"));
    }
    if name=="bool" && !member && args.len()==1 && let Some(text)=args[0].downcast_ref::<cel::common::types::CelString>() {
        if text.inner()=="T" { return Ok(boolean(true)); }
        if text.inner()=="F" { return Ok(boolean(false)); }
    }
    let a = args.first().map(Arc::as_ref);
    let b = args.get(1).map(Arc::as_ref);
    let binary = || a.zip(b).ok_or_else(|| unsupported(name));
    if name == "string"
        && !member
        && args.len() == 1
        && let Some(value) = args[0].downcast_ref::<CelDouble>()
    {
        return Ok(super::eval::string(&gotmpl::format_float_shortest(
            *value.inner(),
        )));
    }
    match name {
        "_+_" => {
            let (a, b) = binary()?;
            own(a
                .as_adder()
                .ok_or_else(|| unsupported(name))?
                .add(b)
                .map_err(error)?)
        }
        "_-_" => {
            let (a, b) = binary()?;
            own(a
                .as_subtractor()
                .ok_or_else(|| unsupported(name))?
                .sub(b)
                .map_err(error)?)
        }
        "_*_" => {
            let (a, b) = binary()?;
            own(a
                .as_multiplier()
                .ok_or_else(|| unsupported(name))?
                .mul(b)
                .map_err(error)?)
        }
        "_/_" => {
            let (a, b) = binary()?;
            own(a
                .as_divider()
                .ok_or_else(|| unsupported(name))?
                .div(b)
                .map_err(error)?)
        }
        "_%_" => {
            let (a, b) = binary()?;
            own(a
                .as_modder()
                .ok_or_else(|| unsupported(name))?
                .modulo(b)
                .map_err(error)?)
        }
        "-_" => Ok(Arc::from(
            a.and_then(Val::as_negator)
                .ok_or_else(|| unsupported(name))?
                .negate()
                .map_err(error)?,
        )),
        "!_" => args
            .first()
            .and_then(|v| v.downcast_ref::<CelBool>())
            .map(|v| boolean(!*v.inner()))
            .ok_or_else(|| unsupported(name)),
        "_==_" | "_!=_" => {
            let (a, b) = binary()?;
            Ok(boolean(a.equals(b) == (name == "_==_")))
        }
        "_<_" | "_<=_" | "_>_" | "_>=_" => {
            let (a, b) = binary()?;
            let order = a
                .as_comparer()
                .ok_or_else(|| unsupported(name))?
                .compare(b)
                .map_err(error)?;
            Ok(boolean(match name {
                "_<_" => order == Ordering::Less,
                "_<=_" => order != Ordering::Greater,
                "_>_" => order == Ordering::Greater,
                _ => order != Ordering::Less,
            }))
        }
        "@in" => {
            let (a, b) = binary()?;
            Ok(boolean(
                b.as_container()
                    .ok_or_else(|| unsupported(name))?
                    .contains(a)
                    .map_err(error)?,
            ))
        }
        "_[_]" => {
            let (a, b) = binary()?;
            own(a
                .as_indexer()
                .ok_or_else(|| unsupported(name))?
                .get(b)
                .map_err(error)?)
        }
        "@has" => {
            let (a, b) = binary()?;
            match a.as_indexer().ok_or_else(|| unsupported(name))?.get(b) {
                Ok(_) => Ok(boolean(true)),
                Err(ExecutionError::NoSuchKey(_)) => Ok(boolean(false)),
                Err(e) => Err(error(e)),
            }
        }
        _ => {
            let values = args
                .iter()
                .map(|v| CowVal::Borrowed(v.as_ref()))
                .collect::<Vec<_>>();
            let function = if member {
                env.find_member_overload(name, &values)
            } else {
                env.find_overload(name, &values)
            }
            .ok_or_else(|| unsupported(name))?;
            own(function(values).map_err(error)?)
        }
    }
}
pub fn type_constant(name: &str) -> Option<V> {
    let canonical = match name {
        "bool" | "int" | "uint" | "double" | "string" | "bytes" | "list" | "map" | "null_type"
        | "type" => name,
        "google.protobuf.Duration" => "google.protobuf.Duration",
        "google.protobuf.Timestamp" => "google.protobuf.Timestamp",
        _ => return None,
    };
    Some(Arc::new(CelType::new(canonical)))
}
