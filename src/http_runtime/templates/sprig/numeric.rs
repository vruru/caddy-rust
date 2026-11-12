use super::*;
use bigdecimal::{BigDecimal, RoundingMode, ToPrimitive};
use std::str::FromStr;
pub(super) fn add(m: &mut M) {
    for name in ["toString","atoi","int64","int","float64","toDecimal","seq","until","untilStep","add1","add","sub","div","mod","mul","add1f","addf","subf","divf","mulf","biggest","max","min","maxf","minf","ceil","floor","round"] {
        put(m,name,move |args| call(name,args));
    }
}
fn call(name: &str,a: &[V]) -> R {
    match name {
        "toString"=>{arity(a,1,1)?;let bytes=if let Some(bytes)=a[0].as_go_bytes(){bytes.to_vec()}else{gotmpl::go_sprint_bytes(&a[..1],false)?};checked_length(0,bytes.len())?;Ok(V::from_go_bytes(bytes))}
        "atoi"=>{arity(a,1,1)?;Ok(V::Int(a[0].as_go_bytes().and_then(|bytes|std::str::from_utf8(bytes).ok()).and_then(|text|text.parse().ok()).unwrap_or(0)))}
        "int64" => {arity(a,1,1)?;Ok(V::Int64(int(&a[0])))}
        "int" => {arity(a,1,1)?;Ok(V::Int(int(&a[0])))}
        "float64" => {arity(a,1,1)?;Ok(V::Float(float(&a[0])))}
        "toDecimal"=>{arity(a,1,1)?;let bytes=gotmpl::go_sprint_bytes(&a[..1],false)?;Ok(V::Int64(std::str::from_utf8(&bytes).ok().and_then(|text|i64::from_str_radix(text,8).ok()).unwrap_or(0)))}
        "add1" => {arity(a,1,1)?;Ok(V::Int64(int(&a[0]).wrapping_add(1)))}
        "add" => Ok(V::Int64(a.iter().fold(0i64,|n,v|n.wrapping_add(int(v))))),
        "sub" => {arity(a,2,2)?;Ok(V::Int64(int(&a[0]).wrapping_sub(int(&a[1]))))}
        "mul" => {arity(a,1,usize::MAX)?;Ok(V::Int64(a[1..].iter().fold(int(&a[0]),|n,v|n.wrapping_mul(int(v)))))}
        "div"|"mod" => {
            arity(a,2,2)?;let n=int(&a[0]);let d=int(&a[1]);
            if d==0 {return Err(err("integer divide by zero"));}
            Ok(V::Int64(if name=="div" {n.wrapping_div(d)} else {n.wrapping_rem(d)}))
        }
        "max"|"biggest"|"min" => {
            arity(a,1,usize::MAX)?;
            Ok(V::Int64(a[1..].iter().fold(int(&a[0]),|n,v|if name=="min" {n.min(int(v))}else{n.max(int(v))})))
        }
        "maxf"|"minf" => {
            arity(a,1,usize::MAX)?;
            Ok(V::Float(a[1..].iter().fold(float(&a[0]),|n,v|if name=="minf" {n.min(float(v))}else{n.max(float(v))})))
        }
        "ceil"|"floor" => {arity(a,1,1)?;Ok(V::Float(if name=="ceil" {float(&a[0]).ceil()}else{float(&a[0]).floor()}))}
        "round" => {
            arity(a,2,usize::MAX)?;let precision=arg_int(a,1)?;
            if !(-308..=308).contains(&precision) {return Err(err("round precision exceeds limit"));}
            let scale=10f64.powi(precision as i32);let digit=scale*float(&a[0]);
            let round_on=if a.len()>2 {float(&a[2])}else{0.5};
            Ok(V::Float(if digit.fract()>=round_on {digit.ceil()}else{digit.floor()}/scale))
        }
        "add1f"|"addf"|"subf"|"divf"|"mulf" => {
            if name=="add1f" {arity(a,1,1)?;} else if name!="addf" {arity(a,1,usize::MAX)?;}
            fn decimal(v:&V)->gotmpl::Result<BigDecimal> {
                BigDecimal::from_str(&float(v).to_string()).map_err(|_|err("non-finite decimal input"))
            }
            let mut current=if name=="addf" {BigDecimal::from(0)} else {decimal(&a[0])?};
            if name=="add1f" {current+=BigDecimal::from(1);}
            for value in if name=="addf" {a}else{&a[1..]} {
                let value=decimal(value)?;
                current=match name {
                    "addf"=>current+value, "subf"=>current-value, "mulf"=>current*value,
                    "divf"=>{if value==BigDecimal::from(0) {return Err(err("decimal division by zero"));} (current/value).with_scale_round(16,RoundingMode::HalfUp)},
                    _=>current,
                };
                let (_,scale)=current.as_bigint_and_exponent();
                if scale.unsigned_abs()>4096 || current.digits()>4096 {return Err(err("decimal work exceeds limit"));}
            }
            Ok(V::Float(current.to_f64().ok_or_else(||err("decimal is outside float64 range"))?))
        }
        "until" => {arity(a,1,1)?;let stop=arg_int(a,0)?;range(0,stop,if stop<0 {-1}else{1})}
        "untilStep" => {arity(a,3,3)?;range(arg_int(a,0)?,arg_int(a,1)?,arg_int(a,2)?)}
        "seq" => {
            if a.is_empty() || a.len()>3 {return output("");}
            let start=if a.len()==1 {1}else{arg_int(a,0)?};
            let end=arg_int(a,a.len()-1)?;
            let increment=if end<start {-1}else{1};
            let step=if a.len()==3 {arg_int(a,1)?}else{increment};
            if end<start && step>0 {return output("");}
            let stop=end.checked_add(increment).ok_or_else(||err("seq endpoint overflows integer"))?;
            let result=range(start,stop,step)?;
            let V::List(values)=result else {return Err(err("sequence invariant"));};
            output(values.iter().map(text).collect::<Vec<_>>().join(" "))
        }
        _=>Err(err("unregistered numeric helper")),
    }
}
fn range(start:i64,stop:i64,step:i64)->R {
    if step==0 || (stop<start && step>=0) || (stop>=start && step<=0) {return list(Vec::new());}
    let distance=(i128::from(stop)-i128::from(start)).unsigned_abs();
    let count=distance.div_ceil(i128::from(step).unsigned_abs());
    if count>MAX_ITEMS as u128 {return Err(err("template range exceeds item limit"));}
    let mut values=Vec::with_capacity(count as usize);
    let mut current=i128::from(start);
    for _ in 0..count {values.push(V::Int(current as i64));current+=i128::from(step);}
    list(values)
}
