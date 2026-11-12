//! Caddy's ToString coercion for helpers accepting `any`, preserving Go bytes.
//! Ordinary strings should be borrowed by the caller; this owned path covers
//! byte/rune slices and scalar/struct formatting on the same render budget.
use super::{RenderResult,error};
use gotmpl::{BudgetAccount,BudgetMeter,BudgetedBytes,Value};
use std::sync::Arc;

const OUTPUT:usize=1<<20;
// The fixed formatter has no caller-controlled width or precision. Its output
// buffer is capped at 1 MiB; this admits old/new growth and bounded map scratch
// before entering the formatter, then retains only the final Vec capacity.
const FORMAT_PEAK:usize=4<<20;

pub(super) fn bytes(value:&Value,meter:Arc<BudgetMeter>)->RenderResult<BudgetedBytes>{
    meter.check()?;
    let material=value.measured_bytes(OUTPUT)?;
    meter.charge_work(material.checked_add(1).ok_or_else(||error("string conversion work overflow"))?)?;
    let account=BudgetAccount::new(meter)?;
    account.reserve(FORMAT_PEAK)?;
    let bytes=match value{
        Value::Nil|Value::NilError=>Vec::new(),
        Value::Uint8(byte)=>vec![*byte],
        Value::String(text)=>text.as_bytes().to_vec(),
        Value::ByteString(text)=>text.as_bytes().to_vec(),
        Value::Slice(slice)if matches!(slice.go_type(),"[]uint8"|"[]byte")=>{
            if let Some(bytes)=slice.visible_bytes(){bytes.to_vec()}
            else{slice.iter().map(|value|match value{Value::Uint8(byte)=>Ok(byte),_=>Err(error("invalid Go byte slice"))}).collect::<RenderResult<Vec<_>>>()?}
        }
        Value::Slice(slice)if matches!(slice.go_type(),"[]int32"|"[]rune")=>{
            let mut out=Vec::with_capacity(slice.len().checked_mul(4).filter(|n|*n<=OUTPUT).ok_or_else(||error("rune conversion exceeds byte limit"))?);
            for value in slice.iter(){
                let value=value.as_int().ok_or_else(||error("invalid Go rune slice"))?;
                let rune=u32::try_from(value).ok().and_then(char::from_u32).unwrap_or(char::REPLACEMENT_CHARACTER);
                let mut buffer=[0;4];out.extend_from_slice(rune.encode_utf8(&mut buffer).as_bytes());
            }
            out
        }
        Value::Float(number)=>{
            let text=if number.is_nan(){"NaN".to_owned()}else if *number==f64::INFINITY{"+Inf".to_owned()}else if *number==f64::NEG_INFINITY{"-Inf".to_owned()}else{number.to_string()};
            text.into_bytes()
        }
        Value::Object(object)if object.display.is_some()=>object.display.as_ref().unwrap().as_bytes().to_vec(),
        _=>gotmpl::go_sprintf_bytes(b"%+v",std::slice::from_ref(value))?,
    };
    if bytes.len()>OUTPUT||bytes.capacity()>FORMAT_PEAK{return Err(error("string conversion exceeds byte limit"));}
    BudgetedBytes::from_account(bytes,&account)
}
