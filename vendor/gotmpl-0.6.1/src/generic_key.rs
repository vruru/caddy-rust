//! Go interface-key equality. The cross-type order is deterministic; Go's
//! rtype-address ordering cannot be reproduced across different runtimes.
use core::cmp::Ordering;
use crate::{Result,TemplateError,Value};
pub(crate) fn valid_key(value:&Value)->Result<()>{
    match value{
        Value::Nil|Value::NilError|Value::Bool(_)|Value::Int(_)|Value::Int64(_)|Value::NamedInt64(..)|Value::Uint(_)|Value::Uint32(_)|Value::Uint8(_)|Value::Uint16(_)|Value::Float(_)|Value::String(_)|Value::ByteString(_)=>Ok(()),
        Value::Object(object)if object.go_type.is_some_and(|name|name.starts_with('*'))||(object.equal.is_some()&&object.key_order.is_some())=>Ok(()),
        _=>Err(TemplateError::Exec(alloc::format!("hash of unhashable type {}",value.type_name()))),
    }
}
fn class(value:&Value)->(&str,u8){match value{
    Value::Nil|Value::NilError=>("",0),Value::Bool(_)=>("bool",1),Value::Int(_)=>("int",2),Value::Int64(_)=>("int64",3),Value::NamedInt64(_,kind)=>(kind.name,4),
    Value::Uint(_)=>("uint64",5),Value::Uint32(_)=>("uint32",6),Value::Uint8(_)=>("uint8",7),Value::Uint16(_)=>("uint16",8),Value::Float(_)=>("float64",9),
    Value::String(_)|Value::ByteString(_)=>("string",10),Value::Object(object)=>(object.go_type.unwrap_or("object"),11),_=>("unhashable",255),
}}
pub fn key_equal(a:&Value,b:&Value)->Result<bool>{
    valid_key(a)?;valid_key(b)?;
    if class(a)!=class(b){return Ok(false);}
    if let(Some(a),Some(b))=(a.as_go_bytes(),b.as_go_bytes()){return Ok(a==b);}
    Ok(match(a,b){
        (Value::Nil|Value::NilError,Value::Nil|Value::NilError)=>true,
        (Value::Bool(a),Value::Bool(b))=>a==b,(Value::Int(a),Value::Int(b))|(Value::Int64(a),Value::Int64(b))|(Value::NamedInt64(a,_),Value::NamedInt64(b,_))=>a==b,
        (Value::Uint(a),Value::Uint(b))=>a==b,(Value::Uint32(a),Value::Uint32(b))=>a==b,(Value::Uint8(a),Value::Uint8(b))=>a==b,(Value::Uint16(a),Value::Uint16(b))=>a==b,
        (Value::Float(a),Value::Float(b))=>a==b,
        (Value::Object(a),Value::Object(b))=>if a.go_type.is_some_and(|name|name.starts_with('*')){a.pointer_key()==b.pointer_key()}else{a.equal.is_some_and(|equal|equal(a,b))},_=>false,
    })
}
pub(crate) fn key_compare(a:&Value,b:&Value)->Result<Ordering>{
    valid_key(a)?;valid_key(b)?;
    let order=class(a).cmp(&class(b));if !order.is_eq(){return Ok(order);}
    if let(Some(a),Some(b))=(a.as_go_bytes(),b.as_go_bytes()){return Ok(a.cmp(b));}
    Ok(match(a,b){
        (Value::Nil|Value::NilError,Value::Nil|Value::NilError)=>Ordering::Equal,
        (Value::NamedInt64(a,kind),Value::NamedInt64(b,_))if kind.kind.starts_with("uint")=>(*a as u64).cmp(&(*b as u64)),
        (Value::Bool(a),Value::Bool(b))=>a.cmp(b),(Value::Int(a),Value::Int(b))|(Value::Int64(a),Value::Int64(b))|(Value::NamedInt64(a,_),Value::NamedInt64(b,_))=>a.cmp(b),
        (Value::Uint(a),Value::Uint(b))=>a.cmp(b),(Value::Uint32(a),Value::Uint32(b))=>a.cmp(b),(Value::Uint8(a),Value::Uint8(b))=>a.cmp(b),(Value::Uint16(a),Value::Uint16(b))=>a.cmp(b),
        (Value::Float(a),Value::Float(b))=>if a.is_nan(){if b.is_nan(){Ordering::Equal}else{Ordering::Less}}else if b.is_nan(){Ordering::Greater}else{a.partial_cmp(b).unwrap_or(Ordering::Equal)},
        (Value::Object(a),Value::Object(b))=>{
            if a.go_type.is_some_and(|name|name.starts_with('*')){a.pointer_key().cmp(&b.pointer_key())}
            else{return a.key_order.ok_or_else(||TemplateError::Exec("host map key has no order".into()))?(a,b);}
        }
        _=>Ordering::Equal,
    })
}
