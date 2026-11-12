// Native behavioral port of yaml.v3 v3.0.1.
// Copyright (c) 2011-2019 Canonical Ltd; Apache-2.0.
// See LICENSES/yaml-v3.0.1-LICENSE and THIRD-PARTY-NOTICES.
//! Scalar resolution follows yaml.v3 v3.0.1 resolve.go; scalar style and
//! explicit tags come from the parser, before serde-style normalization.
use gotmpl::{BudgetAccount, Result, TemplateError, Value};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Tag { Str, Null, Bool, Int, Float, Timestamp, Binary, Merge, Other }
pub(super) struct Resolved { pub tag:Tag, pub value:Value }
fn error(s:&str)->TemplateError{TemplateError::Exec(s.into())}
fn named(t:&[u8])->Tag{match t.strip_prefix(b"tag:yaml.org,2002:").unwrap_or(t){
    b"str"|b"!!str"=>Tag::Str,b"null"|b"!!null"=>Tag::Null,b"bool"|b"!!bool"=>Tag::Bool,
    b"int"|b"!!int"=>Tag::Int,b"float"|b"!!float"=>Tag::Float,b"timestamp"|b"!!timestamp"=>Tag::Timestamp,
    b"binary"|b"!!binary"=>Tag::Binary,b"merge"|b"!!merge"=>Tag::Merge,_=>Tag::Other,
}}
fn raw(input:&[u8],account:&BudgetAccount)->Result<Value>{
    account.reserve(input.len().checked_mul(3).and_then(|n|n.checked_add(128)).ok_or_else(||error("YAML allocation overflow"))?)?;
    Ok(Value::from_go_bytes(std::sync::Arc::<[u8]>::from(input)))
}
fn integer(s:&str)->Option<Value>{
    let signed_plus=s.starts_with('+');let(negative,digits)=if s.starts_with(['-','+']){(s.starts_with('-'),&s[1..])}else{(false,s)};
    let(radix,digits)=if (digits.starts_with("0x")||digits.starts_with("0X")){(16,&digits[2..])}
        else if (digits.starts_with("0b")||digits.starts_with("0B")){(2,&digits[2..])}
        else if (digits.starts_with("0o")||digits.starts_with("0O")){(8,&digits[2..])}
        else if digits.len()>1&&digits.starts_with('0'){(8,&digits[1..])}else{(10,digits)};
    if digits.is_empty()||digits.starts_with(['+','-']){return None;}
    let n=u64::from_str_radix(digits,radix).ok()?;
    if negative {if n==1u64<<63{Some(Value::Int(i64::MIN))}else{i64::try_from(n).ok().map(|n|Value::Int(-n))}}
    else if let Ok(n)=i64::try_from(n){Some(Value::Int(n))}else if !signed_plus{Some(Value::Uint(n))}else{None}
}
fn fallback_integer(s:&str)->Option<Value>{
    for(prefix,base)in[("0b",2),("0o",8)]{
        if let Some(digits)=s.strip_prefix(prefix){
            if let Ok(n)=i64::from_str_radix(digits,base){return Some(Value::Int(n));}
            if !digits.starts_with(['+','-']){if let Ok(n)=u64::from_str_radix(digits,base){return Some(Value::Uint(n));}}
        }
        if let Some(digits)=s.strip_prefix('-').and_then(|s|s.strip_prefix(prefix)){
            if digits.starts_with(['+','-']){continue;}
            if let Ok(n)=u64::from_str_radix(digits,base){if n==1u64<<63{return Some(Value::Int(i64::MIN));}if let Ok(n)=i64::try_from(n){return Some(Value::Int(-n));}}
        }
    }
    None
}
fn decimal(s:&str)->bool{
    let b=s.as_bytes();let mut i=usize::from(b.first().is_some_and(|c|matches!(c,b'+'|b'-')));let mut digits=0;
    while b.get(i).is_some_and(u8::is_ascii_digit){i+=1;digits+=1;}
    if b.get(i)==Some(&b'.'){i+=1;while b.get(i).is_some_and(u8::is_ascii_digit){i+=1;digits+=1;}}
    if digits==0{return false;}
    if b.get(i).is_some_and(|c|matches!(c,b'e'|b'E')){i+=1;if b.get(i).is_some_and(|c|matches!(c,b'+'|b'-')){i+=1;}let start=i;while b.get(i).is_some_and(u8::is_ascii_digit){i+=1;}if i==start{return false;}}
    i==b.len()
}
fn inferred(input:&[u8],allow_time:bool,account:&BudgetAccount,timestamp:&impl Fn(&str)->Result<Option<Value>>)->Result<Resolved>{
    let(tag,value)=match input{
        b""|b"~"|b"null"|b"Null"|b"NULL"=>(Tag::Null,Value::Nil),
        b"true"|b"True"|b"TRUE"=>(Tag::Bool,Value::Bool(true)),b"false"|b"False"|b"FALSE"=>(Tag::Bool,Value::Bool(false)),
        b".nan"|b".NaN"|b".NAN"=>(Tag::Float,Value::Float(f64::NAN)),
        b".inf"|b".Inf"|b".INF"|b"+.inf"|b"+.Inf"|b"+.INF"=>(Tag::Float,Value::Float(f64::INFINITY)),
        b"-.inf"|b"-.Inf"|b"-.INF"=>(Tag::Float,Value::Float(f64::NEG_INFINITY)),b"<<"=>(Tag::Merge,raw(input,account)?),
        _=>{
            let text=std::str::from_utf8(input).map_err(|_|error("invalid UTF-8 in YAML scalar"))?;
            let hint=input.first().copied().unwrap_or(0);
            if hint==b'.'{if decimal(text){if let Ok(n)=text.parse::<f64>(){if n.is_finite(){return Ok(Resolved{tag:Tag::Float,value:Value::Float(n)});}}}}
            if hint.is_ascii_digit()||matches!(hint,b'+'|b'-'){
                if allow_time{if let Some(value)=timestamp(text)?{return Ok(Resolved{tag:Tag::Timestamp,value});}}
                account.reserve(input.len())?;
                let plain=text.replace('_',"");
                if let Some(value)=integer(&plain){return Ok(Resolved{tag:Tag::Int,value});}
                if decimal(&plain){if let Ok(n)=plain.parse::<f64>(){if n.is_finite(){return Ok(Resolved{tag:Tag::Float,value:Value::Float(n)});}}}
                if let Some(value)=fallback_integer(&plain){return Ok(Resolved{tag:Tag::Int,value});}
            }
            (Tag::Str,raw(input,account)?)
        }
    };Ok(Resolved{tag,value})
}
pub(super) fn resolve(input:&[u8],tag:Option<&[u8]>,quoted:bool,account:&BudgetAccount,timestamp:impl Fn(&str)->Result<Option<Value>>)->Result<Resolved>{
    account.charge_work(1+input.len().div_ceil(64))?;
    let explicit=tag.filter(|t|!t.is_empty()&&*t!=b"!").map(named);
    if explicit==Some(Tag::Str)||(explicit.is_none()&&quoted){return Ok(Resolved{tag:Tag::Str,value:raw(input,account)?});}
    if matches!(explicit,Some(Tag::Other|Tag::Merge)){return Ok(Resolved{tag:explicit.unwrap_or(Tag::Other),value:raw(input,account)?});}
    if explicit==Some(Tag::Binary){
        use base64::Engine;
        account.reserve(input.len().checked_mul(4).and_then(|n|n.checked_add(128)).ok_or_else(||error("YAML binary allocation overflow"))?)?;
        let clean=input.iter().copied().filter(|b|!matches!(b,b'\r'|b'\n')).collect::<Vec<_>>();
        let config=base64::engine::GeneralPurposeConfig::new().with_decode_allow_trailing_bits(true);
        let bytes=base64::engine::GeneralPurpose::new(&base64::alphabet::STANDARD,config).decode(&clean).map_err(|_|error("!!binary value contains invalid base64 data"))?;
        return Ok(Resolved{tag:Tag::Binary,value:Value::from_go_bytes(bytes)});
    }
    let mut out=inferred(input,explicit.is_none()||explicit==Some(Tag::Timestamp),account,&timestamp)?;
    if let Some(tag)=explicit{
        if tag==Tag::Float&&out.tag==Tag::Int{if let Value::Int(n)=&out.value{out=Resolved{tag:Tag::Float,value:Value::Float(*n as f64)};}}
        if tag!=out.tag{return Err(error("YAML explicit scalar tag does not match its value"));}
    }
    Ok(out)
}
