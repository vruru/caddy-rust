use super::*;
use base64::Engine;
use gotmpl::go_utf8_text;
#[path="json_input.rs"]mod json_input;
pub(super) fn add(m:&mut M,context:&gotmpl::MapContext){
    for name in ["b64enc","b64dec","b32enc","b32dec","fromJson","mustFromJson","toJson","mustToJson","toPrettyJson","mustToPrettyJson","toRawJson","mustToRawJson","sha1sum","sha256sum","sha512sum","adler32sum"]{
        let context=context.clone();put(m,name,move|a|call(name,a,&context));
    }
}
pub(super) fn from_json(value:&serde_json::Value,context:&gotmpl::MapContext,depth:usize)->R{from_json_inner(value,context,depth,&mut 0)}
fn from_json_inner(value:&serde_json::Value,context:&gotmpl::MapContext,depth:usize,nodes:&mut usize)->R{
    if *nodes>=MAX_ITEMS{return Err(err("JSON template node limit exceeded"));}*nodes+=1;
    if depth>32{return Err(err("JSON value exceeds template depth limit"));}
    match value{
        serde_json::Value::Null=>Ok(V::Nil),serde_json::Value::Bool(value)=>Ok(V::Bool(*value)),
        serde_json::Value::Number(value)=>Ok(V::Float(value.as_f64().ok_or_else(||err("JSON number is outside float64 range"))?)),
        serde_json::Value::String(value)=>output(value.clone()),
        serde_json::Value::Array(values)=>list(values.iter().map(|v|from_json_inner(v,context,depth+1,nodes)).collect::<gotmpl::Result<_>>()?),
        serde_json::Value::Object(values)=>context.map(values.iter().map(|(k,v)|Ok((Arc::from(k.as_str()),from_json_inner(v,context,depth+1,nodes)?))).collect::<gotmpl::Result<_>>()?),
    }
}
fn arg_bytes(a:&[V],index:usize)->gotmpl::Result<&[u8]>{
    a.get(index).and_then(V::as_go_bytes).ok_or_else(||err("expected string argument"))
}
struct JsonValue<'a>(&'a V,usize);
impl serde::Serialize for JsonValue<'_>{
    fn serialize<S:serde::Serializer>(&self,serializer:S)->Result<S::Ok,S::Error>{
        use serde::ser::{Error,SerializeMap,SerializeSeq};
        if self.1>32{return Err(S::Error::custom("template JSON nesting limit exceeded"));}
        // A named, non-pointer slice may implement encoding.TextMarshaler
        // even when nil (net.IP is one). Go checks this before slice nilness.
        if let V::Slice(slice)=self.0 && let Some(method)=slice.named_type().and_then(|kind|kind.methods.iter().find(|method|method.name=="MarshalText")) {
            let text=(method.invoke)(slice,&[]).map_err(S::Error::custom)?;
            if let Some(bytes)=text.as_go_bytes(){return serializer.serialize_str(&go_utf8_text(bytes));}
            if let V::Slice(bytes)=&text && let Some(bytes)=bytes.visible_bytes(){return serializer.serialize_str(&go_utf8_text(&bytes));}
            return Err(S::Error::custom("TextMarshaler must return []uint8"));
        }
        if self.0.is_go_nil(){return serializer.serialize_none();}
        if let Some(snapshot)=self.0.map_snapshot().map_err(S::Error::custom)?{
            let mut object=serializer.serialize_map(Some(snapshot.len()))?;
            for(key,value)in snapshot.iter(){object.serialize_entry(&go_utf8_text(key.as_bytes()),&JsonValue(value,self.1+1))?;}return object.end();
        }
        match self.0{
            V::Field(_)=>{let value=self.0.resolve_field().map_err(S::Error::custom)?;JsonValue(&value,self.1+1).serialize(serializer)},
            V::GenericMap(map)=>{
                let snapshot=map.snapshot().map_err(S::Error::custom)?;
                let account=map.budget_account();
                account.reserve(snapshot.len().checked_mul(std::mem::size_of::<(String,&V)>()+64).ok_or_else(||S::Error::custom("JSON key allocation overflow"))?).map_err(S::Error::custom)?;
                let mut entries=Vec::new();entries.try_reserve_exact(snapshot.len()).map_err(S::Error::custom)?;
                for(key,value)in snapshot.iter(){
                    let name=if let Some(bytes)=key.as_go_bytes(){account.reserve(bytes.len().saturating_mul(3)).map_err(S::Error::custom)?;go_utf8_text(bytes).into_owned()}else{match key{
                        V::NamedInt64(n,kind)if kind.kind.starts_with("uint")=>(*n as u64).to_string(),V::Int(n)|V::Int64(n)|V::NamedInt64(n,_)=>n.to_string(),V::Uint(n)=>n.to_string(),V::Uint32(n)=>n.to_string(),V::Uint8(n)=>n.to_string(),V::Uint16(n)=>n.to_string(),
                        V::Object(object)if object.go_type==Some("time.Time")=>{
                            let json=object.json.as_ref().ok_or_else(||S::Error::custom("time has no text encoding"))?.as_ref().map_err(S::Error::custom)?;
                            serde_json::from_str::<String>(json).map_err(S::Error::custom)?
                        }
                        _=>return Err(S::Error::custom("unsupported dynamic JSON map key")),
                    }};
                    entries.push((name,value));
                }
                entries.sort_unstable_by(|(a,_),(b,_)|a.cmp(b));
                let mut object=serializer.serialize_map(Some(entries.len()))?;for(key,value)in entries{object.serialize_entry(&key,&JsonValue(value,self.1+1))?;}object.end()
            }
            V::Nil|V::NilError=>serializer.serialize_none(),V::Bool(value)=>serializer.serialize_bool(*value),
            V::NamedInt64(value,kind)if kind.kind.starts_with("uint")=>serializer.serialize_u64(*value as u64),
            V::Int(value)|V::Int64(value)|V::NamedInt64(value,_)=>serializer.serialize_i64(*value),
            V::Uint(value)=>serializer.serialize_u64(*value),V::Uint32(value)=>serializer.serialize_u32(*value),V::Uint8(value)=>serializer.serialize_u8(*value),V::Uint16(value)=>serializer.serialize_u16(*value),
            V::Float(value)=>{let text=crate::json_float::format(*value).map_err(S::Error::custom)?;let raw=serde_json::from_str::<&serde_json::value::RawValue>(&text).map_err(S::Error::custom)?;raw.serialize(serializer)},
            V::String(value)=>serializer.serialize_str(value),
            V::ByteString(value)=>serializer.serialize_str(&go_utf8_text(value.as_bytes())),
            V::Slice(slice)=>{if let Some(bytes)=slice.visible_bytes(){serializer.serialize_str(&base64::engine::general_purpose::STANDARD.encode(bytes))}else{let mut sequence=serializer.serialize_seq(Some(slice.len()))?;for value in slice.iter(){sequence.serialize_element(&JsonValue(&value,self.1+1))?;}sequence.end()}},
            V::List(values)=>{let mut sequence=serializer.serialize_seq(Some(values.len()))?;for value in values.iter(){sequence.serialize_element(&JsonValue(value,self.1+1))?;}sequence.end()},
            V::Object(value)=>{
                if let Some(encode)=value.json_dynamic{
                    let encoded=encode(value).map_err(S::Error::custom)?;
                    let bytes=encoded.as_go_bytes().ok_or_else(||S::Error::custom("host JSON encoder must return a Go string"))?;
                    let raw=serde_json::from_slice::<&serde_json::value::RawValue>(bytes).map_err(S::Error::custom)?;
                    return raw.serialize(serializer);
                }
                if let Some(json)=&value.json{let text=json.as_ref().map_err(S::Error::custom)?;let raw=serde_json::from_str::<&serde_json::value::RawValue>(text).map_err(S::Error::custom)?;return raw.serialize(serializer);}
                let mut object=serializer.serialize_map(None)?;
                if let Some(fields)=&value.json_fields{
                    for field in fields.iter(){if let Some(value)=value.field_value(field.source).map_err(S::Error::custom)?{if !field.omit_empty||value.is_truthy(){object.serialize_entry(&go_utf8_text(field.name.as_bytes()),&JsonValue(&value,self.1+1))?;}}}
                }else if let Some(order)=&value.field_order{
                    for name in order.iter(){if let Some(value)=value.field_value(name).map_err(S::Error::custom)?{object.serialize_entry(&go_utf8_text(name.as_bytes()),&JsonValue(&value,self.1+1))?;}}
                }else{for key in value.fields.keys(){if let Some(value)=value.field_value(key).map_err(S::Error::custom)?{object.serialize_entry(&go_utf8_text(key.as_bytes()),&JsonValue(&value,self.1+1))?;}}}
                object.end()
            }
            _=>Err(S::Error::custom("unsupported template value in JSON")),
        }
    }
}
struct Writer(Vec<u8>);
impl std::io::Write for Writer{
    fn write(&mut self,input:&[u8])->std::io::Result<usize>{if input.len()>MAX_BYTES.saturating_sub(self.0.len()){return Err(std::io::Error::other("JSON template byte limit exceeded"));}self.0.extend_from_slice(input);Ok(input.len())}
    fn flush(&mut self)->std::io::Result<()>{Ok(())}
}
pub(super) fn decode_base64_bytes(input:&[u8])->Result<Vec<u8>,base64::DecodeError>{
    let clean=input.iter().copied().filter(|byte|!matches!(*byte,b'\r'|b'\n')).collect::<Vec<_>>();
    base64::engine::GeneralPurpose::new(&base64::alphabet::STANDARD,base64::engine::GeneralPurposeConfig::new().with_decode_allow_trailing_bits(true)).decode(&clean)
}
fn call(name:&str,a:&[V],context:&gotmpl::MapContext)->R{
    arity(a,1,1)?;
    match name{
        "fromJson"|"mustFromJson"=>{
            let raw=arg_bytes(a,0)?;if raw.len()>MAX_BYTES{return Err(err("JSON template input exceeds byte limit"));}
            if name=="mustFromJson"{
                let value=crate::admin_json::decoded_go_bounded(raw,32,4*MAX_ITEMS).map_err(|e|err(e.to_string()))?;from_json(&value,context,0)
            }else{
                let sanitized=crate::admin_json::sanitize_go_bounded(raw,32,4*MAX_ITEMS).map_err(|_|err("JSON template materialization limit exceeded"))?;
                let text=match std::str::from_utf8(&sanitized){Ok(text)=>text,Err(_)=>return Ok(V::Nil)};
                let value=match serde_json::from_str::<&serde_json::value::RawValue>(text){Ok(value)=>value,Err(_)=>return Ok(V::Nil)};
                json_input::non_must(value,context)
            }
        }
        "toJson"|"mustToJson"|"toRawJson"|"mustToRawJson"|"toPrettyJson"|"mustToPrettyJson"=>{
            let result=(||{
                let value=JsonValue(&a[0],0);let mut writer=Writer(Vec::new());
                if name.ends_with("PrettyJson"){serde_json::to_writer_pretty(&mut writer,&value)}else{serde_json::to_writer(&mut writer,&value)}.map_err(|e|err(e.to_string()))?;
                let input=String::from_utf8(writer.0).map_err(|_|err("JSON writer UTF-8 invariant"))?;
                let mut output_text=String::new();
                for c in input.chars(){let replacement=match c{
                    '<' if !name.ends_with("RawJson")=>Some("\\u003c"),
                    '>' if !name.ends_with("RawJson")=>Some("\\u003e"),
                    '&' if !name.ends_with("RawJson")=>Some("\\u0026"),
                    '\u{2028}'=>Some("\\u2028"),'\u{2029}'=>Some("\\u2029"),_=>None,
                };if let Some(replacement)=replacement{checked_length(output_text.len(),replacement.len())?;output_text.push_str(replacement);}else{checked_length(output_text.len(),c.len_utf8())?;output_text.push(c);}}
                output(output_text)
            })();
            match result{Err(_)if !name.starts_with("must")=>output(""),result=>result}
        }
        "b64enc"=>{let input=arg_bytes(a,0)?;if input.len().div_ceil(3)*4>MAX_BYTES{return Err(err("base64 output exceeds byte limit"));}output(base64::engine::general_purpose::STANDARD.encode(input))}
        "b64dec"=>{
            let input=arg_bytes(a,0)?;
            let clean_length=input.iter().filter(|byte|!matches!(**byte,b'\r'|b'\n')).count();
            match decode_base64_bytes(input){
                Ok(bytes)=>{if bytes.len()>MAX_BYTES{return Err(err("base64 result exceeds byte limit"));}Ok(V::from_go_bytes(bytes))}
                Err(error)=>{let offset=match error{base64::DecodeError::InvalidByte(offset,_)|base64::DecodeError::InvalidLastSymbol(offset,_)=>offset,base64::DecodeError::InvalidLength(length)=>length.saturating_sub(length%4),base64::DecodeError::InvalidPadding=>clean_length.saturating_sub(1)};output(format!("illegal base64 data at input byte {offset}"))}
            }
        }
        "b32enc"=>{let input=arg_bytes(a,0)?;if input.len().div_ceil(5)*8>MAX_BYTES{return Err(err("base32 output exceeds byte limit"));}output(data_encoding::BASE32.encode(input))}
        "b32dec"=>{
            let input=arg_bytes(a,0)?;
            let clean:Vec<u8>=input.iter().filter(|b|**b!=b'\r'&&**b!=b'\n').copied().collect();
            match data_encoding::BASE32.decode(&clean){
                Ok(bytes)=>{if bytes.len()>MAX_BYTES{return Err(err("base32 result exceeds byte limit"));}Ok(V::from_go_bytes(bytes))}
                Err(error)=>output(format!("illegal base32 data at input byte {}",error.position)),
            }
        }
        "sha1sum"|"sha256sum"|"sha512sum"=>{use sha2::Digest;let input=arg_bytes(a,0)?;output(match name{"sha1sum"=>format!("{:x}",sha1::Sha1::digest(input)),"sha256sum"=>format!("{:x}",sha2::Sha256::digest(input)),_=>format!("{:x}",sha2::Sha512::digest(input))})}
        "adler32sum"=>{let mut sum=1u32;let mut rolling=0u32;for byte in arg_bytes(a,0)?{sum=(sum+u32::from(*byte))%65521;rolling=(rolling+sum)%65521;}output(((rolling<<16)|sum).to_string())}
        _=>Err(err("unregistered encoding helper")),
    }
}
