//! Only addressable host time fields acquire pointer-receiver methods. The
//! state is owned by one render and never aliases authenticated TLS facts.
use super::*;
use std::sync::{Mutex,Weak};
use crate::http_runtime::templates::render::Control;
struct View{time:Mutex<Time>,owner:Weak<Control>}
impl View{
    fn live(&self)->gotmpl::Result<Arc<Control>>{let c=self.owner.upgrade().ok_or_else(||err("time owner retired"))?;c.check()?;Ok(c)}
    fn get(&self)->gotmpl::Result<Time>{let _c=self.live()?;self.time.lock().map_err(|_|err("time receiver state unavailable")).map(|t|t.clone())}
    fn decode(&self,name:&str,args:&[V])->R{
        arity(args,1,1)?;let c=self.live()?;
        let length=match &args[0]{V::Nil=>0,V::Slice(s)if s.go_type()=="[]uint8"=>s.len(),_=>return Err(err("time decoder requires []uint8"))};
        if length>MAX_BYTES{return Err(err("time decoder input exceeds limit"))}
        c.charge(length.div_ceil(64)+1)?;c.reserve_host_bytes(length.checked_mul(2).and_then(|n|n.checked_add(4096)).ok_or_else(||err("time decoder size overflow"))?)?;
        let held=match &args[0]{V::Nil=>None,V::Slice(s)=>Some(s.visible_bytes().ok_or_else(||err("time decoder requires []uint8"))?),_=>return Err(err("time decoder requires []uint8"))};
        let bytes=held.as_deref().unwrap_or(&[]);
        let decoded=match name{"UnmarshalBinary"|"GobDecode"=>codecs::decode_binary(bytes).map(Some),"UnmarshalJSON"=>codecs::decode_json(bytes),_=>codecs::decode_text(bytes).map(Some)};
        let next=match decoded{Ok(next)=>next,Err(error)=>{
            // A Go method with one `error` result returns that value to the
            // template. Only (value,error) invokes automatic error propagation.
            let text=match error{gotmpl::TemplateError::Exec(text)=>text,error=>error.to_string()};
            return Ok(super::super::super::forms::error_value(text))
        }};
        // Decode and validate first; a failed decoder does not partially erase
        // a field, and a retired render cannot commit a replacement.
        if let Some(next)=next{c.check()?;let mut time=self.time.lock().map_err(|_|err("time receiver state unavailable"))?;c.check()?;*time=next;}
        Ok(V::NilError)
    }
}
fn data(o:&gotmpl::Object)->gotmpl::Result<&View>{o.host_data::<View>("time.Time").ok_or_else(||err("invalid time.Time receiver"))}
pub(super)fn snapshot(o:&gotmpl::Object)->gotmpl::Result<Time>{data(o)?.get()}
fn stringer(o:&gotmpl::Object)->R{output(display::string(&data(o)?.get()?)?)}
fn json(o:&gotmpl::Object)->R{let temporary=time_value(data(o)?.get()?)?;let V::Object(temporary)=temporary else{return Err(err("invalid time JSON projection"))};match temporary.json.as_ref().ok_or_else(||err("time JSON projection absent"))?{Ok(text)=>output(text.to_string()),Err(error)=>Err(err(error.to_string()))}}
pub(super)fn value(time:Time,control:&Arc<Control>)->R{
    control.reserve_host_bytes(16384)?;control.check()?;
    let view=Arc::new(View{time:Mutex::new(time),owner:Arc::downgrade(control)});
    let mut methods=BTreeMap::<Arc<str>,gotmpl::ValueFunc>::new();let mut signatures=BTreeMap::new();
    for name in["UnmarshalBinary","GobDecode","UnmarshalText","UnmarshalJSON"]{let v=view.clone();methods.insert(name.into(),Arc::new(move|a|v.decode(name,a)));signatures.insert(name.into(),gotmpl::Signature::from_static(&[gotmpl::ArgKind::ByteSlice],None));}
    Ok(V::Object(Arc::new(gotmpl::Object{go_type:Some("time.Time"),host_type:Some(&TIME_TYPE),methods,method_signatures:signatures,dynamic_stringer:Some(stringer),json_dynamic:Some(json),formatter:Some(display::formatter),data:Some(view),data_bytes:std::mem::size_of::<View>(),equal:Some(time_equal),deep_equal:Some(time_deep_equal),key_order:Some(time_key_order),..gotmpl::Object::default()})))
}
