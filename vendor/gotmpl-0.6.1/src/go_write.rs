//! Internal raw Go-string output. UTF-8 APIs fail instead of changing bytes.
use alloc::vec::Vec;
use core::fmt::{self,Write};
use crate::{Result,TemplateError,Value};
pub(crate) trait GoWrite:Write {fn write_bytes(&mut self,bytes:&[u8])->fmt::Result;}
pub(crate) struct FmtSink<'a,W:Write>{pub inner:&'a mut W,pub non_utf8:bool}
impl<W:Write> Write for FmtSink<'_,W>{fn write_str(&mut self,text:&str)->fmt::Result{self.inner.write_str(text)}}
impl<W:Write> GoWrite for FmtSink<'_,W>{fn write_bytes(&mut self,bytes:&[u8])->fmt::Result{match core::str::from_utf8(bytes){Ok(text)=>self.inner.write_str(text),Err(_)=>{self.non_utf8=true;Err(fmt::Error)}}}}
pub(crate) struct VecSink<'a>(pub &'a mut Vec<u8>);
impl Write for VecSink<'_>{fn write_str(&mut self,text:&str)->fmt::Result{self.write_bytes(text.as_bytes())}}
impl GoWrite for VecSink<'_>{fn write_bytes(&mut self,bytes:&[u8])->fmt::Result{self.0.extend_from_slice(bytes);Ok(())}}
/// This printer is shared by raw actions and Sprint. It never builds an
/// unbounded intermediate String, including for nested maps and lists.
pub(crate) fn write_value<W:GoWrite>(writer:&mut W,value:&Value,depth:usize)->Result<()>{
    if depth>32{return Err(TemplateError::Exec("template printed value exceeds nesting limit".into()));}
    if let Value::Slice(slice)=value && let Some(display)=slice.string_value()? {
        return write_value(writer,&display,depth+1);
    }
    if let Some(bytes)=value.as_go_bytes(){writer.write_bytes(bytes)?;return Ok(());}
    #[cfg(feature="std")] if let Value::GenericMap(map)=value{
        writer.write_str("map[")?;for(index,(key,value))in map.snapshot()?.iter().enumerate(){if index>0{writer.write_str(" ")?;}write_value(writer,key,depth+1)?;writer.write_str(":")?;write_value(writer,value,depth+1)?;}writer.write_str("]")?;return Ok(());
    }
    if let Some(map)=value.map_snapshot()?{
        writer.write_str("map[")?;
        for(index,(key,value))in map.iter().enumerate(){if index>0{writer.write_str(" ")?;}writer.write_bytes(key.as_bytes())?;writer.write_str(":")?;write_value(writer,value,depth+1)?;}
        writer.write_str("]")?;return Ok(());
    }
    match value{
        Value::Slice(slice)=>{writer.write_str("[")?;for(index,value)in slice.iter().enumerate(){if index>0{writer.write_str(" ")?;}write_value(writer,&value,depth+1)?;}writer.write_str("]")?;}
        Value::List(values)=>{writer.write_str("[")?;for(index,value)in values.iter().enumerate(){if index>0{writer.write_str(" ")?;}write_value(writer,value,depth+1)?;}writer.write_str("]")?;}
        Value::Object(object)=>{
            if let Some(formatter)=object.formatter {
                let formatted=formatter(object,'v',&crate::HostFormat::default())?;
                writer.write_bytes(formatted.as_go_bytes().ok_or_else(||TemplateError::Exec("host formatter must return string".into()))?)?;
                return Ok(());
            }

            if let Some(display)=&object.display{writer.write_str(display)?;}
            else if object.is_nil_pointer(){writer.write_str("<nil>")?;}
            else if depth>0 && object.go_type.is_some_and(|ty|ty.starts_with('*')) {
                let address=object.pointer_identity.unwrap_or(object.as_ref() as *const crate::Object as usize);
                write!(writer,"0x{address:x}")?;
            }
            else if let Some(fields)=&object.field_order{writer.write_str("{")?;for(index,name)in fields.iter().enumerate(){if index>0{writer.write_str(" ")?;}if let Some(value)=object.field_value(name)?{write_value(writer,&value,depth+1)?;}}writer.write_str("}")?;}
            else{return Err(TemplateError::Exec("host value has no Go printable representation".into()));}
        }
        Value::Function(_)=>return Err(TemplateError::Exec("cannot print Go function value".into())),
        _=>write!(writer,"{value}")?,
    }Ok(())
}
