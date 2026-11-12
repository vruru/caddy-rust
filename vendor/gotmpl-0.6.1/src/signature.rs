//! Go function parameter kinds. Only direct Number AST nodes are ideal
//! constants; values from parentheses, variables and pipelines stay typed.
use crate::{Result,TemplateError,Value,parse::{Expr,Number}};
use alloc::{string::String,vec::Vec,borrow::Cow};
#[derive(Clone)]
pub enum ArgKind {Any,Int,Int64,NamedInt64(&'static str,fn(i64)->Value),Uint8,Uint16,Uint32,Uint64,Float64,String,Bool,Map,ByteSlice,GoPointer(&'static str)}
#[derive(Clone)]
pub struct Signature {pub params:Cow<'static,[ArgKind]>,pub variadic:Option<ArgKind>}
impl Signature {
    pub fn new(params:Vec<ArgKind>,variadic:Option<ArgKind>)->Self{Self{params:Cow::Owned(params),variadic}}
    pub const fn from_static(params:&'static[ArgKind],variadic:Option<ArgKind>)->Self{Self{params:Cow::Borrowed(params),variadic}}
    pub(crate) fn check_len(&self,count:usize)->Result<()>{
        if count<self.params.len()||(self.variadic.is_none()&&count!=self.params.len()){Err(error())}else{Ok(())}
    }
    pub(crate) fn kind(&self,index:usize)->ArgKind{self.params.get(index).cloned().or_else(||self.variadic.clone()).unwrap_or(ArgKind::Any)}
}
fn error()->TemplateError{TemplateError::Exec(String::from("template argument is not assignable to function parameter"))}
impl ArgKind {
    pub(crate) fn constant(&self,expression:&Expr)->Result<Option<Value>>{
        let Expr::Number(_,number)=expression else{return Ok(None);};
        let signed=||match *number{Number::Int(n)=>Some(n),Number::Uint(n)=>i64::try_from(n).ok(),Number::Float(n)if n.is_finite()&&n.fract()==0.0&&n>=i64::MIN as f64&&n<9_223_372_036_854_775_808.0=>Some(n as i64),_=>None};
        let unsigned=||match *number{Number::Int(n)=>u64::try_from(n).ok(),Number::Uint(n)=>Some(n),Number::Float(n)if n.is_finite()&&n.fract()==0.0&&n>=0.0&&n<18_446_744_073_709_551_616.0=>Some(n as u64),_=>None};
        Ok(match self{
            Self::Int=>Some(Value::Int(signed().ok_or_else(error)?)),
            Self::NamedInt64(_,make)=>Some(make(signed().ok_or_else(error)?)),
            Self::Int64=>Some(Value::Int64(signed().ok_or_else(error)?)),
            Self::Uint8=>Some(Value::Uint8(unsigned().ok_or_else(error)? as u8)),
            Self::Uint16=>Some(Value::Uint16(unsigned().ok_or_else(error)? as u16)),
            Self::Uint32=>Some(Value::Uint32(unsigned().ok_or_else(error)? as u32)),
            Self::Uint64=>Some(Value::Uint(unsigned().ok_or_else(error)?)),
            Self::Float64=>Some(Value::Float(match *number{Number::Int(n)=>n as f64,Number::Uint(n)=>n as f64,Number::Float(n)=>n})),
            _=>None,
        })
    }
    pub(crate) fn validate(&self,value:&Value)->Result<()>{
        let valid=if let Value::Field(reference)=value {match (self,reference.kind()){(Self::Any,_)|(Self::String,crate::FieldKind::String)|(Self::Bool,crate::FieldKind::Bool)=>true,(Self::GoPointer(name),crate::FieldKind::Pointer(kind))=>*name==kind,_=>false}}else{match self{
            Self::Any=>true,Self::Int=>matches!(value,Value::Int(_)),Self::Int64=>matches!(value,Value::Int64(_)),Self::Uint8=>matches!(value,Value::Uint8(_)),Self::Uint16=>matches!(value,Value::Uint16(_)),Self::Uint32=>matches!(value,Value::Uint32(_)),Self::Uint64=>matches!(value,Value::Uint(_)),Self::Float64=>matches!(value,Value::Float(_)),Self::String=>value.as_go_bytes().is_some(),Self::Bool=>matches!(value,Value::Bool(_)),
            Self::ByteSlice=>matches!(value,Value::Nil)||matches!(value,Value::Slice(slice)if slice.byte_parameter_compatible()),
            Self::GoPointer(name)=>matches!(value,Value::Nil)||matches!(value,Value::Object(object)if object.go_type==Some(*name)),
            Self::NamedInt64(name,_)=>matches!(value,Value::NamedInt64(_,other)if *name==other.name),
            Self::Map=>matches!(value,Value::Nil|Value::Map(_))||{
                #[cfg(feature="std")]{matches!(value,Value::SharedMap(_))}
                #[cfg(not(feature="std"))]{false}
            },
        }};
        if valid{Ok(())}else{Err(error())}
    }
}
