//! Addressable fields retained by the template evaluator until observation.
//! Sources must check their owner and prepay before allocating a returned value.
//! No callback is made while the evaluator holds a collection lock. Collections
//! reject retained references on mutation; callers materialize at Interface boundaries.
use alloc::sync::Arc;
use crate::{Result,TemplateError,Value};
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum FieldKind { String, Bool, Pointer(&'static str) }
impl FieldKind {
 pub fn type_name(self)->&'static str {match self{Self::String=>"string",Self::Bool=>"bool",Self::Pointer(name)=>name}}
 fn accepts(self,value:&Value)->bool {match value{Value::Field(reference)=>reference.kind==self,_=>match self{Self::String=>value.as_go_bytes().is_some(),Self::Bool=>matches!(value,Value::Bool(_)),Self::Pointer(name)=>matches!(value,Value::Object(object)if object.go_type==Some(name))}}}
}
/// A closed host source owns its state, but only weakly owns its render control.
/// `read_field` must not retain the returned reference or insert it in its state.
pub trait FieldSource:core::any::Any+Send+Sync {fn read_field(&self,name:&'static str)->Result<Value>;}
pub struct FieldReference {source:Arc<dyn FieldSource>,name:&'static str,kind:FieldKind}
impl FieldReference {
 /// The caller must reserve the Arc/descriptor storage before construction.
 pub fn new(source:Arc<dyn FieldSource>,name:&'static str,kind:FieldKind)->Self {Self{source,name,kind}}
 /// Read-only concrete source admission; no type-name based provenance.
 pub fn source<T:FieldSource>(&self)->Option<&T>{let source:&dyn core::any::Any=self.source.as_ref();source.downcast_ref::<T>()}
 pub fn kind(&self)->FieldKind{self.kind}
 pub fn name(&self)->&'static str{self.name}
}
impl Value {
 /// Materialize only at an observation/Interface boundary, never variable copy.
 /// The optional gate executes before every source callback, outside all locks.
 pub fn resolve_field_with<G>(&self,mut gate:impl FnMut(&Value)->Result<G>)->Result<Value>{
  let mut value=self.clone();let mut seen:[Option<Arc<FieldReference>>;32]=core::array::from_fn(|_|None);let mut count=0;
  while let Value::Field(reference)=&value {
   if count==seen.len(){return Err(TemplateError::Exec("field reference depth exceeded".into()));}
   if seen[..count].iter().flatten().any(|prior|Arc::ptr_eq(prior,reference)){return Err(TemplateError::Exec("cyclic field reference".into()));}
   seen[count]=Some(reference.clone());count+=1;let _guard=gate(&value)?;
   let next=reference.source.read_field(reference.name)?;
   if !reference.kind.accepts(&next){return Err(TemplateError::Exec("field reference returned incompatible value".into()));}
   value=next;
  }
  Ok(value)
 }
 pub fn resolve_field(&self)->Result<Value>{self.resolve_field_with(|_|Ok(()))}
}

/// The producer has prepaid its input storage. This fixed-stack structural
/// check allocates no metadata and visits at most 16,384 nodes at depth 32.
/// Snapshot methods clone only one existing Arc at each live depth and return
/// after releasing the cell lock, before any child cell is inspected. It never
/// executes dynamic fields, map views, Stringers or opaque host callbacks.
/// Existing opaque payloads retain their previous trusted-host contract.
pub(crate) fn check_storage_fields(values:&[Value])->Result<()> {
 fn visit(value:&Value,depth:usize,nodes:&mut usize)->Result<()> {
  if depth>32{return Err(TemplateError::Exec("slice input graph nesting limit exceeded".into()));}
  *nodes=nodes.checked_sub(1).ok_or_else(||TemplateError::Exec("slice input graph node limit exceeded".into()))?;
  match value {
   Value::Field(_)=>return Err(TemplateError::Exec("slice storage rejects retained field references".into())),
   Value::List(values)=>for value in values.iter(){visit(value,depth+1,nodes)?;},
   Value::Slice(slice)=>if let Some(values)=slice.retained_values(){for value in values.iter(){visit(value,depth+1,nodes)?;}},
   Value::Map(values)=>for value in values.values(){visit(value,depth+1,nodes)?;},
   #[cfg(feature="std")]
   Value::SharedMap(map)=>{let snapshot=map.snapshot_go()?;for value in snapshot.values(){visit(value,depth+1,nodes)?;}},
   #[cfg(feature="std")]
   Value::GenericMap(map)=>{let snapshot=map.snapshot()?;for(key,value)in snapshot.iter(){visit(key,depth+1,nodes)?;visit(value,depth+1,nodes)?;}},
   Value::Object(object)=>for value in object.fields.values(){visit(value,depth+1,nodes)?;},
   _=>{}
  }Ok(())
 }
 let mut nodes=16_384;for value in values{visit(value,0,&mut nodes)?;}Ok(())
}
