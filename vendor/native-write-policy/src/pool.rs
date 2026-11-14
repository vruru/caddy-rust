//! Concrete atomic ownership only; safe to release under a protocol lock.
//! No arbitrary callbacks, waiters, registry or application references.
use std::{fmt,sync::{Arc,atomic::{AtomicUsize,Ordering}}};
#[derive(Debug)]pub struct Denied;
impl fmt::Display for Denied {fn fmt(&self,f:&mut fmt::Formatter<'_>)->fmt::Result{f.write_str("write policy allocation budget exhausted")}}
impl std::error::Error for Denied{}
#[derive(Debug)]struct State{limit:usize,used:AtomicUsize}
#[derive(Clone,Debug)]pub struct Pool(Arc<State>);
impl Pool{
 pub fn new(limit:usize)->Self{Self(Arc::new(State{limit,used:AtomicUsize::new(0)}))}
 pub fn reserve(&self,bytes:usize)->Result<Lease,Denied>{
  if bytes>self.0.limit{return Err(Denied)}
  let mut current=self.0.used.load(Ordering::Acquire);
  loop{let next=current.checked_add(bytes).filter(|n|*n<=self.0.limit).ok_or(Denied)?;
   match self.0.used.compare_exchange_weak(current,next,Ordering::AcqRel,Ordering::Acquire){Ok(_)=>return Ok(Lease{pool:self.clone(),bytes}),Err(actual)=>current=actual}
  }
 }
 pub fn same_owner(&self,other:&Self)->bool{Arc::ptr_eq(&self.0,&other.0)}
 pub fn used(&self)->usize{self.0.used.load(Ordering::Acquire)}
}
#[derive(Debug)]pub struct Lease{pool:Pool,bytes:usize}
impl Lease{
 /// Resize atomically; a failed growth leaves the original credit unchanged.
 pub fn resize(&mut self,new_bytes:usize)->Result<(),Denied>{
  if new_bytes>self.bytes{let mut extra=self.pool.reserve(new_bytes-self.bytes)?;extra.bytes=0;}
  else if new_bytes<self.bytes{let previous=self.pool.0.used.fetch_sub(self.bytes-new_bytes,Ordering::AcqRel);debug_assert!(previous>=self.bytes-new_bytes);}
  self.bytes=new_bytes;Ok(())
 }
 pub fn bytes(&self)->usize{self.bytes} pub fn pool(&self)->Pool{self.pool.clone()}}
impl AsRef<[u8]> for Lease{fn as_ref(&self)->&[u8]{&[]}}
impl Drop for Lease{fn drop(&mut self){let previous=self.pool.0.used.fetch_sub(self.bytes,Ordering::AcqRel);debug_assert!(previous>=self.bytes,"write policy allocation accounting underflow");}}
