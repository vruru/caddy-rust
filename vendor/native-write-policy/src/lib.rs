//! Exact immutable write constraints with concrete allocation ownership.
//! Configuration handlers opt in separately; this crate registers no runtime.
#![forbid(unsafe_code)]
mod pool;
pub use pool::{Pool,Lease,Denied};
use std::{alloc::Layout,num::NonZeroU64,sync::Arc,time::{Duration,Instant}};
pub const MAX_RULES:usize=64;
#[derive(Clone,Copy,Debug)]pub struct Rule{pub installed:Instant,pub idle:Option<Duration>,pub rate:Option<NonZeroU64>,pub hard:Option<Instant>}
#[derive(Debug)]pub enum Error{TooManyRules,Arithmetic,Allocation(Denied)}
impl std::fmt::Display for Error{fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{match self{Self::TooManyRules=>f.write_str("too many active write policies"),Self::Arithmetic=>f.write_str("write policy arithmetic or capacity exhausted"),Self::Allocation(e)=>e.fmt(f)}}}
impl std::error::Error for Error{fn source(&self)->Option<&(dyn std::error::Error+'static)>{match self{Self::Allocation(e)=>Some(e),_=>None}}}
#[derive(Clone,Copy,Debug)]struct Rate{installed:Instant,idle:Duration,rate:NonZeroU64}
/// All owned allocation fields precede their one concrete allocation lease.
/// Clones share this complete object; no callback or user data enters it.
#[derive(Debug)]pub struct PolicySet{hard:Option<Instant>,flat:Option<Duration>,rates:Vec<Rate>,_lease:Lease}
impl PolicySet{
 pub fn allocation_bound(rules:&[Rule])->Result<usize,Error>{
  if rules.len()>MAX_RULES{return Err(Error::TooManyRules)}
  let count=rules.iter().filter(|r|r.idle.is_some_and(|d|!d.is_zero())&&r.rate.is_some()).count();
  let rates=Layout::array::<Rate>(count).map_err(|_|Error::Arithmetic)?.size();
  let (arc,_)=Layout::new::<[usize;2]>().extend(Layout::new::<Self>()).map_err(|_|Error::Arithmetic)?;
  // Named Rust allocation layouts, not malloc rounding/opaque provider RSS.
  arc.pad_to_align().size().checked_add(rates).and_then(|n|n.checked_add(128)).ok_or(Error::Arithmetic)
 }
 pub fn compile(pool:&Pool,rules:&[Rule])->Result<Arc<Self>,Error>{
  let lease=pool.reserve(Self::allocation_bound(rules)?).map_err(Error::Allocation)?;
  let count=rules.iter().filter(|r|r.idle.is_some_and(|d|!d.is_zero())&&r.rate.is_some()).count();
  let mut rates=Vec::new();rates.try_reserve_exact(count).map_err(|_|Error::Arithmetic)?;
  if rates.capacity()!=count{return Err(Error::Arithmetic)}
  let(mut hard,mut flat)=(None,None);
  for rule in rules{
   if let Some(at)=rule.hard{hard=Some(hard.map_or(at,|old:Instant|old.min(at)));}
   let Some(idle)=rule.idle.filter(|d|!d.is_zero())else{continue};
   if let Some(rate)=rule.rate{rates.push(Rate{installed:rule.installed,idle,rate})}else{flat=Some(flat.map_or(idle,|old:Duration|old.min(idle)));}
  }
  Ok(Arc::new(Self{hard,flat,rates,_lease:lease}))
 }
 pub fn deadline(&self,bytes:u64,pending:Option<Instant>,last:Option<Instant>)->Result<Option<Instant>,Error>{
  let Some(pending)=pending else{return Ok(self.hard)};let mut result=self.hard;
  if let Some(flat)=self.flat{let at=last.map_or(pending,|last|last.max(pending)).checked_add(flat).ok_or(Error::Arithmetic)?;result=Some(result.map_or(at,|old|old.min(at)));}
  for rate in &self.rates{let ns=u128::from(bytes)*1_000_000_000/u128::from(rate.rate.get());let secs=u64::try_from(ns/1_000_000_000).map_err(|_|Error::Arithmetic)?;
   let at=rate.installed.checked_add(rate.idle).and_then(|t|t.checked_add(Duration::new(secs,(ns%1_000_000_000)as u32))).ok_or(Error::Arithmetic)?;result=Some(result.map_or(at,|old|old.min(at)));}
  Ok(result)
 }
 pub fn boundary(self:&Arc<Self>,pending:Instant,last:Option<Instant>,bytes_before:u64)->Boundary{Boundary{policies:self.clone(),pending,last,bytes_before}}
}
/// A cheap clone owns the actual complete prepaid policy set. Foreign buffer
/// credits and Wakers are deliberately absent; protocol payload ownership stays
/// in its existing transport-specific retirement machinery.
#[derive(Clone,Debug)]pub struct Boundary{policies:Arc<PolicySet>,pending:Instant,last:Option<Instant>,bytes_before:u64}
impl Boundary{
 pub fn deadline(&self,bytes:usize,last:Option<Instant>)->Result<Option<Instant>,Error>{
  let bytes=u64::try_from(bytes).ok().and_then(|n|self.bytes_before.checked_add(n)).ok_or(Error::Arithmetic)?;
  self.policies.deadline(bytes,Some(self.pending),last.max(self.last))
 }
 pub fn expired_at(&self,bytes:usize,last:Option<Instant>,now:Instant)->bool{match self.deadline(bytes,last){Ok(at)=>at.is_some_and(|at|now>=at),Err(_)=>true}}
}
