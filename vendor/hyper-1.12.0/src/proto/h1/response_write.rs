//! A single concrete response owner beside the actual HTTP/1 write buffer.
use std::{io,pin::Pin,task::{Context,Poll},time::Instant};
use bytes::Bytes;
use crate::{common::time::Time,ext::{ResponseWriteControl,ResponseWriteOwner,WriteTerminal},rt::Sleep};
pub(super) struct BodyState<D>{pub chunk:Option<(D,bool)>,pub ended:bool,pub end_queued:bool,_retained:Option<Bytes>}
impl<D> BodyState<D>{pub fn new(retained:Option<Bytes>)->Self{Self{chunk:None,ended:false,end_queued:false,_retained:retained}}}
pub(super) struct ObservedWrite{
 owner:ResponseWriteOwner,timer:Time,sleep:Option<Pin<Box<dyn Sleep>>>,sleep_at:Option<Instant>,
 boundary:Option<Boundary>,finish_after_flush:bool,pub needs_flush:bool,
 _retained:Option<Bytes>,
}
struct Boundary{wire_total:usize,accepted:usize,payload_start:usize,payload_len:usize,staged_payload:usize,staged_wire:usize,_raw:Bytes}
fn error(e:impl Into<Box<dyn std::error::Error+Send+Sync>>)->io::Error{io::Error::other(e)}
impl ObservedWrite{
 pub fn new(control:ResponseWriteControl,timer:Time)->io::Result<Self>{let owner=control.claim().map_err(error)?;let retained=owner.retention();Ok(Self{owner,timer,sleep:None,sleep_at:None,boundary:None,finish_after_flush:false,needs_flush:false,_retained:retained})}
 pub fn retention(&self)->Option<Bytes>{self._retained.clone()}
 pub fn same_control(&self,control:&ResponseWriteControl)->bool{self.owner.same_control(control)}
 pub fn begin(&mut self,start:usize,payload:usize,wire:usize,raw:Bytes)->io::Result<()>{
  if self.boundary.is_some()||start.checked_add(payload).is_none_or(|n|n>wire){return Err(error("invalid HTTP/1 response boundary"))}
  if wire==0{return Ok(())}
  self.owner.start_boundary(payload,self.timer.now()).map_err(error)?;
  self.boundary=Some(Boundary{wire_total:wire,accepted:0,payload_start:start,payload_len:payload,staged_payload:0,staged_wire:0,_raw:raw});Ok(())
 }
 pub fn pending(&self)->bool{self.boundary.is_some()||self.needs_flush}
 pub fn finish(&mut self)->io::Result<()>{self.finish_after_flush=true;if !self.pending(){self.owner.finish().map_err(error)?;}Ok(())}
 pub fn done(&self)->bool{self.owner.snapshot().terminal==Some(WriteTerminal::Success)&&!self.pending()}
 pub fn abandon(&self){self.owner.abandon();}
 pub fn accepted(&mut self,n:usize)->io::Result<()>{
  let b=self.boundary.as_mut().ok_or_else(||error("unobserved HTTP/1 output under response policy"))?;
  let end=b.accepted.checked_add(n).filter(|n|*n<=b.wire_total).ok_or_else(||error("HTTP/1 wire boundary overflow"))?;
  let payload_end=b.payload_start+b.payload_len;
  let overlap=end.min(payload_end).saturating_sub(b.accepted.max(b.payload_start));
  b.accepted=end;b.staged_payload+=overlap;b.staged_wire+=n;self.needs_flush=true;Ok(())
 }
 pub fn flushed(&mut self)->io::Result<()>{
  let now=self.timer.now();self.needs_flush=false;
  let Some(b)=self.boundary.as_mut()else{return Ok(())};
  let expired=self.owner.deadline().map_err(error)?.is_some_and(|at|now>=at);
  if expired{self.owner.expire();}
  if b.staged_wire!=0{
   if b.staged_payload!=0{self.owner.flushed(b.staged_payload,now).map_err(error)?;}else{self.owner.wire_flushed(now).map_err(error)?;}
   b.staged_payload=0;b.staged_wire=0;
  }
  if expired{return Err(io::Error::new(io::ErrorKind::TimedOut,"HTTP/1 actual flush exceeded response deadline"))}
  if b.accepted==b.wire_total{
   if self.owner.snapshot().pending_since.is_some(){self.owner.flushed(0,now).map_err(error)?;}
   self.boundary=None;
   if self.finish_after_flush{self.owner.finish().map_err(error)?;}
  }else if self.owner.snapshot().pending_since.is_none(){
   // Payload may end before chunk framing does. The real suffix remains an
   // actual zero-payload boundary until its own transport flush.
   self.owner.start_boundary(0,now).map_err(error)?;
  }
  Ok(())
 }
 pub fn poll_deadline(&mut self,cx:&mut Context<'_>)->Poll<io::Result<()>>{
  let at=self.owner.deadline().map_err(error)?;
  let Some(at)=at else{self.sleep=None;self.sleep_at=None;return Poll::Pending};
  if self.timer.now()>=at{self.owner.expire();return Poll::Ready(Err(io::Error::new(io::ErrorKind::TimedOut,"HTTP/1 response write deadline expired")))}
  if self.sleep_at!=Some(at){match &self.timer{
   Time::Empty=>{self.owner.abandon();return Poll::Ready(Err(error("HTTP/1 response policy requires a timer")))},
   Time::Timer(timer)=>{if let Some(sleep)=self.sleep.as_mut(){timer.reset(sleep,at)}else{self.sleep=Some(timer.sleep_until(at));}}
  }self.sleep_at=Some(at);}
  if self.sleep.as_mut().expect("armed native timer").as_mut().poll(cx).is_ready(){self.owner.expire();return Poll::Ready(Err(io::Error::new(io::ErrorKind::TimedOut,"HTTP/1 response write deadline expired")))}
  Poll::Pending
 }
}
