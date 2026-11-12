//! One formatting buffer implementation with typed allocation ownership.
use alloc::{vec::Vec,string::{String,ToString}};
use core::{fmt,ops::{Deref,DerefMut}};
#[cfg(feature="std")]use alloc::sync::Arc;
use crate::{Result,TemplateError};
const MAX:usize=1<<20;
pub(crate) trait Mode{
 fn room(&mut self,bytes:&mut Vec<u8>,required:usize)->Result<()>;
 fn release(&mut self);
 fn temporary(&self,capacity:usize)->Scratch;
 fn check(&self)->Result<()>{Ok(())}
 fn host(&self,_value:&crate::Value)->Result<Option<crate::ByteLease>>{Ok(None)}
}
pub(crate) struct Unmetered;
impl Mode for Unmetered{
 fn room(&mut self,bytes:&mut Vec<u8>,required:usize)->Result<()>{if required>bytes.capacity(){bytes.reserve(required-bytes.len());}Ok(())}
 fn release(&mut self){}
 fn temporary(&self,capacity:usize)->Scratch{Scratch::Plain(ByteBuffer::with_capacity(capacity))}
}
#[cfg(feature="std")]
pub(crate) struct Metered{account:crate::BudgetAccount,scope:Arc<crate::FormatterScope>,held:usize}
#[cfg(feature="std")]
impl Mode for Metered{
 fn room(&mut self,bytes:&mut Vec<u8>,required:usize)->Result<()>{
  self.scope.check()?;if required<=bytes.capacity(){return Ok(());}
  let capacity=crate::go_slice_capacity(bytes.capacity(),required,1,false).ok_or_else(||TemplateError::Exec("formatter capacity overflow".into()))?.min(MAX);
  let total=self.held.checked_add(capacity).ok_or_else(||TemplateError::Exec("formatter loan overflow".into()))?;
  self.scope.work(1+bytes.len().div_ceil(1024))?;
  self.scope.reserve(&self.account,capacity)?;self.held=total;
  let mut next=Vec::new();
  if next.try_reserve_exact(capacity).is_err(){drop(next);self.account.release(capacity)?;self.held-=capacity;return Err(TemplateError::Exec("formatter allocation failed".into()));}
  if next.capacity()!=capacity{drop(next);self.account.release(capacity)?;self.held-=capacity;return Err(TemplateError::Exec("formatter allocator capacity mismatch".into()));}
  next.extend_from_slice(bytes);drop(core::mem::replace(bytes,next));
  let retired=total-capacity;self.account.release(retired)?;self.held=capacity;Ok(())
 }
 fn release(&mut self){let held=core::mem::take(&mut self.held);let result=self.account.release(held);debug_assert!(result.is_ok());}
 fn temporary(&self,capacity:usize)->Scratch{Scratch::Bounded(ByteBuffer::bounded(self.account.clone(),self.scope.clone(),capacity))}
 fn check(&self)->Result<()>{self.scope.check()}
 fn host(&self,value:&crate::Value)->Result<Option<crate::ByteLease>>{self.scope.host(value)}
}
enum Failure{Size,Budget(String)}
pub(crate) struct ByteBuffer<M:Mode=Unmetered>{bytes:Vec<u8>,failure:Option<Failure>,mode:M}
impl ByteBuffer<Unmetered>{
 pub(crate) fn new()->Self{Self{bytes:Vec::new(),failure:None,mode:Unmetered}}
 pub(crate) fn with_capacity(capacity:usize)->Self{let mut out=Self::new();out.reserve(capacity.min(MAX));out}
 pub(crate) fn into_vec(mut self)->Vec<u8>{core::mem::take(&mut self.bytes)}
}
#[cfg(feature="std")]
impl ByteBuffer<Metered>{
 pub(crate) fn bounded(account:crate::BudgetAccount,scope:Arc<crate::FormatterScope>,capacity:usize)->Self{let mut out=Self{bytes:Vec::new(),failure:None,mode:Metered{account,scope,held:0}};out.reserve(capacity.min(MAX));out}
 pub(crate) fn into_budgeted_bytes(mut self)->Result<crate::BudgetedBytes>{self.check()?;let bytes=core::mem::take(&mut self.bytes);self.mode.held=0;crate::BudgetedBytes::from_account(bytes,&self.mode.account)}
}
impl<M:Mode> ByteBuffer<M>{
 pub(crate) fn len(&self)->usize{self.bytes.len()}
 pub(crate) fn as_bytes(&self)->&[u8]{&self.bytes}
 pub(crate) fn is_empty(&self)->bool{self.bytes.is_empty()}
 pub(crate) fn reject_size(&mut self){if self.failure.is_none(){self.failure=Some(Failure::Size);}}
 pub(crate) fn fail_scratch(&mut self,other:&dyn FormatBuffer){if let Err(error)=other.check(){self.fail(error);}}
 fn fail(&mut self,error:TemplateError){if self.failure.is_none(){self.failure=Some(Failure::Budget(error.to_string()));}}
 pub(crate) fn check(&self)->Result<()>{match &self.failure{Some(Failure::Size)=>Err(TemplateError::OutputTooLarge),Some(Failure::Budget(message))=>Err(TemplateError::Exec(message.clone())),None=>self.mode.check()}}
 fn room(&mut self,additional:usize)->bool{
  if self.failure.is_some(){return false;}
  let Some(required)=self.bytes.len().checked_add(additional).filter(|n|*n<=MAX)else{self.reject_size();return false;};
  match self.mode.room(&mut self.bytes,required){Ok(())=>true,Err(error)=>{self.fail(error);false}}
 }
 pub(crate) fn push(&mut self,ch:char){let mut data=[0;4];self.push_bytes(ch.encode_utf8(&mut data).as_bytes());}
 pub(crate) fn push_str(&mut self,text:&str){self.push_bytes(text.as_bytes());}
 pub(crate) fn push_bytes(&mut self,data:&[u8]){if self.room(data.len()){self.bytes.extend_from_slice(data);}}
 pub(crate) fn repeat_ascii(&mut self,pos:usize,byte:u8,count:usize){
  if pos>self.bytes.len(){self.reject_size();return;}if !self.room(count){return;}let old=self.bytes.len();self.bytes.resize(old+count,0);self.bytes.copy_within(pos..old,pos+count);self.bytes[pos..pos+count].fill(byte);
 }
 pub(crate) fn insert(&mut self,pos:usize,ch:char){let mut data=[0;4];self.insert_bytes(pos,ch.encode_utf8(&mut data).as_bytes());}
 pub(crate) fn insert_str(&mut self,pos:usize,text:&str){self.insert_bytes(pos,text.as_bytes());}
 fn insert_bytes(&mut self,pos:usize,data:&[u8]){if pos>self.bytes.len(){self.reject_size();return;}if !self.room(data.len()){return;}let old=self.bytes.len();self.bytes.resize(old+data.len(),0);self.bytes.copy_within(pos..old,pos+data.len());self.bytes[pos..pos+data.len()].copy_from_slice(data);}
 pub(crate) fn reserve(&mut self,additional:usize){let _=self.room(additional);}
 pub(crate) fn truncate(&mut self,length:usize){self.bytes.truncate(length);}
 pub(crate) fn temporary(&self,capacity:usize)->Scratch{self.mode.temporary(capacity)}
 pub(crate) fn host(&self,value:&crate::Value)->Result<Option<crate::ByteLease>>{self.mode.host(value)}
}
impl<M:Mode> Drop for ByteBuffer<M>{fn drop(&mut self){drop(core::mem::take(&mut self.bytes));self.mode.release();}}
impl<M:Mode> fmt::Write for ByteBuffer<M>{fn write_str(&mut self,text:&str)->fmt::Result{self.push_str(text);if self.failure.is_some(){Err(fmt::Error)}else{Ok(())}}}
impl<M:Mode> crate::go_write::GoWrite for ByteBuffer<M>{fn write_bytes(&mut self,data:&[u8])->fmt::Result{self.push_bytes(data);if self.failure.is_some(){Err(fmt::Error)}else{Ok(())}}fn host(&self,value:&crate::Value)->Result<Option<crate::ByteLease>>{self.mode.host(value)}}
pub(crate) trait FormatBuffer:fmt::Write+crate::go_write::GoWrite{
 fn len(&self)->usize;fn as_bytes(&self)->&[u8];fn check(&self)->Result<()>;fn reject_size(&mut self);
 fn push(&mut self,ch:char);fn push_str(&mut self,text:&str);fn push_bytes(&mut self,data:&[u8]);
 fn repeat_ascii(&mut self,pos:usize,byte:u8,count:usize);fn insert(&mut self,pos:usize,ch:char);fn insert_str(&mut self,pos:usize,text:&str);
 fn reserve(&mut self,n:usize);fn truncate(&mut self,length:usize);fn temporary(&self,capacity:usize)->Scratch;fn fail_scratch(&mut self,other:&dyn FormatBuffer);
}
impl<M:Mode> FormatBuffer for ByteBuffer<M>{
 fn len(&self)->usize{self.len()}fn as_bytes(&self)->&[u8]{self.as_bytes()}fn check(&self)->Result<()>{self.check()}fn reject_size(&mut self){self.reject_size()}
 fn push(&mut self,ch:char){self.push(ch)}fn push_str(&mut self,text:&str){self.push_str(text)}fn push_bytes(&mut self,data:&[u8]){self.push_bytes(data)}
 fn repeat_ascii(&mut self,pos:usize,byte:u8,count:usize){self.repeat_ascii(pos,byte,count)}fn insert(&mut self,pos:usize,ch:char){self.insert(pos,ch)}fn insert_str(&mut self,pos:usize,text:&str){self.insert_str(pos,text)}
 fn reserve(&mut self,n:usize){self.reserve(n)}fn truncate(&mut self,length:usize){self.truncate(length)}fn temporary(&self,capacity:usize)->Scratch{self.temporary(capacity)}fn fail_scratch(&mut self,other:&dyn FormatBuffer){self.fail_scratch(other)}
}
pub(crate) enum Scratch{Plain(ByteBuffer),#[cfg(feature="std")]Bounded(ByteBuffer<Metered>)}
impl Deref for Scratch{type Target=dyn FormatBuffer;fn deref(&self)->&Self::Target{match self{Self::Plain(out)=>out,#[cfg(feature="std")]Self::Bounded(out)=>out}}}
impl DerefMut for Scratch{fn deref_mut(&mut self)->&mut Self::Target{match self{Self::Plain(out)=>out,#[cfg(feature="std")]Self::Bounded(out)=>out}}}
impl fmt::Write for Scratch{fn write_str(&mut self,text:&str)->fmt::Result{(**self).write_str(text)}}
impl crate::go_write::GoWrite for Scratch{fn write_bytes(&mut self,data:&[u8])->fmt::Result{(**self).write_bytes(data)}}

// ---------------------------------------------------------------------------
// FmtCursor
// ---------------------------------------------------------------------------

/// Byte-position cursor over a format string.
///
/// Replaces `Peekable<bytes::Iter>` from the original Go formatter.
/// Top-level callers can capture the byte slice of a literal between
/// positions: `&bytes[before .. after]`.
#[derive(Clone)]
pub(crate) struct FmtCursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> FmtCursor<'a> {
    /// Create a cursor at position 0 over `bytes`.
    #[inline]
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    /// Current byte position.
    #[inline]
    pub(crate) fn position(&self) -> usize {
        self.position
    }

    /// Decode the next rune **without** advancing.
    ///
    /// Uses `crate::decode_go_rune` which returns `(char, width)`.
    /// An invalid byte yields the replacement character with width 1.
    #[inline]
    pub(crate) fn peek(&self) -> Option<char> {
        if self.position >= self.bytes.len() {
            return None;
        }
        let (ch, _width) = crate::decode_go_rune(&self.bytes[self.position..])?;
        Some(ch)
    }

    /// Decode the next rune, advancing the position by the rune's width.
    ///
    /// Invalid bytes consume exactly 1 byte (replacement char).
    #[inline]
    pub(crate) fn advance(&mut self) -> Option<char> {
        if self.position >= self.bytes.len() {
            return None;
        }
        let (ch, width) = crate::decode_go_rune(&self.bytes[self.position..])?;
        self.position += width;
        Some(ch)
    }

    /// Peek the next rune; advance **only** if `predicate` accepts it.
    ///
    /// Mirrors `Peekable::next_if` from the standard library so that
    /// call-sites migrated from the original Go formatter keep working.
    #[inline]
    pub(crate) fn next_if(
        &mut self,
        predicate: impl FnOnce(&char) -> bool,
    ) -> Option<char> {
        if self.peek().is_some_and(|c| predicate(&c)) {
            self.advance()
        } else {
            None
        }
    }
}

/// Allow `for ch in cursor` style iteration.
impl<'a> Iterator for FmtCursor<'a> {
    type Item = char;

    #[inline]
    fn next(&mut self) -> Option<char> {
        self.advance()
    }
}
