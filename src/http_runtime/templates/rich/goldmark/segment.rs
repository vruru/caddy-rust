//! Byte segments ported from Goldmark 1.8.6 text/segment.go (MIT).
use gotmpl::{BudgetAccount,BudgetedBytes,Result,TemplateError};
use std::ops::Deref;
fn error()->TemplateError{TemplateError::Exec("invalid Markdown byte segment or allocation".into())}
pub(super) fn is_space(byte:u8)->bool{matches!(byte,b' '|b'\t'|b'\n'|b'\r')}

pub(super) enum Bytes<'a>{Borrowed(&'a[u8]),Owned(BudgetedBytes)}
impl Deref for Bytes<'_>{type Target=[u8];fn deref(&self)->&[u8]{match self{Self::Borrowed(bytes)=>bytes,Self::Owned(bytes)=>bytes.as_bytes()}}}
impl<'a> Bytes<'a>{
    pub fn copy(&self,account:&BudgetAccount)->Result<Self>{
        match self{
            Self::Borrowed(bytes)=>Ok(Self::Borrowed(bytes)),
            Self::Owned(bytes)=>{
                let mut output=super::output::Output::new(account,1<<20);
                output.write(bytes.as_bytes())?;Ok(Self::Owned(output.into_bytes()?))
            }
        }
    }
}
#[derive(Clone,Copy,Debug,Default,PartialEq,Eq)]
pub(super) struct Segment{pub start:usize,pub stop:usize,pub padding:usize,pub force_newline:bool}
impl Segment{
    pub fn new(start:usize,stop:usize)->Self{Self{start,stop,..Self::default()}}
    pub fn new_padding(start:usize,stop:usize,padding:usize)->Self{Self{start,stop,padding,force_newline:false}}
    pub fn len(&self)->Result<usize>{self.stop.checked_sub(self.start).and_then(|n|n.checked_add(self.padding)).ok_or_else(error)}
    pub fn is_empty(&self)->bool{self.start>=self.stop&&self.padding==0}
    fn slice<'a>(&self,source:&'a[u8])->Result<&'a[u8]>{source.get(self.start..self.stop).ok_or_else(error)}
    pub fn value<'a>(&self,source:&'a[u8],account:&BudgetAccount)->Result<Bytes<'a>>{
        let raw=self.slice(source)?;
        let len=self.len()?;
        let newline=self.force_newline&&len!=0&&raw.last()!=Some(&b'\n');
        if self.padding==0&&!newline{return Ok(Bytes::Borrowed(raw));}
        let capacity=len.checked_add(usize::from(newline)).ok_or_else(error)?;
        account.reserve(capacity)?;
        let mut bytes=Vec::new();
        if bytes.try_reserve_exact(capacity).is_err(){account.release(capacity)?;return Err(error());}
        if bytes.capacity()!=capacity{return Err(error());}
        bytes.resize(self.padding,b' ');bytes.extend_from_slice(raw);if newline{bytes.push(b'\n');}
        Ok(Bytes::Owned(BudgetedBytes::from_account(bytes,account)?))
    }
    pub fn between(&self,other:Self)->Result<Self>{
        if self.stop!=other.stop{return Err(error());}
        Ok(Self::new_padding(self.start,other.start,self.padding.checked_sub(other.padding).ok_or_else(error)?))
    }
    pub fn trim_right_space(&self,source:&[u8])->Result<Self>{
        let raw=self.slice(source)?;let trailing=raw.iter().rev().take_while(|byte|is_space(**byte)).count();
        if trailing==raw.len(){return Ok(Self::new(self.start,self.start));}
        Ok(Self::new_padding(self.start,self.stop-trailing,self.padding))
    }
    pub fn trim_left_space(&self,source:&[u8])->Result<Self>{
        let raw=self.slice(source)?;let leading=raw.iter().take_while(|byte|is_space(**byte)).count();
        Ok(Self::new(self.start.checked_add(leading).ok_or_else(error)?,self.stop))
    }
    pub fn trim_left_space_width(&self,mut width:usize,source:&[u8])->Result<Self>{
        let mut padding=self.padding;let consumed=width.min(padding);padding-=consumed;width-=consumed;
        if width==0{return Ok(Self::new_padding(self.start,self.stop,padding));}
        let raw=self.slice(source)?;let mut start=self.start;
        for byte in raw{
            if self.stop.saturating_sub(start)<=1||width==0{break;}
            let cost=match byte{b' '=>1,b'\t'=>4,_=>break};
            start+=1;
            if width<cost{padding=cost-width;break;}
            width-=cost;
        }
        Ok(Self::new_padding(start,self.stop,padding))
    }
    pub fn with_start(&self,start:usize)->Self{Self::new_padding(start,self.stop,self.padding)}
    pub fn with_stop(&self,stop:usize)->Self{Self::new_padding(self.start,stop,self.padding)}
}

/// A Go slice view over prepaid segment backing storage. Slicing does not copy
/// or shrink storage. Appending may overwrite its old suffix, as in Go.
pub(super) struct Segments{values:Vec<Segment>,lo:usize,hi:usize,held:usize,account:BudgetAccount}
impl Segments{
    pub fn new(account:&BudgetAccount)->Self{Self{values:Vec::new(),lo:0,hi:0,held:0,account:account.clone()}}
    pub fn len(&self)->usize{self.hi-self.lo}
    pub fn at(&self,index:usize)->Result<Segment>{self.as_slice().get(index).copied().ok_or_else(error)}
    pub fn as_slice(&self)->&[Segment]{&self.values[self.lo..self.hi]}
    fn room(&mut self,len:usize)->Result<()>{
        let old_capacity=self.values.capacity()-self.lo;
        if len<=old_capacity{return Ok(());}
        let next=gotmpl::go_slice_capacity(old_capacity,len,std::mem::size_of::<Segment>(),false).ok_or_else(error)?;
        let bytes=next.checked_mul(std::mem::size_of::<Segment>()).ok_or_else(error)?;
        let held=self.held.checked_add(bytes).ok_or_else(error)?;
        self.account.reserve(bytes)?;self.held=held;
        let mut values=Vec::new();values.try_reserve_exact(next).map_err(|_|error())?;
        if values.capacity()!=next{return Err(error());}
        values.extend_from_slice(self.as_slice());
        let old=self.held-bytes;drop(std::mem::replace(&mut self.values,values));
        self.lo=0;self.hi=self.values.len();self.account.release(old)?;self.held=bytes;
        Ok(())
    }
    pub fn append(&mut self,value:Segment)->Result<()>{
        self.room(self.len().checked_add(1).ok_or_else(error)?)?;let end=self.hi+1;
        if self.hi<self.values.len(){self.values[self.hi]=value;}else{self.values.push(value);}
        self.hi=end;Ok(())
    }
    pub fn append_all(&mut self,values:&[Segment])->Result<()>{for value in values{self.append(*value)?;}Ok(())}
    pub fn set(&mut self,index:usize,value:Segment)->Result<()>{if index>=self.len(){return Err(error());}self.values[self.lo+index]=value;Ok(())}
    pub fn set_sliced(&mut self,lo:usize,hi:usize)->Result<()>{
        if lo>hi||hi>self.len(){return Err(error());}self.hi=self.lo+hi;self.lo+=lo;Ok(())
    }
    pub fn sliced(&self,lo:usize,hi:usize)->Result<&[Segment]>{self.as_slice().get(lo..hi).ok_or_else(error)}
    pub fn clear(&mut self)->Result<()>{
        drop(std::mem::take(&mut self.values));self.lo=0;self.hi=0;
        self.account.release(self.held)?;self.held=0;Ok(())
    }
    pub fn unshift(&mut self,value:Segment)->Result<()>{
        // Goldmark's s.values[0:1] requires at least one backing slot even if
        // the logical slice is empty. All real parser call sites are nonempty.
        if self.lo>=self.values.capacity(){return Err(error());}
        self.room(self.len().checked_add(1).ok_or_else(error)?)?;let end=self.hi+1;
        if end>self.values.len(){self.values.resize(end,Segment::default());}
        self.values.copy_within(self.lo..self.hi,self.lo+1);self.values[self.lo]=value;self.hi=end;Ok(())
    }
    pub fn value(&self,source:&[u8])->Result<BudgetedBytes>{
        let mut count=0usize;
        for segment in self.as_slice(){
            let raw=segment.slice(source)?;let len=segment.len()?;
            let newline=segment.force_newline&&len!=0&&raw.last()!=Some(&b'\n');
            count=count.checked_add(len).and_then(|n|n.checked_add(usize::from(newline))).ok_or_else(error)?;
        }
        self.account.reserve(count)?;let mut bytes=Vec::new();
        if bytes.try_reserve_exact(count).is_err(){self.account.release(count)?;return Err(error());}
        if bytes.capacity()!=count{return Err(error());}
        for segment in self.as_slice(){
            let raw=segment.slice(source)?;let len=segment.len()?;
            let newline=segment.force_newline&&len!=0&&raw.last()!=Some(&b'\n');
            bytes.resize(bytes.len()+segment.padding,b' ');bytes.extend_from_slice(raw);if newline{bytes.push(b'\n');}
        }
        BudgetedBytes::from_account(bytes,&self.account)
    }
}
impl Drop for Segments{fn drop(&mut self){drop(std::mem::take(&mut self.values));let result=self.account.release(self.held);debug_assert!(result.is_ok());}}
