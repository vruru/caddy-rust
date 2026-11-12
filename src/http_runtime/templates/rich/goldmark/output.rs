//! Owned byte output with full growth-peak prepayment on the parser's account.
use gotmpl::{BudgetAccount,BudgetedBytes,Result,TemplateError};
fn error()->TemplateError{TemplateError::Exec("Markdown byte output limit or allocation exceeded".into())}
pub(super) struct Output{bytes:Vec<u8>,held:usize,limit:usize,account:BudgetAccount}
impl Output{
    pub fn new(account:&BudgetAccount,limit:usize)->Self{Self{bytes:Vec::new(),held:0,limit,account:account.clone()}}
    pub fn len(&self)->usize{self.bytes.len()}
    pub fn as_bytes(&self)->&[u8]{&self.bytes}
    fn room(&mut self,additional:usize)->Result<()>{
        let len=self.bytes.len().checked_add(additional).filter(|len|*len<=self.limit).ok_or_else(error)?;
        if len<=self.bytes.capacity(){return Ok(());}
        let capacity=gotmpl::go_slice_capacity(self.bytes.capacity(),len,1,false).ok_or_else(error)?;
        let held=self.held.checked_add(capacity).ok_or_else(error)?;
        self.account.reserve(capacity)?;self.held=held;
        let mut bytes=Vec::new();bytes.try_reserve_exact(capacity).map_err(|_|error())?;
        if bytes.capacity()!=capacity{return Err(error());}
        bytes.extend_from_slice(&self.bytes);drop(std::mem::replace(&mut self.bytes,bytes));
        let retired=self.held-capacity;self.account.release(retired)?;self.held=capacity;Ok(())
    }
    pub fn write(&mut self,bytes:&[u8])->Result<()>{self.account.charge_work(1+bytes.len().div_ceil(64))?;self.room(bytes.len())?;self.bytes.extend_from_slice(bytes);Ok(())}
    pub fn byte(&mut self,byte:u8)->Result<()>{self.account.charge_work(1)?;self.room(1)?;self.bytes.push(byte);Ok(())}
    pub fn repeat(&mut self,byte:u8,count:usize)->Result<()>{self.account.charge_work(1+count.div_ceil(64))?;self.room(count)?;self.bytes.resize(self.bytes.len()+count,byte);Ok(())}
    pub fn into_bytes(mut self)->Result<BudgetedBytes>{
        let bytes=std::mem::take(&mut self.bytes);self.held=0;
        BudgetedBytes::from_account(bytes,&self.account)
    }
}
impl Drop for Output{fn drop(&mut self){drop(std::mem::take(&mut self.bytes));let result=self.account.release(self.held);debug_assert!(result.is_ok());}}
