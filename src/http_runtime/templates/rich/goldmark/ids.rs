//! Goldmark auto-ID generation with an append-only collision cache.
use super::{allocation,output::Output,segment::is_space,tables};
use gotmpl::{BudgetAccount,BudgetedBytes,Result,TemplateError};
use std::collections::{BTreeMap,BTreeSet};
fn error()->TemplateError{TemplateError::Exec("Markdown identifier allocation or counter overflow".into())}
pub(super) struct Ids{values:BTreeSet<Vec<u8>>,next_suffix:BTreeMap<Vec<u8>,usize>,account:BudgetAccount}
impl Ids{
    pub fn new(account:&BudgetAccount)->Self{Self{values:BTreeSet::new(),next_suffix:BTreeMap::new(),account:account.clone()}}
    fn copy(&self,bytes:&[u8])->Result<Vec<u8>>{
        self.account.reserve(bytes.len())?;let mut value=Vec::new();value.try_reserve_exact(bytes.len()).map_err(|_|error())?;
        if value.capacity()!=bytes.len(){return Err(error());}value.extend_from_slice(bytes);Ok(value)
    }
    pub fn put(&mut self,value:&[u8])->Result<()>{
        if self.values.contains(value){return Ok(());}
        allocation::btree_insert::<Vec<u8>,()>(self.values.is_empty(),&self.account)?;
        let value=self.copy(value)?;self.values.insert(value);Ok(())
    }
    pub fn generate(&mut self,value:&[u8],heading:bool)->Result<BudgetedBytes>{
        let start=value.iter().take_while(|byte|is_space(**byte)).count();
        let stop=value.len()-value[start..].iter().rev().take_while(|byte|is_space(**byte)).count();
        let value=&value[start..stop];let mut result=Output::new(&self.account,1<<20);let mut index=0usize;
        while index<value.len(){
            let byte=value[index];let width=usize::from(tables::UTF8_LEN[byte as usize]);
            index=index.checked_add(width).ok_or_else(error)?;
            if width!=1{continue;}
            if byte.is_ascii_alphanumeric(){result.byte(byte.to_ascii_lowercase())?;}
            else if is_space(byte)||matches!(byte,b'-'|b'_'){result.byte(b'-')?;}
        }
        if result.len()==0{result.write(if heading{b"heading"}else{b"id"})?;}
        if !self.values.contains(result.as_bytes()){self.put(result.as_bytes())?;return result.into_bytes();}
        let base=result.into_bytes()?;let mut suffix=self.next_suffix.get(base.as_bytes()).copied().unwrap_or(1);
        loop{
            self.account.charge_work(1)?;let mut result=Output::new(&self.account,1<<20);
            result.write(base.as_bytes())?;result.byte(b'-')?;decimal(suffix,&mut result)?;
            let next=suffix.checked_add(1).ok_or_else(error)?;
            if !self.values.contains(result.as_bytes()){
                self.put(result.as_bytes())?;
                if let Some(existing)=self.next_suffix.get_mut(base.as_bytes()){*existing=next;}
                else{
                    allocation::btree_insert::<Vec<u8>,usize>(self.next_suffix.is_empty(),&self.account)?;
                    let key=self.copy(base.as_bytes())?;self.next_suffix.insert(key,next);
                }
                return result.into_bytes();
            }
            suffix=next;
        }
    }
}
fn decimal(mut value:usize,output:&mut Output)->Result<()>{
    let mut bytes=[0u8;20];let mut at=bytes.len();
    loop{at=at.checked_sub(1).ok_or_else(error)?;bytes[at]=b'0'+(value%10)as u8;value/=10;if value==0{break;}}
    output.write(&bytes[at..])
}
