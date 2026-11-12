//! Mutable map[interface{}]interface{} identity within one render graph.
use crate::{BudgetAccount,Result,TemplateError,Value};
use crate::generic_key::{valid_key,key_equal,key_compare};
use super::{Graph,MapContext,GenericNode,EntriesSlot};
use std::{sync::Arc,cmp::Ordering,mem::size_of};
type Entries=Vec<(Value,Value)>;
fn error(message:&str)->TemplateError{TemplateError::Exec(message.into())}
pub struct GenericMapCell {
    // Storage is dropped before its conservative accounting owner.
    entries:EntriesSlot<Entries>,
    pub(super) graph:Arc<Graph>,
    retired:Option<Box<GenericNode>>,
    account:BudgetAccount,
}
impl Drop for GenericMapCell {
    fn drop(&mut self) {
        let entries=self.entries.take();
        self.retired.take().expect("live generic map has retirement node").retire(entries);
    }
}
pub struct GenericMapSnapshot { entries:Arc<Entries>, _account:BudgetAccount }
impl GenericMapSnapshot {
    pub fn len(&self)->usize{self.entries.len()}
    pub fn is_empty(&self)->bool{self.entries.is_empty()}
    pub fn iter(&self)->impl Iterator<Item=(&Value,&Value)>{self.entries.iter().map(|(k,v)|(k,v))}
}
impl MapContext {
    /// Input storage must already be prepaid by the producer. Normalization
    /// and the cell are charged here before their additional allocations.
    pub fn generic_map(&self,mut entries:Entries,account:&BudgetAccount)->Result<Value>{
        if entries.len()>16_384{return Err(error("generic map entry limit exceeded"));}
        account.charge_work(1+entries.len().saturating_mul(entries.len().max(1).ilog2()as usize+1))?;
        for(key,value)in &entries{valid_key(key)?;key.measured_bytes(1<<20)?;value.measured_bytes(1<<20)?;}
        account.reserve(entries.len().max(48).checked_mul(size_of::<(Value,Value)>()).and_then(|n|n.checked_add(size_of::<GenericMapCell>()+size_of::<Entries>()+4*size_of::<usize>()+size_of::<GenericNode>())).ok_or_else(||error("generic map allocation overflow"))?)?;
        let mut failure=None;
        // Stable sort preserves original order of equal keys, allowing Go's
        // last-assignment semantics while retaining every NaN key.
        entries.sort_by(|(a,_),(b,_)|match key_compare(a,b){Ok(order)=>order,Err(error)=>{failure=Some(error);Ordering::Equal}});
        if let Some(error)=failure{return Err(error);}
        entries.dedup_by(|later,earlier|if key_equal(&later.0,&earlier.0).unwrap_or(false){std::mem::swap(later,earlier);true}else{false});
        let cell=Arc::new(GenericMapCell{entries:EntriesSlot::new(entries),graph:self.graph.clone(),account:account.clone(),retired:Some(GenericNode::new(account))});
        let gate=self.graph.writes.lock().map_err(|_|error("map graph lock poisoned"))?;
        for(key,value)in cell.snapshot()?.iter(){cell.inspect(key,1)?;cell.inspect(value,1)?;}
        drop(gate);
        Ok(Value::GenericMap(cell))
    }
}
impl GenericMapCell {
    pub(crate) fn ensure_depth(&self,depth:usize)->Result<()> {
        let gate=self.graph.writes.lock().map_err(|_|error("map graph lock poisoned"))?;
        if depth>32{return Err(error("generic map graph nesting limit exceeded"));}
        let base=depth+1;
        for(key,value)in self.snapshot()?.iter(){self.inspect(key,base)?;self.inspect(value,base)?;}
        drop(gate);
        Ok(())
    }
    pub fn budget_account(&self)->BudgetAccount{self.account.clone()}
    pub fn snapshot(&self)->Result<GenericMapSnapshot>{
        self.account.check()?;
        Ok(GenericMapSnapshot{entries:self.entries.lock().map_err(|_|error("generic map lock poisoned"))?.clone(),_account:self.account.clone()})
    }
    pub fn get(&self,key:&Value)->Result<Option<Value>>{
        valid_key(key)?;let snapshot=self.snapshot()?;
        let mut low=0;let mut high=snapshot.len();
        while low<high{
            self.account.charge_work(1)?;let mid=low+(high-low)/2;
            match key_compare(&snapshot.entries[mid].0,key)?{
                Ordering::Less=>low=mid+1,Ordering::Greater=>high=mid,
                Ordering::Equal=>return if key_equal(&snapshot.entries[mid].0,key)?{Ok(Some(snapshot.entries[mid].1.clone()))}else{Ok(None)},
            }
        }
        Ok(None)
    }
    pub fn set(&self,key:Value,value:Value)->Result<()> {
        valid_key(&key)?;key.measured_bytes(1<<20)?;value.measured_bytes(1<<20)?;
        for _ in 0..8 {
        let current=self.snapshot()?;let(mut at,mut duplicate)=(0,None);
        for(i,(old,_))in current.entries.iter().enumerate(){
            self.account.charge_work(1)?;
            let order=key_compare(old,&key)?;
            if order.is_eq()&&key_equal(old,&key)?{duplicate=Some(i);at=i;break;}
            if order.is_gt(){at=i;break;}at=i+1;
        }
        let count=current.len()+usize::from(duplicate.is_none());if count>16_384{return Err(error("generic map entry limit exceeded"));}
        // Key callbacks ran before taking the graph gate. Validate the graph
        // under that gate, then publish only if this cell is still the exact
        // snapshot whose insertion position we calculated.
        let mut writes=self.graph.writes.lock().map_err(|_|error("map graph lock poisoned"))?;
        {let entries=self.entries.lock().map_err(|_|error("generic map lock poisoned"))?;if !Arc::ptr_eq(&entries,&current.entries){continue;}}
        *writes=writes.checked_sub(1).ok_or_else(||error("map mutation budget exhausted"))?;
        let base=1;
        self.inspect(&key,base)?;self.inspect(&value,base)?;
        let bytes=count.checked_mul(size_of::<(Value,Value)>()).and_then(|n|n.checked_add(size_of::<Vec<(Value,Value)>>()+2*size_of::<usize>())).ok_or_else(||error("generic map allocation overflow"))?;
        self.account.reserve(bytes)?;
        let mut next=Vec::new();next.try_reserve_exact(count).map_err(|_|error("generic map allocation failed"))?;
        for(i,(k,v))in current.entries.iter().enumerate(){
            if i==at{next.push((key.clone(),value.clone()));}
            if duplicate!=Some(i){next.push((k.clone(),v.clone()));}
        }
        if at==current.len(){next.push((key,value));}
        let mut entries=self.entries.lock().map_err(|_|error("generic map lock poisoned"))?;
        let retired=std::mem::replace(&mut *entries,Arc::new(next));
        drop(entries);drop(writes);drop(retired);drop(current);
        return Ok(());
        }
        Err(error("generic map changed concurrently; retry required"))
    }
    fn inspect(&self,value:&Value,depth:usize)->Result<()> {
        if depth>32{return Err(error("generic map graph nesting limit exceeded"));}
        self.account.charge_work(1)?;
        match value{
            Value::Field(_)=>return Err(error("map storage rejects retained field references")),
            Value::GenericMap(map)=>{
                if std::ptr::eq(self,map.as_ref()){return Err(error("cyclic template map is not supported"));}
                if !Arc::ptr_eq(&self.graph,&map.graph){return Err(error("mutable template maps belong to different renders"));}
                for(key,value)in map.snapshot()?.iter(){self.inspect(key,depth+1)?;self.inspect(value,depth+1)?;}
            }
            Value::SharedMap(map)=>{
                if !Arc::ptr_eq(&self.graph,&map.graph){return Err(error("mutable template maps belong to different renders"));}
                for value in map.snapshot_go()?.values(){self.inspect(value,depth+1)?;}
            }
            Value::List(items)=>for item in items.iter(){self.inspect(item,depth+1)?;},
            Value::Slice(slice)=>if let Some(items)=slice.retained_values(){for item in items.iter(){self.inspect(item,depth+1)?;}},
            Value::Map(items)=>for item in items.values(){self.inspect(item,depth+1)?;},
            Value::Object(object)=>for item in object.fields.values(){self.inspect(item,depth+1)?;},
            _=>{}
        }Ok(())
    }
}
