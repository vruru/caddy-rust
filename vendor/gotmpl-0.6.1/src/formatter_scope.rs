//! Refundable formatter-result loans scoped to one admitted online Tree.
//! No strong owner callback, no global orphan registry, no Value ABI change.
use alloc::sync::{Arc,Weak};
use alloc::vec::Vec;
use std::sync::Mutex;
use crate::{BudgetMeter,BudgetAccount,BudgetedBytes,ByteLease,Result,TemplateError,Value};
pub struct OwnedFormatterScope{scope:Arc<FormatterScope>,_metadata:ByteLease}
impl OwnedFormatterScope{pub fn scope(&self)->Arc<FormatterScope>{self.scope.clone()}}
pub type FormatHostGuard=Arc<dyn Fn(&Value)->Result<usize>+Send+Sync>;
fn err(s: &str) -> TemplateError { TemplateError::Exec(s.into()) }
fn arc_layout(bytes:usize)->Result<usize>{let payload=core::alloc::Layout::array::<u8>(bytes).map_err(|_|err("arc layout overflow"))?;let(layout,_)=core::alloc::Layout::new::<[usize;2]>().extend(payload).map_err(|_|err("arc layout overflow"))?;Ok(layout.pad_to_align().size())}
enum WeakValue { Text(Weak<str>), Bytes(Weak<[u8]>) }
impl WeakValue {
    fn live(&self) -> bool { match self { Self::Text(x) => x.strong_count() != 0, Self::Bytes(x) => x.strong_count() != 0 } }
}
// Declaration order is intentional: the final Weak deallocates its backing
// before the loan refunds, including while the last strong owner is gone.
struct Record { weak: WeakValue, _loan: ByteLease }
enum Slot { Empty(Option<usize>), Reserved(u64), Live(Record), Metadata(ByteLease) }
struct State { slots: Vec<Slot>, metadata: Option<ByteLease>, sequence: u64, free:Option<usize> }
pub struct FormatterScope { state: Mutex<State>, meter: Arc<BudgetMeter>, host_guard:Option<FormatHostGuard> }
struct Reservation<'a> { registry: &'a FormatterScope, index: usize, sequence: u64, done: bool }
struct Pending { value: Option<Value>, loan: Option<ByteLease> }


impl FormatterScope {
    /// One scope must remain owned by the actual admitted worker/Tree graph.
    /// The host guard must use weak owner captures and admit only audited
    /// factory values. None rejects every callback-based host formatting path.
    pub fn new(meter:Arc<BudgetMeter>,host_guard:Option<FormatHostGuard>)->Result<OwnedFormatterScope>{
        meter.check()?;
        // The admitted Tree owns this outer token. Its field order frees the
        // Scope Arc/allocation before this fixed metadata/scratch loan refunds.
        let fixed=ByteLease::new(meter.clone(),std::mem::size_of::<Self>()+32+8192)?;
        let scope=Arc::new(Self{state:Mutex::new(State{slots:Vec::new(),metadata:None,sequence:0,free:None}),meter,host_guard});
        Ok(OwnedFormatterScope{scope,_metadata:fixed})
    }
    pub fn check(&self)->Result<()>{self.meter.check()}
    pub(crate) fn metadata(&self,bytes:usize)->Result<()>{let slot=self.reserve_slot()?;let loan=self.loan(bytes)?;slot.publish_metadata(loan)}
    pub(crate) fn work(&self,n:usize)->Result<()>{self.meter.charge_work(n)}
    pub fn host(&self,value:&Value)->Result<Option<ByteLease>>{
        self.check()?;let bytes=self.host_guard.as_ref().ok_or_else(||err("bounded formatter rejects opaque host callbacks"))?(value)?;
        if bytes==0{Ok(None)}else{self.loan(bytes).map(Some)}
    }
    pub(crate) fn account(&self)->Result<BudgetAccount>{
        match BudgetAccount::new(self.meter.clone()){Ok(account)=>Ok(account),Err(first)=>{self.sweep()?;BudgetAccount::new(self.meter.clone()).map_err(|_|first)}}
    }
    pub(crate) fn reserve(&self,account:&BudgetAccount,bytes:usize)->Result<()>{
        match account.reserve(bytes){Ok(())=>Ok(()),Err(first)=>{self.sweep()?;account.reserve(bytes).map_err(|_|first)}}
    }
    pub(crate) fn value(&self,output:BudgetedBytes,limit:usize)->Result<Value>{
        if output.as_bytes().len()>limit{return Err(err("formatted value exceeds execution limit"));}
        let input=output.as_bytes();let slot=self.reserve_slot()?;let loan=self.loan(arc_layout(input.len())?)?;
        let (value,weak)=match core::str::from_utf8(input){
            Ok(text)=>{let data:Arc<str>=Arc::from(text);let weak=WeakValue::Text(Arc::downgrade(&data));(Value::String(data),weak)},
            Err(_)=>{let data:Arc<[u8]>=Arc::from(input);let weak=WeakValue::Bytes(Arc::downgrade(&data));(Value::ByteString(crate::GoBytes::from_invalid(data)),weak)}
        };
        let mut pending=Pending{value:Some(value),loan:Some(loan)};slot.publish_weak(&mut pending,weak)?;
        drop(output);pending.value.take().ok_or_else(||err("formatter publication missing value"))
    }
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, State>> { self.state.lock().map_err(|_| err("registry poisoned")) }
    fn reserve_slot(&self) -> Result<Reservation<'_>> {
        for _ in 0..8 {
            self.meter.check()?;self.meter.charge_work(1)?;
            {
                let mut s = self.lock()?;
                if let Some(index) = s.free {
                    let sequence = s.sequence.checked_add(1).ok_or_else(|| err("registry generation overflow"))?;
                    let next=match s.slots.get(index){Some(Slot::Empty(next))=>*next,_=>return Err(err("registry corrupt free list"))};
                    s.sequence = sequence;s.free=next; s.slots[index] = Slot::Reserved(sequence);
                    return Ok(Reservation { registry: self, index, sequence, done: false });
                }
            }
            if self.sweep()? != 0 { continue; }
            let old = self.lock()?.slots.len();
            let capacity = old.checked_mul(2).filter(|n|*n>=old).ok_or_else(||err("formatter registry size overflow"))?.max(16);
            if capacity <= old { return Err(err("registry slot limit")); }
            let bytes = capacity.checked_mul(std::mem::size_of::<Slot>()).ok_or_else(|| err("registry size overflow"))?;
            self.meter.charge_work(capacity)?;
            let metadata = ByteLease::new(self.meter.clone(), bytes)?;
            let mut prepared = Vec::new();
            prepared.try_reserve_exact(capacity).map_err(|_| err("registry allocation failed"))?;
            if prepared.capacity() != capacity { return Err(err("registry allocation capacity mismatch")); }
            prepared.resize_with(capacity, || Slot::Empty(None));
            for i in old..capacity{prepared[i]=Slot::Empty((i+1<capacity).then_some(i+1));}
            let mut s = self.lock()?;
            if s.slots.len() != old || s.free.is_some() { drop(s); drop(prepared); drop(metadata); continue; }
            for (dst, src) in prepared.iter_mut().zip(s.slots.iter_mut()) { *dst = std::mem::replace(src, Slot::Empty(None)); }
            let retired = std::mem::replace(&mut s.slots, prepared);
            let retired_metadata = s.metadata.replace(metadata);s.free=Some(old);
            drop(s); drop(retired); drop(retired_metadata);
        }
        Err(err("registry concurrent growth retry limit"))
    }
    fn sweep(&self) -> Result<usize> {
        // One moved Record is fixed stack scratch, not an allocated Vec.
        // Retirement therefore remains possible with no spare heap credits.
        // Worker-stack admission is separate from this heap-only prototype.
        let (mut position, mut count) = (0usize, 0usize);
        loop {
            self.meter.check()?;self.meter.charge_work(1)?;
            let mut s = self.lock()?;
            let Some(slot) = s.slots.get_mut(position) else { break; };
            let retired = if matches!(slot, Slot::Live(record) if !record.weak.live()) {
                match std::mem::replace(slot, Slot::Reserved(0)) { Slot::Live(record) => Some(record), _ => None }
            } else { None };
            if retired.is_some(){let next=s.free;s.slots[position]=Slot::Empty(next);s.free=Some(position);}
            drop(s);
            if retired.is_some() { count += 1; }
            drop(retired); // Weak backing first, then loan, outside all locks.
            position += 1;
        }
        Ok(count)
    }
    fn loan(&self, bytes: usize) -> Result<ByteLease> {
        self.meter.check()?;
        match ByteLease::new(self.meter.clone(), bytes) {
            Ok(x) => Ok(x),
            Err(first) => { self.sweep()?; ByteLease::new(self.meter.clone(), bytes).map_err(|_| first) }
        }
    }
    pub fn close(&self) -> Result<()> {
        self.sweep()?;
        let count=self.lock()?.slots.len();self.meter.charge_work(count)?;
        if self.lock()?.slots.iter().any(|s| !matches!(s, Slot::Empty(_)|Slot::Metadata(_))) { return Err(err("scope still has live values or reservations")); }
        Ok(())
    }
}
impl Reservation<'_> {
    fn publish_metadata(mut self,loan:ByteLease)->Result<()>{
        let mut state=self.registry.lock()?;
        if !matches!(state.slots.get(self.index),Some(Slot::Reserved(n))if *n==self.sequence){return Err(err("stale formatter metadata reservation"));}
        state.slots[self.index]=Slot::Metadata(loan);self.done=true;drop(state);Ok(())
    }
    fn publish_weak(mut self, pending: &mut Pending, weak: WeakValue) -> Result<()> {
        let mut s = self.registry.lock()?;
        if !matches!(s.slots.get(self.index), Some(Slot::Reserved(n)) if *n == self.sequence) { return Err(err("registry stale reservation")); }
        let loan = pending.loan.take().ok_or_else(|| err("missing pending loan"))?;
        s.slots[self.index] = Slot::Live(Record { weak, _loan:loan }); self.done = true; drop(s); Ok(())
    }
}
impl Drop for Reservation<'_> {
    fn drop(&mut self) {
        if self.done { return; }
        let mut s = self.registry.state.lock().unwrap_or_else(|p| p.into_inner());
        if matches!(s.slots.get(self.index), Some(Slot::Reserved(n)) if *n == self.sequence) { let next=s.free;s.slots[self.index] = Slot::Empty(next);s.free=Some(self.index); }
    }
}
