//! Exact SPKI identities reserved before work can publish or observe a key.
//! Buckets use explicit Vec capacity so both retained and growth-peak storage
//! have a finite charge. A live observation never creates a key allocation.
use std::{mem, sync::{Arc, Weak, atomic::{AtomicBool, Ordering}}};

#[derive(Debug, PartialEq, Eq)]
pub enum KeyRegistryError { Budget, Collision, Unregistered, Allocation }
impl std::fmt::Display for KeyRegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Budget => "certificate SPKI reservation byte budget exhausted",
            Self::Collision => "certificate SPKI digest collision",
            Self::Unregistered => "certificate SPKI has no live reservation",
            Self::Allocation => "certificate SPKI reservation allocation failed",
        })
    }
}
impl std::error::Error for KeyRegistryError {}

pub struct KeyState {
    spki: Arc<[u8]>,
    owner: Arc<()>,
    banned: AtomicBool,
}
impl KeyState {
    pub fn spki_der(&self) -> &[u8] { &self.spki }
    pub fn banned(&self) -> bool { self.banned.load(Ordering::Acquire) }
    pub(super) fn belongs(&self, owner: &Arc<()>) -> bool { Arc::ptr_eq(&self.owner, owner) }
}
impl std::fmt::Debug for KeyState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyState").field("banned", &self.banned()).finish_non_exhaustive()
    }
}

enum Slot {
    Empty,
    Tombstone,
    Full { id: [u8;32], weak: Weak<KeyState>, pinned: Option<Arc<KeyState>>, charge: usize },
}
pub(super) struct Registry {
    slots: Vec<Slot>,
    keys_bytes: usize,
    retired_buckets_bytes: usize,
    used: usize,
    limit: usize,
    owner: Arc<()>,
}
impl Registry {
    pub(super) fn new(limit: usize, owner: Arc<()>) -> Self {
        Self { slots: Vec::new(), keys_bytes: 0, retired_buckets_bytes: 0, used: 0, limit, owner }
    }
    fn fixed_bytes() -> usize { mem::size_of::<Self>() + 2*mem::size_of::<usize>() }
    fn buckets_bytes(&self) -> usize { self.slots.capacity()*mem::size_of::<Slot>() }
    fn key_charge(der_len: usize) -> Result<usize,KeyRegistryError> {
        let align = mem::align_of::<usize>();
        let der = der_len.checked_add(2*mem::size_of::<usize>())
            .and_then(|v|v.checked_add(align-1)).map(|v|v & !(align-1))
            .ok_or(KeyRegistryError::Budget)?;
        mem::size_of::<KeyState>().checked_add(2*mem::size_of::<usize>())
            .and_then(|v|v.checked_add(der)).ok_or(KeyRegistryError::Budget)
    }
    fn start(id: &[u8;32], mask: usize) -> usize {
        // Input is already SHA256, so the first machine word is uniformly
        // distributed; bounded linear probing still compares the complete ID.
        let mut word = 0usize;
        for byte in id.iter().take(mem::size_of::<usize>()) { word = word.wrapping_mul(256).wrapping_add(*byte as usize); }
        word & mask
    }
    fn index(&self, id: &[u8;32]) -> Option<usize> {
        if self.slots.is_empty() { return None; }
        let mask = self.slots.len()-1; let start = Self::start(id,mask);
        for step in 0..self.slots.len() {
            let index = (start+step)&mask;
            match &self.slots[index] {
                Slot::Empty => return None,
                Slot::Full { id: found, .. } if found == id => return Some(index),
                _ => {},
            }
        }
        None
    }
    pub(super) fn get(&self, id: &[u8;32], der: &[u8]) -> Result<Option<Arc<KeyState>>,KeyRegistryError> {
        let Some(index) = self.index(id) else { return Ok(None); };
        let Slot::Full { weak, .. } = &self.slots[index] else { return Ok(None); };
        let Some(state) = weak.upgrade() else { return Ok(None); };
        if state.spki_der() != der { return Err(KeyRegistryError::Collision); }
        Ok(Some(state))
    }
    pub(super) fn take_dead(&mut self, cursor: &mut usize) -> Option<Retired> {
        while *cursor < self.slots.len() {
            let index=*cursor;*cursor+=1;
            let expired=matches!(&self.slots[index],Slot::Full {weak,pinned:None,..} if weak.strong_count()==0);
            if expired {
                if let Slot::Full {weak,charge,..}=mem::replace(&mut self.slots[index],Slot::Tombstone) {
                    self.used-=1;
                    // Keep the full charge until the final Weak/control block
                    // has actually been dropped outside the registry lock.
                    return Some(Retired {weak:Some(weak),buckets:None,keys_charge:charge,bucket_charge:0});
                }
            }
        }
        None
    }
    pub(super) fn release_credit(&mut self, keys: usize, buckets: usize) {
        self.keys_bytes-=keys;self.retired_buckets_bytes-=buckets;
    }
    pub(super) fn needs_reap(&self,id:&[u8;32],der_len:usize)->Result<bool,KeyRegistryError> {
        let charge=Self::key_charge(der_len)?;
        Ok(self.index(id).is_some() || self.growth()?.is_some() || !self.can_charge(charge,0))
    }
    fn can_charge(&self, new_key: usize, new_buckets: usize) -> bool {
        Self::fixed_bytes().checked_add(self.keys_bytes)
            .and_then(|v|v.checked_add(self.retired_buckets_bytes))
            .and_then(|v|v.checked_add(self.buckets_bytes()))
            .and_then(|v|v.checked_add(new_buckets))
            .and_then(|v|v.checked_add(new_key)).is_some_and(|v|v<=self.limit)
    }
    fn growth(&self) -> Result<Option<usize>,KeyRegistryError> {
        if self.slots.is_empty() { return Ok(Some(8)); }
        if self.used < self.slots.len()-self.slots.len()/4 { return Ok(None); }
        self.slots.len().checked_mul(2).map(Some).ok_or(KeyRegistryError::Budget)
    }
    fn vacancy(slots: &[Slot], id: &[u8;32]) -> Option<usize> {
        if slots.is_empty() { return None; }
        let mask=slots.len()-1;let start=Self::start(id,mask);let mut tombstone=None;
        for step in 0..slots.len() {
            let index=(start+step)&mask;
            match &slots[index] {
                Slot::Tombstone if tombstone.is_none()=>tombstone=Some(index),
                Slot::Empty=>return Some(tombstone.unwrap_or(index)),
                _=>{},
            }
        }
        tombstone
    }
    pub(super) fn register(&mut self, id: [u8;32], der: &Arc<[u8]>) -> Result<(Arc<KeyState>,Option<Retired>),KeyRegistryError> {
        if let Some(state)=self.get(&id,&der)? { return Ok((state,None)); }
        let charge=Self::key_charge(der.len())?;
        let growth=self.growth()?;let mut retired=None;
        if let Some(size)=growth {
            let requested=size.checked_mul(mem::size_of::<Slot>()).ok_or(KeyRegistryError::Budget)?;
            if !self.can_charge(charge,requested) { return Err(KeyRegistryError::Budget); }
            let mut next=Vec::new();next.try_reserve_exact(size).map_err(|_|KeyRegistryError::Allocation)?;
            let actual=next.capacity().checked_mul(mem::size_of::<Slot>()).ok_or(KeyRegistryError::Budget)?;
            if !self.can_charge(charge,actual) { return Err(KeyRegistryError::Budget); }
            next.resize_with(size,||Slot::Empty);
            // At most 75% of the smaller table was occupied, so every move
            // has an empty destination in this strictly larger table.
            for slot in &mut self.slots {
                if let Slot::Full {id,..}=slot {
                    let index=Self::vacancy(&next,id).ok_or(KeyRegistryError::Allocation)?;
                    next[index]=mem::replace(slot,Slot::Empty);
                }
            }
            let old=mem::replace(&mut self.slots,next);
            let bucket_charge=old.capacity()*mem::size_of::<Slot>();
            self.retired_buckets_bytes+=bucket_charge;
            retired=Some(Retired {weak:None,buckets:Some(old),keys_charge:0,bucket_charge});
        } else if !self.can_charge(charge,0) { return Err(KeyRegistryError::Budget); }
        let index=Self::vacancy(&self.slots,&id).ok_or(KeyRegistryError::Allocation)?;
        let state=Arc::new(KeyState {spki:der.clone(),owner:self.owner.clone(),banned:AtomicBool::new(false)});
        self.slots[index]=Slot::Full {id,weak:Arc::downgrade(&state),pinned:None,charge};
        self.keys_bytes+=charge;self.used+=1;Ok((state,retired))
    }
    pub(super) fn ban_existing(&mut self, id: &[u8;32], der: &[u8]) -> Result<Arc<KeyState>,KeyRegistryError> {
        let state=self.get(id,der)?.ok_or(KeyRegistryError::Unregistered)?;
        let index=self.index(id).ok_or(KeyRegistryError::Unregistered)?;
        state.banned.store(true,Ordering::Release);
        if let Slot::Full {pinned,..}=&mut self.slots[index] { *pinned=Some(state.clone()); }
        Ok(state)
    }
}

/// Destruction and credit release are a separate phase outside the state lock.
pub(super) struct Retired {
    weak: Option<Weak<KeyState>>, buckets: Option<Vec<Slot>>,
    keys_charge: usize,bucket_charge:usize,
}
impl Retired {
    pub(super) fn release(self)->(usize,usize) {
        let Self {weak,buckets,keys_charge,bucket_charge}=self;
        drop(weak);drop(buckets);(keys_charge,bucket_charge)
    }
}
