//! Scalar state only: safe to update at the successful UDP-send boundary.
//! There are no application callbacks, allocation credits, or wake objects.
use std::{num::NonZeroU64, time::{Duration, Instant}};

#[derive(Clone, Copy, Debug)]
pub struct Policy {
    pub installed: Instant,
    pub idle: Option<Duration>,
    pub minimum_rate: Option<NonZeroU64>,
    pub hard: Option<Instant>,
    pub pending_since: Instant,
    pub last_flush: Option<Instant>,
    pub flushed_before: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error { OffsetOrder, Overflow, AlreadySealed }
#[derive(Clone, Debug)]
pub struct Operation {
    policy: Policy,
    scoped: Option<native_write_policy::Boundary>,
    observed_before: u64,
    seen_end: u64,
    seen_fin: bool,
    payload: Option<(u64,u64)>,
    target: Option<(u64,bool)>,
    flushed: u64,
    last_wire: Option<Instant>,
    completed: bool,
    expired: bool,
}
#[derive(Clone, Copy, Debug)]
pub struct Snapshot {
    pub flushed_payload: u64,
    pub last_wire: Option<Instant>,
    pub completed: bool,
    pub expired: bool,
}
impl Operation {
    /// Arm before a frame whose final encoded length is not yet available.
    pub fn wire(observed_before:u64, policy:Policy)->Self {
        Self {policy,scoped:None,observed_before,seen_end:observed_before,seen_fin:false,
            payload:None,target:None,flushed:0,last_wire:None,
            completed:false,expired:false}
    }
    /// Arm before handing a known DATA frame to the transport. `start` excludes
    /// frame-type and length varints, so only actual payload earns rate credit.
    pub fn data(start:u64, length:usize, observed_before:u64, policy:Policy)->Result<Self,Error> {
        if start<observed_before {return Err(Error::OffsetOrder)}
        let length=u64::try_from(length).map_err(|_|Error::Overflow)?;
        let end=start.checked_add(length).ok_or(Error::Overflow)?;
        let mut op=Self::wire(observed_before,policy);
        op.payload=Some((start,end));op.target=Some((end,false));
        Ok(op)
    }
    /// Exact precompiled server/route clauses. The owned boundary contains only
    /// an allocation-prepaid policy Arc and scalar clocks, never user callbacks.
    pub fn wire_scoped(observed_before:u64,policy:Policy,boundary:native_write_policy::Boundary)->Self {
        let mut op=Self::wire(observed_before,policy);op.scoped=Some(boundary);op
    }
    pub fn data_scoped(start:u64,length:usize,observed_before:u64,policy:Policy,boundary:native_write_policy::Boundary)->Result<Self,Error> {
        let mut op=Self::data(start,length,observed_before,policy)?;op.scoped=Some(boundary);Ok(op)
    }
    /// Sealing uses accepted writer offsets only to locate a boundary. It does
    /// not report progress or earn time/bytes. Already observed actual success
    /// can complete this operation even if the producer was paused before seal.
    pub fn seal_wire(&mut self,end:u64,require_fin:bool)->Result<(),Error> {
        if self.target.is_some() {return Err(Error::AlreadySealed)}
        if end<self.observed_before {return Err(Error::OffsetOrder)}
        self.target=Some((end,require_fin));self.update_completion();Ok(())
    }
    pub fn report(&mut self,end:u64,fin:bool,at:Instant) {
        if self.completed || (end<=self.seen_end && (!fin||self.seen_fin)) {return}
        // Test with the credit earned BEFORE the current physical flush.
        self.expired |= match self.deadline() { Ok(deadline)=>deadline.is_some_and(|d|at>=d), Err(_)=>true };
        self.seen_end=self.seen_end.max(end);self.seen_fin |= fin;
        if let Some((start,finish))=self.payload {
            self.flushed=self.flushed.max(end.saturating_sub(start).min(finish-start));
        }
        self.last_wire=Some(self.last_wire.map_or(at,|last|last.max(at)));
        self.update_completion();
    }
    fn update_completion(&mut self) {
        if let Some((end,fin))=self.target {
            self.completed=self.seen_end>=end && (!fin||self.seen_fin);
        }
    }
    pub fn deadline(&self)->Result<Option<Instant>,Error> {
        if self.completed {return Ok(None)}
        if let Some(boundary)=&self.scoped {
            let payload=usize::try_from(self.flushed).map_err(|_|Error::Overflow)?;
            return boundary.deadline(payload,self.last_wire).map_err(|_|Error::Overflow)
        }
        let p=self.policy;
        let Some(idle)=p.idle.filter(|d|!d.is_zero())else{return Ok(p.hard)};
        let deadline=if let Some(rate)=p.minimum_rate {
            let bytes=p.flushed_before.checked_add(self.flushed).ok_or(Error::Overflow)?;
            let ns=u128::from(bytes)*1_000_000_000/u128::from(rate.get());
            let secs=u64::try_from(ns/1_000_000_000).map_err(|_|Error::Overflow)?;
            p.installed.checked_add(idle)
                .and_then(|t|t.checked_add(Duration::new(secs,(ns%1_000_000_000)as u32)))
        } else {
            self.last_wire.or(p.last_flush).map_or(p.pending_since,|last|last.max(p.pending_since))
                .checked_add(idle)
        }.ok_or(Error::Overflow)?;
        Ok(Some(p.hard.map_or(deadline,|hard|hard.min(deadline))))
    }
    pub fn snapshot(&self)->Snapshot {
        Snapshot {flushed_payload:self.flushed,last_wire:self.last_wire,
            completed:self.completed,expired:self.expired}
    }
}
