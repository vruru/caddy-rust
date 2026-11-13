//! Issuance-operation retry state. Never inferred from journals, ARI failures,
//! backend rank or the lifetime of a perpetual maintenance task.
use super::*;
#[derive(Clone,Copy,Default)]
pub(crate) struct AcmeRound<'a> {pub ordinal:u32,pub(super) operation_id:Option<[u8;32]>,entered:Option<&'a std::sync::atomic::AtomicBool>}
impl<'a> AcmeRound<'a> {
    fn reported(ordinal:u32,operation_id:[u8;32],entered:&'a std::sync::atomic::AtomicBool)->Self{Self{ordinal,operation_id:Some(operation_id),entered:Some(entered)}}
    pub(super) fn enter(self){if let Some(entered)=self.entered{entered.store(true,Ordering::Release)}}
}
#[derive(Debug)]
pub(super) struct NoRetry;
impl std::fmt::Display for NoRetry{fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{f.write_str("certificate issuance retry operation ended")}}
impl std::error::Error for NoRetry{}
#[derive(Default)]
pub(crate) struct RetryOperation {started:Option<std::time::Instant>,ordinal:u32,identity:Option<[u8;32]>,closed_until:Option<std::time::Instant>}
impl RetryOperation {
    fn ordinal(&mut self,scan:Duration)->Option<u32>{
        let now=std::time::Instant::now();
        if self.closed_until.is_some_and(|until|until>now){return None}
        if self.closed_until.take().is_some(){self.started=None;self.ordinal=0;self.identity=None;}
        if self.started.is_some_and(|start|now.saturating_duration_since(start)>=Duration::from_secs(30*24*3600)) {
            self.started=None;self.ordinal=0;self.identity=None;self.closed_until=now.checked_add(scan.max(Duration::from_secs(1)));return None
        }
        self.started.get_or_insert(now);
        Some(self.ordinal)
    }
    pub(crate) fn round<'a>(&mut self,scan:Duration,entered:&'a std::sync::atomic::AtomicBool)->Result<Option<AcmeRound<'a>>>{
        let Some(ordinal)=self.ordinal(scan)else{return Ok(None)};
        if self.identity.is_none(){
            use p256::elliptic_curve::rand_core::RngCore;
            let mut id=[0u8;32];
            if p256::elliptic_curve::rand_core::OsRng.try_fill_bytes(&mut id).is_err(){
                self.started=None;self.ordinal=0;self.closed_until=std::time::Instant::now().checked_add(scan.max(Duration::from_secs(1)));
                return Err(anyhow!("issuance retry operation entropy unavailable").context(NoRetry))
            }
            self.identity=Some(id);
        }
        Ok(Some(AcmeRound::reported(ordinal,self.identity.ok_or_else(||anyhow!("issuance retry operation identity missing"))?,entered)))
    }
    pub(crate) fn close(&mut self){*self=Self::default()}
    pub(crate) fn wait(&self)->Duration{self.closed_until.map_or(Duration::ZERO,|at|at.saturating_duration_since(std::time::Instant::now()))}
    pub(crate) fn failed(&mut self,entered:bool,error:&anyhow::Error,scan:Duration){
        if !entered{if self.ordinal==0{self.started=None;self.identity=None}return}
        let now=std::time::Instant::now();let started=*self.started.get_or_insert(now);
        if error.is::<NoRetry>()||now.saturating_duration_since(started)>=Duration::from_secs(30*24*3600){
            self.ordinal=0;self.started=None;self.identity=None;self.closed_until=now.checked_add(scan.max(Duration::from_secs(1)));
        }else{self.ordinal=self.ordinal.saturating_add(1)}
    }
}

