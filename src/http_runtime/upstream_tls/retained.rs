//! Concrete mapped TLS credits follow the real worker and its pending result.
use native_ssl_tls::ConnectionCredits;
use native_write_policy::{Lease,Pool};
use std::{future::Future,pin::Pin,sync::Arc,task::{Context,Poll}};

pub(super) struct RetainedTls<F:Future>{
    // Declaration order is also the unpolled/cancel/panic destruction order.
    future:Pin<Box<F>>,
    credits:Arc<ConnectionCredits>,
    allocation:Arc<Lease>,
}
impl<F:Future> RetainedTls<F>{
    pub(super) fn new(future:F,credits:Arc<ConnectionCredits>,pool:&Pool)->anyhow::Result<Self>{
        // The box and its finite output/oneshot bookkeeping are admitted before
        // allocating either. This covers our adapter, not the TLS provider heap.
        let bytes=std::mem::size_of::<F>().checked_add(std::mem::size_of::<F::Output>())
            .and_then(|n|n.checked_add(1024)).ok_or_else(||anyhow::anyhow!("Map TLS ownership size overflow"))?;
        let allocation=Arc::new(pool.reserve(bytes)?);
        Ok(Self{future:Box::pin(future),credits,allocation})
    }
}
pub(super) struct RetainedTlsResult<T>{
    value:Option<T>,
    _credits:Arc<ConnectionCredits>,
    _allocation:Arc<Lease>,
}
impl<T> RetainedTlsResult<T>{
    // The caller keeps this envelope alive through classification and handoff.
    pub(super) fn take(&mut self)->T{self.value.take().expect("retained TLS result already taken")}
}
impl<F:Future> Future for RetainedTls<F>{
    type Output=RetainedTlsResult<F::Output>;
    fn poll(self:Pin<&mut Self>,cx:&mut Context<'_>)->Poll<Self::Output>{
        let this=self.get_mut();
        match this.future.as_mut().poll(cx){
            Poll::Pending=>Poll::Pending,
            Poll::Ready(value)=>Poll::Ready(RetainedTlsResult{value:Some(value),_credits:this.credits.clone(),_allocation:this.allocation.clone()}),
        }
    }
}
