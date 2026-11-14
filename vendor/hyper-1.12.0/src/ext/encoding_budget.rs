//! Optional accounting for the HTTP/1 outgoing reusable byte buffer only.
use native_write_policy::{Lease,Pool};
use std::io;
/// Shares an existing atomic byte budget. None leaves the legacy encoder unchanged.
#[derive(Clone,Debug)]
pub struct NativeEncodingBudget { pool:Pool }
impl NativeEncodingBudget {
    /// The caller supplies the actual shared pool; no independent limit is created.
    pub fn new(pool:Pool)->Self{Self{pool}}
    pub(crate) fn reserve(&self,n:usize)->io::Result<Lease>{self.pool.reserve(n).map_err(|e|io::Error::new(io::ErrorKind::OutOfMemory,e))}
}
/// Retained after Vec::clear, until the real encoding allocation is destroyed.
#[derive(Debug)]
pub(crate) struct BufferBudget { context:NativeEncodingBudget, capacity:Lease, _layout:Lease }
impl BufferBudget {
    pub(crate) fn new(context:NativeEncodingBudget,n:usize)->io::Result<Self>{
        let layout=context.reserve(std::mem::size_of::<Self>())?;
        let capacity=context.reserve(n)?;
        Ok(Self{context,capacity,_layout:layout})
    }
    pub(crate) fn reserve(&mut self,bytes:&mut Vec<u8>,required:usize)->io::Result<()>{
        if required<=bytes.capacity(){return Ok(())}
        // Own old and new allocations simultaneously; claim before allocating.
        let mut next_credit=self.context.reserve(required)?;
        let mut next=Vec::new();
        next.try_reserve_exact(required).map_err(|e|io::Error::new(io::ErrorKind::OutOfMemory,e))?;
        if next.capacity()!=required{return Err(io::Error::new(io::ErrorKind::Other,"unexpected encoding capacity"))}
        next.extend_from_slice(bytes);
        std::mem::swap(bytes,&mut next);
        drop(next);
        std::mem::swap(&mut self.capacity,&mut next_credit);
        drop(next_credit);
        Ok(())
    }
}
