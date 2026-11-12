//! BTree reservation for the pinned Rust 1.99.1 allocator layout.
//! alloc/collections/btree/node.rs has B=6, capacity=11, and 12 edges.
//! After insertion each non-root node has at least five entries; three
//! additional nodes cover the root and transient split/root allocations.
use gotmpl::{BudgetAccount,Result,TemplateError};
use std::mem::{size_of,align_of};
pub(super) fn node_upper<K,V>()->Result<usize>{
    if align_of::<K>()>16||align_of::<V>()>16{return Err(TemplateError::Exec("BTree alignment exceeds reserved layout".into()));}
    size_of::<K>().checked_add(size_of::<V>()).and_then(|n|n.checked_mul(11)).and_then(|n|n.checked_add(64+12*size_of::<usize>())).ok_or_else(||TemplateError::Exec("BTree layout size overflow".into()))
}
pub(super) fn btree<K,V>(entries:usize,account:&BudgetAccount)->Result<()>{
    if entries==0{return Ok(());}
    let bytes=entries.div_ceil(5).checked_add(3).and_then(|n|n.checked_mul(node_upper::<K,V>().ok()?)).ok_or_else(||TemplateError::Exec("BTree size overflow".into()))?;
    account.reserve(bytes)
}
pub(super) fn btree_insert<K,V>(first:bool,account:&BudgetAccount)->Result<()>{
    let node=node_upper::<K,V>()?;
    let bytes=node.div_ceil(5).checked_add(if first{node.checked_mul(3).ok_or_else(||TemplateError::Exec("BTree size overflow".into()))?}else{0}).ok_or_else(||TemplateError::Exec("BTree size overflow".into()))?;
    account.reserve(bytes)
}
