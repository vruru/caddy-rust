//! Scoped Rust allocator accounting for the transpiled parser. There is no C
//! unwind boundary. A failed reservation must unwind; returning null would be
//! unsafe because libyaml's growth macros immediately write through the result.
use core::{cell::Cell,ffi::c_void,ptr};
use alloc::alloc::{self as rust,Layout};
std::thread_local!{static ACTIVE:Cell<*mut Scope>=const{Cell::new(ptr::null_mut())};}

#[derive(Clone,Copy)]
pub struct Callbacks {
    pub data:*mut (),
    pub reserve:unsafe fn(*mut (),usize),
    pub release:unsafe fn(*mut (),usize),
}
#[repr(C)]
struct Header{size:usize,previous:*mut Header,next:*mut Header,owner:*mut Scope}
struct Scope{head:*mut Header,callbacks:Callbacks}
struct Guard(*mut Scope);
impl Drop for Guard{
    fn drop(&mut self){
        // Parser state may be halfway through a pointer update after a budget
        // unwind. Never inspect or delete that state: reclaim the allocation
        // list, including allocations not yet attached to parser fields.
        unsafe{while !(*self.0).head.is_null(){free((*self.0).head.add(1).cast());}}
        ACTIVE.with(|active|active.set(ptr::null_mut()));
    }
}
/// Run one parser lifetime with callbacks and reclaim every remaining raw
/// allocation on normal return or Rust unwind. Nested scopes are rejected.
///
/// # Safety
/// No raw libyaml allocation may enter or escape this scope. The parser must
/// skip its normal destructor during unwind because it may be partially
/// updated. `data` and callbacks must remain valid throughout the call;
/// release must be infallible, including during unwind. Reserve may unwind.
pub unsafe fn with_allocator<T>(callbacks:Callbacks,call:impl FnOnce()->T)->T{
    let mut scope=Scope{head:ptr::null_mut(),callbacks};
    let pointer=ptr::addr_of_mut!(scope);
    ACTIVE.with(|active|{assert!(active.get().is_null(),"nested YAML allocation scope");active.set(pointer);});
    // `scope` stays at this address until `guard` has reclaimed its list.
    let guard=Guard(pointer);
    let result=call();
    drop(guard);
    result
}
pub(crate) unsafe fn malloc(payload:usize)->*mut c_void{
    let size=payload.checked_add(core::mem::size_of::<Header>()).expect("YAML allocation size overflow");
    let layout=Layout::from_size_align(size,core::mem::align_of::<Header>()).expect("YAML allocation layout overflow");
    let owner=ACTIVE.with(Cell::get);
    if !owner.is_null(){((*owner).callbacks.reserve)((*owner).callbacks.data,size);}
    let memory=rust::alloc(layout).cast::<Header>();
    if memory.is_null(){rust::handle_alloc_error(layout);}
    memory.write(Header{size,previous:ptr::null_mut(),next:ptr::null_mut(),owner});
    if !owner.is_null(){
        (*memory).next=(*owner).head;
        if !(*owner).head.is_null(){(*(*owner).head).previous=memory;}
        (*owner).head=memory;
    }
    memory.add(1).cast()
}
pub(crate) unsafe fn free(pointer:*mut c_void){
    let header=pointer.cast::<Header>().sub(1);
    let Header{size,previous,next,owner}=header.read();
    if !owner.is_null(){
        if previous.is_null(){(*owner).head=next;}else{(*previous).next=next;}
        if !next.is_null(){(*next).previous=previous;}
    }
    rust::dealloc(header.cast(),Layout::from_size_align_unchecked(size,core::mem::align_of::<Header>()));
    if !owner.is_null(){((*owner).callbacks.release)((*owner).callbacks.data,size);}
}
pub(crate) unsafe fn realloc(pointer:*mut c_void,payload:usize)->*mut c_void{
    // Full new storage is reserved while old storage is still live, matching
    // the actual copy peak rather than charging only the capacity difference.
    let old_size=(*pointer.cast::<Header>().sub(1)).size-core::mem::size_of::<Header>();
    let next=malloc(payload);
    ptr::copy_nonoverlapping(pointer.cast::<u8>(),next.cast::<u8>(),old_size.min(payload));
    free(pointer);
    next
}
