//! Iterative destruction of mutable map graphs. Every intrusive queue node is
//! allocated when its cell is constructed; retirement itself never allocates.
use super::KeyedEntries;
use crate::{BudgetAccount, Value};
use std::{
    cell::RefCell,
    mem::ManuallyDrop,
    ops::{Deref, DerefMut},
    sync::{
        Arc, LockResult, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
};

// std::sync::Mutex uses a lazy heap allocation per initialized mutex on some
// supported hosts. Keep graph/cell locking inline while preserving poisoning.
pub(super) struct Mutex<T> {
    inner: parking_lot::Mutex<T>,
    poisoned: AtomicBool,
}
impl<T> Mutex<T> {
    pub(super) const fn new(value: T) -> Self {
        Self {
            inner: parking_lot::Mutex::new(value),
            poisoned: AtomicBool::new(false),
        }
    }
    pub(super) fn lock(&self) -> LockResult<MutexGuard<'_, T>> {
        let inner = self.inner.lock();
        let guard = MutexGuard {
            inner,
            poisoned: &self.poisoned,
            panicking: std::thread::panicking(),
        };
        if self.poisoned.load(Ordering::Acquire) {
            Err(PoisonError::new(guard))
        } else {
            Ok(guard)
        }
    }
    pub(super) fn get_mut(&mut self) -> LockResult<&mut T> {
        let value = self.inner.get_mut();
        if *self.poisoned.get_mut() {
            Err(PoisonError::new(value))
        } else {
            Ok(value)
        }
    }
}
pub(super) struct MutexGuard<'a, T> {
    inner: parking_lot::MutexGuard<'a, T>,
    poisoned: &'a AtomicBool,
    panicking: bool,
}
impl<T> Deref for MutexGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.inner
    }
}
impl<T> DerefMut for MutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}
impl<T> Drop for MutexGuard<'_, T> {
    fn drop(&mut self) {
        if !self.panicking && std::thread::panicking() {
            self.poisoned.store(true, Ordering::Release);
        }
    }
}

pub(super) struct EntriesSlot<T>(Mutex<Option<Arc<T>>>);
impl<T> EntriesSlot<T> {
    pub(super) fn new(entries: T) -> Self {
        Self(Mutex::new(Some(Arc::new(entries))))
    }
    pub(super) fn lock(&self) -> std::result::Result<EntriesGuard<'_, T>, ()> {
        self.0.lock().map(EntriesGuard).map_err(|_| ())
    }
    pub(super) fn take(&mut self) -> Arc<T> {
        self.0
            .get_mut()
            .unwrap_or_else(|poison| poison.into_inner())
            .take()
            .expect("live map has entries")
    }
}
pub(super) struct EntriesGuard<'a, T>(MutexGuard<'a, Option<Arc<T>>>);
impl<T> Deref for EntriesGuard<'_, T> {
    type Target = Arc<T>;
    fn deref(&self) -> &Arc<T> {
        self.0.as_ref().expect("live map has entries")
    }
}
impl<T> DerefMut for EntriesGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Arc<T> {
        self.0.as_mut().expect("live map has entries")
    }
}

// Two typed heads avoid storing a payload enum/tag in every keyed node.
// Keyed nodes occupy 16 bytes and generic nodes 24 bytes on 64-bit hosts.
pub(super) struct KeyedNode {
    entries: Option<Arc<KeyedEntries>>,
    next: Option<Box<KeyedNode>>,
}
pub(super) struct GenericNode {
    entries: Option<Arc<Vec<(Value, Value)>>>,
    next: Option<Box<GenericNode>>,
    _account: BudgetAccount,
}
impl KeyedNode {
    pub(super) fn new() -> Box<Self> {
        Box::new(Self {
            entries: None,
            next: None,
        })
    }
    pub(super) fn retire(mut self: Box<Self>, entries: Arc<KeyedEntries>) {
        self.entries = Some(entries);
        enqueue(Next::Keyed(self));
    }
}
impl GenericNode {
    pub(super) fn new(account: &BudgetAccount) -> Box<Self> {
        Box::new(Self {
            entries: None,
            next: None,
            _account: account.clone(),
        })
    }
    pub(super) fn retire(mut self: Box<Self>, entries: Arc<Vec<(Value, Value)>>) {
        self.entries = Some(entries);
        enqueue(Next::Generic(self));
    }
}
struct Queue {
    keyed: ManuallyDrop<Option<Box<KeyedNode>>>,
    generic: ManuallyDrop<Option<Box<GenericNode>>>,
    draining: bool,
}
// No TLS destructor: other TLS destructors can still retire graphs. Every
// normal/unwinding exit explicitly drains both heads.
const _: () = assert!(!std::mem::needs_drop::<RefCell<Queue>>());
thread_local! {
    static QUEUE:RefCell<Queue>=const {RefCell::new(Queue{keyed:ManuallyDrop::new(None),generic:ManuallyDrop::new(None),draining:false})};
}
enum Next {
    Keyed(Box<KeyedNode>),
    Generic(Box<GenericNode>),
}
fn drain() {
    loop {
        let next = QUEUE.with(|queue| {
            let mut queue = queue.borrow_mut();
            if let Some(mut node) = queue.keyed.take() {
                *queue.keyed = node.next.take();
                return Some(Next::Keyed(node));
            }
            if let Some(mut node) = queue.generic.take() {
                *queue.generic = node.next.take();
                return Some(Next::Generic(node));
            }
            None
        });
        // Never hold the RefCell borrow while destroying entries or returning
        // their budget. Nested destructors only append their prepaid nodes.
        match next {
            Some(Next::Keyed(mut node)) => {
                drop(node.entries.take());
                drop(node);
            }
            Some(Next::Generic(mut node)) => {
                drop(node.entries.take());
                drop(node);
            }
            None => return,
        }
    }
}
struct DrainGuard;
impl Drop for DrainGuard {
    fn drop(&mut self) {
        // Also finish queued work if a host-owned payload destructor unwinds.
        drain();
        QUEUE.with(|queue| queue.borrow_mut().draining = false);
    }
}
fn enqueue(next: Next) {
    let start = QUEUE.with(|queue| {
        let mut queue = queue.borrow_mut();
        match next {
            Next::Keyed(mut node) => {
                node.next = queue.keyed.take();
                *queue.keyed = Some(node);
            }
            Next::Generic(mut node) => {
                node.next = queue.generic.take();
                *queue.generic = Some(node);
            }
        }
        if queue.draining {
            false
        } else {
            queue.draining = true;
            true
        }
    });
    if start {
        let guard = DrainGuard;
        drain();
        drop(guard);
    }
}
