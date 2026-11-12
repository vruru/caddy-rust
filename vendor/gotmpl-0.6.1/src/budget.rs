// src/budget.rs
//
// Shared budget bridge for template rendering.
// Provides ByteLease (per-allocation ownership) and BudgetAccount (temporary
// allocation tracking). Both cooperate with an external BudgetMeter to enforce
// a global byte/work ceiling (e.g. 64 MiB / 32 MiB ticket budgets).
//
// Design invariants:
// - ByteLease is NOT stored inside Control to avoid Arc cycles.
// - BudgetAccount is the ONLY cloneable handle (O(1) Arc clone, shared ledger).
// - BudgetAccount does NOT create a new limit pool; it tracks temporary
//   allocation ownership within the single BudgetMeter.
// - commit_retained: returns permanent usage to caller; the meter Arc is
//   dropped normally (no mem::forget). Budget is released only when the
//   owning Control root ends its lifetime (conservative cumulative strategy).
// - The actual heap allocation must be destroyed BEFORE calling release /
//   dropping the Account. Returned Vec should transfer its actual capacity
//   via `transfer`. A renderer that converts to Arc should reserve peak
//   bytes before the conversion. Newly allocated values may be committed
//   via `commit_retained`.
//
// no_std compatible: uses `core` + `alloc` only. No `unsafe`. No external
// dependencies. Atomic operations via `core::sync::atomic`.

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::{Result, TemplateError};

// ---------------------------------------------------------------------------
// BudgetMeter callback adapter
// ---------------------------------------------------------------------------

/// Closed callback adapter to the owning render's single budget pool.
/// Allocation/refund operations are private; only ownership accounts and leases
/// can use them. The caller must charge adapter construction metadata first.
pub struct BudgetMeter {
    check:Box<dyn Fn()->Result<()>+Send+Sync>,
    work:Box<dyn Fn(usize)->Result<()>+Send+Sync>,
    reserve:Box<dyn Fn(usize)->Result<()>+Send+Sync>,
    refund:Box<dyn Fn(usize)+Send+Sync>,
}
impl BudgetMeter {
    /// Callbacks must be synchronous. Refund must never panic or check cancellation.
    pub fn new<C,W,R,F>(check:C,work:W,reserve:R,refund:F)->Self
    where C:Fn()->Result<()>+Send+Sync+'static,W:Fn(usize)->Result<()>+Send+Sync+'static,R:Fn(usize)->Result<()>+Send+Sync+'static,F:Fn(usize)+Send+Sync+'static {
        Self{check:Box::new(check),work:Box::new(work),reserve:Box::new(reserve),refund:Box::new(refund)}
    }
    pub fn check(&self)->Result<()>{(self.check)()}
    pub fn charge_work(&self,units:usize)->Result<()>{(self.work)(units)}
    fn reserve_bytes(&self,bytes:usize)->Result<()>{(self.reserve)(bytes)}
    fn release_bytes(&self,bytes:usize){if bytes!=0{(self.refund)(bytes);}}
}

// ---------------------------------------------------------------------------
// ByteLease
// ---------------------------------------------------------------------------

/// A single-allocation ownership token tied to the shared `BudgetMeter`.
///
/// The lease represents a reserved byte range. On drop the reservation is
/// returned to the meter. `commit_retained` permanently converts the
/// reservation (the meter Arc is dropped; budget freed only when the
/// Control root ends its lifetime — conservative cumulative policy).
///
/// ByteLease is intentionally **not** Clone (single-owner semantics).
pub struct ByteLease {
    meter: Arc<BudgetMeter>,
    bytes: usize,
}

impl ByteLease {
    /// Create a new lease, reserving `bytes` on the meter **before** the
    /// lease struct is constructed.
    pub fn new(meter: Arc<BudgetMeter>, bytes: usize) -> Result<Self> {
        meter.reserve_bytes(bytes)?;
        Ok(Self { meter, bytes })
    }

    /// Private constructor used by `BudgetAccount::transfer`.
    /// The bytes have already been reserved (subtracted from account
    /// reserved), so no additional meter call is needed.
    fn from_reserved(meter: Arc<BudgetMeter>, bytes: usize) -> Self {
        Self { meter, bytes }
    }

    /// Increase the lease by `add` bytes.
    /// Order: checked_add → meter.reserve → update field.
    /// On overflow the lease is unchanged.
    pub fn grow(&mut self, add: usize) -> Result<()> {
        let new_total = self
            .bytes
            .checked_add(add)
            .ok_or_else(|| TemplateError::Exec("ByteLease::grow: overflow".into()))?;
        self.meter.reserve_bytes(add)?;
        self.bytes = new_total;
        Ok(())
    }

    /// Shrink the lease to `n` bytes, refunding the difference.
    /// Rejects `n > current bytes`.
    pub fn shrink_to(&mut self, n: usize) -> Result<()> {
        if n > self.bytes {
            return Err(TemplateError::Exec(
                "ByteLease::shrink_to: target exceeds current bytes".into(),
            ));
        }
        let refund = self.bytes - n;
        self.bytes = n;
        self.meter.release_bytes(refund);
        Ok(())
    }

    /// Current byte count held by this lease.
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    /// Permanently commit the reservation.
    ///
    /// Sets internal byte count to 0 so that the subsequent normal `Drop`
    /// releases zero (no budget is returned). The `meter: Arc<…>` is dropped
    /// normally — **no** `mem::forget`. The reserved bytes are considered
    /// permanently consumed until the Control root ends its lifetime
    /// (conservative cumulative strategy).
    ///
    /// Returns the number of bytes permanently committed.
    pub fn commit_retained(mut self) -> usize {
        let b = self.bytes;
        self.bytes = 0;
        b
        // `self` is consumed; Drop sees bytes == 0 → release_bytes(0).
    }
}

impl Drop for ByteLease {
    fn drop(&mut self) {
        let b = self.bytes;
        self.bytes = 0;
        // release_bytes is infallible; no check / cancel.
        self.meter.release_bytes(b);
    }
}

// ---------------------------------------------------------------------------
// AccountInner
// ---------------------------------------------------------------------------

/// Interior state of `BudgetAccount`.
///
/// `reserved` tracks only **runtime** ownership bytes (does NOT include the
/// metadata reservation made at construction).
struct AccountInner {
    meter: Arc<BudgetMeter>,
    /// Runtime-owned reserved bytes (atomic for concurrent clone access).
    reserved: AtomicUsize,
    /// Bytes reserved for this struct's own Arc/metadata overhead.
    /// Fixed at construction; not transferable; released on final drop.
    metadata_bytes: usize,
}

impl AccountInner {
    fn new(meter: Arc<BudgetMeter>) -> Result<Self> {
        // Check meter is healthy before any reservation.
        meter.check()?;

        // Conservative metadata: size_of AccountInner + 4 * size_of(usize)
        // accounts for Arc header, refcount, vtable pointer, alignment.
        let metadata = core::mem::size_of::<AccountInner>() + 4 * core::mem::size_of::<usize>();

        meter.reserve_bytes(metadata)?;

        Ok(Self {
            meter,
            reserved: AtomicUsize::new(0),
            metadata_bytes: metadata,
        })
    }
}

impl Drop for AccountInner {
    fn drop(&mut self) {
        // `self` is uniquely owned here (last Arc strong ref).
        let runtime = core::mem::take(self.reserved.get_mut());
        let total = runtime.checked_add(self.metadata_bytes);

        match total {
            Some(t) => {
                // Single release. Theoretical bound: init + owned ≤ 64 MiB
                // so checked_add practically cannot overflow on 64-bit,
                // and even on 32-bit the budget ceiling guarantees no wrap.
                self.meter.release_bytes(t);
            }
            None => {
                // Defensive: if the sum overflows (pathological), split into
                // two separate infallible releases to avoid any panic/mint.
                self.meter.release_bytes(runtime);
                self.meter.release_bytes(self.metadata_bytes);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// BudgetAccount
// ---------------------------------------------------------------------------

/// Cloneable handle to a shared temporary-allocation ownership ledger.
///
/// All clones observe the same `AccountInner` (single `reserved` counter,
/// single meter). Clone is O(1) Arc bump. The account does **not** create a
/// new budget pool — it partitions the caller's BudgetMeter for scoped
/// temporary allocations during rendering.
#[derive(Clone)]
pub struct BudgetAccount {
    inner: Arc<AccountInner>,
}

impl BudgetAccount {
    /// Construct a new account on the given meter.
    ///
    /// Performs `meter.check()` then reserves metadata bytes
    /// (`size_of::<AccountInner>() + 4 * size_of::<usize>()`) before
    /// allocating the `Arc<AccountInner>`.
    pub fn new(meter: Arc<BudgetMeter>) -> Result<Self> {
        let inner = AccountInner::new(meter)?;
        Ok(Self {
            inner: Arc::new(inner),
        })
    }

    /// Reserve `n` additional runtime bytes.
    ///
    /// Order: meter.reserve → atomic fetch_update(checked_add) on `reserved`.
    /// If the atomic add overflows, the outer reservation is released and
    /// an error is returned.
    pub fn reserve(&self, n: usize) -> Result<()> {
        self.inner.meter.reserve_bytes(n)?;

        let prev = self.inner.reserved.try_update(
            Ordering::SeqCst,
            Ordering::SeqCst,
            |cur| cur.checked_add(n),
        );

        match prev {
            Ok(_) => Ok(()),
            Err(_) => {
                // checked_add overflowed; undo the outer reservation.
                self.inner.meter.release_bytes(n);
                Err(TemplateError::Exec("BudgetAccount::reserve: overflow".into()))
            }
        }
    }

    /// Release `n` runtime bytes back to the meter.
    ///
    /// CAS-based `checked_sub` on `reserved`. If `n` exceeds the current
    /// reserved amount the operation fails; the meter is **not** touched.
    pub fn release(&self, n: usize) -> Result<()> {
        let prev = self.inner.reserved.try_update(
            Ordering::SeqCst,
            Ordering::SeqCst,
            |cur| cur.checked_sub(n),
        );

        match prev {
            Ok(_) => {
                self.inner.meter.release_bytes(n);
                Ok(())
            }
            Err(_) => Err(TemplateError::Exec(
                "BudgetAccount::release: exceeds reserved".into(),
            )),
        }
    }

    /// Transfer `n` bytes of ownership out of the account as a new
    /// `ByteLease`.
    ///
    /// CAS `checked_sub` on the account's reserved counter; the lease is
    /// constructed via the private `from_reserved` path (no new
    /// meter.reserve / release). Used e.g. to hand a `Vec`'s actual
    /// capacity to a renderer.
    ///
    /// The caller must exclusively own the `n` prepaid credits being handed
    /// off. A shared account balance is not permission to transfer credits
    /// still needed by a parent scope, another buffer, or a live allocation.
    /// The resulting lease must remain alive until its allocation is freed.
    pub fn transfer(&self, n: usize) -> Result<ByteLease> {
        let prev = self.inner.reserved.try_update(
            Ordering::SeqCst,
            Ordering::SeqCst,
            |cur| cur.checked_sub(n),
        );

        match prev {
            Ok(_) => {
                let lease = ByteLease::from_reserved(self.inner.meter.clone(), n);
                Ok(lease)
            }
            Err(_) => Err(TemplateError::Exec(
                "BudgetAccount::transfer: exceeds reserved".into(),
            )),
        }
    }

    /// Delegate health check to the underlying meter.
    pub fn check(&self) -> Result<()> {
        self.inner.meter.check()
    }

    /// Delegate work charging to the underlying meter.
    pub fn charge_work(&self, units: usize) -> Result<()> {
        self.inner.meter.charge_work(units)
    }

    /// Current runtime reserved bytes (excludes metadata overhead).
    pub fn reserved_bytes(&self) -> usize {
        self.inner.reserved.load(Ordering::SeqCst)
    }
}

// ---------------------------------------------------------------------------
// Tests are intentionally omitted per specification.
// ---------------------------------------------------------------------------

/// Rendered bytes and their already-reserved allocation. Fields intentionally
/// drop in declaration order: the Vec is destroyed before the lease refunds.
pub struct BudgetedBytes {
    bytes:alloc::vec::Vec<u8>,
    lease:ByteLease,
}
impl BudgetedBytes {
    /// Transfer a fully prepaid, exclusively owned Vec into its output lease.
    /// All of `bytes.capacity()` must already belong to this buffer in the
    /// account; charging only its length is insufficient. No other live
    /// allocation may reuse those credits, and any later buffer growth must
    /// acquire additional credits before allocating (this API exposes no
    /// unmetered mutable Vec access).
    pub fn from_account(bytes:alloc::vec::Vec<u8>,account:&BudgetAccount)->Result<Self>{
        let lease=account.transfer(bytes.capacity())?;Ok(Self{bytes,lease})
    }
    pub fn as_bytes(&self)->&[u8]{&self.bytes}
    pub fn capacity(&self)->usize{self.bytes.capacity()}
    /// Reserve the Vec+Arc conversion peak, destroy the old Vec before refund,
    /// then conservatively retain the new Value charge until the render ends.
    pub fn into_value(self,limit:usize)->Result<crate::Value>{
        if self.bytes.len()>limit{return Err(TemplateError::Exec("rendered bytes exceed output limit".into()));}
        let data=core::alloc::Layout::array::<u8>(self.bytes.len()).map_err(|_|TemplateError::Exec("rendered byte layout overflow".into()))?;
        let (layout,_)=core::alloc::Layout::new::<[usize;2]>().extend(data).map_err(|_|TemplateError::Exec("rendered Arc layout overflow".into()))?;
        let retained=ByteLease::new(self.lease.meter.clone(),layout.pad_to_align().size())?;
        let value=match core::str::from_utf8(&self.bytes){Ok(text)=>crate::Value::String(Arc::from(text)),Err(_)=>crate::Value::from_go_bytes(Arc::<[u8]>::from(self.bytes.as_slice()))};
        drop(self);retained.commit_retained();Ok(value)
    }
}
