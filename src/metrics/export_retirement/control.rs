//! Concrete metrics control loans. Both limits cover the same allocation.
use anyhow::{Context, Result};
use std::{alloc::Layout, mem::size_of, sync::Arc};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
pub(super) const LIMIT: usize = 8 << 20;

// Allocation layout of ArcInner<T> for these concrete standard-aligned types.
// The two atomic refcounts precede T, with its actual alignment/padding.
fn arc_layout<T>() -> Result<usize> {
    let header = Layout::new::<[std::sync::atomic::AtomicUsize; 2]>();
    let (layout, _) = header
        .extend(Layout::new::<T>())
        .context("metrics control Arc layout overflow")?;
    Ok(layout.pad_to_align().size())
}

struct Bootstrap {
    // Return the secondary quota and its pool reference before the physical
    // parent reservation. This holder has no Admission or CreditInner backedge.
    _subtype: OwnedSemaphorePermit,
    _parent: OwnedSemaphorePermit,
}
struct CreditInner {
    // Data/control users drop their actual object before their MetricCredit.
    // Keep subtype/bootstrap controls through every clone of this exact loan.
    _subtype: OwnedSemaphorePermit,
    _parent: OwnedSemaphorePermit,
    _bootstrap: Arc<Bootstrap>,
}
#[derive(Clone)]
pub(super) struct MetricCredit {
    _inner: Arc<CreditInner>,
}
pub(super) struct MetricAdmission {
    parent: Arc<Semaphore>,
    subtype: Arc<Semaphore>,
    bootstrap: Arc<Bootstrap>,
}
impl MetricAdmission {
    pub(super) fn new(parent: Arc<Semaphore>) -> Result<Arc<Self>> {
        let bytes = arc_layout::<Self>()?
            .checked_add(arc_layout::<Semaphore>()?)
            .and_then(|n| n.checked_add(arc_layout::<Bootstrap>().ok()?))
            .context("metrics control bootstrap layout overflow")?;
        let count = u32::try_from(bytes).context("metrics control bootstrap too large")?;
        // The existing 64MiB parent is prepaid BEFORE even the subtype pool
        // allocates. The fresh secondary limit is applied to that same layout
        // before the remaining bootstrap/Admission allocations become live.
        let primary = parent
            .clone()
            .try_acquire_many_owned(count)
            .context("metrics request-state control bootstrap admission refused")?;
        let subtype = Arc::new(Semaphore::new(LIMIT));
        let secondary = subtype
            .clone()
            .try_acquire_many_owned(count)
            .context("metrics control subtype bootstrap admission refused")?;
        let bootstrap = Arc::new(Bootstrap {
            _subtype: secondary,
            _parent: primary,
        });
        Ok(Arc::new(Self {
            parent,
            subtype,
            bootstrap,
        }))
    }
    pub(super) fn reserve(&self, bytes: usize) -> Result<MetricCredit> {
        let total = bytes
            .checked_add(arc_layout::<CreditInner>()?)
            .context("metrics control reservation layout overflow")?;
        let count = u32::try_from(total).context("metrics control reservation too large")?;
        let primary = self
            .parent
            .clone()
            .try_acquire_many_owned(count)
            .context("metrics request-state control admission refused")?;
        let secondary = self
            .subtype
            .clone()
            .try_acquire_many_owned(count)
            .context("metrics control subtype admission refused")?;
        Ok(MetricCredit {
            _inner: Arc::new(CreditInner {
                _subtype: secondary,
                _parent: primary,
                _bootstrap: self.bootstrap.clone(),
            }),
        })
    }
    pub(super) fn used(&self) -> usize {
        LIMIT - self.subtype.available_permits()
    }
    pub(super) fn credit_layout() -> usize {
        size_of::<CreditInner>() + 4 * size_of::<usize>()
    }
}
