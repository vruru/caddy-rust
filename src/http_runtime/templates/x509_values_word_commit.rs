//! Two-phase Number metadata and shared Word-cell commit. No callback or
//! fallible arithmetic occurs under Number locks; all cells change together.
use super::*;
use super::words::{Words, Staged};
use gotmpl::{TypedSlice, ValuesWrite};

#[derive(Clone, Copy)]
pub(super) struct Shape {
    pub(super) requested: usize,
    pub(super) written: usize,
    pub(super) force_new: bool,
    pub(super) preserve_header: bool,
}
impl Shape {
    pub(super) fn copy(n: &BigInt) -> RenderResult<Self> {
        let len = usize::try_from(n.bits().div_ceil(64)).map_err(|_| error("big.Word result length overflow"))?;
        Ok(Self { requested: len, written: len, force_new: false, preserve_header: false })
    }
}
pub(super) struct Change<'a> {
    pub(super) data: &'a Integer,
    pub(super) number: BigInt,
    pub(super) negative_zero: bool,
    pub(super) shape: Shape,
    pub(super) adopt: Option<Words>,
}
struct Meta<'a> {
    data: &'a Integer,
    epoch: u64,
    words: Words,
    last: usize,
}

/// Callers stage arithmetic and result Object allocation before entering here.
/// Duplicate Number outputs preserve input write order, including Word tails;
/// each Number's final metadata comes from its last write. Number locks and
/// Word locks each use their actual canonical cell order. Old snapshots and
/// staged payloads are dropped only after the Number guards have been released.
pub(super) fn commit<'a>(factory: &Arc<Factory>, changes: &mut [Change<'a>]) -> RenderResult<()> {
    if changes.len() > 256 { return Err(error("big.Int atomic output limit exceeded")); }
    factory.work(0)?;
    for change in changes.iter() {
        let target_owner = owner(change.data)?;
        if !Arc::ptr_eq(&target_owner, factory) { return Err(error("foreign big.Int output owner")); }
        target_owner.work(0)?;
        if let Some(words)=&change.adopt {words.check_owner(factory)?;}
    }
    let unit = std::mem::size_of::<Change<'_>>().checked_add(std::mem::size_of::<Meta<'_>>())
        .and_then(|n| n.checked_add(std::mem::size_of::<Staged>()))
        .and_then(|n| n.checked_add(std::mem::size_of::<ValuesWrite<'_>>()))
        .and_then(|n| n.checked_add(128)).ok_or_else(|| error("big.Int commit metadata overflow"))?;
    factory.reserve(unit.checked_mul(changes.len()).and_then(|n|n.checked_mul(3))
        .and_then(|n|n.checked_add(2048)).ok_or_else(|| error("big.Int commit budget overflow"))?)?;
    factory.work(changes.len().checked_add(1).ok_or_else(|| error("big.Int commit work overflow"))?)?;
    let mut metadata: BTreeMap<usize, Meta<'a>> = BTreeMap::new();
    let mut stages = Vec::new();
    stages.try_reserve_exact(changes.len()).map_err(|_| error("big.Int staging allocation failed"))?;
    // Snapshot every receiver header and precheck every epoch before preparing
    // even a private new backing. Recheck all of these immediately at commit.
    for (index, change) in changes.iter().enumerate() {
        let id = std::ptr::from_ref(change.data) as usize;
        if metadata.contains_key(&id) { continue; }
        let state = change.data.number.lock().map_err(|_| error("big.Int cell poisoned"))?;
        let meta = Meta { data: change.data, epoch: state.epoch, words: state.words.clone(), last: index };
        drop(state);
        if meta.epoch == u64::MAX { return Err(error("big.Int epoch overflow")); }
        metadata.insert(id, meta);
    }
    for (index, change) in changes.iter().enumerate() {
        let id = std::ptr::from_ref(change.data) as usize;
        let meta = metadata.get_mut(&id).ok_or_else(|| error("big.Int output metadata missing"))?;
        let shape = change.shape;
        let staged = match &change.adopt {
            Some(words)=>Staged{next:words.clone(),target:None,values:Vec::new()},
            None=>meta.words.stage(factory, &change.number, shape.requested, shape.written, shape.force_new, shape.preserve_header)?,
        };
        meta.words = staged.next.clone();
        meta.last = index;
        stages.push(staged);
    }
    let mut word_writes = Vec::new();
    word_writes.try_reserve_exact(stages.len()).map_err(|_| error("big.Int Word-write metadata allocation failed"))?;
    for stage in &stages {
        if let Some(target) = &stage.target {
            word_writes.push(ValuesWrite { slice: target, offset: 0, values: &stage.values });
        }
    }
    let mut ticket = TypedSlice::prepare_values_writes_reusing_exclusive_scalars(&word_writes)?;
    // Retain copies of references independently of the metadata container so
    // safe Rust can move its final headers while guards borrow the real cells.
    let mut cells: Vec<&'a Integer> = Vec::new();
    let mut metas = Vec::new();
    let mut epochs = Vec::new();
    cells.try_reserve_exact(metadata.len()).map_err(|_| error("big.Int cell metadata allocation failed"))?;
    metas.try_reserve_exact(metadata.len()).map_err(|_| error("big.Int metadata allocation failed"))?;
    epochs.try_reserve_exact(metadata.len()).map_err(|_| error("big.Int epoch metadata allocation failed"))?;
    for meta in metadata.into_values() {
        cells.push(meta.data); metas.push(meta); epochs.push(0u64);
    }
    let mut guards = Vec::new();
    guards.try_reserve_exact(cells.len()).map_err(|_| error("big.Int guard allocation failed"))?;
    // Revalidate every owner outside all receiver/cell locks. A cancellation
    // arriving afterwards cannot turn this bounded atomic swap into half writes.
    factory.work(0)?;
    for cell in &cells {
        let target_owner = owner(cell)?;
        if !Arc::ptr_eq(&target_owner, factory) { return Err(error("foreign big.Int output owner")); }
        target_owner.work(0)?;
    }
    let mut failure = None;
    for cell in &cells {
        match cell.number.lock() {
            Ok(state) => guards.push(state),
            Err(_) => { failure = Some("big.Int cell poisoned"); break; }
        }
    }
    if failure.is_none() {
        for ((state, meta), next) in guards.iter().zip(&metas).zip(&mut epochs) {
            if state.epoch != meta.epoch { failure = Some("concurrent big.Int output change"); break; }
            match state.epoch.checked_add(1) {
                Some(epoch) => *next = epoch,
                None => { failure = Some("big.Int epoch overflow"); break; }
            }
        }
    }
    let mut ticket_failure = None;
    if failure.is_none() {
        match ticket.try_commit() {
            Err(e) => ticket_failure = Some(e),
            Ok(()) => {
                // Every index/header/epoch was validated before the Word swap.
                // BigInt::default is allocation-free zero; the metadata moves
                // below cannot invoke foreign Value/callback destructors.
                for ((state, meta), epoch) in guards.iter_mut().zip(&mut metas).zip(epochs) {
                    let change = &mut changes[meta.last];
                    state.number = std::mem::take(&mut change.number);
                    state.negative_zero = change.negative_zero;
                    state.words = std::mem::replace(&mut meta.words, Words::nil());
                    state.epoch = epoch;
                }
            }
        }
    }
    drop(guards);
    // Error conversion and all retirement happen after the last Number lock.
    if let Some(message) = failure { return Err(error(message)); }
    if let Some(e) = ticket_failure { return Err(e.into()); }
    Ok(())
}
