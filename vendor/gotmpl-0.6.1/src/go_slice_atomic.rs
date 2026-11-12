//! Prepaid, version-checked atomic replacement of existing Values backings.
//! Preparation may call budget gates and allocate. Commit does not renew owner
//! admission: a host must recheck its owners/cancellation before taking its own
//! receiver locks, then commit this ticket and update receiver metadata without
//! further fallible work. The ticket cannot grow or forge a backing identity.
use super::*;

/// One Go copy into a Values view. Every supplied value is type-checked, even
/// when the view truncates the actual copy to `min(values.len(), len-offset)`.
pub struct ValuesWrite<'a> {
    pub slice: &'a TypedSlice,
    pub offset: usize,
    pub values: &'a [Value],
}

const MAX_WRITES: usize = 256;
const MAX_INPUT_VALUES: usize = 1 << 20;

fn error(message: &str) -> TemplateError {
    TemplateError::Exec(message.into())
}

#[cfg(feature = "std")]
struct Group {
    cell: ValueCell,
    original: Arc<[Value]>,
    replacement: Arc<[Value]>,
}
#[cfg(feature = "std")]
struct Stage {
    cell: ValueCell,
    first: usize,
    backing_len: usize,
    original: Option<Arc<[Value]>>,
    values: Vec<Value>,
}
#[cfg(feature = "std")]
enum Prepared {
    Empty,
    Writes { groups: Vec<Group> },
}

/// Allocation-free commit failure. Convert to TemplateError only after the
/// host has released its own receiver locks; conversion creates a small string.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValuesCommitError {
    AlreadyAttempted,
    GuardAllocation,
    Poisoned,
    VersionChanged,
}
impl ValuesCommitError {
    pub const fn message(self) -> &'static str {
        match self {
            Self::AlreadyAttempted => "atomic Values ticket already attempted",
            Self::GuardAllocation => "atomic Values guard allocation failed",
            Self::Poisoned => "Values backing lock poisoned",
            Self::VersionChanged => "Values backing version changed",
        }
    }
}
impl core::fmt::Display for ValuesCommitError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.message())
    }
}
impl core::error::Error for ValuesCommitError {}
impl From<ValuesCommitError> for TemplateError {
    fn from(error: ValuesCommitError) -> Self {
        TemplateError::Exec(error.message().into())
    }
}

/// A one-use ticket containing fully allocated replacement snapshots.
///
/// The only allocation in commit is a bounded guard Vec, reserved once before
/// taking any lock; its conservative capacity was prepaid during preparation.
/// This safe-Rust exception avoids manufacturing guard lifetimes. Lock, version
/// validation, and the entire swap sequence allocate nothing and call no host
/// callback. All old values remain retained until every guard is unlocked.
#[cfg(feature = "std")]
pub struct PreparedValuesWrites {
    attempted: bool,
    prepared: Prepared,
}
#[cfg(not(feature = "std"))]
pub struct PreparedValuesWrites {
    attempted: bool,
}

impl TypedSlice {
    /// Read-only identity of the real Values backing and this view's span.
    /// nil and byte backings return None; no synthetic nil identity is exposed.
    /// An identity is an opaque comparison token, never a dereferenceable API.
    pub fn values_span(&self) -> Option<(usize, usize, usize, usize)> {
        match self.storage.as_ref()? {
            #[cfg(feature = "std")]
            SliceData::Values(cell) => {
                Some((Arc::as_ptr(cell) as usize, self.start, self.len, self.cap))
            }
            #[cfg(not(feature = "std"))]
            SliceData::Values(data) => Some((
                Arc::as_ptr(data) as *const Value as usize,
                self.start,
                self.len,
                self.cap,
            )),
            SliceData::Bytes(_) => None,
        }
    }

    /// Prepare at most 256 writes and 1,048,576 supplied values.
    /// Both mutation APIs accept only edge-free scalars; graph-bearing Slice,
    /// Object, List, Map and Function values, and named dyn-method descriptors,
    /// are rejected even in a truncated tail. Composite copy needs graph-aware
    /// retirement and is deliberately not exposed by these entry points. Overlapping
    /// writes to one cell are applied in input order, with later writes winning.
    /// Each view's gate is checked outside all backing locks; metadata is paid
    /// by the first effective write and each backing by its first effective
    /// view. Hosts must bind those gates to the intended common budget account.
    ///
    /// Since preparation always creates replacements, a nonempty effective
    /// write requires a host budget even when its current Arc is exclusive.
    /// A rejected preparation never modifies any cell. Without std only an
    /// empty write list is accepted; all nonempty lists explicitly fail.
    #[cfg(feature = "std")]
    pub fn prepare_values_writes(writes: &[ValuesWrite<'_>]) -> Result<PreparedValuesWrites> {
        if writes.is_empty() {
            return Ok(PreparedValuesWrites {
                attempted: false,
                prepared: Prepared::Empty,
            });
        }
        if writes.len() > MAX_WRITES {
            return Err(error("atomic Values write count exceeds limit"));
        }
        let mut total = 0usize;
        let mut first_effective = None;
        // Only borrowed metadata and short, read-only locks in this pass.
        for (index, write) in writes.iter().enumerate() {
            let slice = write.slice;
            if write.offset > slice.len {
                return Err(error("slice index out of range"));
            }
            total = total
                .checked_add(write.values.len())
                .ok_or_else(|| error("atomic Values input count overflow"))?;
            if total > MAX_INPUT_VALUES {
                return Err(error("atomic Values input count exceeds limit"));
            }
            let elem = slice
                .named
                .map(|kind| kind.element)
                .or_else(|| slice.go_type.strip_prefix("[]"))
                .ok_or_else(|| error("invalid Values slice type"))?;
            if elem == "uint8" || elem == "byte" {
                return Err(error("atomic writes require Values backing"));
            }
            if let Some(gate) = &slice.host_budget {
                gate(0)?;
            }
            for chunk in write.values.chunks(256) {
                if let Some(gate) = &slice.host_budget {
                    gate(0)?;
                }
                if chunk.iter().any(|value| !canonical_elem_ok(value, elem)) {
                    return Err(error("slice element type mismatch"));
                }
                if chunk
                    .iter()
                    .any(|value| !values_payload_has_no_edges(value))
                {
                    return Err(error(
                        "Values mutation accepts edge-free scalar payloads only",
                    ));
                }
            }
            let n = write.values.len().min(slice.len - write.offset);
            match &slice.storage {
                Some(SliceData::Values(cell)) => {
                    let current = cell
                        .lock()
                        .map_err(|_| error("Values backing lock poisoned"))?;
                    let end = slice
                        .start
                        .checked_add(slice.cap)
                        .ok_or_else(|| error("slice span overflow"))?;
                    if end > current.len() || slice.len > slice.cap {
                        return Err(error("invalid Values slice span"));
                    }
                }
                None if slice.len == 0 && slice.cap == 0 && slice.start == 0 => {}
                _ => return Err(error("atomic writes require Values backing")),
            }
            if n != 0 && first_effective.is_none() {
                first_effective = Some(index);
            }
        }
        let Some(first) = first_effective else {
            return Ok(PreparedValuesWrites {
                attempted: false,
                prepared: Prepared::Empty,
            });
        };
        let unit = core::mem::size_of::<Stage>()
            .checked_add(core::mem::size_of::<Group>())
            .and_then(|n| {
                n.checked_add(core::mem::size_of::<std::sync::MutexGuard<'_, Arc<[Value]>>>())
            })
            .and_then(|n| n.checked_add(32))
            .ok_or_else(|| error("atomic Values metadata size overflow"))?;
        let metadata = unit
            .checked_mul(writes.len())
            .and_then(|n| n.checked_mul(2))
            .and_then(|n| n.checked_add(2048))
            .ok_or_else(|| error("atomic Values metadata size overflow"))?;
        writes[first].slice.reserve_host_bytes(metadata)?;
        let mut stages: Vec<Stage> = Vec::new();
        stages
            .try_reserve_exact(writes.len())
            .map_err(|_| error("atomic Values stage allocation failed"))?;
        for (index, write) in writes.iter().enumerate() {
            if write.values.len().min(write.slice.len - write.offset) == 0 {
                continue;
            }
            let Some(SliceData::Values(cell)) = &write.slice.storage else {
                return Err(error("missing effective Values backing"));
            };
            if stages.iter().any(|group| Arc::ptr_eq(&group.cell, cell)) {
                continue;
            }
            let backing_len = cell
                .lock()
                .map_err(|_| error("Values backing lock poisoned"))?
                .len();
            stages.push(Stage {
                cell: cell.clone(),
                first: index,
                backing_len,
                original: None,
                values: Vec::new(),
            });
        }
        // Admit every backing before copying any. Conversion Vec -> Arc may
        // temporarily retain both buffers, so pay two full capacities + header.
        for group in &stages {
            let peak = group
                .backing_len
                .checked_mul(core::mem::size_of::<Value>())
                .and_then(|n| n.checked_add(128))
                .and_then(|n| n.checked_mul(2))
                .ok_or_else(|| error("atomic Values COW size overflow"))?;
            writes[group.first].slice.reserve_host_bytes(peak)?;
        }
        for group in &mut stages {
            let original = group
                .cell
                .lock()
                .map_err(|_| error("Values backing lock poisoned"))?
                .clone();
            if original.len() != group.backing_len {
                return Err(error("Values backing length changed"));
            }
            group
                .values
                .try_reserve_exact(group.backing_len)
                .map_err(|_| error("atomic Values COW allocation failed"))?;
            for chunk in original.chunks(256) {
                writes[group.first].slice.reserve_host_bytes(0)?;
                group.values.extend_from_slice(chunk);
            }
            group.original = Some(original);
        }
        for write in writes {
            let n = write.values.len().min(write.slice.len - write.offset);
            if n == 0 {
                continue;
            }
            let Some(SliceData::Values(cell)) = &write.slice.storage else {
                return Err(error("missing Values backing"));
            };
            let group = stages
                .iter_mut()
                .find(|group| Arc::ptr_eq(&group.cell, cell))
                .ok_or_else(|| error("missing prepared Values group"))?;
            let start = write
                .slice
                .start
                .checked_add(write.offset)
                .ok_or_else(|| error("slice span overflow"))?;
            let end = start
                .checked_add(n)
                .filter(|end| *end <= group.backing_len)
                .ok_or_else(|| error("invalid Values write span"))?;
            for (target, input) in group.values[start..end]
                .chunks_mut(256)
                .zip(write.values[..n].chunks(256))
            {
                write.slice.reserve_host_bytes(0)?;
                target.clone_from_slice(input);
            }
        }
        let mut groups = Vec::new();
        groups
            .try_reserve_exact(stages.len())
            .map_err(|_| error("atomic Values group allocation failed"))?;
        for stage in stages {
            groups.push(Group {
                cell: stage.cell,
                original: stage
                    .original
                    .ok_or_else(|| error("missing Values version"))?,
                replacement: stage.values.into(),
            });
        }
        groups.sort_unstable_by_key(|group| Arc::as_ptr(&group.cell) as usize);
        Ok(PreparedValuesWrites {
            attempted: false,
            prepared: Prepared::Writes { groups },
        })
    }

    #[cfg(not(feature = "std"))]
    pub fn prepare_values_writes(writes: &[ValuesWrite<'_>]) -> Result<PreparedValuesWrites> {
        if writes.is_empty() {
            Ok(PreparedValuesWrites { attempted: false })
        } else {
            Err(error("atomic Values writes unavailable without std"))
        }
    }
}

impl PreparedValuesWrites {
    /// Attempt a prepaid snapshot exactly once, retaining every snapshot in
    /// this ticket on either result. A changed version or poisoned cell rejects
    /// all writes. The host revalidates owners/cancellation before taking its
    /// receiver locks, updates metadata only on success, releases all those
    /// locks, and then drops this ticket. No Value destructor runs in commit.
    #[cfg(feature = "std")]
    pub fn try_commit(&mut self) -> core::result::Result<(), ValuesCommitError> {
        if self.attempted {
            return Err(ValuesCommitError::AlreadyAttempted);
        }
        self.attempted = true;
        let Prepared::Writes { groups } = &self.prepared else {
            return Ok(());
        };
        // Safe-Rust lifetime scratch exception: reserve before acquiring locks.
        let mut guards = Vec::new();
        if guards.try_reserve_exact(groups.len()).is_err() {
            return Err(ValuesCommitError::GuardAllocation);
        }
        for group in groups {
            let guard = match group.cell.lock() {
                Ok(guard) => guard,
                Err(_) => return Err(ValuesCommitError::Poisoned),
            };
            guards.push(guard);
        }
        for (guard, group) in guards.iter().zip(groups) {
            if !Arc::ptr_eq(guard, &group.original) {
                return Err(ValuesCommitError::VersionChanged);
            }
        }
        for (guard, group) in guards.iter_mut().zip(groups) {
            **guard = group.replacement.clone();
        }
        drop(guards);
        Ok(())
    }
    #[cfg(not(feature = "std"))]
    pub fn try_commit(&mut self) -> core::result::Result<(), ValuesCommitError> {
        if self.attempted {
            Err(ValuesCommitError::AlreadyAttempted)
        } else {
            self.attempted = true;
            Ok(())
        }
    }
}
