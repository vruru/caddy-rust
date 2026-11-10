//! Diagnostics for the opt-in bounded HTTP/1 trailer compatibility encoder.
use std::sync::atomic::{AtomicU64, Ordering};
static FILTERED: AtomicU64 = AtomicU64::new(0);
static OVERSIZED: AtomicU64 = AtomicU64::new(0);
static INVALID: AtomicU64 = AtomicU64::new(0);
static UNDELIVERABLE: AtomicU64 = AtomicU64::new(0);
/// Process-wide monotonic counters; no header names or values are retained.
#[derive(Clone, Copy, Debug)]
pub struct Snapshot {
    /// Forbidden field values excluded from the wire.
    pub filtered: u64,
    /// Trailer blocks exceeding the bounded encoder budget.
    pub oversized: u64,
    /// Blocks rejected for invalid wire characters.
    pub invalid: u64,
    /// Trailer blocks incompatible with fixed-length or close-delimited framing.
    pub undeliverable: u64,
}
/// Reads diagnostic counters without resetting concurrent producers.
pub fn snapshot() -> Snapshot {
    Snapshot {filtered: FILTERED.load(Ordering::Relaxed), oversized: OVERSIZED.load(Ordering::Relaxed), invalid: INVALID.load(Ordering::Relaxed), undeliverable: UNDELIVERABLE.load(Ordering::Relaxed)}
}
pub(crate) fn filtered() { FILTERED.fetch_add(1, Ordering::Relaxed); }
pub(crate) fn oversized() { OVERSIZED.fetch_add(1, Ordering::Relaxed); }
pub(crate) fn invalid() { INVALID.fetch_add(1, Ordering::Relaxed); }
pub(crate) fn undeliverable() { UNDELIVERABLE.fetch_add(1, Ordering::Relaxed); }
