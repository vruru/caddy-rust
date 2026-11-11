// Copyright (c) 2016-2022 Uber Technologies, Inc.
// SPDX-License-Identifier: MIT
//! Fixed zap v1.28.0 bucket sampling, with Caddy's zero-value defaults.
use super::{config::Sampling, level::Level, types::Timestamp};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
const BUCKETS: usize = 4096;
const LEVELS: usize = 7;
struct Counter {
    reset_at: AtomicI64,
    count: AtomicU64,
}
pub(super) struct Sampler {
    interval: i64,
    first: u64,
    thereafter: u64,
    counters: Box<[Counter]>,
}
impl Sampler {
    pub(super) const fn allocation_bytes() -> usize {
        BUCKETS * LEVELS * std::mem::size_of::<Counter>()
    }
    /// The caller reserves allocation_bytes() from its preparation budget first.
    pub(super) fn new(config: Sampling) -> Self {
        let interval = if config.interval == 0 {
            1_000_000_000
        } else {
            config.interval
        };
        let first = if config.first == 0 { 100 } else { config.first } as u64;
        let thereafter = if config.thereafter == 0 {
            100
        } else {
            config.thereafter
        } as u64;
        // Allocate directly on the heap, not a large array on a reactor stack.
        let counters = (0..BUCKETS * LEVELS)
            .map(|_| Counter {
                reset_at: AtomicI64::new(0),
                count: AtomicU64::new(0),
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Self {
            interval,
            first,
            thereafter,
            counters,
        }
    }
    pub(super) fn keep(&self, level: Level, message: &str, time: Timestamp) -> bool {
        let index =
            (level as i8 + 1) as usize * BUCKETS + (fnv32a(message.as_bytes()) as usize % BUCKETS);
        let counter = &self.counters[index];
        let now = time
            .seconds
            .wrapping_mul(1_000_000_000)
            .wrapping_add(i64::from(time.nanosecond));
        let reset = counter.reset_at.load(Ordering::SeqCst);
        let count = if reset > now {
            counter.count.fetch_add(1, Ordering::SeqCst).wrapping_add(1)
        } else {
            counter.count.store(1, Ordering::SeqCst);
            if counter
                .reset_at
                .compare_exchange(
                    reset,
                    now.wrapping_add(self.interval),
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                )
                .is_ok()
            {
                1
            } else {
                counter.count.fetch_add(1, Ordering::SeqCst).wrapping_add(1)
            }
        };
        count <= self.first
            || (self.thereafter != 0
                && count
                    .wrapping_sub(self.first)
                    .is_multiple_of(self.thereafter))
    }
}
fn fnv32a(bytes: &[u8]) -> u32 {
    let mut hash = 2_166_136_261u32;
    for b in bytes {
        hash ^= u32::from(*b);
        hash = hash.wrapping_mul(16_777_619);
    }
    hash
}
