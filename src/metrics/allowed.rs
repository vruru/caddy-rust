//! The optional configured-host index has independent real metadata credits.
//! Failure to index a configured host never admits arbitrary request hostnames.
use std::{
    collections::BTreeSet,
    sync::{Arc, atomic::Ordering},
};
use tokio::sync::OwnedSemaphorePermit;
#[derive(Default)]
pub(crate) struct Inputs {
    values: Vec<(String, OwnedSemaphorePermit)>,
    buffer: Option<super::budget::Lease>,
}
#[derive(Default)]
pub(crate) struct Allowed {
    values: BTreeSet<String>,
    _credits: Vec<OwnedSemaphorePermit>,
    _buffer: Option<super::budget::Lease>,
}
impl Inputs {
    pub(crate) fn push(&mut self, host: &str, process: &Arc<super::Process>) {
        let credit = host
            .len()
            .checked_mul(8)
            .and_then(|n| n.checked_add(1024))
            .and_then(|n| u32::try_from(n).ok())
            .and_then(|n| process.pay_labels(n));
        let Some(credit) = credit else {
            process.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        };
        let paid = if let Some(buffer) = &self.buffer {
            buffer.grow(128)
        } else {
            self.buffer = super::budget::Lease::new(process.labels.clone(), 256);
            self.buffer.is_some()
        };
        if !paid {
            process.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if self.values.try_reserve(1).is_err() {
            process.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        self.values.push((host.to_owned(), credit));
    }
    pub(crate) fn build(self, process: &Arc<super::Process>) -> Allowed {
        let Self { values, buffer } = self;
        let mut out = Allowed {
            _buffer: buffer,
            ..Default::default()
        };
        for (input, credit) in values {
            let host = input.to_lowercase();
            if out.values.contains(&host) {
                continue;
            }
            if out.values.len() >= super::SERIES_LIMIT {
                process.dropped.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            out.values.insert(host);
            out._credits.push(credit);
        }
        out
    }
}
impl Allowed {
    pub(super) fn contains(&self, host: &str) -> bool {
        self.values.contains(host)
    }
}
