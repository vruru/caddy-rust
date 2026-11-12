//! Opt-in exact encoded-wire intervals; notifications occur only after real
//! underlying flush and outside h2 stream/store locks.
use crate::data_receipt::DataFragmentOwner;
use std::{collections::VecDeque, io, time::Instant};
pub(crate) const CAP: usize = 256;
#[derive(Debug)]
pub(crate) struct Span {
    start: u128,
    end: u128,
    payload_start: usize,
    payload_len: usize,
    open_header: bool,
    owner: DataFragmentOwner,
}
#[derive(Debug)]
pub(crate) struct WireProgress {
    encoded: u128,
    accepted: u128,
    confirmed: u128,
    pub(crate) needs_flush: bool,
    spans: VecDeque<Span>,
}
fn overflow() -> io::Error {
    io::Error::other("HTTP/2 observed wire position exhausted")
}
impl WireProgress {
    pub(crate) fn new(initial_unwritten: usize) -> Self {
        Self {
            encoded: initial_unwritten as u128,
            accepted: 0,
            confirmed: 0,
            needs_flush: false,
            spans: VecDeque::with_capacity(CAP),
        }
    }
    pub(crate) fn len(&self) -> usize {
        self.spans.len()
    }
    pub(crate) fn buffered(
        &mut self,
        n: usize,
        owner: Option<DataFragmentOwner>,
        payload: Option<usize>,
        open_header: bool,
    ) -> Result<(), crate::codec::UserError> {
        let start = self.encoded;
        self.encoded = self
            .encoded
            .checked_add(n as u128)
            .ok_or(crate::codec::UserError::Rejected)?;
        if let Some(owner) = owner {
            if self.spans.len() == CAP {
                return Err(crate::codec::UserError::Rejected);
            }
            let (payload_start, payload_len) = payload.map_or((0, 0), |n| (9, n));
            assert!(payload_start + payload_len <= n);
            self.spans.push_back(Span {
                start,
                end: self.encoded,
                payload_start,
                payload_len,
                open_header,
                owner,
            });
        }
        Ok(())
    }
    pub(crate) fn continuation(&mut self, n: usize, still_open: bool) -> io::Result<()> {
        self.encoded = self.encoded.checked_add(n as u128).ok_or_else(overflow)?;
        if let Some(span) = self.spans.back_mut() {
            if span.open_header {
                span.end = self.encoded;
                span.open_header = still_open;
            }
        }
        Ok(())
    }
    pub(crate) fn wrote(&mut self, n: usize) -> io::Result<()> {
        self.accepted = self
            .accepted
            .checked_add(n as u128)
            .filter(|n| *n <= self.encoded)
            .ok_or_else(overflow)?;
        self.needs_flush = true;
        Ok(())
    }
    pub(crate) fn flushed(&mut self, at: Instant) {
        let from = self.confirmed;
        let to = self.accepted;
        loop {
            let Some(span) = self.spans.front() else {
                break;
            };
            if span.start >= to {
                break;
            }
            let begin = from.max(span.start);
            let end = to.min(span.end);
            let pbegin = span.start + span.payload_start as u128;
            let pend = pbegin + span.payload_len as u128;
            let bytes = usize::try_from(end.min(pend).saturating_sub(begin.max(pbegin)))
                .expect("bounded frame payload");
            if !span.open_header && span.end <= to {
                let span = self.spans.pop_front().unwrap();
                span.owner.finish_wire(bytes, at);
            } else {
                if begin < end {
                    self.spans.front_mut().unwrap().owner.progress(bytes, at);
                }
                break;
            }
        }
        self.confirmed = to;
        self.needs_flush = false;
    }
}
