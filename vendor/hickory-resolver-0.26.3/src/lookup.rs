// Copyright 2015-2023 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Lookup result from a resolution of ipv4 and ipv6 records with a Resolver.

use std::{
    cmp::min,
    time::{Duration, Instant},
};

use crate::{
    cache::MAX_TTL,
    proto::{
        op::{Message, OpCode, Query},
        rr::{RData, Record},
    },
};

/// Result of a DNS query when querying for any record type supported by the Hickory DNS Proto library.
///
/// For IP resolution see LookupIp, as it has more features for A and AAAA lookups.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Lookup {
    message: Message,
    valid_until: Instant,
}

impl Lookup {
    /// Create a new Lookup from a complete DNS Message.
    pub(crate) fn new(message: Message, valid_until: Instant) -> Self {
        debug_assert!(
            !message.queries.is_empty(),
            "lookup message must have at least one query"
        );

        Self {
            message,
            valid_until,
        }
    }

    /// Return new instance with given rdata and the maximum TTL.
    pub fn from_rdata(query: Query, rdata: RData) -> Self {
        let record = Record::from_rdata(query.name().clone(), MAX_TTL, rdata);
        Self::new_with_max_ttl(query, [record])
    }

    /// Return new instance with given records and the maximum TTL.
    pub fn new_with_max_ttl(query: Query, answers: impl IntoIterator<Item = Record>) -> Self {
        let valid_until = Instant::now() + Duration::from_secs(u64::from(MAX_TTL));
        Self::new_with_deadline(query, answers, valid_until)
    }

    /// Return a new instance with the given records and deadline.
    pub fn new_with_deadline(
        query: Query,
        answers: impl IntoIterator<Item = Record>,
        valid_until: Instant,
    ) -> Self {
        let mut message = Message::response(0, OpCode::Query);
        message.add_query(query.clone());
        message.add_answers(answers);

        Self {
            message,
            valid_until,
        }
    }

    /// Returns a reference to the `Query` that was used to produce this result.
    pub fn query(&self) -> &Query {
        self.message
            .queries
            .first()
            .expect("Lookup message always has a query")
    }

    /// Returns a reference to the underlying DNS Message.
    pub fn message(&self) -> &Message {
        &self.message
    }

    /// Returns a reference to the answer records from the message.
    pub fn answers(&self) -> &[Record] {
        &self.message.answers
    }

    /// Returns a reference to the authority records from the message.
    pub fn authorities(&self) -> &[Record] {
        &self.message.authorities
    }

    /// Returns a reference to the additional records from the message.
    pub fn additionals(&self) -> &[Record] {
        &self.message.additionals
    }

    /// Returns the `Instant` at which this `Lookup` is no longer valid.
    pub fn valid_until(&self) -> Instant {
        self.valid_until
    }

    /// Combine two lookup results, preserving section structure
    ///
    /// Appends records from each section of `other` to the corresponding section of `self`.
    pub(crate) fn append(&self, other: Self) -> Self {
        // Clone self to get a mutable copy
        let mut result = self.clone();

        // Append each section separately to preserve structure
        result.message.add_answers(other.answers().iter().cloned());
        result
            .message
            .add_authorities(other.authorities().iter().cloned());
        result
            .message
            .add_additionals(other.additionals().iter().cloned());

        // Choose the sooner deadline of the two lookups
        result.valid_until = min(self.valid_until(), other.valid_until());
        result
    }

    #[doc(hidden)] // For use in server tests
    pub fn extend_authorities(&mut self, records: impl IntoIterator<Item = Record>) {
        self.message.add_authorities(records);
    }

    #[doc(hidden)] // For use in server tests
    pub fn extend_additionals(&mut self, records: impl IntoIterator<Item = Record>) {
        self.message.add_additionals(records);
    }


}

impl From<Lookup> for Message {
    fn from(lookup: Lookup) -> Self {
        lookup.message
    }
}
