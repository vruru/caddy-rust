// Copyright 2015-2023 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Caching related functionality for the Resolver.

use std::{
    borrow::Cow,
    future::Future,
    time::{Duration, Instant},
};

use once_cell::sync::Lazy;

#[cfg(feature = "__dnssec")]
use crate::proto::dnssec::{DnssecSummary, Proof};
use crate::{
    cache::{MAX_TTL, ResponseCache, TtlConfig},
    lookup::Lookup,
    net::{
        DnsError, NetError, NoRecords,
        xfer::{DnsHandle, FirstAnswer},
    },
    proto::{
        op::{DnsRequestOptions, DnsResponse, Message, OpCode, Query, ResponseCode},
        rr::{
            DNSClass, Name, RData, Record, RecordRef, RecordType,
            domain::usage::{
                DEFAULT, IN_ADDR_ARPA_127, INVALID, IP6_ARPA_1, LOCAL,
                LOCALHOST as LOCALHOST_usage, ONION, ResolverUsage,
            },
            rdata::{A, AAAA, CNAME, PTR},
        },
    },
};

static LOCALHOST: Lazy<RData> =
    Lazy::new(|| RData::PTR(PTR(Name::from_ascii("localhost.").unwrap())));
static LOCALHOST_V4: Lazy<RData> = Lazy::new(|| RData::A(A::new(127, 0, 0, 1)));
static LOCALHOST_V6: Lazy<RData> = Lazy::new(|| RData::AAAA(AAAA::new(0, 0, 0, 0, 0, 0, 0, 1)));

/// Counts the depth of CNAME query resolutions.
#[derive(Default, Clone, Copy)]
struct DepthTracker {
    query_depth: u8,
}

impl DepthTracker {
    fn nest(self) -> Self {
        Self {
            query_depth: self.query_depth + 1,
        }
    }

    fn is_exhausted(self) -> bool {
        self.query_depth + 1 >= Self::MAX_QUERY_DEPTH
    }

    const MAX_QUERY_DEPTH: u8 = 8; // arbitrarily chosen number...
}

#[derive(Clone, Debug)]
#[doc(hidden)]
pub struct CachingClient<C>
where
    C: DnsHandle,
{
    cache: ResponseCache,
    client: C,
    preserve_intermediates: bool,
    allow_special_use_queries: bool,
    #[cfg(feature = "metrics")]
    cache_metrics: crate::metrics::CacheMetrics,
}

impl<C> CachingClient<C>
where
    C: DnsHandle + Send + 'static,
{
    #[doc(hidden)]
    pub fn new(max_size: u64, client: C, preserve_intermediates: bool) -> Self {
        Self::with_cache(
            ResponseCache::new(max_size, TtlConfig::default()),
            client,
            preserve_intermediates,
        )
    }

    pub(crate) fn with_cache(
        cache: ResponseCache,
        client: C,
        preserve_intermediates: bool,
    ) -> Self {
        Self {
            cache,
            client,
            preserve_intermediates,
            allow_special_use_queries: false,
            #[cfg(feature = "metrics")]
            cache_metrics: crate::metrics::CacheMetrics::default(),
        }
    }

    pub(crate) fn with_special_use_queries(mut self, allow: bool) -> Self {
        self.allow_special_use_queries = allow;
        self
    }

    /// Perform a lookup against this caching client, looking first in the cache for a result
    pub fn lookup(
        &self,
        query: Query,
        options: DnsRequestOptions,
    ) -> impl Future<Output = Result<Lookup, NetError>> {
        Self::inner_lookup(
            query,
            options,
            self.clone(),
            vec![],
            DepthTracker::default(),
        )
    }

    async fn inner_lookup(
        query: Query,
        options: DnsRequestOptions,
        mut client: Self,
        preserved_records: Vec<Record>,
        depth: DepthTracker,
    ) -> Result<Lookup, NetError> {
        // see https://tools.ietf.org/html/rfc6761
        //
        // ```text
        // Name resolution APIs and libraries SHOULD recognize localhost
        // names as special and SHOULD always return the IP loopback address
        // for address queries and negative responses for all other query
        // types.  Name resolution APIs SHOULD NOT send queries for
        // localhost names to their configured caching DNS server(s).
        // ```
        // special use rules only apply to the IN Class
        if !client.allow_special_use_queries && query.query_class() == DNSClass::IN {
            let usage = match query.name() {
                n if LOCALHOST_usage.zone_of(n) => &*LOCALHOST_usage,
                n if IN_ADDR_ARPA_127.zone_of(n) => &*LOCALHOST_usage,
                n if IP6_ARPA_1.zone_of(n) => &*LOCALHOST_usage,
                n if INVALID.zone_of(n) => &*INVALID,
                n if LOCAL.zone_of(n) => &*LOCAL,
                n if ONION.zone_of(n) => &*ONION,
                _ => &*DEFAULT,
            };

            match usage.resolver() {
                ResolverUsage::Loopback => match query.query_type() {
                    // TODO: look in hosts for these ips/names first...
                    RecordType::A => return Ok(Lookup::from_rdata(query, LOCALHOST_V4.clone())),
                    RecordType::AAAA => return Ok(Lookup::from_rdata(query, LOCALHOST_V6.clone())),
                    RecordType::PTR => return Ok(Lookup::from_rdata(query, LOCALHOST.clone())),
                    // Are there any other types we can use?
                    _ => return Err(NoRecords::new(query, ResponseCode::NoError).into()),
                },
                // TODO: this requires additional config, as Kubernetes and other systems misuse the .local. zone.
                // when mdns is not enabled we will return errors on LinkLocal ("*.local.") names
                ResolverUsage::LinkLocal => (),
                ResolverUsage::NxDomain => {
                    return Err(NoRecords::new(query, ResponseCode::NXDomain).into());
                }
                ResolverUsage::Normal => (),
            }
        }

        let is_dnssec = client.client.is_verifying_dnssec();

        #[cfg(feature = "metrics")]
        let request_start = Instant::now();

        if let Some(cached_lookup) = client.lookup_from_cache(&query) {
            #[cfg(feature = "metrics")]
            {
                client.cache_metrics.cache_hit.increment(1);
                client
                    .cache_metrics
                    .cache_hit_duration
                    .record(request_start.elapsed());
                client
                    .cache_metrics
                    .cache_size
                    .set(client.cache.entry_count() as f64);
            }
            return cached_lookup;
        };

        #[cfg(feature = "metrics")]
        client.cache_metrics.cache_miss.increment(1);

        let response_message = client
            .client
            .lookup(query.clone(), options)
            .first_answer()
            .await;

        // TODO: technically this might be duplicating work, as name_server already performs this evaluation.
        //  we may want to create a new type, if evaluated... but this is most generic to support any impl in LookupState...
        let response_message = if let Ok(response) = response_message {
            DnsError::from_response(response).map_err(NetError::from)
        } else {
            response_message
        };

        // TODO: This doesn't yet take into account the CD flag. There is not yet a way to pass it
        // from the ForwarderZoneHandler, through the Resolver public API, to here.
        #[cfg(feature = "__dnssec")]
        if is_dnssec {
            let summary_opt = match &response_message {
                Ok(response) => Some(DnssecSummary::from_records(response.answers.iter())),
                Err(NetError::Dns(DnsError::Nsec {
                    response, proof, ..
                })) => Some(if *proof == Proof::Bogus {
                    DnssecSummary::Bogus
                } else {
                    DnssecSummary::from_records(response.authorities.iter())
                }),
                _ => None,
            };
            if let Some(DnssecSummary::Bogus) = summary_opt {
                #[cfg(feature = "metrics")]
                client
                    .cache_metrics
                    .cache_miss_duration
                    .record(request_start.elapsed());
                return Err(NetError::Dns(DnsError::DnssecBogus));
            }
        }

        // TODO: take all records and cache them?
        //  if it's DNSSEC they must be signed, otherwise?
        let records = match response_message {
            Ok(response_message) => {
                // allow the handle_noerror function to deal with any error codes
                let records = match Self::handle_noerror(
                    &mut client,
                    options,
                    &query,
                    response_message,
                    preserved_records,
                    depth,
                ) {
                    Ok(records) => records,
                    Err(err) => {
                        #[cfg(feature = "metrics")]
                        client
                            .cache_metrics
                            .cache_miss_duration
                            .record(request_start.elapsed());
                        return Err(err);
                    }
                };

                Ok(records)
            }
            // this is the only cacheable form
            Err(NetError::Dns(DnsError::NoRecordsFound(mut no_records))) => {
                if is_dnssec {
                    no_records.negative_ttl = None;
                }
                Err(no_records.into())
            }
            Err(err) => {
                #[cfg(feature = "metrics")]
                client
                    .cache_metrics
                    .cache_miss_duration
                    .record(request_start.elapsed());
                return Err(err);
            }
        };

        // after the request, evaluate if we have additional queries to perform
        let result = match records {
            Ok(Records::CnameChain { next: future, .. }) => match future.await {
                Ok(lookup) => client.cname(lookup, query),
                Err(e) => client.cache(query, Err(e)),
            },
            Ok(Records::Exists { message }) => client.cache(query, Ok(message)),
            Err(e) => client.cache(query, Err(e)),
        };

        #[cfg(feature = "metrics")]
        client
            .cache_metrics
            .cache_miss_duration
            .record(request_start.elapsed());

        result
    }

    /// Check if this query is already cached
    fn lookup_from_cache(&self, query: &Query) -> Option<Result<Lookup, NetError>> {
        let now = Instant::now();
        let message_res = self.cache.get(query, now)?;
        let message = match message_res {
            Ok(message) => message,
            Err(err) => return Some(Err(err)),
        };

        let valid_until = now
            + Duration::from_secs(
                message
                    .answers
                    .iter()
                    .map(|r| r.ttl)
                    .min()
                    .unwrap_or(MAX_TTL)
                    .into(),
            );

        Some(Ok(Lookup::new(message, valid_until)))
    }

    /// Handle the case where there is no error returned
    fn handle_noerror(
        client: &mut Self,
        options: DnsRequestOptions,
        query: &Query,
        response: DnsResponse,
        mut preserved_records: Vec<Record>,
        depth: DepthTracker,
    ) -> Result<Records<impl Future<Output = Result<Lookup, NetError>>>, NetError> {
        // TODO: there should be a ResolverOpts config to disable the
        // name validation in this function to more closely match the
        // behaviour of glibc if that's what the user expects.

        // initial ttl is what CNAMES use for min usage
        const INITIAL_TTL: u32 = MAX_TTL;

        // need to capture these before the subsequent and destructive record processing
        let soa = response.soa().as_ref().map(RecordRef::to_owned);
        let negative_ttl = response.negative_ttl();
        let response_code = response.response_code;

        // seek out CNAMES, this is only performed if the query is not a CNAME, ANY, or SRV
        // FIXME: for SRV this evaluation is inadequate. CNAME is a single chain to a single record
        //   for SRV, there could be many different targets. The search_name needs to be enhanced to
        //   be a list of names found for SRV records.
        let (search_name, was_cname, preserved_records) = {
            // this will only search for CNAMEs if the request was not meant to be for one of the triggers for recursion
            let (search_name, cname_ttl, was_cname) =
                if query.query_type().is_any() || query.query_type().is_cname() {
                    (Cow::Borrowed(query.name()), INITIAL_TTL, false)
                } else {
                    // Folds any cnames from the answers section, into the final cname in the answers section
                    //   this works by folding the last CNAME found into the final folded result.
                    //   it assumes that the CNAMEs are in chained order in the DnsResponse Message...
                    // For SRV, the name added for the search becomes the target name.
                    //
                    // TODO: should this include the additionals?
                    response.answers.iter().fold(
                        (Cow::Borrowed(query.name()), INITIAL_TTL, false),
                        |(search_name, cname_ttl, was_cname), r| {
                            match &r.data {
                                RData::CNAME(CNAME(cname)) => {
                                    // take the minimum TTL of the cname_ttl and the next record in the chain
                                    let ttl = cname_ttl.min(r.ttl);
                                    debug_assert_eq!(r.record_type(), RecordType::CNAME);
                                    if search_name.as_ref() == &r.name {
                                        return (Cow::Owned(cname.clone()), ttl, true);
                                    }
                                }
                                RData::SRV(srv) => {
                                    // take the minimum TTL of the cname_ttl and the next record in the chain
                                    let ttl = cname_ttl.min(r.ttl);
                                    debug_assert_eq!(r.record_type(), RecordType::SRV);

                                    // the search name becomes the srv.target
                                    return (Cow::Owned(srv.target.clone()), ttl, true);
                                }
                                _ => (),
                            }

                            (search_name, cname_ttl, was_cname)
                        },
                    )
                };

            // take all answers. // TODO: following CNAMES?
            let mut message = response.into_message();

            // set of names that still require resolution
            // TODO: this needs to be enhanced for SRV
            let mut found_name = false;
            let mut found_cname_target = false;
            // Scan through all sections to determine what we found.
            // We need this first pass to decide our strategy: return complete message vs filter
            for r in message.all_sections() {
                // restrict to the RData type requested
                if query.query_class() != r.dns_class {
                    continue;
                }

                // standard evaluation, it's an any type, or it's the requested type and the
                // search_name matches
                let type_matches =
                    query.query_type().is_any() || query.query_type() == r.record_type();
                let name_matches = search_name.as_ref() == &r.name || query.name() == &r.name;
                if type_matches && name_matches {
                    found_name = true;
                    // Track if we found the CNAME target (not just the original name)
                    if was_cname && search_name.as_ref() == &r.name {
                        found_cname_target = true;
                    }
                }
            }

            // After following all the CNAMES to the last one, try and lookup the final name
            if found_name && (!was_cname || preserved_records.is_empty()) {
                // Decide strategy: do we need to filter, or return the message as-is?
                // - If we have accumulated records from previous CNAME hops → must filter and merge
                // - If we found the CNAME target in this response → filter out intermediate CNAMEs
                //   (unless preserve_intermediates)
                // - Otherwise → return complete message to preserve all sections exactly as DNS server
                //   sent them
                let needs_filtering = !preserved_records.is_empty()
                    || (found_cname_target && !client.preserve_intermediates);

                if needs_filtering {
                    // Filter records that belong in ANSWER section only
                    // Don't include records from ADDITIONAL/AUTHORITY here - they're preserved as-is below
                    preserved_records.extend(message.all_sections().filter_map(|r| {
                        // because this resolved potentially recursively, we want the min TTL from the chain
                        let ttl = cname_ttl.min(r.ttl);
                        let mut r = r.clone();
                        r.ttl = ttl;

                        // restrict to the RData type requested
                        if query.query_class() != r.dns_class {
                            return None;
                        }

                        // standard evaluation, it's an any type, or it's the requested type
                        // and the search_name matches
                        let query_type = query.query_type();
                        let record_type = r.record_type();
                        let type_matches = query_type.is_any() || query_type == record_type;
                        let name_matches =
                            search_name.as_ref() == &r.name || query.name() == &r.name;
                        if type_matches && name_matches {
                            return Some(r);
                        }

                        // CNAME evaluation, the record is from the CNAME lookup chain.
                        if client.preserve_intermediates && record_type == RecordType::CNAME {
                            return Some(r);
                        }

                        // Note: NS glue and SRV target IPs are NOT included here
                        // They belong in ADDITIONAL section and are preserved below via insert_additionals
                        None
                    }));

                    // Replace ANSWER section with filtered records, preserve AUTHORITY and ADDITIONAL sections
                    message.answers = preserved_records;
                }

                // Strip DNSSEC records if DO bit is not set.
                message = message.maybe_strip_dnssec_records(options.edns_set_dnssec_ok);

                return Ok(Records::Exists { message });
            }

            // We didn't find the answer - need to continue following CNAME chain
            // Only accumulate ANSWER-section records (CNAMEs) for next hop
            // AUTHORITY and ADDITIONAL records stay with their original message and are not carried forward
            preserved_records.extend(message.take_all_sections().filter_map(|mut r| {
                // because this resolved potentially recursively, we want the min TTL from the chain
                r.ttl = cname_ttl.min(r.ttl);

                // restrict to the RData type requested
                if query.query_class() != r.dns_class {
                    return None;
                }

                // CNAME evaluation, the record is from the CNAME lookup chain.
                if client.preserve_intermediates && r.record_type() == RecordType::CNAME {
                    return Some(r);
                }

                // Note: NS glue and SRV target IPs are NOT accumulated across hops
                // They belong in ADDITIONAL section of their original response, not in ANSWER
                None
            }));

            (search_name.into_owned(), was_cname, preserved_records)
        };

        // TODO: for SRV records we *could* do an implicit lookup, but, this requires knowing the type of IP desired
        //    for now, we'll make the API require the user to perform a follow up to the lookups.
        // It was a CNAME, but not included in the request...
        if was_cname && !depth.is_exhausted() {
            let next_query = Query::query(search_name, query.query_type());
            Ok(Records::CnameChain {
                next: Box::pin(Self::inner_lookup(
                    next_query,
                    options,
                    client.clone(),
                    #[cfg(test)]
                    preserved_records.clone(),
                    #[cfg(not(test))]
                    preserved_records,
                    depth.nest(),
                )),
                #[cfg(test)]
                preserved_records,
            })
        } else {
            // TODO: review See https://tools.ietf.org/html/rfc2308 for NoData section
            // Note on DNSSEC, in secure_client_handle, if verify_nsec fails then the request fails.
            //   this will mean that no unverified negative caches will make it to this point and be stored
            let mut new = NoRecords::new(query.clone(), response_code);
            new.soa = soa.map(Box::new);
            new.negative_ttl = negative_ttl;
            Err(new.into())
        }
    }

    #[allow(clippy::unnecessary_wraps)]
    fn cname(&self, lookup: Lookup, query: Query) -> Result<Lookup, NetError> {
        let mut message = Message::response(0, OpCode::Query);
        message.add_query(query.clone());
        message.add_answers(lookup.answers().iter().cloned());
        message.add_authorities(lookup.authorities().iter().cloned());
        message.add_additionals(lookup.additionals().iter().cloned());
        self.cache.insert(query, Ok(message), Instant::now());
        Ok(lookup)
    }

    fn cache(&self, query: Query, result: Result<Message, NetError>) -> Result<Lookup, NetError> {
        let now = Instant::now();
        let result = match result {
            Ok(mut message) => {
                // Clamp record TTLs before building the Lookup so that the first
                // response to the client reflects positive_min/max_ttl, not the
                // raw upstream TTL.
                let ttl = self
                    .cache
                    .clamp_positive_ttls(query.query_type(), &mut message);
                let valid_until = now + ttl;
                let lookup = Lookup::new(message.clone(), valid_until);
                self.cache.insert(query, Ok(message), now);
                Ok(lookup)
            }
            Err(err) => {
                self.cache.insert(query, Err(err.clone()), now);
                Err(err)
            }
        };
        #[cfg(feature = "metrics")]
        self.cache_metrics
            .cache_size
            .set(self.cache.entry_count() as f64);
        result
    }

    /// Flushes/Removes all entries from the cache
    pub fn clear_cache(&self) {
        self.cache.clear();
    }

    /// Flushes/Removes the entry from the cache that is associated with this query
    pub fn clear_cache_query(&self, query: &Query) {
        self.cache.clear_query(query);
    }
}

enum Records<F> {
    /// The records exist, stored as a complete DNS Message
    Exists { message: Message },
    /// Future lookup for recursive cname records
    CnameChain {
        next: F,
        #[cfg(test)]
        preserved_records: Vec<Record>,
    },
}

// see also the lookup_tests.rs in integration-tests crate
