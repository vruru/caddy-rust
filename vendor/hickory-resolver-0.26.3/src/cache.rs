//! A cache for DNS responses.

use std::{
    collections::HashMap,
    ops::RangeInclusive,
    sync::Arc,
    time::{Duration, Instant},
};

use moka::{Expiry, sync::Cache};
#[cfg(feature = "serde")]
use serde::Deserialize;

use crate::{
    config,
    net::{DnsError, NetError, NoRecords},
    proto::{
        op::{Message, Query},
        rr::RecordType,
    },
};
#[cfg(feature = "__dnssec")]
use crate::{net::dnssec::BOGUS_CACHE_TTL, proto::dnssec::DnssecSummary};

/// A cache for DNS responses.
#[derive(Clone, Debug)]
pub struct ResponseCache {
    cache: Cache<Query, Entry>,
    ttl_config: Arc<TtlConfig>,
}

impl ResponseCache {
    /// Construct a new response cache.
    ///
    /// # Arguments
    ///
    /// * `capacity` - size in number of cached responses
    /// * `ttl_config` - minimum and maximum TTLs for cached records
    pub fn new(capacity: u64, ttl_config: TtlConfig) -> Self {
        Self {
            cache: Cache::builder()
                .max_capacity(capacity)
                .expire_after(EntryExpiry)
                .build(),
            ttl_config: Arc::new(ttl_config),
        }
    }

    /// Insert a response into the cache.
    pub fn insert(&self, query: Query, result: Result<Message, NetError>, now: Instant) {
        self.upsert_clamped_ttl(query, result, now, false)
    }

    /// Inserts a message into the cache, but may clamp the TTL of the entry to that of the existing
    /// entry, if any.
    ///
    /// If `clamp_valid_until` is true, the cache expiration time of any existing entry will not be
    /// extended when the entry's contents are replaced. This is used in a mitigation for ghost
    /// domain attacks, where queries for an apex NS RRset keep a cache entry warm, without ever
    /// checking the referral in the parent zone. This can be eliminated once authoritative
    /// responses and referral responses are cached separately.
    pub(super) fn upsert_clamped_ttl(
        &self,
        query: Query,
        result: Result<Message, NetError>,
        now: Instant,
        clamp_valid_until: bool,
    ) {
        let (ttl, result) = match result {
            Ok(mut message) => {
                let ttl = self.clamp_positive_ttls(query.query_type(), &mut message);
                (ttl, Ok(message))
            }
            Err(NetError::Dns(DnsError::NoRecordsFound(no_records))) => {
                let (negative_min_ttl, negative_max_ttl) = self
                    .ttl_config
                    .negative_response_ttl_bounds(query.query_type())
                    .into_inner();
                let ttl = if let Some(ttl) = no_records.negative_ttl {
                    Duration::from_secs(u64::from(ttl)).clamp(negative_min_ttl, negative_max_ttl)
                } else {
                    negative_min_ttl
                };
                (
                    ttl,
                    Err(NetError::Dns(DnsError::NoRecordsFound(no_records))),
                )
            }
            Err(_) => return,
        };
        let valid_until = now + ttl;
        if clamp_valid_until {
            self.cache.entry(query).and_upsert_with(|entry_opt| Entry {
                result: Arc::new(result),
                original_time: now,
                valid_until: entry_opt.map_or(valid_until, |entry| {
                    entry.value().valid_until.min(valid_until)
                }),
            });
        } else {
            self.cache.insert(
                query,
                Entry {
                    result: Arc::new(result),
                    original_time: now,
                    valid_until,
                },
            );
        }
    }

    /// Try to retrieve a cached response with the given query.
    pub fn get(&self, query: &Query, now: Instant) -> Option<Result<Message, NetError>> {
        let entry = self.cache.get(query)?;
        if !entry.is_current(now) {
            return None;
        }
        Some(entry.updated_ttl(now))
    }

    /// Clamp all record TTLs to `[positive_min_ttl, positive_max_ttl]` and return
    /// the cache duration derived from the minimum TTL of records matching
    /// `query_type` across all sections.
    ///
    /// Each record is clamped according to the TTL bounds configured for its own
    /// record type, so that per-type overrides are respected even for authority
    /// and additional section records.
    pub(crate) fn clamp_positive_ttls(
        &self,
        query_type: RecordType,
        message: &mut Message,
    ) -> Duration {
        #[cfg(feature = "__dnssec")]
        let bogus = matches!(
            DnssecSummary::from_records(message.all_sections()),
            DnssecSummary::Bogus,
        );

        for record in message
            .answers
            .iter_mut()
            .chain(message.authorities.iter_mut())
            .chain(message.additionals.iter_mut())
        {
            let (min_secs, max_secs) = self
                .ttl_config
                .positive_ttl_bounds_secs(record.record_type());
            record.ttl = record.ttl.clamp(min_secs, max_secs);
        }

        let (positive_min_ttl, positive_max_ttl) = self
            .ttl_config
            .positive_response_ttl_bounds(query_type)
            .into_inner();

        let min_ttl = if query_type == RecordType::NS {
            // Derive cache duration from the minimum TTL of the NS records. Check both the answer
            // section and the authority section, to handle both apex NS RRsets and referral
            // responses.
            message
                .answers
                .iter()
                .chain(message.authorities.iter())
                .filter(|r| r.record_type() == RecordType::NS)
                .map(|r| Duration::from_secs(r.ttl.into()))
                .min()
        } else {
            // Derive cache duration from the minimum TTL of records whose type matches the query
            // (or CNAME records, see RFC2181 sections 5.4.1 and 10.1.1), from the answers section
            // only. This avoids letting unrelated authority/additional records skew the cache
            // lifetime.
            message
                .answers
                .iter()
                .filter(|r| r.record_type() == query_type || r.record_type() == RecordType::CNAME)
                .map(|r| Duration::from_secs(r.ttl.into()))
                .min()
        };

        let ttl = min_ttl
            .unwrap_or(positive_min_ttl)
            .clamp(positive_min_ttl, positive_max_ttl);

        // Cap the cache lifetime independently of operator-configured min/max
        // bounds for bogus DNSSEC responses.
        // RFC 4035 §4.7 requires implementations to assign a small TTL
        // since the wire TTL is attacker-influenced
        #[cfg(feature = "__dnssec")]
        let ttl = if bogus { ttl.min(BOGUS_CACHE_TTL) } else { ttl };

        ttl
    }

    pub(crate) fn clear(&self) {
        self.cache.invalidate_all();
    }

    pub(crate) fn clear_query(&self, query: &Query) {
        self.cache.invalidate(query);
    }

    /// Returns the approximate number of entries in the cache.
    #[cfg(feature = "metrics")]
    pub(crate) fn entry_count(&self) -> u64 {
        #[cfg(test)]
        {
            // For tests, ensure pending tasks are processed before getting the count.
            // This allows unit tests of the respective cache size metrics to be
            // written without flakyness. In a production context, we're happier
            // to defer background work and to return an approximate count.
            self.cache.run_pending_tasks();
        }

        self.cache.entry_count()
    }
}

/// An entry in the response cache.
///
/// This contains the response itself (or an error), the time it was received, and the time at which
/// it expires.
#[derive(Debug, Clone)]
struct Entry {
    result: Arc<Result<Message, NetError>>,
    original_time: Instant,
    valid_until: Instant,
}

impl Entry {
    /// Return the `Result` stored in this entry, with modified TTLs, subtracting the elapsed time
    /// since the response was received.
    fn updated_ttl(&self, now: Instant) -> Result<Message, NetError> {
        let elapsed = u32::try_from(now.saturating_duration_since(self.original_time).as_secs())
            .unwrap_or(u32::MAX);
        match &*self.result {
            Ok(response) => {
                let mut response = response.clone();
                for records in [
                    &mut response.answers,
                    &mut response.authorities,
                    &mut response.additionals,
                ] {
                    for record in records {
                        record.decrement_ttl(elapsed);
                    }
                }
                Ok(response)
            }
            Err(e) => {
                let mut e = e.clone();

                // The NoRecords error may contain up to four fields with TTL values present: negative_ttl, soa, authorities, and ns.
                // For completeness, we update each field, if present.
                if let NetError::Dns(DnsError::NoRecordsFound(NoRecords {
                    negative_ttl,
                    soa,
                    authorities,
                    ns,
                    ..
                })) = &mut e
                {
                    if let Some(ttl) = negative_ttl {
                        *ttl = ttl.saturating_sub(elapsed);
                    }

                    if let Some(soa) = soa {
                        soa.decrement_ttl(elapsed);
                    }

                    if let Some(recs) = authorities.take() {
                        authorities.replace(Arc::from(
                            recs.iter()
                                .cloned()
                                .map(|mut rec| {
                                    rec.decrement_ttl(elapsed);
                                    rec
                                })
                                .collect::<Vec<_>>(),
                        ));
                    }

                    if let Some(ns_recs) = ns.take() {
                        ns.replace(Arc::from(
                            ns_recs
                                .iter()
                                .cloned()
                                .map(|mut ns| {
                                    ns.ns.decrement_ttl(elapsed);
                                    ns.glue = Arc::from(
                                        ns.glue
                                            .iter()
                                            .cloned()
                                            .map(|mut glue| {
                                                glue.decrement_ttl(elapsed);
                                                glue
                                            })
                                            .collect::<Vec<_>>(),
                                    );

                                    ns
                                })
                                .collect::<Vec<_>>(),
                        ));
                    }
                }
                Err(e)
            }
        }
    }

    /// Returns whether this cache entry is still valid.
    fn is_current(&self, now: Instant) -> bool {
        now <= self.valid_until
    }

    /// Returns the remaining time that this cache entry is valid for.
    fn ttl(&self, now: Instant) -> Duration {
        self.valid_until.saturating_duration_since(now)
    }
}

struct EntryExpiry;

impl Expiry<Query, Entry> for EntryExpiry {
    fn expire_after_create(
        &self,
        _key: &Query,
        value: &Entry,
        created_at: Instant,
    ) -> Option<Duration> {
        Some(value.ttl(created_at))
    }

    fn expire_after_update(
        &self,
        _key: &Query,
        value: &Entry,
        updated_at: Instant,
        _duration_until_expiry: Option<Duration>,
    ) -> Option<Duration> {
        Some(value.ttl(updated_at))
    }
}

/// The time-to-live (TTL) configuration used by the cache.
///
/// Minimum and maximum TTLs can be set for both positive responses and negative responses. Separate
/// limits may be set depending on the query type. If a minimum value is not provided, it will
/// default to 0 seconds. If a maximum value is not provided, it will default to one day.
///
/// Note that TTLs in DNS are represented as a number of seconds stored in a 32-bit unsigned
/// integer. We use `Duration` here, instead of `u32`, which can express larger values than the DNS
/// standard. Generally, a `Duration` greater than `u32::MAX_VALUE` shouldn't cause any issue, as
/// this will never be used in serialization, but note that this would be outside the standard
/// range.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(from = "ttl_config_deserialize::TtlConfigMap")
)]
pub struct TtlConfig {
    /// TTL limits applied to all queries.
    default: TtlBounds,

    /// TTL limits applied to queries with specific query types.
    by_query_type: HashMap<RecordType, TtlBounds>,
}

impl TtlConfig {
    /// Construct the LRU's TTL configuration based on the ResolverOpts configuration.
    pub fn from_opts(opts: &config::ResolverOpts) -> Self {
        Self::from(TtlBounds {
            positive_min_ttl: opts.positive_min_ttl,
            negative_min_ttl: opts.negative_min_ttl,
            positive_max_ttl: opts.positive_max_ttl,
            negative_max_ttl: opts.negative_max_ttl,
        })
    }

    /// Override the minimum and maximum TTL values for a specific query type.
    ///
    /// If a minimum value is not provided, it will default to 0 seconds. If a maximum value is not
    /// provided, it will default to one day.
    pub fn with_query_type_ttl_bounds(
        &mut self,
        query_type: RecordType,
        bounds: TtlBounds,
    ) -> &mut Self {
        self.by_query_type.insert(query_type, bounds);
        self
    }

    /// Returns the positive-response TTL bounds as `(min_secs, max_secs)` clamped to `u32`.
    ///
    /// This is a convenience wrapper around [`positive_response_ttl_bounds`](Self::positive_response_ttl_bounds)
    /// for use when clamping individual record TTLs.
    fn positive_ttl_bounds_secs(&self, record_type: RecordType) -> (u32, u32) {
        let (min, max) = self.positive_response_ttl_bounds(record_type).into_inner();
        (
            u32::try_from(min.as_secs()).unwrap_or(MAX_TTL),
            u32::try_from(max.as_secs()).unwrap_or(MAX_TTL),
        )
    }

    /// Retrieves the minimum and maximum TTL values for positive responses.
    pub fn positive_response_ttl_bounds(&self, query_type: RecordType) -> RangeInclusive<Duration> {
        let bounds = self.by_query_type.get(&query_type).unwrap_or(&self.default);
        let min = bounds
            .positive_min_ttl
            .unwrap_or_else(|| Duration::from_secs(0));
        let max = bounds
            .positive_max_ttl
            .unwrap_or_else(|| Duration::from_secs(u64::from(MAX_TTL)));
        min..=max
    }

    /// Retrieves the minimum and maximum TTL values for negative responses.
    pub fn negative_response_ttl_bounds(&self, query_type: RecordType) -> RangeInclusive<Duration> {
        let bounds = self.by_query_type.get(&query_type).unwrap_or(&self.default);
        let min = bounds
            .negative_min_ttl
            .unwrap_or_else(|| Duration::from_secs(0));
        let max = bounds
            .negative_max_ttl
            .unwrap_or_else(|| Duration::from_secs(u64::from(MAX_TTL)));
        min..=max
    }
}

impl From<TtlBounds> for TtlConfig {
    fn from(default: TtlBounds) -> Self {
        Self {
            default,
            by_query_type: HashMap::default(),
        }
    }
}

/// Minimum and maximum TTL values for positive and negative responses.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct TtlBounds {
    /// An optional minimum TTL value for positive responses.
    ///
    /// Positive responses with TTLs under `positive_min_ttl` will use
    /// `positive_min_ttl` instead.
    #[cfg_attr(
        feature = "serde",
        serde(default, deserialize_with = "config::duration_opt::deserialize")
    )]
    positive_min_ttl: Option<Duration>,

    /// An optional minimum TTL value for negative (`NXDOMAIN`) responses.
    ///
    /// `NXDOMAIN` responses with TTLs under `negative_min_ttl` will use
    /// `negative_min_ttl` instead.
    #[cfg_attr(
        feature = "serde",
        serde(default, deserialize_with = "config::duration_opt::deserialize")
    )]
    negative_min_ttl: Option<Duration>,

    /// An optional maximum TTL value for positive responses.
    ///
    /// Positive responses with TTLs over `positive_max_ttl` will use
    /// `positive_max_ttl` instead.
    #[cfg_attr(
        feature = "serde",
        serde(default, deserialize_with = "config::duration_opt::deserialize")
    )]
    positive_max_ttl: Option<Duration>,

    /// An optional maximum TTL value for negative (`NXDOMAIN`) responses.
    ///
    /// `NXDOMAIN` responses with TTLs over `negative_max_ttl` will use
    /// `negative_max_ttl` instead.
    #[cfg_attr(
        feature = "serde",
        serde(default, deserialize_with = "config::duration_opt::deserialize")
    )]
    negative_max_ttl: Option<Duration>,
}

#[cfg(feature = "serde")]
mod ttl_config_deserialize {
    use std::collections::HashMap;

    use serde::Deserialize;

    use super::{TtlBounds, TtlConfig};
    use crate::proto::rr::RecordType;

    #[derive(Deserialize)]
    pub(super) struct TtlConfigMap(HashMap<TtlConfigField, TtlBounds>);

    impl From<TtlConfigMap> for TtlConfig {
        fn from(value: TtlConfigMap) -> Self {
            let mut default = TtlBounds::default();
            let mut by_query_type = HashMap::new();
            for (field, bounds) in value.0.into_iter() {
                match field {
                    TtlConfigField::RecordType(record_type) => {
                        by_query_type.insert(record_type, bounds);
                    }
                    TtlConfigField::Default => default = bounds,
                }
            }
            Self {
                default,
                by_query_type,
            }
        }
    }

    #[derive(PartialEq, Eq, Hash, Deserialize)]
    enum TtlConfigField {
        #[serde(rename = "default")]
        Default,
        #[serde(untagged)]
        RecordType(RecordType),
    }
}

/// Maximum TTL. This is set to one day (in seconds).
///
/// [RFC 2181, section 8](https://tools.ietf.org/html/rfc2181#section-8) says
/// that the maximum TTL value is 2147483647, but implementations may place an
/// upper bound on received TTLs.
pub const MAX_TTL: u32 = 86400_u32;
