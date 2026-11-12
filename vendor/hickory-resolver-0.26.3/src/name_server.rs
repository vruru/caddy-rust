// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#[cfg(not(test))]
use std::time::{Duration, Instant};
use std::{
    cmp,
    fmt::Debug,
    marker::PhantomData,
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicU8, AtomicU32, Ordering},
    },
};

use futures_util::lock::Mutex as AsyncMutex;
use parking_lot::Mutex as SyncMutex;

use tracing::{debug, error, warn};

#[cfg(all(feature = "metrics", any(feature = "__tls", feature = "__quic")))]
use crate::metrics::opportunistic_encryption::ProbeMetrics;
#[cfg(feature = "metrics")]
use crate::metrics::{NameServerAddr, ResolverMetrics};
use crate::{
    config::{
        ConnectionConfig, NameServerConfig, OpportunisticEncryption, ResolverOpts,
        ServerOrderingStrategy,
    },
    connection_provider::ConnectionProvider,
    name_server_pool::{NameServerTransportState, PoolContext},
    net::{
        DnsError, NetError, NoRecords,
        runtime::{RuntimeProvider, Spawn},
        xfer::{DnsHandle, FirstAnswer, Protocol},
    },
    proto::{
        op::{DnsRequest, DnsRequestOptions, DnsResponse, Query, ResponseCode},
        rr::{Name, RecordType},
    },
};

/// A remote DNS server, identified by its IP address.
///
/// This potentially holds multiple open connections to the server, according to the
/// configured protocols, and will make new connections as needed.
pub struct NameServer<P: ConnectionProvider> {
    config: NameServerConfig,
    connections: AsyncMutex<Vec<ConnectionState<P>>>,
    /// Metrics related to opportunistic encryption probes.
    #[cfg(all(feature = "metrics", any(feature = "__tls", feature = "__quic")))]
    opportunistic_probe_metrics: ProbeMetrics,
    /// Metrics related to outgoing queries.
    #[cfg(feature = "metrics")]
    resolver_metrics: ResolverMetrics,
    server_srtt: DecayingSrtt,
    connection_provider: P,
}

impl<P: ConnectionProvider> NameServer<P> {
    /// Create a new [`NameServer`] with the given connections and configuration.
    ///
    /// The `connections` will usually be empty.
    pub fn new(
        connections: impl IntoIterator<Item = (Protocol, P::Conn)>,
        config: NameServerConfig,
        options: &ResolverOpts,
        connection_provider: P,
    ) -> Self {
        let mut connections = connections
            .into_iter()
            .map(|(protocol, handle)| ConnectionState::new(handle, protocol))
            .collect::<Vec<_>>();

        // Unless the user specified that we should follow the configured order,
        // re-order the connections to prioritize UDP.
        if options.server_ordering_strategy != ServerOrderingStrategy::UserProvidedOrder {
            connections.sort_by_key(|ns| ns.protocol != Protocol::Udp);
        }

        #[cfg(feature = "metrics")]
        let resolver_metrics = ResolverMetrics::new(match options.enable_per_name_server_metrics {
            true => NameServerAddr::Individual(config.ip),
            false => NameServerAddr::Aggregated,
        });

        Self {
            config,
            connections: AsyncMutex::new(connections),
            server_srtt: DecayingSrtt::new(Duration::from_micros(rand::random_range(1..32))),
            #[cfg(all(feature = "metrics", any(feature = "__tls", feature = "__quic")))]
            opportunistic_probe_metrics: ProbeMetrics::default(),
            #[cfg(feature = "metrics")]
            resolver_metrics,
            connection_provider,
        }
    }

    // TODO: there needs to be some way of customizing the connection based on EDNS options from the server side...
    pub(crate) async fn send(
        self: Arc<Self>,
        request: DnsRequest,
        policy: ConnectionPolicy,
        cx: &Arc<PoolContext>,
    ) -> Result<DnsResponse, NetError> {
        let (_protocol, result) = self.send_inner(request, policy, cx).await;
        #[cfg(feature = "metrics")]
        if let Some(protocol) = _protocol {
            self.resolver_metrics
                .increment_query_result(&protocol, result.as_ref().map(|_| ()));
        }

        result
    }

    async fn send_inner(
        &self,
        request: DnsRequest,
        policy: ConnectionPolicy,
        cx: &Arc<PoolContext>,
    ) -> (Option<Protocol>, Result<DnsResponse, NetError>) {
        // Reconnect and retry once if a reused connection was closed mid-flight.
        // Caps total retries even when the pool holds several reusable connections.
        let mut reconnect_budget = 1u8;
        loop {
            let ConnectedClient {
                handle,
                meta,
                protocol,
                reuse,
            } = match self.connected_mut_client(policy, cx).await {
                Ok(v) => v,
                Err((err, protocol)) => {
                    debug!(config = ?self.config, ?protocol, %err, "failed to establish connection to name server");
                    return (protocol, Err(err));
                }
            };
            #[cfg(feature = "metrics")]
            self.resolver_metrics.increment_outgoing_query(&protocol);
            let now = Instant::now();
            let response = handle.send(request.clone()).first_answer().await;
            let rtt = now.elapsed();

            match response {
                Ok(response) => {
                    meta.set_status(Status::Established);
                    let result = DnsError::from_response(response);
                    let error = match result {
                        Ok(response) => {
                            meta.srtt.record(rtt);
                            self.server_srtt.record(rtt);
                            if cx.opportunistic_encryption.is_enabled() && protocol.is_encrypted() {
                                cx.transport_state()
                                    .await
                                    .response_received(self.config.ip, protocol);
                            }
                            return (Some(protocol), Ok(response));
                        }
                        Err(error) => error,
                    };

                    let update = match error {
                        DnsError::NoRecordsFound(NoRecords {
                            response_code: ResponseCode::ServFail,
                            ..
                        }) => Some(true),
                        DnsError::NoRecordsFound(NoRecords { .. }) => Some(false),
                        _ => None,
                    };

                    match update {
                        Some(true) => {
                            meta.srtt.record(rtt);
                            self.server_srtt.record(rtt);
                        }
                        Some(false) => {
                            // record the failure
                            meta.srtt.record_failure();
                            self.server_srtt.record_failure();
                        }
                        None => {}
                    }

                    let err = NetError::from(error);
                    if cx.opportunistic_encryption.is_enabled() && protocol.is_encrypted() {
                        cx.transport_state()
                            .await
                            .error_received(self.config.ip, protocol, &err)
                    }
                    return (Some(protocol), Err(err));
                }
                Err(error) => {
                    debug!(config = ?self.config, %error, "failed to connect to name server");

                    // this transitions the state to failure, so the next acquire drops it
                    meta.set_status(Status::Failed);

                    // A reused connection the peer had already closed isn't a server fault.
                    // Reconnect and retry once without penalizing server selection. The resend
                    // is at-least-once; the resolver only sends read-only queries through this pool.
                    if reuse == ConnectionReuse::Reused
                        && reconnect_budget > 0
                        && error.is_connection_closed()
                    {
                        #[cfg(feature = "metrics")]
                        // The increment in send() won't occur since we're retrying.
                        self.resolver_metrics
                            .increment_query_result(&protocol, Err(&error));
                        reconnect_budget -= 1;
                        continue;
                    }

                    // record the failure on both the per-connection and server-level SRTTs.
                    // updating server_srtt ensures the server is deprioritized in pool
                    // ordering (decayed_srtt) so other servers get a chance to be tried.
                    match &error {
                        NetError::Busy | NetError::Io(_) | NetError::Timeout => {
                            meta.srtt.record_failure();
                            self.server_srtt.record_failure();
                        }
                        #[cfg(feature = "__quic")]
                        NetError::QuinnConfigError(_)
                        | NetError::QuinnConnect(_)
                        | NetError::QuinnConnection(_)
                        | NetError::QuinnTlsConfigError(_) => {
                            meta.srtt.record_failure();
                            self.server_srtt.record_failure();
                        }
                        #[cfg(feature = "__tls")]
                        NetError::RustlsError(_) => {
                            meta.srtt.record_failure();
                            self.server_srtt.record_failure();
                        }
                        _ => {}
                    }

                    if cx.opportunistic_encryption.is_enabled() && protocol.is_encrypted() {
                        cx.transport_state()
                            .await
                            .error_received(self.config.ip, protocol, &error);
                    }

                    // These are connection failures, not lookup failures, that is handled in the resolver layer
                    return (Some(protocol), Err(error));
                }
            }
        }
    }

    /// This will return a mutable client to allows for sending messages.
    ///
    /// If the connection is in a failed state, then this will establish a new connection.
    ///
    async fn connected_mut_client(
        &self,
        policy: ConnectionPolicy,
        cx: &Arc<PoolContext>,
    ) -> Result<ConnectedClient<P>, (NetError, Option<Protocol>)> {
        // Check for an existing usable connection (short lock)
        {
            let mut connections = self.connections.lock().await;
            connections
                .retain(|conn| matches!(conn.meta.status(), Status::Init | Status::Established));
            if let Some(conn) = policy.select_connection(
                self.config.ip,
                &*cx.transport_state().await,
                &cx.opportunistic_encryption,
                &connections,
            ) {
                return Ok(ConnectedClient {
                    handle: conn.handle.clone(),
                    meta: conn.meta.clone(),
                    protocol: conn.protocol,
                    reuse: ConnectionReuse::Reused,
                });
            }
        }

        // Select connection config and update transport state (no lock)
        debug!(config = ?self.config, "connecting");
        let config = policy
            .select_connection_config(
                self.config.ip,
                &*cx.transport_state().await,
                &cx.opportunistic_encryption,
                &self.config.connections,
            )
            .ok_or((NetError::NoConnections, None))?;

        let protocol = config.protocol.to_protocol();
        if cx.opportunistic_encryption.is_enabled() && protocol.is_encrypted() {
            cx.transport_state()
                .await
                .initiate_connection(self.config.ip, protocol);
        } else if cx.opportunistic_encryption.is_enabled() && !protocol.is_encrypted() {
            self.consider_probe_encrypted_transport(&policy, cx).await;
        }

        // Establish connection
        let handle_fut = self
            .connection_provider
            .new_connection(self.config.ip, config, cx)
            .map_err(|e| (e, Some(protocol)))?;

        let handle = Box::pin(handle_fut)
            .await
            .map_err(|e| (e, Some(protocol)))?;

        if cx.opportunistic_encryption.is_enabled() && protocol.is_encrypted() {
            cx.transport_state()
                .await
                .complete_connection(self.config.ip, protocol);
        }

        // Store the new connection (with lock)
        let state = ConnectionState::new(handle.clone(), protocol);
        let meta = state.meta.clone();
        self.connections.lock().await.push(state);
        Ok(ConnectedClient {
            handle,
            meta,
            protocol,
            reuse: ConnectionReuse::Fresh,
        })
    }

    pub(super) fn protocols(&self) -> impl Iterator<Item = Protocol> + '_ {
        self.config
            .connections
            .iter()
            .map(|conn| conn.protocol.to_protocol())
    }

    pub(super) fn ip(&self) -> IpAddr {
        self.config.ip
    }

    pub(crate) fn decayed_srtt(&self) -> f64 {
        self.server_srtt.current()
    }

    /// Records an SRTT observation for a server whose in-flight request was
    /// cancelled because a parallel request to another server succeeded first.
    ///
    /// Records the winner's RTT plus a small penalty (`CANCEL_PENALTY`) as the
    /// observation: the cancelled server was *at least* that slow (it hadn't
    /// responded yet), and the penalty ensures the winner retains a sorting
    /// advantage in the next round. This avoids the full `FAILURE_PENALTY`
    /// which would be too harsh for a server that's merely slightly slower.
    ///
    /// A truly unreachable server will be cancelled on every query and its SRTT
    /// will ratchet up as the EWMA repeatedly incorporates the winner's RTT
    /// without ever recording a real (successful) measurement to bring it back
    /// down.
    pub(super) fn record_cancelled(&self, winner_rtt: Duration) {
        const CANCEL_PENALTY: Duration = Duration::from_millis(5);
        self.server_srtt.record(winner_rtt + CANCEL_PENALTY);
    }





    pub(crate) fn trust_negative_responses(&self) -> bool {
        self.config.trust_negative_responses
    }

    async fn consider_probe_encrypted_transport(
        &self,
        policy: &ConnectionPolicy,
        cx: &Arc<PoolContext>,
    ) {
        let Some(probe_config) =
            policy.select_encrypted_connection_config(&self.config.connections)
        else {
            warn!("no encrypted connection configs available for probing");
            return;
        };

        let probe_protocol = probe_config.protocol.to_protocol();
        let should_probe = {
            let state = cx.transport_state().await;
            state.should_probe_encrypted(
                self.config.ip,
                probe_protocol,
                &cx.opportunistic_encryption,
            )
        };

        if !should_probe {
            return;
        }

        if let Err(err) = self.probe_encrypted_transport(cx, probe_config) {
            error!(%err, "opportunistic encrypted probe attempt failed");
        }
    }

    fn probe_encrypted_transport(
        &self,
        cx: &Arc<PoolContext>,
        probe_config: &ConnectionConfig,
    ) -> Result<(), NetError> {
        let mut budget = cx.opportunistic_probe_budget.load(Ordering::Relaxed);
        #[cfg(all(feature = "metrics", any(feature = "__tls", feature = "__quic")))]
        self.opportunistic_probe_metrics.probe_budget.set(budget);
        loop {
            if budget == 0 {
                debug!("no remaining budget for opportunistic probing");
                return Ok(());
            }
            match cx.opportunistic_probe_budget.compare_exchange_weak(
                budget,
                budget - 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(current) => budget = current,
            }
        }

        let connect = ProbeRequest::new(
            probe_config,
            self,
            cx,
            #[cfg(all(feature = "metrics", any(feature = "__tls", feature = "__quic")))]
            self.opportunistic_probe_metrics.clone(),
        )?;
        self.connection_provider
            .runtime_provider()
            .create_handle()
            .spawn_bg(connect.run());

        Ok(())
    }
}

struct ProbeRequest<P: ConnectionProvider> {
    ip: IpAddr,
    proto: Protocol,
    connecting: P::FutureConn,
    context: Arc<PoolContext>,
    #[cfg(all(feature = "metrics", any(feature = "__tls", feature = "__quic")))]
    metrics: ProbeMetrics,
    provider: PhantomData<P>,
}

impl<P: ConnectionProvider> ProbeRequest<P> {
    fn new(
        config: &ConnectionConfig,
        ns: &NameServer<P>,
        cx: &Arc<PoolContext>,
        #[cfg(all(feature = "metrics", any(feature = "__tls", feature = "__quic")))]
        metrics: ProbeMetrics,
    ) -> Result<Self, NetError> {
        Ok(Self {
            ip: ns.config.ip,
            proto: config.protocol.to_protocol(),
            connecting: ns
                .connection_provider
                .new_connection(ns.config.ip, config, cx)?,
            context: cx.clone(),
            #[cfg(all(feature = "metrics", any(feature = "__tls", feature = "__quic")))]
            metrics,
            provider: PhantomData,
        })
    }

    async fn run(self) {
        let Self {
            ip,
            proto,
            connecting,
            context,
            #[cfg(all(feature = "metrics", any(feature = "__tls", feature = "__quic")))]
            metrics,
            provider: _,
        } = self;

        #[cfg(all(feature = "metrics", any(feature = "__tls", feature = "__quic")))]
        let start = Instant::now();

        context
            .transport_state()
            .await
            .initiate_connection(ip, proto);
        #[cfg(all(feature = "metrics", any(feature = "__tls", feature = "__quic")))]
        metrics.increment_attempts(proto);

        let conn = match connecting.await {
            Ok(conn) => conn,
            Err(err) => {
                debug!(?proto, "probe connection failed");
                let _prev = context
                    .opportunistic_probe_budget
                    .fetch_add(1, Ordering::Relaxed);
                #[cfg(all(feature = "metrics", any(feature = "__tls", feature = "__quic")))]
                {
                    metrics.increment_errors(proto, &err);
                    metrics.probe_budget.set(_prev + 1);
                    metrics.record_probe_duration(proto, start.elapsed());
                }
                context
                    .transport_state()
                    .await
                    .error_received(ip, proto, &err);
                return;
            }
        };

        debug!(?proto, "probe connection succeeded");
        context
            .transport_state()
            .await
            .complete_connection(ip, proto);

        match conn
            .send(DnsRequest::from_query(
                Query::query(Name::root(), RecordType::NS),
                DnsRequestOptions::default(),
            ))
            .first_answer()
            .await
        {
            Ok(_) => {
                debug!(?proto, "probe query succeeded");
                #[cfg(all(feature = "metrics", any(feature = "__tls", feature = "__quic")))]
                metrics.increment_successes(proto);
                context.transport_state().await.response_received(ip, proto);
            }
            Err(err) => {
                debug!(?proto, ?err, "probe query failed");
                #[cfg(all(feature = "metrics", any(feature = "__tls", feature = "__quic")))]
                metrics.increment_errors(proto, &err);
                context
                    .transport_state()
                    .await
                    .error_received(ip, proto, &err);
            }
        }

        let _prev = context
            .opportunistic_probe_budget
            .fetch_add(1, Ordering::Relaxed);
        #[cfg(all(feature = "metrics", any(feature = "__tls", feature = "__quic")))]
        {
            metrics.probe_budget.set(_prev + 1);
            metrics.record_probe_duration(proto, start.elapsed());
        }
    }
}

/// Whether `connected_mut_client` returned an existing pooled connection or established a new one.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ConnectionReuse {
    Reused,
    Fresh,
}

/// A connection selected by [`NameServer::connected_mut_client`] for sending a request.
struct ConnectedClient<P: ConnectionProvider> {
    handle: P::Conn,
    meta: Arc<ConnectionMeta>,
    protocol: Protocol,
    reuse: ConnectionReuse,
}

struct ConnectionState<P: ConnectionProvider> {
    protocol: Protocol,
    handle: P::Conn,
    meta: Arc<ConnectionMeta>,
}

impl<P: ConnectionProvider> ConnectionState<P> {
    fn new(handle: P::Conn, protocol: Protocol) -> Self {
        Self {
            protocol,
            handle,
            meta: Arc::new(ConnectionMeta::default()),
        }
    }
}

struct ConnectionMeta {
    status: AtomicU8,
    srtt: DecayingSrtt,
}

impl ConnectionMeta {
    fn set_status(&self, status: Status) {
        self.status.store(status.into(), Ordering::Release);
    }

    fn status(&self) -> Status {
        Status::from(self.status.load(Ordering::Acquire))
    }
}

impl Default for ConnectionMeta {
    fn default() -> Self {
        // Initialize the SRTT to a randomly generated value that represents a
        // very low RTT. Such a value helps ensure that each server is attempted
        // early.
        Self {
            status: AtomicU8::new(Status::Init.into()),
            srtt: DecayingSrtt::new(Duration::from_micros(rand::random_range(1..32))),
        }
    }
}

struct DecayingSrtt {
    /// The smoothed round-trip time (SRTT).
    ///
    /// This value represents an exponentially weighted moving average (EWMA) of
    /// recorded latencies. The algorithm for computing this value is based on
    /// the following:
    ///
    /// <https://en.wikipedia.org/wiki/Moving_average#Application_to_measuring_computer_performance>
    ///
    /// It is also partially inspired by the BIND and PowerDNS implementations:
    ///
    /// - <https://github.com/isc-projects/bind9/blob/7bf8a7ab1b280c1021bf1e762a239b07aac3c591/lib/dns/adb.c#L3487>
    /// - <https://github.com/PowerDNS/pdns/blob/7c5f9ae6ae4fb17302d933eaeebc8d6f0249aab2/pdns/syncres.cc#L123>
    ///
    /// The algorithm for computing and using this value can be summarized as
    /// follows:
    ///
    /// 1. The value is initialized to a random value that represents a very low
    ///    latency.
    /// 2. If the round-trip time (RTT) was successfully measured for a query,
    ///    then it is incorporated into the EWMA using the formula linked above.
    /// 3. If the RTT could not be measured (i.e. due to a connection failure),
    ///    then a constant penalty factor is applied to the EWMA.
    /// 4. When comparing EWMA values, a time-based decay is applied to each
    ///    value. Note that this decay is only applied at read time.
    ///
    /// For the original discussion regarding this algorithm, see
    /// <https://github.com/hickory-dns/hickory-dns/issues/1702>.
    srtt_microseconds: AtomicU32,

    /// The last time the `srtt_microseconds` value was updated.
    last_update: SyncMutex<Option<Instant>>,
}

impl DecayingSrtt {
    fn new(initial_srtt: Duration) -> Self {
        Self {
            srtt_microseconds: AtomicU32::new(initial_srtt.as_micros() as u32),
            last_update: SyncMutex::new(None),
        }
    }

    fn record(&self, rtt: Duration) {
        // If the cast on the result does overflow (it shouldn't), then the
        // value is saturated to u32::MAX, which is above the `MAX_SRTT_MICROS`
        // limit (meaning that any potential overflow is inconsequential).
        // See https://github.com/rust-lang/rust/issues/10184.
        self.update(
            rtt.as_micros() as u32,
            |cur_srtt_microseconds, last_update| {
                // An arbitrarily low weight is used when computing the factor
                // to ensure that recent RTT measurements are weighted more
                // heavily.
                let factor = compute_srtt_factor(last_update, 3);
                let new_srtt = (1.0 - factor) * (rtt.as_micros() as f64)
                    + factor * f64::from(cur_srtt_microseconds);
                new_srtt.round() as u32
            },
        );
    }

    /// Records a connection failure for a particular query.
    fn record_failure(&self) {
        self.update(
            Self::FAILURE_PENALTY,
            |cur_srtt_microseconds, _last_update| {
                cur_srtt_microseconds.saturating_add(Self::FAILURE_PENALTY)
            },
        );
    }

    /// Returns the SRTT value after applying a time based decay.
    ///
    /// The decay exponentially decreases the SRTT value. The primary reasons
    /// for applying a downwards decay are twofold:
    ///
    /// 1. It helps distribute query load.
    /// 2. It helps detect positive network changes. For example, decreases in
    ///    latency or a server that has recovered from a failure.
    fn current(&self) -> f64 {
        let srtt = f64::from(self.srtt_microseconds.load(Ordering::Acquire));
        self.last_update.lock().map_or(srtt, |last_update| {
            // In general, if the time between queries is relatively short, then
            // the server ordering algorithm will approximate a spike
            // distribution where the servers with the lowest latencies are
            // chosen much more frequently. Conversely, if the time between
            // queries is relatively long, then the query distribution will be
            // more uniform. A larger weight widens the window in which servers
            // with historically lower latencies will be heavily preferred. On
            // the other hand, a larger weight may also increase the time it
            // takes to recover from a failure or to observe positive changes in
            // latency.
            srtt * compute_srtt_factor(last_update, 180)
        })
    }

    /// Updates the SRTT value.
    ///
    /// If the `last_update` value has not been set, then uses the `default`
    /// value to update the SRTT. Otherwise, invokes the `update_fn` with the
    /// current SRTT value and the `last_update` timestamp.
    fn update(&self, default: u32, update_fn: impl Fn(u32, Instant) -> u32) {
        let last_update = self.last_update.lock().replace(Instant::now());
        let _ = self.srtt_microseconds.fetch_update(
            Ordering::SeqCst,
            Ordering::SeqCst,
            move |cur_srtt_microseconds| {
                Some(
                    last_update
                        .map_or(default, |last_update| {
                            update_fn(cur_srtt_microseconds, last_update)
                        })
                        .min(Self::MAX_SRTT_MICROS),
                )
            },
        );
    }



    const FAILURE_PENALTY: u32 = Duration::from_millis(150).as_micros() as u32;
    const MAX_SRTT_MICROS: u32 = Duration::from_secs(5).as_micros() as u32;
}

/// Returns an exponentially weighted value in the range of 0.0 < x < 1.0
///
/// Computes the value using the following formula:
///
/// e<sup>(-t<sub>now</sub> - t<sub>last</sub>) / weight</sup>
///
/// As the duration since the `last_update` approaches the provided `weight`,
/// the returned value decreases.
fn compute_srtt_factor(last_update: Instant, weight: u32) -> f64 {
    let exponent = (-last_update.elapsed().as_secs_f64().max(1.0)) / f64::from(weight);
    exponent.exp()
}

/// State of a connection with a remote NameServer.
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
#[repr(u8)]
enum Status {
    /// For some reason the connection failed. For UDP this would generally be a timeout
    ///  for TCP this could be either Connection could never be established, or it
    ///  failed at some point after. The Failed state should *not* be entered due to an
    ///  error contained in a Message received from the server. In All cases to reestablish
    ///  a new connection will need to be created.
    Failed = 0,
    /// Initial state, if Edns is not none, then Edns will be requested
    Init = 1,
    /// There has been successful communication with the remote.
    ///  if no Edns is associated, then the remote does not support Edns
    Established = 2,
}

impl From<Status> for u8 {
    /// used for ordering purposes. The highest priority is placed on open connections
    fn from(val: Status) -> Self {
        val as Self
    }
}

impl From<u8> for Status {
    fn from(val: u8) -> Self {
        match val {
            2 => Self::Established,
            1 => Self::Init,
            _ => Self::Failed,
        }
    }
}

#[derive(Debug, Copy, Clone, Default, Eq, PartialEq)]
pub(crate) struct ConnectionPolicy {
    pub(crate) disable_udp: bool,
}

impl ConnectionPolicy {
    /// Checks if the given server has any protocols compatible with current policy.
    pub(crate) fn allows_server<P: ConnectionProvider>(&self, server: &NameServer<P>) -> bool {
        server.protocols().any(|p| self.allows_protocol(p))
    }

    /// Select the best pre-existing connection to use.
    ///
    /// This choice is made based on opportunistic encryption policy & probe history,
    /// protocol policy, and the SRTT performance metrics.
    fn select_connection<'a, P: ConnectionProvider>(
        &self,
        ip: IpAddr,
        encrypted_transport_state: &NameServerTransportState,
        opportunistic_encryption: &OpportunisticEncryption,
        connections: &'a [ConnectionState<P>],
    ) -> Option<&'a ConnectionState<P>> {
        let selected = connections
            .iter()
            .filter(|conn| self.allows_protocol(conn.protocol))
            .min_by(|a, b| self.compare_connections(opportunistic_encryption.is_enabled(), a, b));

        let selected = selected?;

        // If we're using opportunistic encryption and selected a pre-existing unencrypted connection,
        // and have successfully probed on any supported encrypted protocol, we should _not_ reuse the
        // existing connection and instead return `None`. This will result in a new encrypted connection
        // being made to the successfully probed protocol and added to the connection list for future
        // re-use.
        match opportunistic_encryption.is_enabled()
            && !selected.protocol.is_encrypted()
            && encrypted_transport_state.any_recent_success(ip, opportunistic_encryption)
        {
            true => None,
            false => Some(selected),
        }
    }

    /// Select the best connection configuration to use for a new connection.
    ///
    /// This choice is made based on opportunistic encryption policy & probe history,
    /// and protocol policy.
    fn select_connection_config<'a>(
        &self,
        ip: IpAddr,
        encrypted_transport_state: &NameServerTransportState,
        opportunistic_encryption: &OpportunisticEncryption,
        connection_configs: &'a [ConnectionConfig],
    ) -> Option<&'a ConnectionConfig> {
        connection_configs
            .iter()
            .filter(|c| self.allows_protocol(c.protocol.to_protocol()))
            .min_by(|a, b| {
                self.compare_connection_configs(
                    ip,
                    encrypted_transport_state,
                    opportunistic_encryption,
                    a,
                    b,
                )
            })
    }

    /// Select the first protocol allowed by current policy that uses an encrypted transport.
    fn select_encrypted_connection_config<'a>(
        &self,
        connection_config: &'a [ConnectionConfig],
    ) -> Option<&'a ConnectionConfig> {
        connection_config
            .iter()
            .filter(|c| self.allows_protocol(c.protocol.to_protocol()))
            .find(|c| c.protocol.to_protocol().is_encrypted())
    }

    /// Checks if the given protocol is allowed by current policy.
    fn allows_protocol(&self, protocol: Protocol) -> bool {
        !(self.disable_udp && protocol == Protocol::Udp)
    }

    /// Compare two connections according to policy, protocol, and performance.
    /// If opportunistic encryption is enabled we make an effort to select an encrypted connection.
    fn compare_connections<P: ConnectionProvider>(
        &self,
        opportunistic_encryption: bool,
        a: &ConnectionState<P>,
        b: &ConnectionState<P>,
    ) -> cmp::Ordering {
        // When opportunistic encryption is in-play, we want to consider encrypted
        // connections with the greatest priority.
        if opportunistic_encryption {
            match (a.protocol.is_encrypted(), b.protocol.is_encrypted()) {
                (true, false) => return cmp::Ordering::Less,
                (false, true) => return cmp::Ordering::Greater,
                // When _both_ are encrypted, then decide on ordering based on other properties (like SRTT).
                _ => {}
            }
        }

        match (a.protocol, b.protocol) {
            (ap, bp) if ap == bp => a.meta.srtt.current().total_cmp(&b.meta.srtt.current()),
            (Protocol::Udp, _) => cmp::Ordering::Less,
            (_, Protocol::Udp) => cmp::Ordering::Greater,
            _ => a.meta.srtt.current().total_cmp(&b.meta.srtt.current()),
        }
    }

    fn compare_connection_configs(
        &self,
        ip: IpAddr,
        encrypted_transport_state: &NameServerTransportState,
        opportunistic_encryption: &OpportunisticEncryption,
        a: &ConnectionConfig,
        b: &ConnectionConfig,
    ) -> cmp::Ordering {
        let a_protocol = a.protocol.to_protocol();
        let b_protocol = b.protocol.to_protocol();

        // When opportunistic encryption is in-play, prioritize encrypted protocols
        // that have recent successful connections
        if opportunistic_encryption.is_enabled() {
            let a_recent_enc_success = a_protocol.is_encrypted()
                && encrypted_transport_state.recent_success(
                    ip,
                    a_protocol,
                    opportunistic_encryption,
                );
            let b_recent_enc_success = b_protocol.is_encrypted()
                && encrypted_transport_state.recent_success(
                    ip,
                    b_protocol,
                    opportunistic_encryption,
                );

            match (a_recent_enc_success, b_recent_enc_success) {
                (true, false) => return cmp::Ordering::Less,
                (false, true) => return cmp::Ordering::Greater,
                // When both have recent success or neither do, continue with normal ordering
                _ => {}
            }
        }

        // Default protocol ordering: UDP first, then others
        match (a_protocol, b_protocol) {
            (ap, bp) if ap == bp => cmp::Ordering::Equal,
            (Protocol::Udp, _) => cmp::Ordering::Less,
            (_, Protocol::Udp) => cmp::Ordering::Greater,
            _ => cmp::Ordering::Equal,
        }
    }
}
