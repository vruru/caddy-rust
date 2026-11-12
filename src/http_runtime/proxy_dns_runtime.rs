// Copyright 2015 Matthew Holt and The Caddy Authors.
// SPDX-License-Identifier: Apache-2.0
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use hickory_resolver::net::runtime::{RuntimeProvider, Spawn, TokioRuntimeProvider};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

#[derive(Clone)]
pub(super) struct TrackedRuntime {
    base: TokioRuntimeProvider,
    custom: Option<super::proxy_dns_exchange::Exchange>,
    dial_timeout_ns: i64,
    exchange_leg: Duration,
    tasks: TaskTracker,
    stop: CancellationToken,
    slots: Arc<Semaphore>,
    rejected: Arc<AtomicU64>,
}

impl TrackedRuntime {
    pub(super) fn with_exchange_leg(mut self, leg: Duration) -> Self {
        self.exchange_leg = leg;
        self
    }
    pub(super) fn with_custom(mut self, source: super::proxy_dns_exchange::Exchange) -> Self {
        self.custom = Some(source);
        self
    }

    pub(super) fn with_dial_timeout(mut self, ns: i64) -> Self {
        self.dial_timeout_ns = ns;
        self
    }
    pub(super) fn new(
        tasks: TaskTracker,
        stop: CancellationToken,
        slots: Arc<Semaphore>,
        rejected: Arc<AtomicU64>,
    ) -> Self {
        Self {
            base: TokioRuntimeProvider::default(),
            custom: None,
            dial_timeout_ns: 0,
            exchange_leg: Duration::from_secs(5),
            tasks,
            stop,
            slots,
            rejected,
        }
    }
}

#[derive(Clone)]
pub(super) struct TrackedHandle {
    tasks: TaskTracker,
    stop: CancellationToken,
    slots: Arc<Semaphore>,
    rejected: Arc<AtomicU64>,
}

impl RuntimeProvider for TrackedRuntime {
    type Handle = TrackedHandle;
    type Timer = <TokioRuntimeProvider as RuntimeProvider>::Timer;
    type Udp = <TokioRuntimeProvider as RuntimeProvider>::Udp;
    type Tcp = super::proxy_dns_stream::DnsStream;

    fn create_handle(&self) -> Self::Handle {
        TrackedHandle {
            tasks: self.tasks.clone(),
            stop: self.stop.clone(),
            slots: self.slots.clone(),
            rejected: self.rejected.clone(),
        }
    }

    fn connect_tcp(
        &self,
        server_addr: SocketAddr,
        bind_addr: Option<SocketAddr>,
        timeout: Option<Duration>,
    ) -> Pin<Box<dyn Send + Future<Output = Result<Self::Tcp, io::Error>>>> {
        if let Some(source) = self.custom.clone() {
            let stop = self.stop.clone();
            let timeout = self.exchange_leg;
            return Box::pin(async move {
                Ok(super::proxy_dns_stream::DnsStream::exchange(
                    source,
                    server_addr,
                    timeout,
                    stop,
                ))
            });
        }
        let timeout = match dial_budget(self.dial_timeout_ns) {
            DialBudget::Expired => return Box::pin(async { Err(dial_expired()) }),
            DialBudget::None => timeout,
            DialBudget::Cap(cap) => Some(timeout.map_or(cap, |existing| existing.min(cap))),
        };
        let base_fut = self.base.connect_tcp(server_addr, bind_addr, timeout);
        let stop = self.stop.clone();
        Box::pin(async move {
            tokio::select! {
                biased;
                _ = stop.cancelled() => Err(io::Error::new(io::ErrorKind::Interrupted, "DNS runtime stopped")),
                res = base_fut => res.map(super::proxy_dns_stream::DnsStream::direct),
            }
        })
    }

    fn bind_udp(
        &self,
        local_addr: SocketAddr,
        server_addr: SocketAddr,
    ) -> Pin<Box<dyn Send + Future<Output = Result<Self::Udp, io::Error>>>> {
        let budget = dial_budget(self.dial_timeout_ns);
        if budget == DialBudget::Expired {
            return Box::pin(async { Err(dial_expired()) });
        }
        let base_fut = self.base.bind_udp(local_addr, server_addr);
        let base_fut = async move {
            match budget {
                DialBudget::Cap(cap) => tokio::time::timeout(cap, base_fut)
                    .await
                    .map_err(|_| dial_expired())?,
                _ => base_fut.await,
            }
        };
        let stop = self.stop.clone();
        Box::pin(async move {
            tokio::select! {
                biased;
                _ = stop.cancelled() => Err(io::Error::new(io::ErrorKind::Interrupted, "DNS runtime stopped")),
                res = base_fut => res,
            }
        })
    }
}

impl Spawn for TrackedHandle {
    fn spawn_bg(&mut self, future: impl Future<Output = ()> + Send + 'static) {
        if self.stop.is_cancelled() {
            drop(future);
            return;
        }
        let permit = match self.slots.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                self.rejected.fetch_add(1, Ordering::Relaxed);
                drop(future);
                return;
            }
        };
        let stop = self.stop.clone();
        self.tasks.spawn(async move {
            let _permit = permit;
            tokio::select! {
                biased;
                _ = stop.cancelled() => {}
                _ = future => {}
            }
        });
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DialBudget {
    None,
    Expired,
    Cap(Duration),
}
pub(super) fn dial_budget(ns: i64) -> DialBudget {
    match ns {
        0 => DialBudget::None,
        n if n < 0 => DialBudget::Expired,
        n => DialBudget::Cap(Duration::from_nanos(n as u64)),
    }
}
fn dial_expired() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "DNS dial timeout")
}
