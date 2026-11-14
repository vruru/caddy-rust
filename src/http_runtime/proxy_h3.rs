//! Upstream HTTP/3. A cached connection and each response own their QUIC I/O.
use super::{
    Body, BoxError,
    http_dial::{Family, FamilyResolver},
    proxy_dynamic::DnsShared,
    proxy_transport::{LocalAddress, Settings},
};
use anyhow::{Result, ensure};
use bytes::{Buf, Bytes};
use http::{Request, Response, Uri, Version};
use http_body_util::BodyExt;
use hyper::body::{Body as HttpBody, Frame};
use std::{
    collections::HashMap,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio::sync::{Notify, OnceCell};
use tokio_util::sync::CancellationToken;
use tower_service::Service;
type Sender = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;
type Receiver = h3::client::RequestStream<h3_quinn::RecvStream, Bytes>;
#[derive(Clone)]
pub(super) struct Pool {
    inner: Arc<Inner>,
}
struct Inner {
    settings: Arc<Settings>,
    tls: rustls::ClientConfig,
    managed: Option<Arc<crate::tls_app_config::ManagedClientSource>>,
    dns: Arc<DnsShared>,
    cache: Mutex<Cache>,
    handshake: Option<Duration>,
    dial: Duration,
}
struct Cache {
    bytes: usize,
    entries: HashMap<
        String,
        (
            Arc<OnceCell<Arc<Entry>>>,
            Arc<native_write_policy::Lease>,
            usize,
            Option<Arc<super::map_runtime::DialOwner>>,
        ),
    >,
}
struct Entry {
    sender: Sender,
    connection: quinn::Connection,
    _endpoint: quinn::Endpoint,
    binding: Option<Arc<crate::tls_app_config::ClientBinding>>,
    activity: Arc<Activity>,
    _permit: Option<Arc<tokio::sync::OwnedSemaphorePermit>>,
    _metadata: Option<Arc<native_write_policy::Lease>>,
    _map: Option<Arc<super::map_runtime::DialOwner>>,
}
// Actual protocol/IO owners precede every loan. The driver holds the same
// loans after cache retirement, without retaining Entry or creating a cycle.
struct DriverOwner {
    driver: h3::client::Connection<h3_quinn::Connection, Bytes>,
    connection: quinn::Connection,
    _endpoint: quinn::Endpoint,
    activity: Arc<Activity>,
    stop: CancellationToken,
    idle: i64,
    _permit: Option<Arc<tokio::sync::OwnedSemaphorePermit>>,
    _metadata: Option<Arc<native_write_policy::Lease>>,
    _map: Option<Arc<super::map_runtime::DialOwner>>,
}
impl Drop for DriverOwner {
    fn drop(&mut self) {
        self.connection
            .close(0u32.into(), b"upstream driver retired");
    }
}
impl DriverOwner {
    async fn run(mut self) {
        let activity = self.activity.clone();
        let idle = self.idle;
        let idle_watch = async {
            loop {
                let until = {
                    let last = *activity.last.lock().unwrap_or_else(|e| e.into_inner());
                    if idle > 0 && activity.active.load(Ordering::Acquire) == 0 {
                        last.checked_add(Duration::from_nanos(idle as u64))
                    } else {
                        None
                    }
                };
                match until {
                    Some(until) => {
                        tokio::select! {_=activity.changed.notified()=>{},_=tokio::time::sleep_until(until.into())=>{if activity.active.load(Ordering::Acquire)==0{break}}}
                    }
                    None => activity.changed.notified().await,
                }
            }
        };
        tokio::select! {_=self.driver.wait_idle()=>{},_=self.stop.cancelled()=>{},_=idle_watch=>{}}
        self.connection
            .close(0u32.into(), b"upstream idle or stopped");
        // self owns every physical field and is destroyed before its loans.
    }
}
struct Activity {
    active: AtomicUsize,
    last: Mutex<Instant>,
    changed: Notify,
}
struct Active {
    entry: Arc<Entry>,
}
impl Drop for Active {
    fn drop(&mut self) {
        *self
            .entry
            .activity
            .last
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Instant::now();
        self.entry.activity.active.fetch_sub(1, Ordering::AcqRel);
        self.entry.activity.changed.notify_one();
    }
}
impl Drop for Entry {
    fn drop(&mut self) {
        self.connection.close(0u32.into(), b"upstream retired");
    }
}
impl Pool {
    pub(super) fn new(
        settings: Arc<Settings>,
        mut tls: rustls::ClientConfig,
        managed: Option<Arc<crate::tls_app_config::ManagedClientSource>>,
        dns: Arc<DnsShared>,
        handshake: Option<Duration>,
        dial: Duration,
    ) -> Self {
        tls.alpn_protocols = vec![b"h3".to_vec()];
        Self {
            inner: Arc::new(Inner {
                settings,
                tls,
                managed,
                dns,
                cache: Mutex::new(Cache {
                    bytes: 0,
                    entries: HashMap::new(),
                }),
                handshake,
                dial,
            }),
        }
    }
    async fn connection(
        &self,
        dial: &Uri,
        family: Family,
        name: Option<rustls::pki_types::ServerName<'static>>,
        resources: &super::resource_budget::Resources,
        mapped: bool,
    ) -> Result<Arc<Entry>> {
        let input = dial.to_string().len().saturating_add(1024);
        let _work = if mapped {
            Some(
                resources
                    .map_bytes
                    .reserve(input.saturating_mul(8).saturating_add(8192))?,
            )
        } else {
            None
        };
        let host = dial
            .host()
            .ok_or_else(|| anyhow::anyhow!("missing upstream H3 host"))?;
        let name = name.unwrap_or(rustls::pki_types::ServerName::try_from(
            super::http_dial::tls_host(host).to_owned(),
        )?);
        let sni = match &name {
            rustls::pki_types::ServerName::DnsName(v) => v.as_ref().to_string(),
            rustls::pki_types::ServerName::IpAddress(ip) => std::net::IpAddr::from(*ip).to_string(),
            _ => anyhow::bail!("unsupported H3 server name"),
        };
        let key = format!("{family:?}|{dial}|{sni}");
        let cacheable = self.inner.settings.options.keep_alive.enabled
            && self.inner.settings.options.keep_alive.max_idle_per_host > 0;
        let retired = {
            let mut cache = self
                .inner
                .cache
                .lock()
                .map_err(|_| anyhow::anyhow!("H3 cache unavailable"))?;
            let dead = cache
                .entries
                .iter()
                .filter(|(_, v)| {
                    v.0.get()
                        .is_some_and(|e| e.connection.close_reason().is_some())
                })
                .map(|(k, _)| k.clone())
                .collect::<Vec<_>>();
            let mut retired = Vec::new();
            for key in dead {
                if let Some(v) = cache.entries.remove(&key) {
                    cache.bytes = cache.bytes.saturating_sub(v.2);
                    retired.push(v);
                }
            }
            retired
        };
        drop(retired);
        let hit = {
            self.inner
                .cache
                .lock()
                .map_err(|_| anyhow::anyhow!("H3 cache unavailable"))?
                .entries
                .get(&key)
                .map(|v| (v.0.clone(), Some(v.1.clone()), v.3.clone()))
        };
        let (cell, credit, owner) = if let Some(hit) = hit {
            hit
        } else {
            let cost = input
                .checked_mul(16)
                .and_then(|n| n.checked_add(8192))
                .ok_or_else(|| anyhow::anyhow!("H3 metadata overflow"))?;
            let mut credit = if cost <= 4 << 20 {
                resources
                    .proxy_client_cache_bytes
                    .reserve(cost)
                    .ok()
                    .map(Arc::new)
            } else {
                None
            };
            let mut owner = if mapped {
                let retained = match &credit {
                    Some(c) => c.clone(),
                    None => Arc::new(resources.map_bytes.reserve(cost)?),
                };
                Some(super::map_runtime::DialOwner::new(
                    resources.map_bytes.clone(),
                    retained,
                ))
            } else {
                None
            };
            let mut cell = Arc::new(OnceCell::new());
            if cacheable {
                if let Some(cache_credit) = credit.clone() {
                    let mut cache = self
                        .inner
                        .cache
                        .lock()
                        .map_err(|_| anyhow::anyhow!("H3 cache unavailable"))?;
                    if let Some(existing) = cache.entries.get(&key) {
                        cell = existing.0.clone();
                        credit = Some(existing.1.clone());
                        owner = existing.3.clone();
                    } else if cache.entries.len() < 1024
                        && cache.bytes.saturating_add(cost) <= 4 << 20
                    {
                        cache.bytes += cost;
                        cache
                            .entries
                            .insert(key, (cell.clone(), cache_credit, cost, owner.clone()));
                    }
                }
            }
            (cell, credit, owner)
        };
        let entry = cell
            .get_or_try_init(|| {
                self.open(
                    dial,
                    family,
                    &sni,
                    resources.proxy_dial_dns.clone(),
                    credit,
                    owner,
                )
            })
            .await?
            .clone();
        if let Some(binding) = &entry.binding {
            binding.check()?
        }
        Ok(entry)
    }
    async fn open(
        &self,
        dial: &Uri,
        family: Family,
        sni: &str,
        dns_budget: super::resource_budget::BlockingBudget,
        credit: Option<Arc<native_write_policy::Lease>>,
        owner: Option<Arc<super::map_runtime::DialOwner>>,
    ) -> Result<Arc<Entry>> {
        let host = super::http_dial::tls_host(
            dial.host()
                .ok_or_else(|| anyhow::anyhow!("missing H3 host"))?,
        );
        let port = dial.port_u16().unwrap_or(443);
        let mut resolver = match &owner {
            Some(owner) => FamilyResolver::with_map(family, dns_budget, owner.clone()),
            None => FamilyResolver::new(family),
        };
        if !self.inner.settings.options.resolvers.is_empty() {
            resolver = resolver.with_custom(
                self.inner.dns.clone(),
                self.inner.settings.options.resolvers.clone(),
                self.inner.dial,
                self.inner.settings.options.fallback_ns,
            );
        }
        let addresses = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            vec![std::net::SocketAddr::new(ip, port)]
        } else {
            resolver
                .call(host.parse()?)
                .await?
                .map(|mut a| {
                    a.set_port(port);
                    a
                })
                .collect::<Vec<_>>()
        };
        let mut addresses = addresses.into_iter().filter_map(|a| family.admit(a));
        let peer = addresses
            .next()
            .ok_or_else(|| anyhow::anyhow!("no upstream H3 address"))?;
        let local = match &self.inner.settings.local {
            Some(LocalAddress::Tcp(a)) => *a,
            Some(LocalAddress::Unix(_)) => anyhow::bail!("H3 needs an IP local address"),
            None => {
                if peer.is_ipv4() {
                    "0.0.0.0:0".parse()?
                } else {
                    "[::]:0".parse()?
                }
            }
        };
        ensure!(
            local.is_ipv4() == peer.is_ipv4(),
            "H3 local address family mismatch"
        );
        let gate = self.inner.settings.gate(&dial.to_string())?;
        let permit = match gate {
            Some(gate) => Some(Arc::new(gate.acquire_owned().await?)),
            None => None,
        };
        let mut tls = self.inner.tls.clone();
        let binding = self.inner.managed.as_ref().map(|s| s.binding());
        if let Some(binding) = &binding {
            tls.client_auth_cert_resolver = binding.clone();
        }
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)?;
        let mut endpoint = quinn::Endpoint::client(local)?;
        endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
        let connecting = endpoint.connect(peer, sni)?;
        let connection = if let Some(timeout) = self.inner.handshake.filter(|d| !d.is_zero()) {
            tokio::time::timeout(timeout, connecting).await??
        } else {
            connecting.await?
        };
        if let Some(binding) = &binding {
            binding.check()?
        }
        let mut builder = h3::client::builder();
        builder.max_field_section_size(self.inner.settings.options.max_header_bytes as u64);
        let (driver, sender) = builder
            .build(h3_quinn::Connection::new(connection.clone()))
            .await?;
        let activity = Arc::new(Activity {
            active: AtomicUsize::new(0),
            last: Mutex::new(Instant::now()),
            changed: Notify::new(),
        });
        let driver_owner = DriverOwner {
            driver,
            connection: connection.clone(),
            _endpoint: endpoint.clone(),
            activity: activity.clone(),
            stop: self.inner.dns.transport_stop(),
            idle: self.inner.settings.options.keep_alive.idle_ns,
            _permit: permit.clone(),
            _metadata: credit.clone(),
            _map: owner.clone(),
        };
        self.inner.dns.transport_tasks().spawn(driver_owner.run());
        Ok(Arc::new(Entry {
            _metadata: credit,
            _map: owner,
            sender,
            connection,
            _endpoint: endpoint,
            binding,
            activity,
            _permit: permit,
        }))
    }
    pub(super) async fn fetch(
        &self,
        dial: &Uri,
        family: Family,
        name: Option<rustls::pki_types::ServerName<'static>>,
        request: Request<Body>,
        timeout: Option<i64>,
        resources: &super::resource_budget::Resources,
        mapped: bool,
    ) -> Result<Response<Body>> {
        let entry = self
            .connection(dial, family, name, resources, mapped)
            .await?;
        entry.activity.active.fetch_add(1, Ordering::AcqRel);
        entry.activity.changed.notify_one();
        let active = Arc::new(Active {
            entry: entry.clone(),
        });
        let (mut parts, body) = request.into_parts();
        parts.version = Version::HTTP_3;
        // NativeConnectBody carries the genuine authority-form target across the
        // normal reverse-proxy request builder. H3 plain CONNECT has no :path.
        if let Some(connect) = parts.extensions.get::<hyper::ext::NativeConnectBody>() {
            parts.uri = connect.target.clone();
        }
        let mut sender = entry.sender.clone();
        let stream = sender.send_request(Request::from_parts(parts, ())).await?;
        let (mut send, mut recv) = stream.split();
        let cancel = CancellationToken::new();
        let _cancel_on_drop = CancelOnDrop(cancel.clone());
        let upload_cancel = cancel.clone();
        let retain = active.clone();
        let binding = entry.binding.clone();
        let (sent, mut done) = tokio::sync::oneshot::channel();
        self.inner.dns.transport_tasks().spawn(async move{
   let output={let result=async{let mut body=body;while let Some(frame)=body.frame().await{if let Some(binding)=&binding{binding.check()?}let frame=frame?;match frame.into_data(){Ok(mut data)=>while !data.is_empty(){let n=data.len().min(16384);send.send_data(data.split_to(n)).await?},Err(frame)=>if let Ok(trailers)=frame.into_trailers(){send.send_trailers(trailers).await?;return Ok::<_,BoxError>(())}}}send.finish().await?;Ok::<_,BoxError>(())};
   tokio::pin!(result);tokio::select!{biased;_=upload_cancel.cancelled()=>None,result=&mut result=>Some(result)}};
   // Drop the sending future before reset/lease release; it owns borrowed IO.

   if output.is_none(){send.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);}
   let _=sent.send(output.unwrap_or_else(||Err(std::io::Error::other("H3 upload cancelled").into())));drop(retain);
  });
        let response = {
            let response = recv.recv_response();
            tokio::pin!(response);
            tokio::select! {biased;result=&mut response=>result.map_err(anyhow::Error::new),upload=&mut done=>{
             match upload{Ok(Ok(()))=>{},Ok(Err(error))=>{cancel.cancel();return Err(anyhow::Error::from_boxed(error))},Err(error)=>{cancel.cancel();return Err(error.into())}}
             if let Some(ns)=timeout.filter(|n|*n>0){tokio::time::timeout(Duration::from_nanos(ns as u64),&mut response).await.map_err(|_|super::request::failure(http::StatusCode::GATEWAY_TIMEOUT))?.map_err(anyhow::Error::new)}else{response.await.map_err(anyhow::Error::new)}
            }}
        };
        match response {
            Ok(mut response) => {
                *response.version_mut() = Version::HTTP_3;
                Ok(response.map(|_| {
                    H3Body {
                        recv,
                        cancel,
                        active: Some(active),
                        data_done: false,
                        done: false,
                    }
                    .boxed_unsync()
                }))
            }
            Err(error) => {
                cancel.cancel();
                Err(error)
            }
        }
    }
}
struct H3Body {
    recv: Receiver,
    cancel: CancellationToken,
    active: Option<Arc<Active>>,
    data_done: bool,
    done: bool,
}
impl HttpBody for H3Body {
    type Data = Bytes;
    type Error = BoxError;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        if self.done {
            return Poll::Ready(None);
        }
        if let Some(binding) = self.active.as_ref().and_then(|a| a.entry.binding.as_ref()) {
            if let Err(e) = binding.check() {
                self.done = true;
                self.cancel.cancel();
                return Poll::Ready(Some(Err(e.into())));
            }
        }
        if !self.data_done {
            match self.recv.poll_recv_data(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(Some(mut data))) => {
                    let n = data.remaining();
                    return Poll::Ready(Some(Ok(Frame::data(data.copy_to_bytes(n)))));
                }
                Poll::Ready(Ok(None)) => self.data_done = true,
                Poll::Ready(Err(error)) => {
                    self.done = true;
                    self.cancel.cancel();
                    return Poll::Ready(Some(Err(error.into())));
                }
            }
        }
        match self.recv.poll_recv_trailers(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                self.done = true;
                self.active.take();
                Poll::Ready(match result {
                    Ok(Some(h)) => Some(Ok(Frame::trailers(h))),
                    Ok(None) => None,
                    Err(e) => Some(Err(e.into())),
                })
            }
        }
    }
    fn is_end_stream(&self) -> bool {
        self.done
    }
}
impl Drop for H3Body {
    fn drop(&mut self) {
        self.cancel.cancel();
        if !self.done {
            self.recv
                .stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
        }
    }
}

struct CancelOnDrop(CancellationToken);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}
