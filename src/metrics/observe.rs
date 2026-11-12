use super::{
    budget::Lease,
    config,
    registry::{Base, Registry},
};
use std::{
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering},
    },
    time::Instant,
};
use tokio::sync::OwnedSemaphorePermit;
const ROUTES_PER_REQUEST: usize = 64;
/// A writer layer owns its own measurements. Inner template/intercept/encode
/// writers can finish before their outer representation reaches the transport.
pub(crate) struct Observation {
    registry: Arc<Registry>,
    base: Arc<Base>,
    method: &'static str,
    start: Instant,
    bytes: AtomicU64,
    request: AtomicU64,
    code: AtomicU16,
    returned: AtomicBool,
    completed: AtomicBool,
    headers: AtomicBool,
    finished: AtomicBool,
    _credit: OwnedSemaphorePermit,
}
impl Observation {
    pub fn returned(&self, request: u64) {
        self.request.store(request, Ordering::Relaxed);
        self.returned.store(true, Ordering::Release);
    }
    pub fn complete(&self, code: u16, explicit: bool) {
        self.code.store(code, Ordering::Relaxed);
        self.completed.store(true, Ordering::Release);
        if explicit && !self.headers.swap(true, Ordering::AcqRel) {
            self.registry.histogram(
                &self.base,
                self.method,
                code,
                3,
                self.start.elapsed().as_secs_f64(),
            );
        }
    }
    fn finish_error(&self, code: Option<u16>, request: u64) {
        if !self.finished.swap(true, Ordering::AcqRel) {
            self.registry.finish(
                &self.base,
                self.method,
                code,
                self.start.elapsed().as_secs_f64(),
                request,
                self.bytes.load(Ordering::Relaxed),
                true,
            );
        }
    }
    fn abandon(&self) {
        if !self.finished.swap(true, Ordering::AcqRel) {
            self.base.in_flight.fetch_sub(1, Ordering::Relaxed);
            self.registry
                .process
                .dropped
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    fn frame(&self) -> Option<OwnedSemaphorePermit> {
        match self
            .registry
            .process
            .request_bytes
            .clone()
            .try_acquire_many_owned(256)
        {
            Ok(credit) => Some(credit),
            Err(_) => {
                self.abandon();
                None
            }
        }
    }
    fn add_bytes(&self, n: usize) {
        let _ = self
            .bytes
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |old| {
                Some(old.saturating_add(n as u64))
            });
    }
}
impl Drop for Observation {
    fn drop(&mut self) {
        if !self.finished.swap(true, Ordering::AcqRel) {
            let code = (self.completed.load(Ordering::Acquire)
                || self.returned.load(Ordering::Acquire))
            .then(|| self.code.load(Ordering::Relaxed));
            self.registry.finish(
                &self.base,
                self.method,
                code,
                self.start.elapsed().as_secs_f64(),
                self.request.load(Ordering::Relaxed),
                self.bytes.load(Ordering::Relaxed),
                false,
            );
        }
    }
}
/// Weak writer identities support error-suffix unwinding without extending the
/// successful lifetime of inner buffered writers to the outermost transport.
pub(crate) struct Group {
    registry: Arc<Registry>,
    active: Mutex<Vec<Weak<Observation>>>,
    _lease: Lease,
}
impl Group {
    pub fn new(registry: Arc<Registry>, _request: u64) -> Option<Arc<Self>> {
        if !registry.enabled() {
            return None;
        }
        let lease = registry.request_lease()?;
        Some(Arc::new(Self {
            registry,
            active: Mutex::new(Vec::new()),
            _lease: lease,
        }))
    }
    pub fn begin(
        &self,
        server: Arc<str>,
        handler: Arc<str>,
        host: &str,
        tls: bool,
        method: &str,
    ) -> Option<(usize, Arc<Observation>)> {
        let bytes = host
            .len()
            .checked_add(server.len())
            .and_then(|n| n.checked_add(handler.len()))
            .and_then(|n| n.checked_mul(8))
            .and_then(|n| n.checked_add(256));
        if bytes.is_none_or(|bytes| !self._lease.grow(bytes)) {
            self.registry
                .process
                .dropped
                .fetch_add(1, Ordering::Relaxed);
            return None;
        }
        let key = self.registry.key(server, handler, host, tls);
        let base = self.registry.base(key)?;
        let mut active = self.active.lock().unwrap_or_else(|e| e.into_inner());
        let credit = self
            .registry
            .process
            .request_bytes
            .clone()
            .try_acquire_many_owned(512)
            .ok();
        if active.len() >= ROUTES_PER_REQUEST || credit.is_none() || !self._lease.grow(64) {
            self.registry
                .process
                .dropped
                .fetch_add(1, Ordering::Relaxed);
            return None;
        }
        let marker = active.len();
        base.in_flight.fetch_add(1, Ordering::Relaxed);
        let observation = Arc::new(Observation {
            registry: self.registry.clone(),
            base,
            method: config::method(method),
            start: Instant::now(),
            bytes: AtomicU64::new(0),
            request: AtomicU64::new(0),
            code: AtomicU16::new(200),
            returned: AtomicBool::new(false),
            completed: AtomicBool::new(false),
            headers: AtomicBool::new(false),
            finished: AtomicBool::new(false),
            _credit: credit.expect("admitted observation"),
        });
        active.push(Arc::downgrade(&observation));
        Some((marker, observation))
    }
    pub fn error_from(&self, marker: Option<usize>, status: Option<u16>, request: u64) {
        let Some(marker) = marker else {
            return;
        };
        let mut active = self.active.lock().unwrap_or_else(|e| e.into_inner());
        let marker = marker.min(active.len());
        for observation in active.drain(marker..).filter_map(|o| o.upgrade()) {
            if !observation.returned.load(Ordering::Acquire) {
                observation.finish_error(status, request);
            }
        }
    }
    pub fn mark(&self) -> usize {
        self.active.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
    pub fn scope(&self, mark: usize) -> Option<Scope> {
        let active = self.active.lock().unwrap_or_else(|e| e.into_inner());
        let values = active.get(mark..).unwrap_or_default();
        if !values.iter().any(|v| v.strong_count() > 0) {
            return None;
        }
        let credit = match self
            .registry
            .process
            .request_bytes
            .clone()
            .try_acquire_many_owned(1024)
        {
            Ok(credit) => credit,
            Err(_) => {
                for observation in values.iter().filter_map(Weak::upgrade) {
                    observation.abandon();
                }
                return None;
            }
        };
        Some(Scope {
            process: self.registry.process.clone(),
            observations: values.to_vec(),
            _credit: credit,
        })
    }
    pub fn retain_tunnel(&self) -> Option<Tunnel> {
        let active = self.active.lock().unwrap_or_else(|e| e.into_inner());
        let credit = match self
            .registry
            .process
            .request_bytes
            .clone()
            .try_acquire_many_owned(8192)
        {
            Ok(credit) => credit,
            Err(_) => {
                for observation in active.iter().filter_map(Weak::upgrade) {
                    observation.abandon();
                }
                return None;
            }
        };
        Some(Tunnel {
            _observations: active.iter().filter_map(Weak::upgrade).collect(),
            _credit: credit,
        })
    }
}
pub(crate) struct Tunnel {
    _observations: Vec<Arc<Observation>>,
    _credit: OwnedSemaphorePermit,
}
pub(crate) fn attach_body(
    body: crate::http_runtime::Body,
    observation: Arc<Observation>,
) -> crate::http_runtime::Body {
    use http_body_util::BodyExt;
    CountBody {
        body,
        observation: Some(observation),
    }
    .boxed_unsync()
}
struct CountBody {
    body: crate::http_runtime::Body,
    observation: Option<Arc<Observation>>,
}
impl hyper::body::Body for CountBody {
    type Data = bytes::Bytes;
    type Error = crate::http_runtime::BoxError;
    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        match std::pin::Pin::new(&mut self.body).poll_frame(cx) {
            std::task::Poll::Ready(Some(Ok(frame))) => {
                let observation = self.observation.clone();
                std::task::Poll::Ready(Some(Ok(frame.map_data(move |data| {
                    if let Some(observation) = observation {
                        observation.add_bytes(data.len());
                        if let Some(credit) = observation.frame() {
                            return bytes::Bytes::from_owner(TransportBytes {
                                data,
                                _observation: observation,
                                _credit: credit,
                            });
                        }
                    }
                    data
                }))))
            }
            std::task::Poll::Ready(None) => {
                self.observation.take();
                std::task::Poll::Ready(None)
            }
            std::task::Poll::Ready(Some(Err(error))) => {
                if let Some(observation) = &self.observation {
                    observation.abandon();
                }
                self.observation.take();
                std::task::Poll::Ready(Some(Err(error)))
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }
    fn size_hint(&self) -> hyper::body::SizeHint {
        self.body.size_hint()
    }
}
impl Drop for CountBody {
    fn drop(&mut self) {
        // A body may finish without another poll_frame(None), notably a
        // successful empty Full/Incoming body. Other premature drops abandon
        // this writer's observations rather than report a completed request.
        if !hyper::body::Body::is_end_stream(&self.body) {
            if let Some(observation) = &self.observation {
                observation.abandon();
            }
        }
    }
}

struct TransportBytes {
    data: bytes::Bytes,
    _observation: Arc<Observation>,
    _credit: OwnedSemaphorePermit,
}
impl AsRef<[u8]> for TransportBytes {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

pub(crate) struct Scope {
    process: Arc<super::Process>,
    observations: Vec<Weak<Observation>>,
    _credit: OwnedSemaphorePermit,
}
impl Scope {
    pub fn admit_discard(&self) -> Option<OwnedSemaphorePermit> {
        self.process
            .discarded_bodies
            .clone()
            .try_acquire_owned()
            .ok()
    }
    pub fn abandon(&mut self) {
        for observation in self.observations.iter().filter_map(Weak::upgrade) {
            observation.abandon();
        }
    }
}
