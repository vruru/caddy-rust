//! Each DATA owner retains its prepaid batch. Absolute deadlines cancel and
//! join the actual connection epoch; a completed response is not a body fence.
use bytes::Bytes;
use hyper::body::{Frame, Incoming};
use hyper_util::client::legacy::Client as HyperClient;
use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};
use tokio::sync::OwnedSemaphorePermit;
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tonic::body::Body as TonicBody;
type Client = HyperClient<crate::http_runtime::metrics_client::Connector, OwnedBody>;
type Error = Box<dyn std::error::Error + Send + Sync>;
#[derive(Clone)]
struct Executor {
    tasks: TaskTracker,
    handle: tokio::runtime::Handle,
}
impl<F> hyper::rt::Executor<F> for Executor
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    fn execute(&self, future: F) {
        self.tasks.spawn_on(future, &self.handle);
    }
}
struct Epoch {
    client: Mutex<Option<Client>>,
    cancel: CancellationToken,
    tasks: TaskTracker,
    scope: crate::outgoing_tls::ScopeOwner,
}
impl Epoch {
    async fn shutdown(&self) {
        self.cancel.cancel();
        self.scope.close();
        let client = self.client.lock().unwrap_or_else(|e| e.into_inner()).take();
        drop(client);
        self.tasks.close();
        self.tasks.wait().await;
        self.scope.wait().await;
    }
}
impl Drop for Epoch {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}
pub(super) struct Transport {
    current: Mutex<Option<Arc<Epoch>>>,
    connector: crate::http_runtime::metrics_client::Connector,
    timeout: Duration,
    h2: bool,
    cancel: CancellationToken,
    tasks: TaskTracker,
}
impl Transport {
    pub(super) fn new(
        connector: crate::http_runtime::metrics_client::Connector,
        timeout: Duration,
        h2: bool,
    ) -> Arc<Self> {
        Arc::new(Self {
            current: Mutex::new(None),
            connector,
            timeout,
            h2,
            cancel: CancellationToken::new(),
            tasks: TaskTracker::new(),
        })
    }
    fn epoch(&self) -> Result<Arc<Epoch>, Error> {
        if self.cancel.is_cancelled() {
            return Err(std::io::Error::other("OTLP exporter stopped").into());
        }
        {
            let current = self.current.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(epoch) = current.as_ref().filter(|e| !e.cancel.is_cancelled()) {
                return Ok(epoch.clone());
            }
        }
        let cancel = CancellationToken::new();
        let (connector, scope) = self.connector.epoch(cancel.clone())
            .map_err(|e| e.reallocate_into_boxed_dyn_error_without_backtrace())?;
        let tasks = TaskTracker::new();
        let client = HyperClient::builder(Executor {
            tasks: tasks.clone(), handle: tokio::runtime::Handle::current(),
        }).http2_only(self.h2).pool_idle_timeout(self.timeout).build(connector);
        let candidate = Arc::new(Epoch { client: Mutex::new(Some(client)), cancel, tasks, scope });
        let (selected, previous) = {
            let mut current = self.current.lock().unwrap_or_else(|e| e.into_inner());
            if self.cancel.is_cancelled() { (None, None) }
            else if let Some(epoch) = current.as_ref().filter(|e| !e.cancel.is_cancelled()) {
                (Some(epoch.clone()), None)
            } else {
                (Some(candidate.clone()), current.replace(candidate.clone()))
            }
        };
        // A losing/newly retired Epoch cancels IO and may synchronously wake;
        // its final owner is never destroyed under the current-epoch mutex.
        drop(previous);
        drop(candidate);
        selected.ok_or_else(|| std::io::Error::other("OTLP exporter stopped").into())
    }
    fn deadline(&self, epoch: Arc<Epoch>, credit: &Arc<Credit>) {
        if credit
            .deadline_started
            .swap(true, std::sync::atomic::Ordering::AcqRel)
        {
            return;
        }
        let done = credit.done.clone();
        let deadline = credit
            .created
            .checked_add(self.timeout)
            .expect("validated exporter timeout");
        let timer = credit
            .timer_credit
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        self.tasks.spawn(async move{let _timer=timer;tokio::select!{biased;_=done.cancelled()=>{},_=tokio::time::sleep_until(deadline)=>epoch.shutdown().await}});
    }
    pub(super) async fn send(
        &self,
        request: http::Request<TonicBody>,
        credit: Arc<Credit>,
    ) -> Result<http::Response<Incoming>, Error> {
        if credit.created.elapsed() >= self.timeout {
            return Err(
                std::io::Error::new(std::io::ErrorKind::TimedOut, "OTLP export deadline").into(),
            );
        }
        let epoch = self.epoch()?;
        self.deadline(epoch.clone(), &credit);
        let client = epoch
            .client
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .cloned()
            .ok_or_else(|| std::io::Error::other("OTLP transport deadline"))?;
        let response = client
            .request(request.map(|inner| OwnedBody { inner, credit }))
            .await?;
        Ok(response)
    }
    pub(super) fn proxy_authorization(&self) -> Option<http::HeaderValue> {
        self.connector.proxy_authorization()
    }
    pub(super) async fn shutdown(&self) {
        self.cancel.cancel();
        let epoch = self
            .current
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(epoch) = epoch {
            epoch.shutdown().await;
        }
        self.tasks.close();
        self.tasks.wait().await;
    }
}
impl Drop for Transport {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Some(epoch) = self
            .current
            .get_mut()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            epoch.cancel.cancel();
        }
    }
}
#[derive(Debug)]
pub(super) struct Credit {
    _scratch: Option<OwnedSemaphorePermit>,
    pub(super) _metadata: Arc<super::budget::Metadata>,
    memory: Option<Arc<BatchMemory>>,
    pub(super) created: tokio::time::Instant,
    pub(super) done: tokio_util::sync::CancellationToken,
    pub(super) deadline_started: std::sync::atomic::AtomicBool,
    pub(super) timer_credit: std::sync::Mutex<Option<OwnedSemaphorePermit>>,
}

/// Trace-only data lifetime. Pins must not retain Credit itself: its Drop
/// controls the original IO deadline and retained-DATA retry predicate.
#[derive(Debug)]
pub(super) struct BatchMemory {
    _scratch: OwnedSemaphorePermit,
    _metadata: Arc<super::budget::Metadata>,
    _control: Arc<super::distributed_trace::processor::Credit>,
}
impl Credit {
    pub(super) fn new(scratch: OwnedSemaphorePermit, metadata: Arc<super::budget::Metadata>, timer: OwnedSemaphorePermit) -> Self {
        Self { _scratch: Some(scratch), _metadata: metadata, memory: None,
            created: tokio::time::Instant::now(), done: CancellationToken::new(),
            deadline_started: Default::default(), timer_credit: Mutex::new(Some(timer)) }
    }
    /// Native trace CPU producers only; layout is paid before the extra Arc.
    pub(super) fn trace(
        scratch: OwnedSemaphorePermit,
        metadata: Arc<super::budget::Metadata>,
        timer: OwnedSemaphorePermit,
        source: &Arc<super::distributed_trace::processor::Process>,
        created: tokio::time::Instant,
    ) -> anyhow::Result<Self> {
        let layout = std::mem::size_of::<BatchMemory>()
            .checked_add(std::mem::size_of::<super::distributed_trace::processor::Credit>())
            .and_then(|n| n.checked_add(4 * std::mem::size_of::<usize>()))
            .ok_or_else(|| anyhow::anyhow!("trace batch memory layout overflow"))?;
        let control = source.metadata(layout)?;
        let memory = Arc::new(BatchMemory { _scratch: scratch, _metadata: metadata.clone(), _control: control });
        Ok(Self { _scratch: None, _metadata: metadata, memory: Some(memory),
            created, done: CancellationToken::new(),
            deadline_started: Default::default(), timer_credit: Mutex::new(Some(timer)) })
    }
    pub(super) fn memory(&self) -> anyhow::Result<Arc<BatchMemory>> {
        self.memory.clone().ok_or_else(|| anyhow::anyhow!("trace batch memory unavailable"))
    }
}

impl Drop for Credit {
    fn drop(&mut self) {
        self.done.cancel();
    }
}

pub(super) struct OwnedBody {
    inner: TonicBody,
    credit: Arc<Credit>,
}

pub(super) struct OwnedBytes {
    pub(super) data: Bytes,
    pub(super) _credit: Arc<Credit>,
    pub(super) _attempt: Option<Arc<()>>,
}

impl AsRef<[u8]> for OwnedBytes {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl hyper::body::Body for OwnedBody {
    type Data = Bytes;
    type Error = tonic::Status;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let me = self.get_mut();

        match Pin::new(&mut me.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                Ok(data) => {
                    let owned = OwnedBytes {
                        data,
                        _credit: me.credit.clone(),
                        _attempt: None,
                    };
                    Poll::Ready(Some(Ok(Frame::data(Bytes::from_owner(owned)))))
                }
                Err(frame) => Poll::Ready(Some(Ok(frame))),
            },
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}
