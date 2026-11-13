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
    pub(super) _scratch: OwnedSemaphorePermit,
    pub(super) _metadata: Arc<super::budget::Metadata>,
    pub(super) created: tokio::time::Instant,
    pub(super) done: tokio_util::sync::CancellationToken,
    pub(super) deadline_started: std::sync::atomic::AtomicBool,
    pub(super) timer_credit: std::sync::Mutex<Option<OwnedSemaphorePermit>>,
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
