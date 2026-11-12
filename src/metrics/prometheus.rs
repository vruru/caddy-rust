use super::{Process, Registry};
use anyhow::{Result, ensure};
use std::{
    collections::BTreeMap,
    net::ToSocketAddrs,
    sync::{Arc, Mutex, Weak},
};
use tokio::{net::TcpListener, sync::OwnedSemaphorePermit};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
#[derive(Default)]
pub(super) struct Servers(Mutex<BTreeMap<String, Weak<Server>>>);
struct Listener {
    socket: TcpListener,
    _credit: OwnedSemaphorePermit,
}
pub(super) struct Server {
    listener: Mutex<Option<Arc<Listener>>>,
    process: Weak<Process>,
    key: String,
    active: Mutex<Option<(Weak<()>, Weak<Registry>)>>,
    cancel: CancellationToken,
    started: std::sync::OnceLock<()>,
    tasks: TaskTracker,
    connections: Arc<tokio::sync::Semaphore>,
    connection_state: Arc<tokio::sync::Semaphore>,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Some(process) = self.process.upgrade() {
            let mut cache = process
                .prom_servers
                .0
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if cache
                .get(&self.key)
                .is_some_and(|weak| std::ptr::eq(weak.as_ptr(), self))
            {
                cache.remove(&self.key);
            }
        }
    }
}
impl Servers {
    pub fn prepare(&self, process: &Arc<Process>) -> Result<Arc<Server>> {
        let host =
            std::env::var("OTEL_EXPORTER_PROMETHEUS_HOST").unwrap_or_else(|_| "localhost".into());
        let port = std::env::var("OTEL_EXPORTER_PROMETHEUS_PORT")
            .unwrap_or_else(|_| "9464".into())
            .parse::<u16>()?;
        ensure!(host.len() <= 4096, "Prometheus host exceeds limit");
        let key = format!("{host}:{port}");
        // Preparation runs in the bounded metadata lane. Do not hold the
        // cache mutex across address resolution or binding: final-owner Drop
        // also removes its cache entry.
        let mut servers = self.0.lock().unwrap_or_else(|e| e.into_inner());
        servers.retain(|_, server| server.strong_count() > 0);
        if let Some(server) = servers
            .get(&key)
            .and_then(Weak::upgrade)
            .filter(|server| !server.cancel.is_cancelled())
        {
            return Ok(server);
        }
        drop(servers);
        // At most 16 live endpoints and two bounded 4102-byte keys per
        // endpoint. Cache nodes are prepaid by the process's fixed 256 KiB.

        let credit = process.prom_listeners.clone().try_acquire_owned()?;
        let mut listener = None;
        let mut last = None;
        for address in (host.as_str(), port).to_socket_addrs()?.take(128) {
            match std::net::TcpListener::bind(address) {
                Ok(socket) => {
                    listener = Some(socket);
                    break;
                }
                Err(error) => last = Some(error),
            }
        }
        let socket = listener.ok_or_else(|| {
            last.unwrap_or_else(|| std::io::Error::other("Prometheus host has no address"))
        })?;
        socket.set_nonblocking(true)?;
        let server = Arc::new(Server {
            process: Arc::downgrade(process),
            key: key.clone(),
            listener: Mutex::new(Some(Arc::new(Listener {
                socket: TcpListener::from_std(socket)?,
                _credit: credit,
            }))),
            active: Mutex::new(None),
            cancel: CancellationToken::new(),
            started: std::sync::OnceLock::new(),
            tasks: TaskTracker::new(),
            connections: process.prom_connections.clone(),
            connection_state: process.request_bytes.clone(),
        });
        let mut servers = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(existing) = servers
            .get(&key)
            .and_then(Weak::upgrade)
            .filter(|server| !server.cancel.is_cancelled())
        {
            return Ok(existing);
        }
        servers.insert(key, Arc::downgrade(&server));
        Ok(server)
    }
}
impl Server {
    pub fn activate(self: &Arc<Self>, owner: &Arc<()>, registry: &Arc<Registry>) {
        *self.active.lock().unwrap_or_else(|e| e.into_inner()) =
            Some((Arc::downgrade(owner), Arc::downgrade(registry)));
        self.started.get_or_init(||{
            let Some(listener)=self.listener.lock().unwrap_or_else(|e|e.into_inner()).as_ref().cloned()else{return;};let cancel=self.cancel.clone();let weak=Arc::downgrade(self);let tasks=self.tasks.clone();let connections=self.connections.clone();let state=self.connection_state.clone();
            self.tasks.spawn(async move{
                loop{
                    let accepted=tokio::select!{biased;_=cancel.cancelled()=>break,result=listener.socket.accept()=>result};
                    let Ok((stream,_))=accepted else{continue;};let Ok(credit)=connections.clone().try_acquire_owned()else{continue;};let Ok(bytes)=state.clone().try_acquire_many_owned(256<<10)else{continue;};let weak=weak.clone();let cancel=cancel.clone();
                    tasks.spawn(async move{
                        let _credit=credit;let _bytes=bytes;
                        let service=hyper::service::service_fn(move|request:http::Request<hyper::body::Incoming>|{
                            let registry=weak.upgrade().and_then(|server|server.active.lock().unwrap_or_else(|e|e.into_inner()).as_ref().and_then(|(_,registry)|registry.upgrade()));
                            async move{
                                let response=if request.uri().path()=="/metrics"{
                                    if let Some(registry)=registry{registry.scrape_auto(request.headers()).await}else{failure(503,"metrics generation unavailable\n")}
                                }else{failure(404,"404 page not found\n")};Ok::<_,std::convert::Infallible>(response)
                            }
                        });
                        let io=crate::http_runtime::timeout_io::TimeoutIo::new(hyper_util::rt::TokioIo::new(stream),Some(std::time::Duration::from_secs(120)),Some(std::time::Duration::from_secs(10)));
                        let connection=hyper::server::conn::http1::Builder::new().max_buf_size(64<<10).timer(hyper_util::rt::TokioTimer::new()).header_read_timeout(std::time::Duration::from_secs(5)).serve_connection(io,service);
                        tokio::pin!(connection);
                        tokio::select!{_= &mut connection=>{},_=cancel.cancelled()=>{connection.as_mut().graceful_shutdown();let _=tokio::time::timeout(std::time::Duration::from_secs(10),connection).await;}}
                    });
                }
            });
        });
    }
    pub async fn retire(&self, owner: &Arc<()>) {
        let current = {
            let mut active = self.active.lock().unwrap_or_else(|e| e.into_inner());
            if active
                .as_ref()
                .is_some_and(|(id, _)| id.ptr_eq(&Arc::downgrade(owner)))
            {
                active.take();
                true
            } else {
                false
            }
        };
        if current {
            self.cancel.cancel();
            self.tasks.close();
            self.tasks.wait().await;
            // A retained registry may still hold this retired Server. Its Arc
            // must not keep a dead endpoint bound or block a fresh generation.
            let listener = self
                .listener
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take();
            drop(listener);
        }
    }
}
fn failure(code: u16, message: &'static str) -> http::Response<crate::http_runtime::Body> {
    use http_body_util::BodyExt;
    let mut response = http::Response::new(
        http_body_util::Full::new(bytes::Bytes::from_static(message.as_bytes()))
            .map_err(|never| match never {})
            .boxed_unsync(),
    );
    *response.status_mut() = http::StatusCode::from_u16(code).expect("static status");
    response
}
