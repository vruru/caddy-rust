use super::{
    AdminController, AdminError, AdminOptions,
    controller::Inner,
    files, ids,
    policy::{LocalPolicy, OriginPolicy},
    remote::{Grant, Remote, RemoteAccess},
};
use http::{Request, Response, header};
use http_body_util::{BodyExt, Full};
use hyper::{
    body::{Bytes, Incoming},
    service::service_fn,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use rustix::fs::{self, AtFlags, FileType, Mode, OFlags};
use std::{
    convert::Infallible,
    ffi::CString,
    fs::File,
    net::SocketAddr,
    os::unix::ffi::OsStrExt,
    path::PathBuf,
    sync::{Arc, Weak},
    time::Duration,
};
use tokio::{
    net::{TcpListener, UnixListener},
    sync::{Semaphore, watch},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;
type Reply = Response<Full<Bytes>>;
fn failure(category: &'static str) -> AdminError {
    AdminError::new(400, category)
}
fn io_failure() -> AdminError {
    AdminError::new(500, "admin_listener_operation_failed")
}
struct SocketOwner {
    cap: files::Parent,
    dev: u64,
    ino: u64,
    gate: std::sync::Mutex<Option<File>>,
    released: std::sync::atomic::AtomicBool,
}
impl SocketOwner {
    fn release(&self) {
        if self
            .released
            .swap(true, std::sync::atomic::Ordering::AcqRel)
        {
            return;
        }
        if self.matches() {
            let _ = fs::unlinkat(&self.cap.fd, &self.cap.name, AtFlags::empty());
            let _ = fs::fsync(&self.cap.fd);
        }
        let mut gate = self
            .gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        drop(gate.take());
    }
    fn matches(&self) -> bool {
        fs::statat(&self.cap.fd, &self.cap.name, AtFlags::SYMLINK_NOFOLLOW).is_ok_and(|s| {
            s.st_dev as u64 == self.dev
                && s.st_ino == self.ino
                && FileType::from_raw_mode(s.st_mode) == FileType::Socket
        })
    }
}
impl Drop for SocketOwner {
    fn drop(&mut self) {
        self.release();
    }
}
#[derive(Clone)]
enum Security {
    Local(OriginPolicy),
    Remote(Arc<RemoteAccess>),
}
#[derive(Clone)]
enum Peer {
    Local,
    Tls(Vec<rustls::pki_types::CertificateDer<'static>>),
}
enum Listener {
    Tcp(TcpListener),
    Unix(UnixListener),
}
pub(super) struct Prepared {
    listener: Listener,
    owner: Option<Arc<SocketOwner>>,
    pub address: String,
    requested: String,
    policy: Security,
    options: AdminOptions,
    unix: bool,
    port: u16,
    peer_uid: bool,
}
pub(super) struct Running {
    pub address: String,
    pub requested: String,
    cancel: CancellationToken,
    task: Option<JoinHandle<()>>,
    policy: watch::Sender<Security>,
    unix: bool,
    port: u16,
    owner: Option<Arc<SocketOwner>>,
    closed: Option<tokio::sync::oneshot::Receiver<()>>,
}
pub struct AdminServerHandle {
    inner: Weak<Inner>,
    address: String,
}
impl AdminServerHandle {
    pub(super) fn new(inner: Weak<Inner>, address: String) -> Self {
        Self { inner, address }
    }
    pub fn local_address(&self) -> String {
        self.address.clone()
    }
    pub async fn shutdown(self) -> Result<(), AdminError> {
        if let Some(inner) = self.inner.upgrade() {
            inner.shutdown().await?;
        }
        Ok(())
    }
}
pub(super) struct ModeChange {
    owner: Arc<SocketOwner>,
    old: Mode,
    new: Mode,
    changed: bool,
    finished: bool,
}
impl ModeChange {
    pub fn restrictive(&self) -> bool {
        self.new.bits() & self.old.bits() == self.new.bits()
    }
    pub fn commit(&mut self) -> Result<(), AdminError> {
        if !self.owner.matches() {
            return Err(failure("admin_socket_replaced"));
        }
        fs::chmodat(
            &self.owner.cap.fd,
            &self.owner.cap.name,
            self.new,
            AtFlags::empty(),
        )
        .map_err(|_| io_failure())?;
        self.changed = true;
        if !self.owner.matches() {
            return Err(failure("admin_socket_replaced"));
        }
        Ok(())
    }
    pub fn finish(mut self) {
        self.finished = true;
    }
}
impl Drop for ModeChange {
    fn drop(&mut self) {
        if self.changed
            && !self.finished
            && self.owner.matches()
            && fs::chmodat(
                &self.owner.cap.fd,
                &self.owner.cap.name,
                self.old,
                AtFlags::empty(),
            )
            .is_err()
        {
            eprintln!(
                "admin event=socket_mode_restore_failed category=admin_file_operation_failed"
            );
        }
    }
}
impl Running {
    pub fn same_remote_endpoint(&self, raw: &str) -> bool {
        let raw = if raw.is_empty() { ":2021" } else { raw };
        if self.requested.starts_with("fd/") && raw.starts_with("fd/") {
            return super::inherited::key(&self.requested)
                .is_some_and(|key| Some(key) == super::inherited::key(raw));
        }
        if self.unix && self.requested.split('|').next() == raw.split('|').next() {
            return true;
        }
        if self.requested == raw {
            return true;
        }
        let expanded = if raw.starts_with(':') {
            format!("[::]{raw}")
        } else {
            raw.to_owned()
        };
        match (
            expanded.parse::<SocketAddr>(),
            self.address.parse::<SocketAddr>(),
        ) {
            (Ok(candidate), Ok(actual)) => candidate.port() != 0 && candidate == actual,
            _ => false,
        }
    }

    pub fn same_local_endpoint(&self, p: &LocalPolicy) -> bool {
        if self.requested.starts_with("fd/") && p.listen.starts_with("fd/") {
            return super::inherited::key(&self.requested)
                .is_some_and(|key| Some(key) == super::inherited::key(&p.listen));
        }
        if self.unix {
            self.requested.split('|').next() == p.listen.split('|').next()
        } else {
            if self.requested == p.listen {
                return true;
            }
            let actual: Result<SocketAddr, _> = self.address.parse();
            let raw = p.listen.strip_prefix("tcp/").unwrap_or(&p.listen);
            if let Ok(candidate) = raw.parse::<SocketAddr>() {
                return candidate.port() != 0 && Ok(candidate) == actual;
            }
            if let (Some(port), Ok(actual)) = (
                raw.strip_prefix("localhost:")
                    .and_then(|p| p.parse::<u16>().ok()),
                actual,
            ) {
                return port != 0
                    && port == actual.port()
                    && actual.ip() == std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
            }
            false
        }
    }
    pub fn mode_change(&self, p: &LocalPolicy) -> Result<Option<ModeChange>, AdminError> {
        let Some(owner) = &self.owner else {
            return Ok(None);
        };
        let new = match p.listen.rsplit_once('|') {
            None => 0o600,
            Some((_, "0600")) => 0o600,
            Some((_, "0660")) => 0o660,
            Some(_) => return Err(failure("unsupported_admin_socket_permissions")),
        };
        if !owner.matches() {
            return Err(failure("admin_socket_replaced"));
        }
        let st = fs::statat(&owner.cap.fd, &owner.cap.name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| io_failure())?;
        let old = st.st_mode & 0o7777;
        if old == new {
            Ok(None)
        } else {
            Ok(Some(ModeChange {
                owner: owner.clone(),
                old: Mode::from_raw_mode(old),
                new: Mode::from_raw_mode(new),
                changed: false,
                finished: false,
            }))
        }
    }

    pub fn validate_policy(&self, p: &LocalPolicy) -> Result<(), AdminError> {
        OriginPolicy::new(p, self.unix, self.port).map(|_| ())
    }
    pub fn update_policy(&self, p: &LocalPolicy) -> Result<(), AdminError> {
        self.policy
            .send_replace(Security::Local(OriginPolicy::new(p, self.unix, self.port)?));
        Ok(())
    }
    pub fn update_remote(&self, access: Arc<RemoteAccess>) {
        self.policy.send_replace(Security::Remote(access));
    }
    pub async fn retire(mut self) {
        self.cancel.cancel();
        if let Some(owner) = &self.owner {
            owner.release();
        }
        if let Some(closed) = self.closed.take() {
            let _ = tokio::time::timeout(Duration::from_secs(2), closed).await;
        }
        if let Some(task) = self.task.take() {
            tokio::spawn(async move {
                let _ = task.await;
            });
        }
    }
    pub async fn shutdown(mut self) {
        self.cancel.cancel();
        if let Some(owner) = &self.owner {
            owner.release();
        }
        if let Some(mut task) = self.task.take()
            && tokio::time::timeout(Duration::from_secs(35), &mut task)
                .await
                .is_err()
        {
            task.abort();
            let _ = task.await;
        }
    }
}
impl Drop for Running {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}
impl Prepared {
    pub async fn prepare(local: &LocalPolicy, options: &AdminOptions) -> Result<Self, AdminError> {
        if local.listen.starts_with("fd/") {
            return Self::inherited(&local.listen, Some(local), None, options);
        }
        if local.listen.starts_with("unix/@") {
            return Self::abstract_unix(local, options);
        }

        if let Some(raw) = local.listen.strip_prefix("unix/") {
            let (path, mode) = match raw.rsplit_once('|') {
                Some((p, "0600")) => (p, 0o600),
                Some((p, "0660")) => (p, 0o660),
                Some(_) => return Err(failure("unsupported_admin_socket_permissions")),
                None => (raw, 0o600),
            };
            let path = PathBuf::from(path);
            let length = path.as_os_str().as_bytes().len();
            let max = if cfg!(target_os = "macos") { 103 } else { 107 };
            if !path.is_absolute() || length == 0 || length > max {
                return Err(failure("invalid_admin_unix_socket_address"));
            }
            let cap = files::parent(&path, false)?;
            let gate_name = CString::new(format!(
                ".caddy-rust-admin-{}.gate",
                files::basename_hash(path.file_name().ok_or_else(io_failure)?)
            ))
            .map_err(|_| io_failure())?;
            let gate = fs::openat(
                &cap.fd,
                &gate_name,
                OFlags::RDWR
                    | OFlags::CREATE
                    | OFlags::NOFOLLOW
                    | OFlags::CLOEXEC
                    | OFlags::NONBLOCK
                    | OFlags::NOCTTY,
                Mode::from_raw_mode(0o600),
            )
            .map_err(|_| failure("unsafe_admin_socket_gate"))?;
            let st = fs::fstat(&gate).map_err(|_| io_failure())?;
            if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile
                || st.st_uid != cap.uid
                || st.st_nlink != 1
                || st.st_mode & 0o7777 != 0o600
            {
                return Err(failure("unsafe_admin_socket_gate"));
            }
            fs::flock(&gate, fs::FlockOperation::NonBlockingLockExclusive)
                .map_err(|_| failure("admin_socket_already_owned"))?;
            match fs::statat(&cap.fd, &cap.name, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(st) => {
                    if FileType::from_raw_mode(st.st_mode) != FileType::Socket
                        || st.st_uid != cap.uid
                    {
                        return Err(failure("unsafe_existing_admin_socket"));
                    }
                    match tokio::time::timeout(
                        Duration::from_secs(1),
                        tokio::net::UnixStream::connect(&path),
                    )
                    .await
                    {
                        Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => {}
                        _ => return Err(failure("existing_admin_socket_active_or_unknown")),
                    }
                    let again = fs::statat(&cap.fd, &cap.name, AtFlags::SYMLINK_NOFOLLOW)
                        .map_err(|_| failure("existing_admin_socket_changed"))?;
                    if again.st_dev != st.st_dev || again.st_ino != st.st_ino {
                        return Err(failure("existing_admin_socket_changed"));
                    }
                    fs::unlinkat(&cap.fd, &cap.name, AtFlags::empty()).map_err(|_| io_failure())?;
                }
                Err(rustix::io::Errno::NOENT) => {}
                Err(_) => return Err(io_failure()),
            }
            let socket = socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None)
                .map_err(|_| io_failure())?;
            socket.set_nonblocking(true).map_err(|_| io_failure())?;
            socket
                .bind(&socket2::SockAddr::unix(&path).map_err(|_| io_failure())?)
                .map_err(|_| io_failure())?;
            let st = fs::statat(&cap.fd, &cap.name, AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|_| io_failure())?;
            let owner = SocketOwner {
                cap,
                dev: st.st_dev as u64,
                ino: st.st_ino,
                gate: std::sync::Mutex::new(Some(File::from(gate))),
                released: std::sync::atomic::AtomicBool::new(false),
            };
            fs::chmodat(
                &owner.cap.fd,
                &owner.cap.name,
                Mode::from_raw_mode(mode),
                AtFlags::empty(),
            )
            .map_err(|_| io_failure())?;
            if !owner.matches() {
                return Err(failure("admin_socket_replaced"));
            }
            socket.listen(128).map_err(|_| io_failure())?;
            let std_listener: std::os::unix::net::UnixListener = socket.into();
            let listener = UnixListener::from_std(std_listener).map_err(|_| io_failure())?;
            Ok(Self {
                listener: Listener::Unix(listener),
                owner: Some(Arc::new(owner)),
                address: local.listen.clone(),
                requested: local.listen.clone(),
                policy: Security::Local(OriginPolicy::new(local, true, 0)?),
                options: options.clone(),
                unix: true,
                port: 0,
                peer_uid: false,
            })
        } else {
            let address = local.listen.strip_prefix("tcp/").unwrap_or(&local.listen);
            let mut addresses: Vec<SocketAddr> = if let Ok(addr) = address.parse::<SocketAddr>() {
                vec![addr]
            } else {
                let (host, port) = address
                    .rsplit_once(':')
                    .ok_or_else(|| failure("invalid_admin_tcp_address"))?;
                if host != "localhost" {
                    return Err(failure("admin_tcp_requires_loopback_literal_or_localhost"));
                }
                let port: u16 = port
                    .parse()
                    .map_err(|_| failure("invalid_admin_tcp_port"))?;
                tokio::time::timeout(
                    Duration::from_secs(5),
                    tokio::net::lookup_host((host, port)),
                )
                .await
                .map_err(|_| io_failure())?
                .map_err(|_| io_failure())?
                .collect()
            };
            if addresses.is_empty() || addresses.iter().any(|a| !a.ip().is_loopback()) {
                return Err(failure("admin_tcp_requires_loopback"));
            }
            addresses.sort_by_key(|address| !address.is_ipv4());
            let mut bound = None;
            for addr in addresses {
                if let Ok(listener) = TcpListener::bind(addr).await {
                    bound = Some(listener);
                    break;
                }
            }
            let listener = bound.ok_or_else(io_failure)?;
            let addr = listener.local_addr().map_err(|_| io_failure())?;
            let port = addr.port();
            Ok(Self {
                listener: Listener::Tcp(listener),
                owner: None,
                address: addr.to_string(),
                requested: local.listen.clone(),
                policy: Security::Local(OriginPolicy::new(local, false, port)?),
                options: options.clone(),
                unix: false,
                port,
                peer_uid: false,
            })
        }
    }
    pub async fn prepare_remote(
        config: &Remote,
        access: Arc<RemoteAccess>,
        options: &AdminOptions,
    ) -> Result<Self, AdminError> {
        let raw = if config.listen.is_empty() {
            ":2021"
        } else {
            &config.listen
        };
        if raw.starts_with("fd/") {
            return Self::inherited(raw, None, Some(access), options);
        }
        if raw.starts_with("unix/") {
            let local = LocalPolicy::parse(&serde_json::json!({"admin":{"listen":raw}}))?;
            let mut ready = Self::prepare(&local, options).await?;
            ready.policy = Security::Remote(access);
            return Ok(ready);
        }
        if raw.contains(['\0', '{', '}', '|']) {
            return Err(failure("invalid_remote_admin_address"));
        }
        let target = raw.strip_prefix("tcp/").unwrap_or(raw);
        let address = if target.starts_with(':') {
            format!("[::]{target}")
        } else {
            target.to_owned()
        };
        let listener = TcpListener::bind(&address)
            .await
            .map_err(|_| io_failure())?;
        let actual = listener.local_addr().map_err(|_| io_failure())?;
        Ok(Self {
            listener: Listener::Tcp(listener),
            owner: None,
            address: actual.to_string(),
            requested: raw.to_owned(),
            policy: Security::Remote(access),
            options: options.clone(),
            unix: false,
            port: actual.port(),
            peer_uid: false,
        })
    }
    fn inherited(
        raw: &str,
        local: Option<&LocalPolicy>,
        remote: Option<Arc<RemoteAccess>>,
        options: &AdminOptions,
    ) -> Result<Self, AdminError> {
        let captured = super::inherited::get(raw)?;
        let socket = captured.socket;
        let addr = socket.local_addr().map_err(|_| io_failure())?;
        let (listener, unix, port, address, peer_uid) = if let Some(addr) = addr.as_socket() {
            if local.is_some() && !addr.ip().is_loopback() {
                return Err(failure("admin_tcp_requires_loopback"));
            }
            socket.set_nonblocking(true).map_err(|_| io_failure())?;
            let listener: std::net::TcpListener = socket.into();
            (
                Listener::Tcp(TcpListener::from_std(listener).map_err(|_| io_failure())?),
                false,
                addr.port(),
                addr.to_string(),
                false,
            )
        } else {
            let mut peer_uid = addr.as_pathname().is_none();
            if local.is_some()
                && let Some(path) = addr.as_pathname()
            {
                use std::os::unix::fs::{FileTypeExt, MetadataExt};
                let meta = std::fs::symlink_metadata(path)
                    .map_err(|_| failure("unsafe_inherited_admin_unix_socket"))?;
                if !meta.file_type().is_socket() {
                    return Err(failure("unsafe_inherited_admin_unix_socket"));
                }
                // A public/foreign-owned inherited socket does not inherit
                // implicit local-admin trust. 0600/0660 self/root-owned sockets
                // retain their supervisor's explicit owner/group boundary.
                if meta.mode() & 0o0002 != 0
                    || (meta.uid() != 0 && meta.uid() != rustix::process::geteuid().as_raw())
                {
                    peer_uid = true;
                }
            }
            socket.set_nonblocking(true).map_err(|_| io_failure())?;
            let listener: std::os::unix::net::UnixListener = socket.into();
            (
                Listener::Unix(UnixListener::from_std(listener).map_err(|_| io_failure())?),
                true,
                0,
                raw.to_owned(),
                peer_uid,
            )
        };
        let policy = if let Some(remote) = remote {
            Security::Remote(remote)
        } else {
            Security::Local(OriginPolicy::new(
                local.ok_or_else(io_failure)?,
                unix,
                port,
            )?)
        };
        Ok(Self {
            listener,
            owner: None,
            address,
            requested: raw.to_owned(),
            policy,
            options: options.clone(),
            unix,
            port,
            peer_uid,
        })
    }
    fn abstract_unix(local: &LocalPolicy, options: &AdminOptions) -> Result<Self, AdminError> {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            use std::os::linux::net::SocketAddrExt;
            let name = local.listen.strip_prefix("unix/@").ok_or_else(io_failure)?;
            if name.is_empty() || name.len() > 107 || name.contains(['|', '\0']) {
                return Err(failure("invalid_admin_abstract_address"));
            }
            let addr = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes())
                .map_err(|_| io_failure())?;
            let listener =
                std::os::unix::net::UnixListener::bind_addr(&addr).map_err(|_| io_failure())?;
            listener.set_nonblocking(true).map_err(|_| io_failure())?;
            Ok(Self {
                listener: Listener::Unix(
                    UnixListener::from_std(listener).map_err(|_| io_failure())?,
                ),
                owner: None,
                address: local.listen.clone(),
                requested: local.listen.clone(),
                policy: Security::Local(OriginPolicy::new(local, true, 0)?),
                options: options.clone(),
                unix: true,
                port: 0,
                peer_uid: true,
            })
        }
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        {
            let _ = (local, options);
            Err(failure("admin_abstract_socket_platform_unsupported"))
        }
    }
    pub fn start(self, inner: Weak<Inner>) -> Running {
        let (policy, rx) = watch::channel(self.policy.clone());
        let cancel = inner
            .upgrade()
            .map(|i| i.cancel.child_token())
            .unwrap_or_default();
        let stop = cancel.clone();
        let address = self.address.clone();
        let requested = self.requested.clone();
        let unix = self.unix;
        let port = self.port;
        let peer_uid = self.peer_uid;
        let owner = self.owner.clone();
        let (closed_tx, closed) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let owner = self.owner;
            let listener = self.listener;
            let permits = Arc::new(Semaphore::new(self.options.max_connections));
            let rejects = Arc::new(Semaphore::new(16));
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {biased;_=stop.cancelled()=>break,Some(_)=connections.join_next(),if !connections.is_empty()=>{},accepted=accept(&listener)=>{
                 let stream=match accepted{Ok(stream)=>stream,Err(error)=>{if matches!(error.kind(),std::io::ErrorKind::Interrupted|std::io::ErrorKind::ConnectionAborted|std::io::ErrorKind::ConnectionReset)||error.raw_os_error()==Some(libc::EPROTO){continue;}eprintln!("admin event=accept_failed category=admin_accept_failed");tokio::select!{_=stop.cancelled()=>break,_=tokio::time::sleep(Duration::from_millis(100))=>{}}continue;}};if peer_uid && let Stream::Unix(ref s)=stream && !s.peer_cred().is_ok_and(|p|p.uid()==rustix::process::geteuid().as_raw()){continue;}let Ok(permit)=permits.clone().try_acquire_owned()else{if let Ok(reject)=rejects.clone().try_acquire_owned(){connections.spawn(async move{let _reject=reject;reject_connection(stream).await;});}continue;};
                 let inner=inner.clone();let policy=rx.clone();let cancel=stop.clone();let options=self.options.clone();connections.spawn(async move{let _permit=permit;match stream{Stream::Tcp(s)=>serve_accepted(s,inner,policy,cancel,options).await,Stream::Unix(s)=>serve_accepted(s,inner,policy,cancel,options).await}});
                }}
            }
            drop(listener);
            if let Some(owner) = &owner {
                owner.release();
            }
            drop(owner);
            let _ = closed_tx.send(());
            let deadline = tokio::time::sleep(Duration::from_secs(30));
            tokio::pin!(deadline);
            while !connections.is_empty() {
                tokio::select! {_= &mut deadline=>{connections.abort_all();break;},_=connections.join_next()=>{}}
            }
        });
        Running {
            address,
            requested,
            cancel,
            task: Some(task),
            policy,
            unix,
            port,
            owner,
            closed: Some(closed),
        }
    }
}
enum Stream {
    Tcp(tokio::net::TcpStream),
    Unix(tokio::net::UnixStream),
}
async fn accept(listener: &Listener) -> std::io::Result<Stream> {
    match listener {
        Listener::Tcp(l) => l.accept().await.map(|(s, _)| Stream::Tcp(s)),
        Listener::Unix(l) => l.accept().await.map(|(s, _)| Stream::Unix(s)),
    }
}
async fn reject_connection(stream: Stream) {
    use tokio::io::AsyncWriteExt;
    let data=b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nRetry-After: 1\r\nConnection: close\r\n\r\n";
    match stream {
        Stream::Tcp(mut s) => {
            let _ = tokio::time::timeout(Duration::from_secs(1), s.write_all(data)).await;
        }
        Stream::Unix(mut s) => {
            let _ = tokio::time::timeout(Duration::from_secs(1), s.write_all(data)).await;
        }
    }
}
async fn serve_accepted<S>(
    stream: S,
    inner: Weak<Inner>,
    policy: watch::Receiver<Security>,
    cancel: CancellationToken,
    options: AdminOptions,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let security = policy.borrow().clone();
    match security {
        Security::Local(_) => serve(stream, inner, policy, cancel, options, Peer::Local).await,
        Security::Remote(access) => {
            let acceptor = tokio_rustls::TlsAcceptor::from(access.tls.clone());
            let accepted = tokio::select! {_=cancel.cancelled()=>return,r=tokio::time::timeout(options.header_timeout,acceptor.accept(stream))=>r};
            if let Ok(Ok(tls)) = accepted {
                let chain = tls
                    .get_ref()
                    .1
                    .peer_certificates()
                    .unwrap_or_default()
                    .iter()
                    .map(|c| c.clone().into_owned())
                    .collect();
                serve(tls, inner, policy, cancel, options, Peer::Tls(chain)).await;
            }
        }
    }
}
async fn serve<S>(
    stream: S,
    inner: Weak<Inner>,
    policy: watch::Receiver<Security>,
    cancel: CancellationToken,
    options: AdminOptions,
    peer: Peer,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let service = service_fn(move |req| {
        let inner = inner.clone();
        let policy = policy.borrow().clone();
        let peer = peer.clone();
        async move { Ok::<_, Infallible>(handle(req, inner, policy, peer).await) }
    });
    let mut builder = hyper::server::conn::http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(options.header_timeout)
        .max_buf_size(64 * 1024);
    let connection = builder.serve_connection(TokioIo::new(stream), service);
    tokio::pin!(connection);
    tokio::select! {_= &mut connection=>{},_=cancel.cancelled()=>{connection.as_mut().graceful_shutdown();let _=connection.await;},_=tokio::time::sleep(Duration::from_secs(60))=>{connection.as_mut().graceful_shutdown();let _=tokio::time::timeout(Duration::from_secs(2),connection).await;}}
}
fn reply(status: u16, body: Vec<u8>) -> Reply {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())))
}
fn error(error: AdminError, opid: &str) -> Reply {
    let mut out = reply(
        error.status,
        serde_json::to_vec(
            &serde_json::json!({"error":error.category,"opid":opid,"line":error.line}),
        )
        .unwrap_or_default(),
    );
    if error.status == 503 {
        out.headers_mut()
            .insert(header::RETRY_AFTER, http::HeaderValue::from_static("1"));
    }
    out
}
fn decode_path(raw: &str) -> Result<String, AdminError> {
    let mut out = Vec::with_capacity(raw.len());
    let bytes = raw.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err(failure("invalid_path_escape"));
            }
            let h = (bytes[i + 1] as char)
                .to_digit(16)
                .ok_or_else(|| failure("invalid_path_escape"))?;
            let l = (bytes[i + 2] as char)
                .to_digit(16)
                .ok_or_else(|| failure("invalid_path_escape"))?;
            out.push((h * 16 + l) as u8);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| failure("invalid_path_encoding"))
}
async fn body(
    request: Request<Incoming>,
    limit: usize,
    timeout: Duration,
) -> Result<Vec<u8>, AdminError> {
    if request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .is_some_and(|n| n > limit as u64)
    {
        return Err(AdminError::new(413, "admin_body_too_large"));
    }
    let mut incoming = request.into_body();
    tokio::time::timeout(timeout, async move {
        let mut output = Vec::new();
        while let Some(frame) = incoming.frame().await {
            let frame = frame.map_err(|_| failure("admin_body_read_failed"))?;
            if let Ok(bytes) = frame.into_data() {
                if bytes.len() > limit.saturating_sub(output.len()) {
                    return Err(AdminError::new(413, "admin_body_too_large"));
                }
                output.extend_from_slice(&bytes);
            }
        }
        Ok(output)
    })
    .await
    .map_err(|_| AdminError::new(408, "admin_body_timeout"))?
}
pub(super) fn content_adapter(content: Option<&str>) -> Result<Option<String>, AdminError> {
    let raw = content.unwrap_or("");
    if raw.is_empty() {
        return Ok(None);
    }
    let parsed = raw
        .parse::<mime_guess::mime::Mime>()
        .map_err(|_| failure("invalid_content_type"))?;
    let mime = parsed.essence_str().to_ascii_lowercase();
    if mime.ends_with("/json") {
        return Ok(None);
    }
    let subtype = mime
        .split_once('/')
        .ok_or_else(|| failure("invalid_content_type"))?
        .1;
    if subtype.is_empty() || subtype.len() > 100 {
        return Err(failure("invalid_content_type"));
    }
    Ok(Some(subtype.to_owned()))
}

async fn handle(
    request: Request<Incoming>,
    inner: Weak<Inner>,
    policy: Security,
    peer: Peer,
) -> Reply {
    let opid = files::random().unwrap_or_else(|_| "unavailable".to_owned());
    let method = match request.method().as_str() {
        "GET" => "GET",
        "POST" => "POST",
        "PUT" => "PUT",
        "PATCH" => "PATCH",
        "DELETE" => "DELETE",
        "HEAD" => "HEAD",
        "OPTIONS" => "OPTIONS",
        _ => "OTHER",
    };
    let raw_path = request.uri().path().to_owned();
    let route = if raw_path.starts_with("/config") {
        "config"
    } else if raw_path.starts_with("/id/") {
        "id"
    } else if raw_path == "/load" {
        "load"
    } else if raw_path == "/adapt" {
        "adapt"
    } else if raw_path == "/stop" {
        "stop"
    } else {
        "unknown"
    };
    let pathhash = files::basename_hash(std::ffi::OsStr::new(&raw_path));
    let result = dispatch(request, inner, policy, peer).await;
    let status = result
        .as_ref()
        .map(|r| r.status().as_u16())
        .unwrap_or_else(|e| e.status);
    eprintln!(
        "admin method={method} route={route} pathhash={pathhash} opid={opid} status={status}"
    );
    result.unwrap_or_else(|e| error(e, &opid))
}
async fn dispatch(
    mut request: Request<Incoming>,
    inner: Weak<Inner>,
    policy: Security,
    peer: Peer,
) -> Result<Reply, AdminError> {
    let inner = inner
        .upgrade()
        .ok_or_else(|| AdminError::new(503, "admin_unavailable"))?;
    let _permit = inner
        .requests
        .clone()
        .try_acquire_owned()
        .map_err(|_| AdminError::new(503, "admin_request_capacity_exceeded"))?;
    if let Some(authority) = request.uri().authority() {
        let host = request
            .headers()
            .get(header::HOST)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| failure("absolute_uri_host_required"))?;
        if !authority.as_str().eq_ignore_ascii_case(host) {
            return Err(failure("absolute_uri_host_mismatch"));
        }
    }
    let (origin, mut grant) = match (&policy, &peer) {
        (Security::Local(policy), Peer::Local) => (policy.check(request.headers())?, None),
        (Security::Remote(access), Peer::Tls(chain)) => {
            super::policy::remote_browser_check(request.headers())?;
            let _ = access;
            (
                None,
                Some(Grant {
                    chain: chain.clone(),
                    method: String::new(),
                    path: String::new(),
                }),
            )
        }
        _ => return Err(AdminError::new(401, "admin_transport_identity_mismatch")),
    };
    let path = decode_path(request.uri().path())?;
    if !path.starts_with('/') || path.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(failure("invalid_admin_path"));
    }
    if let Some(grant) = &mut grant {
        grant.method = request.method().as_str().to_owned();
        grant.path = path.clone();
        inner.state.load().authorize(grant, None)?;
    }
    let mut clean = ids::clean(&path);
    if clean == "/config" || clean == "/id" {
        clean.push('/');
    }
    if path != clean {
        const ESC: &percent_encoding::AsciiSet = &percent_encoding::CONTROLS
            .add(b' ')
            .add(b'%')
            .add(b'?')
            .add(b'#')
            .add(b'"')
            .add(b'<')
            .add(b'>')
            .add(b'`')
            .add(b'{')
            .add(b'}')
            .add(b'\\')
            .add(b'^');
        let mut target = percent_encoding::utf8_percent_encode(&clean, ESC).to_string();
        if let Some(query) = request.uri().query() {
            target.push('?');
            target.push_str(query);
        }
        let mut response = reply(307, Vec::new());
        response.headers_mut().insert(
            header::LOCATION,
            http::HeaderValue::from_str(&target).map_err(|_| failure("invalid_admin_redirect"))?,
        );
        return Ok(response);
    }
    let controller = AdminController::borrowed(inner.clone());
    let method = request.method().as_str().to_owned();
    let content = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let tag = request
        .headers()
        .get(header::IF_MATCH)
        .map(|v| {
            std::str::from_utf8(v.as_bytes())
                .map(str::to_owned)
                .map_err(|_| failure("invalid_if_match"))
        })
        .transpose()?;
    if request.headers().get_all(header::IF_MATCH).iter().count() > 1 {
        return Err(failure("duplicate_if_match"));
    }
    let force = request
        .headers()
        .get(header::CACHE_CONTROL)
        .is_some_and(|v| v == "must-revalidate");
    let mut response = match (method.as_str(), path.as_str()) {
        ("GET", p) if p == "/config" || p.starts_with("/config/") || p.starts_with("/id/") => {
            let (value, tag) = controller.read_authorized(p, grant.clone()).await?;
            let mut response = reply(200, value);
            response.headers_mut().insert(
                header::ETAG,
                http::HeaderValue::from_bytes(tag.as_bytes()).map_err(|_| io_failure())?,
            );
            response
        }
        ("POST", "/stop") => {
            controller.stop(grant.clone()).await?;
            reply(200, Vec::new())
        }
        ("POST", "/adapt") | ("POST", "/load") => {
            let adapter = content_adapter(content.as_deref())?;
            let filename = request
                .headers_mut()
                .remove("x-caddy-filename")
                .and_then(|h| h.to_str().ok().map(str::to_owned));
            let bytes = body(
                request,
                inner.options.body_limit,
                inner.options.body_timeout,
            )
            .await?;
            let adapted = if adapter.is_none() {
                super::AdaptedConfig {
                    result: inner
                        .offload(move || {
                            crate::admin_json::decoded(&bytes)
                                .map_err(|e| AdminError::new(400, e.category))
                        })
                        .await?,
                    warnings: Vec::new(),
                }
            } else {
                inner.backend.adapt(bytes, adapter, filename).await?
            };
            if path == "/load" {
                controller
                    .submit_authorized(
                        "POST",
                        "/config",
                        Some(adapted.result),
                        tag.as_deref(),
                        force,
                        grant.clone(),
                    )
                    .await?;
                if adapted.warnings.is_empty() {
                    reply(200, Vec::new())
                } else {
                    reply(
                        200,
                        serde_json::to_vec(&serde_json::json!({"warnings":adapted.warnings}))
                            .map_err(|_| io_failure())?,
                    )
                }
            } else {
                reply(
                    200,
                    serde_json::to_vec(
                        &serde_json::json!({"result":adapted.result,"warnings":adapted.warnings}),
                    )
                    .map_err(|_| io_failure())?,
                )
            }
        }
        (m, p)
            if matches!(m, "POST" | "PUT" | "PATCH" | "DELETE")
                && (p == "/config" || p.starts_with("/config/") || p.starts_with("/id/")) =>
        {
            if method != "DELETE" && content.as_ref().is_none_or(|ct| !ct.contains("/json")) {
                return Err(AdminError::new(400, "configuration_requires_json"));
            }
            let bytes = body(
                request,
                inner.options.body_limit,
                inner.options.body_timeout,
            )
            .await?;
            let value = if method == "DELETE" {
                None
            } else {
                Some(
                    inner
                        .offload(move || {
                            crate::admin_json::decoded(&bytes).map_err(|e| {
                                AdminError::new(
                                    if e.category == "configuration_depth_limit" {
                                        400
                                    } else {
                                        500
                                    },
                                    e.category,
                                )
                            })
                        })
                        .await?,
                )
            };
            controller
                .submit_authorized(&method, &path, value, tag.as_deref(), force, grant.clone())
                .await?;
            reply(200, Vec::new())
        }
        (_, p)
            if p == "/stop"
                || p == "/load"
                || p == "/adapt"
                || p == "/config"
                || p.starts_with("/config/")
                || p.starts_with("/id/") =>
        {
            return Err(AdminError::new(405, "method_not_allowed"));
        }
        _ => return Err(AdminError::new(404, "admin_route_not_found")),
    };
    if let Some(origin) = origin {
        response.headers_mut().insert(
            header::ACCESS_CONTROL_ALLOW_ORIGIN,
            http::HeaderValue::from_str(&origin).map_err(|_| failure("invalid_origin"))?,
        );
        response
            .headers_mut()
            .insert(header::VARY, http::HeaderValue::from_static("Origin"));
    }
    Ok(response)
}
