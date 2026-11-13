//! Bounded native process-manager notifications. Only `run` captures the
//! inherited endpoint; library users and short-lived admin CLI clients never
//! impersonate the serving process. Notification failures cannot undo a commit.
#[derive(Clone, Copy)]
pub enum State { Ready, Reloading, Stopping, ReloadFailed }
impl State {
    fn payload(self)-> &'static [u8] {match self {
        Self::Ready=>b"READY=1", Self::Reloading=>b"RELOADING=1",
        Self::Stopping=>b"STOPPING=1", Self::ReloadFailed=>b"STATUS=config_reload_failed",
    }}
}
#[cfg(target_os="linux")]
mod linux {
    use super::State;
    use std::{io,os::{linux::net::SocketAddrExt,unix::{ffi::OsStrExt,net::{SocketAddr,UnixDatagram}}},sync::{OnceLock,atomic::{AtomicBool,Ordering}},time::Duration};
    static TARGET:OnceLock<Option<SocketAddr>>=OnceLock::new();
    static ORDER:tokio::sync::Mutex<()>=tokio::sync::Mutex::const_new(());
    static STOPPING:AtomicBool=AtomicBool::new(false);
    pub(super) fn initialize() {
        TARGET.get_or_init(||match capture() {
            Ok(target)=>target,
            Err(_)=>{eprintln!("run event=process_notify_unavailable");None},
        });
    }
    fn capture()->io::Result<Option<SocketAddr>> {
        let Some(raw)=std::env::var_os("NOTIFY_SOCKET") else{return Ok(None)};
        let bytes=raw.as_os_str().as_bytes();
        if bytes.is_empty(){return Ok(None)}
        if bytes.contains(&0){return Err(io::Error::from(io::ErrorKind::InvalidInput))}
        let addr=if bytes[0]==b'@' {SocketAddr::from_abstract_name(&bytes[1..])?}
            else {SocketAddr::from_pathname(std::ffi::OsStr::from_bytes(bytes))?};
        Ok(Some(addr))
    }
    pub(super) async fn send(state:State) {
        let Some(target)=TARGET.get().and_then(Option::as_ref) else{return};
        // Serializes only the tiny manager datagrams, not request/config work.
        // Never advertise READY after an authorized stop has begun.
        let _order=ORDER.lock().await;
        if STOPPING.load(Ordering::Acquire){return}
        if matches!(state,State::Stopping){STOPPING.store(true,Ordering::Release);}
        let sent=tokio::time::timeout(Duration::from_millis(100),async {
            let socket=UnixDatagram::unbound()?;socket.set_nonblocking(true)?;
            let socket=tokio::io::unix::AsyncFd::new(socket)?;
            let payload=state.payload();
            let n=socket.async_io(tokio::io::Interest::WRITABLE,|socket|socket.send_to_addr(payload,target)).await?;
            if n!=payload.len(){return Err(io::Error::from(io::ErrorKind::WriteZero))}
            Ok::<_,io::Error>(())
        }).await;
        if !matches!(sent,Ok(Ok(()))){eprintln!("run event=process_notify_failed");}
    }
}
/// Called once on the serving main thread, before constructing its runtime.
/// Does not change the inherited environment or print endpoint contents.
pub fn initialize() {#[cfg(target_os="linux")] linux::initialize();}
pub async fn send(state:State) {
    #[cfg(target_os="linux")] linux::send(state).await;
    #[cfg(not(target_os="linux"))] let _=state.payload();
}
