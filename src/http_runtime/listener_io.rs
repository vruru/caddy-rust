use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
    io::IoSlice,
};

#[cfg(unix)]
use tokio::net::UnixStream;

/// Closed delegation module for accepted streams.
///
/// Only two builtin stream types are supported: TCP and Unix.
/// This module handles mechanical IO delegation for the shared admission/TLS/HTTP layers.
pub(super) enum Stream {
    Tcp(TcpStream),
    #[cfg(unix)]
    Unix(UnixStream),
}

impl Stream {
    /// Returns a reference to the inner TCP stream if this is a TCP connection.
    /// Returns `None` for Unix streams.
    pub(super) fn tcp(&self) -> Option<&TcpStream> {
        match self {
            Stream::Tcp(t) => Some(t),
            #[cfg(unix)]
            Stream::Unix(_) => None,
        }
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.as_mut().get_mut() {
            Stream::Tcp(t) => Pin::new(t).poll_read(cx, buf),
            #[cfg(unix)]
            Stream::Unix(u) => Pin::new(u).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.as_mut().get_mut() {
            Stream::Tcp(t) => Pin::new(t).poll_write(cx, buf),
            #[cfg(unix)]
            Stream::Unix(u) => Pin::new(u).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().get_mut() {
            Stream::Tcp(t) => Pin::new(t).poll_flush(cx),
            #[cfg(unix)]
            Stream::Unix(u) => Pin::new(u).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().get_mut() {
            Stream::Tcp(t) => Pin::new(t).poll_shutdown(cx),
            #[cfg(unix)]
            Stream::Unix(u) => Pin::new(u).poll_shutdown(cx),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            Stream::Tcp(t) => t.is_write_vectored(),
            #[cfg(unix)]
            Stream::Unix(u) => u.is_write_vectored(),
        }
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match self.as_mut().get_mut() {
            Stream::Tcp(t) => Pin::new(t).poll_write_vectored(cx, bufs),
            #[cfg(unix)]
            Stream::Unix(u) => Pin::new(u).poll_write_vectored(cx, bufs),
        }
    }
}

use crate::{http_config::ListenerAddress as Address,net_address::NetAddress};
use std::sync::Arc;
pub(super) enum Listener {
    Tcp(tokio::net::TcpListener),
    #[cfg(unix)]
    Unix{socket:tokio::net::UnixListener,packet:bool},
}
impl Listener {
    pub(super) async fn accept(&self)->io::Result<(Stream,NetAddress,NetAddress)> {
        match self {
            Self::Tcp(socket)=>{let(stream,peer)=socket.accept().await?;let local=stream.local_addr()?;Ok((Stream::Tcp(stream),peer.into(),local.into()))},
            #[cfg(unix)]
            Self::Unix{socket,packet}=>{let(stream,peer)=socket.accept().await?;let local=stream.local_addr()?;Ok((Stream::Unix(stream),unix_address(&peer,*packet),unix_address(&local,*packet)))},
        }
    }
    pub(super) fn address(&self)->io::Result<Address>{match self{
        Self::Tcp(socket)=>Ok(Address::Inet(socket.local_addr()?)),
        #[cfg(unix)]
        Self::Unix{socket,packet}=>{let address=unix_address(&socket.local_addr()?,*packet);match address{NetAddress::Unix{path,..}|NetAddress::UnixPacket{path}=>Ok(Address::Unix{path,packet:*packet}),_=>unreachable!()}},
    }}
}
#[cfg(unix)]
fn unix_address(address:&tokio::net::unix::SocketAddr,packet:bool)->NetAddress {
    use std::os::unix::ffi::OsStrExt;
    let path:Arc<[u8]>=if let Some(path)=address.as_pathname(){Arc::from(path.as_os_str().as_bytes())}else{
        #[cfg(any(target_os="linux",target_os="android"))]
        if let Some(name)=address.as_abstract_name(){let mut value=Vec::with_capacity(name.len()+1);value.push(b'@');value.extend_from_slice(name);return if packet{NetAddress::UnixPacket{path:value.into()}}else{NetAddress::Unix{path:value.into(),datagram:false}};}
        Arc::from(b"@".as_slice())
    };
    if packet{NetAddress::UnixPacket{path}}else{NetAddress::Unix{path,datagram:false}}
}

/// Only a descriptor this runtime actually bound owns an unlink capability.
/// Closing a duplicate inherited descriptor never unlinks its caller's path.
#[cfg(unix)]
pub(super) struct PathCleanup{path:std::path::PathBuf,dev:u64,ino:u64}
#[cfg(unix)]
impl PathCleanup{pub(super) fn identity(&self)->(u64,u64){(self.dev,self.ino)}}
#[cfg(unix)]
impl Drop for PathCleanup {
    fn drop(&mut self){use std::os::unix::fs::{MetadataExt,FileTypeExt};if let Ok(meta)=std::fs::symlink_metadata(&self.path){if meta.file_type().is_socket()&&meta.dev()==self.dev&&meta.ino()==self.ino{let _=std::fs::remove_file(&self.path);}}}
}
#[cfg(not(unix))]
pub(super) struct PathCleanup;
pub(super) struct Bound {
    pub(super) listener:Listener,
    pub(super) actual:Address,
    pub(super) only_v6:bool,
    pub(super) cleanup:Option<PathCleanup>,
}
pub(super) fn bind(address:&Address,only_v6:bool,mode:Option<u32>)->io::Result<Bound>{
    if let Address::Inet(address)=address {
        let(socket,only_v6)=super::bind_listener(*address,only_v6)?;
        let actual=Address::Inet(socket.local_addr()?);
        return Ok(Bound{listener:Listener::Tcp(socket),actual,only_v6,cleanup:None});
    }
    #[cfg(unix)]
    {bind_local(address,mode)}
    #[cfg(not(unix))]
    {let _=mode;Err(io::Error::new(io::ErrorKind::Unsupported,"Unix/fd HTTP listeners are unavailable on this platform"))}
}
#[cfg(unix)]
fn bind_local(address:&Address,mode:Option<u32>)->io::Result<Bound>{
    use std::os::{fd::{AsRawFd,FromRawFd,IntoRawFd},unix::{ffi::OsStrExt,fs::{MetadataExt,FileTypeExt}}};
    let (socket,cleanup)=match address {
        Address::Unix{path,packet}=>{
            let mut raw=path.to_vec();let abstract_socket=raw.first()==Some(&b'@');
            if abstract_socket {
                #[cfg(not(any(target_os="linux",target_os="android")))]
                return Err(io::Error::new(io::ErrorKind::Unsupported,"abstract Unix sockets require Linux"));
                #[cfg(any(target_os="linux",target_os="android"))]
                {raw[0]=0;}
            }
            let path=std::path::Path::new(std::ffi::OsStr::from_bytes(&raw));
            let addr=socket2::SockAddr::unix(path)?;
            let kind=if *packet{socket2::Type::SEQPACKET}else{socket2::Type::STREAM};
            if !abstract_socket {
                match std::fs::symlink_metadata(path){
                    Ok(meta)=>{
                        if !meta.file_type().is_socket(){return Err(io::Error::new(io::ErrorKind::AlreadyExists,"Unix listener path is not a socket"))}
                        let probe=socket2::Socket::new(socket2::Domain::UNIX,kind,None)?;probe.set_nonblocking(true)?;
                        match probe.connect(&addr){
                            Err(error)if error.raw_os_error()==Some(libc::ECONNREFUSED)=>{
                                let current=std::fs::symlink_metadata(path)?;
                                if current.dev()!=meta.dev()||current.ino()!=meta.ino(){return Err(io::Error::new(io::ErrorKind::AlreadyExists,"Unix listener path changed"))}
                                std::fs::remove_file(path)?;
                            },
                            _=>return Err(io::Error::new(io::ErrorKind::AddrInUse,"Unix listener is already active")),
                        }
                    },Err(error)if error.kind()==io::ErrorKind::NotFound=>{},Err(error)=>return Err(error),
                }
            }
            let socket=socket2::Socket::new(socket2::Domain::UNIX,kind,None)?;socket.set_nonblocking(true)?;socket.bind(&addr)?;
            let cleanup=if abstract_socket{None}else{let meta=std::fs::symlink_metadata(path)?;Some(PathCleanup{path:std::path::absolute(path)?,dev:meta.dev(),ino:meta.ino()})};
            if let Some(mode)=mode{set_mode(address,mode,cleanup.as_ref().map(PathCleanup::identity))?;}
            socket.listen(1024)?;(socket,cleanup)
        },
        Address::Fd{number,datagram:false}=>{
            // SAFETY: duplicate without consuming or closing the caller's fd.
            // Socket type and accept state are checked before typed conversion.
            let fd=unsafe{libc::fcntl(*number as i32,libc::F_DUPFD_CLOEXEC,3)};
            if fd<0{return Err(io::Error::last_os_error())}
            let socket=unsafe{socket2::Socket::from_raw_fd(fd)};
            let kind=socket.r#type()?;
            if kind!=socket2::Type::STREAM&&kind!=socket2::Type::SEQPACKET{return Err(io::Error::new(io::ErrorKind::InvalidInput,"fd is not a stream listener"))}
            let mut value=0i32;let mut length=std::mem::size_of_val(&value)as libc::socklen_t;
            let rc=unsafe{libc::getsockopt(socket.as_raw_fd(),libc::SOL_SOCKET,libc::SO_ACCEPTCONN,(&mut value as *mut i32).cast(),&mut length)};
            if rc!=0 {
                let error=io::Error::last_os_error();
                // Darwin exposes the constant but its kernel does not implement
                // this query. Like Go FileListener, retain the typed stream in
                // that case; accept still enforces actual kernel listen state.
                #[cfg(not(target_os="macos"))]
                return Err(error);
                #[cfg(target_os="macos")]
                if error.raw_os_error()!=Some(libc::ENOPROTOOPT){return Err(error)}
            }else if value==0{return Err(io::Error::new(io::ErrorKind::InvalidInput,"fd is not listening"))}
            socket.set_nonblocking(true)?;(socket,None)
        },
        _=>return Err(io::Error::new(io::ErrorKind::InvalidInput,"packet descriptor cannot accept HTTP streams")),
    };
    let local=socket.local_addr()?;
    if let Some(actual)=local.as_socket(){
        let only_v6=actual.is_ipv6()&&socket.only_v6()?;
        let stream=std::net::TcpListener::from(socket);
        return Ok(Bound{listener:Listener::Tcp(tokio::net::TcpListener::from_std(stream)?),actual:actual.into(),only_v6,cleanup});
    }
    if !local.is_unix(){return Err(io::Error::new(io::ErrorKind::Unsupported,"unsupported inherited listener family"))}
    let packet=socket.r#type()?==socket2::Type::SEQPACKET;
    // SAFETY: the descriptor is an owned, listening AF_UNIX stream/seqpacket.
    let stream=unsafe{std::os::unix::net::UnixListener::from_raw_fd(socket.into_raw_fd())};
    let listener=Listener::Unix{socket:tokio::net::UnixListener::from_std(stream)?,packet};let actual=listener.address()?;
    Ok(Bound{listener,actual,only_v6:false,cleanup})
}
pub(super) fn set_mode(address:&Address,mode:u32,expected:Option<(u64,u64)>)->io::Result<()> {
    #[cfg(unix)]
    if let Address::Unix{path,..}=address {
        use std::os::unix::{ffi::OsStrExt,fs::{MetadataExt,FileTypeExt}};
        if path.first()==Some(&b'@'){return Ok(())}
        let path=std::path::Path::new(std::ffi::OsStr::from_bytes(path));
        let before=std::fs::symlink_metadata(path)?;
        let matches=|dev:u64,ino:u64|expected.is_none_or(|id|id==(dev,ino));
        if !before.file_type().is_socket()||!matches(before.dev(),before.ino()){return Err(io::Error::new(io::ErrorKind::AlreadyExists,"Unix listener inode changed"))}
        let bits=(mode&0o777)|if mode&(1<<23)!=0{0o4000}else{0}|if mode&(1<<22)!=0{0o2000}else{0}|if mode&(1<<20)!=0{0o1000}else{0};
        let permissions=rustix::fs::Mode::from_bits_truncate(bits as _);
        #[cfg(target_os="linux")]
        {
            use std::os::fd::AsRawFd;
            let fd=rustix::fs::open(path,rustix::fs::OFlags::PATH|rustix::fs::OFlags::NOFOLLOW|rustix::fs::OFlags::CLOEXEC,rustix::fs::Mode::empty())?;
            let stat=rustix::fs::fstat(&fd)?;
            if rustix::fs::FileType::from_raw_mode(stat.st_mode)!=rustix::fs::FileType::Socket||!matches(stat.st_dev as u64,stat.st_ino){return Err(io::Error::new(io::ErrorKind::AlreadyExists,"Unix listener inode changed"))}
            let result=unsafe{libc::syscall(linux_raw_sys::general::__NR_fchmodat2 as libc::c_long,fd.as_raw_fd(),c"".as_ptr(),bits as libc::mode_t,libc::AT_EMPTY_PATH)};
            if result!=0{
                let error=io::Error::last_os_error();
                if matches!(error.raw_os_error(),Some(libc::ENOSYS)|Some(libc::EINVAL)){
                    rustix::fs::chmodat(rustix::fs::CWD,format!("/proc/self/fd/{}",fd.as_raw_fd()),permissions,rustix::fs::AtFlags::empty())?;
                }else{return Err(error)}
            }
        }
        #[cfg(not(target_os="linux"))]
        rustix::fs::chmodat(rustix::fs::CWD,path,permissions,rustix::fs::AtFlags::SYMLINK_NOFOLLOW)?;
        let after=std::fs::symlink_metadata(path)?;
        if !after.file_type().is_socket()||after.dev()!=before.dev()||after.ino()!=before.ino(){return Err(io::Error::new(io::ErrorKind::AlreadyExists,"Unix listener inode changed"))}
    }
    #[cfg(not(unix))]
    let _=(address,mode,expected);
    Ok(())
}
