//! Apply a generation's TCP keepalive policy to each newly accepted socket.
//! Reusing a listening descriptor never changes already accepted connections.
use crate::http_config::server_options::Keepalive;
use std::{io,time::Duration};
pub(super) fn apply(stream:&tokio::net::TcpStream,options:Keepalive)->io::Result<()> {
    let socket=socket2::SockRef::from(stream);
    socket.set_keepalive(options.interval>=0)?;
    if options.interval<0{return Ok(())}
    // net rounds positive subsecond intervals up to a kernel second. Negative
    // idle/count retain the socket's inherited value, rather than becoming 0.
    let seconds=|n:i64|Duration::from_secs((n as u64).div_ceil(1_000_000_000));
    let mut config=socket2::TcpKeepalive::new();
    if options.idle>=0{config=config.with_time(if options.idle==0{Duration::from_secs(15)}else{seconds(options.idle)});}
    config=config.with_interval(if options.interval==0{Duration::from_secs(15)}else{seconds(options.interval)});
    socket.set_tcp_keepalive(&config)?;
    if options.count>=0 {
        let count=if options.count==0{9}else{u32::try_from(options.count).map_err(|_|io::Error::new(io::ErrorKind::InvalidInput,"TCP keepalive count out of range"))?};
        socket.set_tcp_keepalive(&socket2::TcpKeepalive::new().with_retries(count))?;
    }
    Ok(())
}
