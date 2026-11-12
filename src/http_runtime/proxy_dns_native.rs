// Go Darwin resolver behavior port; BSD-3-Clause notice in THIRD-PARTY-NOTICES.
//! Darwin's default A/AAAA resolution uses the operating system, as Go does.
//! This preserves supplemental/scoped DNS and mDNS policy. Explicit resolver
//! configurations keep their independent DNS protocol implementation.
use super::{proxy_dns_ip::Address, proxy_dynamic::MAX_ENDPOINTS};
use std::{
    ffi::{CStr, CString},
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ptr,
    sync::{Arc, OnceLock},
};
use tokio::sync::Semaphore;

/// The permit moves into the blocking job, so timeout/cancellation cannot admit
/// unbounded replacement jobs while libc is still resolving an older request.
pub(super) async fn lookup(name: &str, version: Option<u8>) -> io::Result<Vec<Address>> {
    if name.is_empty() || name.len() > 4096 || name.as_bytes().contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid native DNS name",
        ));
    }
    static SLOTS: OnceLock<Arc<Semaphore>> = OnceLock::new();
    let permit = SLOTS
        .get_or_init(|| Arc::new(Semaphore::new(128)))
        .clone()
        .try_acquire_owned()
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::WouldBlock,
                "native DNS worker capacity exceeded",
            )
        })?;
    let name = name.to_owned();
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        resolve(&name, version)
    })
    .await
    .map_err(|_| io::Error::other("native DNS worker stopped"))?
}
struct Answers(*mut libc::addrinfo);
impl Drop for Answers {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this pointer is the successful result of getaddrinfo below,
            // owned exclusively by this guard and released once after traversal.
            unsafe { libc::freeaddrinfo(self.0) };
        }
    }
}
fn resolve(name: &str, version: Option<u8>) -> io::Result<Vec<Address>> {
    let name = CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid native DNS name"))?;
    // SAFETY: all-zero addrinfo is the libc-specified empty hints structure.
    let mut hints: libc::addrinfo = unsafe { std::mem::zeroed() };
    hints.ai_family = match version {
        Some(4) => libc::AF_INET,
        Some(6) => libc::AF_INET6,
        _ => libc::AF_UNSPEC,
    };
    hints.ai_socktype = libc::SOCK_STREAM;
    hints.ai_flags = (libc::AI_CANONNAME | libc::AI_V4MAPPED | libc::AI_ALL) & libc::AI_MASK;
    let mut head = ptr::null_mut();
    // SAFETY: name is NUL-terminated, hints and output remain live for this call;
    // a null service requests addresses only, matching Go's Darwin resolver.
    let status = unsafe { libc::getaddrinfo(name.as_ptr(), ptr::null(), &hints, &mut head) };
    if status != 0 {
        // SAFETY: gai_strerror returns a static NUL-terminated error description.
        let description = unsafe { CStr::from_ptr(libc::gai_strerror(status)) }.to_string_lossy();
        return Err(io::Error::other(format!(
            "native DNS lookup: {description}"
        )));
    }
    let _answers = Answers(head);
    let mut result = Vec::new();
    let mut current = head;
    let mut visited = 0usize;
    while !current.is_null() {
        visited += 1;
        if visited > MAX_ENDPOINTS {
            return Err(io::Error::other("native DNS address limit exceeded"));
        }
        // SAFETY: successful getaddrinfo supplies a linked list valid until
        // freeaddrinfo. We check family and length before reading each sockaddr.
        let item = unsafe { &*current };
        current = item.ai_next;
        if item.ai_socktype != libc::SOCK_STREAM || item.ai_addr.is_null() {
            continue;
        }
        let address = if item.ai_family == libc::AF_INET
            && item.ai_addrlen as usize >= std::mem::size_of::<libc::sockaddr_in>()
        {
            // SAFETY: checked address family/size; unaligned read needs no
            // stronger alignment than libc's sockaddr pointer promises.
            let sa = unsafe { ptr::read_unaligned(item.ai_addr.cast::<libc::sockaddr_in>()) };
            Some(Address::plain(IpAddr::V4(Ipv4Addr::from(
                sa.sin_addr.s_addr.to_ne_bytes(),
            ))))
        } else if item.ai_family == libc::AF_INET6
            && item.ai_addrlen as usize >= std::mem::size_of::<libc::sockaddr_in6>()
        {
            // SAFETY: the same family/length checks hold for sockaddr_in6.
            let sa = unsafe { ptr::read_unaligned(item.ai_addr.cast::<libc::sockaddr_in6>()) };
            let ip=Ipv6Addr::from(sa.sin6_addr.s6_addr);
            Some(match ip.to_ipv4_mapped() {
                Some(ip)=>Address::plain(IpAddr::V4(ip)),
                None=>Address {
                    ip: IpAddr::V6(ip),
                    zone: (sa.sin6_scope_id != 0).then(|| Arc::from(sa.sin6_scope_id.to_string())),
                },
            })
        } else {
            None
        };
        if let Some(address) = address {
            // Go internetAddrList filters by To4 after getaddrinfo and IP.String
            // emits mapped addresses as IPv4. Keep both family and formatting.
            if matches!(version,Some(4)) && !address.ip.is_ipv4()
                || matches!(version,Some(6)) && !address.ip.is_ipv6() {continue;}
            result.push(address);
        }
    }
    if result.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "native DNS lookup returned no addresses",
        ));
    }
    Ok(result)
}
