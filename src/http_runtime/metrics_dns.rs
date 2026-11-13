//! Scoped owned system DNS. Rust buffers are admitted before allocation;
//! libc/NSS allocations stay provider-owned, not a claimed Rust/RSS allowance.
use super::http_dial::{Family, FamilyAddrs};
use crate::outgoing_tls::{ConnectionBytes, ConnectionLease, ConnectionMetadata};
use hyper_util::client::legacy::connect::dns::Name;
use std::{io, net::SocketAddr};
const MAX_ANSWERS: usize = 4096;
pub(super) struct Resident {
    _bytes: ConnectionBytes,
    _lease: ConnectionLease,
}
struct Job {
    name: SystemName,
    family: Family,
    bytes: Option<ConnectionBytes>,
    lease: Option<ConnectionLease>,
}
enum SystemName {
    Metrics(Name),
    #[cfg(unix)]
    Acme(reqwest::dns::Name),
}
impl SystemName {
    fn as_str(&self) -> &str {
        match self {
            Self::Metrics(name) => name.as_str(),
            #[cfg(unix)]
            Self::Acme(name) => name.as_str(),
        }
    }
}
impl Drop for Job {
    fn drop(&mut self) {}
}
struct Output {
    values: io::Result<Vec<SocketAddr>>,
    resident: Resident,
}
impl Job {
    fn run(mut self) -> Output {
        let values = system(
            self.name.as_str(),
            self.family,
            self.bytes.as_mut().expect("owned DNS bytes"),
            self.lease.as_ref().expect("owned DNS lease"),
        );
        Output {
            values,
            resident: Resident {
                _bytes: self.bytes.take().expect("owned DNS bytes"),
                _lease: self.lease.take().expect("owned DNS lease"),
            },
        }
    }
}
struct ErrorResident {
    _bytes: ConnectionBytes,
    _metadata: ConnectionMetadata,
}
impl Resident {
    fn into_error(self) -> ErrorResident {
        let Self { _bytes, _lease } = self;
        ErrorResident { _bytes, _metadata: _lease.into_metadata() }
    }
}
struct LookupError {
    inner: io::Error,
    _resident: ErrorResident,
}
impl std::fmt::Debug for LookupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.inner.fmt(f)
    }
}
impl std::fmt::Display for LookupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.inner.fmt(f)
    }
}
impl std::error::Error for LookupError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.inner)
    }
}
pub(super) async fn lookup(
    name: Name,
    family: Family,
    lease: ConnectionLease,
) -> io::Result<FamilyAddrs> {
    lookup_inner(SystemName::Metrics(name), family, lease).await
}
#[cfg(unix)]
pub(super) async fn lookup_reqwest(name: reqwest::dns::Name, lease: ConnectionLease) -> io::Result<FamilyAddrs> {
    lookup_inner(SystemName::Acme(name), Family::Any, lease).await
}
async fn lookup_inner(name: SystemName, family: Family, lease: ConnectionLease) -> io::Result<FamilyAddrs> {
    let metadata = std::mem::size_of::<Job>()
        .checked_add(std::mem::size_of::<Output>())
        .and_then(|n| n.checked_add(name.as_str().len() + 1))
        .and_then(|n| n.checked_add(4096))
        .ok_or_else(|| io::Error::other("observability DNS metadata overflow"))?;
    let bytes = lease
        .bytes(metadata)
        .map_err(|e| io::Error::other(e.reallocate_into_boxed_dyn_error_without_backtrace()))?;
    let job = Job {
        name,
        family,
        bytes: Some(bytes),
        lease: Some(lease),
    };
    // This runs inside the existing dedicated client runtime. Abort only stops
    // unstarted work; a real running libc call retains the complete envelope.
    let task =
        tokio_util::task::AbortOnDropHandle::new(tokio::task::spawn_blocking(move || job.run()));
    let Output { values, resident } = task.await.map_err(io::Error::other)?;
    match values {
        Ok(values) => Ok(FamilyAddrs::with_metrics(values, resident)),
        Err(inner) => Err(io::Error::new(
            inner.kind(),
            LookupError {
                inner,
                _resident: resident.into_error(),
            },
        )),
    }
}
#[cfg(unix)]
fn system(
    host: &str,
    family: Family,
    bytes: &mut ConnectionBytes,
    lease: &ConnectionLease,
) -> io::Result<Vec<SocketAddr>> {
    use std::{ffi::CString, ptr};
    let stop = lease.cancellation();
    if stop.is_cancelled() {
        return Err(io::Error::other("observability DNS stopped"));
    }
    let name = CString::new(host)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid resolver name"))?;
    // Same zero hints + SOCK_STREAM as Rust 1.100 LookupHost. No AI_ADDRCONFIG
    // or sort/filter policy is added; preserve the linked-list order verbatim.
    let mut hints: libc::addrinfo = unsafe { std::mem::zeroed() };
    hints.ai_socktype = libc::SOCK_STREAM;
    let mut head = ptr::null_mut();
    let status = unsafe { libc::getaddrinfo(name.as_ptr(), ptr::null(), &hints, &mut head) };
    struct Owned(*mut libc::addrinfo);
    impl Drop for Owned {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { libc::freeaddrinfo(self.0) };
            }
        }
    }
    let _answers = Owned(head);
    if status != 0 {
        if status == libc::EAI_SYSTEM {
            return Err(io::Error::last_os_error());
        }
        return Err(io::Error::other(format!(
            "system address lookup failed ({status})"
        )));
    }
    let mut values = Vec::new();
    let mut current = head;
    let mut count = 0;
    while !current.is_null() {
        count += 1;
        if count > MAX_ANSWERS {
            return Err(io::Error::other(
                "observability DNS answer capacity exceeded",
            ));
        }
        if stop.is_cancelled() {
            return Err(io::Error::other("observability DNS stopped"));
        }
        // SAFETY: libc's guarded list stays alive for this whole traversal.
        // Check family and length before unaligned sockaddr field reads.
        let item = unsafe { &*current };
        current = item.ai_next;
        if item.ai_addr.is_null() {
            continue;
        }
        let address = socket_address(item);
        if let Some(address) = address.and_then(|a| family.admit(a)) {
            if values.len() == values.capacity() {
                let next = values
                    .capacity()
                    .max(2)
                    .checked_mul(2)
                    .filter(|n| *n <= MAX_ANSWERS)
                    .ok_or_else(|| {
                        io::Error::other("observability DNS vector capacity exceeded")
                    })?;
                let amount = next
                    .checked_mul(std::mem::size_of::<SocketAddr>())
                    .ok_or_else(|| io::Error::other("observability DNS metadata overflow"))?;
                // Keep all previous growth credit until actual output Drop:
                // new+old allocations overlap, and the sum is <2*final cap.
                bytes.grow(amount).map_err(|e| {
                    io::Error::other(e.reallocate_into_boxed_dyn_error_without_backtrace())
                })?;
                values
                    .try_reserve_exact(next - values.len())
                    .map_err(io::Error::other)?;
            }
            values.push(address);
        }
    }
    if values.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "no addresses admitted",
        ));
    }
    Ok(values)
}
#[cfg(unix)]
fn socket_address(item: &libc::addrinfo) -> Option<SocketAddr> {
    use std::{
        net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV6},
        ptr,
    };
    if item.ai_addr.is_null() {
        return None;
    }
    if item.ai_family == libc::AF_INET
        && item.ai_addrlen as usize >= std::mem::size_of::<libc::sockaddr_in>()
    {
        let raw = unsafe { ptr::read_unaligned(item.ai_addr.cast::<libc::sockaddr_in>()) };
        Some(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::from(raw.sin_addr.s_addr.to_ne_bytes())),
            0,
        ))
    } else if item.ai_family == libc::AF_INET6
        && item.ai_addrlen as usize >= std::mem::size_of::<libc::sockaddr_in6>()
    {
        let raw = unsafe { ptr::read_unaligned(item.ai_addr.cast::<libc::sockaddr_in6>()) };
        Some(SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::from(raw.sin6_addr.s6_addr),
            0,
            raw.sin6_flowinfo,
            raw.sin6_scope_id,
        )))
    } else {
        None
    }
}
#[cfg(not(unix))]
fn system(
    _host: &str,
    _family: Family,
    _bytes: &mut ConnectionBytes,
    _lease: &ConnectionLease,
) -> io::Result<Vec<SocketAddr>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "owned observability resolver unsupported on this platform",
    ))
}
