//! The owned copy of a mapped NSS result has a finite prepaid capacity.
//! System/NSS allocations before this iterator remain outside this boundary.
use std::{io, net::SocketAddr};
pub(super) const MAX_ADDRS: usize = 4096;
#[derive(Debug)]
pub(super) enum CopyFailure {
    Capacity(std::collections::TryReserveError),
    Limit,
}
impl std::fmt::Display for CopyFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("mapped proxy DNS local result capacity exceeded")
    }
}
impl std::error::Error for CopyFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self { Self::Capacity(error) => Some(error), Self::Limit => None }
    }
}
pub(super) fn copy_admitted(
    addrs: impl Iterator<Item = SocketAddr>,
    mut admit: impl FnMut(SocketAddr) -> Option<SocketAddr>,
) -> io::Result<Vec<SocketAddr>> {
    // The closed caller prepays two complete copies before starting the real
    // resolver worker. Do not trust an iterator's unbounded size_hint.
    let mut output = Vec::new();
    output.try_reserve_exact(MAX_ADDRS)
        .map_err(|error| io::Error::other(CopyFailure::Capacity(error)))?;
    for (index, address) in addrs.enumerate() {
        if index == MAX_ADDRS {
            return Err(io::Error::other(CopyFailure::Limit));
        }
        if let Some(address) = admit(address) {
            output.push(address);
        }
    }
    Ok(output)
}
