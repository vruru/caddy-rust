//! The owned copy of a mapped NSS result has a finite prepaid capacity.
//! System/NSS allocations before this iterator remain outside this boundary.
use std::{io, net::SocketAddr};
pub(super) const MAX_ADDRS: usize = 4096;
pub(super) fn copy_admitted(
    addrs: impl Iterator<Item = SocketAddr>,
    mut admit: impl FnMut(SocketAddr) -> Option<SocketAddr>,
) -> io::Result<Vec<SocketAddr>> {
    // The closed caller prepays two complete copies before starting the real
    // resolver worker. Do not trust an iterator's unbounded size_hint.
    let mut output = Vec::new();
    output.try_reserve_exact(MAX_ADDRS).map_err(io::Error::other)?;
    for (index, address) in addrs.enumerate() {
        if index == MAX_ADDRS {
            return Err(io::Error::other("mapped proxy DNS address result limit exceeded"));
        }
        if let Some(address) = admit(address) {
            output.push(address);
        }
    }
    Ok(output)
}
