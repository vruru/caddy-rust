//! Bounded exact-wire certificate evidence. OpenSSL's X509 re-encoding is never
//! used as a replacement for the DER bytes authenticated by the peer.
use std::{
    io,
    ops::Range,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
pub(crate) const MAX_MESSAGE: usize = 1024 * 1024;
const MAX_CHAIN: usize = 64;
const POOL_BYTES: usize = 64 * 1024 * 1024;
static USED: AtomicUsize = AtomicUsize::new(0);
pub(crate) fn usage() -> (usize, usize) {
    (USED.load(Ordering::Acquire), POOL_BYTES)
}
struct Credit(usize);
impl Credit {
    fn reserve(n: usize) -> io::Result<Self> {
        USED.fetch_update(Ordering::AcqRel, Ordering::Acquire, |old| {
            old.checked_add(n).filter(|sum| *sum <= POOL_BYTES)
        })
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::OutOfMemory,
                "TLS certificate observation capacity exhausted",
            )
        })?;
        Ok(Self(n))
    }
}
impl Drop for Credit {
    fn drop(&mut self) {
        USED.fetch_sub(self.0, Ordering::AcqRel);
    }
}
pub(crate) struct Chain {
    bytes: Vec<u8>,
    certs: [Range<usize>; MAX_CHAIN],
    count: usize,
    ocsp: Option<Range<usize>>,
    // Data is destroyed before the final prepaid credit is returned.
    _credit: Credit,
}
fn malformed() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid TLS certificate handshake",
    )
}
fn take<'a>(b: &'a [u8], p: &mut usize, n: usize) -> io::Result<&'a [u8]> {
    let end = p.checked_add(n).ok_or_else(malformed)?;
    let v = b.get(*p..end).ok_or_else(malformed)?;
    *p = end;
    Ok(v)
}
fn u24(b: &[u8]) -> usize {
    (b[0] as usize) << 16 | (b[1] as usize) << 8 | b[2] as usize
}
impl Chain {
    pub(crate) fn parse(message: &[u8], tls13: bool) -> io::Result<Arc<Self>> {
        if message.len() > MAX_MESSAGE {
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "TLS certificate handshake exceeds observation bound",
            ));
        }
        if message.len() < 7 || message[0] != 11 || u24(&message[1..4]) != message.len() - 4 {
            return Err(malformed());
        }
        let mut p = 4;
        if tls13 {
            let n = take(message, &mut p, 1)?[0] as usize;
            take(message, &mut p, n)?;
        }
        let size = u24(take(message, &mut p, 3)?);
        if size != message.len() - p {
            return Err(malformed());
        }
        let mut certs = std::array::from_fn(|_| 0..0);
        let mut count = 0;
        let mut ocsp = None;
        while p < message.len() {
            if count == MAX_CHAIN {
                return Err(io::Error::new(
                    io::ErrorKind::OutOfMemory,
                    "TLS certificate chain count exceeds observation bound",
                ));
            }
            let len = u24(take(message, &mut p, 3)?);
            if len == 0 {
                return Err(malformed());
            }
            let start = p;
            take(message, &mut p, len)?;
            certs[count] = start..p;
            if tls13 {
                let ext = take(message, &mut p, 2)?;
                let size = u16::from_be_bytes([ext[0], ext[1]]) as usize;
                let end = p.checked_add(size).ok_or_else(malformed)?;
                if end > message.len() {
                    return Err(malformed());
                }
                while p < end {
                    let h = take(message, &mut p, 4)?;
                    let kind = u16::from_be_bytes([h[0], h[1]]);
                    let n = u16::from_be_bytes([h[2], h[3]]) as usize;
                    let start = p;
                    let v = take(message, &mut p, n)?;
                    if p > end {
                        return Err(malformed());
                    }
                    if count == 0 && kind == 5 {
                        if ocsp.is_some()
                            || v.len() < 4
                            || v[0] != 1
                            || u24(&v[1..4]) != v.len() - 4
                        {
                            return Err(malformed());
                        }
                        ocsp = Some(start + 4..p);
                    }
                }
            }
            count += 1;
        }
        if count == 0 {
            return Err(malformed());
        }
        // Includes Vec allocation, Arc control/data block and bounded verifier view.
        let credit = Credit::reserve(message.len().checked_add(4096).ok_or_else(malformed)?)?;
        let mut bytes = Vec::with_capacity(message.len());
        bytes.extend_from_slice(message);
        Ok(Arc::new(Self {
            bytes,
            certs,
            count,
            ocsp,
            _credit: credit,
        }))
    }
    pub(crate) fn leaf(&self) -> &[u8] {
        &self.bytes[self.certs[0].clone()]
    }
    pub(crate) fn intermediates(&self) -> impl Iterator<Item = &[u8]> {
        self.certs[1..self.count]
            .iter()
            .map(|r| &self.bytes[r.clone()])
    }
    pub(crate) fn certificates(&self) -> impl Iterator<Item = &[u8]> {
        self.certs[..self.count]
            .iter()
            .map(|r| &self.bytes[r.clone()])
    }
    pub(crate) fn ocsp(&self) -> &[u8] {
        self.ocsp.as_ref().map_or(&[], |r| &self.bytes[r.clone()])
    }
}
