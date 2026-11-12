use alloc::sync::Arc;
use alloc::vec::Vec;
use pki_types::CertificateDer;

use crate::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainUnavailable {
    EnumerationLimit,
    RootSourceUnknown,
    PlatformVerifier,
    PolicyDivergence,
    TooLargeForSession,
    LegacySession,
}

#[derive(Clone, Debug, Default)]
pub enum ClientChainObservation {
    #[default]
    NotVerified,
    Verified(VerifiedChainSet),
    Unavailable(ChainUnavailable),
}

#[derive(Clone, Debug)]
pub struct VerifiedChainRef {
    pub intermediates: Vec<u8>,
    pub root: Option<u8>,
}

#[derive(Clone, Debug)]
pub struct VerifiedChainSet {
    paths: Vec<VerifiedChainRef>,
    roots: Arc<[CertificateDer<'static>]>,
    binding: [u8; 32],
}

impl VerifiedChainSet {
    pub fn new(
        paths: Vec<VerifiedChainRef>,
        roots: Arc<[CertificateDer<'static>]>,
        binding: [u8; 32],
        peer_len: usize,
    ) -> Result<Self, Error> {
        // Validate peer_len: 1..=65
        if peer_len < 1 || peer_len > 65 {
            return Err(Error::General("invalid verified client chains".into()));
        }

        // Validate paths: 1..=16
        if paths.is_empty() || paths.len() > 16 {
            return Err(Error::General("invalid verified client chains".into()));
        }

        // Validate roots: <= 16
        if roots.len() > 16 {
            return Err(Error::General("invalid verified client chains".into()));
        }

        // Validate roots total DER bytes <= 16KiB
        let total_roots_bytes: usize = roots.iter().map(|c| c.len()).sum();
        if total_roots_bytes > 16384 || roots.iter().any(|cert| cert.is_empty()) {
            return Err(Error::General("invalid verified client chains".into()));
        }

        // Validate each path
        for path in &paths {
            // intermediates count <= 6
            if path.intermediates.len() > 6 {
                return Err(Error::General("invalid verified client chains".into()));
            }

            // If root is None, intermediates must be empty
            if path.root.is_none() && !path.intermediates.is_empty() {
                return Err(Error::General("invalid verified client chains".into()));
            }

            // Check no duplicate indices in intermediates
            if has_duplicate_indices(&path.intermediates) {
                return Err(Error::General("invalid verified client chains".into()));
            }

            // Validate each intermediate index: must be > 0 and < peer_len
            for &idx in &path.intermediates {
                if idx == 0 || idx >= peer_len as u8 {
                    return Err(Error::General("invalid verified client chains".into()));
                }
            }

            // Validate root index if present: must be < roots.len()
            if let Some(root_idx) = path.root {
                if root_idx >= roots.len() as u8 {
                    return Err(Error::General("invalid verified client chains".into()));
                }
            }
        }

        Ok(Self {
            paths,
            roots,
            binding,
        })
    }

    pub fn paths(&self) -> &[VerifiedChainRef] {
        &self.paths
    }

    pub fn roots(&self) -> &[CertificateDer<'static>] {
        &self.roots
    }

    pub fn binding(&self) -> [u8; 32] {
        self.binding
    }
}

impl ClientChainObservation {
    pub(crate) fn to_session_bytes(&self) -> Vec<u8> {
        match self {
            ClientChainObservation::NotVerified => {
                alloc::vec![0u8]
            }
            ClientChainObservation::Unavailable(reason) => {
                alloc::vec![2u8, *reason as u8]
            }
            ClientChainObservation::Verified(set) => {
                // Estimate size and check if it fits
                let estimated = estimated_verified_size(set);
                if estimated > 16384 {
                    return alloc::vec![2u8, ChainUnavailable::TooLargeForSession as u8];
                }

                let mut bytes = Vec::with_capacity(estimated);
                // status byte
                bytes.push(1u8);
                // binding
                bytes.extend_from_slice(&set.binding);
                // rootcount
                bytes.push(set.roots.len() as u8);
                // roots: (u16BE DERlen, DERbytes)*
                for cert in set.roots.iter() {
                    let len = cert.len();
                    // len must fit in u16 for encoding; checked earlier by total size constraints
                    if len > 65535 {
                        // This shouldn't happen if total <= 16384 and count <= 16,
                        // but be safe: return TooLarge
                        return alloc::vec![2u8, ChainUnavailable::TooLargeForSession as u8];
                    }
                    bytes.push((len >> 8) as u8);
                    bytes.push((len & 0xff) as u8);
                    bytes.extend_from_slice(cert.as_ref());
                }
                // pathcount
                bytes.push(set.paths.len() as u8);
                // paths
                for path in set.paths.iter() {
                    // intercount
                    bytes.push(path.intermediates.len() as u8);
                    // inter indices
                    for &idx in path.intermediates.iter() {
                        bytes.push(idx);
                    }
                    // rootindex
                    match path.root {
                        Some(idx) => bytes.push(idx),
                        None => bytes.push(0xff),
                    }
                }

                bytes
            }
        }
    }

    pub(crate) fn from_session_bytes(bytes: &[u8], peer_len: usize) -> Option<Self> {
        // Must be non-empty
        if bytes.is_empty() {
            return None;
        }
        // Must be <= 16384
        if bytes.len() > 16384 {
            return None;
        }

        let mut cursor = Cursor::new(bytes);

        let status = cursor.take_u8()?;

        match status {
            0 => {
                // NotVerified: must consume all bytes
                if cursor.remaining() != 0 {
                    return None;
                }
                Some(ClientChainObservation::NotVerified)
            }
            1 => {
                // Verified
                let binding = cursor.take_32()?;
                let root_count = cursor.take_u8()? as usize;
                if root_count > 16 {
                    return None;
                }

                let mut roots: Vec<CertificateDer<'static>> = Vec::with_capacity(root_count);
                for _ in 0..root_count {
                    let der_len = cursor.take_u16_be()? as usize;
                    let der_bytes = cursor.take(der_len)?;
                    if der_bytes.is_empty() {
                        // DER bytes must not be empty
                        return None;
                    }
                    roots.push(CertificateDer::from(der_bytes.to_vec()));
                }

                // Check total roots bytes <= 16KiB
                let total_roots_bytes: usize = roots.iter().map(|c| c.len()).sum();
                if total_roots_bytes > 16384 {
                    return None;
                }

                let path_count = cursor.take_u8()? as usize;
                if path_count == 0 || path_count > 16 {
                    return None;
                }

                let mut paths: Vec<VerifiedChainRef> = Vec::with_capacity(path_count);
                for _ in 0..path_count {
                    let inter_count = cursor.take_u8()? as usize;
                    if inter_count > 6 {
                        return None;
                    }
                    let mut intermediates = Vec::with_capacity(inter_count);
                    for _ in 0..inter_count {
                        let idx = cursor.take_u8()?;
                        // Validate index: > 0 and < peer_len
                        if peer_len == 0 {
                            return None;
                        }
                        if idx == 0 || idx >= peer_len as u8 {
                            return None;
                        }
                        intermediates.push(idx);
                    }
                    // Check no duplicates in intermediates
                    if has_duplicate_indices(&intermediates) {
                        return None;
                    }
                    let root_byte = cursor.take_u8()?;
                    let root: Option<u8> = if root_byte == 0xff {
                        None
                    } else {
                        Some(root_byte)
                    };

                    // If root is None, intermediates must be empty
                    if root.is_none() && !intermediates.is_empty() {
                        return None;
                    }

                    // If root is Some, it must be < root_count
                    if let Some(root_idx) = root {
                        if root_idx >= root_count as u8 {
                            return None;
                        }
                    }

                    paths.push(VerifiedChainRef {
                        intermediates,
                        root,
                    });
                }

                // Must consume all bytes
                if cursor.remaining() != 0 {
                    return None;
                }

                let arc_roots: Arc<[CertificateDer<'static>]> = Arc::from(roots.into_boxed_slice());

                // peer_len validation: for Verified, peer_len must be 1..=65
                // and indices were already validated against peer_len above
                // (idx < peer_len and idx > 0)

                let set = VerifiedChainSet::new(paths, arc_roots, binding, peer_len).ok()?;

                Some(ClientChainObservation::Verified(set))
            }
            2 => {
                // Unavailable
                let reason = cursor.take_u8()?;
                if cursor.remaining() != 0 {
                    return None;
                }
                let chain_unavailable = match reason {
                    0 => ChainUnavailable::EnumerationLimit,
                    1 => ChainUnavailable::RootSourceUnknown,
                    2 => ChainUnavailable::PlatformVerifier,
                    3 => ChainUnavailable::PolicyDivergence,
                    4 => ChainUnavailable::TooLargeForSession,
                    5 => ChainUnavailable::LegacySession,
                    _ => return None,
                };
                if peer_len == 0 && chain_unavailable != ChainUnavailable::LegacySession { return None; }
                Some(ClientChainObservation::Unavailable(chain_unavailable))
            }
            _ => None,
        }
    }
}

fn has_duplicate_indices(indices: &[u8]) -> bool {
    for i in 0..indices.len() {
        for j in i + 1..indices.len() {
            if indices[i] == indices[j] {
                return true;
            }
        }
    }
    false
}

fn estimated_verified_size(set: &VerifiedChainSet) -> usize {
    // status: 1
    let mut size = 1;
    // binding: 32
    size += 32;
    // rootcount: 1
    size += 1;
    // roots
    for cert in set.roots.iter() {
        // u16BE length: 2
        size += 2;
        // DER bytes
        size += cert.len();
    }
    // pathcount: 1
    size += 1;
    // paths
    for path in set.paths.iter() {
        // intercount: 1
        size += 1;
        // inter indices
        size += path.intermediates.len();
        // root index: 1
        size += 1;
    }
    size
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.offset
    }

    fn take(&mut self, count: usize) -> Option<&'a [u8]> {
        let new_offset = checked_add(self.offset, count)?;
        if new_offset > self.bytes.len() {
            return None;
        }
        let slice = &self.bytes[self.offset..new_offset];
        self.offset = new_offset;
        Some(slice)
    }

    fn take_u8(&mut self) -> Option<u8> {
        let slice = self.take(1)?;
        Some(slice[0])
    }

    fn take_u16_be(&mut self) -> Option<u16> {
        let slice = self.take(2)?;
        let hi = slice[0] as u16;
        let lo = slice[1] as u16;
        Some((hi << 8) | lo)
    }

    fn take_32(&mut self) -> Option<[u8; 32]> {
        let slice = self.take(32)?;
        let mut buf = [0u8; 32];
        buf.copy_from_slice(slice);
        Some(buf)
    }
}

fn checked_add(a: usize, b: usize) -> Option<usize> {
    a.checked_add(b)
}

pub(crate) fn resumption_allowed(verifier: &dyn crate::verify::ClientCertVerifier,
    session: &crate::msgs::persist::ServerSessionValue) -> bool {
    if session.client_cert_chain.as_ref().is_none_or(|chain| chain.is_empty()) { return true; }
    if verifier.resume_requires_verified_chains() {
        return matches!(&session.native_client_chains, ClientChainObservation::Verified(set)
            if Some(set.binding()) == verifier.chain_binding());
    }
    match (&session.native_client_chains, verifier.chain_binding()) {
        (ClientChainObservation::Verified(set), Some(binding)) => set.binding() == binding,
        _ => true,
    }
}

pub(crate) fn restored_observation(verifier: &dyn crate::verify::ClientCertVerifier,
    session: &crate::msgs::persist::ServerSessionValue) -> ClientChainObservation {
    if session.client_cert_chain.as_ref().is_none_or(|chain|chain.is_empty()) {
        return ClientChainObservation::NotVerified;
    }
    if !verifier.resume_requires_verified_chains()
        && matches!(session.native_client_chains,
            ClientChainObservation::Unavailable(ChainUnavailable::LegacySession)) {
        return ClientChainObservation::NotVerified;
    }
    session.native_client_chains.clone()
}
