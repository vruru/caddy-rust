use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use zeroize::Zeroizing;

static USED: AtomicUsize = AtomicUsize::new(0);
const CAPACITY: usize = 32 * 1024 * 1024;
const INPUT_CAPACITY: usize = 16 * 1024 * 1024;
static INPUT_USED: AtomicUsize = AtomicUsize::new(0);
#[derive(Debug, Clone, Copy)]
enum Class {
    Engine,
    Input,
}

/// Credit token for buffer reservations.
///
/// Rust transfer buffers only, caller/FFI allocations separate.
#[derive(Debug)]
pub(super) struct Credit {
    bytes: usize,
    class: Class,
}

impl Credit {
    /// Reserves `bytes` of capacity, returning a Credit on success.
    ///
    /// Uses checked_add and atomic compare_exchange with AcqRel ordering.
    /// Returns OutOfMemory if capacity is exceeded.
    pub(super) fn reserve(bytes: usize) -> io::Result<Self> {
        Self::reserve_class(bytes, Class::Engine)
    }
    fn reserve_input(bytes: usize) -> io::Result<Self> {
        Self::reserve_class(bytes, Class::Input)
    }
    fn reserve_class(bytes: usize, class: Class) -> io::Result<Self> {
        let (used, cap) = match class {
            Class::Engine => (&USED, CAPACITY),
            Class::Input => (&INPUT_USED, INPUT_CAPACITY),
        };
        used.try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
            n.checked_add(bytes).filter(|n| *n <= cap)
        })
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::OutOfMemory,
                "SSL transfer buffer capacity exhausted",
            )
        })?;
        Ok(Self { bytes, class })
    }
    pub(super) fn input_usage() -> (usize, usize) {
        (INPUT_USED.load(Ordering::Acquire), INPUT_CAPACITY)
    }
    /// Returns (usage, capacity).
    pub(super) fn usage() -> (usize, usize) {
        (USED.load(Ordering::Acquire), CAPACITY)
    }
}

impl Drop for Credit {
    fn drop(&mut self) {
        match self.class {
            Class::Engine => &USED,
            Class::Input => &INPUT_USED,
        }
        .fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

/// Encrypted input buffer with credit.
///
/// Rust transfer buffers only, caller/FFI allocations separate.
pub struct EncryptedInput {
    bytes: Vec<u8>,
    _credit: Credit,
}

impl EncryptedInput {
    /// Creates a new EncryptedInput from `data`.
    ///
    /// Maximum length 32768. Reserves len + 256 bytes of credit, then
    /// try_reserve_exact and extends. Empty input is allowed.
    pub fn new(data: &[u8]) -> io::Result<Self> {
        if data.len() > 32768 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "input exceeds 32768 bytes",
            ));
        }
        let credit_bytes = data.len().saturating_add(256);
        let credit = Credit::reserve_input(credit_bytes)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(data.len())
            .map_err(|_| io::Error::new(io::ErrorKind::OutOfMemory, "allocation failed"))?;
        bytes.extend_from_slice(data);
        Ok(EncryptedInput {
            bytes,
            _credit: credit,
        })
    }

    pub(super) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Owned write buffer with credit.
///
/// Rust transfer buffers only, caller/FFI allocations separate.
pub struct OwnedWrite {
    bytes: Zeroizing<Vec<u8>>,
    offset: usize,
    _credit: Credit,
}

impl OwnedWrite {
    pub(super) fn remaining(&self) -> &[u8] {
        &self.bytes[self.offset..]
    }
    pub(super) fn advance(&mut self, n: usize) {
        self.offset += n;
    }
    /// Creates a new OwnedWrite from `data`.
    ///
    /// Maximum length 16384. Reserves len + 256 bytes of credit, then copies.
    pub fn new(data: &[u8]) -> io::Result<Self> {
        if data.len() > 16384 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "input exceeds 16384 bytes",
            ));
        }
        let credit_bytes = data.len().saturating_add(256);
        let credit = Credit::reserve_input(credit_bytes)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(data.len())
            .map_err(|_| io::Error::new(io::ErrorKind::OutOfMemory, "allocation failed"))?;
        bytes.extend_from_slice(data);
        Ok(OwnedWrite {
            bytes: Zeroizing::new(bytes),
            offset: 0,
            _credit: credit,
        })
    }
}

/// Step data holding wire, plaintext, optional retry, and credit.
///
/// Rust transfer buffers only, caller/FFI allocations separate.
pub struct StepData {
    wire: Vec<u8>,
    plaintext: Zeroizing<Vec<u8>>,
    retry: Option<OwnedWrite>,
    _credit: Credit,
}

impl StepData {
    /// Creates a new StepData.
    pub(super) fn new(
        wire: Vec<u8>,
        plaintext: Zeroizing<Vec<u8>>,
        retry: Option<OwnedWrite>,
        credit: Credit,
    ) -> Self {
        StepData {
            wire,
            plaintext,
            retry,
            _credit: credit,
        }
    }

    /// Returns wire as a slice.
    pub fn wire(&self) -> &[u8] {
        &self.wire
    }

    /// Returns plaintext as a slice.
    pub fn plaintext(&self) -> &[u8] {
        &self.plaintext
    }

    /// Consumes self, returning the retry if present.
    ///
    /// The returned OwnedWrite carries its own independent credit.
    /// Other fields drop normally.
    pub fn take_retry(&mut self) -> Option<OwnedWrite> {
        self.retry.take()
    }
    pub(super) fn recycle(self) -> Credit {
        let Self {
            wire,
            plaintext,
            retry,
            _credit,
        } = self;
        drop(wire);
        drop(plaintext);
        drop(retry);
        _credit
    }

    /// Reserves credit for output: loan of 32768 + 16384 + 512.
    ///
    /// Call before engine produces wire/plaintext.
    pub(super) fn reserve_output() -> io::Result<Credit> {
        let loan = 32768 + 16384 + 512;
        Credit::reserve(loan)
    }
}
