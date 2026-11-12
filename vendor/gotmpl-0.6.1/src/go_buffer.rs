// go_buffer.rs — Go-formatter migration buffer (no_std + alloc, forbid unsafe)
//
// ByteBuffer: the single output buffer for top-level format emission.
//   Other user Values are NOT stringified into this buffer.
// FmtCursor: a byte-position cursor over the format string, replacing
//   Peekable<&[u8]-iter> from the original Go formatter.


use alloc::vec::Vec;
use core::fmt;

// ---------------------------------------------------------------------------
// ByteBuffer
// ---------------------------------------------------------------------------

/// Maximum byte length of the format-output buffer (1 MiB).
const MAX: usize = 1 << 20;

/// Accumulates formatted output as raw bytes.
///
/// Every mutating method sets `failed = true` on capacity overflow and
/// silently becomes a no-op thereafter, so callers never need to check
/// an error at each call-site.  Call [`check`](Self::check) once at the
/// end to propagate the single possible error.
pub(crate) struct ByteBuffer {
    bytes: Vec<u8>,
    failed: bool,
}

impl ByteBuffer {
    // ---- construction -----------------------------------------------------

    /// Create an empty buffer with no pre-allocated capacity.
    pub(crate) fn new() -> Self {
        Self {
            bytes: Vec::new(),
            failed: false,
        }
    }

    /// Create a buffer with initial capacity clamped to [`MAX`].
    ///
    /// A requested capacity larger than MAX is silently reduced to MAX;
    /// the buffer is NOT marked `failed`.
    pub(crate) fn with_capacity(cap: usize) -> Self {
        let cap = core::cmp::min(cap, MAX);
        Self {
            bytes: Vec::with_capacity(cap),
            failed: false,
        }
    }

    // ---- accessors --------------------------------------------------------

    /// View the accumulated bytes.
    #[inline]
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Current number of bytes in the buffer.
    #[inline]
    pub(crate) fn len(&self) -> usize {
        self.bytes.len()
    }

    /// True when the buffer contains zero bytes.
    #[inline]
    pub(crate) fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Consume the buffer and hand back the underlying `Vec<u8>`.
    #[inline]
    pub(crate) fn repeat_ascii(&mut self,pos:usize,byte:u8,count:usize){
        if self.failed{return;}if pos>self.bytes.len()||self.overflows(count){self.failed=true;return;}
        let old=self.bytes.len();self.bytes.resize(old+count,0);self.bytes.copy_within(pos..old,pos+count);self.bytes[pos..pos+count].fill(byte);
    }
    pub(crate) fn into_vec(self) -> Vec<u8> {
        self.bytes
    }

    /// Return `Ok(())` if no overflow occurred, otherwise a single
    /// `Err` with the canonical message.
    pub(crate) fn reject_size(&mut self){self.failed=true;}
    pub(crate) fn check(&self) -> crate::Result<()> {
        if self.failed {
            Err(crate::TemplateError::OutputTooLarge)
        } else {
            Ok(())
        }
    }

    // ---- private size guard -----------------------------------------------

    /// Returns `true` (and marks `failed`) when appending `additional`
    /// bytes would exceed [`MAX`] or overflow `usize`.
    #[inline]
    fn overflows(&mut self, additional: usize) -> bool {
        match self.bytes.len().checked_add(additional) {
            Some(n) if n <= MAX => false,
            _ => {
                self.failed = true;
                true
            }
        }
    }

    // ---- push / append (void, no-op after failure) ------------------------

    /// Append a single `char` (UTF-8 encoded) to the buffer.
    pub(crate) fn push(&mut self, ch: char) {
        if self.failed {
            return;
        }
        // A char encodes to at most 4 UTF-8 bytes.
        if self.overflows(ch.len_utf8()) {
            return;
        }
        let mut buf = [0u8; 4];
        self.bytes.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
    }

    /// Append an entire `&str`.
    pub(crate) fn push_str(&mut self, s: &str) {
        if self.failed {
            return;
        }
        if self.overflows(s.len()) {
            return;
        }
        self.bytes.extend_from_slice(s.as_bytes());
    }

    /// Append raw bytes (already valid in the output encoding).
    pub(crate) fn push_bytes(&mut self, b: &[u8]) {
        if self.failed {
            return;
        }
        if self.overflows(b.len()) {
            return;
        }
        self.bytes.extend_from_slice(b);
    }

    // ---- insert (void, no-op after failure) -------------------------------

    /// Insert a single `char` at byte position `pos`.
    ///
    /// No UTF-8 boundary check is performed: `bytes` is a raw byte Vec,
    /// matching the original Go formatter's byte-level semantics.
    pub(crate) fn insert(&mut self, pos: usize, ch: char) {
        if self.failed {
            return;
        }
        // A char is at most 4 bytes, so pos must not exceed len.
        if pos > self.bytes.len() {
            self.failed = true;
            return;
        }
        if self.overflows(ch.len_utf8()) {
            return;
        }
        let mut buf = [0u8; 4];
        let encoded = ch.encode_utf8(&mut buf).as_bytes();
        self.bytes.splice(pos..pos, encoded.iter().copied());
    }

    /// Insert a `&str` at byte position `pos`.
    pub(crate) fn insert_str(&mut self, pos: usize, s: &str) {
        if self.failed {
            return;
        }
        if pos > self.bytes.len() {
            self.failed = true;
            return;
        }
        if self.overflows(s.len()) {
            return;
        }
        self.bytes.splice(pos..pos, s.bytes());
    }

    // ---- reserve ----------------------------------------------------------

    /// Hint that at least `additional` more bytes will be appended.
    ///
    /// Performs no allocation when the buffer has already `failed`
    /// or when the hint would push past [`MAX`].
    pub(crate) fn reserve(&mut self, additional: usize) {
        if self.failed {
            return;
        }
        match self.bytes.len().checked_add(additional) {
            Some(n) if n <= MAX => self.bytes.reserve(additional),
            _ => self.failed = true,
        }
    }
}

// ---- core::fmt::Write ----------------------------------------------------

impl fmt::Write for ByteBuffer {
    #[inline]
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.push_str(s);
        if self.failed {
            Err(fmt::Error)
        } else {
            Ok(())
        }
    }
}

impl crate::go_write::GoWrite for ByteBuffer {fn write_bytes(&mut self,b:&[u8])->fmt::Result{self.push_bytes(b);if self.failed{Err(fmt::Error)}else{Ok(())}}}

// ---------------------------------------------------------------------------
// FmtCursor
// ---------------------------------------------------------------------------

/// Byte-position cursor over a format string.
///
/// Replaces `Peekable<bytes::Iter>` from the original Go formatter.
/// Top-level callers can capture the byte slice of a literal between
/// positions: `&bytes[before .. after]`.
#[derive(Clone)]
pub(crate) struct FmtCursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> FmtCursor<'a> {
    /// Create a cursor at position 0 over `bytes`.
    #[inline]
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    /// Current byte position.
    #[inline]
    pub(crate) fn position(&self) -> usize {
        self.position
    }

    /// Decode the next rune **without** advancing.
    ///
    /// Uses `crate::decode_go_rune` which returns `(char, width)`.
    /// An invalid byte yields the replacement character with width 1.
    #[inline]
    pub(crate) fn peek(&self) -> Option<char> {
        if self.position >= self.bytes.len() {
            return None;
        }
        let (ch, _width) = crate::decode_go_rune(&self.bytes[self.position..])?;
        Some(ch)
    }

    /// Decode the next rune, advancing the position by the rune's width.
    ///
    /// Invalid bytes consume exactly 1 byte (replacement char).
    #[inline]
    pub(crate) fn advance(&mut self) -> Option<char> {
        if self.position >= self.bytes.len() {
            return None;
        }
        let (ch, width) = crate::decode_go_rune(&self.bytes[self.position..])?;
        self.position += width;
        Some(ch)
    }

    /// Peek the next rune; advance **only** if `predicate` accepts it.
    ///
    /// Mirrors `Peekable::next_if` from the standard library so that
    /// call-sites migrated from the original Go formatter keep working.
    #[inline]
    pub(crate) fn next_if(
        &mut self,
        predicate: impl FnOnce(&char) -> bool,
    ) -> Option<char> {
        if self.peek().is_some_and(|c| predicate(&c)) {
            self.advance()
        } else {
            None
        }
    }
}

/// Allow `for ch in cursor` style iteration.
impl<'a> Iterator for FmtCursor<'a> {
    type Item = char;

    #[inline]
    fn next(&mut self) -> Option<char> {
        self.advance()
    }
}
