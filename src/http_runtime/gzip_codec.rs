//! Bounded gzip wire encoder backed by zlib's raw DEFLATE implementation.
//! The stateless mode releases its complete zlib window after every write.
use crc32fast::Hasher;
use libz_sys as z;
use std::{cell::Cell, io, marker::PhantomData, ptr};

const CHUNK_MAX: usize = 65536;
const OUTPUT_MAX: usize = 196608;
const HEADER: &[u8] = &[31, 139, 8, 0, 0, 0, 0, 0, 0, 255];

pub(super) struct GzipCodec {
    stream: Option<RawDeflater>,
    stateless: bool,
    header_written: bool,
    crc: Hasher,
    size: u32,
    failed: bool,
}
impl GzipCodec {
    pub(super) fn new(level: i32) -> io::Result<Self> {
        let stateless = level == -3;
        let (level, strategy) = match level {
            -3 => (6, z::Z_DEFAULT_STRATEGY),
            -2 => (6, z::Z_HUFFMAN_ONLY),
            -1 => (6, z::Z_DEFAULT_STRATEGY),
            0 => (5, z::Z_DEFAULT_STRATEGY),
            1..=9 => (level, z::Z_DEFAULT_STRATEGY),
            _ => return Err(invalid("invalid gzip level")),
        };
        // The stateless mode must not allocate or keep a window between calls.
        Ok(Self {
            stream: if stateless {
                None
            } else {
                Some(RawDeflater::new(level, strategy)?)
            },
            stateless,
            header_written: false,
            crc: Hasher::new(),
            size: 0,
            failed: false,
        })
    }
    fn header(&mut self, out: &mut Vec<u8>) {
        if !self.header_written {
            out.extend_from_slice(HEADER);
            self.header_written = true;
        }
    }
    pub(super) fn write(&mut self, input: &[u8], flush: bool) -> io::Result<Vec<u8>> {
        if self.failed {
            return Err(invalid("gzip encoder failed"));
        }
        if input.len() > CHUNK_MAX {
            self.failed = true;
            return Err(invalid("gzip chunk limit exceeded"));
        }
        let mut out = Vec::new();
        self.header(&mut out);
        let result = if self.stateless {
            if input.is_empty() {
                Ok(())
            } else {
                RawDeflater::new(6, z::Z_DEFAULT_STRATEGY)
                    .and_then(|mut raw| raw.process(input, z::Z_SYNC_FLUSH, &mut out))
            }
        } else {
            self.stream
                .as_mut()
                .expect("stateful encoder owns stream")
                .process(
                    input,
                    if flush {
                        z::Z_SYNC_FLUSH
                    } else {
                        z::Z_NO_FLUSH
                    },
                    &mut out,
                )
        };
        if let Err(error) = result {
            self.failed = true;
            return Err(error);
        }
        self.crc.update(input);
        self.size = self.size.wrapping_add(input.len() as u32);
        Ok(out)
    }
    pub(super) fn finish(mut self) -> io::Result<Vec<u8>> {
        if self.failed {
            return Err(invalid("gzip encoder failed"));
        }
        let mut out = Vec::new();
        self.header(&mut out);
        if self.stateless {
            // All preceding SYNC_FLUSH writes ended on a byte boundary and
            // emitted only BFINAL=0 blocks. End the single DEFLATE stream.
            out.extend_from_slice(&[1, 0, 0, 255, 255]);
        } else {
            self.stream
                .as_mut()
                .expect("stateful encoder owns stream")
                .process(&[], z::Z_FINISH, &mut out)?;
        }
        out.extend_from_slice(&self.crc.finalize().to_le_bytes());
        out.extend_from_slice(&self.size.to_le_bytes());
        Ok(out)
    }
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::other(message)
}

struct RawDeflater {
    stream: Box<z::z_stream>,
    initialized: bool,
    _not_sync: PhantomData<Cell<()>>,
}
// SAFETY: zlib has no thread affinity. The allocation containing z_stream is
// address-stable, uniquely owned and never accessed concurrently. Input/output
// pointers exist only during process() and are cleared before it returns.
unsafe impl Send for RawDeflater {}
impl RawDeflater {
    fn new(level: i32, strategy: i32) -> io::Result<Self> {
        let mut this = Self {
            stream: Box::new(z::z_stream {
                next_in: ptr::null_mut(),
                avail_in: 0,
                total_in: 0,
                next_out: ptr::null_mut(),
                avail_out: 0,
                total_out: 0,
                msg: ptr::null_mut(),
                state: ptr::null_mut(),
                zalloc: allocate,
                zfree: release,
                opaque: ptr::null_mut(),
                data_type: 0,
                adler: 0,
                reserved: 0,
            }),
            initialized: false,
            _not_sync: PhantomData,
        };
        // SAFETY: the boxed structure is initialized, uniquely borrowed and
        // remains at the same address until its paired deflateEnd in Drop.
        let code = unsafe {
            z::deflateInit2_(
                &mut *this.stream,
                level,
                z::Z_DEFLATED,
                -15,
                8,
                strategy,
                z::zlibVersion(),
                std::mem::size_of::<z::z_stream>() as i32,
            )
        };
        if code != z::Z_OK {
            return Err(invalid("gzip initialization failed"));
        }
        this.initialized = true;
        Ok(this)
    }
    fn process(&mut self, input: &[u8], mode: i32, out: &mut Vec<u8>) -> io::Result<()> {
        if input.is_empty() && mode == z::Z_NO_FLUSH {
            return Ok(());
        }
        self.stream.next_in = input.as_ptr().cast_mut();
        self.stream.avail_in = input.len() as z::uInt;
        let result = self.process_inner(mode, out);
        self.stream.next_in = ptr::null_mut();
        self.stream.avail_in = 0;
        self.stream.next_out = ptr::null_mut();
        self.stream.avail_out = 0;
        result
    }
    fn process_inner(&mut self, mode: i32, out: &mut Vec<u8>) -> io::Result<()> {
        let mut buffer = [0u8; 16384];
        loop {
            let input_before = self.stream.avail_in;
            self.stream.next_out = buffer.as_mut_ptr();
            self.stream.avail_out = buffer.len() as z::uInt;
            // SAFETY: input/output slices remain alive and non-overlapping for
            // the synchronous call. zlib receives their exact bounded lengths.
            let code = unsafe { z::deflate(&mut *self.stream, mode) };
            let produced = buffer.len() - self.stream.avail_out as usize;
            if out.len().saturating_add(produced) > OUTPUT_MAX {
                return Err(invalid("gzip output bound exceeded"));
            }
            out.extend_from_slice(&buffer[..produced]);
            if code == z::Z_STREAM_END {
                return if mode == z::Z_FINISH && self.stream.avail_in == 0 {
                    Ok(())
                } else {
                    Err(invalid("unexpected gzip stream end"))
                };
            }
            if code != z::Z_OK
                && !(code == z::Z_BUF_ERROR && mode == z::Z_SYNC_FLUSH && self.stream.avail_in == 0)
            {
                return Err(invalid("gzip compression failed"));
            }
            if mode != z::Z_FINISH && self.stream.avail_in == 0 && self.stream.avail_out != 0 {
                return Ok(());
            }
            if produced == 0 && input_before == self.stream.avail_in {
                return Err(invalid("gzip encoder made no progress"));
            }
        }
    }
}
impl Drop for RawDeflater {
    fn drop(&mut self) {
        if self.initialized {
            // SAFETY: exactly one matching successful Init; pointer remains
            // valid and uniquely owned. An unfinished stream may return DATA_ERROR.
            unsafe {
                z::deflateEnd(&mut *self.stream);
            }
        }
    }
}
unsafe extern "C" fn allocate(_: z::voidpf, items: z::uInt, size: z::uInt) -> z::voidpf {
    let Some(total) = (items as usize).checked_mul(size as usize) else {
        return ptr::null_mut();
    };
    // SAFETY: calloc accepts this checked size. A null allocation is handled by zlib.
    unsafe { libc::calloc(1, total) }
}
unsafe extern "C" fn release(_: z::voidpf, allocation: z::voidpf) {
    // SAFETY: zlib only passes allocations from the paired calloc callback.
    unsafe {
        libc::free(allocation);
    }
}
