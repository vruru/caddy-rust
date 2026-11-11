use std::io::{self, Write};
use std::mem;

const MAX_SINK_SIZE: usize = 196_608;
const MAX_INPUT_SIZE: usize = 65_536;

struct BoundedSink {
    buf: Vec<u8>,
}

impl Write for BoundedSink {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let new_len = self.buf.len().saturating_add(data.len());
        if new_len > MAX_SINK_SIZE {
            return Err(io::Error::other("zstd output bound exceeded"));
        }
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl BoundedSink {
    fn new() -> Self {
        BoundedSink { buf: Vec::new() }
    }
}

pub(super) struct ZstdCodec {
    encoder: zstd::stream::write::Encoder<'static, BoundedSink>,
    failed: bool,
}

impl ZstdCodec {
    pub(super) fn new(level: &str, checksum: Option<bool>) -> io::Result<Self> {
        let level: i32 = match level.to_ascii_lowercase().as_str() {
            "" | "default" => 3,
            "fastest" => 1,
            "better" => 7,
            "best" => 11,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid zstd level",
                ));
            }
        };

        let sink = BoundedSink::new();
        let mut encoder = zstd::stream::write::Encoder::new(sink, level)?;

        encoder.window_log(17)?;

        encoder.include_checksum(checksum.unwrap_or(true))?;

        encoder.include_contentsize(false)?;

        Ok(ZstdCodec {
            encoder,
            failed: false,
        })
    }

    pub(super) fn write(&mut self, input: &[u8], flush: bool) -> io::Result<Vec<u8>> {
        if self.failed {
            return Err(io::Error::other("zstd encoder failed"));
        }
        if input.len() > MAX_INPUT_SIZE {
            self.failed = true;
            return Err(io::Error::other("zstd chunk limit exceeded"));
        }
        let result = self
            .encoder
            .write_all(input)
            .and_then(|()| if flush { self.encoder.flush() } else { Ok(()) });
        if let Err(error) = result {
            self.failed = true;
            return Err(error);
        }
        Ok(mem::take(&mut self.encoder.get_mut().buf))
    }
    pub(super) fn finish(self) -> io::Result<Vec<u8>> {
        if self.failed {
            return Err(io::Error::other("zstd encoder failed"));
        }
        Ok(self.encoder.finish()?.buf)
    }
}
