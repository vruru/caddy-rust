//! Public reverse-proxy host counters; no credentials or upstream config.
use super::AdminError;
use serde::Serialize;
use std::io::Write;
#[derive(Serialize)]
pub struct UpstreamStatus { pub address: String, pub num_requests: u64, pub fails: u64 }
pub(super) fn encode(rows:&[UpstreamStatus],pool:&super::byte_budget::Pool)->Result<hyper::body::Bytes,AdminError> {
    const LIMIT:usize=8<<20;
    struct Count(usize);
    impl Write for Count {
        fn write(&mut self,bytes:&[u8])->std::io::Result<usize>{self.0=self.0.checked_add(bytes.len()).filter(|n|*n<=LIMIT).ok_or_else(||std::io::Error::other("upstream response limit exceeded"))?;Ok(bytes.len())}
        fn flush(&mut self)->std::io::Result<()>{Ok(())}
    }
    fn json<W:Write>(mut writer:W,rows:&[UpstreamStatus])->Result<(),serde_json::Error>{
        rows.serialize(&mut serde_json::Serializer::with_formatter(&mut writer,super::pki::GoFormatter))?;
        writer.write_all(b"\n").map_err(serde_json::Error::io)
    }
    let mut count=Count(0);json(&mut count,rows).map_err(|_|AdminError::new(413,"upstream_response_too_large"))?;
    let mut output=super::byte_budget::Buffer::new(pool,count.0)?;
    json(&mut output,rows).map_err(|_|AdminError::new(500,"upstream_response_encoding_failed"))?;
    let(data,credit)=output.into_parts();Ok(super::byte_budget::Buffer::into_bytes(data,credit))
}
