//! A job never duplicates a downloaded chain when cloned or checkpointed.
//! Raw FD input, JSON decode scratch, snapshot metadata and encoded output
//! are admitted by actual size. Downloaded PEM remains shared payload memory.
use super::Job;
use crate::acme_wire::chain_memory::{self, Buffer, Scratch};
use anyhow::{Result, anyhow, ensure};
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{self, SeqAccess, Visitor},
};
use std::{fmt, io::Write, sync::Arc};
use zeroize::Zeroizing;

const MAX_FILE: usize = 12 * 1024 * 1024;
pub(super) struct Snapshot {
    job: Job,
    lease_name: String,
    _credit: Scratch,
}
fn clone_bytes(job: &Job) -> Result<usize> {
    validate(job)?;
    let mut bytes = 8192usize;
    let mut string = |s: &str| -> Result<()> {
        bytes = bytes
            .checked_add(s.len())
            .ok_or(crate::cert_transient::ResourceDenied)?;
        Ok(())
    };
    for s in [
        &job.directory,
        &job.account_location,
        &job.config_email,
        &job.profile,
        &job.attempt_id,
        &job.phase,
        &job.private_key_pem,
    ] {
        string(s)?;
    }
    for s in [
        &job.initial_key_hash,
        &job.requested_not_after,
        &job.order_url,
        &job.certificate_url,
        &job.stored_leaf_sha256,
    ]
    .into_iter()
    .flatten()
    {
        string(s)?;
    }
    for s in job.names.iter().chain(job.renewal_names.iter().flatten()) {
        string(s)?;
    }
    let count = job.names.len() + job.renewal_names.as_ref().map_or(0, Vec::len);
    bytes = bytes
        .checked_add(count * std::mem::size_of::<String>())
        .and_then(|n| n.checked_add(job.csr_der.len()))
        .ok_or(crate::cert_transient::ResourceDenied)?;
    Ok(bytes)
}
pub(super) async fn snapshot(job: &Job, lease_name: &str) -> Result<Snapshot> {
    let bytes = clone_bytes(job)?
        .checked_add(lease_name.len())
        .ok_or(crate::cert_transient::ResourceDenied)?;
    let credit = chain_memory::scratch(bytes, tokio_util::sync::CancellationToken::new()).await?;
    Ok(Snapshot {
        job: job.clone(),
        lease_name: lease_name.to_owned(),
        _credit: credit,
    })
}
pub(super) fn decode_credit(raw_bytes: usize) -> Result<Scratch> {
    // Raw allocation has its own FD-read owner. String contents cannot exceed
    // encoded input bytes, CSR Vec is bounded64KiB and two name arrays each100.
    // Unescape reallocation overlap <=3*raw; owned typed field bytes <=raw.
    let bytes = raw_bytes
        .checked_mul(4)
        .and_then(|n| n.checked_add(65536 + 8192))
        .ok_or(crate::cert_transient::ResourceDenied)?;
    chain_memory::try_scratch(bytes).map_err(|_| crate::cert_transient::ResourceDenied.into())
}
pub(super) struct Encoded {
    bytes: Zeroizing<Vec<u8>>,
    _credit: Scratch,
}
impl AsRef<[u8]> for Encoded {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}
impl Encoded {
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}
#[derive(Serialize)]
struct Record<'a> {
    #[serde(flatten)]
    job: &'a Job,
    lease_name: &'a str,
}
struct Count(usize);
impl Write for Count {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        let n = self
            .0
            .checked_add(b.len())
            .filter(|n| *n <= MAX_FILE)
            .ok_or_else(|| std::io::Error::other("ACME checkpoint file capacity"))?;
        self.0 = n;
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
struct Writer {
    bytes: Zeroizing<Vec<u8>>,
    limit: usize,
}
impl Write for Writer {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        if b.len() > self.limit - self.bytes.len() {
            return Err(std::io::Error::other(
                "ACME checkpoint changed during encoding",
            ));
        }
        self.bytes.extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
pub(super) fn encode(snapshot: Snapshot) -> Result<Encoded> {
    // Own the complete snapshot until its copied strings/CSR have died.
    let snapshot = snapshot;
    let record = Record {
        job: &snapshot.job,
        lease_name: &snapshot.lease_name,
    };
    let mut count = Count(0);
    serde_json::to_writer(&mut count, &record)
        .map_err(|_| crate::cert_transient::ResourceDenied)?;
    let credit =
        chain_memory::try_scratch(count.0).map_err(|_| crate::cert_transient::ResourceDenied)?;
    let mut bytes = Zeroizing::new(Vec::new());
    bytes
        .try_reserve_exact(count.0)
        .map_err(|_| crate::cert_transient::ResourceDenied)?;
    ensure!(
        bytes.capacity() == count.0,
        "unexpected ACME checkpoint capacity"
    );
    let mut writer = Writer {
        bytes,
        limit: count.0,
    };
    serde_json::to_writer(&mut writer, &record)?;
    ensure!(
        writer.bytes.len() == count.0,
        "ACME checkpoint encoding count mismatch"
    );
    drop(snapshot);
    Ok(Encoded {
        bytes: writer.bytes,
        _credit: credit,
    })
}
// All durable fields other than downloaded PEM remain small even for an
// adversarial on-disk journal. Limits are checked during decoding, before
// allocation; no intermediate serde_json::Value is constructed.
fn string<'de, D: Deserializer<'de>, const LIMIT: usize>(d: D) -> Result<String, D::Error> {
    struct V<const L: usize>;
    impl<'de, const L: usize> Visitor<'de> for V<L> {
        type Value = String;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "a string up to {L} bytes")
        }
        fn visit_str<E: de::Error>(self, s: &str) -> Result<String, E> {
            if s.len() > L {
                return Err(E::custom("ACME checkpoint string limit"));
            }
            Ok(s.to_owned())
        }
        fn visit_string<E: de::Error>(self, s: String) -> Result<String, E> {
            if s.len() > L {
                return Err(E::custom("ACME checkpoint string limit"));
            }
            Ok(s)
        }
    }
    d.deserialize_str(V::<LIMIT>)
}
pub(super) fn text<'de, D: Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    string::<D, 65536>(d)
}
pub(super) fn key<'de, D: Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    string::<D, 131072>(d)
}
pub(super) fn profile<'de, D: Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    string::<D, 1024>(d)
}
pub(super) fn optional_text<'de, D: Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    struct Text(String);
    impl<'de> Deserialize<'de> for Text {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            text(d).map(Self)
        }
    }
    Option::<Text>::deserialize(d).map(|x| x.map(|x| x.0))
}
pub(super) fn names<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
    struct Name(String);
    impl<'de> Deserialize<'de> for Name {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            string::<D, 253>(d).map(Self)
        }
    }
    struct V;
    impl<'de> Visitor<'de> for V {
        type Value = Vec<String>;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("up to 100 DNS names")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut v = Vec::with_capacity(100);
            while let Some(name) = seq.next_element::<Name>()? {
                if v.len() == 100 {
                    return Err(de::Error::custom("ACME checkpoint names limit"));
                }
                v.push(name.0)
            }
            Ok(v)
        }
    }
    d.deserialize_seq(V)
}
pub(super) fn optional_names<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<Option<Vec<String>>, D::Error> {
    struct Names(Vec<String>);
    impl<'de> Deserialize<'de> for Names {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            names(d).map(Self)
        }
    }
    Option::<Names>::deserialize(d).map(|x| x.map(|x| x.0))
}
pub(super) fn csr<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    struct V;
    impl<'de> Visitor<'de> for V {
        type Value = Vec<u8>;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("up to 64 KiB CSR")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut v = Vec::with_capacity(65536);
            while let Some(byte) = seq.next_element::<u8>()? {
                if v.len() == 65536 {
                    return Err(de::Error::custom("ACME checkpoint CSR limit"));
                }
                v.push(byte)
            }
            Ok(v)
        }
    }
    d.deserialize_seq(V)
}
pub(super) mod pem {
    use super::*;
    pub(crate) fn serialize<S: Serializer>(
        body: &Option<Arc<Buffer>>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        match body {
            None => s.serialize_none(),
            Some(body) => s.serialize_some(
                std::str::from_utf8(body.as_slice()).map_err(serde::ser::Error::custom)?,
            ),
        }
    }
    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Option<Arc<Buffer>>, D::Error> {
        struct Pem(Arc<Buffer>);
        impl<'de> Deserialize<'de> for Pem {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                struct V;
                impl<'de> Visitor<'de> for V {
                    type Value = Pem;
                    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                        f.write_str("an owned, prepaid PEM string")
                    }
                    fn visit_str<E: de::Error>(self, s: &str) -> Result<Pem, E> {
                        if s.len() > 4 * 1024 * 1024 {
                            return Err(E::custom("ACME checkpoint PEM limit"));
                        }
                        let body =
                            Buffer::assemble(&chain_memory::shared().payload, &[s.as_bytes()])
                                .map_err(|_|E::custom("native checkpoint payload admission denied"))?;
                        Ok(Pem(Arc::new(body)))
                    }
                }
                d.deserialize_str(V)
            }
        }
        Option::<Pem>::deserialize(d).map(|x| x.map(|x| x.0))
    }
}

pub(super) fn validate(job: &Job) -> Result<()> {
    ensure!(
        job.names.len() <= 100 && job.names.iter().all(|x| x.len() <= 253),
        "ACME checkpoint names limit"
    );
    ensure!(
        job.renewal_names
            .as_ref()
            .is_none_or(|v| v.len() <= 100 && v.iter().all(|x| x.len() <= 253)),
        "ACME checkpoint renewal names limit"
    );
    ensure!(
        job.csr_der.len() <= 65536
            && job.private_key_pem.len() <= 131072
            && job.profile.len() <= 1024,
        "ACME checkpoint material limit"
    );
    for text in [
        &job.directory,
        &job.account_location,
        &job.config_email,
        &job.attempt_id,
        &job.phase,
    ] {
        ensure!(text.len() <= 65536, "ACME checkpoint string limit");
    }
    for text in [
        &job.initial_key_hash,
        &job.requested_not_after,
        &job.order_url,
        &job.certificate_url,
        &job.stored_leaf_sha256,
    ]
    .into_iter()
    .flatten()
    {
        ensure!(text.len() <= 65536, "ACME checkpoint optional string limit");
    }
    Ok(())
}

/// Admission for typed strings transfers before the decode worker can return;
/// cancellation or an untouched completed JoinHandle retains the real owner.
pub(super) fn decode(raw:&[u8])->Result<Job>{
    let scratch=decode_credit(raw.len())?;
    let mut job:Job=serde_json::from_slice(raw).map_err(|error|{
        if error.to_string().starts_with("native checkpoint payload admission denied") {
            anyhow::Error::from(crate::cert_transient::ResourceDenied)
        }else{anyhow!(error).context("invalid ACME recovery checkpoint")}
    })?;
    let memory=chain_memory::shared().payload.reserve(clone_bytes(&job)?)
        .map_err(|_|crate::cert_transient::ResourceDenied)?;
    job.restored_memory=Some(Arc::new(memory));
    drop(scratch);Ok(job)
}

/// Bounded typed journal record encoding; no intermediate Value/key copy.
pub(super) fn encode_record(value:&impl Serialize,lease_name:&str)->Result<Encoded> {
    #[derive(Serialize)] struct Record<'a,T:Serialize>{#[serde(flatten)] value:&'a T,lease_name:&'a str}
    let record=Record{value,lease_name};let mut count=Count(0);
    serde_json::to_writer(&mut count,&record).map_err(|_|crate::cert_transient::ResourceDenied)?;
    let credit=chain_memory::try_scratch(count.0).map_err(|_|crate::cert_transient::ResourceDenied)?;
    let mut bytes=Zeroizing::new(Vec::new());bytes.try_reserve_exact(count.0).map_err(|_|crate::cert_transient::ResourceDenied)?;
    let mut writer=Writer{bytes,limit:count.0};serde_json::to_writer(&mut writer,&record)?;
    ensure!(writer.bytes.len()==count.0,"journal record encoding changed");
    Ok(Encoded{bytes:writer.bytes,_credit:credit})
}
