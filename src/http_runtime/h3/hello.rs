//! Bounded assembly of QUIC Initial CRYPTO fragments before actual TLS accept.
use std::sync::{Arc, Mutex};
const MAX_CLIENT_HELLO: usize = 32 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Limit,
    Conflict,
    Invalid,
}
#[derive(Debug)]
pub struct Hello {
    pub server_name: Option<String>,
    pub protocols: Vec<Vec<u8>>,
    pub signatures: Vec<rustls::SignatureScheme>,
    pub event:super::super::tls_events::HelloFields,
}

pub struct Crypto {
    bytes: Vec<u8>,
    present: Vec<bool>,
    contiguous: usize,
    needed: Option<usize>,
}
impl Crypto {
    pub fn new() -> Self {
        Self {
            bytes: Vec::new(),
            present: Vec::new(),
            contiguous: 0,
            needed: None,
        }
    }
    pub fn add(&mut self, offset: u64, fragment: &[u8]) -> Result<(), Error> {
        let offset = usize::try_from(offset).map_err(|_| Error::Limit)?;
        let end = offset
            .checked_add(fragment.len())
            .filter(|&n| n <= MAX_CLIENT_HELLO)
            .ok_or(Error::Limit)?;
        if self.bytes.len() < end {
            self.bytes.resize(end, 0);
            self.present.resize(end, false);
        }
        for (position, &value) in (offset..end).zip(fragment) {
            if self.present[position] && self.bytes[position] != value {
                return Err(Error::Conflict);
            }
            self.bytes[position] = value;
            self.present[position] = true;
        }
        while self.present.get(self.contiguous) == Some(&true) {
            self.contiguous += 1;
        }
        if self.needed.is_none() && self.contiguous >= 4 {
            if self.bytes[0] != 1 {
                return Err(Error::Invalid);
            }
            let length =
                u32::from_be_bytes([0, self.bytes[1], self.bytes[2], self.bytes[3]]) as usize;
            self.needed = Some(
                length
                    .checked_add(4)
                    .filter(|&n| n <= MAX_CLIENT_HELLO)
                    .ok_or(Error::Limit)?,
            );
        }
        Ok(())
    }
    pub fn parse(
        &self,
        config: &rustls::ServerConfig,
        version: u32,
    ) -> Result<Option<Hello>, Error> {
        let Some(needed) = self.needed.filter(|needed| *needed <= self.contiguous) else {
            return Ok(None);
        };
        let observer = Arc::new(Observe(Mutex::new(None)));
        let mut config = config.clone();
        config.cert_resolver = observer.clone();
        let version = match version {
            1 | 0xff000021..=0xff000022 => rustls::quic::Version::V1,
            0xff00001d..=0xff000020 => rustls::quic::Version::V1Draft,
            _ => return Err(Error::Invalid),
        };
        // Use the normal Rustls QUIC ClientHello parser and TLS1.3 negotiation.
        // The local observer always declines the certificate, before selecting
        // a key exchange group or producing any handshake bytes.
        let mut parser = rustls::quic::ServerConnection::new(Arc::new(config), version, Vec::new())
            .map_err(|_| Error::Invalid)?;
        let _ = parser.read_hs(&self.bytes[..needed]);
        let hello = observer
            .0
            .lock()
            .map_err(|_| Error::Invalid)?
            .take()
            .ok_or(Error::Invalid)?;
        Ok(Some(hello))
    }
}

#[derive(Debug)]
struct Observe(Mutex<Option<Hello>>);

impl rustls::server::ResolvesServerCert for Observe {
    fn resolve(
        &self,
        hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        if hello.negotiated_version() == Some(rustls::ProtocolVersion::TLSv1_3)
            && !hello.signature_schemes().is_empty()
        {
            *self.0.lock().ok()? = Some(Hello {
                event:super::super::tls_events::HelloFields::capture(&hello),
                server_name: hello.offered_server_name().map(str::to_owned),
                protocols: hello
                    .alpn()
                    .map(|p| p.map(<[u8]>::to_vec).collect())
                    .unwrap_or_default(),
                signatures: hello.signature_schemes().to_vec(),
            });
        }
        None
    }
}
