// ECH server behavior follows Go 1.27.3 crypto/tls/ech.go.
// Copyright 2024 The Go Authors. All rights reserved.
// The Go BSD-3-Clause license is reproduced in the project THIRD-PARTY-NOTICES.
//! RFC 9849 server-side ECH. The application owns configuration rotation; each
//! handshake retains one immutable key snapshot, including through an HRR.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;

use crate::crypto::hpke::{EncapsulatedSecret, Hpke, HpkeOpener, HpkePrivateKey, HpkePublicKey};
use crate::msgs::codec::Codec;
use crate::msgs::handshake::{
    EchConfigPayload, EncryptedClientHello, HandshakePayload, HpkeSymmetricCipherSuite,
    ServerEncryptedClientHello,
};
use crate::msgs::message::{Message, MessagePayload};
use crate::sync::Arc;
use crate::{ContentType, Error};

const ECH: u16 = 0xfe0d;
const OUTER_EXTENSIONS: u16 = 0xfd00;

/// An ECH configuration and its HPKE private key. Debug never exposes key bytes.
pub struct EchServerKey {
    config: EchConfigPayload,
    raw_config: Vec<u8>,
    private_key: HpkePrivateKey,
    send_as_retry: bool,
    // Last: private key/config data is destroyed before its prepaid owner.
    retention: Option<Arc<dyn core::any::Any + Send + Sync>>,
}

impl fmt::Debug for EchServerKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EchServerKey")
            .field("send_as_retry", &self.send_as_retry)
            .finish_non_exhaustive()
    }
}

impl EchServerKey {
    /// Attach an application-owned lifetime credit before sharing this key.
    ///
    /// The owner must not refer back to this key, its key slice, or their
    /// provider. It is retained until the actual last key is destroyed. Shared
    /// keys and replacement of an existing owner are rejected.
    pub fn with_retention(
        mut self: Arc<Self>,
        owner: Arc<dyn core::any::Any + Send + Sync>,
    ) -> Result<Arc<Self>, Error> {
        let key = Arc::get_mut(&mut self)
            .ok_or_else(|| invalid("ECH retention requires a unique key"))?;
        if key.retention.is_some() {
            return Err(invalid("ECH retention owner already installed"));
        }
        key.retention = Some(owner);
        Ok(self)
    }

    /// Validate a single RFC 9849 ECHConfig and its matching raw HPKE private key.
    /// This uses the existing AWS-LC HPKE provider; unsupported suites are rejected.
    pub fn new(
        config_bytes: &[u8],
        private_key_bytes: &[u8],
        send_as_retry: bool,
    ) -> Result<Arc<Self>, Error> {
        let config = EchConfigPayload::read_bytes(config_bytes)?;
        let EchConfigPayload::V18(contents) = &config else {
            return Err(invalid("unsupported ECH version"));
        };
        if config.get_encoding() != config_bytes
            || contents.has_duplicate_extension()
            || contents.has_unknown_mandatory_extension()
        {
            return Err(invalid("invalid ECH configuration"));
        }
        let suite = supported_suites()
            .iter()
            .copied()
            .find(|suite| {
                suite.suite().kem == contents.key_config.kem_id
                    && contents
                        .key_config
                        .symmetric_cipher_suites
                        .contains(&suite.suite().sym)
            })
            .ok_or_else(|| invalid("unsupported ECH HPKE configuration"))?;
        let private_key = HpkePrivateKey::from(private_key_bytes.to_vec());
        let public = HpkePublicKey(contents.key_config.public_key.0.clone());
        // The HPKE abstraction intentionally does not export private-to-public
        // derivation. Its authenticated round trip checks the configured pair.
        let (enc, ciphertext) = suite.seal(b"rustls ECH key validation", b"", b"ECH", &public)?;
        if suite.open(
            &enc,
            b"rustls ECH key validation",
            b"",
            &ciphertext,
            &private_key,
        )? != b"ECH"
        {
            return Err(invalid("ECH private key does not match configuration"));
        }
        Ok(Arc::new(Self {
            config,
            raw_config: config_bytes.to_vec(),
            private_key,
            send_as_retry,
            retention: None,
        }))
    }
}

/// Supplies the immutable ECH keys used by a new server handshake.
pub trait EchConfigProvider: fmt::Debug + Send + Sync {
    /// Return a connection-retained snapshot; order determines HPKE trial order.
    fn keys(&self) -> Arc<[Arc<EchServerKey>]>;
}

#[cfg(feature = "aws_lc_rs")]
fn supported_suites() -> &'static [&'static dyn Hpke] {
    crate::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES
}
#[cfg(not(feature = "aws_lc_rs"))]
fn supported_suites() -> &'static [&'static dyn Hpke] {
    &[]
}

#[derive(Debug)]
pub(super) struct ServerEch {
    keys: Arc<[Arc<EchServerKey>]>,
    opener: Option<Box<dyn HpkeOpener>>,
    suite: Option<HpkeSymmetricCipherSuite>,
    config_id: u8,
    pub(super) inner_random: Option<[u8; 32]>,
    direct_inner: bool,
    offered_outer: bool,
}

impl ServerEch {
    pub(super) fn retry_configs(&self) -> Option<ServerEncryptedClientHello> {
        if !self.offered_outer || self.inner_random.is_some() {
            return None;
        }
        let retry_configs: Vec<_> = self
            .keys
            .iter()
            .filter(|key| key.send_as_retry)
            .map(|key| key.config.clone())
            .collect();
        (!retry_configs.is_empty()).then_some(ServerEncryptedClientHello { retry_configs })
    }

    pub(super) fn first(
        message: Message<'_>,
        keys: Arc<[Arc<EchServerKey>]>,
    ) -> Result<(Message<'static>, Self), Error> {
        let mut state = Self {
            keys,
            opener: None,
            suite: None,
            config_id: 0,
            inner_random: None,
            direct_inner: false,
            offered_outer: false,
        };
        let extension = hello(&message)?.encrypted_client_hello.clone();
        let Some(extension) = extension else {
            return Ok((owned(message), state));
        };
        let EncryptedClientHello::Outer(outer) = extension else {
            // A forwarded inner marker is not proof that this server decrypted ECH.
            state.direct_inner = true;
            return Ok((owned(message), state));
        };
        state.offered_outer = true;
        let aad = outer_aad(&message)?;
        for key in state.keys.iter() {
            let EchConfigPayload::V18(contents) = &key.config else {
                continue;
            };
            // IDs select an installed configuration before doing HPKE. They
            // are not authentication credentials; AEAD still verifies the AAD.
            if outer.config_id != contents.key_config.config_id
                || !contents
                    .key_config
                    .symmetric_cipher_suites
                    .contains(&outer.cipher_suite)
            {
                continue;
            }
            let Some(hpke) = supported_suites().iter().copied().find(|suite| {
                suite.suite().kem == contents.key_config.kem_id
                    && suite.suite().sym == outer.cipher_suite
            }) else {
                continue;
            };
            let mut info = b"tls ech\0".to_vec();
            info.extend_from_slice(&key.raw_config);
            let Ok(mut opener) = hpke.setup_opener(
                &EncapsulatedSecret(outer.enc.0.clone()),
                &info,
                &key.private_key,
            ) else {
                continue;
            };
            let Ok(plaintext) = opener.open(&aad, &outer.payload.0) else {
                continue;
            };
            let inner = reconstruct(&message, &plaintext)?;
            state.inner_random = Some(hello(&inner)?.random.0);
            state.opener = Some(opener);
            state.suite = Some(outer.cipher_suite);
            state.config_id = outer.config_id;
            return Ok((inner, state));
        }
        Ok((owned(message), state))
    }

    pub(super) fn second(&mut self, message: Message<'_>) -> Result<Message<'static>, Error> {
        let extension = hello(&message)?.encrypted_client_hello.as_ref();
        let Some(opener) = &mut self.opener else {
            if self.direct_inner && !matches!(extension, Some(EncryptedClientHello::Inner)) {
                return Err(invalid("ECH type changed after HelloRetryRequest"));
            }
            if !self.direct_inner && matches!(extension, Some(EncryptedClientHello::Inner)) {
                return Err(invalid("ECH type changed after HelloRetryRequest"));
            }
            return Ok(owned(message));
        };
        let Some(EncryptedClientHello::Outer(outer)) = extension else {
            return Err(invalid("ECH missing after HelloRetryRequest"));
        };
        if Some(outer.cipher_suite) != self.suite
            || outer.config_id != self.config_id
            || !outer.enc.0.is_empty()
        {
            return Err(invalid("ECH parameters changed after HelloRetryRequest"));
        }
        let plaintext = opener
            .open(&outer_aad(&message)?, &outer.payload.0)
            .map_err(|_| Error::DecryptError)?;
        reconstruct(&message, &plaintext)
    }
}

pub(super) fn owned(message: Message<'_>) -> Message<'static> {
    Message {
        version: message.version,
        payload: message.payload.into_owned(),
    }
}

fn invalid(message: &str) -> Error {
    Error::General(message.into())
}

fn hello<'a>(
    message: &'a Message<'_>,
) -> Result<&'a crate::msgs::handshake::ClientHelloPayload, Error> {
    match &message.payload {
        MessagePayload::Handshake { parsed, .. } => match &parsed.0 {
            HandshakePayload::ClientHello(hello) => Ok(hello),
            _ => Err(invalid("expected ECH ClientHello")),
        },
        _ => Err(invalid("expected ECH ClientHello")),
    }
}

fn raw<'a>(message: &'a Message<'_>) -> Result<&'a [u8], Error> {
    match &message.payload {
        MessagePayload::Handshake { encoded, .. } => Ok(encoded.bytes()),
        _ => Err(invalid("expected ECH ClientHello")),
    }
}

// All slices refer to the original wire encoding: extension order is part of
// both HPKE AAD and the reconstructed inner handshake transcript.
struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}
impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }
    fn take(&mut self, len: usize) -> Result<&'a [u8], Error> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or_else(|| invalid("ECH length overflow"))?;
        let value = self
            .bytes
            .get(self.pos..end)
            .ok_or_else(|| invalid("truncated ECH ClientHello"))?;
        self.pos = end;
        Ok(value)
    }
    fn u8(&mut self) -> Result<usize, Error> {
        Ok(self.take(1)?[0] as usize)
    }
    fn u16(&mut self) -> Result<usize, Error> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]) as usize)
    }
    fn vector8(&mut self) -> Result<&'a [u8], Error> {
        let len = self.u8()?;
        self.take(len)
    }
    fn vector16(&mut self) -> Result<&'a [u8], Error> {
        let len = self.u16()?;
        self.take(len)
    }
}

fn outer_parts(bytes: &[u8]) -> Result<(&[u8], usize, &[u8]), Error> {
    let mut r = Cursor::new(bytes);
    r.take(4 + 2 + 32)?;
    let sid = r.vector8()?;
    r.vector16()?;
    r.vector8()?;
    let extension_offset = r.pos + 2;
    let extensions = r.vector16()?;
    if r.pos != bytes.len() {
        return Err(invalid("trailing outer ClientHello data"));
    }
    Ok((sid, extension_offset, extensions))
}

fn outer_aad(message: &Message<'_>) -> Result<Vec<u8>, Error> {
    let wire = raw(message)?;
    let (_, offset, extensions) = outer_parts(wire)?;
    let mut r = Cursor::new(extensions);
    while r.pos < extensions.len() {
        let kind = r.u16()? as u16;
        let ext = r.vector16()?;
        if kind != ECH {
            continue;
        }
        let ext_start = r.pos - ext.len();
        let mut ech = Cursor::new(ext);
        if ech.u8()? != 0 {
            return Err(invalid("invalid outer ECH type"));
        }
        ech.take(5)?; // KDF, AEAD and config_id
        ech.vector16()?;
        let payload = ech.vector16()?;
        if ech.pos != ext.len() {
            return Err(invalid("trailing ECH extension data"));
        }
        let start = offset + ext_start + ech.pos - payload.len();
        let mut aad = wire[4..].to_vec();
        aad[start - 4..start - 4 + payload.len()].fill(0);
        return Ok(aad);
    }
    Err(invalid("missing outer ECH extension"))
}

fn reconstruct(outer: &Message<'_>, plaintext: &[u8]) -> Result<Message<'static>, Error> {
    let (sid, _, outer_extensions) = outer_parts(raw(outer)?)?;
    let mut r = Cursor::new(plaintext);
    let prefix = r.take(34)?;
    if !r.vector8()?.is_empty() {
        return Err(invalid("encoded inner session id is not empty"));
    }
    let suites_start = r.pos;
    r.vector16()?;
    r.vector8()?;
    let suites_and_compression = &plaintext[suites_start..r.pos];
    let inner_extensions = r.vector16()?;
    if plaintext[r.pos..].iter().any(|byte| *byte != 0) {
        return Err(invalid("nonzero ECH padding"));
    }
    let mut encoded_extensions = Vec::new();
    let mut inner = Cursor::new(inner_extensions);
    let mut source = Cursor::new(outer_extensions);
    let mut compressed = false;
    while inner.pos < inner_extensions.len() {
        let start = inner.pos;
        let kind = inner.u16()? as u16;
        let ext = inner.vector16()?;
        if kind != OUTER_EXTENSIONS {
            encoded_extensions.extend_from_slice(&inner_extensions[start..inner.pos]);
            continue;
        }
        if compressed {
            return Err(invalid("duplicate ech_outer_extensions"));
        }
        compressed = true;
        let mut refs = Cursor::new(ext);
        let names = refs.vector8()?;
        if refs.pos != ext.len() || names.is_empty() || names.len() % 2 != 0 {
            return Err(invalid("invalid ech_outer_extensions"));
        }
        for name in names.chunks_exact(2) {
            let wanted = u16::from_be_bytes([name[0], name[1]]);
            if wanted == ECH || wanted == OUTER_EXTENSIONS {
                return Err(invalid("forbidden compressed ECH extension"));
            }
            loop {
                let start = source.pos;
                let kind = source.u16()? as u16;
                source.vector16()?;
                if wanted == kind {
                    encoded_extensions.extend_from_slice(&outer_extensions[start..source.pos]);
                    break;
                }
            }
        }
    }
    let ext_len = u16::try_from(encoded_extensions.len())
        .map_err(|_| invalid("ECH extension list too long"))?;
    let mut bytes = alloc::vec![1, 0, 0, 0];
    bytes.extend_from_slice(prefix);
    bytes.push(sid.len() as u8);
    bytes.extend_from_slice(sid);
    bytes.extend_from_slice(suites_and_compression);
    bytes.extend_from_slice(&ext_len.to_be_bytes());
    bytes.extend_from_slice(&encoded_extensions);
    let len = bytes.len() - 4;
    bytes[1..4].copy_from_slice(&(len as u32).to_be_bytes()[1..]);
    let payload = MessagePayload::new(ContentType::Handshake, outer.version, &bytes)?.into_owned();
    let message = Message {
        version: outer.version,
        payload,
    };
    let hello = hello(&message)?;
    if !matches!(
        hello.encrypted_client_hello,
        Some(EncryptedClientHello::Inner)
    ) {
        return Err(invalid("decrypted ClientHello lacks inner ECH marker"));
    }
    let versions = hello
        .supported_versions
        .as_ref()
        .ok_or_else(|| invalid("ECH requires TLS 1.3"))?;
    if !versions.tls13
        || versions.native_offered[..usize::from(versions.native_len)]
            .iter()
            .any(|v| {
                let n = u16::from(*v);
                n < 0x0304 && !((n & 0x0f0f) == 0x0a0a && n >> 8 == n & 0xff)
            })
    {
        return Err(invalid("ECH inner offers a version below TLS 1.3"));
    }
    Ok(message)
}
