//! Native stateless ticket framing. Go-compatible shared files supply seeds;
//! the opaque Go TLS session format is never interpreted as Rustls data.
use super::{Owner, go_gob::Persisted};
use crate::leaf_guard::LeafState;
use aws_lc_rs::{aead, hkdf, rand};
use rustls::{ProtocolVersion, server::ProducesTickets};
use std::{
    fmt,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicU8, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"CRSTEK01";
const KEY_ID: usize = 16;
const NONCE: usize = 12;
const HEADER: usize = MAGIC.len() + 8 + KEY_ID + NONCE;
const TAG: usize = aead::MAX_TAG_LEN;
const MAX_PLAINTEXT: usize = 4096;
// Go's server also attempts only the first five offered TLS1.3 PSKs.
const MAX_ATTEMPTS: u8 = 5;
const MAX_SNI: usize = 253;
const MAX_AGE: u32 = 7 * 24 * 60 * 60;
const MAX_FUTURE_SKEW: u64 = 60;
const CONTEXT: &[u8] = b"caddy-rust/stek/resume/business/v1";
const MAX_AAD: usize = CONTEXT.len() + 2 + MAX_SNI + 2 + 32 + 32 + HEADER;

struct Key {
    id: [u8; KEY_ID],
    aead: aead::LessSafeKey,
    ssl_secret:Zeroizing<[u8;32]>,
}

pub(super) struct KeySet(Vec<Key>);

struct KeyIdLength;
impl hkdf::KeyType for KeyIdLength {
    fn len(&self) -> usize {
        KEY_ID
    }
}

impl KeySet {
    pub(super) fn derive(ring: &Persisted) -> Option<Self> {
        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, b"caddy-rust/stek/ticket-key/v1");
        let mut keys = Vec::<Key>::with_capacity(ring.keys.len());
        for seed in ring.keys.iter() {
            let prk = salt.extract(seed);
            let mut id = [0; KEY_ID];
            prk.expand(&[b"public-key-id"], KeyIdLength)
                .ok()?
                .fill(&mut id)
                .ok()?;
            if keys.iter().any(|known| known.id == id) {
                continue;
            }
            let mut material = Zeroizing::new([0; 32]);
            prk.expand(&[b"aes-256-gcm-siv"], hkdf::HKDF_SHA256)
                .ok()?
                .fill(material.as_mut())
                .ok()?;
            let unbound = aead::UnboundKey::new(&aead::AES_256_GCM_SIV, material.as_ref()).ok()?;
            let mut ssl_secret=Zeroizing::new([0u8;32]);
            prk.expand(&[b"openssl-rfc5077-host-binding-v1"],hkdf::HKDF_SHA256).ok()?.fill(ssl_secret.as_mut()).ok()?;
            keys.push(Key {
                ssl_secret,
                id,
                aead: aead::LessSafeKey::new(unbound),
            });
        }
        (!keys.is_empty()).then_some(Self(keys))
    }
}

struct Selection {
    sni: Box<str>,
    version: ProtocolVersion,
    chain: [u8; 32],
    leaf: Arc<LeafState>,
    not_after: i64,
}
impl Selection {
    fn current(&self, now: u64) -> bool {
        i64::try_from(now).is_ok_and(|now| now < self.not_after)
            && self.leaf.admission().allow_certificate
    }
    fn aad(&self, realm: &[u8; 32], header: &[u8; HEADER], buffer: &mut [u8; MAX_AAD]) -> usize {
        let mut offset = 0;
        for part in [
            CONTEXT,
            &(self.sni.len() as u16).to_be_bytes(),
            self.sni.as_bytes(),
            &u16::from(self.version).to_be_bytes(),
            realm,
            &self.chain,
            header,
        ] {
            let end = offset + part.len();
            buffer[offset..end].copy_from_slice(part);
            offset = end;
        }
        offset
    }
}

/// A per-handshake bridge. Construct only for ordinary no-client-auth TLS;
/// ACME proof and authenticated clients have no ticket bridge at all.
pub struct ConnectionTickets {
    owner: Arc<Owner>,
    realm: [u8; 32],
    enabled: bool,
    selection: OnceLock<Selection>,
    attempts: AtomicU8,
    authenticated_issued: OnceLock<u64>,
}
impl fmt::Debug for ConnectionTickets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectionTickets").finish_non_exhaustive()
    }
}
impl ConnectionTickets {
    pub fn new(owner: Arc<Owner>, realm: [u8; 32]) -> Self {
        let enabled = owner.available();
        Self {
            owner,
            realm,
            enabled,
            selection: OnceLock::new(),
            attempts: AtomicU8::new(0),
            authenticated_issued: OnceLock::new(),
        }
    }

    /// Supply the verified current selection from the actual negotiated
    /// resolver callback, never the unnegotiated ClientHello hint. Subsequent
    /// callbacks (e.g. HelloRetryRequest) must present that exact selection.
    pub fn select(
        &self,
        normalized_sni: &str,
        version: ProtocolVersion,
        chain: [u8; 32],
        leaf: Arc<LeafState>,
        not_after: i64,
    ) -> bool {
        if normalized_sni.is_empty()
            || normalized_sni.len() > MAX_SNI
            || !normalized_sni.is_ascii()
            || !matches!(version, ProtocolVersion::TLSv1_2 | ProtocolVersion::TLSv1_3)
        {
            return false;
        }
        let selected = self.selection.get_or_init(|| Selection {
            sni: normalized_sni.into(),
            version,
            chain,
            leaf: leaf.clone(),
            not_after,
        });
        selected.sni.as_ref() == normalized_sni
            && selected.version == version
            && selected.chain == chain
            && Arc::ptr_eq(&selected.leaf, &leaf)
            && selected.not_after == not_after
            && now().is_some_and(|now| selected.current(now))
    }

    /// Require this mark only if Rustls reports an actually resumed
    /// stateless handshake. The TLS binder and ciphersuite checks remain
    /// Rustls's responsibility; a mere successful decrypt cannot admit TLS.
    pub fn authenticated(&self) -> bool {
        self.authenticated_issued.get().is_some()
            && self
                .selection
                .get()
                .is_some_and(|selection| now().is_some_and(|now| selection.current(now)))
    }
}

impl ProducesTickets for ConnectionTickets {
    fn enabled(&self) -> bool {
        self.enabled
    }

    fn lifetime(&self) -> u32 {
        MAX_AGE
    }

    fn encrypt(&self, plain: &[u8]) -> Option<Vec<u8>> {
        if !self.enabled || plain.is_empty() || plain.len() > MAX_PLAINTEXT {
            return None;
        }
        let selection = self.selection.get()?;
        let at = now()?;
        if !selection.current(at) {
            return None;
        }
        // A TLS1.2 resumed connection rewraps the same master secret. Keep
        // its original age across renewal as Go does. If Rustls authenticated
        // the old envelope but did a full fallback (e.g. incompatible suite),
        // conservatively retain the older age without changing that handshake.
        let issued = if selection.version == ProtocolVersion::TLSv1_2 {
            self.authenticated_issued.get().copied().unwrap_or(at)
        } else {
            at
        };
        if !age_ok(at, issued) {
            return None;
        }
        self.owner.with_ticket_keys(|keys| {
            let key = keys.0.first()?;
            let mut nonce = [0; NONCE];
            rand::fill(&mut nonce).ok()?;
            let mut header = [0; HEADER];
            header[..8].copy_from_slice(MAGIC);
            header[8..16].copy_from_slice(&issued.to_be_bytes());
            header[16..32].copy_from_slice(&key.id);
            header[32..].copy_from_slice(&nonce);
            let mut aad = [0; MAX_AAD];
            let n = selection.aad(&self.realm, &header, &mut aad);
            let mut out = Zeroizing::new(Vec::with_capacity(HEADER + plain.len() + TAG));
            out.extend_from_slice(&header);
            out.extend_from_slice(plain);
            let tag = key
                .aead
                .seal_in_place_separate_tag(
                    aead::Nonce::assume_unique_for_key(nonce),
                    aead::Aad::from(&aad[..n]),
                    &mut out[HEADER..],
                )
                .ok()?;
            out.extend_from_slice(tag.as_ref());
            selection.current(now()?).then(|| std::mem::take(&mut *out))
        })
    }

    fn decrypt(&self, ticket: &[u8]) -> Option<Vec<u8>> {
        if !self.enabled
            || self
                .attempts
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |prior| {
                    (prior < MAX_ATTEMPTS).then(|| prior + 1)
                })
                .is_err()
            || !(HEADER + TAG + 1..=HEADER + TAG + MAX_PLAINTEXT).contains(&ticket.len())
        {
            return None;
        }
        let selection = self.selection.get()?;
        let at = now()?;
        if !selection.current(at) {
            return None;
        }
        let header: &[u8; HEADER] = ticket[..HEADER].try_into().ok()?;
        if &header[..8] != MAGIC {
            return None;
        }
        let issued = u64::from_be_bytes(header[8..16].try_into().ok()?);
        if !age_ok(at, issued) {
            return None;
        }
        let id = &header[16..32];
        let nonce = aead::Nonce::assume_unique_for_key(header[32..].try_into().ok()?);
        self.owner.with_ticket_keys(|keys| {
            // Key IDs are public framing; only one AEAD attempt is needed.
            let key = keys.0.iter().find(|key| key.id.as_slice() == id)?;
            let mut aad = [0; MAX_AAD];
            let n = selection.aad(&self.realm, header, &mut aad);
            let mut body = Zeroizing::new(ticket[HEADER..].to_vec());
            let body_len = key
                .aead
                .open_in_place(nonce, aead::Aad::from(&aad[..n]), &mut body)
                .ok()?
                .len();
            let at = now()?;
            if !selection.current(at) || !age_ok(at, issued) {
                return None;
            }
            body.truncate(body_len);
            let _ = self.authenticated_issued.set(issued);
            Some(std::mem::take(&mut *body))
        })
    }
}

fn now() -> Option<u64> {
    Some(SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs())
}

fn age_ok(now: u64, issued: u64) -> bool {
    issued <= now.saturating_add(MAX_FUTURE_SKEW)
        && issued
            .checked_add(u64::from(MAX_AGE))
            .is_some_and(|until| now < until)
}

// Public SSL callbacks only receive separately derived ticket keys. Raw shared
// seed material never leaves this module, and record encryption stays in SSL.
impl native_ssl_tls::ServerTicketProvider for ConnectionTickets {
 fn key(&self,requested:Option<&[u8;16]>)->Option<(native_ssl_tls::TicketKey,bool)>{
  if !self.enabled{return None}
  let selection=self.selection.get()?;
  if !selection.current(now()?){return None}
  self.owner.with_ticket_keys(|keys|{
   let (index,key)=if let Some(id)=requested{keys.0.iter().enumerate().find(|(_,k)|&k.id==id)?}else{(0,keys.0.first()?)};
   let salt=hkdf::Salt::new(hkdf::HKDF_SHA256,b"caddy-rust/openssl-ticket-key/v1");let prk=salt.extract(key.ssl_secret.as_ref());
   let mut binding=[0u8;MAX_AAD];let n=selection.aad(&self.realm,&[0u8;HEADER],&mut binding);
   let mut enc=Zeroizing::new([0u8;32]);let mut mac=Zeroizing::new([0u8;32]);
   prk.expand(&[b"aes-256-cbc",&binding[..n]],hkdf::HKDF_SHA256).ok()?.fill(enc.as_mut()).ok()?;
   prk.expand(&[b"hmac-sha256",&binding[..n]],hkdf::HKDF_SHA256).ok()?.fill(mac.as_mut()).ok()?;
   selection.current(now()?).then(||(native_ssl_tls::TicketKey::new(key.id,enc,mac),index==0))
  })
 }
 fn seal(&self,plain:&[u8])->Option<Vec<u8>>{if plain.len()!=8{return None}ProducesTickets::encrypt(self,plain)}
 fn open(&self,sealed:&[u8])->Option<Vec<u8>>{if sealed.len()>256{return None}let value=ProducesTickets::decrypt(self,sealed)?;(value.len()==8).then_some(value)}
}
