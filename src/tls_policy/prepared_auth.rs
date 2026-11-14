//! Closed preparation ownership for client-authentication material.
use anyhow::{Result, ensure};
use std::sync::{Arc, Mutex};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use crate::{acme_wire::chain_memory::{self, Lease, Pool}, cert_transient::ResourceDenied};

#[derive(Clone)]
pub(crate) enum AuthBudget {
    /// Borrow the existing CertificateResources external_bytes pool.
    Root(Arc<Semaphore>),
    /// Public synchronous construction has no Root; borrow the existing pool.
    Standalone(Arc<Pool>),
}
impl AuthBudget {
    pub(crate) fn standalone() -> Self { Self::Standalone(chain_memory::shared().payload.clone()) }
    pub(crate) fn reserve_buffer(&self, bytes: usize) -> Result<BufferCredit> {
        Ok(BufferCredit { _loan: self.claim(bytes)? })
    }
    fn claim(&self, bytes: usize) -> Result<Credit> {
        match self {
            Self::Root(pool) => Ok(Credit::Root {
                permit: pool.clone().try_acquire_many_owned(u32::try_from(bytes).map_err(|_| ResourceDenied)?)
                    .map_err(|_| ResourceDenied)?, pool: pool.clone(),
            }),
            Self::Standalone(pool) => Ok(Credit::Standalone(pool.reserve(bytes)?)),
        }
    }
}

/// Per-buffer reservation for prepared source material. This token is
/// moved with its data; it does not alias the constructor's high-water credit.
pub(crate) struct BufferCredit { _loan: Credit }
impl BufferCredit {pub(crate) fn resize(&mut self,bytes:usize)->Result<()>{self._loan.resize(bytes)}}

// permit is deliberately before pool: it returns its credit while the pool
// remains live. Neither variant creates an additional pool.
enum Credit { Root { permit: OwnedSemaphorePermit, pool: Arc<Semaphore> }, Standalone(Lease) }
impl Credit {
    fn resize(&mut self, bytes: usize) -> Result<()> {
        match self {
            Self::Root { permit, pool } => {
                let current = permit.num_permits();
                if bytes > current {
                    let added = pool.clone().try_acquire_many_owned(u32::try_from(bytes-current).map_err(|_| ResourceDenied)?)
                        .map_err(|_| ResourceDenied)?;
                    permit.merge(added);
                } else if bytes < current {
                    drop(permit.split(current-bytes).ok_or(ResourceDenied)?);
                }
                Ok(())
            }
            Self::Standalone(lease) => lease.resize(bytes),
        }
    }
}
struct State { bytes: usize, sealed: bool, credit: Credit }

/// The final Verifier owns this Arc in its LAST field. A waiter, Services or
/// PreparedAuth wrapper is not the owner of the actual retained DER.
pub(crate) struct AuthMaterialCredit { state: Mutex<State> }
impl AuthMaterialCredit {
    pub(crate) fn new(budget: &AuthBudget) -> Result<Arc<Self>> {
        let bytes = std::mem::size_of::<Self>().checked_add(128).ok_or(ResourceDenied)?;
        // Prepay the Mutex/Arc control block before constructing either.
        let credit = budget.claim(bytes)?;
        Ok(Arc::new(Self { state: Mutex::new(State { bytes, sealed: false, credit }) }))
    }
    /// Additive construction prepayment, BEFORE each closed producer allocates.
    /// Temporary old/new buffers must coexist under this or their source loan.
    pub(crate) fn reserve(&self, added: usize) -> Result<()> {
        let mut state = self.state.lock().map_err(|_| ResourceDenied)?;
        ensure!(!state.sealed, "client authentication material is sealed");
        let bytes = state.bytes.checked_add(added).ok_or(ResourceDenied)?;
        state.credit.resize(bytes)?;
        state.bytes = bytes;
        Ok(())
    }
    fn is_sealed(&self) -> Result<bool> {
        Ok(self.state.lock().map_err(|_| ResourceDenied)?.sealed)
    }
    /// Only the consuming constructor may call this, AFTER its owned temporary
    /// inputs are destroyed. The retained estimate includes this owner/control
    /// block, every mode's root_ders, actual Vec/Arc capacity and all payloads.
    fn seal_after_inputs_drop(&self, retained: usize) -> Result<()> {
        let mut state = self.state.lock().map_err(|_| ResourceDenied)?;
        let minimum = std::mem::size_of::<Self>().checked_add(128).ok_or(ResourceDenied)?;
        ensure!(!state.sealed && retained <= state.bytes && retained >= minimum,
            "invalid client authentication material prepayment");
        state.credit.resize(retained)?;
        state.bytes = retained;
        state.sealed = true;
        Ok(())
    }
}
impl crate::cert_cpu::MaterialOwner for AuthMaterialCredit {
    fn reserve(&self, bytes: usize) -> Result<()> { Self::reserve(self, bytes) }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct AuthKey {
    pub(crate) server_ordinal: usize,
    pub(crate) policy_ordinal: usize,
    pub(crate) raw_policy: [u8; 32],
}

#[path="prepared_auth/snapshots.rs"]
mod snapshots;
pub(crate) use snapshots::{AuthEntry, AuthInputs, RetainedAuth, PreparedSlot};

pub(crate) fn json_binding(value:&impl serde::Serialize)->Result<[u8;32]>{
    use sha2::{Digest,Sha256};use std::io::Write;
    struct Sink(Sha256);impl Write for Sink{fn write(&mut self,b:&[u8])->std::io::Result<usize>{self.0.update(b);Ok(b.len())}fn flush(&mut self)->std::io::Result<()>{Ok(())}}
    let mut s=Sink(Sha256::new());serde_json::to_writer(&mut s,value)?;Ok(s.0.finalize().into())
}
/// No-allocation digest of the typed original inputs. JSON values are length
/// framed with a counting pass before hashing; concatenated scalars cannot alias.
pub(crate) fn input_binding(raw:&super::ClientAuth)->Result<[u8;32]>{
    use sha2::{Digest,Sha256};use std::io::Write;
    super::client_auth::raw_clone_cost(raw)?; // existing depth/overflow preflight
    struct Sink(Sha256);
    impl Write for Sink{fn write(&mut self,b:&[u8])->std::io::Result<usize>{self.0.update(b);Ok(b.len())}fn flush(&mut self)->std::io::Result<()>{Ok(())}}
    struct Count(usize);
    impl Write for Count{fn write(&mut self,b:&[u8])->std::io::Result<usize>{self.0=self.0.checked_add(b.len()).filter(|n|*n<=64<<20).ok_or_else(||std::io::Error::other("client authentication binding exceeds limit"))?;Ok(b.len())}fn flush(&mut self)->std::io::Result<()>{Ok(())}}
    fn json(s:&mut Sink,v:&serde_json::Value)->Result<()>{let mut n=Count(0);serde_json::to_writer(&mut n,v)?;s.write_all(&(n.0 as u64).to_be_bytes())?;serde_json::to_writer(s,v)?;Ok(())}
    let mut s=Sink(Sha256::new());s.write_all(b"caddy-client-auth-raw-v1")?;
    s.write_all(&[raw.mode.map_or(0,|v|v as u8+1),raw.ca.is_some()as u8])?;
    if let Some(v)=&raw.ca{json(&mut s,v)?;}
    for values in [&raw.trusted_ca_certs,&raw.trusted_ca_certs_pem_files,&raw.trusted_leaf_certs]{s.write_all(&(values.len()as u64).to_be_bytes())?;for v in values{s.write_all(&(v.len()as u64).to_be_bytes())?;s.write_all(v.as_bytes())?;}}
    s.write_all(&(raw.verifiers.len()as u64).to_be_bytes())?;for v in &raw.verifiers{json(&mut s,v)?;}
    Ok(s.0.finalize().into())
}

/// A single normal-preparation CA Value and its actual receiving allowance.
/// Arc clones share the same allocation; this never deep-clones under a loan.
pub(crate) struct PreparedCa {pub(crate) value:serde_json::Value,pub(crate) memory:SourceMemory}
pub(crate) struct SourceMemory {charged:usize,credit:BufferCredit}
impl SourceMemory {
    pub(crate) fn reserve_value(&mut self,value:&serde_json::Value)->Result<()>{
        let bytes=crate::cert_json_shape::clone_cost(value)?.checked_mul(2).and_then(|n|n.checked_add(256)).ok_or(ResourceDenied)?;
        let next=self.charged.checked_add(bytes).ok_or(ResourceDenied)?;
        self.credit.resize(next)?;self.charged=next;Ok(())
    }
}
impl PreparedCa {
    pub(crate) fn copy(value:&serde_json::Value,budget:&AuthBudget)->Result<Arc<Self>>{
        let charged=crate::cert_json_shape::clone_cost(value)?.checked_add(std::mem::size_of::<Self>()+512).ok_or(ResourceDenied)?;
        let credit=budget.reserve_buffer(charged)?;
        Ok(Arc::new(Self{value:value.clone(),memory:SourceMemory{charged,credit}}))
    }
}
pub(crate) struct ResolvedFrontCa {key:AuthKey,binding:[u8;32],source:Arc<PreparedCa>}
impl ResolvedFrontCa {
    pub(crate) fn new(key:AuthKey,binding:[u8;32],source:Arc<PreparedCa>)->Self{Self{key,binding,source}}
    fn check(&self,key:AuthKey,binding:[u8;32])->Result<()>{ensure!(self.key==key&&self.binding==binding,"client authentication CA input differs");Ok(())}
    pub(crate) fn value(&self)->&serde_json::Value{&self.source.value}
}

pub(crate) struct AuthSources {pub(crate) ca:Option<ResolvedFrontCa>,pub(crate) leaf:super::leaf_sources::LeafData}

/// The real CPU worker consumes this whole envelope. Source data retires
/// before its last credit even after true caller abort or an unconsumed result.
pub(crate) struct AuthBuildInput {
    pub(super) raw: Option<super::ClientAuth>,
    pub(super) sources: Option<AuthSources>,
    pub(super) credit: Arc<AuthMaterialCredit>,
}
impl AuthBuildInput {
    pub(crate) fn from_sources(key:AuthKey,raw:&super::ClientAuth,sources:AuthSources,budget:&AuthBudget)->Result<Self>{
        if let Some(ca)=&sources.ca{ca.check(key,input_binding(raw)?)?;}
        let working=super::client_auth::paid_working_bound(raw)?;
        let credit=AuthMaterialCredit::new(budget)?;credit.reserve(working)?;
        Ok(Self{raw:Some(raw.clone()),sources:Some(sources),credit})
    }
    pub(crate) fn execute(mut self) -> Result<super::client_auth::PreparedAuth> {
        // Keep self WHOLE while any called producer can panic. Destructuring
        // its credit into a last local would drop that local before raw input
        // bindings during unwinding, violating the data-before-credit order.
        let result = super::client_auth::prepare_paid(
            self.raw.as_ref().expect("owned authentication input"),
            self.sources.as_ref().and_then(|v|v.ca.as_ref()).map(ResolvedFrontCa::value),
            self.sources.as_ref().map(|v|v.leaf.groups()),self.credit.clone());
        // Source buffers/DOM and their loans retire before construction credit
        // is trimmed. self still holds the last credit across these drops.
        drop(self.sources.take());
        if let Some(mut raw)=self.raw.take(){super::client_auth::wipe_raw(&mut raw);drop(raw);}
        match result {
            Ok(prepared) => {
                self.credit.seal_after_inputs_drop(prepared.credit_bytes)?;
                Ok(prepared)
            }
            Err(error) => Err(crate::cert_cpu::retained_error(error, self.credit.clone())),
        }
    }
}

impl Drop for AuthBuildInput{fn drop(&mut self){if let Some(raw)=&mut self.raw{super::client_auth::wipe_raw(raw);}}}
