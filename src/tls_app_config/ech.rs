//! Native ECH configuration material and its CertMagic-compatible storage.
//! Private keys have no Debug/JSON view. The TLS bridge consumes owned snapshots.
#[path="ech/config.rs"]mod config;
#[path="ech/material.rs"]mod material;
#[path="ech/store.rs"]mod store;
pub(crate)use config::Settings;
pub(crate)use material::Key;
pub(crate)use store::prepare;
use std::sync::Arc;
pub(crate)struct Snapshot{pub(crate)keys:Arc<[Arc<Key>]>,tls_keys:Arc<[Arc<rustls::server::EchServerKey>]>,pub(crate)names:Arc<[String]>,_memory:Arc<crate::acme_wire::chain_memory::Lease>}
impl Snapshot{
    fn new(keys:Vec<Arc<Key>>)->anyhow::Result<Self>{
        // This memory outlives preparation and may retire under a QUIC state
        // lock. Reuse the existing persistent atomic payload budget, whose
        // release cannot invoke a semaphore waiter's callback.
        let memory=Arc::new(crate::acme_wire::chain_memory::shared().payload.reserve(keys.len().saturating_mul(16384).saturating_add(4096))?);
        let mut names=std::collections::BTreeSet::new();for key in &keys{names.insert(key.public_name.to_string());}
        let tls_keys=keys.iter().map(|key|rustls::server::EchServerKey::new(&key.config,key.private_bytes(),key.send_as_retry())?.with_retention(memory.clone())).collect::<Result<Vec<_>,_>>()?;
        Ok(Self{keys:keys.into(),tls_keys:tls_keys.into(),names:names.into_iter().collect::<Vec<_>>().into(),_memory:memory})
    }
}
pub(crate)struct Runtime{snapshot:arc_swap::ArcSwap<Snapshot>}
impl std::fmt::Debug for Runtime{fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{f.write_str("EchRuntime { .. }")}}
impl rustls::server::EchConfigProvider for Runtime{
    fn keys(&self)->Arc<[Arc<rustls::server::EchServerKey>]>{self.snapshot.load().tls_keys.clone()}
}
impl Runtime{
    pub(crate)fn new(snapshot:Arc<Snapshot>)->Arc<Self>{Arc::new(Self{snapshot:arc_swap::ArcSwap::new(snapshot)})}
    pub(crate)fn current(&self)->Arc<Snapshot>{self.snapshot.load_full()}
    pub(crate)fn publish(&self,snapshot:Arc<Snapshot>){self.snapshot.store(snapshot)}
}
