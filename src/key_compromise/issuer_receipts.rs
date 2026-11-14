//! Authenticated API confirmations are local private-state facts, not OCSP
//! signatures. No public/config/import decoder can introduce a live receipt.
use super::*;
use anyhow::bail;
use crate::cert_automation::{IssuerBackendId,IssuerReceipt};
use crate::acme_wire::chain_memory::{self,Lease};
#[derive(Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version:u8,source:String,backend:IssuerBackendId,certificate_id:String,
    leaf:String,leaf_sha256:String,spki_sha256:String,reason:u8,confirmed_at:i64,not_after:i64,
    // False means authenticated exact-leaf revocation, with the requested
    // reason retained solely as a conservative local veto policy.
    requested_reason_confirmed:bool,
}
pub(crate) struct Fact {
    record:Record,spki:Arc<[u8]>,leaf:[u8;32],_memory:Lease,
}
fn hash(bytes:&[u8])->String{format!("{:x}",Sha256::digest(bytes))}
fn hex(hash:&str)->bool{hash.len()==64&&hash.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))}
impl Fact {
    /// Only the closed revoke producer wraps this result in IssuerReceipt.
    pub(crate) fn from_authenticated(backend:&IssuerBackendId,certificate_id:String,leaf:&[u8],reason:u8,confirmed_at:i64,requested_reason_confirmed:bool)->Result<Arc<Self>>{
        ensure!(leaf.len()<=1024*1024,"issuer receipt leaf exceeds limit");
        let text=match backend{IssuerBackendId::Acme{directory,config_identity}=>directory.len()+config_identity.len(),IssuerBackendId::ZeroSsl{config_identity}=>config_identity.len(),IssuerBackendId::Internal{ca,options_identity}=>ca.len()+options_identity.len()};
        let bytes=leaf.len().checked_mul(4).and_then(|n|n.checked_add(certificate_id.len()*2+text*2+2048)).ok_or(crate::cert_transient::ResourceDenied)?;
        let memory=chain_memory::shared().payload.reserve(bytes)?;
        let(tail,certificate)=crate::cert_transient::parse_certificate(leaf)?;ensure!(tail.is_empty(),"trailing issuer receipt leaf");
        let record=Record{version:2,source:"issuer_api_confirmation".to_owned(),backend:backend.clone(),certificate_id,
            leaf:STANDARD.encode(leaf),leaf_sha256:hash(leaf),spki_sha256:hash(certificate.public_key().raw),reason,confirmed_at,requested_reason_confirmed,
            not_after:certificate.validity().not_after.timestamp()};
        drop(certificate);Self::validate(record,memory)
    }
    fn validate(record:Record,memory:Lease)->Result<Arc<Self>>{
        ensure!(record.version==2&&record.source=="issuer_api_confirmation","unsupported issuer receipt source/version");
        ensure!([0,1,3,4,5].contains(&record.reason)&&hex(&record.leaf_sha256)&&hex(&record.spki_sha256),"invalid issuer receipt identity");
        ensure!(!record.certificate_id.is_empty()&&record.certificate_id.len()<=4096&&!record.certificate_id.bytes().any(|b|b<32||b==127),"invalid issuer receipt certificate ID");
        match &record.backend {
            IssuerBackendId::Acme{directory,config_identity}=>ensure!(directory.len()<=4096&&url::Url::parse(directory).is_ok()&&hex(config_identity),"invalid issuer receipt ACME binding"),
            IssuerBackendId::ZeroSsl{config_identity}=>ensure!(hex(config_identity),"invalid issuer receipt ZeroSSL binding"),
            IssuerBackendId::Internal{..}=>bail!("internal issuer cannot confirm remote revocation"),
        }
        let now=i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
        ensure!(record.confirmed_at>0&&record.confirmed_at<=now.saturating_add(300),"invalid issuer receipt confirmation time");
        let leaf=STANDARD.decode(&record.leaf)?;ensure!(leaf.len()<=1024*1024&&hash(&leaf)==record.leaf_sha256,"issuer receipt leaf fingerprint changed");
        let(tail,certificate)=crate::cert_transient::parse_certificate(&leaf)?;
        ensure!(tail.is_empty()&&hash(certificate.public_key().raw)==record.spki_sha256
            &&certificate.validity().not_after.timestamp()==record.not_after,"issuer receipt leaf/SPKI binding changed");
        let spki=Arc::from(certificate.public_key().raw);let leaf=crate::leaf_guard::leaf_id(&leaf);
        Ok(Arc::new(Self{record,spki,leaf,_memory:memory}))
    }
    fn decode(raw:&[u8],path:&str)->Result<Arc<Self>>{
        ensure!(raw.len()<=MAX_RECORD,"issuer receipt exceeds history record limit");
        let memory=chain_memory::shared().payload.reserve(raw.len().checked_mul(4).and_then(|n|n.checked_add(2048)).ok_or(crate::cert_transient::ResourceDenied)?)?;
        let record:Record=serde_json::from_slice(raw).map_err(|_|anyhow!("invalid private issuer receipt"))?;
        let fact=Self::validate(record,memory)?;ensure!(fact.path()==path,"issuer receipt path binding changed");Ok(fact)
    }
    fn path(&self)->String{format!("issuer-receipts/{}.json",self.record.leaf_sha256)}
    fn bytes(&self)->usize{self._memory.bytes()}
    fn observation(&self)->crate::leaf_guard::Observation{crate::leaf_guard::Observation{status:crate::leaf_guard::Status::Revoked,
        this_update:self.record.confirmed_at,produced_at:self.record.confirmed_at,valid_until:self.record.not_after,reason:Some(self.record.reason)}}
}
impl KeyDeny {
    fn install_issuer_fact(&self,fact:Arc<Fact>,pending:bool)->Result<()> {
        if fact.record.reason==1 {let state=self.register_spki(fact.spki.clone())?;let id=Sha256::digest(fact.spki.as_ref()).into();
            self.state.write().map_err(|_|anyhow!("key compromise state unavailable"))?.registry.ban_existing(&id,state.spki_der())?;}
        let old={let mut state=self.state.write().map_err(|_|anyhow!("key compromise state unavailable"))?;
            if let Some(old)=state.issuer_facts.get(&fact.leaf){
                if old.record.reason==1{return Ok(())}
                if old.record.confirmed_at>fact.record.confirmed_at&&fact.record.reason!=1{return Ok(())}
            }
            ensure!(state.issuer_facts.len()<65536||state.issuer_facts.contains_key(&fact.leaf),"issuer receipt history count exceeded");
            if pending {
                let previous=state.issuer_facts.get(&fact.leaf).filter(|_|state.issuer_pending.contains(&fact.leaf)).map_or(0,|f|f.bytes());
                let bytes=state.issuer_pending_bytes.saturating_sub(previous).checked_add(fact.bytes()).ok_or(crate::cert_transient::ResourceDenied)?;
                ensure!(bytes.checked_add(state.pending_bytes).is_some_and(|n|n<=MAX_PENDING_BYTES),"issuer receipt pending history exceeds limit");
                state.issuer_pending_bytes=bytes;state.issuer_pending.insert(fact.leaf);
            }
            state.issuer_facts.insert(fact.leaf,fact)
        };drop(old);Ok(())
    }
    /// Accept only a capability made by the authenticated manager producer.
    pub(crate) async fn record_issuer_confirmation(&self,receipt:IssuerReceipt,cpu:Arc<Semaphore>,cancel:CancellationToken)->Result<()> {
        let(key,reason,history)=receipt.into_parts();
        ensure!(self.owns_state(&key),"issuer receipt key belongs to another runtime");
        if reason==1{
            let id=Sha256::digest(key.spki_der()).into();
            self.state.write().map_err(|_|anyhow!("key compromise state unavailable"))?.registry.ban_existing(&id,key.spki_der())?;
        }
        // The fixed authenticated fact is applied even when history admission
        // or persistence fails, matching the existing live OCSP veto contract.
        self.changed.send_modify(|epoch|*epoch=epoch.wrapping_add(1));
        let fact=crate::cert_cpu::run(cpu.clone(),cancel.clone(),move||history.execute()).await
            .map_err(|error|anyhow::Error::new(KeyCompromiseNotDurable).context(error))?;
        self.install_issuer_fact(fact,true).map_err(|error|anyhow::Error::new(KeyCompromiseNotDurable).context(error))?;
        self.flush(cpu,cancel).await.map_err(|error|anyhow::Error::new(KeyCompromiseNotDurable).context(error))
    }
    pub(crate) fn issuer_observation(&self,leaf:&crate::leaf_guard::LeafId,not_after:i64)->Result<Option<crate::leaf_guard::Observation>>{
        let state=self.state.read().map_err(|_|anyhow!("key compromise state unavailable"))?;
        state.issuer_facts.get(leaf).map(|fact|{ensure!(fact.record.not_after==not_after,"issuer receipt leaf validity changed");Ok(fact.observation())}).transpose()
    }
    pub(super) async fn load_issuer_history(&self,store:&FsStore,cpu:Arc<Semaphore>,cancel:CancellationToken,ocsp_bytes:usize)->Result<()> {
        let paths=store.issuer_receipt_paths().await?;ensure!(paths.len()<=65536,"issuer receipt history count exceeded");let mut total=0usize;
        for path in paths {
            let raw=store.issuer_receipt_read(&path).await?.ok_or_else(||anyhow!("private issuer receipt disappeared"))?;
            total=total.checked_add(raw.len()).ok_or(crate::cert_transient::ResourceDenied)?;
            ensure!(total.checked_add(ocsp_bytes).is_some_and(|n|n<=MAX_HISTORY_BYTES),"issuer receipt history size exceeded");
            let fact=crate::cert_cpu::run(cpu.clone(),cancel.clone(),move||Fact::decode(raw.as_slice(),&path)).await?;
            self.install_issuer_fact(fact,false)?;
        }
        self.state.write().map_err(|_|anyhow!("key compromise state unavailable"))?.issuer_durable_bytes=total;Ok(())
    }
    pub(super) async fn flush_issuer_history(&self,store:&FsStore,cpu:Arc<Semaphore>,cancel:CancellationToken)->Result<()> {
        let pending={let state=self.state.read().map_err(|_|anyhow!("key compromise state unavailable"))?;
            state.issuer_pending.iter().filter_map(|leaf|state.issuer_facts.get(leaf).cloned()).collect::<Vec<_>>()};
        if pending.is_empty(){return Ok(())}
        let lease=store.lock("key_compromise",cancel.clone()).await?;
        let result=async{
            let mut total=0usize;let mut disk=HashMap::new();
            for path in store.issuer_receipt_paths().await? {
                let raw=store.issuer_receipt_read(&path).await?.ok_or_else(||anyhow!("private issuer receipt disappeared"))?;
                total=total.checked_add(raw.len()).ok_or(crate::cert_transient::ResourceDenied)?;disk.insert(path,raw.len());
            }
            for fact in pending {
                let path=fact.path();let(encoded,expected)={let fact=fact.clone();crate::cert_cpu::run(cpu.clone(),cancel.clone(),move||{
                    let encoded=crate::cert_transient::encode_json(&fact.record)?;let hash:[u8;32]=Sha256::digest(encoded.as_slice()).into();Ok((encoded,hash))
                }).await?};
                let next=total.saturating_sub(disk.get(&path).copied().unwrap_or(0)).checked_add(encoded.len()).ok_or(crate::cert_transient::ResourceDenied)?;
                let ocsp=self.state.read().map_err(|_|anyhow!("key compromise state unavailable"))?.durable_bytes;
                ensure!(encoded.len()<=MAX_RECORD&&next.checked_add(ocsp).is_some_and(|n|n<=MAX_HISTORY_BYTES),"issuer receipt durable history exceeds limit");
                let size=encoded.len();store.issuer_receipt_write(&path,encoded,&lease).await?;
                let raw=store.issuer_receipt_read(&path).await?.ok_or_else(||anyhow!("issuer receipt write disappeared"))?;
                let same=crate::cert_cpu::run(cpu.clone(),cancel.clone(),move||Ok(<[u8;32]>::from(Sha256::digest(raw.as_slice()))==expected)).await?;
                ensure!(same,"issuer receipt read-back content changed");
                total=next;disk.insert(path,size);
                let mut state=self.state.write().map_err(|_|anyhow!("key compromise state unavailable"))?;
                // A newer live receipt cannot be retired by an older IO batch.
                if state.issuer_facts.get(&fact.leaf).is_some_and(|current|Arc::ptr_eq(current,&fact))&&state.issuer_pending.remove(&fact.leaf){state.issuer_pending_bytes=state.issuer_pending_bytes.saturating_sub(fact.bytes());}
                state.issuer_durable_bytes=total;
            }
            Ok::<_,anyhow::Error>(())
        }.await;let released=lease.release().await;result?;released
    }
}
