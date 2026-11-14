//! Revoke the actual stored winner, never whichever issuer is first today.
use super::*;
use crate::cert_transient::{Bytes,Lifetime};
#[derive(Serialize,Deserialize)]
struct Intent {
    version:u8,backend:attempt::BackendId,
    #[serde(deserialize_with="super::job_codec::text")] certificate_id:String,
    #[serde(deserialize_with="super::job_codec::text")] leaf_sha256:String,
    #[serde(deserialize_with="super::job_codec::text")] spki_sha256:String,
    reason:u8,
    #[serde(deserialize_with="super::job_codec::text")] phase:String,
}
struct Snapshot {value:Intent,_memory:crate::acme_wire::chain_memory::Scratch}
impl Snapshot {
    fn encode(self,name:String)->Result<job_codec::Encoded>{job_codec::encode_record(&self.value,&name)}
}
struct IntentJob {value:Intent,name:String,_memory:crate::acme_wire::chain_memory::Scratch}
impl IntentJob {
    fn new(backend:&attempt::BackendId,target:&Target,info:&MaterialInfo,reason:u8,name:&str)->Result<Self>{
        let bytes=backend::identity_bytes(backend)?.checked_add(target.id.len()).and_then(|n|n.checked_add(name.len()+1024)).ok_or(crate::cert_transient::ResourceDenied)?;
        let memory=crate::cert_transient::reserve(bytes)?;
        Ok(Self{value:Intent{version:1,backend:backend.clone(),certificate_id:target.id.clone(),leaf_sha256:info.leaf_sha256.clone(),
            spki_sha256:digest(&info.spki_der),reason,phase:"intent".to_owned()},name:name.to_owned(),_memory:memory})
    }
    fn execute(self)->Result<job_codec::Encoded>{job_codec::encode_record(&self.value,&self.name)}
}
struct Target {leaf:Bytes,id:String,account:String,_memory:crate::acme_wire::chain_memory::Scratch}
struct TargetInput {bundle:OwnedCertificateBundle,zero:bool,_memory:crate::acme_wire::chain_memory::Scratch}
impl TargetInput {
    fn execute(self)->Result<Target>{
        let blocks=crate::cert_transient::certificate_blocks(&self.bundle.chain_pem)?;
        let leaf=blocks.first().ok_or_else(||anyhow!("revocation certificate missing"))?;
        let raw_id=if self.zero{Some(self.bundle.metadata["issuer_data"]["id"].as_str().ok_or_else(||anyhow!("stored ZeroSSL certificate ID missing"))?)}
            else{self.bundle.metadata["issuer_data"]["url"].as_str().filter(|s|!s.is_empty())};
        let account=self.bundle.metadata["issuer_data"]["account"].as_str().unwrap_or_default();
        ensure!(raw_id.is_none_or(|id|!id.is_empty()&&id.len()<=4096)&&account.len()<=4096,"stored revocation identity exceeds bounds");
        let id=raw_id.map(str::to_owned).unwrap_or_else(||format!("leaf:{}",digest(&leaf.1)));let account=account.to_owned();
        Ok(Target{leaf:Bytes::copy(&leaf.1,Lifetime::Temporary)?,id,account,_memory:self._memory})
    }
}
#[derive(Debug)]
struct Rejected;
impl std::fmt::Display for Rejected {fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{f.write_str("certificate issuer rejected the revocation request")}}
impl std::error::Error for Rejected{}
enum Revoker<'a> {
    Acme{session:AccountSession,_network:NetworkPermit<'a>},
    ZeroSsl{wire:crate::zerossl_wire::Wire,id:crate::zerossl_wire::models::CertId,already:bool,
        _issuer:tokio::sync::SemaphorePermit<'a>,_global:tokio::sync::SemaphorePermit<'a>},
}
impl Revoker<'_> {
    async fn send(self,leaf:&[u8],reason:u8,cancel:&CancellationToken)->Result<bool>{
        // Borrow the entire envelope until actual request completion. Dropping
        // an unused destructured permit before await would bypass admission.
        let result=match &self {
            Self::ZeroSsl{wire,id,already,..}=>if *already{Ok(false)}else{wire.revoke(id,crate::zerossl_wire::models::RevocationReason::from_code(reason)?,cancel).await.map(|()|true)},
            Self::Acme{session,..}=>match session.revoke(leaf,reason,cancel).await{
                Err(error)if error.downcast_ref::<ProtocolError>().is_some_and(|e|e.status()==400&&e.kind()=="alreadyRevoked"&&!e.uncertain())=>Ok(false),result=>result.map(|()|true),
            },
        };drop(self);
        result.map_err(|error|{
            let rejected=error.downcast_ref::<crate::zerossl_wire::models::ApiError>().is_some_and(|e|e.confirmed_rejection)
                ||error.downcast_ref::<ProtocolError>().is_some_and(|e|(400..500).contains(&e.status())&&!e.uncertain());
            if rejected{error.context(Rejected)}else{error}
        })
    }
}
/// Fixed authenticated capability. There is deliberately no Deserialize or
/// public constructor. History construction may fail without losing key veto.
pub(crate) struct IssuerReceipt {key:Arc<crate::key_compromise::KeyState>,reason:u8,history:IssuerReceiptHistory}
pub(crate) struct IssuerReceiptHistory {
    backend:Arc<backend::BackendIdentity>,target:Target,reason:u8,at:i64,requested_reason_confirmed:bool,
}
impl IssuerReceiptHistory {
    pub(crate) fn execute(self)->Result<Arc<crate::key_compromise::issuer_receipts::Fact>>{
        crate::key_compromise::issuer_receipts::Fact::from_authenticated(&self.backend.id,self.target.id,self.target.leaf.as_slice(),self.reason,self.at,self.requested_reason_confirmed)
    }
}
impl IssuerReceipt {
    fn authenticated(key:Arc<crate::key_compromise::KeyState>,backend:Arc<backend::BackendIdentity>,target:Target,reason:u8,at:i64,requested_reason_confirmed:bool)->Self{
        Self{key,reason,history:IssuerReceiptHistory{backend,target,reason,at,requested_reason_confirmed}}
    }
    pub(crate) fn into_parts(self)->(Arc<crate::key_compromise::KeyState>,u8,IssuerReceiptHistory){(self.key,self.reason,self.history)}
}
fn identity(backend:&attempt::BackendId,leaf:&str)->Result<String>{
    struct Sink<'a>(&'a mut Sha256);
    impl std::io::Write for Sink<'_>{fn write(&mut self,b:&[u8])->std::io::Result<usize>{self.0.update(b);Ok(b.len())}fn flush(&mut self)->std::io::Result<()>{Ok(())}}
    let mut hash=Sha256::new();hash.update(b"revoke-v1\0");hash.update(leaf.as_bytes());serde_json::to_writer(Sink(&mut hash),backend)?;
    Ok(format!("revoke-v1-{:x}",hash.finalize()))
}
impl CertificateManager {
    async fn revoke_intent(&self,id:&str)->Result<Option<Snapshot>>{
        self.inner.store.journal_decode_admitted(id,|raw|{
            let memory=job_codec::decode_credit(raw.len())?;
            let value:Intent=serde_json::from_slice(raw).map_err(|_|anyhow!("invalid revocation intent"))?;
            ensure!(value.version==1&&[0,1,3,4,5].contains(&value.reason)&&matches!(value.phase.as_str(),"intent"|"confirmed"|"rejected")
                &&value.leaf_sha256.len()==64&&value.spki_sha256.len()==64&&value.certificate_id.len()<=4096,"invalid revocation intent binding");
            Ok(Snapshot{value,_memory:memory})
        }).await
    }
    /// Only private native intent is consulted; a public storage metadata flag
    /// or imported file cannot authorize revocation or claim a confirmation.
    pub(super) async fn check_revoke_intent(&self,backend:&attempt::BackendId,info:&MaterialInfo)->Result<()> {
        let id=identity(backend,&info.leaf_sha256)?;
        if let Some(saved)=self.revoke_intent(&id).await?{
            ensure!(saved.value.backend==*backend&&saved.value.leaf_sha256==info.leaf_sha256
                &&saved.value.spki_sha256==digest(&info.spki_der),"stored revocation intent identity changed");
            if saved.value.phase=="rejected"{return Ok(())}
            ensure!(saved.value.phase=="confirmed","stored certificate has an unresolved revocation; resume revoke_managed with its original issuer");
            ensure!(self.inner.resolver.leaf_guard().key_deny().issuer_observation(&info.leaf_id,info.not_after)?.is_some(),"confirmed revocation receipt is missing from instance state");
        }
        Ok(())
    }
    /// Remotely revoke the exact stored certificate using its saved backend.
    /// Pass the target returned by ensure/load_cached. A different current leaf
    /// is a stale-target error, never permission to revoke its replacement.
    /// The resolver's instance-private veto history must already be loaded.
    /// An incomplete remote result keeps a native intent and never asserts a
    /// local CA confirmation. An already-revoked reply proves the exact leaf
    /// revoked; it does not prove that this request's reason was accepted.
    /// A requested key-compromise veto is then a conservative local constraint,
    /// recorded separately from reason confirmation. This API does not delete
    /// the public PEM assets.
    pub async fn revoke_managed(&self,certificate:&ManagedCertificate,reason:u8,cancel:CancellationToken)->Result<()> {
        ensure!([0,1,3,4,5].contains(&reason),"unsupported certificate revocation reason");
        self.inner.resolver.leaf_guard().key_deny().require_loaded()?;
        ensure!(certificate.leaf_sha256.len()==64,"invalid requested revocation fingerprint");
        let names=self.normalize_subjects(&certificate.names)?;self.startup_recovery(cancel.clone()).await?;
        let gate=self.name_gate(&names).await?;
        let _gate=tokio::select!{biased;_=cancel.cancelled()=>bail!("certificate revocation cancelled"),g=gate.lock()=>g};
        let lease=self.inner.store.lock(&format!("issue_cert_{}",names[0]),cancel.clone()).await?;
        let work=cancel.child_token();let lost=lease.lost();
        let result={let operation=self.revoke_inner(&names,certificate,reason,&lease,&work);tokio::pin!(operation);
            tokio::select!{biased;r=&mut operation=>r,
                _=cancel.cancelled()=>{work.cancel();let _=operation.await;Err(anyhow!("certificate revocation cancelled"))},
                _=lost.cancelled()=>{work.cancel();let _=operation.await;Err(anyhow!("certificate revocation lease lost"))},
                _=tokio::time::sleep(self.inner.options.job_timeout.min(Duration::from_secs(120)))=>{work.cancel();let _=operation.await;Err(anyhow!("certificate revocation deadline exceeded"))},
            }};
        work.cancel();let released=lease.release().await;result?;released
    }
    async fn revoke_inner(&self,names:&[String],expected:&ManagedCertificate,reason:u8,lease:&StorageLease,cancel:&CancellationToken)->Result<()> {
        let key=names_key(names)?;let state=self.load_attempt(names).await?;
        let saved=state.as_ref().and_then(|s|s.winner.as_ref().map(|w|(w.backend.as_ref(),w.issuer_key.as_str(),w.leaf_sha256.as_str()))
            .or_else(||s.base_leaf.as_deref().and_then(|leaf|s.base_backend.as_ref().map(|b|(Some(b),"",leaf)))));
        let mut found=None;
        for(index,backend)in self.inner.backends.iter().enumerate(){
            if let Some((Some(id),_,_))=saved{if &backend.id!=id{continue}}
            else if let Some((None,issuer,_))=saved{if backend.storage_key!=issuer{continue}}
            if self.inner.backends.iter().enumerate().any(|(prior,b)|prior<index&&b.storage_key==backend.storage_key){
                // A typed exact backend was filtered before this check; only
                // legacy ambiguous storage credentials are rejected below.
                if saved.is_none_or(|s|s.0.is_none()){continue}
            }
            if let Some(bundle)=self.read_issuer_certificate(&backend.storage_key,&key,cancel).await?{
                ensure!(found.is_none(),"legacy revocation issuer is ambiguous");found=Some((index,bundle));
            }
        }
        let(index,bundle)=found.ok_or_else(||anyhow!("original revocation issuer/material is not available in the current policy"))?;
        let backend=&self.inner.backends[index];ensure!(!matches!(backend.kind,backend::BackendKind::Internal{..}),"internal issuer has no remote revocation capability");
        if saved.is_none_or(|s|s.0.is_none()){
            ensure!(self.inner.backends.iter().filter(|b|b.storage_key==backend.storage_key).count()==1,"legacy revocation credentials are ambiguous");
        }
        let info=self.inspect_material(&bundle,names,cancel).await?;
        ensure!(expected.issuer_key==backend.storage_key&&expected.leaf_sha256==info.leaf_sha256,"requested revocation target is stale");
        if let Some((_,_,expected))=saved{ensure!(info.leaf_sha256==expected,"stored revocation winner changed");}
        let snapshot=backend::BackendIdentity::copy(&backend.id)?;
        let input=TargetInput{bundle,zero:matches!(backend.kind,backend::BackendKind::ZeroSsl(_)),_memory:crate::cert_transient::reserve(32768)?};
        let target=self.cpu(cancel,move||input.execute()).await?;
        let id=identity(&backend.id,&info.leaf_sha256)?;
        let previous=self.revoke_intent(&id).await?;
        if let Some(previous)=&previous {
            ensure!(previous.value.backend==backend.id&&previous.value.certificate_id==target.id
                &&previous.value.leaf_sha256==info.leaf_sha256&&previous.value.spki_sha256==digest(&info.spki_der),"revocation retry scope changed");
            if previous.value.phase=="confirmed"&&previous.value.reason==reason {
                ensure!(self.inner.resolver.leaf_guard().key_deny().issuer_observation(&info.leaf_id,info.not_after)?.is_some(),"confirmed issuer receipt missing");return Ok(())
            }
            ensure!(previous.value.phase!="intent"||previous.value.reason==reason,"finish the original revocation reason before changing it");
        }
        // Complete local constructor/account checks before recording the
        // irreversible request intent. Setup failures must not strand a leaf.
        let revoker=match &backend.kind {
            backend::BackendKind::ZeroSsl(state)=>{
                let issuer=tokio::select!{biased;_=cancel.cancelled()=>bail!("ZeroSSL revocation cancelled"),p=state.limiter.acquire()=>p.map_err(|_|anyhow!("ZeroSSL issuer closed"))?};
                let global=tokio::select!{biased;_=cancel.cancelled()=>bail!("ZeroSSL revocation cancelled"),p=self.inner.global.acquire()=>p.map_err(|_|anyhow!("certificate manager closed"))?};
                let wire=self.zero_wire(state,cancel).await?.clone();let cert_id=crate::zerossl_wire::models::CertId::parse(target.id.clone())?;
                let reply=wire.get(&cert_id,cancel).await?;ensure!(reply.value.id==cert_id.as_str(),"ZeroSSL revoke certificate ID changed");
                let already=reply.value.status=="revoked";
                Revoker::ZeroSsl{wire,id:cert_id,already,_issuer:issuer,_global:global}
            },
            backend::BackendKind::Acme(index)=>{
                ensure!(!target.account.is_empty(),"original stored ACME account identity is required for revocation");
                let issuer=&self.inner.issuers[*index];let network=self.net_permit(issuer,cancel).await?;
                let wire=issuer.wire.get_or_try_init(||AcmeWire::connect_with_client_tls_scope(issuer.config.wire.clone(),self.inner.local.clone(),self.inner.chain_memory.clone(),
                    #[cfg(feature="native-run")] self.inner.outgoing_tls.clone(),self.wire_client_owner_for(issuer),cancel)).await?;
                let session=self.account(issuer,wire,Some(&target.account),cancel).await?;
                Revoker::Acme{session,_network:network}
            },
            backend::BackendKind::Internal{..}=>bail!("internal issuer has no remote revocation capability"),
        };
        let intent=IntentJob::new(&backend.id,&target,&info,reason,lease.name())?;
        let encoded=self.cpu(cancel,move||intent.execute()).await?;
        self.inner.store.journal_store_encoded_fenced(&id,encoded,lease).await?;
        let requested_reason_confirmed=match revoker.send(target.leaf.as_slice(),reason,cancel).await{
            Ok(confirmed)=>confirmed,
            Err(error)=>{
            if error.is::<Rejected>(){
                let mut saved=self.revoke_intent(&id).await?.ok_or_else(||anyhow!("revocation intent disappeared"))?;
                saved.value.phase="rejected".to_owned();let name=lease.name().to_owned();
                let encoded=self.cpu(cancel,move||saved.encode(name)).await?;
                self.inner.store.journal_store_encoded_fenced(&id,encoded,lease).await?;
            }
            return Err(error)
            }
        };
        // Only this authenticated result can construct the capability. Apply
        // the exact leaf immediately; a persistence failure cannot undo it.
        let at=now();let guard=self.inner.resolver.leaf_guard();
        guard.intern(info.leaf_id,info.not_after)?.observe_issuer(crate::leaf_guard::Observation{status:crate::leaf_guard::Status::Revoked,
            this_update:at,produced_at:at,valid_until:info.not_after,reason:Some(reason)})?;
        let receipt=IssuerReceipt::authenticated(info._key_state.clone(),snapshot,target,reason,at,requested_reason_confirmed);
        guard.key_deny().record_issuer_confirmation(receipt,self.inner.local.clone(),cancel.clone()).await?;
        let mut intent=self.revoke_intent(&id).await?.ok_or_else(||anyhow!("revocation intent disappeared"))?;
        intent.value.phase="confirmed".to_owned();let name=lease.name().to_owned();
        let encoded=self.cpu(cancel,move||intent.encode(name)).await?;
        self.inner.store.journal_store_encoded_fenced(&id,encoded,lease).await?;
        let _=self.inner.events.send(AutomationEvent{names:names.to_vec(),kind:"certificate_revoked",recovery_issue:None});Ok(())
    }
}
