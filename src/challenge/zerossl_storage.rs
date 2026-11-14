//! ZeroSSL's Go-compatible shared proof namespace, separate from ACME jobs.
use std::{collections::HashMap,sync::{Arc,RwLock,Weak}};
use anyhow::{Result,ensure,anyhow};
use serde::{Serialize,Deserialize};
use tokio_util::sync::CancellationToken;
use crate::{certstore::{FsStore,StorageLease},acme_wire::chain_memory};
#[derive(Default)]
pub(super) struct Sources {
    values:RwLock<HashMap<(u64,u64),Weak<Source>>>,
    readers:RwLock<Vec<Weak<Reader>>>,
}
pub(crate) struct ReaderPolicy {
    pub subjects:crate::tls_app_config::PreparedSubjectMatcher,
    pub source:Option<Arc<Source>>,
}
pub(crate) struct Reader {
    policies:Vec<ReaderPolicy>,
    cancel:CancellationToken,
    _memory:chain_memory::Scratch,
}
impl Reader {
    fn source(&self,name:&str)->Option<Arc<Source>> {
        if self.cancel.is_cancelled(){return None}
        self.policies.iter().find(|p|p.subjects.matches(name)).and_then(|p|p.source.clone())
    }
}
pub(crate) struct Source {store:FsStore,cpu:Arc<tokio::sync::Semaphore>,_memory:chain_memory::Lease}
#[derive(Serialize,Deserialize)]
pub(crate) struct Record {
    pub url:String,pub token:String,
    #[serde(default)] pub identifier:Identifier,
    #[serde(default,skip_serializing_if="Option::is_none")] pub native_owner:Option<String>,
    #[serde(default,skip_serializing_if="Option::is_none")] pub native_expires:Option<i64>,
}
#[derive(Default,Serialize,Deserialize)]
pub(crate) struct Identifier {#[serde(rename="type",default)]pub kind:String,#[serde(default)]pub value:String}
fn key(domain:&str)->String{format!("zerossl/challenge_tokens/{}.json",crate::certstore::safe(domain))}
fn now()->i64{std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0,|d|i64::try_from(d.as_secs()).unwrap_or(i64::MAX))}
impl Record {
    fn answer(&self,domain:&str,path:&str)->Result<Option<Option<crate::cert_transient::Bytes>>>{
        ensure!(self.token.len()<=16*1024,"ZeroSSL stored proof exceeds limit");
        if self.native_expires.is_some_and(|until|until<=now()){return Ok(None)}
        let url=url::Url::parse(&self.url).map_err(|_|anyhow!("invalid stored ZeroSSL proof URL"))?;
        ensure!(url.scheme()=="http"&&url.host_str().and_then(|host|super::normalize_zerossl_host(host).ok()).is_some_and(|host|host==domain),"ZeroSSL stored proof host changed");
        ensure!(url.path().starts_with("/.well-known/pki-validation/")&&url.path().len()<=1024,"invalid ZeroSSL proof path");
        if url.path()!=path{return Ok(Some(None))}
        Ok(Some(Some(crate::cert_transient::Bytes::copy(self.token.as_bytes(),crate::cert_transient::Lifetime::Temporary)?)))
    }
}
impl Sources {
    pub(super) fn register(&self,store:FsStore,cpu:Arc<tokio::sync::Semaphore>)->Result<Arc<Source>>{
        let mut values=self.values.write().map_err(|_|anyhow!("ZeroSSL storage sources unavailable"))?;
        values.retain(|_,v|v.strong_count()>0);let id=store.root_identity();
        if let Some(source)=values.get(&id).and_then(Weak::upgrade){return Ok(source)}
        ensure!(values.len()<128,"ZeroSSL storage source limit reached");
        let memory=chain_memory::shared().payload.reserve(std::mem::size_of::<Source>()+256)?;
        let source=Arc::new(Source{store,cpu,_memory:memory});values.insert(id,Arc::downgrade(&source));Ok(source)
    }
    pub(super) fn reader(&self,policies:Vec<ReaderPolicy>,cancel:CancellationToken,memory:chain_memory::Scratch)->Result<Arc<Reader>> {
        let mut readers=self.readers.write().map_err(|_|anyhow!("ZeroSSL storage readers unavailable"))?;
        readers.retain(|entry|entry.upgrade().is_some_and(|r|!r.cancel.is_cancelled()));
        ensure!(readers.len()<128,"ZeroSSL storage reader limit reached");
        let reader=Arc::new(Reader{policies,cancel,_memory:memory});
        readers.push(Arc::downgrade(&reader));Ok(reader)
    }
    pub(super) async fn lookup(&self,authority:&str,path:&str)->Option<Option<crate::cert_transient::Bytes>>{
        let domain=super::normalize_zerossl_authority(authority).ok()?;
        let readers=self.readers.read().ok()?.iter().filter_map(Weak::upgrade).collect::<Vec<_>>();
        let mut found_host=false;
        for reader in readers {
            let Some(source)=reader.source(&domain) else{continue};
            let Some(raw)=source.store.load_ca_input(&key(&domain)).await.ok().flatten() else{continue};
            if raw.len()>64*1024{continue}
            let domain=domain.clone();let path=path.to_owned();
            let answer=crate::cert_cpu::run(source.cpu.clone(),CancellationToken::new(),move||{
                let _parse=crate::cert_transient::reserve(raw.len().checked_mul(4).and_then(|n|n.checked_add(8192)).ok_or(crate::cert_transient::ResourceDenied)?)?;
                let record:Record=serde_json::from_slice(raw.as_ref()).map_err(|_|anyhow!("invalid stored ZeroSSL proof"))?;
                record.answer(&domain,&path)
            }).await;
            if reader.cancel.is_cancelled(){continue}
            match answer {Ok(Some(Some(answer)))=>return Some(Some(answer)),Ok(Some(None))=>found_host=true,_=>{}}
        }
        if found_host{Some(None)}else{None}
    }
}
/// ZeroSSL owns its lease until bounded remote cancellation and fenced cleanup
/// finish. Acquisition still joins caller cancellation; no lost lease revives.
pub(crate) async fn cleanup_lease(store:&FsStore,name:&str,cancel:CancellationToken)
    ->Result<(StorageLease,tokio_util::sync::DropGuard)> {
    let lifetime=CancellationToken::new();
    let mut guard=Some(lifetime.clone().drop_guard());
    let acquire=store.lock(name,lifetime);tokio::pin!(acquire);
    let lease=tokio::select!{biased;
        _=cancel.cancelled()=>{
            drop(guard.take());
            if let Ok(lease)=acquire.await{let _=lease.release().await;}
            return Err(anyhow!("ZeroSSL lease acquisition cancelled"))
        },
        lease=&mut acquire=>lease?,
    };
    Ok((lease,guard.take().expect("owned ZeroSSL lease lifetime")))
}
impl Source {
    pub(crate) async fn clear(self:&Arc<Self>,owner:&str,domain:&str,cancel:CancellationToken)->Result<()>{
        let domain=super::normalize_zerossl_host(domain)?;
        let(lease,lifetime)=cleanup_lease(&self.store,&format!("zerossl_validation_{domain}"),cancel).await?;
        Presentation{source:self.clone(),lease,key:key(&domain),owner:owner.to_owned(),_lifetime:lifetime}.cleanup().await
    }

    pub(crate) async fn present(self:&Arc<Self>,owner:&str,domain:&str,url:&str,body:&str,cancel:CancellationToken)->Result<Presentation>{
        let domain=super::normalize_zerossl_host(domain)?;
        ensure!(owner.len()<=128&&!owner.is_empty()&&body.len()<=16*1024&&!body.is_empty(),"invalid ZeroSSL proof");
        let key=key(&domain);
        let record=Record{url:url.to_owned(),token:body.to_owned(),identifier:Identifier{kind:String::new(),value:domain.clone()},
            native_owner:Some(owner.to_owned()),native_expires:Some(now().saturating_add(3600))};
        // Validate the external URL before writing. A query is irrelevant to
        // Go's Path comparison and is never fetched by this proof responder.
        let parsed=url::Url::parse(url).map_err(|_|anyhow!("invalid ZeroSSL validation URL"))?;
        let _=record.answer(&domain,parsed.path())?;
        let owner=owner.to_owned();
        let encoded=crate::cert_cpu::run(self.cpu.clone(),cancel.clone(),move||crate::cert_transient::encode_json(&record)).await?;
        let(lease,lifetime)=cleanup_lease(&self.store,&format!("zerossl_validation_{domain}"),cancel).await?;
        self.store.store_fenced(&key,&encoded,&lease).await?;
        Ok(Presentation{source:self.clone(),lease,key,owner,_lifetime:lifetime})
    }
}
pub(crate) struct Presentation {source:Arc<Source>,lease:StorageLease,key:String,owner:String,_lifetime:tokio_util::sync::DropGuard}
impl Presentation {
    pub(crate) async fn cleanup(self)->Result<()>{
        let result:Result<()>=async{
            if let Some(raw)=self.source.store.load_ca_input(&self.key).await?{
                let owner=self.owner.clone();
                let ours=crate::cert_cpu::run(self.source.cpu.clone(),CancellationToken::new(),move||{
                    if raw.len()>64*1024{return Ok(false)}
                    let record:Record=serde_json::from_slice(raw.as_ref()).map_err(|_|anyhow!("invalid ZeroSSL proof cleanup record"))?;
                    Ok(record.native_owner.as_deref()==Some(owner.as_str()))
                }).await?;
                if ours{self.source.store.delete_fenced(&self.key,&self.lease).await?;}
            }
            Ok(())
        }.await;
        let released=self.lease.release().await;result?;released
    }
}
