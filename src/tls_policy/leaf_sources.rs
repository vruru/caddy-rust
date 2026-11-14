//! Provision-owned leaf input loading; raw JSON and verifier grouping are retained.
use super::{ClientAuth,prepared_auth::{AuthBudget,AuthEntry,BufferCredit}};
use anyhow::{Result,ensure,bail};
use rustls::pki_types::CertificateDer;
use serde_json::Value;
use std::{path::{Path,PathBuf},sync::Arc,io::Read};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;
use crate::cert_transient::{self,ResourceDenied};
const LIMIT:usize=16<<20;
#[derive(Clone,Copy)]
struct Spec{group:usize,loader:usize,item:usize,kind:Kind}
#[derive(Clone,Copy,PartialEq,Eq)]
enum Kind{File,Pem,Folder,Storage}
impl Kind{fn key(self)->&'static str{match self{Self::File=>"files",Self::Folder=>"folders",Self::Pem|Self::Storage=>"certificates"}}}
pub(crate) type StorageInputs=Vec<(usize,usize,crate::certstore::FsStore)>;
pub(crate) struct LeafData{groups:Vec<Vec<CertificateDer<'static>>>,bytes:usize,count:usize,_credit:BufferCredit}
impl LeafData{
    pub(crate) fn groups(&self)->&[Vec<CertificateDer<'static>>]{&self.groups}
    fn new(raw:&ClientAuth,budget:&AuthBudget)->Result<Self>{
        let n=raw.verifiers.len();
        let credit=budget.reserve_buffer(n.checked_mul(std::mem::size_of::<Vec<CertificateDer>>()).and_then(|n|n.checked_add(1024)).ok_or(ResourceDenied)?)?;
        let mut groups=Vec::new();groups.try_reserve_exact(n)?;groups.resize_with(n,Vec::new);
        Ok(Self{groups,bytes:0,count:0,_credit:credit})
    }
    fn retained(&self)->Result<usize>{
        self.groups.iter().try_fold(self.groups.capacity().checked_mul(std::mem::size_of::<Vec<CertificateDer>>()).and_then(|n|n.checked_add(1024)).ok_or(ResourceDenied)?,|n,g|{
            g.iter().try_fold(n.checked_add(g.capacity().checked_mul(std::mem::size_of::<CertificateDer>()).ok_or(ResourceDenied)?).ok_or(ResourceDenied)?,|n,c|n.checked_add(c.len().checked_mul(2).ok_or(ResourceDenied)?).ok_or(ResourceDenied))
        }).map_err(Into::into)
    }
    fn consume(mut self,spec:Spec,source:Source,cancel:&CancellationToken)->Result<Self>{
        ensure!(!cancel.is_cancelled(),"leaf input preparation cancelled");
        let working=self.retained()?.checked_add(source.bytes().len().checked_mul(6).ok_or(ResourceDenied)?).and_then(|n|n.checked_add(64<<10)).ok_or(ResourceDenied)?;
        self._credit.resize(working)?;
        let certs=super::client_auth::leaf_certificates(source.bytes(),matches!(spec.kind,Kind::File|Kind::Storage))?;
        for cert in &certs{self.count=self.count.checked_add(1).ok_or(ResourceDenied)?;self.bytes=self.bytes.checked_add(cert.len()).ok_or(ResourceDenied)?;ensure!(self.count<=4096&&self.bytes<=LIMIT,"client trust budget exceeded");}
        let group=self.groups.get_mut(spec.group).ok_or_else(||anyhow::anyhow!("leaf input topology changed"))?;
        group.try_reserve_exact(certs.len())?;group.extend(certs);
        drop(source);
        self._credit.resize(self.retained()?)?;Ok(self)
    }
}
fn each(raw:&ClientAuth,mut f:impl FnMut(Spec,&str)->Result<()>)->Result<()>{
    for(gi,verifier)in raw.verifiers.iter().enumerate(){
        let obj=super::require_object(verifier)?;super::check_unknown(obj,&["verifier","leaf_certs_loaders"],"client certificate verifier")?;
        ensure!(obj.get("verifier").and_then(Value::as_str)==Some("leaf"),"unsupported client certificate verifier");
        if let Some(loaders)=obj.get("leaf_certs_loaders").filter(|v|!v.is_null()){
            for(li,loader)in super::require_array(loaders,"leaf certificate loaders")?.iter().enumerate(){
                let obj=super::require_object(loader)?;
                let kind=match obj.get("loader").and_then(Value::as_str){Some("file")=>Kind::File,Some("pem")=>Kind::Pem,Some("folder")=>Kind::Folder,Some("storage")=>Kind::Storage,_=>bail!("unsupported client leaf certificate loader")};
                let key=kind.key();
                if kind==Kind::Storage{super::check_unknown(obj,&["loader",key,"storage"],"leaf storage loader")?;}else{super::check_unknown(obj,&["loader",key],"leaf certificate loader")?;}
                if let Some(items)=obj.get(key).filter(|v|!v.is_null()){
                    let items=super::require_array(items,"leaf certificate input")?;ensure!(items.len()<=256,"too many leaf inputs");
                    for(ii,item)in items.iter().enumerate(){let value=super::require_string(item,"leaf certificate input")?;super::check_len(value,4096,"leaf certificate input")?;f(Spec{group:gi,loader:li,item:ii,kind},value)?;}
                }
            }
        }
    }Ok(())
}
fn raw_at(raw:&ClientAuth,spec:Spec)->Result<&str>{
    raw.verifiers.get(spec.group).and_then(|v|v.get("leaf_certs_loaders")).and_then(|v|v.get(spec.loader)).and_then(|v|v.get(spec.kind.key())).and_then(|v|v.get(spec.item)).and_then(Value::as_str).ok_or_else(||anyhow::anyhow!("leaf input topology changed"))
}
enum Source{Stored(crate::cert_transient::Bytes),Inline(crate::tls_app_config::leaf_values::Expanded),File{bytes:Zeroizing<Vec<u8>>,_credit:crate::acme_wire::chain_memory::Scratch}}
impl Source{fn bytes(&self)->&[u8]{match self{Self::Stored(v)=>v.as_slice(),Self::Inline(v)=>v.as_bytes(),Self::File{bytes,..}=>bytes}}}
fn read_file(path:&[u8],cwd:&Path,cancel:&CancellationToken)->Result<Source>{
    let mut f=crate::tls_app_config::leaf_values::open(path,cwd)?;
    let n=usize::try_from(f.metadata()?.len()).map_err(|_|ResourceDenied)?;ensure!(n<=LIMIT,"leaf certificate file exceeds limit");
    let credit=cert_transient::reserve(n.checked_add(1).ok_or(ResourceDenied)?)?;
    let mut bytes=Zeroizing::new(Vec::new());bytes.try_reserve_exact(n)?;bytes.resize(n,0);f.read_exact(&mut bytes)?;
    let mut extra=[0u8;1];ensure!(f.read(&mut extra)?==0,"leaf certificate file changed during read");
    ensure!(!cancel.is_cancelled(),"leaf input preparation cancelled");
    Ok(Source::File{bytes,_credit:credit})
}
fn load(raw:&str,kind:Kind,cwd:&Path,cancel:&CancellationToken)->Result<Source>{
    let value=crate::tls_app_config::leaf_values::expand(raw,cwd,cancel)?;
    if kind==Kind::Pem{return Ok(Source::Inline(value))}
    ensure!(kind==Kind::File,"leaf input requires a contextual loader");
    read_file(value.as_bytes(),cwd,cancel)
}
struct LoadJob{entry:Arc<AuthEntry>,spec:Spec,cwd:Arc<PathBuf>}
impl LoadJob{fn execute(self,cancel:&CancellationToken)->Result<Source>{load(raw_at(self.entry.raw(),self.spec)?,self.spec.kind,&self.cwd,cancel)}}
#[path="leaf_sources/folder.rs"]mod folder;
struct ParseJob{data:LeafData,spec:Spec,source:Source}
impl ParseJob{fn execute(self,cancel:&CancellationToken)->Result<LeafData>{self.data.consume(self.spec,self.source,cancel)}}
pub(crate) async fn prepare(entry:Arc<AuthEntry>,cwd:PathBuf,io:Arc<Semaphore>,cpu:Arc<Semaphore>,budget:AuthBudget,cancel:CancellationToken,storage:StorageInputs)->Result<LeafData>{
    let e=entry.clone();let b=budget.clone();
    let(mut data,specs,_index)=crate::cert_cpu::run(cpu.clone(),cancel.clone(),move||{
        let mut count=0usize;each(e.raw(),|_,_|{count=count.checked_add(1).ok_or(ResourceDenied)?;Ok(())})?;
        let index=b.reserve_buffer(count.checked_mul(std::mem::size_of::<Spec>()).and_then(|n|n.checked_add(1024)).ok_or(ResourceDenied)?)?;
        let mut specs=Vec::new();specs.try_reserve_exact(count)?;each(e.raw(),|s,_|{specs.push(s);Ok(())})?;
        Ok((LeafData::new(e.raw(),&b)?,specs,index))
    }).await?;
    let cwd=Arc::new(cwd);
    for spec in specs{
        if spec.kind==Kind::Folder{
            let e=entry.clone();let c=cwd.clone();let token=cancel.clone();
            let files=crate::cert_cpu::run(io.clone(),cancel.clone(),move||folder::list(raw_at(e.raw(),spec)?,&c,&token)).await?;
            for path in &files.paths{
                let path=path.clone();let c=cwd.clone();let token=cancel.clone();
                let source=crate::cert_cpu::run(io.clone(),cancel.clone(),move||read_file(path.as_os_str().as_encoded_bytes(),&c,&token)).await?;
                let job=ParseJob{data,spec,source};let token=cancel.clone();
                data=crate::cert_cpu::run(cpu.clone(),CancellationToken::new(),move||job.execute(&token)).await?;
            }
        }else{
            let source=if spec.kind==Kind::Storage{
                let e=entry.clone();let c=cwd.clone();let token=cancel.clone();
                let value=crate::cert_cpu::run(io.clone(),cancel.clone(),move||crate::tls_app_config::leaf_values::expand(raw_at(e.raw(),spec)?,&c,&token)).await?;
                ensure!(value.as_bytes().len()<=4096,"leaf storage key exceeds limit");
                let key=std::str::from_utf8(value.as_bytes()).map_err(|_|anyhow::anyhow!("leaf storage key is not UTF-8"))?;
                let store=storage.iter().find(|(g,l,_)|*g==spec.group&&*l==spec.loader).ok_or_else(||anyhow::anyhow!("leaf storage context missing"))?;
                ensure!(!cancel.is_cancelled(),"leaf input preparation cancelled");
                let source=store.2.load_ca_input(key).await?.ok_or_else(||anyhow::anyhow!("leaf storage certificate missing"))?;
                ensure!(source.len()<=LIMIT,"leaf certificate file exceeds limit");Source::Stored(source)
            }else{
                let job=LoadJob{entry:entry.clone(),spec,cwd:cwd.clone()};let token=cancel.clone();
                crate::cert_cpu::run(io.clone(),cancel.clone(),move||job.execute(&token)).await?
            };
            let job=ParseJob{data,spec,source};let token=cancel.clone();
            data=crate::cert_cpu::run(cpu.clone(),CancellationToken::new(),move||job.execute(&token)).await?;
        }
    }Ok(data)
}
pub(super) fn prepare_sync(raw:&ClientAuth)->Result<LeafData>{
    let budget=AuthBudget::standalone();let mut data=Some(LeafData::new(raw,&budget)?);let cwd=std::env::current_dir()?;let token=CancellationToken::new();
    each(raw,|spec,value|{
        if spec.kind==Kind::Folder{
            let files=folder::list(value,&cwd,&token)?;
            for path in &files.paths{let source=read_file(path.as_os_str().as_encoded_bytes(),&cwd,&token)?;data=Some(data.take().expect("leaf state").consume(spec,source,&token)?);}
        }else{
            ensure!(spec.kind!=Kind::Storage,"synchronous leaf preparation requires storage context");
            let source=load(value,spec.kind,&cwd,&token)?;data=Some(data.take().expect("leaf state").consume(spec,source,&token)?);
        }Ok(())
    })?;
    Ok(data.expect("leaf state"))
}
