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
struct Spec{group:usize,loader:usize,item:usize,file:bool}
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
        let certs=super::client_auth::leaf_certificates(source.bytes(),spec.file)?;
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
                let(file,key)=match obj.get("loader").and_then(Value::as_str){Some("file")=>(true,"files"),Some("pem")=>(false,"certificates"),_=>bail!("unsupported client leaf certificate loader")};
                super::check_unknown(obj,&["loader",key],"leaf certificate loader")?;
                if let Some(items)=obj.get(key).filter(|v|!v.is_null()){
                    let items=super::require_array(items,"leaf certificate input")?;ensure!(items.len()<=256,"too many leaf inputs");
                    for(ii,item)in items.iter().enumerate(){let value=super::require_string(item,"leaf certificate input")?;super::check_len(value,4096,"leaf certificate input")?;f(Spec{group:gi,loader:li,item:ii,file},value)?;}
                }
            }
        }
    }Ok(())
}
fn raw_at(raw:&ClientAuth,spec:Spec)->Result<&str>{
    raw.verifiers.get(spec.group).and_then(|v|v.get("leaf_certs_loaders")).and_then(|v|v.get(spec.loader)).and_then(|v|v.get(if spec.file{"files"}else{"certificates"})).and_then(|v|v.get(spec.item)).and_then(Value::as_str).ok_or_else(||anyhow::anyhow!("leaf input topology changed"))
}
enum Source{Inline(crate::tls_app_config::leaf_values::Expanded),File{bytes:Zeroizing<Vec<u8>>,_credit:crate::acme_wire::chain_memory::Scratch}}
impl Source{fn bytes(&self)->&[u8]{match self{Self::Inline(v)=>v.as_bytes(),Self::File{bytes,..}=>bytes}}}
fn load(raw:&str,file:bool,cwd:&Path,cancel:&CancellationToken)->Result<Source>{
    let value=crate::tls_app_config::leaf_values::expand(raw,cwd,cancel)?;
    if !file{return Ok(Source::Inline(value))}
    let mut f=crate::tls_app_config::leaf_values::open(value.as_bytes(),cwd)?;
    let n=usize::try_from(f.metadata()?.len()).map_err(|_|ResourceDenied)?;ensure!(n<=LIMIT,"leaf certificate file exceeds limit");
    let credit=cert_transient::reserve(n.checked_add(1).ok_or(ResourceDenied)?)?;
    let mut bytes=Zeroizing::new(Vec::new());bytes.try_reserve_exact(n)?;bytes.resize(n,0);f.read_exact(&mut bytes)?;
    let mut extra=[0u8;1];ensure!(f.read(&mut extra)?==0,"leaf certificate file changed during read");
    ensure!(!cancel.is_cancelled(),"leaf input preparation cancelled");
    Ok(Source::File{bytes,_credit:credit})
}
struct LoadJob{entry:Arc<AuthEntry>,spec:Spec,cwd:Arc<PathBuf>}
impl LoadJob{fn execute(self,cancel:&CancellationToken)->Result<Source>{load(raw_at(self.entry.raw(),self.spec)?,self.spec.file,&self.cwd,cancel)}}
struct ParseJob{data:LeafData,spec:Spec,source:Source}
impl ParseJob{fn execute(self,cancel:&CancellationToken)->Result<LeafData>{self.data.consume(self.spec,self.source,cancel)}}
pub(crate) async fn prepare(entry:Arc<AuthEntry>,cwd:PathBuf,io:Arc<Semaphore>,cpu:Arc<Semaphore>,budget:AuthBudget,cancel:CancellationToken)->Result<LeafData>{
    let e=entry.clone();let b=budget.clone();
    let(mut data,specs,_index)=crate::cert_cpu::run(cpu.clone(),cancel.clone(),move||{
        let mut count=0usize;each(e.raw(),|_,_|{count=count.checked_add(1).ok_or(ResourceDenied)?;Ok(())})?;
        let index=b.reserve_buffer(count.checked_mul(std::mem::size_of::<Spec>()).and_then(|n|n.checked_add(1024)).ok_or(ResourceDenied)?)?;
        let mut specs=Vec::new();specs.try_reserve_exact(count)?;each(e.raw(),|s,_|{specs.push(s);Ok(())})?;
        Ok((LeafData::new(e.raw(),&b)?,specs,index))
    }).await?;
    let cwd=Arc::new(cwd);
    for spec in specs{
        let job=LoadJob{entry:entry.clone(),spec,cwd:cwd.clone()};let token=cancel.clone();
        let source=crate::cert_cpu::run(io.clone(),cancel.clone(),move||job.execute(&token)).await?;
        let job=ParseJob{data,spec,source};let token=cancel.clone();
        data=crate::cert_cpu::run(cpu.clone(),CancellationToken::new(),move||job.execute(&token)).await?;
    }Ok(data)
}
pub(super) fn prepare_sync(raw:&ClientAuth)->Result<LeafData>{
    let budget=AuthBudget::standalone();let mut data=Some(LeafData::new(raw,&budget)?);let cwd=std::env::current_dir()?;let token=CancellationToken::new();
    each(raw,|spec,value|{let source=load(value,spec.file,&cwd,&token)?;data=Some(data.take().expect("leaf state").consume(spec,source,&token)?);Ok(())})?;
    Ok(data.expect("leaf state"))
}
