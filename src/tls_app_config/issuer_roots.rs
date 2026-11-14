//! Caddy ACME explicit custom roots: Provision once, retain exact accepted input.
//! Public WireOptions keeps its additive contract; this is a private policy.
use super::{model::{CertificatePlan,Issuer},services::PrepareContext};
use crate::tls_policy::prepared_auth::{AuthBudget,BufferCredit};
use crate::cert_transient::ResourceDenied;
use anyhow::{Result,ensure,anyhow};
use std::{path::PathBuf,sync::Arc};
use rustls::pki_types::CertificateDer;
use tokio::sync::OnceCell;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;
use sha2::{Digest,Sha256};
pub(crate) struct Input{paths:Vec<PathBuf>,id:[u8;32],ready:OnceCell<Option<Arc<CustomRoots>>>}
pub(crate) struct CustomRoots{certs:Vec<CertificateDer<'static>>,pems:Vec<Zeroizing<Vec<u8>>>,_credit:BufferCredit}
impl CustomRoots{
    pub(crate) fn certificates(&self)->&[CertificateDer<'static>]{&self.certs}
    /// The original PEM identity copy and destination Vec growth coexist
    /// with the retained ready source; admit them before any Group clone.
    pub(super) fn identity_copy_upper(&self,existing:usize)->Result<usize>{
        let count=existing.checked_add(self.pems.len()).ok_or(ResourceDenied)?;
        ensure!(count<=32,"ACME trust configuration exceeds bounds");
        let metadata=count.checked_mul(2).and_then(|n|n.checked_add(existing))
            .and_then(|n|n.checked_mul(std::mem::size_of::<Vec<u8>>()))
            .and_then(|n|n.checked_add(512)).ok_or(ResourceDenied)?;
        self.pems.iter().try_fold(metadata,|n,pem|n.checked_add(pem.len()).ok_or(ResourceDenied)).map_err(Into::into)
    }
    pub(super) fn append_identity_pems(&self,out:&mut Vec<Vec<u8>>,credit:&crate::acme_wire::chain_memory::Scratch)->Result<()>{
        ensure!(credit.bytes()>=self.identity_copy_upper(out.len())?,ResourceDenied);
        out.try_reserve_exact(self.pems.len())?;for pem in &self.pems{out.push(pem.to_vec());}Ok(())
    }
    fn retained(&self)->Result<usize>{
        let n=self.certs.capacity().checked_mul(std::mem::size_of::<CertificateDer>()).and_then(|n|self.pems.capacity().checked_mul(std::mem::size_of::<Zeroizing<Vec<u8>>>()).and_then(|m|n.checked_add(m))).and_then(|n|n.checked_add(1024)).ok_or(ResourceDenied)?;
        self.certs.iter().map(|v|v.len()).chain(self.pems.iter().map(|v|v.capacity())).try_fold(n,|n,b|n.checked_add(b.checked_mul(2).ok_or(ResourceDenied)?).ok_or(ResourceDenied)).map_err(Into::into)
    }
}
impl Input{
    pub(super) fn new(paths:Vec<PathBuf>)->Result<Arc<Self>>{
        ensure!(paths.len()<=32,"ACME trust configuration exceeds bounds");let mut hash=Sha256::new();hash.update(b"acme-custom-roots-v1");hash.update((paths.len()as u64).to_be_bytes());
        for p in &paths{let b=p.as_os_str().as_encoded_bytes();hash.update((b.len()as u64).to_be_bytes());hash.update(b);}
        Ok(Arc::new(Self{paths,id:hash.finalize().into(),ready:OnceCell::new()}))
    }
    pub(super) fn empty()->Arc<Self>{static EMPTY:std::sync::OnceLock<Arc<Input>>=std::sync::OnceLock::new();EMPTY.get_or_init(||{let v=Self::new(Vec::new()).expect("empty root input");v.ready.set(None).ok();v}).clone()}
    pub(super) fn get(&self)->Result<Option<Arc<CustomRoots>>>{self.ready.get().cloned().ok_or_else(||anyhow!("ACME roots are not prepared"))}
    async fn prepare(self:&Arc<Self>,context:&PrepareContext,cancel:CancellationToken)->Result<()>{
        self.ready.get_or_try_init(||async{
            if self.paths.is_empty(){return Ok::<_,anyhow::Error>(None)}
            let budget=AuthBudget::Root(context.resources.external_bytes.clone());
            let n=self.paths.len();let credit=budget.reserve_buffer(n.checked_mul(std::mem::size_of::<CertificateDer>()+std::mem::size_of::<Zeroizing<Vec<u8>>>()).and_then(|n|n.checked_add(2048)).ok_or(ResourceDenied)?)?;
            let mut state=CustomRoots{certs:Vec::new(),pems:Vec::new(),_credit:credit};state.pems.try_reserve_exact(n)?;
            for path in &self.paths{
                let path=super::storage::absolute(&context.paths.cwd,path);
                let (bytes,memory)=super::loaders::blocking(context.resources.io.clone(),cancel.clone(),move||super::loaders::read_root_input(&path)).await?;
                let bytes=Zeroizing::new(bytes);let token=cancel.clone();
                // Actual source credit is inside the consuming worker, not the await.
                let job=RootJob{state,bytes,_source:memory};
                state=crate::cert_cpu::run(context.resources.cpu.clone(),CancellationToken::new(),move||job.execute(&token)).await?;
            }
            Ok(Some(Arc::new(state)))
        }).await?;Ok(())
    }
}
struct RootJob{state:CustomRoots,bytes:Zeroizing<Vec<u8>>,_source:crate::acme_wire::chain_memory::Scratch}
impl RootJob{fn execute(mut self,cancel:&CancellationToken)->Result<CustomRoots>{
    ensure!(!cancel.is_cancelled(),"ACME root preparation cancelled");ensure!(self.bytes.len()<=1<<20,"ACME trust root exceeds bounds");
    let working=self.state.retained()?.checked_add(self.bytes.len().checked_mul(6).ok_or(ResourceDenied)?).and_then(|n|n.checked_add(64<<10)).ok_or(ResourceDenied)?;self.state._credit.resize(working)?;
    let parsed=crate::tls_policy::source_append_certificates(&self.bytes)?;
    let mut valid=0usize;
    for cert in parsed{if rustls::RootCertStore::empty().add(cert.clone()).is_ok(){self.state.certs.try_reserve(1)?;self.state.certs.push(cert);valid+=1;}}
    ensure!(valid>0,"ACME custom root file has no usable certificates");
    self.state.pems.push(self.bytes);self.state._credit.resize(self.state.retained()?)?;Ok(self.state)
}}
#[derive(Clone,Copy,PartialEq,Eq)]
struct Key{identity:bool,policy:usize,issuer:usize,id:[u8;32]}
struct Slot{key:Key,value:Option<Arc<CustomRoots>>}
pub(super) struct Retained{slots:Vec<Slot>,_credit:BufferCredit}
fn each(plan:&CertificatePlan,mut f:impl FnMut(Key,&Arc<Input>)->Result<()>)->Result<()>{
    for(pi,p)in plan.policies.iter().enumerate(){for(ii,i)in p.issuers.iter().enumerate(){if let Issuer::Acme(a)=i{f(Key{identity:false,policy:pi,issuer:ii,id:a.roots.id},&a.roots)?;}}}
    if let Some(p)=&plan.identity{for(ii,i)in p.issuers.iter().enumerate(){if let Issuer::Acme(a)=i{f(Key{identity:true,policy:0,issuer:ii,id:a.roots.id},&a.roots)?;}}}Ok(())
}
pub(super) async fn prepare_all(plan:&CertificatePlan,context:&PrepareContext,cancel:CancellationToken)->Result<()>{
    // Traverse the complete original issuer topology. Internal issuers do not
    // shift a retained ACME slot's original ordinal.
    for p in &plan.policies{for i in &p.issuers{if let Issuer::Acme(a)=i{a.roots.prepare(context,cancel.clone()).await?;}}}
    if let Some(p)=&plan.identity{for i in &p.issuers{if let Issuer::Acme(a)=i{a.roots.prepare(context,cancel.clone()).await?;}}}Ok(())
}
pub(super) fn retain(plan:&CertificatePlan,budget:&AuthBudget)->Result<Arc<Retained>>{
    let mut count=0usize;each(plan,|_,_|{count=count.checked_add(1).ok_or(ResourceDenied)?;Ok(())})?;
    let credit=budget.reserve_buffer(count.checked_mul(std::mem::size_of::<Slot>()).and_then(|n|n.checked_add(1024)).ok_or(ResourceDenied)?)?;
    let mut slots=Vec::new();slots.try_reserve_exact(count)?;each(plan,|key,input|{slots.push(Slot{key,value:input.get()?});Ok(())})?;Ok(Arc::new(Retained{slots,_credit:credit}))
}
pub(super) fn restore(plan:&CertificatePlan,saved:&Retained)->Result<()>{
    let mut slots=saved.slots.iter();each(plan,|key,input|{let slot=slots.next().ok_or_else(||anyhow!("retained ACME root slot missing"))?;ensure!(slot.key==key,"retained ACME root topology differs");if let Some(old)=input.ready.get(){ensure!(match(old,&slot.value){(None,None)=>true,(Some(a),Some(b))=>Arc::ptr_eq(a,b),_=>false},"ACME root ready state differs");}Ok(())})?;ensure!(slots.next().is_none(),"retained ACME root slot extra");
    let mut slots=saved.slots.iter();each(plan,|_,input|{let slot=slots.next().expect("validated root slot");if input.ready.get().is_none(){input.ready.set(slot.value.clone()).map_err(|_|anyhow!("ACME root restore raced"))?;}Ok(())})
}
