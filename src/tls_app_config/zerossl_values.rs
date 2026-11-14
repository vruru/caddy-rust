//! Accepted ZeroSSL credentials are retained by occurrence, including identity.
use super::{model::{CertificatePlan,Issuer},zerossl_settings::{Input,Prepared}};
use anyhow::{Result,ensure};
use std::sync::Arc;
use crate::acme_wire::chain_memory::{Pool,Lease};

fn inputs(plan:&CertificatePlan)->impl Iterator<Item=&Arc<Input>> {
    plan.policies.iter().flat_map(|p|p.issuers.iter())
        .chain(plan.identity.iter().flat_map(|p|p.issuers.iter()))
        .filter_map(|i|match i{Issuer::ZeroSsl(input)=>Some(input),_=>None})
}
pub(super) async fn prepare(plan:&CertificatePlan,io:Arc<tokio::sync::Semaphore>,pool:Arc<Pool>,cwd:&std::path::Path,cancel:tokio_util::sync::CancellationToken)->Result<()> {
    if inputs(plan).next().is_none(){return Ok(())}
    let cwd=super::manual_values::cwd(cwd)?;
    // Provider reads use the existing IO lane; no CPU permit waits on files.
    // Serial preparation adds no new concurrency or budget pool.
    for input in inputs(plan){input.prepare_in_pool(io.clone(),pool.clone(),cwd.clone(),cancel.clone()).await?;}
    Ok(())
}
struct Saved {id:[u8;32],value:Arc<Prepared>}
pub(super) struct Retained {values:Vec<Saved>,_memory:Lease}
pub(super) fn retain(plan:&CertificatePlan,pool:&Arc<Pool>)->Result<Option<Arc<Retained>>> {
    let count=inputs(plan).count();if count==0{return Ok(None)}
    let bytes=count.checked_mul(std::mem::size_of::<Saved>()).and_then(|n|n.checked_add(std::mem::size_of::<Retained>()+256))
        .ok_or(crate::cert_transient::ResourceDenied)?;
    let memory=pool.reserve(bytes)?;let mut values=Vec::new();values.try_reserve_exact(count).map_err(|_|crate::cert_transient::ResourceDenied)?;
    for input in inputs(plan){values.push(Saved{id:input.id(),value:input.get()?});}
    Ok(Some(Arc::new(Retained{values,_memory:memory})))
}
pub(super) fn restore(plan:&CertificatePlan,retained:Option<&Retained>)->Result<()> {
    let values=retained.map_or(&[][..],|r|r.values.as_slice());
    ensure!(inputs(plan).count()==values.len(),"retained ZeroSSL issuer count changed");
    // Validate the whole occurrence list before installing any capability.
    for(input,saved)in inputs(plan).zip(values){ensure!(input.id()==saved.id,"retained ZeroSSL issuer identity changed");}
    for(input,saved)in inputs(plan).zip(values){input.restore(saved.id,saved.value.clone())?;}
    Ok(())
}
