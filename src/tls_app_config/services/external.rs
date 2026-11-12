//! A private resolver per external-manager handshake. It never contributes
//! aliases to the automated resident cache and cannot authorize issuance.
use super::*;
use crate::http_runtime::{AcquiredCertificate, CertificateHello, TransientCertificate};
// Reserve before any untrusted response or parser allocation. The conservative
// working set includes the PEM input, decoded copies, signing profiles, names,
// resolver snapshot, OCSP state and task metadata. Shared across generations.
const WORKING_BYTES: u32 = 64 * 1024 * 1024;
impl CertificateServices {
    pub(super) async fn acquire_external(
        self: &Arc<Self>,
        policy: Policy,
        subject: String,
        hello: CertificateHello,
        selection: Option<crate::http_runtime::WarmSelection>,
        caller: CancellationToken,
    ) -> Result<Option<AcquiredCertificate>> {
        let waiter = self.on_demand.external_waiter()?;
        let operation = caller.child_token();
        let deadline = operation.clone();
        let timer = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(120)).await;
            deadline.cancel();
        }));
        let result=self.owned(operation,move|this,cancel|Box::pin(async move {
            let _waiter=waiter;
            let reservation=tokio::select! {biased;
                _=cancel.cancelled()=>anyhow::bail!("external certificate acquisition cancelled"),
                permit=this.context.resources.external_bytes.clone().acquire_many_owned(WORKING_BYTES)=>
                    permit.map_err(|_|anyhow!("external certificate memory capacity unavailable"))?,
            };
            let mut last_error=None;
            let mut selected=None;
            for manager in &policy.managers {
                match manager.fetch(&hello,&this.context.resources.issuance,cancel.clone()).await {
                    Ok(Some(value))=>{
                        let parsed=crate::cert_cpu::run(this.context.resources.cpu.clone(),cancel.clone(),move||{
                            let (certificate,key)=super::super::external::split_bundle(value)?;
                            Ok(Arc::new(Material::from_pem(certificate,key)?))
                        }).await;
                        match parsed {Ok(material)=>{selected=Some(material);last_error=None;break;},
                            Err(error)=>last_error=Some(error)}
                    },
                    Ok(None)=>last_error=None,
                    Err(error)=>last_error=Some(error),
                }
                ensure!(!cancel.is_cancelled(),"external certificate acquisition cancelled");
            }
            if let Some(error)=last_error {return Err(error);}
            let Some(material)=selected else{return Ok(None);};
            let guard=this.context.leaf_guard.clone();
            let challenges=this.context.challenges.clone();
            let token=cancel.clone();
            let (resolver,receipt,slot,material)=crate::cert_cpu::run(this.context.resources.cpu.clone(),cancel.clone(),move||{
                material.validate_at(now()?,false)?;
                ensure!(material.names.len()<=4096 && material.retained_san_bytes()<=2*1024*1024,
                    "external certificate SAN memory limit exceeded");
                material.register_key(guard.key_deny())?;
                reject_revoked(&material,&guard,true)?;
                let resolver=Arc::new(HotCertificateResolver::with_leaf_guard(challenges,guard));
                let scope=CertificateScope::new();let slot=Arc::new(CertificateResidency::default());
                let input=CertificateInput{names:&material.names,certificate_pem:&material.certificate,private_key_pem:&material.key};
                if let Some(selection)=&selection {
                    ensure!(resolver.candidate_allowed(&input,&[],None,
                        &selection.schemes,selection.version)?,"external certificate incompatible with TLS policy");
                }
                let receipt=resolver.upsert_resident(&input,&scope,&slot,&token,||Ok(()))?;
                Ok((resolver,receipt,slot,material))
            }).await?;
            // Retain only a conservative actual-size reservation after parsing.
            // Names, profiles and map/task overhead are charged independently
            // of DER length, so many tiny SAN labels cannot evade the pool.
            let names_cost=material.names.iter().map(|s|s.capacity()+512).sum::<usize>();
            let retained=(material.certificate.len()+material.key.len()).saturating_mul(32)
                .saturating_add(names_cost.saturating_mul(16)).saturating_add(512*1024);
            ensure!(retained<=WORKING_BYTES as usize,"external certificate retained memory capacity exceeded");
            let mut reservation=reservation;
            let unused=reservation.num_permits()-retained;
            drop(reservation.split(unused));
            let reservation=Arc::new(reservation);
            let lifetime=this.context.cancel.child_token();
            let external=Arc::new(TransientCertificate{resolver:resolver.clone(),cancel:lifetime.clone(),reservation});
            if !this.plan.disable_ocsp && !policy.disable_ocsp {
                let root=policy.storage.as_ref().or(this.plan.storage.as_ref())
                    .unwrap_or(&this.context.paths.default_storage).clone();
                let store=this.context.resources.store(root,&this.context.paths,cancel.clone()).await?;
                let overrides=policy.ocsp_overrides.into_iter().collect::<HashMap<_,_>>();
                let (max_concurrent,max_concurrent_per_responder)=this.context.resources.ocsp.limits();
                let manager=OcspManager::with_resources_and_inventory_cpu(store.fs.clone(),resolver.clone(),
                    OcspOptions{check_interval:this.plan.ocsp_interval,max_concurrent,max_concurrent_per_responder,..OcspOptions::default()},
                    Arc::new(move |_|Ok(OcspConfig{responder_overrides:overrides.clone(),..OcspConfig::default()})),
                    Arc::new(|_|true),this.context.resources.ocsp.clone(),this.context.resources.cpu.clone())?;
                let cert=resolver.ocsp_certificates()?.into_iter().next().ok_or_else(||anyhow!("external certificate status instance missing"))?;
                manager.prime_cached_one(cert,cancel.clone()).await?;
                reject_revoked(&material,&this.context.leaf_guard,true)?;
                // The runner owns its byte reservation until cancelled jobs
                // have joined. It does not own the connection lease itself.
                let charge=external.reservation.clone();let resources=this.context.resources.clone();
                let runner_cancel=lifetime.clone();
                let _admission=this.admission.lock().map_err(|_|anyhow!("certificate service admission unavailable"))?;
                ensure!(!this.context.cancel.is_cancelled(),"certificate services stopped");
                this.tasks.spawn(async move {
                    let _charge=charge;
                    let mut events=manager.subscribe();
                    let running=manager.run(runner_cancel);
                    tokio::pin!(running);
                    loop {tokio::select! {biased;
                        result=&mut running=>{let _=result;break;},
                        event=events.recv()=>match event {
                            Ok(event) if event.status.as_ref().is_some_and(|status|status.state==OcspState::Revoked)=>resources.revoked.notify_waiters(),
                            Err(broadcast::error::RecvError::Lagged(_))=>resources.revoked.notify_waiters(),
                            Err(broadcast::error::RecvError::Closed)=>{let _=running.await;break;},
                            _=>{},
                        }
                    }}
                    resources.revoked.notify_waiters();
                });
            }
            ensure!(!cancel.is_cancelled(),"external certificate acquisition cancelled");
            Ok(Some(AcquiredCertificate{subject,receipt,slot,external:Some(external)}))
        })).await;
        timer.abort();
        let _ = timer.await;
        result
    }
}
