//! Closed owned handoff between ACME validation and production publication.
//! Moving the candidate copies no PEM/key payload. Retention fields outlive the
//! actual bundle, job and proofs on success, error and future cancellation.
use super::*;
#[derive(Clone,Copy,Debug,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="snake_case")]
pub(super) enum AcmePurpose {Primary,Probe}

pub(super) enum AcmeCandidate {
    Stored {purpose:AcmePurpose,bundle:OwnedCertificateBundle,info:Option<MaterialInfo>,id:String,issuer_name:String,
        _input:Option<Arc<attempt::RuntimeInput>>,_key:Option<Arc<crate::key_compromise::KeyState>>,_memory:crate::acme_wire::chain_memory::Scratch},
    Downloaded {purpose:AcmePurpose,bundle:DownloadedBundle,info:Option<MaterialInfo>,job:Job,id:String,issuer_name:String,
        _proofs:Vec<ChallengeLease>,_input:Option<Arc<attempt::RuntimeInput>>,_key:Option<Arc<crate::key_compromise::KeyState>>,
        _memory:crate::acme_wire::chain_memory::Scratch},
}
impl AcmeCandidate {
    pub(super) fn purpose(&self)->AcmePurpose {match self {Self::Stored{purpose,..}|Self::Downloaded{purpose,..}=>*purpose}}
}
impl CertificateManager {
    pub(super) async fn commit_primary_candidate(&self,names:&[String],issuer:&IssuerState,
        lease:&StorageLease,attempt_id:&str,lifecycle:&crate::cert_events::Attempt,
        cancel:&CancellationToken,input:Option<&Arc<attempt::RuntimeInput>>,
        produced:Option<&std::sync::atomic::AtomicBool>,candidate:AcmeCandidate)->Result<ManagedCertificate> {
        ensure!(candidate.purpose()==AcmePurpose::Primary,"probe candidate cannot enter production commit");
        let mut candidate=candidate;
        // Borrow the complete owner rather than destructuring retention fields:
        // candidate field order retires real payload/proofs before its credits.
        match &mut candidate {
            AcmeCandidate::Stored{bundle,info,id,issuer_name,..}=>{
                let facts=info.as_ref().ok_or_else(||anyhow!("ACME stored candidate facts missing"))?;
                ensure!(self.claim_winner(names,attempt_id,id,issuer_name,&facts.leaf_sha256,lease).await?,
                    "certificate attempt lost publication CAS");
                self.publish(names,bundle,cancel).await?;
                self.managed(names,issuer_name,bundle,info.take().ok_or_else(||anyhow!("ACME stored candidate facts missing"))?,false)
            },
            AcmeCandidate::Downloaded{bundle,info,job,id,issuer_name,..}=>{
                let wire=issuer.wire.get().ok_or_else(||anyhow!("ACME wire missing at candidate commit"))?;
                let has_known_order=job.order_url.is_some();
                let operation=async {
                    let facts=info.as_ref().ok_or_else(||anyhow!("ACME downloaded candidate facts missing"))?;
                    if let Some(produced)=produced{produced.store(true,Ordering::Release);}
                    if let Some(cert_id)=self.certificate_id(&bundle.chain_pem,cancel).await?
                        &&let Ok(Some(ari))=wire.renewal_info(&cert_id,cancel).await {
                        bundle.update_ari(&ari,facts,self.inner.options.renewal_window_ratio)?;
                    }
                    job.stored_leaf_sha256=Some(facts.leaf_sha256.clone());job.phase="store_intent".to_owned();self.save_job(id,job,lease).await?;
                    if let Some(input)=input {self.require_active_backend(names,attempt_id,id,
                        self.issuer_identity(issuer)?,&input.binding,lease).await?;}
                    lease.check().await?;self.save_issued_certificate(issuer_name,&names_key(names)?,bundle,lease,job.initial_key_hash.as_deref()).await?;
                    lifecycle.obtained(self.inner.lifecycle_events.as_ref(),issuer_name,names,&job.csr_der,cancel).await;
                    job.phase="stored".to_owned();job.private_key_pem.zeroize();job.downloaded_pem=None;job.csr_der.clear();self.save_job(id,job,lease).await?;
                    ensure!(self.claim_winner(names,attempt_id,id,issuer_name,&facts.leaf_sha256,lease).await?,"certificate attempt lost publication CAS");
                    self.publish(names,bundle,cancel).await?;
                    self.managed(names,issuer_name,bundle,info.take().ok_or_else(||anyhow!("ACME downloaded candidate facts missing"))?,true)
                }.await;
                operation.map_err(|error|if has_known_order{ActiveOrderError(error).into()}else{error})
            },
        }
    }
}
