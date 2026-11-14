//! Independent ZeroSSL REST leg under the manager's shared input and winner CAS.
use super::*;
use super::attempt::RuntimeInput;
use super::zerossl_record::{Leg,Phase,ValidationProof};
use crate::zerossl_wire::{Wire,models::CertId};

pub(crate) type HttpPreparation=Arc<dyn Fn(CancellationToken)->futures_util::future::BoxFuture<'static,Result<()>>+Send+Sync>;
pub(super) struct State {
    pub settings:Arc<crate::tls_app_config::zerossl_settings::Prepared>,
    pub prepare:Option<HttpPreparation>,
    pub wire:OnceCell<Wire>,
    pub limiter:Arc<Semaphore>,
}
#[derive(Debug)]
pub(super) struct CreateUncertain;
impl std::fmt::Display for CreateUncertain {fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{f.write_str("ZeroSSL create result is uncertain; original certificate ID is required before recovery")}}
impl std::error::Error for CreateUncertain{}
#[derive(Debug)]
pub(super) struct IssuedCandidate;
impl std::fmt::Display for IssuedCandidate {fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{f.write_str("ZeroSSL issued candidate must recover its original certificate ID")}}
impl std::error::Error for IssuedCandidate{}
#[derive(Debug)]
pub(super) struct ClosedLeg;
impl std::fmt::Display for ClosedLeg {fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{f.write_str("ZeroSSL certificate leg is definitively closed")}}
impl std::error::Error for ClosedLeg{}

pub(super) fn backend_identity(settings:&crate::tls_app_config::zerossl_settings::Prepared,key_type:KeyType,must_staple:bool,reuse:bool)->Result<attempt::BackendId>{
    let mut hash=Sha256::new();hash.update(b"zerossl-backend-v1\0");hash.update(settings.identity().as_bytes());
    hash.update(serde_json::to_vec(&(key_type,must_staple,reuse))?);
    Ok(attempt::BackendId::ZeroSsl{config_identity:format!("{:x}",hash.finalize())})
}
pub(super) fn leg_id(attempt_id:&str,backend:&attempt::BackendId)->Result<String>{
    let attempt::BackendId::ZeroSsl{config_identity}=backend else{bail!("ZeroSSL backend identity mismatch")};
    Ok(digest(format!("zerossl-v1\0{attempt_id}\0{config_identity}").as_bytes()))
}
fn csr(input:&RuntimeInput,must_staple:bool)->Result<Vec<u8>> {
    use rcgen::{PublicKeyData,SigningKey};
    use der::{Decode,Encode};
    let common=input.record.names.iter().position(|n|n.len()<=64)
        .ok_or_else(||anyhow!("ZeroSSL requires a CommonName within 64 bytes"))?;
    let mut names=input.record.names.clone();let common=names.remove(common);
    let mut params=rcgen::CertificateParams::new(names).map_err(|_|anyhow!("invalid ZeroSSL CSR names"))?;
    params.distinguished_name=rcgen::DistinguishedName::new();
    params.distinguished_name.push(rcgen::DnType::CommonName,common);
    if must_staple{params.custom_extensions.push(rcgen::CustomExtension::from_oid_content(&[1,3,6,1,5,5,7,1,24],vec![0x30,0x03,0x02,0x01,0x05]));}
    let signer=crate::crypto::x509_signer::X509Signer::from_private_key(input.record.private_key_pem.as_bytes())?;
    ensure!(signer.subject_public_key_info()==input.record.spki_der,"ZeroSSL CSR public key changed");
    let encoded=params.serialize_request(&signer).map_err(|_|anyhow!("ZeroSSL CSR signing failed"))?.der().to_vec();
    let mut request=x509_cert::request::CertReq::from_der(&encoded)?;
    if request.info.public_key.to_der()?!=input.record.spki_der {
        request.info.public_key=x509_cert::spki::SubjectPublicKeyInfoOwned::from_der(&input.record.spki_der)?;
        request.signature=der::asn1::BitString::new(0,signer.sign(&request.info.to_der()?).map_err(|_|anyhow!("ZeroSSL CSR SPKI signature failed"))?)?;
    }
    request.to_der().map_err(Into::into)
}
fn validate_csr(leg:&Leg,input:&RuntimeInput)->Result<Vec<String>> {
    use x509_parser::prelude::FromDer;
    let _ast=crate::cert_transient::reserve(crate::acme_wire::chain_deep_shape::csr_cost(&leg.csr_der)?)?;
    let(tail,csr)=x509_parser::certification_request::X509CertificationRequest::from_der(&leg.csr_der)
        .map_err(|_|anyhow!("invalid ZeroSSL persisted CSR"))?;
    ensure!(tail.is_empty()&&csr.certification_request_info.subject_pki.raw==input.record.spki_der,"ZeroSSL persisted CSR key changed");
    crate::cert_status::verify_x509_signature(&csr.certification_request_info.subject_pki,&csr.signature_algorithm,&csr.signature_value.data,csr.certification_request_info.raw,true)?;
    let mut names=Vec::new();
    let common=csr.certification_request_info.subject.iter_common_name().next()
        .and_then(|n|n.as_str().ok()).ok_or_else(||anyhow!("ZeroSSL CSR CommonName missing"))?;
    ensure!(!common.is_empty()&&common.len()<=64,"invalid ZeroSSL CSR CommonName");names.push(common.to_owned());
    let mut ips=Vec::new();
    for attribute in csr.certification_request_info.iter_attributes(){
        if let x509_parser::cri_attributes::ParsedCriAttribute::ExtensionRequest(request)=attribute.parsed_attribute(){
            for extension in &request.extensions {if let x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san)=extension.parsed_extension(){
                for name in &san.general_names {ensure!(names.len()+ips.len()<100,"ZeroSSL CSR SAN limit");match name {
                    x509_parser::extensions::GeneralName::DNSName(v)=>names.push((*v).to_owned()),
                    x509_parser::extensions::GeneralName::IPAddress(v) if v.len()==4=>ips.push(std::net::Ipv4Addr::new(v[0],v[1],v[2],v[3]).to_string()),
                    x509_parser::extensions::GeneralName::IPAddress(v) if v.len()==16=>ips.push(crate::tls_resolver::canonical_certificate_ip(std::net::IpAddr::V6(std::net::Ipv6Addr::from(<[u8;16]>::try_from(*v)?)))),
                    _=>bail!("ZeroSSL CSR contains unsupported subject type"),
                }}
            }}
        }
    }
    names.extend(ips);let mut set=names.clone();set.sort();set.dedup();
    ensure!(set==input.record.names&&set.len()==names.len(),"ZeroSSL CSR subject scope changed");
    Ok(names)
}
struct CreateJob {
    csr:Vec<u8>,names:Vec<String>,validity:i64,_memory:crate::acme_wire::chain_memory::Scratch,
}
impl CreateJob {
    fn copy(leg:&Leg,names:&[String],validity:i64)->Result<Self>{
        let bytes=names.iter().try_fold(16384usize,|n,s|s.len().checked_mul(2).and_then(|b|n.checked_add(b)).ok_or(crate::cert_transient::ResourceDenied))?
            .checked_add(names.len().checked_mul(std::mem::size_of::<String>()).ok_or(crate::cert_transient::ResourceDenied)?)
            .and_then(|n|leg.csr_der.len().checked_mul(3).and_then(|b|n.checked_add(b))).ok_or(crate::cert_transient::ResourceDenied)?;
        let memory=crate::cert_transient::reserve(bytes)?;
        Ok(Self{csr:leg.csr_der.clone(),names:names.to_vec(),validity,_memory:memory})
    }
    fn execute(self)->Result<crate::zerossl_wire::CreateInput>{
        let csr=pem::encode(&pem::Pem::new("CERTIFICATE REQUEST",self.csr));
        crate::zerossl_wire::CreateInput::copy(&self.names.join(","),&csr,self.validity)
    }
}
impl CertificateManager {
    /// Only ZeroSSL's definite non-order/closed states permit replacing a
    /// changed configuration. Unknown/created/issued orders keep the old fence.
    pub(super) async fn closed_zero_configuration(&self,state:&Attempt)->Result<bool>{
        if state.winner.is_some()||state.retired||state.acme_phase.is_some()
            ||state.backend_sequence.is_empty()||state.configured_sequence.is_empty()||!state.backend_sequence.iter().chain(&state.configured_sequence).all(|b|matches!(b,attempt::BackendId::ZeroSsl{..})){return Ok(false)}
        let current=match (&state.current_backend,&state.current_job_id,&state.current_input){
            (None,None,None)=>None,
            (Some(backend),Some(job),Some(_))=>{
                if leg_id(&state.attempt_id,backend)?!=*job{return Ok(false)}
                Some(state.backend_sequence.iter().position(|b|b==backend).ok_or_else(||anyhow!("closed ZeroSSL backend is outside its attempt"))?)
            },
            _=>return Ok(false),
        };
        for(index,backend)in state.backend_sequence.iter().enumerate(){
            let id=leg_id(&state.attempt_id,backend)?;
            match self.load_zero(&id).await?{
                None if current.is_some_and(|rank|index<=rank)=>return Ok(false),
                None=>{},
                Some(leg)=>{
                    ensure!(leg.attempt_id==state.attempt_id&&leg.names==state.names&&&leg.backend==backend,"closed ZeroSSL leg identity changed");
                    let attempt::InputBinding::Shared{input_id,..}=&leg.input else{return Ok(false)};
                    ensure!(state.input_id.as_ref()==Some(input_id),"closed ZeroSSL input binding changed");
                    if let Some(input)=&state.current_input{ensure!(&leg.input==input,"closed ZeroSSL shared input changed");}
                    if !matches!(leg.phase,Phase::Prepared|Phase::CreateRejected|Phase::Cancelled){return Ok(false)}
                },
            }
        }
        Ok(true)
    }
    pub(super) async fn archive_closed_zero(&self,state:Attempt,lease:&StorageLease,cancel:&CancellationToken)->Result<()>{
        let id=format!("closed-zero-attempt-v1-{}",state.attempt_id);let name=lease.name().to_owned();
        let encoded=self.cpu(cancel,move||job_codec::encode_record(&state,&name)).await?;
        self.inner.store.journal_store_encoded_fenced(&id,encoded,lease).await
    }
    pub(super) async fn zero_wire<'a>(&self,state:&'a State,cancel:&CancellationToken)->Result<&'a Wire>{
        state.wire.get_or_try_init(||Wire::connect(state.settings.clone(),self.inner.local.clone(),
            #[cfg(feature="native-run")] self.inner.outgoing_tls.clone(),self.wire_client_owner(),cancel.clone())).await
    }
    async fn save_zero(&self,id:&str,leg:Leg,lease:&StorageLease,cancel:&CancellationToken)->Result<Leg>{
        let name=lease.name().to_owned();
        let(leg,encoded)=self.cpu(cancel,move||{leg.validate()?;let encoded=job_codec::encode_record(&leg,&name)?;Ok((leg,encoded))}).await?;
        self.inner.store.journal_store_encoded_fenced(id,encoded,lease).await?;Ok(leg)
    }
    pub(super) async fn load_zero(&self,id:&str)->Result<Option<Leg>>{
        self.inner.store.journal_decode_admitted(id,|raw|{
            let memory=Arc::new(job_codec::decode_credit(raw.len())?);
            let mut leg:Leg=serde_json::from_slice(raw).map_err(|_|anyhow!("invalid ZeroSSL leg record"))?;
            leg.validate()?;leg._memory=Some(memory);Ok(leg)
        }).await
    }
    pub(super) async fn issue_zerossl(&self,names:&[String],backend:&backend::Backend,state:&State,
        input:Arc<RuntimeInput>,attempt_id:&str,lease:&StorageLease,lifecycle:&crate::cert_events::Attempt,
        cancel:&CancellationToken,report_obtained:bool,produced:Option<&std::sync::atomic::AtomicBool>)->Result<ManagedCertificate>{
        let id=leg_id(attempt_id,&backend.id)?;let key=names_key(names)?;
        self.inner.store.recover_certificate_with_lease("zerossl",&key,lease).await?;
        let mut leg=if let Some(leg)=self.load_zero(&id).await?{leg}else{
            let memory=Arc::new(crate::acme_wire::chain_memory::scratch(512*1024,cancel.clone()).await?);
            let input=input.clone();let names=names.to_vec();let backend=backend.id.clone();let attempt_id=attempt_id.to_owned();let must_staple=self.inner.must_staple;
            let initial_key_hash=self.initial_key("zerossl",&key,cancel).await?.map(|(snapshot,_)|snapshot.digest().to_owned());
            self.cpu(cancel,move||{let csr_der=csr(&input,must_staple)?;Ok(Leg{version:1,attempt_id,names,backend,input:input.binding.clone(),
                csr_hash:digest(&csr_der),csr_der,phase:Phase::Prepared,certificate:None,validation_proof:None,downloaded_pem:None,stored_leaf_sha256:None,
                initial_key_hash,_memory:Some(memory),_api_memory:None})}).await?
        };
        ensure!(leg.attempt_id==attempt_id&&leg.names==names&&leg.backend==backend.id&&leg.input==input.binding,"ZeroSSL leg binding changed");
        let check_input=input.clone();let(checked,identifiers)=self.cpu(cancel,move||{let names=validate_csr(&leg,&check_input)?;Ok((leg,names))}).await?;leg=checked;
        self.inner.resolver.leaf_guard().key_deny().check_state(&input.key_state)?;
        if leg.phase==Phase::CreateIntent{return Err(CreateUncertain.into())}
        if matches!(leg.phase,Phase::Cancelled|Phase::CreateRejected){return Err(ClosedLeg.into())}
        leg=self.save_zero(&id,leg,lease,cancel).await?;
        self.activate_backend(names,attempt_id,&id,backend.id.clone(),input.binding.clone(),lease).await?;
        if let Some(expected)=leg.stored_leaf_sha256.as_deref()
            &&let Some(bundle)=self.read_issuer_certificate("zerossl",&key,cancel).await?{
            let info=self.inspect_material(&bundle,names,cancel).await?;
            if info.leaf_sha256==expected{
                ensure!(info.spki_der.as_ref()==input.record.spki_der,"stored ZeroSSL public key changed");
                stored_candidate_time(&info)?;self.inner.resolver.leaf_guard().key_deny().check_state(&input.key_state)?;
                ensure!(self.claim_winner(names,attempt_id,&id,"zerossl",expected,lease).await?,"ZeroSSL candidate lost publication CAS");
                return Ok(ManagedCertificate{names:names.to_vec(),issuer_key:"zerossl".to_owned(),not_after_unix:info.not_after,
                    renew_at_unix:backend.renewal(&info,self.inner.options.renewal_window_ratio,None,self.inner.options.poll_interval)?,leaf_sha256:info.leaf_sha256,obtained:false})
            }
        }
        ensure!(leg.phase!=Phase::Stored,"stored ZeroSSL candidate assets changed");
        if leg.phase==Phase::CreateIntent{return Err(CreateUncertain.into())}
        if matches!(leg.phase,Phase::Cancelled|Phase::CreateRejected){return Err(ClosedLeg.into())}
        let _issuer=tokio::select!{biased;_=cancel.cancelled()=>bail!("ZeroSSL issuance cancelled"),p=state.limiter.acquire()=>p.map_err(|_|anyhow!("ZeroSSL issuer closed"))?};
        let _global=tokio::select!{biased;_=cancel.cancelled()=>bail!("ZeroSSL issuance cancelled"),p=self.inner.global.acquire()=>p.map_err(|_|anyhow!("certificate manager closed"))?};
        let wire=self.zero_wire(state,cancel).await?;
        if leg.phase==Phase::Prepared{
            // Build all local inputs before the irreversible create intent.
            let request=CreateJob::copy(&leg,&identifiers,state.settings.settings.validity_days)?;
            let request=self.cpu(cancel,move||request.execute()).await?;
            leg.phase=Phase::CreateIntent;leg=self.save_zero(&id,leg,lease,cancel).await?;
            match wire.create(request,cancel).await{
                Ok(reply)=>{let(value,memory)=reply.into_parts();leg.certificate=Some(value);leg._api_memory=Some(memory);leg.phase=Phase::Created;leg=self.save_zero(&id,leg,lease,cancel).await?;},
                Err(error)=>{
                    if error.downcast_ref::<crate::zerossl_wire::models::ApiError>().is_some_and(|e|e.confirmed_rejection){
                        leg.phase=Phase::CreateRejected;let _=self.save_zero(&id,leg,lease,&CancellationToken::new()).await?;return Err(ClosedLeg.into())
                    }
                    return Err(error.context(CreateUncertain))
                },
            }
        }
        let cert_id=CertId::parse(leg.certificate.as_ref().ok_or_else(||anyhow!("ZeroSSL certificate identity missing"))?.id.clone())?;
        let result=self.finish_zero(names,backend,state,input.clone(),attempt_id,&id,&cert_id,leg,lease,lifecycle,cancel,report_obtained,produced,&identifiers).await;
        if let Err(error)=result{
            if self.load_zero(&id).await?.is_some_and(|leg|leg.certificate.as_ref().is_some_and(|c|c.status=="issued")) {
                if let Some(produced)=produced{produced.store(true,Ordering::Release);}
                return Err(error.context(IssuedCandidate))
            }
            // A durable known id permits bounded cleanup; an unknown create id
            // never enters this path and cannot be silently replayed.
            self.cancel_zero(&id,&cert_id,wire,lease).await?;
            return Err(error)
        }
        result
    }
    async fn cancel_zero(&self,id:&str,cert_id:&CertId,wire:&Wire,lease:&StorageLease)->Result<()> {
        let cancel=CancellationToken::new();let timer=cancel.clone();
        let task=tokio::spawn(async move{tokio::time::sleep(Duration::from_secs(10)).await;timer.cancel();});
        let result=async{
            let mut leg=self.load_zero(id).await?.ok_or_else(||anyhow!("ZeroSSL cancel leg missing"))?;
            if matches!(leg.phase,Phase::Stored|Phase::StoreIntent|Phase::Issued){return Ok(())}
            let resuming=leg.phase==Phase::CancelIntent;
            leg.phase=Phase::CancelIntent;leg=self.save_zero(id,leg,lease,&cancel).await?;
            let already=if resuming{
                let reply=wire.get(cert_id,&cancel).await?;ensure!(reply.value.id==cert_id.as_str(),"ZeroSSL cancel certificate ID changed");
                matches!(reply.value.status.as_str(),"cancelled"|"canceled")
            }else{false};
            if !already{wire.cancel(cert_id,&cancel).await?;}
            if let Some(proof)=&leg.validation_proof{
                self.inner.registry.zerossl_source(self.inner.store.clone(),self.inner.local.clone())?
                    .clear(id,&proof.domain,cancel.clone()).await?;
            }
            leg.phase=Phase::Cancelled;self.save_zero(id,leg,lease,&cancel).await?;Ok(())
        }.await;task.abort();let _=task.await;result
    }
}
impl CertificateManager {
    async fn finish_zero(&self,names:&[String],backend:&backend::Backend,state:&State,input:Arc<RuntimeInput>,
        attempt_id:&str,id:&str,cert_id:&CertId,mut leg:Leg,lease:&StorageLease,lifecycle:&crate::cert_events::Attempt,
        cancel:&CancellationToken,report_obtained:bool,produced:Option<&std::sync::atomic::AtomicBool>,identifiers:&[String])->Result<ManagedCertificate>{
        let wire=self.zero_wire(state,cancel).await?;
        if leg.phase==Phase::CancelIntent{
            self.cancel_zero(id,cert_id,wire,lease).await?;return Err(ClosedLeg.into())
        }
        let recovered_candidate=matches!(leg.phase,Phase::Issued|Phase::StoreIntent);
        if !recovered_candidate{
            if leg.validation_proof.is_none(){
                ensure!(leg.phase==Phase::Created,"ZeroSSL persisted validation proof missing");
                let validation=leg.certificate.as_ref().and_then(|c|c.validation.as_ref())
                    .and_then(|v|v.other_methods.get(&identifiers[0])).ok_or_else(||anyhow!("ZeroSSL validation data missing for CSR CommonName"))?;
                let body_bytes=validation.file_validation_content.iter().try_fold(0usize,|n,s|n.checked_add(s.len()).ok_or(crate::cert_transient::ResourceDenied))?
                    .checked_add(validation.file_validation_content.len().saturating_sub(1)).ok_or(crate::cert_transient::ResourceDenied)?;
                ensure!(body_bytes<=16*1024&&validation.file_validation_url_http.len()<=4096,"ZeroSSL HTTP validation proof exceeds bounds");
                leg.validation_proof=Some(ValidationProof{domain:identifiers[0].clone(),url:validation.file_validation_url_http.clone(),body:validation.file_validation_content.join("\n")});
                leg=self.save_zero(id,leg,lease,cancel).await?;
            }
            let proof=leg.validation_proof.as_ref().ok_or_else(||anyhow!("ZeroSSL validation proof missing"))?;
            ensure!(proof.domain==identifiers[0],"ZeroSSL validation proof domain changed");
            let url=proof.url.clone();let body=proof.body.clone();
            let parsed=url::Url::parse(&url).map_err(|_|anyhow!("invalid ZeroSSL HTTP validation URL"))?;
            ensure!(parsed.scheme()=="http"&&parsed.host_str().and_then(|v|crate::challenge::normalize_zerossl_host(v).ok()).is_some_and(|v|v==identifiers[0]),"ZeroSSL validation URL is outside bound host");
            let source=self.inner.registry.zerossl_source(self.inner.store.clone(),self.inner.local.clone())?;
            let presentation=source.present(id,&identifiers[0],&url,&body,cancel.clone()).await?;
            let proof=self.inner.registry.register_zerossl(id,&identifiers[0],parsed.path(),body.as_bytes(),Duration::from_secs(3600));
            let validation=async{
                let _proof=proof?;
                let prepare=state.prepare.as_ref().ok_or_else(||anyhow!("ZeroSSL requires an HTTP validation listener provider"))?;
                prepare(cancel.clone()).await?;
                if leg.phase==Phase::Created {
                    leg.phase=Phase::VerifyIntent;leg=self.save_zero(id,leg,lease,cancel).await?;
                    let reply=wire.verify_http(cert_id,cancel).await?;
                    let(value,memory)=reply.into_parts();ensure!(value.id==cert_id.as_str(),"ZeroSSL verify certificate ID changed");
                    leg.certificate=Some(value);leg._api_memory=Some(memory);leg.phase=Phase::Pending;leg=self.save_zero(id,leg,lease,cancel).await?;
                }else{
                    let reply=wire.get(cert_id,cancel).await?;
                    let(value,memory)=reply.into_parts();ensure!(value.id==cert_id.as_str(),"ZeroSSL recovery certificate ID changed");
                    leg.certificate=Some(value);leg._api_memory=Some(memory);
                    // Verify is id-bound, unlike create. If a crash preceded
                    // its send, restart resumes that exact known certificate.
                    if leg.phase==Phase::VerifyIntent&&leg.certificate.as_ref().is_some_and(|c|c.status=="draft"){
                        let reply=wire.verify_http(cert_id,cancel).await?;
                        let(value,memory)=reply.into_parts();ensure!(value.id==cert_id.as_str(),"ZeroSSL verify certificate ID changed");
                        leg.certificate=Some(value);leg._api_memory=Some(memory);
                    }
                    leg.phase=Phase::Pending;leg=self.save_zero(id,leg,lease,cancel).await?;
                }
                loop {
                    match leg.certificate.as_ref().map(|c|c.status.as_str()) {
                        Some("issued")=>break,
                        Some("pending_validation")=>{},
                        _=>bail!("unexpected ZeroSSL validation status"),
                    }
                    sleep_cancel(Duration::from_secs(5),cancel).await?;
                    let reply=wire.get(cert_id,cancel).await?;let(value,memory)=reply.into_parts();
                    ensure!(value.id==cert_id.as_str(),"ZeroSSL poll certificate ID changed");
                    leg.certificate=Some(value);leg._api_memory=Some(memory);leg=self.save_zero(id,leg,lease,cancel).await?;
                }
                let bundle=wire.download(cert_id,cancel).await?;
                if let Some(produced)=produced{produced.store(true,Ordering::Release);}
                let pools=self.inner.chain_memory.clone();
                let pem=self.cpu(cancel,move||Ok(Arc::new(crate::acme_wire::chain_memory::Buffer::assemble(&pools.payload,
                    &[bundle.value.certificate_crt.as_bytes(),bundle.value.ca_bundle_crt.as_bytes()])?))).await?;
                leg.downloaded_pem=Some(pem);leg.phase=Phase::Issued;
                self.save_zero(id,leg,lease,cancel).await
            }.await;
            let cleaned=presentation.cleanup().await;
            leg=validation?;cleaned?;
        }
        if recovered_candidate&&let Some(proof)=&leg.validation_proof {
            self.inner.registry.zerossl_source(self.inner.store.clone(),self.inner.local.clone())?
                .clear(id,&proof.domain,cancel.clone()).await?;
        }
        let chain=leg.downloaded_pem.as_ref().ok_or_else(||anyhow!("ZeroSSL signed candidate missing"))?;
        let mut bundle=DownloadedBundle::new(chain.as_slice(),input.record.private_key_pem.as_bytes(),&input.record.names,None,"zerossl","")?;
        let(leg,bundle)=self.cpu(cancel,move||{
            let encoded=crate::cert_transient::encode_json(leg.certificate.as_ref().ok_or_else(||anyhow!("ZeroSSL issuer metadata missing"))?)?;
            let json=crate::cert_transient::json_value(encoded.as_ref(),Some(crate::cert_transient::Lifetime::Persistent))?;
            let(value,memory)=json.into_parts();
            bundle.bundle.metadata["issuer_data"]=value;bundle.metadata_memory=memory;
            Ok((leg,bundle))
        }).await?;let mut leg=leg;
        let info=self.inspect_material(&bundle,names,cancel).await?;
        ensure!(info.spki_der.as_ref()==input.record.spki_der,"ZeroSSL issued a different public key");
        self.inner.resolver.leaf_guard().key_deny().check_state(&input.key_state)?;stored_candidate_time(&info)?;
        leg.phase=Phase::StoreIntent;leg.stored_leaf_sha256=Some(info.leaf_sha256.clone());
        let initial=leg.initial_key_hash.clone();leg=self.save_zero(id,leg,lease,cancel).await?;
        self.require_active_backend(names,attempt_id,id,&backend.id,&input.binding,lease).await?;
        self.save_issued_certificate("zerossl",&names_key(names)?,&bundle,lease,initial.as_deref()).await?;
        ensure!(self.claim_winner(names,attempt_id,id,"zerossl",&info.leaf_sha256,lease).await?,"ZeroSSL candidate lost publication CAS");
        leg.phase=Phase::Stored;leg.downloaded_pem=None;self.save_zero(id,leg,lease,cancel).await?;
        if report_obtained{lifecycle.obtained(self.inner.lifecycle_events.as_ref(),"zerossl",names,&input.record.csr_der,cancel).await;}
        Ok(ManagedCertificate{names:names.to_vec(),issuer_key:"zerossl".to_owned(),not_after_unix:info.not_after,
            renew_at_unix:backend.renewal(&info,self.inner.options.renewal_window_ratio,None,self.inner.options.poll_interval)?,leaf_sha256:info.leaf_sha256,obtained:true})
    }
}
