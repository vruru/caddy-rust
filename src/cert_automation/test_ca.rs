//! Private Caddy test-CA plans; these never add configured fallback backends.
use super::*;
use super::attempt::BackendId;
pub(crate) const LE_PRIMARY:&str="https://acme-v02.api.letsencrypt.org/directory";
pub(crate) const LE_TEST:&str="https://acme-staging-v02.api.letsencrypt.org/directory";
pub(crate) fn directory<'a>(primary:&str,configured:Option<&'a str>)->Option<&'a str>{
    match configured {None=>None,Some("") if primary==LE_PRIMARY=>Some(LE_TEST),Some("")=>None,Some(value)=>Some(value)}
}
pub(super) enum TestPolicy {Disabled,SameEndpoint,Separate(TestIssuer)}
pub(super) struct TestIssuer {
    pub state:IssuerState,
    pub id:BackendId,
    pub policy:String,
}
/// Exact cells of the newly owned policy/callback vectors, including Disabled
/// and SameEndpoint entries. Charge before the constructor reserves either Vec.
pub(crate) fn plan_metadata_cost(count:usize)->Result<usize>{
    ensure!(count<=16,"test CA policy count outside bounds");
    count.checked_mul(std::mem::size_of::<TestPolicy>()+std::mem::size_of::<Option<SolverPreparation>>())
        .and_then(|n|n.checked_add(if count==0{0}else{2*std::mem::size_of::<Vec<TestPolicy>>()+128}))
        .ok_or_else(||crate::cert_transient::ResourceDenied.into())
}
fn sum(parts:&[usize])->Result<usize>{parts.iter().try_fold(0usize,|n,v|n.checked_add(*v).ok_or_else(||crate::cert_transient::ResourceDenied.into()))}
fn strings(values:&[String])->Result<usize>{
    values.iter().try_fold(values.len().checked_mul(std::mem::size_of::<String>()).ok_or(crate::cert_transient::ResourceDenied)?,|n,s|
        n.checked_add(s.len()).and_then(|n|n.checked_add(32)).ok_or_else(||crate::cert_transient::ResourceDenied.into()))
}
fn wire_copy(config:&WireOptions,test:&str)->Result<usize>{
    let roots=config.extra_ca_pem.iter().try_fold(config.extra_ca_pem.len().checked_mul(std::mem::size_of::<Vec<u8>>()).ok_or(crate::cert_transient::ResourceDenied)?,|n,v|n.checked_add(v.len()).and_then(|n|n.checked_add(32)).ok_or(crate::cert_transient::ResourceDenied))?;
    let proxy=config.network_proxy.as_ref().map_or(0,|proxy|{let(a,b)=proxy.fingerprint();a.len()+b.len()+64});
    sum(&[std::mem::size_of::<WireOptions>(),test.len(),roots,strings(&config.trusted_ca_origins)?,proxy,256])
}
/// Existing backend identity/cooldown encoders run sequentially. Their
/// borrowed tuple includes preferred-chain strings: one input byte needs at
/// most six JSON bytes, plus quotes/commas and fixed typed keys/enum labels.
/// Vec growth can retain the old buffer while requesting a new capacity:
/// old < final length, new <= 2*final length. This prepays that 3x peak, not
/// an arbitrary number of configured-value clones or a larger resource pool.
fn identity_json_temp(config:&AcmeIssuerConfig)->Result<usize>{
    let lists=[&config.preferred_chains.any_common_name,&config.preferred_chains.root_common_name];
    let mut payload=0usize;let mut count=0usize;
    for list in lists{count=count.checked_add(list.len()).ok_or(crate::cert_transient::ResourceDenied)?;
        for name in list{payload=payload.checked_add(name.len()).ok_or(crate::cert_transient::ResourceDenied)?;}}
    let encoded=payload.checked_mul(6).and_then(|n|count.checked_mul(4).and_then(|c|n.checked_add(c)))
        .and_then(|n|config.challenge_types.len().checked_mul(64).and_then(|c|n.checked_add(c)))
        .and_then(|n|n.checked_add(1024)).ok_or(crate::cert_transient::ResourceDenied)?;
    encoded.checked_mul(3).and_then(|n|n.checked_add(128)).ok_or_else(||crate::cert_transient::ResourceDenied.into())
}
/// Incremental closed clone families for the private fixed-name Caddy Group:
/// one auxiliary config, every actually possible physical builder input, and
/// its one current initializer. True caller.abort can leave a worker alive.
/// The supplied width comes from the actual AutomationResources constructor;
/// it is not a new CPU limit and is not a public multi-name manager promise.
pub(crate) fn copy_cost(config:&AcmeIssuerConfig,configured:Option<&str>,client_inputs:usize)->Result<usize>{
    let Some(test)=directory(&config.wire.directory,configured)else{return Ok(0)};
    if test==config.wire.directory {return Ok(256)}
    let wire=wire_copy(&config.wire,test)?;
    let wire_family=wire.checked_mul(client_inputs.checked_add(1).ok_or(crate::cert_transient::ResourceDenied)?)
        .ok_or(crate::cert_transient::ResourceDenied)?;
    // Only one fixed-name initializer can retain its async pre-builder view:
    // normalized directory + configured HTTP origin + trusted directory origin,
    // every trusted-origin String in its HashSet, and one origin parser/value
    // temporary. Older aborted physical workers own Input, not this async view.
    // The fixed metadata above is not used to hide variable origin text.
    let longest_origin=config.wire.trusted_ca_origins.iter().map(String::len).max().unwrap_or(0);
    let current_view=sum(&[test.len().checked_mul(3).ok_or(crate::cert_transient::ResourceDenied)?,
        strings(&config.wire.trusted_ca_origins)?,longest_origin.checked_mul(2).ok_or(crate::cert_transient::ResourceDenied)?])?;
    let eab=config.eab.as_ref().map_or(Ok(0),|e|sum(&[e.kid.len(),e.hmac_key.len(),64]))?;
    let names=sum(&[strings(&config.preferred_chains.any_common_name)?,strings(&config.preferred_chains.root_common_name)?])?;
    // Url normalization, origin, backend identity and temporary hash encoding
    // are all built on the constructor CPU lane before its owner may retire.
    sum(&[wire_family,current_view,identity_json_temp(config)?,std::mem::size_of::<TestIssuer>(),std::mem::size_of::<AcmeIssuerConfig>(),
        config.wire.directory.len(),config.email.len(),config.profile.len(),eab,names,names,
        config.challenge_types.len().checked_mul(std::mem::size_of::<ChallengeType>()).ok_or(crate::cert_transient::ResourceDenied)?,
        test.len().checked_mul(6).ok_or(crate::cert_transient::ResourceDenied)?,16384])
}
impl CertificateManager {
    /// Caller uses copy_cost before any config clone and attaches that actual
    /// constructor owner first. Public standalone constructors never call this.
    pub(crate) fn with_prepared_test_cas(mut self,values:Vec<Option<String>>,resources:&AutomationResources)->Result<Self>{
        let inner=Arc::get_mut(&mut self.inner).ok_or_else(||anyhow!("certificate manager already shared"))?;
        ensure!(inner.construction_owner.is_some(),"test CA constructor allowance missing");
        ensure!(values.len()==inner.issuers.len()&&values.len()<=16,"test CA index count changed");
        ensure!(inner.test_policies.is_empty(),"test CA policy already installed");
        let mut policies=Vec::new();policies.try_reserve_exact(values.len())?;
        for (index,raw) in values.iter().enumerate(){
            let primary=&inner.issuers[index].config;
            let Some(test)=directory(&primary.wire.directory,raw.as_deref())else{policies.push(TestPolicy::Disabled);continue};
            let parsed=crate::acme_wire::directory_url::normalize(test)?;
            ensure!(parsed.as_str()==test,"test CA must be prepared before manager construction");
            if test==primary.wire.directory {policies.push(TestPolicy::SameEndpoint);continue}
            let mut config=primary.clone();config.wire.directory=test.to_owned();
            let ca=Arc::new(CaState{limiter:resources.ca(parsed.origin().ascii_serialization())?,next_allowed_unix:resources.cooldown(&inner.store,&config)?});
            let id=backend::acme_id(&config)?;
            let owner=inner.backends.iter().find(|b|matches!(b.kind,backend::BackendKind::Acme(i)if i==index))
                .ok_or_else(||anyhow!("test CA production backend missing"))?;
            let mut hash=Sha256::new();hash.update(b"test-ca-policy-v1");
            for value in [&owner.id,&id] {let BackendId::Acme{directory,config_identity}=value else{bail!("test CA owner kind changed")};for text in [directory,config_identity]{hash.update(u64::try_from(text.len())?.to_be_bytes());hash.update(text.as_bytes());}}
            let policy=format!("{:x}",hash.finalize());
            policies.push(TestPolicy::Separate(TestIssuer{state:IssuerState{custom_roots:inner.issuers[index].custom_roots.clone(),config,ca,wire:OnceCell::new(),solver_override:None},id,policy}));
        }
        inner.test_policies=policies;Ok(self)
    }
    pub(crate) fn with_test_ca_solvers(mut self,solvers:Vec<Option<SolverPreparation>>)->Result<Self>{
        let inner=Arc::get_mut(&mut self.inner).ok_or_else(||anyhow!("certificate manager already shared"))?;
        ensure!(solvers.len()==inner.issuers.len()&&inner.test_policies.len()==solvers.len(),"test CA solver indices changed");
        for (policy,solver)in inner.test_policies.iter_mut().zip(solvers){match policy {
            TestPolicy::Separate(test)=>test.state.solver_override=Some(solver.ok_or_else(||anyhow!("test CA proof binding missing"))?),
            _=>ensure!(solver.is_none(),"unused test CA proof binding"),
        }}Ok(self)
    }
    pub(super) fn same_test_endpoint(&self,index:usize)->bool{matches!(self.inner.test_policies.get(index),Some(TestPolicy::SameEndpoint))}
}


impl CertificateManager {
    pub(super) fn validate_probe_binding(&self,issuer:&IssuerState,binding:&super::acme_probe::PhaseBinding)->Result<()> {
        binding.validate()?;
        ensure!(binding.step==super::acme_probe::PhaseStep::Probe,"probe endpoint used outside active probe");
        let index=usize::from(binding.owner_acme_index);
        let primary=self.inner.backends.iter().find(|backend|matches!(backend.kind,backend::BackendKind::Acme(i)if i==index))
            .ok_or_else(||anyhow!("probe production index missing"))?;
        ensure!(primary.id==binding.owner,"probe production identity changed");
        let Some(TestPolicy::Separate(test))=self.inner.test_policies.get(index)else{bail!("probe test policy missing")};
        ensure!(test.id==binding.endpoint&&test.policy==binding.test_policy&&std::ptr::eq(&test.state,issuer),"active probe test endpoint/policy changed");
        Ok(())
    }
}
