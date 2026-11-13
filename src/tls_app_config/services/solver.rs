use super::super::model::AcmeSettings;
use super::*;
use crate::{
    cert_automation::{ChallengeType, SolverPreparation},
    http_runtime::{ChallengeBindingRequest, ChallengeListenerLease},
};

pub(super) struct SolverBroker {
    settings: Vec<BindingSettings>,
    staged: Vec<StagedAddress>,
    provider: Option<Arc<dyn ChallengeListenerProvider>>,
    leases: AsyncMutex<Vec<Box<dyn ChallengeListenerLease>>>,
    // Actual settings/leases/callbacks retire before their producer credit.
    _memory:crate::acme_wire::chain_memory::Scratch,
    _issuer_values_credit:Option<Arc<crate::acme_wire::chain_memory::Lease>>,
}
struct BindingSettings {
    directory: String,
    bind_host: String,
    bind_address: Option<std::net::SocketAddr>,
    http_port: u16,
    alpn_port: u16,
}
impl SolverBroker {
    pub(super) fn new(
        settings: Vec<AcmeSettings>,
        staged: Vec<StagedAddress>,
        provider: Option<Arc<dyn ChallengeListenerProvider>>,
    ) -> Result<Arc<Self>> {
        ensure!(settings.len()<=16,"challenge issuer binding limit");
        let bytes=settings.iter().try_fold(8192usize,|n,s|{
            let text=s.config.wire.directory.len().checked_mul(3).and_then(|a|s.bind_host.len().checked_mul(2).and_then(|b|a.checked_add(b))).ok_or(crate::cert_transient::ResourceDenied)?;
            n.checked_add(text).and_then(|n|n.checked_add(std::mem::size_of::<BindingSettings>()+2048)).ok_or(crate::cert_transient::ResourceDenied)
        })?.checked_add(staged.len().checked_mul(std::mem::size_of::<StagedAddress>()).ok_or(crate::cert_transient::ResourceDenied)?)
            .ok_or(crate::cert_transient::ResourceDenied)?;
        let memory=crate::cert_transient::reserve(bytes)?;
        let settings = settings
            .into_iter()
            .map(|settings| {
                let directory = url::Url::parse(&settings.config.wire.directory)
                    .map_err(|_| anyhow!("invalid challenge issuer directory"))?
                    .to_string();
                let bind_address=if let Some(provider)=&provider {provider.resolve_bind_host(&settings.bind_host)?}else{crate::http_runtime::listener_lease::numeric_bind_host(&settings.bind_host)?};
                Ok(BindingSettings {
                    directory,
                    bind_host: settings.bind_host,
                    bind_address,
                    http_port: settings.http_port.unwrap_or(80),
                    alpn_port: settings.alpn_port.unwrap_or(443),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Arc::new(Self {
            settings,
            staged,
            provider,
            leases: AsyncMutex::new(Vec::new()),
            _memory:memory,
            _issuer_values_credit:None,
        }))
    }
    pub(super) fn with_issuer_values_credit(mut self:Arc<Self>,credit:Option<Arc<crate::acme_wire::chain_memory::Lease>>)->Result<Arc<Self>>{
        Arc::get_mut(&mut self).ok_or_else(||anyhow!("challenge broker already shared"))?._issuer_values_credit=credit;
        Ok(self)
    }
    pub(super) fn callbacks(self:&Arc<Self>)->Result<Vec<SolverPreparation>>{
        // Constructor prepaid this bounded vector/callback metadata. Every
        // callback and invoked future keeps the concrete producer alive.
        (0..self.settings.len()).map(|index|self.callback_for(index)).collect()
    }
    pub(super) fn callback_for(self:&Arc<Self>,index:usize)->Result<SolverPreparation>{
        ensure!(index<self.settings.len(),"issuer proof binding index out of range");
        let this=self.clone();
        Ok(Arc::new(move|directory:String,kind,cancel|{
            let this=this.clone();
            Box::pin(async move {
                ensure!(this.settings[index].directory==directory,"issuer proof binding changed");
                this.prepare_index(index,kind,cancel).await
            })
        }))
    }
    pub(super) fn callback(self: &Arc<Self>) -> SolverPreparation {
        let this = self.clone();
        Arc::new(move |directory, kind, cancel| {
            let this = this.clone();
            Box::pin(async move { this.prepare(directory, kind, cancel).await })
        })
    }
    async fn prepare(
        &self,
        directory: String,
        kind: ChallengeType,
        cancel: CancellationToken,
    ) -> Result<()> {
        ensure!(
            !cancel.is_cancelled(),
            "challenge listener preparation cancelled"
        );
        let mut matches=self.settings.iter().enumerate().filter(|(_,s)|s.directory==directory);
        let(index,_)=matches.next().ok_or_else(||anyhow!("challenge issuer binding is missing"))?;
        ensure!(matches.next().is_none(),"ambiguous unbound challenge issuer directory");
        self.prepare_index(index,kind,cancel).await
    }
    async fn prepare_index(&self,index:usize,kind:ChallengeType,cancel:CancellationToken)->Result<()> {
        ensure!(!cancel.is_cancelled(),"challenge listener preparation cancelled");
        let settings=self.settings.get(index).ok_or_else(||anyhow!("challenge issuer binding missing"))?;
        let port = match kind {
            ChallengeType::Http01 => settings.http_port,
            ChallengeType::TlsAlpn01 => settings.alpn_port,
        };
        let capable=|bindings:&[StagedAddress]|coverage(bindings.iter(),kind,port,settings.bind_address);
        if capable(&self.staged) {
            return Ok(());
        }
        let mut leases = tokio::select! { biased; _ = cancel.cancelled() => return Err(anyhow!("challenge listener preparation cancelled")), leases = self.leases.lock() => leases };
        if leases
            .iter()
            .any(|lease| capable(lease.addresses()))
        {
            return Ok(());
        }
        ensure!(
            leases.len() < 32,
            "challenge listener lease capacity exceeded"
        );
        let provider = self
            .provider
            .as_ref()
            .ok_or_else(|| anyhow!("ACME requires a challenge listener provider"))?;
        let request = ChallengeBindingRequest {
            bind_host: settings.bind_host.clone(),
            http_port: (kind == ChallengeType::Http01).then_some(port),
            tls_alpn_port: (kind == ChallengeType::TlsAlpn01).then_some(port),
        };
        let lease = provider.acquire(vec![request], cancel.clone()).await?;
        let valid=lease.addresses().iter().filter(|binding|binding.declared.port()==port
            && settings.bind_address.is_none_or(|mut requested| {requested.set_port(port);binding.declared==requested}));
        if !coverage(valid,kind,port,settings.bind_address) {
            let _ = lease.release().await;
            return Err(anyhow!(
                "challenge listener provider returned an invalid proof"
            ));
        }
        if cancel.is_cancelled() {
            let _ = lease.release().await;
            return Err(anyhow!("challenge listener preparation cancelled"));
        }
        leases.push(lease);
        Ok(())
    }
    pub(super) async fn release(&self) -> Result<()> {
        let leases = std::mem::take(&mut *self.leases.lock().await);
        let mut releases = Vec::new();
        for lease in leases {
            releases.push(lease.release());
        }
        let outcomes = stream::iter(releases)
            .buffer_unordered(8)
            .collect::<Vec<_>>()
            .await;
        ensure!(
            outcomes.into_iter().all(|outcome| outcome.is_ok()),
            "challenge listener release failed"
        );
        Ok(())
    }
}

// Empty host requests the OS wildcard convention. Aggregate real capabilities
// across the borrowed IPv4 and IPv6 owners; one v6-only socket is not dual-stack.
fn coverage<'a>(bindings:impl Iterator<Item=&'a StagedAddress>+Clone,kind:ChallengeType,port:u16,bind:Option<std::net::SocketAddr>)->bool {
    if bind.is_some(){return bindings.clone().any(|binding|serves(binding,kind,port,bind));}
    let ipv4=std::net::SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(),port);
    let ipv6=std::net::SocketAddr::new(std::net::Ipv6Addr::UNSPECIFIED.into(),port);
    bindings.clone().any(|binding|serves(binding,kind,port,Some(ipv4)))
        && bindings.clone().any(|binding|serves(binding,kind,port,Some(ipv6)))
}

fn serves(
    binding: &StagedAddress,
    kind: ChallengeType,
    port: u16,
    bind: Option<std::net::SocketAddr>,
) -> bool {
    let protocol = match kind {
        ChallengeType::Http01 => binding.http01,
        ChallengeType::TlsAlpn01 => binding.tls_alpn01,
    };
    protocol
        && binding.actual.port() == port
        && bind.is_none_or(|requested| {
            let actual = binding.actual;
            let scope_matches=match (actual,requested) {
                (std::net::SocketAddr::V6(a),std::net::SocketAddr::V6(r))=>
                    r.scope_id()==0 || a.scope_id()==r.scope_id()
                        || a.ip().is_unspecified()&&a.scope_id()==0,
                _=>true,
            };
            scope_matches && (actual.ip() == requested.ip()
                || match actual.ip() {
                    std::net::IpAddr::V4(ip) => ip.is_unspecified() && requested.is_ipv4(),
                    std::net::IpAddr::V6(ip) => ip.is_unspecified()
                        && (!binding.only_v6 || requested.is_ipv6()),
                })
        })
}
