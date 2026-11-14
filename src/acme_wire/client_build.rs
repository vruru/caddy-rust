//! Concrete configured-client ownership through construction, connectors and IO.
//! The owner contains only existing loans, never a manager or cancellation owner.
use super::*;
#[derive(Clone,Default)]
pub(crate) struct ClientOwner {
    values:Option<Arc<chain_memory::Lease>>,
    material:Option<Arc<dyn crate::cert_cpu::MaterialOwner>>,
}
impl ClientOwner {
    pub(crate) fn new(values:Option<Arc<chain_memory::Lease>>,material:Option<Arc<dyn crate::cert_cpu::MaterialOwner>>)->Self {Self{values,material}}
}
pub(super) struct Input {
    options:WireOptions,
    #[cfg(feature="native-run")]
    scope:Option<Arc<crate::outgoing_tls::Scope>>,
    cpu: Arc<Semaphore>,
    owner:ClientOwner,
}
pub(super) struct Built {pub client:reqwest::Client,pub owner:ClientOwner}
impl Input {
    pub fn new(options:WireOptions,#[cfg(feature="native-run")] scope:Option<Arc<crate::outgoing_tls::Scope>>,owner:ClientOwner,
        cpu: Arc<Semaphore>,
    )->Self {
        Self{options,#[cfg(feature="native-run")] scope,
            cpu,owner}
    }
    // A consuming method captures the complete input envelope, including its
    // last loan field, through queued/unstarted/started worker destruction.
    pub fn build(mut self)->Result<Built> {
        let mut builder=reqwest::Client::builder()
            .tls_crypto_provider(crate::crypto::client_provider())
            .rustls_certificate_verifier_wrapper(crate::cert_uri_san::wrap_server_verifier)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(self.options.request_timeout)
            .user_agent("Caddy-Rust-ACME/0.1");
        if let Some(proxy)=self.options.network_proxy.take(){builder=proxy.apply(builder)?;}
        for pem in std::mem::take(&mut self.options.extra_ca_pem) {
            ensure!(pem.len()<=1024*1024,"ACME trust root exceeds bounds");
            builder=append_trusted_root_pem(builder,&pem)?;
        }
        #[cfg(feature="native-run")]
        if let Some(scope)=self.scope.take(){
            scope.prepare_sign_driver(self.cpu.clone())?;
            #[cfg(unix)]
            {builder=builder.dns_resolver(crate::http_runtime::acme_client_dns::Resolver::new(scope.clone(),self.owner.clone())?);}
            builder=builder.connector_layer(scope.layer()?.with_issuer_owner(self.owner.clone()));
        }
        let client=builder.build().map_err(|_|anyhow!("ACME client construction failed"))?;
        let built=Built{client,owner:std::mem::take(&mut self.owner)};
        Ok(built)
    }
}
