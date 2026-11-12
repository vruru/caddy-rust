//! Certificate endpoints are delegated only by an authenticated order/chain
//! response. This private grant never changes account/order/challenge origins.
use super::{AccountSession, CertificateChain, certificate_links, validate_url};
use anyhow::{Result, anyhow, ensure};
use std::{
    collections::{HashMap, HashSet},
    future::Future,
    pin::Pin,
    sync::Arc,
};
use tokio_util::sync::CancellationToken;
use url::Url;

const MAX_REQUESTS: usize = 32;
const MAX_DEPTH: usize = 8;
const MAX_VISITS: usize = 128;
const MAX_CHAINS: usize = 16;

struct Endpoint {
    url: Url,
    require_https: bool,
}
impl Endpoint {
    fn declared(base: &Url, raw: &str, require_https: bool, allow_loopback: bool) -> Result<Self> {
        ensure!(raw.len() <= 8192, "ACME certificate URL exceeds bounds");
        let url = base
            .join(raw)
            .map_err(|_| anyhow!("invalid ACME certificate link"))?;
        ensure!(
            url.as_str().len() <= 8192,
            "ACME resolved certificate URL exceeds bounds"
        );
        validate_url(
            &url,
            &HashSet::from([url.origin().ascii_serialization()]),
            allow_loopback && !require_https,
        )?;
        ensure!(
            !require_https || url.scheme() == "https",
            "ACME certificate link downgrades HTTPS"
        );
        Ok(Self {
            require_https: require_https || url.scheme() == "https",
            url,
        })
    }
}
struct Node {
    body: Arc<super::chain_memory::Buffer>,
    info: super::chain_validation::Validated,
    links: Vec<certificate_links::Link>,
}
#[derive(Default)]
struct Owner {
    cache: HashMap<String, Arc<Node>>,
    path: HashSet<String>,
    requests: usize,
    visits: usize,
}
impl AccountSession {
    /// Only an authenticated, valid order delegates the first certificate URL.
    pub(crate) async fn download_order_chains(
        &self, order_url: &str, want_names: bool, cancel: &CancellationToken,
    ) -> Result<Vec<CertificateChain>> {
        let order=self.order(order_url,cancel).await?;
        ensure!(order.value.status=="valid","certificate chain order is not valid");
        let base=self.wire.endpoint(order_url)?;
        let raw=order.value.certificate.as_deref().ok_or_else(||anyhow!("valid order has no certificate URL"))?;
        let endpoint=Endpoint::declared(&base,raw,base.scheme()=="https",self.wire.inner.allow_loopback)?;
        self.fetch_chains(endpoint,&mut Owner::default(),0,want_names,cancel).await
    }
    fn fetch_chains<'a>(&'a self,endpoint:Endpoint,owner:&'a mut Owner,depth:usize,want_names:bool,cancel:&'a CancellationToken)
        -> Pin<Box<dyn Future<Output=Result<Vec<CertificateChain>>>+Send+'a>> {
        Box::pin(async move {
            ensure!(!cancel.is_cancelled(),"ACME chain download cancelled");
            ensure!(depth<=MAX_DEPTH,"ACME certificate graph depth exceeded");
            ensure!(owner.visits<MAX_VISITS,"ACME certificate graph visit budget exhausted");
            owner.visits+=1;
            let key=endpoint.url.to_string();
            ensure!(owner.path.insert(key.clone()),"ACME certificate graph cycle");
            let result=self.fetch_chain_contents(endpoint,owner,depth,want_names,cancel).await;
            owner.path.remove(&key);result
        })
    }
    async fn fetch_chain_contents(&self,endpoint:Endpoint,owner:&mut Owner,depth:usize,want_names:bool,cancel:&CancellationToken)->Result<Vec<CertificateChain>> {
        use super::{chain_memory as memory,chain_validation as validation};
        let key=endpoint.url.to_string();
        let node=if let Some(node)=owner.cache.get(&key){node.clone()}else{
            ensure!(owner.requests<MAX_REQUESTS,"ACME certificate request budget exhausted");
            owner.requests+=1;
            let response=self.wire.signed_certificate_url(&self.signer,&self.location,endpoint.url.clone(),cancel).await?;
            let mut links=Vec::new();let mut header_bytes=0usize;
            for header in response.headers.get_all(reqwest::header::LINK) {
                header_bytes=header_bytes.saturating_add(header.as_bytes().len());if header_bytes>65536{break}
                if let Ok(raw)=header.to_str(){links.extend(certificate_links::parse(raw).into_iter().take(64-links.len()));}
                if links.len()==64{break}
            }
            let body=Arc::new(memory::Buffer::adopt(response.body,response.body_memory.ok_or_else(||anyhow!("ACME response memory credit missing"))?)?);
            let decode=memory::scratch(validation::decode_cost(body.len())?,cancel.clone()).await?;
            let input=body.clone();let pool=self.wire.inner.chain_memory.payload.clone();
            let info=crate::cert_cpu::run(self.wire.inner.cpu.clone(),cancel.clone(),move||{
                let _decode=decode;validation::validate(input,pool,want_names)
            }).await?;
            let node=Arc::new(Node{body,info,links});owner.cache.insert(key.clone(),node.clone());node
        };
        let body=&node.body;
        let up=node.links.iter().filter(|link|link.up).collect::<Vec<_>>();
        let mut chains=Vec::new();
        if up.is_empty(){
            chains.push(CertificateChain {url:key.clone(),chain_pem:body.clone(),first:node.info.first.clone(),last:node.info.last.clone(),count:node.info.count,names:vec![node.info.names.clone()]});
        }else{
            let mut up_targets=HashSet::new();
            for link in up {
                let Ok(issuer)=Endpoint::declared(&endpoint.url,&link.target,endpoint.require_https,self.wire.inner.allow_loopback)else{continue};
                if !up_targets.insert(issuer.url.to_string()){continue}
                if let Ok(parents)=self.fetch_chains(issuer,owner,depth+1,want_names,cancel).await {
                    for parent in parents {
                        if chains.len()==MAX_CHAINS{break}
                        let count=node.info.count+parent.count;if count>32{continue}
                        let bridge=memory::scratch(validation::CRYPTO_SCRATCH,cancel.clone()).await?;
                        let child=node.info.last.clone();let issuer=parent.first.clone();let input=body.clone();let suffix=parent.chain_pem.clone();let pool=self.wire.inner.chain_memory.payload.clone();
                        let result=crate::cert_cpu::run(self.wire.inner.cpu.clone(),cancel.clone(),move||{
                            let _bridge=bridge;validation::bridge(child,issuer)?;
                            let separator=if input.as_slice().ends_with(b"\n"){&b""[..]}else{&b"\n"[..]};
                            Ok(Arc::new(memory::Buffer::assemble(&pool,&[input.as_slice(),separator,suffix.as_slice()])?))
                        }).await;
                        if let Ok(chain_pem)=result {
                            let mut names=vec![node.info.names.clone()];names.extend(parent.names);
                            chains.push(CertificateChain{url:key.clone(),chain_pem,first:node.info.first.clone(),last:parent.last,count,names});
                        }
                    }
                }
            }
            ensure!(!chains.is_empty(),"required ACME issuer chain unavailable");
        }
        let mut alternate_targets=HashSet::new();
        for link in node.links.iter().filter(|link|link.alternate){
            ensure!(!cancel.is_cancelled(),"ACME chain download cancelled");if chains.len()==MAX_CHAINS{break}
            let Ok(alternate)=Endpoint::declared(&endpoint.url,&link.target,endpoint.require_https,self.wire.inner.allow_loopback)else{continue};
            if !alternate_targets.insert(alternate.url.to_string()){continue}
            if let Ok(alternates)=self.fetch_chains(alternate,owner,depth+1,want_names,cancel).await {
                for candidate in alternates {if chains.len()==MAX_CHAINS{break}if candidate.first.as_slice()==node.info.first.as_slice(){chains.push(candidate);}}
            }
        }
        Ok(chains)
    }
}
