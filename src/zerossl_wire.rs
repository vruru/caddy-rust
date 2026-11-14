//! Fixed-endpoint ZeroSSL REST transport for the native typed issuer.
mod http;
pub(crate) mod models;
use crate::acme_wire::{ClientOwner,chain_memory::{self,Lease,Pool}};
use crate::tls_app_config::zerossl_settings::Prepared;
use anyhow::{Result,ensure};
use std::{sync::Arc,time::Duration};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;
use models::*;
const BASE:&str="https://api.zerossl.com";
pub(crate) const BODY_LIMIT:usize=5*1024*1024;
#[derive(Debug)]pub(crate) struct MissingApiKey;
impl std::fmt::Display for MissingApiKey{fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{f.write_str("ZeroSSL API key is empty")}}
impl std::error::Error for MissingApiKey{}
#[derive(Debug)]pub(crate) struct InvalidResponse;
impl std::fmt::Display for InvalidResponse{fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{f.write_str("invalid ZeroSSL API response")}}
impl std::error::Error for InvalidResponse{}
#[derive(Debug)]pub(crate) struct Cancelled;
impl std::fmt::Display for Cancelled{fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{f.write_str("ZeroSSL request cancelled")}}
impl std::error::Error for Cancelled{}
/// Data is dropped before its callback-free resident credit.
pub(crate) struct Owned<T>{pub value:T,_memory:Lease}
impl<T> Owned<T>{pub(crate) fn into_parts(self)->(T,Lease){(self.value,self._memory)}}
struct Inner {client:reqwest::Client,prepared:Arc<Prepared>,base:url::Url,cpu:Arc<Semaphore>,owner:ClientOwner}
#[derive(Clone)]pub(crate) struct Wire {inner:Arc<Inner>}
struct CredentialHeader {value:Zeroizing<Vec<u8>>,_owner:ClientOwner}
impl AsRef<[u8]> for CredentialHeader {fn as_ref(&self)->&[u8]{self.value.as_slice()}}
/// Called only inside the bounded preparation envelope. Temporary validation
/// bytes are guarded too; HeaderValue's validator is reused without retaining
/// an unguarded secret allocation or copying a private validation algorithm.
pub(crate) fn validate_api_key(key:&str)->Result<()>{
    ensure!(key.len()<=1024*1024,"ZeroSSL API credential exceeds limit");
    let value=Zeroizing::new(key.as_bytes().to_vec());
    let bytes=bytes::Bytes::from_owner(CredentialHeader{value,_owner:ClientOwner::default()});
    let mut header=reqwest::header::HeaderValue::from_maybe_shared(bytes).map_err(|_|anyhow::anyhow!("invalid ZeroSSL API credential header"))?;
    header.set_sensitive(true);drop(header);Ok(())
}
struct BuildInput {cpu:Arc<Semaphore>,prepared:Arc<Prepared>,#[cfg(feature="native-run")]scope:Option<Arc<crate::outgoing_tls::Scope>>,owner:ClientOwner}
struct Built {client:reqwest::Client,prepared:Arc<Prepared>,owner:ClientOwner}
impl BuildInput {
 fn execute(self)->Result<Built>{
  let n=self.prepared.api_key().len().checked_add(6).ok_or(crate::cert_transient::ResourceDenied)?;
  let _temporary=chain_memory::try_scratch(n.checked_add(4096).ok_or(crate::cert_transient::ResourceDenied)?)?;
  let mut key=Zeroizing::new(Vec::new());key.try_reserve_exact(n).map_err(|_|crate::cert_transient::ResourceDenied)?;key.extend_from_slice(b"ApiKey ");key.extend_from_slice(self.prepared.api_key().as_bytes());
  // Preserve the guarded allocation through every default-header clone and
  // actual IO owner. HeaderValue's sensitive bit alone only controls Debug.
  let bytes=bytes::Bytes::from_owner(CredentialHeader{value:key,_owner:self.owner.clone()});
  let mut header=reqwest::header::HeaderValue::from_maybe_shared(bytes).map_err(|_|anyhow::anyhow!("invalid ZeroSSL API credential header"))?;header.set_sensitive(true);
  let mut headers=reqwest::header::HeaderMap::new();headers.insert(reqwest::header::AUTHORIZATION,header);
  let builder=crate::acme_wire::configured_base_builder(Duration::from_secs(120),"Caddy-Rust-ZeroSSL/0.1").default_headers(headers).native_http1_encoding_budget(Some(hyper::ext::NativeEncodingBudget::new(chain_memory::shared().payload.allocation_pool())));
  let builder=self.owner.apply_system_roots(builder)?;
  #[cfg(feature="native-run")]
  if let Some(scope)=self.scope.as_ref(){scope.prepare_sign_driver(self.cpu.clone())?;}
  let builder=crate::acme_wire::attach_owned_scope(builder,#[cfg(feature="native-run")]self.scope,&self.owner)?;
  let client=builder.build().map_err(|_|anyhow::anyhow!("ZeroSSL client construction failed"))?;
  Ok(Built{client,prepared:self.prepared,owner:self.owner})
 }
}
impl Wire {
 pub(crate) async fn connect(prepared:Arc<Prepared>,cpu:Arc<Semaphore>,
  #[cfg(feature="native-run")]scope:Option<Arc<crate::outgoing_tls::Scope>>,owner:ClientOwner,cancel:CancellationToken)->Result<Self>{
  if prepared.api_key().is_empty(){return Err(MissingApiKey.into())}
  ensure!(!cancel.is_cancelled(),"ZeroSSL construction cancelled");
  // This loan covers the visible constructor/default HeaderValue family only.
  // Actual request head encoding/copies are a separate acceptance boundary.
  let bytes=prepared.api_key().len().checked_mul(2).and_then(|n|n.checked_add(std::mem::size_of::<Inner>()+8192)).ok_or(crate::cert_transient::ResourceDenied)?;
  let credit=Arc::new(prepared.pool().reserve(bytes)?);let owner=owner.with_additional_values_credit(credit)?;
  let input=BuildInput{cpu:cpu.clone(),prepared,#[cfg(feature="native-run")]scope,owner};
  let built=crate::cert_cpu::run(cpu.clone(),cancel,move||input.execute()).await?;
  Ok(Self{inner:Arc::new(Inner{client:built.client,prepared:built.prepared,base:url::Url::parse(BASE)?,cpu,owner:built.owner})})
 }
 pub(crate) async fn create(&self,input:CreateInput,cancel:&CancellationToken)->Result<Owned<CertificateObject>>{
  let cpu=self.inner.cpu.clone();let encoded=crate::cert_cpu::run(cpu,cancel.clone(),move||input.encode()).await?;
  let reply:Owned<CertificateObject>=self.request(reqwest::Method::POST,&["certificates"],None,Some(encoded),cancel).await?;
  reply.value.validate()?;Ok(reply)
 }
 pub(crate) async fn verify_http(&self,id:&CertId,cancel:&CancellationToken)->Result<Owned<CertificateObject>>{
  let encoded=http::encode(&VerifyRequest{validation_method:"HTTP_CSR_HASH"})?;
  let reply:Owned<CertificateObject>=self.request(reqwest::Method::POST,&["certificates",id.as_str(),"challenges"],None,Some(encoded),cancel).await?;reply.value.validate()?;Ok(reply)
 }
 pub(crate) async fn get(&self,id:&CertId,cancel:&CancellationToken)->Result<Owned<CertificateObject>>{
  let reply:Owned<CertificateObject>=self.request(reqwest::Method::GET,&["certificates",id.as_str()],None,None,cancel).await?;reply.value.validate()?;Ok(reply)
 }
 pub(crate) async fn download(&self,id:&CertId,cancel:&CancellationToken)->Result<Owned<CertificateBundle>>{
  let reply:Owned<CertificateBundle>=self.request(reqwest::Method::GET,&["certificates",id.as_str(),"download","return"],None,None,cancel).await?;
  ensure!(!reply.value.certificate_crt.is_empty(),"empty ZeroSSL certificate download");Ok(reply)
 }
 pub(crate) async fn cancel(&self,id:&CertId,cancel:&CancellationToken)->Result<()>{self.success(&["certificates",id.as_str(),"cancel"],None,cancel).await}
 pub(crate) async fn revoke(&self,id:&CertId,reason:RevocationReason,cancel:&CancellationToken)->Result<()>{self.success(&["certificates",id.as_str(),"revoke"],Some(("reason",reason.wire())),cancel).await}
 async fn success(&self,path:&[&str],query:Option<(&str,&str)>,cancel:&CancellationToken)->Result<()>{
  let reply:Owned<Success>=self.request(reqwest::Method::POST,path,query,None,cancel).await?;ensure!(reply.value.success.0,"ZeroSSL API did not confirm operation");Ok(())
 }
}
/// Build on the caller's existing CPU material lane; B will pass its bound CSR.
pub(crate) struct CreateInput {domains:String,csr:Zeroizing<String>,validity:i64,_memory:Lease}
impl CreateInput {
 pub(crate) fn copy(domains:&str,csr_pem:&str,validity:i64)->Result<Self>{
  let n=domains.len().checked_add(csr_pem.len()).ok_or(crate::cert_transient::ResourceDenied)?;ensure!(n<=BODY_LIMIT,"ZeroSSL request input exceeds limit");
  let memory=chain_memory::shared().payload.reserve(n+std::mem::size_of::<Self>())?;
  fn copy(s:&str)->Result<String>{let mut v=String::new();v.try_reserve_exact(s.len()).map_err(|_|crate::cert_transient::ResourceDenied)?;v.push_str(s);Ok(v)}
  Ok(Self{domains:copy(domains)?,csr:Zeroizing::new(copy(csr_pem)?),validity,_memory:memory})
 }
 fn encode(self)->Result<http::BodyBytes>{http::encode(&CreateRequest{certificate_domains:&self.domains,certificate_csr:&self.csr,certificate_validity_days:self.validity,strict_domains:1})}
}
