//! Immutable business transport material. No socket, Client, Scope or executor.
use super::*;
use crate::{cert_transient::ResourceDenied,tls_policy::prepared_auth::{AuthBudget,BufferCredit}};
use std::sync::Mutex;
use zeroize::Zeroizing;
struct Loan{credit:Mutex<BufferCredit>}
impl Loan{fn resize(&self,bytes:usize)->Result<()>{self.credit.lock().map_err(|_|ResourceDenied)?.resize(bytes)}}
/// The verifier and static resolver independently retain the same actual loan,
/// so retiring the staging shell cannot refund still-used trust/credentials.
pub(crate) struct PreparedOutgoingTrust{
    binding:[u8;32],
    verifier:Arc<dyn ServerCertVerifier>,
    identity:Option<Arc<StaticIdentity>>,
    _loan:Option<Arc<Loan>>,
}
impl PreparedOutgoingTrust{
    pub(crate) fn prepare_root(tls:&ProxyTls,pool:Arc<tokio::sync::Semaphore>)->Result<Arc<Self>>{
        if let Some(saved)=&tls.prepared_trust{
            ensure!(saved.binding==tls.source_identity,"outgoing accepted TLS input differs");return Ok(saved.clone())
        }
        // Existing upstream material input bound. This is a concrete retained
        // material loan, not a claim over opaque crypto/OS heap or all RSS.
        let budget=AuthBudget::Root(pool);
        let credit=budget.reserve_buffer((64<<20)+65536)?;
        let loan=Arc::new(Loan{credit:Mutex::new(credit)});
        let(mut material,bytes)=load_counted(tls,provider_for(tls)?,false,Some(loan.clone()))?;
        loan.resize(bytes)?;material._loan=Some(loan);Ok(Arc::new(material))
    }
    pub(crate) fn binding(&self)->[u8;32]{self.binding}
    pub(super) fn verifier(&self)->Arc<dyn ServerCertVerifier>{self.verifier.clone()}
    pub(super) fn identity(&self)->Option<Arc<StaticIdentity>>{self.identity.clone()}
}
pub(super) struct StaticIdentity{
    certified:Arc<rustls::sign::CertifiedKey>,
    key:Zeroizing<rustls::pki_types::PrivateKeyDer<'static>>,
    _loan:Option<Arc<Loan>>,
}
impl std::fmt::Debug for StaticIdentity{fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{f.write_str("AcceptedStaticClientIdentity")}}
impl StaticIdentity{
    pub(super) fn chain(&self)->&[CertificateDer<'static>]{&self.certified.cert}
    pub(super) fn secret_der(&self)->&[u8]{self.key.secret_der()}
}
impl rustls::client::ResolvesClientCert for StaticIdentity{
    fn resolve(&self,_:&[&[u8]],_:&[SignatureScheme])->Option<Arc<rustls::sign::CertifiedKey>>{Some(self.certified.clone())}
    fn has_certs(&self)->bool{true}
}
struct CreditedSigningKey{inner:Arc<dyn rustls::sign::SigningKey>,_loan:Arc<Loan>}
impl std::fmt::Debug for CreditedSigningKey{fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{f.write_str("AcceptedClientSigningKey")}}
impl rustls::sign::SigningKey for CreditedSigningKey{
    fn choose_scheme(&self,offered:&[SignatureScheme])->Option<Box<dyn rustls::sign::Signer>>{self.inner.choose_scheme(offered).map(|inner|Box::new(CreditedSigner{inner,_loan:self._loan.clone()})as Box<dyn rustls::sign::Signer>)}
    fn public_key(&self)->Option<rustls::pki_types::SubjectPublicKeyInfoDer<'_>>{self.inner.public_key()}
    fn algorithm(&self)->rustls::SignatureAlgorithm{self.inner.algorithm()}
}
struct CreditedSigner{inner:Box<dyn rustls::sign::Signer>,_loan:Arc<Loan>}
impl std::fmt::Debug for CreditedSigner{fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{f.write_str("AcceptedClientSigner")}}
impl rustls::sign::Signer for CreditedSigner{
    fn sign(&self,message:&[u8])->Result<Vec<u8>,rustls::Error>{self.inner.sign(message)}
    fn scheme(&self)->SignatureScheme{self.inner.scheme()}
}
struct CreditedVerifier{inner:Arc<dyn ServerCertVerifier>,_loan:Arc<Loan>}
impl std::fmt::Debug for CreditedVerifier{fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{f.write_str("AcceptedOutgoingTrustVerifier")}}
impl ServerCertVerifier for CreditedVerifier{
    fn verify_server_cert(&self,end:&CertificateDer<'_>,chain:&[CertificateDer<'_>],name:&ServerName<'_>,ocsp:&[u8],now:UnixTime)->Result<ServerCertVerified,rustls::Error>{self.inner.verify_server_cert(end,chain,name,ocsp,now)}
    fn verify_tls12_signature(&self,msg:&[u8],cert:&CertificateDer<'_>,dss:&DigitallySignedStruct)->Result<HandshakeSignatureValid,rustls::Error>{self.inner.verify_tls12_signature(msg,cert,dss)}
    fn verify_tls13_signature(&self,msg:&[u8],cert:&CertificateDer<'_>,dss:&DigitallySignedStruct)->Result<HandshakeSignatureValid,rustls::Error>{self.inner.verify_tls13_signature(msg,cert,dss)}
    fn supported_verify_schemes(&self)->Vec<SignatureScheme>{self.inner.supported_verify_schemes()}
    fn requires_raw_public_keys(&self)->bool{self.inner.requires_raw_public_keys()}
    fn root_hint_subjects(&self)->Option<&[rustls::DistinguishedName]>{self.inner.root_hint_subjects()}
}
fn add(n:usize,v:usize)->Result<usize>{n.checked_add(v).ok_or_else(||ResourceDenied.into())}
fn mul(n:usize,v:usize)->Result<usize>{n.checked_mul(v).ok_or_else(||ResourceDenied.into())}
fn roots_bytes(roots:&rustls::RootCertStore)->Result<usize>{
    let mut n=mul(roots.roots.capacity(),std::mem::size_of::<rustls::pki_types::TrustAnchor<'static>>())?;
    for root in &roots.roots{for part in [root.subject.as_ref(),root.subject_public_key_info.as_ref(),root.name_constraints.as_ref().map_or(&[][..],|v|v.as_ref())]{n=add(n,part.len())?;}}
    Ok(n)
}
pub(super) fn load(tls:&ProxyTls,provider:Arc<rustls::crypto::CryptoProvider>,allow_empty:bool)->Result<PreparedOutgoingTrust>{Ok(load_counted(tls,provider,allow_empty,None)?.0)}
fn load_counted(tls:&ProxyTls,provider:Arc<rustls::crypto::CryptoProvider>,allow_empty:bool,loan:Option<Arc<Loan>>)->Result<(PreparedOutgoingTrust,usize)>{
    ensure!(tls.client_certificate_file.is_some()==tls.client_certificate_key_file.is_some(),"client_certificate_file and client_certificate_key_file must be set together");
    let mut budget=64*1024*1024;
    let roots=load_roots(tls,&mut budget)?;
    ensure!(allow_empty||tls.ca.is_some()||tls.insecure_skip_verify||!roots.is_empty(),"upstream trust roots unavailable");
    let mut bytes=add(roots_bytes(&roots)?,std::mem::size_of::<PreparedOutgoingTrust>()+std::mem::size_of::<Loan>()+2048)?;
    let verifier:Arc<dyn ServerCertVerifier>=if tls.insecure_skip_verify||roots.is_empty(){Arc::new(InsecureVerifier{provider:provider.clone(),skip_chain:tls.insecure_skip_verify})}
        else{rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(roots),provider.clone()).build()?};
    let verifier=crate::cert_uri_san::wrap_server_verifier(verifier)?;
    let verifier:Arc<dyn ServerCertVerifier>=if let Some(loan)=&loan{Arc::new(CreditedVerifier{inner:verifier,_loan:loan.clone()})}else{verifier};
    let identity=if let(Some(cert),Some(key))=(&tls.client_certificate_file,&tls.client_certificate_key_file){
        let certs=certificates(&read_material(cert,&mut budget)?)?;
        let pem=read_secret_material(key,&mut budget)?;
        let key=rustls_pemfile::private_key(&mut std::io::Cursor::new(pem.as_slice()))
            .map_err(|_|anyhow::anyhow!("invalid upstream client private key PEM"))?.ok_or_else(||anyhow::anyhow!("upstream client private key missing or encrypted"))?;
        bytes=add(bytes,mul(certs.capacity(),std::mem::size_of::<CertificateDer<'static>>())?)?;
        for cert in &certs{bytes=add(bytes,mul(cert.len(),2)?)?;}
        bytes=add(bytes,key.secret_der().len())?;bytes=add(bytes,std::mem::size_of::<StaticIdentity>()+std::mem::size_of::<rustls::sign::CertifiedKey>()+512)?;
        // The new retained secret copy is guarded. The original key is consumed
        // by the same provider constructor used by with_client_auth_cert.
        let retained_key=Zeroizing::new(key.clone_key());
        let mut certified=rustls::sign::CertifiedKey::from_der(certs,key,&provider)
            .map_err(|_|anyhow::anyhow!("invalid upstream client certificate/key pair"))?;
        if let Some(owner)=&loan{certified.key=Arc::new(CreditedSigningKey{inner:certified.key,_loan:owner.clone()});}
        Some(Arc::new(StaticIdentity{certified:Arc::new(certified),key:retained_key,_loan:loan.clone()}))
    }else{None};
    Ok((PreparedOutgoingTrust{binding:tls.source_identity,verifier,identity,_loan:loan},bytes))
}
