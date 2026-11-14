//! Pinned ZeroSSL v0.1.6 JSON shapes. External fields never enter Debug output.
use serde::{Deserialize,Serialize};
use std::{collections::BTreeMap,fmt};
#[derive(Default,Clone,Copy,Serialize)]
pub(crate) struct AnyBool(pub bool);
impl<'de> Deserialize<'de> for AnyBool {
 fn deserialize<D:serde::Deserializer<'de>>(d:D)->Result<Self,D::Error>{
  struct V;
  impl<'de> serde::de::Visitor<'de> for V {
   type Value=AnyBool;
   fn expecting(&self,f:&mut fmt::Formatter<'_>)->fmt::Result{f.write_str("JSON value")}
   fn visit_bool<E:serde::de::Error>(self,v:bool)->Result<AnyBool,E>{Ok(AnyBool(v))}
   fn visit_u64<E:serde::de::Error>(self,v:u64)->Result<AnyBool,E>{Ok(AnyBool(v==1))}
   fn visit_i64<E:serde::de::Error>(self,v:i64)->Result<AnyBool,E>{Ok(AnyBool(v==1))}
   fn visit_f64<E:serde::de::Error>(self,_:f64)->Result<AnyBool,E>{Ok(AnyBool(false))}
   fn visit_str<E:serde::de::Error>(self,v:&str)->Result<AnyBool,E>{Ok(AnyBool(v.eq_ignore_ascii_case("true")||v=="1"||v.eq_ignore_ascii_case("yes")||v.eq_ignore_ascii_case("y")))}
   fn visit_unit<E:serde::de::Error>(self)->Result<AnyBool,E>{Ok(AnyBool(false))}
   fn visit_seq<A:serde::de::SeqAccess<'de>>(self,mut a:A)->Result<AnyBool,A::Error>{while a.next_element::<serde::de::IgnoredAny>()?.is_some(){}Ok(AnyBool(false))}
   fn visit_map<A:serde::de::MapAccess<'de>>(self,mut a:A)->Result<AnyBool,A::Error>{while a.next_entry::<serde::de::IgnoredAny,serde::de::IgnoredAny>()?.is_some(){}Ok(AnyBool(false))}
  }
  d.deserialize_any(V)
 }
}
/// Caller-owned ID. It is opaque, not a filesystem name or a trusted URL.
pub(crate) struct CertId(String);
impl CertId {
 pub(crate) fn parse(value:String)->anyhow::Result<Self>{anyhow::ensure!(!value.is_empty()&&value.len()<=4096&&!value.bytes().any(|b|b<32||b==127),"invalid ZeroSSL certificate ID");Ok(Self(value))}
 pub(crate) fn as_str(&self)->&str{&self.0}
}
#[derive(Default,Deserialize,Serialize)]
#[serde(default)]
pub(crate) struct ValidationObject {
 pub file_validation_url_http:String,pub file_validation_url_https:String,
 pub file_validation_content:Vec<String>,pub cname_validation_p1:String,pub cname_validation_p2:String,
}
#[derive(Default,Deserialize,Serialize)]
#[serde(default)]
pub(crate) struct Validation {
 pub email_validation:BTreeMap<String,Vec<String>>,
 pub other_methods:BTreeMap<String,ValidationObject>,
}
#[derive(Default,Deserialize,Serialize)]
#[serde(default)]
pub(crate) struct CertificateObject {
 pub id:String,#[serde(rename="type")]pub kind:String,pub common_name:String,pub additional_domains:String,
 pub created:String,pub expires:String,pub last_updated:String,pub status:String,
 pub validation_type:Option<String>,pub validation_emails:Option<String>,pub replacement_for:String,
 pub fingerprint_sha1:Option<String>,pub brand_validation:serde_json::Value,pub validation:Option<Validation>,
 pub signature_algorithm_properties:serde_json::Value,pub ca_certificate_id:i64,
}
impl CertificateObject {
 pub(crate) fn validate(&self)->anyhow::Result<()>{
  anyhow::ensure!(!self.id.is_empty()&&self.id.len()<=4096&&!self.id.bytes().any(|b|b<32||b==127),"invalid ZeroSSL certificate ID");
  anyhow::ensure!(!self.status.is_empty()&&self.status.len()<=128,"missing ZeroSSL certificate status");Ok(())
 }
}
#[derive(Default,Deserialize,Serialize)]
#[serde(default)]
pub(crate) struct CertificateBundle {
 #[serde(rename="certificate.crt")]pub certificate_crt:String,
 #[serde(rename="ca_bundle.crt")]pub ca_bundle_crt:String,
}
#[derive(Serialize)]
pub(crate) struct CreateRequest<'a> {
 pub certificate_domains:&'a str,pub certificate_csr:&'a str,
 #[serde(skip_serializing_if="is_zero")]pub certificate_validity_days:i64,
 pub strict_domains:u8,
}
fn is_zero(value:&i64)->bool{*value==0}
#[derive(Serialize)]
pub(crate) struct VerifyRequest {pub validation_method:&'static str}
#[derive(Default,Deserialize)]
#[serde(default)]
pub(crate) struct Success {pub success:AnyBool}
#[derive(Default,Deserialize)]
#[serde(default)]
pub(crate) struct ApiReplyError {pub success:Option<AnyBool>,pub error:ApiErrorInfo}
#[derive(Default,Deserialize)]
#[serde(default)]
pub(crate) struct ApiErrorInfo {pub code:i64,#[serde(rename="type")]pub kind:String,pub details:serde_json::Value}
/// Raw external strings are available to closed callers but never logged here.
pub(crate) struct ApiError {
 pub http_status:u16,pub info:ApiErrorInfo,
 pub(super) _memory:crate::acme_wire::chain_memory::Lease,
}
impl fmt::Debug for ApiError {fn fmt(&self,f:&mut fmt::Formatter<'_>)->fmt::Result{f.debug_struct("ZeroSslApiError").field("status",&self.http_status).field("code",&self.info.code).finish()}}
impl fmt::Display for ApiError {fn fmt(&self,f:&mut fmt::Formatter<'_>)->fmt::Result{write!(f,"ZeroSSL API rejected request (HTTP {}, code {})",self.http_status,self.info.code)}}
impl std::error::Error for ApiError{}
#[derive(Clone,Copy,PartialEq,Eq)]
pub(crate) enum RevocationReason {Unspecified,KeyCompromise,AffiliationChanged,Superseded,CessationOfOperation}
impl RevocationReason {
 pub(crate) fn from_code(code:u8)->anyhow::Result<Self>{Ok(match code {0=>Self::Unspecified,1=>Self::KeyCompromise,3=>Self::AffiliationChanged,4=>Self::Superseded,5=>Self::CessationOfOperation,_=>anyhow::bail!("unsupported ZeroSSL revocation reason")})}
 pub(crate) fn wire(self)->&'static str{match self {Self::Unspecified=>"unspecified",Self::KeyCompromise=>"keyCompromise",Self::AffiliationChanged=>"affiliationChanged",Self::Superseded=>"Superseded",Self::CessationOfOperation=>"cessationOfOperation"}}
}
