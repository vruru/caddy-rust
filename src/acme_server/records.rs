use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use serde_json::{Value, value::RawValue};
use std::collections::BTreeMap;

// serde's derived flatten buffers values through ContentDeserializer, which
// cannot preserve RawValue fragments. Read the raw map directly instead, then
// decode only known fields. Unknown large numbers/formatting remain exact.
type RawFields = BTreeMap<String, Box<RawValue>>;
fn take<T: serde::de::DeserializeOwned + Default, E: serde::de::Error>(
    raw: &mut RawFields,
    name: &str,
) -> Result<T, E> {
    match raw.remove(name) {
        None => Ok(T::default()),
        Some(value) if value.get() == "null" => Ok(T::default()),
        Some(value) => serde_json::from_str(value.get()).map_err(E::custom),
    }
}
fn take_time<T: From<String>, E: serde::de::Error>(
    raw: &mut RawFields,
    name: &str,
) -> Result<T, E> {
    match raw.remove(name) {
        None => Ok(zero_time().into()),
        Some(value) if value.get() == "null" => Ok(zero_time().into()),
        Some(value) => serde_json::from_str::<String>(value.get())
            .map(T::from)
            .map_err(E::custom),
    }
}
macro_rules! raw_record {
    ($name:ident {$($field:ident:$key:literal=>$parser:ident),* $(,)?})=>{
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D:serde::Deserializer<'de>>(deserializer:D)->Result<Self,D::Error> {
                let mut raw=RawFields::deserialize(deserializer)?;
                Ok(Self{$($field:$parser::<_,D::Error>(&mut raw,$key)?,)* unknown:raw})
            }
        }
    }
}
raw_record!(Identifier {kind:"type"=>take,value:"value"=>take});
raw_record!(DbAccount {id:"id"=>take,key:"key"=>take,contact:"contact"=>take,status:"status"=>take,
    location_prefix:"locationPrefix"=>take,provisioner_id:"provisionerID"=>take,provisioner_name:"provisionerName"=>take,
    created_at:"createdAt"=>take_time,deactivated_at:"deactivatedAt"=>take_time});
raw_record!(DbOrder {id:"id"=>take,account_id:"accountID"=>take,provisioner_id:"provisionerID"=>take,
    identifiers:"identifiers"=>take,authorization_ids:"authorizationIDs"=>take,status:"status"=>take,
    not_before:"notBefore"=>take_time,not_after:"notAfter"=>take_time,created_at:"createdAt"=>take_time,
    expires_at:"expiresAt"=>take_time,certificate:"certificate"=>take,error:"error"=>take});
raw_record!(DbAuthz {id:"id"=>take,account_id:"accountID"=>take,identifier:"identifier"=>take,status:"status"=>take,
    token:"token"=>take,fingerprint:"fingerprint"=>take,challenge_ids:"challengeIDs"=>take,wildcard:"wildcard"=>take,
    created_at:"createdAt"=>take_time,expires_at:"expiresAt"=>take_time,error:"error"=>take});
raw_record!(DbChallenge {id:"id"=>take,account_id:"accountID"=>take,kind:"type"=>take,status:"status"=>take,
    token:"token"=>take,value:"value"=>take,target:"target"=>take,validated_at:"validatedAt"=>take,
    created_at:"createdAt"=>take_time,error:"error"=>take});
raw_record!(DbCert {id:"id"=>take,created_at:"createdAt"=>take_time,account_id:"accountID"=>take,order_id:"orderID"=>take,
    leaf:"leaf"=>take,intermediates:"intermediates"=>take});
raw_record!(DbNonce {id:"ID"=>take,created_at:"CreatedAt"=>take_time,deleted_at:"DeletedAt"=>take_time});
raw_record!(SerialIndex {serial:"serial"=>take,certificate_id:"certificateID"=>take});
raw_record!(ProvisionerData {id:"id"=>take,name:"name"=>take,kind:"type"=>take});
raw_record!(CertificateData {provisioner:"provisioner"=>take});
raw_record!(RevokedInfo {serial:"Serial"=>take,provisioner_id:"ProvisionerID"=>take,reason_code:"ReasonCode"=>take,
    reason:"Reason"=>take,revoked_at:"RevokedAt"=>take_time,expires_at:"ExpiresAt"=>take_time,token_id:"TokenID"=>take,
    mtls:"MTLS"=>take,acme:"ACME"=>take});

fn zero_time() -> String {
    "0001-01-01T00:00:00Z".to_string()
}

fn time_or_zero<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let opt: Option<String> = Option::deserialize(deserializer)?;
    match opt {
        Some(s) => Ok(s),
        None => Ok(zero_time()),
    }
}

fn is_none_or_empty(v: &Option<Vec<String>>) -> bool {
    match v {
        None => true,
        Some(vec) => vec.is_empty(),
    }
}

fn is_empty_str(v: &String) -> bool {
    v.is_empty()
}

fn is_null_value(v: &Value) -> bool {
    v.is_null()
}

#[derive(Serialize, Debug, Clone)]
pub struct Identifier {
    #[serde(rename = "type", default)]
    pub kind: String,
    #[serde(default)]
    pub value: String,
    #[serde(flatten)]
    pub unknown: BTreeMap<String, Box<RawValue>>,
}

impl Default for Identifier {
    fn default() -> Self {
        Self {
            kind: String::new(),
            value: String::new(),
            unknown: BTreeMap::new(),
        }
    }
}

#[derive(Serialize, Debug, Clone)]
pub struct DbAccount {
    #[serde(rename = "id", default)]
    pub id: String,
    #[serde(rename = "key", default)]
    pub key: Value,
    #[serde(rename = "contact", default, skip_serializing_if = "is_none_or_empty")]
    pub contact: Option<Vec<String>>,
    #[serde(rename = "status", default)]
    pub status: String,
    #[serde(rename = "locationPrefix", default)]
    pub location_prefix: String,
    #[serde(
        rename = "provisionerID",
        default,
        skip_serializing_if = "is_empty_str"
    )]
    pub provisioner_id: String,
    #[serde(rename = "provisionerName", default)]
    pub provisioner_name: String,
    #[serde(
        rename = "createdAt",
        default = "zero_time",
        deserialize_with = "time_or_zero"
    )]
    pub created_at: String,
    #[serde(
        rename = "deactivatedAt",
        default = "zero_time",
        deserialize_with = "time_or_zero"
    )]
    pub deactivated_at: String,
    #[serde(flatten)]
    pub unknown: BTreeMap<String, Box<RawValue>>,
}

#[derive(Serialize, Debug, Clone)]
pub struct DbOrder {
    #[serde(rename = "id", default)]
    pub id: String,
    #[serde(rename = "accountID", default)]
    pub account_id: String,
    #[serde(rename = "provisionerID", default)]
    pub provisioner_id: String,
    #[serde(rename = "identifiers", default)]
    pub identifiers: Option<Vec<Identifier>>,
    #[serde(rename = "authorizationIDs", default)]
    pub authorization_ids: Option<Vec<String>>,
    #[serde(rename = "status", default)]
    pub status: String,
    #[serde(
        rename = "notBefore",
        default = "zero_time",
        deserialize_with = "time_or_zero"
    )]
    pub not_before: String,
    #[serde(
        rename = "notAfter",
        default = "zero_time",
        deserialize_with = "time_or_zero"
    )]
    pub not_after: String,
    #[serde(
        rename = "createdAt",
        default = "zero_time",
        deserialize_with = "time_or_zero"
    )]
    pub created_at: String,
    #[serde(
        rename = "expiresAt",
        default = "zero_time",
        deserialize_with = "time_or_zero"
    )]
    pub expires_at: String,
    #[serde(rename = "certificate", default, skip_serializing_if = "is_empty_str")]
    pub certificate: String,
    #[serde(rename = "error", default, skip_serializing_if = "is_null_value")]
    pub error: Value,
    #[serde(flatten)]
    pub unknown: BTreeMap<String, Box<RawValue>>,
}

#[derive(Serialize, Debug, Clone)]
pub struct DbAuthz {
    #[serde(rename = "id", default)]
    pub id: String,
    #[serde(rename = "accountID", default)]
    pub account_id: String,
    #[serde(rename = "identifier", default)]
    pub identifier: Identifier,
    #[serde(rename = "status", default)]
    pub status: String,
    #[serde(rename = "token", default)]
    pub token: String,
    #[serde(rename = "fingerprint", default, skip_serializing_if = "is_empty_str")]
    pub fingerprint: String,
    #[serde(rename = "challengeIDs", default)]
    pub challenge_ids: Option<Vec<String>>,
    #[serde(rename = "wildcard", default)]
    pub wildcard: bool,
    #[serde(
        rename = "createdAt",
        default = "zero_time",
        deserialize_with = "time_or_zero"
    )]
    pub created_at: String,
    #[serde(
        rename = "expiresAt",
        default = "zero_time",
        deserialize_with = "time_or_zero"
    )]
    pub expires_at: String,
    #[serde(rename = "error", default)]
    pub error: Value,
    #[serde(flatten)]
    pub unknown: BTreeMap<String, Box<RawValue>>,
}

#[derive(Serialize, Debug, Clone)]
pub struct DbChallenge {
    #[serde(rename = "id", default)]
    pub id: String,
    #[serde(rename = "accountID", default)]
    pub account_id: String,
    #[serde(rename = "type", default)]
    pub kind: String,
    #[serde(rename = "status", default)]
    pub status: String,
    #[serde(rename = "token", default)]
    pub token: String,
    #[serde(rename = "value", default)]
    pub value: String,
    #[serde(rename = "target", default, skip_serializing_if = "is_empty_str")]
    pub target: String,
    #[serde(rename = "validatedAt", default)]
    pub validated_at: String,
    #[serde(
        rename = "createdAt",
        default = "zero_time",
        deserialize_with = "time_or_zero"
    )]
    pub created_at: String,
    #[serde(rename = "error", default)]
    pub error: Value,
    #[serde(flatten)]
    pub unknown: BTreeMap<String, Box<RawValue>>,
}

#[derive(Serialize, Debug, Clone)]
pub struct DbCert {
    #[serde(rename = "id", default)]
    pub id: String,
    #[serde(
        rename = "createdAt",
        default = "zero_time",
        deserialize_with = "time_or_zero"
    )]
    pub created_at: String,
    #[serde(rename = "accountID", default)]
    pub account_id: String,
    #[serde(rename = "orderID", default)]
    pub order_id: String,
    #[serde(rename = "leaf", default)]
    pub leaf: GoBytes,
    #[serde(rename = "intermediates", default)]
    pub intermediates: GoBytes,
    #[serde(flatten)]
    pub unknown: BTreeMap<String, Box<RawValue>>,
}

#[derive(Serialize, Debug, Clone)]
pub struct DbNonce {
    #[serde(rename = "ID", default)]
    pub id: String,
    #[serde(
        rename = "CreatedAt",
        default = "zero_time",
        deserialize_with = "time_or_zero"
    )]
    pub created_at: String,
    #[serde(
        rename = "DeletedAt",
        default = "zero_time",
        deserialize_with = "time_or_zero"
    )]
    pub deleted_at: String,
    #[serde(flatten)]
    pub unknown: BTreeMap<String, Box<RawValue>>,
}

#[derive(Serialize, Debug, Clone)]
pub struct SerialIndex {
    #[serde(rename = "serial", default)]
    pub serial: String,
    #[serde(rename = "certificateID", default)]
    pub certificate_id: String,
    #[serde(flatten)]
    pub unknown: BTreeMap<String, Box<RawValue>>,
}

#[derive(Serialize, Debug, Clone)]
pub struct RevokedInfo {
    #[serde(rename = "Serial", default)]
    pub serial: String,
    #[serde(rename = "ProvisionerID", default)]
    pub provisioner_id: String,
    #[serde(rename = "ReasonCode", default)]
    pub reason_code: i64,
    #[serde(rename = "Reason", default)]
    pub reason: String,
    #[serde(
        rename = "RevokedAt",
        default = "zero_time",
        deserialize_with = "time_or_zero"
    )]
    pub revoked_at: String,
    #[serde(
        rename = "ExpiresAt",
        default = "zero_time",
        deserialize_with = "time_or_zero"
    )]
    pub expires_at: String,
    #[serde(rename = "TokenID", default)]
    pub token_id: String,
    #[serde(rename = "MTLS", default)]
    pub mtls: bool,
    #[serde(rename = "ACME", default)]
    pub acme: bool,
    #[serde(flatten)]
    pub unknown: BTreeMap<String, Box<RawValue>>,
}

#[derive(Debug, Clone)]
pub struct GoBytes(pub Option<Vec<u8>>);

impl Serialize for GoBytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match &self.0 {
            None => serializer.serialize_none(),
            Some(bytes) => {
                let encoded = STANDARD.encode(bytes);
                serializer.serialize_str(&encoded)
            }
        }
    }
}

impl<'de> Deserialize<'de> for GoBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let opt_str: Option<String> = Option::deserialize(deserializer)?;
        match opt_str {
            None => Ok(GoBytes(None)),
            Some(s) => {
                if s.is_empty() {
                    return Ok(GoBytes(Some(vec![])));
                }
                match STANDARD.decode(&s) {
                    Ok(bytes) => Ok(GoBytes(Some(bytes))),
                    Err(_) => Err(serde::de::Error::custom("invalid base64")),
                }
            }
        }
    }
}

impl Default for GoBytes {
    fn default() -> Self {
        GoBytes(None)
    }
}

#[derive(Serialize, Deserialize, Debug, Default)]
#[serde(transparent)]
pub(super) struct OrderIndex(pub Option<Vec<String>>);
#[derive(Serialize, Debug, Default)]
pub(super) struct ProvisionerData {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(flatten)]
    pub unknown: BTreeMap<String, Box<RawValue>>,
}
#[derive(Serialize, Debug, Default)]
pub(super) struct CertificateData {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provisioner: Option<ProvisionerData>,
    #[serde(flatten)]
    pub unknown: BTreeMap<String, Box<RawValue>>,
}
mod sealed {
    pub trait Sealed {}
}
/// Only native record DTOs can enter the storage serializer. This is not an
/// admission path for an opaque host's arbitrary Serialize implementation.
pub(super) trait Record: sealed::Sealed + Serialize + serde::de::DeserializeOwned {
    fn scratch_bytes(&self) -> Option<usize> {
        Some(0)
    }
}
macro_rules! plain_record {($($t:ty),*)=>{$(impl sealed::Sealed for $t {} impl Record for $t {})*};}
plain_record!(
    DbAccount,
    DbOrder,
    DbAuthz,
    DbChallenge,
    DbNonce,
    SerialIndex,
    RevokedInfo,
    OrderIndex,
    CertificateData
);
impl sealed::Sealed for DbCert {}
impl Record for DbCert {
    fn scratch_bytes(&self) -> Option<usize> {
        let leaf = self.leaf.0.as_ref().map_or(0, Vec::len);
        let chain = self.intermediates.0.as_ref().map_or(0, Vec::len);
        // GoBytes' base64 scratch precedes the bounded output writer.
        leaf.div_ceil(3)
            .checked_mul(4)?
            .checked_add(chain.div_ceil(3).checked_mul(4)?)
    }
}
