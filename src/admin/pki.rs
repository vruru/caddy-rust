//! Public CA metadata only. Private key material never crosses this boundary.
use super::AdminError;
use serde::Serialize;

#[derive(Serialize)]
pub struct PkiInfo {
    pub id: String,
    pub name: String,
    pub root_common_name: String,
    pub intermediate_common_name: String,
    pub root_certificate: String,
    pub intermediate_certificate: String,
}

pub(super) enum Route { Info(String), Certificates(String) }
pub(super) fn route(path: &str) -> Option<Route> {
    let rest=path.strip_prefix("/pki/ca/")?;
    if let Some(id)=rest.strip_suffix("/certificates") {
        valid_id(id).then(||Route::Certificates(id.to_owned()))
    } else { valid_id(rest).then(||Route::Info(rest.to_owned())) }
}
fn valid_id(id:&str)->bool {
    !id.is_empty() && id.len()<=240 && !id.chars().any(|c|c=='/'||c=='\\'||c.is_control())
}
pub(super) fn validate(info:&PkiInfo)->Result<(),AdminError> {
    let total=[&info.id,&info.name,&info.root_common_name,&info.intermediate_common_name,&info.root_certificate,&info.intermediate_certificate].into_iter().try_fold(0usize,|n,s|n.checked_add(s.len()));
    if total.is_none_or(|n|n>1<<20){return Err(AdminError::new(413,"pki_response_too_large"));}
    for certificate in [&info.root_certificate,&info.intermediate_certificate] {
        if certificate.contains("PRIVATE KEY") {return Err(AdminError::new(500,"pki_response_contains_private_material"));}
        if !certificate.contains("-----BEGIN CERTIFICATE-----") {return Err(AdminError::new(500,"invalid_pki_certificate_response"));}
    }
    Ok(())
}

pub(super) fn encode(info:&PkiInfo,pem:bool,pool:&super::byte_budget::Pool)->Result<hyper::body::Bytes,AdminError> {
    use std::io::Write;
    validate(info)?;
    const LIMIT:usize=8<<20;
    struct Count(usize);
    impl Write for Count {
        fn write(&mut self,bytes:&[u8])->std::io::Result<usize>{self.0=self.0.checked_add(bytes.len()).filter(|n|*n<=LIMIT).ok_or_else(||std::io::Error::other("PKI response limit exceeded"))?;Ok(bytes.len())}
        fn flush(&mut self)->std::io::Result<()>{Ok(())}
    }
    let size=if pem {info.intermediate_certificate.len().checked_add(info.root_certificate.len()).filter(|n|*n<=LIMIT).ok_or_else(||AdminError::new(413,"pki_response_too_large"))?} else {
        let mut count=Count(0);json(&mut count,info).map_err(|_|AdminError::new(413,"pki_response_too_large"))?;count.0
    };
    let mut output=super::byte_budget::Buffer::new(pool,size)?;
    if pem {output.write_all(info.intermediate_certificate.as_bytes()).and_then(|_|output.write_all(info.root_certificate.as_bytes())).map_err(|_|AdminError::new(500,"pki_response_encoding_failed"))?;}
    else {json(&mut output,info).map_err(|_|AdminError::new(500,"pki_response_encoding_failed"))?;}
    let(data,credit)=output.into_parts();Ok(super::byte_budget::Buffer::into_bytes(data,credit))
}

pub(super) struct GoFormatter;
impl serde_json::ser::Formatter for GoFormatter {
    fn write_string_fragment<W:std::io::Write+?Sized>(&mut self,writer:&mut W,fragment:&str)->std::io::Result<()> {
        let mut from=0;
        for (at,c) in fragment.char_indices() {
            let escaped=match c {'<'=>"\\u003c",'>'=>"\\u003e",'&'=>"\\u0026",'\u{2028}'=>"\\u2028",'\u{2029}'=>"\\u2029",_=>continue};
            writer.write_all(fragment[from..at].as_bytes())?;writer.write_all(escaped.as_bytes())?;from=at+c.len_utf8();
        }
        writer.write_all(fragment[from..].as_bytes())
    }
}
fn json<W:std::io::Write>(writer:W,info:&PkiInfo)->Result<(),serde_json::Error> {
    info.serialize(&mut serde_json::Serializer::with_formatter(writer,GoFormatter))
}
