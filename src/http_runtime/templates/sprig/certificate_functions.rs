//! Typed template boundary; native X.509 operations live in certificates.rs.
use super::*;
use super::certificates::{self,Certificate};
struct TemplateCertificate{cert:Arc<[u8]>,key:Arc<[u8]>,signer:Certificate}
fn equal(a:&gotmpl::Object,b:&gotmpl::Object)->bool{
    let(Some(a),Some(b))=(a.host_data::<TemplateCertificate>("sprig.certificate"),b.host_data::<TemplateCertificate>("sprig.certificate"))else{return false;};a.cert==b.cert&&a.key==b.key
}
fn value(certificate:Certificate)->R{let cert=Arc::from(certificate.cert.as_bytes());let key=Arc::from(certificate.key.as_bytes());value_raw(certificate,cert,key)}
fn value_raw(signer:Certificate,cert:Arc<[u8]>,key:Arc<[u8]>)->R{
    let bytes=cert.len().checked_add(key.len()).and_then(|n|n.checked_add(signer.cert.len())).and_then(|n|n.checked_add(signer.key.len())).and_then(|n|n.checked_add(std::mem::size_of::<TemplateCertificate>())).filter(|n|*n<=MAX_BYTES).ok_or_else(||err("certificate exceeds template byte limit"))?;
    let fields=BTreeMap::from([("Cert".into(),V::from_go_bytes(cert.clone())),("Key".into(),V::from_go_bytes(key.clone()))]);
    Ok(V::Object(Arc::new(gotmpl::Object{field_order:Some([Arc::from("Cert"),Arc::from("Key")].into()),fields,go_type:Some("sprig.certificate"),data:Some(Arc::new(TemplateCertificate{cert,key,signer})),data_bytes:bytes,equal:Some(equal),..gotmpl::Object::default()})))
}
fn extract(value:&V)->gotmpl::Result<&Certificate>{let V::Object(value)=value else{return Err(err("expected sprig.certificate"));};value.host_data::<TemplateCertificate>("sprig.certificate").map(|value|&value.signer).ok_or_else(||err("expected sprig.certificate"))}
fn strings(value:&V)->gotmpl::Result<Vec<String>>{
    let values=match value{V::Nil=>return Ok(Vec::new()),V::List(values)=>values,_=>return Err(err("expected []interface {}"))};
    if values.len()>MAX_ITEMS{return Err(err("too many certificate SAN entries"));}
    values.iter().map(|value|value.as_str().map(str::to_owned).ok_or_else(||err("certificate SAN entries must be strings"))).collect()
}
fn signer_key(value:&V)->gotmpl::Result<String>{
    certificates::private_key_signer_material(value.as_go_bytes().ok_or_else(||err("expected string"))?).map_err(|e|err(e.to_string()))
}
pub(super) fn add(m:&mut M){
    put(m,"genPrivateKey",|a|{arity(a,1,1)?;output(certificates::gen_private_key(arg_text(a,0)?).map_err(|e|err(e.to_string()))?)});
    put(m,"buildCustomCert",|a|{
        arity(a,2,2)?;
        let cert=super::encoding::decode_base64_bytes(a[0].as_go_bytes().ok_or_else(||err("expected string"))?).map_err(|_|err("unable to decode base64 certificate"))?;
        let key=super::encoding::decode_base64_bytes(a[1].as_go_bytes().ok_or_else(||err("expected string"))?).map_err(|_|err("unable to decode base64 private key"))?;
        if cert.len().saturating_add(key.len())>MAX_BYTES{return Err(err("certificate exceeds template byte limit"));}
        let signer=certificates::custom_cert_signer_material(&cert,&key).map_err(|e|err(e.to_string()))?;value_raw(signer,cert.into(),key.into())
    });
    for name in ["genCA","genCAWithKey"]{put(m,name,move|a|{let key=name.ends_with("WithKey");arity(a,if key{3}else{2},if key{3}else{2})?;let key=if key{Some(signer_key(&a[2])?)}else{None};value(certificates::gen_ca(arg_text(a,0)?,arg_int(a,1)?,key.as_deref()).map_err(|e|err(e.to_string()))?) });}
    for name in ["genSelfSignedCert","genSelfSignedCertWithKey","genSignedCert","genSignedCertWithKey"]{put(m,name,move|a|{
        let key=name.ends_with("WithKey");let signed=name.starts_with("genSigned");let count=4+usize::from(key)+usize::from(signed);arity(a,count,count)?;
        let common=arg_text(a,0)?;let ips=strings(&a[1])?;let dns=strings(&a[2])?;let days=arg_int(a,3)?;let key=if key{Some(signer_key(&a[count-1])?)}else{None};
        value(if signed{certificates::gen_signed(common,&ips,&dns,days,extract(&a[4])?,key.as_deref())}else{certificates::gen_self_signed(common,&ips,&dns,days,key.as_deref())}.map_err(|e|err(e.to_string()))?)
    });}
}
