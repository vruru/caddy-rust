//! Ordinary replacer formatting of the same accepted client-certificate facts.
use super::client_cert_facts::{Cache,Facts};
use anyhow::{Result,anyhow};
use base64::Engine;
use sha2::{Digest,Sha256};
use std::sync::Arc;

pub(crate) fn known(name:&str)->bool {
    let Some(field)=name.strip_prefix("http.request.tls.")else{return false};
    let field=field.to_ascii_lowercase();
    if matches!(field.as_str(),"client.fingerprint"|"client.public_key"|"client.public_key_sha256"|"client.issuer"|"client.serial"|"client.subject"|"client.certificate_pem"|"client.certificate_der_base64"){return true}
    let Some(san)=field.strip_prefix("client.san.")else{return false};
    let(kind,index)=san.split_once('.').map_or((san,None),|(kind,index)|(kind,Some(index)));
    matches!(kind,"dns_names"|"emails"|"ips"|"uris")&&index.is_none_or(|v|!v.is_empty()&&v.trim_start_matches('+').parse::<usize>().is_ok()&&!v.starts_with("++"))
}

pub(crate) fn upper(tls:bool,cache:Option<&Arc<Cache>>)->Result<usize>{
    if !tls{return Ok(1024)}
    let facts=cache.ok_or_else(||anyhow!("TLS client certificate cache missing"))?.ready().map_err(anyhow::Error::msg)?;
    Ok(facts.as_ref().map_or(1024,|f|f.der.len().saturating_mul(16).saturating_add(65536)))
}

pub(crate) fn lookup(name:&str,tls:bool,cache:Option<&Arc<Cache>>)->Option<Result<Vec<u8>>>{
    if !known(name){return None}
    Some((||{
        if !tls{return Ok(Vec::new())}
        let facts=cache.ok_or_else(||anyhow!("TLS client certificate cache missing"))?.ready().map_err(anyhow::Error::msg)?;
        let field=name["http.request.tls.".len()..].to_ascii_lowercase();
        format(&field,facts.as_ref().map(Arc::as_ref))
    })())
}

fn format(field:&str,facts:Option<&Facts>)->Result<Vec<u8>>{
    let der=facts.map_or(&[][..],|f|f.der.as_ref());
    Ok(match field{
        "client.fingerprint"=>format!("{:x}",Sha256::digest(der)).into_bytes(),
        "client.public_key"=>facts.and_then(|f|f.public_key.as_deref()).map_or_else(Vec::new,|key|key.iter().flat_map(|v|[b"0123456789abcdef"[(v>>4)as usize],b"0123456789abcdef"[(v&15)as usize]]).collect()),
        "client.public_key_sha256"=>facts.and_then(|f|f.public_key.as_deref()).map_or_else(Vec::new,|key|format!("{:x}",Sha256::digest(key)).into_bytes()),
        "client.subject"=>facts.map_or_else(Vec::new,|f|f.subject_display.as_bytes().to_vec()),
        "client.issuer"=>facts.map_or_else(Vec::new,|f|f.issuer_display.as_bytes().to_vec()),
        "client.serial"=>facts.map_or_else(||b"<nil>".to_vec(),|f|f.serial_decimal.as_bytes().to_vec()),
        "client.certificate_der_base64"=>base64::engine::general_purpose::STANDARD.encode(der).into_bytes(),
        "client.certificate_pem"=>{
            let encoded=base64::engine::general_purpose::STANDARD.encode(der);
            let mut out=b"-----BEGIN CERTIFICATE-----\n".to_vec();
            for line in encoded.as_bytes().chunks(64){out.extend_from_slice(line);out.push(b'\n');}
            out.extend_from_slice(b"-----END CERTIFICATE-----\n");out
        },
        _=>{
            let san=field.strip_prefix("client.san.").expect("recognized SAN provider");
            let(kind,index)=san.split_once('.').map_or((san,None),|(kind,index)|(kind,Some(index)));
            let count=facts.map_or(0,|f|match kind{"dns_names"=>f.dns.len(),"emails"=>f.emails.len(),"ips"=>f.ips.len(),"uris"=>f.uris.len(),_=>0});
            let value=|i:usize|->Result<String>{
                let f=facts.expect("nonempty list has certificate facts");
                Ok(match kind{
                    "dns_names"=>f.dns[i].clone(),"emails"=>f.emails[i].clone(),
                    "ips"=>{
                        let bytes=&f.ips[i];
                        if bytes.len()==4{std::net::Ipv4Addr::new(bytes[0],bytes[1],bytes[2],bytes[3]).to_string()}
                        else{crate::tls_resolver::canonical_certificate_ip(std::net::IpAddr::V6(std::net::Ipv6Addr::from(<[u8;16]>::try_from(bytes.as_slice())?)))}
                    },
                    "uris"=>super::templates::render::go_url::Url::parse(&f.uris[i]).and_then(|u|u.string()).map_err(|_|anyhow!("invalid client certificate URI value"))?,
                    _=>unreachable!(),
                })
            };
            if let Some(index)=index{
                let index=index.trim_start_matches('+').parse::<usize>()?;
                if index>=count{Vec::new()}else{value(index)?.into_bytes()}
            }else{
                let mut out=String::from("[");
                for i in 0..count{if i>0{out.push(' ')}out.push_str(&value(i)?);}
                out.push(']');out.into_bytes()
            }
        },
    })
}
