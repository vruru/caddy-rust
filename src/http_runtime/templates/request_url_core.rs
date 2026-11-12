// Go 1.27.3 net/url behavior. Copyright 2009 The Go Authors (BSD-3-Clause).
// Owned byte parsing; callers admit peak allocation and work before entry.
use super::{Facts,User,RenderResult,error,decode,decode_host,escape_path,escape_fragment,escaped_path};
use std::sync::Arc;
#[path="request_url_paths.rs"]mod paths;
pub(super) fn set_path(facts:&mut Facts,raw:&[u8])->RenderResult<()>{
    let path=decode(raw).map_err(|_|error("invalid URL path escape"))?;
    let hint=if escape_path(&path)==raw{Vec::new()}else{raw.to_vec()};facts.path=path;facts.raw_path=hint;Ok(())
}
fn set_fragment(facts:&mut Facts,raw:&[u8])->RenderResult<()>{
    let fragment=decode(raw).map_err(|_|error("invalid URL fragment escape"))?;
    let hint=if escape_fragment(&fragment)==raw{Vec::new()}else{raw.to_vec()};facts.fragment=fragment;facts.raw_fragment=hint;Ok(())
}
fn scheme(raw:&[u8])->RenderResult<(&[u8],&[u8])>{
    for(i,b)in raw.iter().copied().enumerate(){
        if b.is_ascii_alphabetic(){continue;}
        if b.is_ascii_digit()||b"+-.".contains(&b){if i==0{return Ok((b"",raw));}continue;}
        if b==b':'{if i==0{return Err(error("missing protocol scheme"));}return Ok((&raw[..i],&raw[i+1..]));}
        return Ok((b"",raw));
    }Ok((b"",raw))
}
fn split<'a>(raw:&'a[u8],delimiter:u8)->(&'a[u8],Option<&'a[u8]>){raw.iter().position(|b|*b==delimiter).map_or((raw,None),|i|(&raw[..i],Some(&raw[i+1..])))}
pub(super) fn authority(facts:&mut Facts,raw:&[u8])->RenderResult<()>{
    let(user,host)=raw.iter().rposition(|b|*b==b'@').map_or((None,raw),|i|(Some(&raw[..i]),&raw[i+1..]));
    facts.host=decode_host(&facts.scheme,host).map_err(|_|error("invalid URL host"))?;
    if let Some(user)=user{
        if !user.iter().all(|b|b.is_ascii_alphanumeric()||b"-._:~!$&'()*+,;=%@".contains(b)){return Err(error("invalid URL userinfo"));}
        let(username,password)=split(user,b':');facts.user=Some(Arc::new(User{username:decode(username).map_err(|_|error("invalid URL user escape"))?,password:password.map(decode).transpose().map_err(|_|error("invalid URL password escape"))?}));
    }Ok(())
}
pub(super) fn parse(raw:&[u8])->RenderResult<Facts>{
    let(raw,fragment)=split(raw,b'#');if raw.iter().any(|b|*b<32||*b==127){return Err(error("invalid control character in URL"));}
    let mut facts=Facts::empty();
    if raw==b"*"{facts.path=b"*".to_vec();}else{
        let(scheme,mut rest)=scheme(raw)?;facts.scheme=scheme.iter().map(u8::to_ascii_lowercase).collect();
        if rest.ends_with(b"?")&&rest.iter().filter(|b|**b==b'?').count()==1{facts.force_query=true;rest=&rest[..rest.len()-1];}else{let(before,query)=split(rest,b'?');rest=before;facts.query=query.unwrap_or_default().to_vec();}
        if !rest.starts_with(b"/"){
            if !facts.scheme.is_empty(){facts.opaque=rest.to_vec();if let Some(fragment)=fragment{if !fragment.is_empty(){set_fragment(&mut facts,fragment)?;}}return Ok(facts);}
            if rest.split(|b|*b==b'/').next().is_some_and(|part|part.contains(&b':')){return Err(error("first URL path segment contains colon"));}
        }
        if (!facts.scheme.is_empty()||!rest.starts_with(b"///"))&&rest.starts_with(b"//"){
            let after=&rest[2..];let end=after.iter().position(|b|*b==b'/').unwrap_or(after.len());authority(&mut facts,&after[..end])?;rest=&after[end..];
        }else if !facts.scheme.is_empty()&&rest.starts_with(b"/"){facts.omit_host=true;}
        set_path(&mut facts,rest)?;
    }
    if let Some(fragment)=fragment{if !fragment.is_empty(){set_fragment(&mut facts,fragment)?;}}Ok(facts)
}
pub(super) fn resolve(base:&Facts,reference:&Facts)->RenderResult<Facts>{
    let mut url=reference.clone();if reference.scheme.is_empty(){url.scheme=base.scheme.clone();}
    if !reference.scheme.is_empty()||!reference.host.is_empty()||reference.user.is_some(){set_path(&mut url,&paths::resolve_path(&escaped_path(reference),b""))?;return Ok(url);}
    if !reference.opaque.is_empty(){url.user=None;url.host.clear();url.path.clear();return Ok(url);}
    if reference.path.is_empty()&&!reference.force_query&&reference.query.is_empty(){url.query=base.query.clone();if reference.fragment.is_empty(){url.fragment=base.fragment.clone();url.raw_fragment=base.raw_fragment.clone();}}
    if reference.path.is_empty()&&!base.opaque.is_empty(){url.opaque=base.opaque.clone();url.user=None;url.host.clear();url.path.clear();return Ok(url);}
    url.host=base.host.clone();url.user=base.user.clone();set_path(&mut url,&paths::resolve_path(&escaped_path(base),&escaped_path(reference)))?;Ok(url)
}
pub(super) fn join(base:&Facts,parts:&[&[u8]])->Facts{
    let escaped=escaped_path(base);let relative=!escaped.starts_with(b"/");let mut first=Vec::new();if relative{first.push(b'/');}first.extend_from_slice(&escaped);
    let mut all=Vec::with_capacity(parts.len()+1);all.push(first.as_slice());all.extend_from_slice(parts);let trailing=all.last().is_some_and(|part|part.ends_with(b"/"));
    let mut path=paths::clean_join(&all);if relative{path.remove(0);}if trailing&&!path.ends_with(b"/"){path.push(b'/');}
    let mut url=base.clone();let _=set_path(&mut url,&path);url
}
