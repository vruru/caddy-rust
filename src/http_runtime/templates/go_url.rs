//! Go net/url Parse and URL.String for helper values, reusing listener URL primitives.
use crate::http_runtime::http_redirect::url as primitive;
#[derive(Clone,Default)]
pub(super) struct Url {
    pub scheme:String,pub opaque:String,pub host:String,pub user:Option<String>,pub path:String,pub raw_path:String,
    pub raw_query:String,pub force_query:bool,pub omit_host:bool,pub fragment:String,
}
impl Url {
    pub fn parse(input:&str)->Result<Self,()>{
        if input.len()>1<<20||input.bytes().any(|b|b<32||b==127){return Err(());}
        let(raw,fragment)=input.split_once('#').map_or((input,None),|(a,b)|(a,Some(b)));
        let mut url=Self::default();if let Some(fragment)=fragment{url.fragment=primitive::template_decode(fragment)?;}
        if raw=="*"{url.path=raw.into();return Ok(url);}
        let mut rest=raw;
        for(i,byte)in raw.bytes().enumerate(){
            if byte==b':'{if i==0{return Err(());}url.scheme=raw[..i].to_ascii_lowercase();rest=&raw[i+1..];break;}
            if !(byte.is_ascii_alphabetic()||i>0&&(byte.is_ascii_digit()||b"+-.".contains(&byte))){break;}
        }
        if rest.ends_with('?')&&rest.bytes().filter(|b|*b==b'?').count()==1{url.force_query=true;rest=&rest[..rest.len()-1];}
        else if let Some((path,query))=rest.split_once('?'){rest=path;url.raw_query=query.into();}
        if !rest.starts_with('/'){
            if !url.scheme.is_empty(){url.opaque=rest.into();return Ok(url);}
            if rest.split('/').next().unwrap_or_default().contains(':'){return Err(());}
        }
        if rest.starts_with("//")&&(!url.scheme.is_empty()||!rest.starts_with("///")){
            let raw=&rest[2..];let at=raw.find('/').unwrap_or(raw.len());
            (url.host,url.user)=primitive::template_authority(&url.scheme,&raw[..at])?;rest=&raw[at..];
        }else if !url.scheme.is_empty()&&rest.starts_with('/'){url.omit_host=true;}
        url.path=primitive::template_decode(rest)?;
        if primitive::template_encode_path(&url.path)!=rest{url.raw_path=rest.into();}
        Ok(url)
    }
    pub fn hostname(&self)->&str{
        let host=if let Some((name,port))=self.host.rsplit_once(':'){if port.bytes().all(|b|b.is_ascii_digit()){name}else{&self.host}}else{&self.host};
        host.strip_prefix('[').and_then(|s|s.strip_suffix(']')).unwrap_or(host)
    }
    pub fn string(&self)->Result<String,()>{
        let mut out=String::new();if !self.scheme.is_empty(){out.push_str(&self.scheme);out.push(':');}
        if !self.opaque.is_empty(){out.push_str(&self.opaque);}else{
            if (!self.scheme.is_empty()||!self.host.is_empty()||self.user.is_some())&&!(self.omit_host&&self.host.is_empty()&&self.user.is_none()){
                if !self.host.is_empty()||!self.path.is_empty()||self.user.is_some(){out.push_str("//");}
                if let Some(user)=&self.user{out.push_str(user);out.push('@');}out.push_str(&primitive::template_encode_host(&self.host));
            }
            let path=if self.raw_path.is_empty(){primitive::template_encode_path(&self.path)}else{primitive::template_path(&self.raw_path)?};
            if !path.is_empty()&&!path.starts_with('/')&&!self.host.is_empty(){out.push('/');}
            if out.is_empty()&&path.split('/').next().unwrap_or_default().contains(':'){out.push_str("./");}out.push_str(&path);
        }
        if self.force_query||!self.raw_query.is_empty(){out.push('?');out.push_str(&self.raw_query);}
        if !self.fragment.is_empty(){out.push('#');for byte in self.fragment.bytes(){if byte.is_ascii_alphanumeric()||b"-_.~$&+,/:;=?@!()*".contains(&byte){out.push(byte as char);}else{use std::fmt::Write;let _=write!(out,"%{byte:02X}");}}}
        if out.len()>1<<20{return Err(());}Ok(out)
    }
}
