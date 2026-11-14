use crate::tls_app_config::{ConfigError,error::pointer};
use super::super::{decode::Object,schema::ObjectKind};
use serde_json::Value;
use std::sync::Arc;
#[derive(Clone)]pub(crate)struct Settings{pub(crate)names:Arc<[String]>}
impl Settings{
    pub(crate)fn parse(raw:&Value,path:&str)->Result<Self,ConfigError>{
        let root=Object::new(Some(raw),ObjectKind::Ech,path)?;
        let mut names=std::collections::BTreeSet::new();
        if let Some(configs)=root.value("configs"){
            let configs=configs.as_array().ok_or_else(||ConfigError::invalid(pointer(path,"configs")))?;
            if configs.len()>256{return Err(ConfigError::invalid(pointer(path,"configs")))}
            for(i,value)in configs.iter().enumerate(){
                let at=pointer(&pointer(path,"configs"),&i.to_string());let value=Object::new(Some(value),ObjectKind::EchConfig,&at)?;
                let name=value.string("public_name")?.trim().to_ascii_lowercase();
                if !valid_public_name(&name){return Err(ConfigError::invalid(pointer(&at,"public_name")))}names.insert(name);
            }
        }
        if let Some(publications)=root.value("publication"){
            let publications=publications.as_array().ok_or_else(||ConfigError::invalid(pointer(path,"publication")))?;
            if publications.len()>256{return Err(ConfigError::invalid(pointer(path,"publication")))}
            for(i,publication)in publications.iter().enumerate(){
                let at=pointer(&pointer(path,"publication"),&i.to_string());let object=Object::new(Some(publication),ObjectKind::EchPublication,&at)?;
                for key in["configs","domains","publishers"]{if let Some(value)=object.value(key){
                    match key{
                        "configs"|"domains"=>if !value.is_null(){let list=value.as_array().ok_or_else(||ConfigError::invalid(pointer(&at,key)))?;if list.len()>10000||list.iter().any(|v|v.as_str().is_none()){return Err(ConfigError::invalid(pointer(&at,key)))}}
                        "publishers"=>if !value.is_null(){let publishers=value.as_object().ok_or_else(||ConfigError::invalid(pointer(&at,key)))?;if !publishers.is_empty(){
                            // DNS provider modules are optional plugins, absent
                            // from the actual standard-module inventory. Never
                            // pretend a publisher without its provider can run.
                            return Err(ConfigError::unsupported(pointer(&at,key),"ech_publisher_provider"))
                        }},
                        _=>return Err(ConfigError::unknown(pointer(&at,key))),
                    }
                }}
            }
        }
        Ok(Self{names:names.into_iter().collect::<Vec<_>>().into()})
    }
}
pub(super)fn valid_public_name(name:&str)->bool{
    !name.is_empty()&&name.len()<=253&&name.is_ascii()&&name.parse::<std::net::IpAddr>().is_err()
        &&name.split('.').all(|label|!label.is_empty()&&label.len()<=63&&!label.starts_with('-')&&!label.ends_with('-')&&label.bytes().all(|b|b.is_ascii_alphanumeric()||b==b'-'))
}
