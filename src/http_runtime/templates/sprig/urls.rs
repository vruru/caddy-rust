use super::*;
use super::super::go_url::Url;
pub(super) fn add(m:&mut M,maps:&gotmpl::MapContext){
    let maps=maps.clone();put(m,"urlParse",move|a|{
        arity(a,1,1)?;let url=Url::parse(arg_text(a,0)?).map_err(|_|err("unable to parse URL"))?;
        let fields=BTreeMap::from([("scheme".into(),V::from(url.scheme.clone())),("host".into(),V::from(url.host.clone())),("hostname".into(),V::from(url.hostname())),("path".into(),V::from(url.path)),("query".into(),V::from(url.raw_query)),("opaque".into(),V::from(url.opaque)),("fragment".into(),V::from(url.fragment)),("userinfo".into(),V::from(url.user.unwrap_or_default()))]);maps.map(fields)
    });
    put(m,"urlJoin",|a|{
        arity(a,1,1)?;let fields=match &a[0]{V::Nil=>Arc::new(BTreeMap::new()),V::Map(_)|V::SharedMap(_)=>a[0].as_map_view()?.ok_or_else(||err("expected URL dictionary"))?,_=>return Err(err("expected URL dictionary"))};
        let get=|name:&str|->gotmpl::Result<String>{fields.get(name).map_or_else(||Ok(String::new()),|v|v.as_str().map(str::to_owned).ok_or_else(||err("URL dictionary values must be strings")))};
        let user=get("userinfo")?;let user=if user.is_empty(){None}else{Url::parse(&format!("proto://{user}@host")).map_err(|_|err("invalid URL userinfo"))?.user};
        let url=Url{scheme:get("scheme")?,host:get("host")?,path:get("path")?,raw_query:get("query")?,opaque:get("opaque")?,fragment:get("fragment")?,user,..Url::default()};output(url.string().map_err(|_|err("unable to join URL"))?)
    });
}
