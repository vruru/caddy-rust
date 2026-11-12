//! Automatic HTTP redirects preserve explicit routes and canonical TLS ports.
use std::{collections::BTreeMap,net::SocketAddr};
use crate::http_config::types::{Route,Matcher,Handler,HeaderOps};
#[derive(Default)]
pub(super) struct Domains(BTreeMap<String,Vec<SocketAddr>>);
impl Domains {
    pub(super) fn record(&mut self,names:&[String],addresses:&[SocketAddr],https_port:u16){
        for name in names.iter().map(String::as_str).chain(names.is_empty().then_some("")) {
            for address in addresses {
                let selected=self.0.entry(name.to_owned()).or_default();
                if let Some(first)=selected.first() {
                    if first.port()!=address.port() {
                        if address.port()!=https_port {continue;}
                        selected.clear();
                    }
                }
                if !selected.contains(address){selected.push(*address);}
            }
        }
    }
    pub(super) fn routes(self,http_port:u16,https_port:u16)->BTreeMap<SocketAddr,Vec<Route>>{
        let mut by_target=BTreeMap::<SocketAddr,Vec<String>>::new();
        for (name,addresses) in self.0{for address in addresses{by_target.entry(address).or_default().push(name.clone());}}
        let mut listeners=BTreeMap::<SocketAddr,Vec<(String,SocketAddr,Route)>>::new();
        for (target,names) in by_target {
            let host=names.first().cloned().unwrap_or_default();
            let mut matchers=vec![Matcher::Protocol("http".into())];
            if names.len()!=1||!host.is_empty(){matchers.push(Matcher::Host(names));}
            listeners.entry(SocketAddr::new(target.ip(),http_port)).or_default()
                .push((host,target,make(http_port,https_port,target.port(),matchers)));
        }
        listeners.into_iter().map(|(address,mut routes)|{
            routes.sort_by(|(a,at,_),(b,bt,_)|a.is_empty().cmp(&b.is_empty())
                .then_with(||a.contains('*').cmp(&b.contains('*')))
                .then_with(||b.len().cmp(&a.len())).then_with(||a.cmp(b))
                .then_with(||at.cmp(bt)));
            (address,routes.into_iter().map(|(_,_,route)|route).collect())
        }).collect()
    }
}
pub(super) fn fallback(http_port:u16,https_port:u16)->Route{
    make(http_port,https_port,https_port,vec![Matcher::Protocol("http".into())])
}
fn make(http_port:u16,https_port:u16,target:u16,matchers:Vec<Matcher>)->Route{
    let port=if [80,443,http_port,https_port].contains(&target){String::new()}else{format!(":{target}")};
    let location=format!("https://{{http.request.host}}{port}{{http.request.uri}}");
    Route { metrics: true,trace_modules:vec![super::handler_trace::Module::redirect(&location)],group:None,
        matchers:vec![matchers],handlers:vec![Handler::StaticResponse{
            status:"308".into(),body:String::new(),headers:HeaderOps{
                set:vec![("Location".into(),vec![location])],..Default::default()},close:true}],
        terminal:true}
}
