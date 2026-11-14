use anyhow::{Result,anyhow};
use crate::tls_policy::prepared_auth::{SourceMemory,PreparedCa,AuthBudget};
use serde_json::Value;
use std::sync::Arc;

use crate::http_config::PreparedConfig;
use crate::http_config::types::{Handler, ResponseRoute, Route};

fn visit_routes<F>(routes: &[Route], f: &mut F) -> Result<()>
where
    F: FnMut(&Value) -> Result<()> + ?Sized,
{
    for route in routes {
        visit_route(route, f)?;
    }
    Ok(())
}

fn visit_route<F>(route: &Route, f: &mut F) -> Result<()>
where
    F: FnMut(&Value) -> Result<()> + ?Sized,
{
    for handler in &route.handlers {
        visit_handler(handler, f)?;
    }
    Ok(())
}

fn visit_handler<F>(handler: &Handler, f: &mut F) -> Result<()>
where
    F: FnMut(&Value) -> Result<()> + ?Sized,
{
    match handler {
        Handler::Subroute { routes, errors, .. } => {
            visit_routes(routes, f)?;
            visit_routes(errors, f)?;
        }
        Handler::Intercept(response_routes) => {
            visit_response_routes(response_routes, f)?;
        }
        Handler::ReverseProxy(proxy) => {
            if let Some(ref tls) = proxy.tls {
                if tls.prepared_trust.is_none() && let Some(ca) = tls.prepared_ca.as_ref().map(|v|&v.value).or(tls.ca.as_ref()) {
                    f(ca)?;
                }
            }
            visit_response_routes(&proxy.response_routes, f)?;
        }
        _ => {}
    }
    Ok(())
}

fn visit_response_routes<F>(routes: &[ResponseRoute], f: &mut F) -> Result<()>
where
    F: FnMut(&Value) -> Result<()> + ?Sized,
{
    for rr in routes {
        if let Some(ref inner_routes) = rr.routes {
            visit_routes(inner_routes, f)?;
        }
    }
    Ok(())
}

fn visit_server<F>(server: &crate::http_config::ServerConfig, f: &mut F) -> Result<()>
where
    F: FnMut(&Value) -> Result<()> + ?Sized,
{
    for policy in &server.tls_policies {
        if policy.prepared_client_auth.is_some(){continue}
        if let Some(ca) = policy.prepared_ca.as_ref().map(|v|&v.value).or_else(||policy.client_auth.as_ref().and_then(|ca| ca.ca.as_ref())) {
            f(ca)?;
        }
    }
    visit_routes(&server.routes, f)?;
    visit_routes(&server.errors, f)?;
    for route in server.named_routes.values() {
        visit_route(route, f)?;
    }
    Ok(())
}

pub(super) fn each_root(
    config: &PreparedConfig,
    f: &mut impl FnMut(&Value) -> Result<()>,
) -> Result<()> {
    for server in &config.servers {
        visit_server(server.as_ref(), f)?;
    }
    Ok(())
}

fn visit_routes_mut<F>(routes: &mut [Route], f: &mut F) -> Result<()>
where
    F: FnMut(&mut Value,&mut SourceMemory) -> Result<()> + ?Sized,
{
    for route in routes {
        visit_route_mut(route, f)?;
    }
    Ok(())
}

fn visit_route_mut<F>(route: &mut Route, f: &mut F) -> Result<()>
where
    F: FnMut(&mut Value,&mut SourceMemory) -> Result<()> + ?Sized,
{
    for handler in &mut route.handlers {
        visit_handler_mut(handler, f)?;
    }
    Ok(())
}

fn visit_handler_mut<F>(handler: &mut Handler, f: &mut F) -> Result<()>
where
    F: FnMut(&mut Value,&mut SourceMemory) -> Result<()> + ?Sized,
{
    match handler {
        Handler::Subroute { routes, errors, .. } => {
            visit_routes_mut(routes, f)?;
            visit_routes_mut(errors, f)?;
        }
        Handler::Intercept(response_routes) => {
            visit_response_routes_mut(response_routes, f)?;
        }
        Handler::ReverseProxy(proxy) => {
            if let Some(ref mut tls) = proxy.tls {
                if tls.prepared_trust.is_none() && tls.ca.is_some() {
                    let source=Arc::get_mut(tls.prepared_ca.as_mut().ok_or_else(||anyhow!("CA source is not prepared"))?).ok_or_else(||anyhow!("CA source is shared during preparation"))?;
                    f(&mut source.value,&mut source.memory)?;
                }
            }
            visit_response_routes_mut(&mut proxy.response_routes, f)?;
        }
        _ => {}
    }
    Ok(())
}

fn visit_response_routes_mut<F>(routes: &mut [ResponseRoute], f: &mut F) -> Result<()>
where
    F: FnMut(&mut Value,&mut SourceMemory) -> Result<()> + ?Sized,
{
    for rr in routes {
        if let Some(ref mut inner_routes) = rr.routes {
            visit_routes_mut(inner_routes, f)?;
        }
    }
    Ok(())
}

fn visit_server_mut<F>(server: &mut crate::http_config::ServerConfig, f: &mut F) -> Result<()>
where
    F: FnMut(&mut Value,&mut SourceMemory) -> Result<()> + ?Sized,
{
    for policy in &mut server.tls_policies {
        if policy.prepared_client_auth.is_some(){continue}
        if policy.client_auth.as_ref().is_some_and(|ca|ca.ca.is_some()) {
            let source=Arc::get_mut(policy.prepared_ca.as_mut().ok_or_else(||anyhow!("CA source is not prepared"))?).ok_or_else(||anyhow!("CA source is shared during preparation"))?;
            f(&mut source.value,&mut source.memory)?;
        }
    }
    visit_routes_mut(&mut server.routes, f)?;
    visit_routes_mut(&mut server.errors, f)?;
    for route in server.named_routes.values_mut() {
        visit_route_mut(route, f)?;
    }
    Ok(())
}

pub(super) fn each_root_mut_owned(
    config: &mut PreparedConfig,
    f: &mut impl FnMut(&mut Value,&mut SourceMemory) -> Result<()>,
) -> Result<()> {
    for server_arc in &mut config.servers {
        let server = Arc::make_mut(server_arc);
        visit_server_mut(server, f)?;
    }
    Ok(())
}

pub(super) fn each_root_mut(config:&mut PreparedConfig,f:&mut impl FnMut(&mut Value)->Result<()>)->Result<()>{each_root_mut_owned(config,&mut|value,_|f(value))}

fn module_children(
    value: &Value,
    depth: usize,
    f: &mut impl FnMut(&Value) -> Result<()>,
) -> Result<()> {
    anyhow::ensure!(depth < 8, "CA module nesting too deep");
    match value.get("provider").and_then(Value::as_str) {
        Some("combined") => {
            if let Some(sources) = value.get("sources").and_then(Value::as_array) {
                for source in sources {
                    module_children(source, depth + 1, f)?;
                }
            }
        }
        Some("http") => {
            if let Some(ca) = value.get("tls").and_then(|v| v.get("ca")) {
                f(ca)?;
                module_children(ca, depth + 1, f)?;
            }
        }
        _ => {}
    }
    Ok(())
}
fn module_children_mut(
    value: &mut Value,
    depth: usize,
    f: &mut impl FnMut(&mut Value) -> Result<()>,
) -> Result<()> {
    anyhow::ensure!(depth < 8, "CA module nesting too deep");
    match value.get("provider").and_then(Value::as_str) {
        Some("combined") => {
            if let Some(sources) = value.get_mut("sources").and_then(Value::as_array_mut) {
                for source in sources {
                    module_children_mut(source, depth + 1, f)?;
                }
            }
        }
        Some("http") => {
            if let Some(ca) = value.get_mut("tls").and_then(|v| v.get_mut("ca")) {
                f(ca)?;
                module_children_mut(ca, depth + 1, f)?;
            }
        }
        _ => {}
    }
    Ok(())
}
pub(super) fn each(
    config: &PreparedConfig,
    f: &mut impl FnMut(&Value) -> Result<()>,
) -> Result<()> {
    each_root(config, &mut |value| {
        f(value)?;
        module_children(value, 0, f)
    })
}
pub(super) fn each_mut(config:&mut PreparedConfig,f:&mut impl FnMut(&mut Value)->Result<()>)->Result<()>{
    each_root_mut_owned(config,&mut|value,memory|{f(value)?;module_children_mut(value,0,f)?;memory.reserve_value(value)})
}
fn children_owned(value:&mut Value,depth:usize,memory:&mut SourceMemory,f:&mut impl FnMut(&mut Value,&mut SourceMemory)->Result<()>)->Result<()>{
    anyhow::ensure!(depth<8,"CA module nesting too deep");
    match value.get("provider").and_then(Value::as_str){
        Some("combined")=>if let Some(values)=value.get_mut("sources").and_then(Value::as_array_mut){for value in values{children_owned(value,depth+1,memory,f)?;}},
        Some("http")=>if let Some(ca)=value.get_mut("tls").and_then(|v|v.get_mut("ca")){f(ca,memory)?;children_owned(ca,depth+1,memory,f)?;},_=>{}
    }Ok(())
}
pub(super) fn each_mut_owned(config:&mut PreparedConfig,f:&mut impl FnMut(&mut Value,&mut SourceMemory)->Result<()>)->Result<()>{
    each_root_mut_owned(config,&mut|value,memory|{f(value,memory)?;children_owned(value,0,memory,f)})
}
pub(super) fn prepare_sources(config:&mut PreparedConfig,budget:&AuthBudget)->Result<()>{
    anyhow::ensure!(config.servers.iter().all(|s|Arc::strong_count(s)==1&&Arc::weak_count(s)==0),"CA source preparation requires a unique server plan");
    for server in &mut config.servers{let server=Arc::get_mut(server).expect("validated unique source graph");for policy in &mut server.tls_policies{
        if policy.prepared_client_auth.is_none()&&policy.prepared_ca.is_none(){if let Some(ca)=policy.client_auth.as_ref().and_then(|a|a.ca.as_ref()){policy.prepared_ca=Some(PreparedCa::copy(ca,budget)?);}}
    }}
    each_proxy_tls_mut(config,&mut|_,_,tls|{if tls.prepared_trust.is_none()&&tls.prepared_ca.is_none(){if let Some(ca)=&tls.ca{tls.prepared_ca=Some(PreparedCa::copy(ca,budget)?);}}Ok(())})
}

fn proxy_routes(routes:&[Route],ordinal:&mut usize,f:&mut impl FnMut(usize,&crate::http_config::types::ProxyTls)->Result<()>)->Result<()>{for route in routes{proxy_route(route,ordinal,f)?;}Ok(())}
fn proxy_responses(routes:&[ResponseRoute],ordinal:&mut usize,f:&mut impl FnMut(usize,&crate::http_config::types::ProxyTls)->Result<()>)->Result<()>{for r in routes{if let Some(routes)=&r.routes{proxy_routes(routes,ordinal,f)?;}}Ok(())}
fn proxy_route(route:&Route,ordinal:&mut usize,f:&mut impl FnMut(usize,&crate::http_config::types::ProxyTls)->Result<()>)->Result<()>{
    for handler in &route.handlers{match handler{
        Handler::ReverseProxy(proxy)=>{if let Some(tls)=&proxy.tls{f(*ordinal,tls)?;*ordinal=ordinal.checked_add(1).ok_or(crate::cert_transient::ResourceDenied)?;}proxy_responses(&proxy.response_routes,ordinal,f)?;},
        Handler::Subroute{routes,errors,..}=>{proxy_routes(routes,ordinal,f)?;proxy_routes(errors,ordinal,f)?;},
        Handler::Intercept(routes)=>proxy_responses(routes,ordinal,f)?,_=>{}
    }}Ok(())
}
pub(super) fn each_proxy_tls(config:&PreparedConfig,f:&mut impl FnMut(usize,usize,&crate::http_config::types::ProxyTls)->Result<()>)->Result<()>{
    for(si,s)in config.servers.iter().enumerate(){let mut ordinal=0;let mut visit=|i,tls:&crate::http_config::types::ProxyTls|f(si,i,tls);proxy_routes(&s.routes,&mut ordinal,&mut visit)?;proxy_routes(&s.errors,&mut ordinal,&mut visit)?;for route in s.named_routes.values(){proxy_route(route,&mut ordinal,&mut visit)?;}}Ok(())
}
fn proxy_routes_mut(routes:&mut[Route],ordinal:&mut usize,f:&mut impl FnMut(usize,&mut crate::http_config::types::ProxyTls)->Result<()>)->Result<()>{for route in routes{proxy_route_mut(route,ordinal,f)?;}Ok(())}
fn proxy_responses_mut(routes:&mut[ResponseRoute],ordinal:&mut usize,f:&mut impl FnMut(usize,&mut crate::http_config::types::ProxyTls)->Result<()>)->Result<()>{for r in routes{if let Some(routes)=&mut r.routes{proxy_routes_mut(routes,ordinal,f)?;}}Ok(())}
fn proxy_route_mut(route:&mut Route,ordinal:&mut usize,f:&mut impl FnMut(usize,&mut crate::http_config::types::ProxyTls)->Result<()>)->Result<()>{
    for handler in &mut route.handlers{match handler{
        Handler::ReverseProxy(proxy)=>{if let Some(tls)=&mut proxy.tls{f(*ordinal,tls)?;*ordinal=ordinal.checked_add(1).ok_or(crate::cert_transient::ResourceDenied)?;}proxy_responses_mut(&mut proxy.response_routes,ordinal,f)?;},
        Handler::Subroute{routes,errors,..}=>{proxy_routes_mut(routes,ordinal,f)?;proxy_routes_mut(errors,ordinal,f)?;},
        Handler::Intercept(routes)=>proxy_responses_mut(routes,ordinal,f)?,_=>{}
    }}Ok(())
}
pub(super) fn each_proxy_tls_mut(config:&mut PreparedConfig,f:&mut impl FnMut(usize,usize,&mut crate::http_config::types::ProxyTls)->Result<()>)->Result<()>{
    // Private Root candidate only. Check all before the first change; do not
    // deep clone server routes under a tiny TLS index allowance.
    anyhow::ensure!(config.servers.iter().all(|s|Arc::strong_count(s)==1&&Arc::weak_count(s)==0),"outgoing trust installation requires a unique server plan");
    for(si,s)in config.servers.iter_mut().enumerate(){let s=Arc::get_mut(s).expect("validated unique server plan");let mut ordinal=0;let mut visit=|i,tls:&mut crate::http_config::types::ProxyTls|f(si,i,tls);proxy_routes_mut(&mut s.routes,&mut ordinal,&mut visit)?;proxy_routes_mut(&mut s.errors,&mut ordinal,&mut visit)?;for route in s.named_routes.values_mut(){proxy_route_mut(route,&mut ordinal,&mut visit)?;}}Ok(())
}
