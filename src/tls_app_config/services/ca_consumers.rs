use anyhow::Result;
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
                if let Some(ref ca) = tls.ca {
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
        if let Some(ca) = policy.client_auth.as_ref().and_then(|ca| ca.ca.as_ref()) {
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
    F: FnMut(&mut Value) -> Result<()> + ?Sized,
{
    for route in routes {
        visit_route_mut(route, f)?;
    }
    Ok(())
}

fn visit_route_mut<F>(route: &mut Route, f: &mut F) -> Result<()>
where
    F: FnMut(&mut Value) -> Result<()> + ?Sized,
{
    for handler in &mut route.handlers {
        visit_handler_mut(handler, f)?;
    }
    Ok(())
}

fn visit_handler_mut<F>(handler: &mut Handler, f: &mut F) -> Result<()>
where
    F: FnMut(&mut Value) -> Result<()> + ?Sized,
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
                if let Some(ref mut ca) = tls.ca {
                    f(ca)?;
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
    F: FnMut(&mut Value) -> Result<()> + ?Sized,
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
    F: FnMut(&mut Value) -> Result<()> + ?Sized,
{
    for policy in &mut server.tls_policies {
        if let Some(ca) = policy.client_auth.as_mut().and_then(|ca| ca.ca.as_mut()) {
            f(ca)?;
        }
    }
    visit_routes_mut(&mut server.routes, f)?;
    visit_routes_mut(&mut server.errors, f)?;
    for route in server.named_routes.values_mut() {
        visit_route_mut(route, f)?;
    }
    Ok(())
}

pub(super) fn each_root_mut(
    config: &mut PreparedConfig,
    f: &mut impl FnMut(&mut Value) -> Result<()>,
) -> Result<()> {
    for server_arc in &mut config.servers {
        let server = Arc::make_mut(server_arc);
        visit_server_mut(server, f)?;
    }
    Ok(())
}

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
pub(super) fn each_mut(
    config: &mut PreparedConfig,
    f: &mut impl FnMut(&mut Value) -> Result<()>,
) -> Result<()> {
    each_root_mut(config, &mut |value| {
        f(value)?;
        module_children_mut(value, 0, f)
    })
}
