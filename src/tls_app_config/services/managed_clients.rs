//! Prepare all typed proxy consumers on the existing bounded metadata lane.
use super::*;
use crate::http_config::{
    PreparedConfig,
    types::{Handler, ProxyTls, ResponseRoute, Route},
};
use std::collections::BTreeMap;
fn routes(routes: &mut [Route], f: &mut impl FnMut(&mut ProxyTls) -> Result<()>) -> Result<()> {
    for route in routes {
        for handler in &mut route.handlers {
            match handler {
                Handler::Subroute {
                    routes: inner,
                    errors,
                    ..
                } => {
                    routes_fn(inner, f)?;
                    routes_fn(errors, f)?
                }
                Handler::Intercept(inner) => responses(inner, f)?,
                Handler::ReverseProxy(proxy) => {
                    if let Some(tls) = proxy.tls.as_mut() {
                        f(tls)?
                    }
                    responses(&mut proxy.response_routes, f)?
                }
                _ => {}
            }
        }
    }
    Ok(())
}
fn routes_fn(inner: &mut [Route], f: &mut impl FnMut(&mut ProxyTls) -> Result<()>) -> Result<()> {
    routes(inner, f)
}
fn responses(
    routes: &mut [ResponseRoute],
    f: &mut impl FnMut(&mut ProxyTls) -> Result<()>,
) -> Result<()> {
    for route in routes {
        if let Some(inner) = route.routes.as_mut() {
            routes_fn(inner, f)?
        }
    }
    Ok(())
}
impl CertificateServices {
    pub(super) fn prepare_business_names(
        &self,
        mut names: Vec<Vec<String>>,
    ) -> Result<Vec<Vec<String>>> {
        names.extend(self.plan.automate.iter().map(|name| vec![name.clone()]));
        if let Some(clients) = self.client_automate_names.get() {
            let mut covered = names
                .iter()
                .flatten()
                .cloned()
                .collect::<std::collections::HashSet<_>>();
            for name in clients {
                if covered.contains(name) {
                    continue;
                }
                names.push(vec![name.clone()]);
                covered.insert(name.clone());
            }
        }
        self.preflight(names)
    }

    pub(super) async fn prepare_managed_clients(
        self: &Arc<Self>,
        config: PreparedConfig,
        cancel: CancellationToken,
    ) -> Result<PreparedConfig> {
        self.owned(cancel, move |this, token| {
            Box::pin(async move {
                let manual = this.manual_resolver.clone();
                let business = this.context.resolver.clone();
                let (config, names) =
                    crate::cert_cpu::run(this.context.resources.cpu.clone(), token, move || {
                        let mut config = config;
                        let mut sources = BTreeMap::<
                            String,
                            Arc<crate::tls_app_config::ManagedClientSource>,
                        >::new();
                        let mut prepare = |tls: &mut ProxyTls| -> Result<()> {
                            if let Some(name) = tls.client_certificate_automate.as_deref() {
                                let name = crate::tls_resolver::normalize_certificate_name(name)?;
                                if !sources.contains_key(&name) {
                                    ensure!(
                                        sources.len() < crate::tls_resolver::MAX_CERTIFICATES,
                                        "managed client certificate count exceeds bounds"
                                    );
                                    let source =
                                        super::super::managed_client::ManagedClientSource::new(
                                            &name,
                                            manual.clone(),
                                            business.clone(),
                                        )?;
                                    sources.insert(name.clone(), source);
                                }
                                tls.client_certificate_automate = Some(name.clone());
                                tls.managed_client = Some(sources[&name].clone());
                            }
                            Ok(())
                        };
                        for server in &mut config.servers {
                            let server = Arc::make_mut(server);
                            routes(&mut server.routes, &mut prepare)?;
                            routes(&mut server.errors, &mut prepare)?;
                            for route in server.named_routes.values_mut() {
                                routes(std::slice::from_mut(route), &mut prepare)?;
                            }
                        }
                        Ok((config, sources.into_keys().collect::<Vec<_>>()))
                    })
                    .await?;
                if let Some(previous) = this.client_automate_names.get() {
                    ensure!(
                        previous == &names,
                        "managed client certificate topology changed"
                    )
                } else {
                    this.client_automate_names
                        .set(names)
                        .map_err(|_| anyhow!("managed client certificate topology raced"))?;
                }
                Ok(config)
            })
        })
        .await
    }
}
