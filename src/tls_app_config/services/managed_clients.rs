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
    ) -> Result<PreparedBusinessNames> {
        let automate=self.plan.automate.get()?.names();
        ensure!(names.len().checked_add(automate.len()).is_some_and(|n|n<=crate::tls_resolver::MAX_CERTIFICATES),
            "certificate group capacity exceeded");
        let clients=self.client_automate_names.get().map_or(&[][..],Vec::as_slice);
        let mut count=automate.len().checked_add(clients.len()).ok_or(crate::cert_transient::ResourceDenied)?;
        let mut text=0usize;
        for name in automate {
            text=text.checked_add(name.len()).ok_or(crate::cert_transient::ResourceDenied)?;
        }
        count=count.checked_add(names.iter().map(Vec::len).sum::<usize>()).ok_or(crate::cert_transient::ResourceDenied)?;
        let table=count.checked_next_power_of_two().unwrap_or(1).max(4);
        // New automate text peak: bridge input + normalized output + group keys + aliases.
        // covered clients drop before preflight, so never add a fifth text copy.
        // Table allowance includes old+new capacity for three bounded sets;
        // nested input/output Vec slots and normalization's single-group scratch
        // are separate. This admission owns the actual worker/result, not the
        // awaiter. Existing non-automate text and all subsequent legacy group/cache
        // ownership keep their existing budgets; this does not replace them.
        let slots=table.checked_mul(6*(std::mem::size_of::<String>()+std::mem::size_of::<Vec<String>>()+32))
            .and_then(|n| n.checked_add(count.checked_mul(4*std::mem::size_of::<String>())?))
            .and_then(|n| n.checked_add((names.len()+automate.len()+clients.len()).checked_mul(4*std::mem::size_of::<Vec<String>>())?))
            .ok_or(crate::cert_transient::ResourceDenied)?;
        let bytes=if automate.is_empty() { 0 } else {
            text.checked_mul(4).and_then(|n|n.checked_add(slots))
                .and_then(|n|n.checked_add(128*1024)).ok_or(crate::cert_transient::ResourceDenied)?
        };
        let memory=crate::cert_transient::reserve(bytes)?;
        names.try_reserve(automate.len()+clients.len()).map_err(|_|crate::cert_transient::ResourceDenied)?;
        for name in automate {
            // Values are already strict managed identifiers, normalized before
            // choosing a policy, with the same representation as literal input.
            let mut group=Vec::new();group.try_reserve_exact(1).map_err(|_|crate::cert_transient::ResourceDenied)?;
            let mut copied=String::new();copied.try_reserve_exact(name.len()).map_err(|_|crate::cert_transient::ResourceDenied)?;
            copied.push_str(name);group.push(copied);names.push(group);
        }
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
        Ok(PreparedBusinessNames {names:self.preflight(names)?,_memory:memory})
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
