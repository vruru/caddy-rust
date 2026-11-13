//! Native ACME DNS uses the same owned system lookup as observability. No
//! issuer retry or physical-retirement receipt is inferred from its completion.
use super::{http_dial::FamilyAddrs, metrics_dns};
use crate::{acme_wire::ClientOwner, outgoing_tls::{ConnectionBytes, ConnectionControl, Scope}};
use anyhow::Result;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use std::{mem::{size_of, size_of_val}, sync::Arc};
type Error = Box<dyn std::error::Error + Send + Sync>;

pub(crate) struct Resolver {
    scope: Arc<Scope>,
    owner: ClientOwner,
    _metadata: ConnectionBytes,
}
impl Resolver {
    // Called on the existing client-construction CPU lane. This plain metadata
    // loan has no task token: keeping a configured client is not running DNS.
    pub(crate) fn new(scope: Arc<Scope>, owner: ClientOwner) -> Result<Arc<Self>> {
        let bytes = size_of::<Self>().checked_add(2 * size_of::<usize>())
            .ok_or(crate::cert_transient::ResourceDenied)?;
        let metadata = scope.client_bytes(bytes)?;
        Ok(Arc::new(Self { scope, owner, _metadata: metadata }))
    }
}
fn admission(error: anyhow::Error) -> Error {
    Box::new(ConnectionControl::Admission(error.reallocate_into_boxed_dyn_error_without_backtrace()))
}
impl Resolve for Resolver {
    fn resolve(&self, name: Name) -> Resolving {
        // The incoming Name is moved, never cloned. Prepay both its retained
        // bytes and the eventual boxed address iterator before either handoff.
        let bytes = name.as_str().len().checked_add(1)
            .and_then(|n| n.checked_add(size_of::<FamilyAddrs>()))
            .and_then(|n| n.checked_add(size_of::<Result<Addrs, Error>>()))
            .ok_or(crate::cert_transient::ResourceDenied);
        let lease = match bytes.map_err(anyhow::Error::from)
            .and_then(|n| self.scope.connection_with_issuer_owner(n, self.owner.clone())) {
            Ok(lease) => lease,
            Err(error) => return Box::pin(std::future::ready(Err(admission(error)))),
        };
        let work = lease.clone();
        let future = async move {
            match metrics_dns::lookup_reqwest(name, work.clone()).await {
                Ok(values) => Ok(Box::new(values) as Addrs),
                Err(error) => Err(work.error(Box::new(error))),
            }
        };
        let bytes = size_of_val(&future).checked_add(size_of::<Resolving>())
            .ok_or_else(|| anyhow::Error::from(crate::cert_transient::ResourceDenied));
        if let Err(error) = bytes.and_then(|n| lease.grow(n)) {
            drop(future);
            return Box::pin(std::future::ready(Err(lease.error(admission(error)))));
        }
        Box::pin(future)
    }
}
