use super::{AdminError, controller::Inner, local_access::LocalAdmission, remote::Grant};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use std::sync::Arc;
pub(super) fn registered_path(path: &str) -> Option<&'static str> {
    if path == "/config" || path.starts_with("/config/") {
        Some("/config/")
    } else if path.starts_with("/id/") {
        Some("/id/")
    } else if path.starts_with("/pki/ca/") {
        Some("/pki/ca/")
    } else {
        match path {
            "/stop" => Some("/stop"),
            "/load" => Some("/load"),
            "/adapt" => Some("/adapt"),
            "/metrics" => Some("/metrics"),
            "/reverse_proxy/upstreams" => Some("/reverse_proxy/upstreams"),
            _ => None,
        }
    }
}
pub(super) async fn collect(
    inner: &Arc<Inner>,
    headers: &http::HeaderMap,
    grant: Option<&Grant>,
    local: Option<&LocalAdmission>,
) -> Result<http::Response<Full<Bytes>>, AdminError> {
    let check = || -> Result<(), AdminError> {
        inner.check_readable()?;
        if let Some(local) = local {
            local.check()?;
        }
        if let Some(grant) = grant {
            inner.state.load().authorize(grant, None)?;
        }
        Ok(())
    };
    check()?;
    let registry = inner
        .backend
        .metrics_registry()
        .ok_or_else(|| AdminError::new(503, "metrics_unavailable"))?;
    let response = registry.scrape(headers, false).await;
    let (parts, body) = response.into_parts();
    let bytes = body
        .collect()
        .await
        .map_err(|_| AdminError::new(500, "metrics_response_failed"))?
        .to_bytes();
    check()?;
    Ok(http::Response::from_parts(parts, Full::new(bytes)))
}
