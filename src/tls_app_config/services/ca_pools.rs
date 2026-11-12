//! Resolve generation-owned native PKI trust inputs before TLS provisioning.
//! The original runtime/admin configuration is never rewritten.
use super::*;
use base64::Engine;
use futures_util::TryStreamExt;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

const MAX_REFERENCES: usize = 4096;
const MAX_PEM_BYTES: usize = 16 * 1024 * 1024;

fn provider(value: &Value) -> Option<&str> {
    value.get("provider").and_then(Value::as_str)
}
fn authorities(value: &Value) -> Result<&[Value]> {
    match value.get("authority") {
        None | Some(Value::Null) => Ok(&[]),
        Some(Value::Array(values)) => {
            ensure!(
                values.len() <= 256,
                "PKI trust authority count exceeds bounds"
            );
            Ok(values)
        }
        _ => Err(anyhow!("PKI trust authorities must be an array")),
    }
}
fn scan(
    value: &Value,
    depth: usize,
    ids: &mut BTreeSet<String>,
    found: &mut bool,
    references: &mut usize,
) -> Result<()> {
    ensure!(depth < 8, "client trust provider nesting too deep");
    match provider(value) {
        Some("pki_root" | "pki_intermediate") => {
            let object = value
                .as_object()
                .ok_or_else(|| anyhow!("PKI trust provider must be an object"))?;
            crate::http_config::helpers::deny_unknown(
                object,
                &["provider", "authority"],
                "PKI trust pool",
            )?;
            *found = true;
            for id in authorities(value)? {
                let id = id
                    .as_str()
                    .ok_or_else(|| anyhow!("PKI trust authority must be a string"))?;
                ensure!(
                    !id.is_empty() && id.len() <= 4096,
                    "invalid PKI trust authority identity"
                );
                *references = references
                    .checked_add(1)
                    .ok_or(crate::cert_transient::ResourceDenied)?;
                ensure!(
                    *references <= MAX_REFERENCES,
                    "PKI trust references exceed bounds"
                );
                if !ids.contains(id) {
                    ensure!(ids.len() < 256, "PKI trust authority count exceeds bounds");
                    ids.insert(id.into());
                }
            }
        }
        Some("combined") => {
            // Only module children are traversed, never arbitrary user object values.
            let object = value
                .as_object()
                .ok_or_else(|| anyhow!("combined trust pool must be an object"))?;
            crate::http_config::helpers::deny_unknown(
                object,
                &["provider", "sources"],
                "combined client trust pool",
            )?;
            let sources = value
                .get("sources")
                .and_then(Value::as_array)
                .ok_or_else(|| anyhow!("combined client trust sources required"))?;
            ensure!(
                !sources.is_empty() && sources.len() <= 256,
                "client trust source count exceeds bounds"
            );
            for source in sources {
                scan(source, depth + 1, ids, found, references)?;
            }
        }
        _ => {}
    }
    Ok(())
}
fn pem<'a>(snapshot: &'a crate::local_pki::CaSnapshot, kind: &str) -> &'a [u8] {
    if kind == "pki_root" {
        &snapshot.root_certificate_pem
    } else {
        &snapshot.intermediate_chain_pem
    }
}
fn input_bound(
    value: &Value,
    snapshots: &BTreeMap<String, crate::local_pki::CaSnapshot>,
    total: &mut usize,
) -> Result<()> {
    match provider(value) {
        Some(kind @ ("pki_root" | "pki_intermediate")) => {
            for id in authorities(value)? {
                let snapshot = snapshots
                    .get(
                        id.as_str()
                            .ok_or_else(|| anyhow!("invalid PKI trust authority"))?,
                    )
                    .ok_or_else(|| anyhow!("PKI trust snapshot missing"))?;
                *total = total
                    .checked_add(pem(snapshot, kind).len())
                    .ok_or(crate::cert_transient::ResourceDenied)?;
                ensure!(
                    *total <= MAX_PEM_BYTES,
                    "PKI trust input exceeds supported bounds"
                );
            }
        }
        Some("combined") => {
            if let Some(Value::Array(sources)) = value.get("sources") {
                for source in sources {
                    input_bound(source, snapshots, total)?;
                }
            }
        }
        _ => {}
    }
    Ok(())
}
fn transform(
    value: &mut Value,
    snapshots: &BTreeMap<String, crate::local_pki::CaSnapshot>,
    count: &mut usize,
    der_bytes: &mut usize,
) -> Result<()> {
    match provider(value) {
        Some(kind @ ("pki_root" | "pki_intermediate")) => {
            let mut output = Vec::new();
            for id in authorities(value)? {
                let snapshot = snapshots
                    .get(
                        id.as_str()
                            .ok_or_else(|| anyhow!("invalid PKI trust authority"))?,
                    )
                    .ok_or_else(|| anyhow!("PKI trust snapshot missing"))?;
                let blocks = crate::cert_transient::certificate_blocks(pem(snapshot, kind))?;
                ensure!(
                    !blocks.is_empty(),
                    "PKI trust authority has no certificates"
                );
                // Go's root getter returns one certificate; IntermediateCertificateChain
                // deliberately returns the complete chain, including configured parents.
                let limit = if kind == "pki_root" { 1 } else { blocks.len() };
                for (_, der) in blocks.iter().take(limit) {
                    *count = count
                        .checked_add(1)
                        .ok_or(crate::cert_transient::ResourceDenied)?;
                    *der_bytes = der_bytes
                        .checked_add(der.len())
                        .ok_or(crate::cert_transient::ResourceDenied)?;
                    ensure!(
                        *count <= 4096 && *der_bytes <= MAX_PEM_BYTES,
                        "PKI trust material exceeds supported bounds"
                    );
                    output.push(Value::String(
                        base64::engine::general_purpose::STANDARD.encode(der),
                    ));
                }
            }
            *value = json!({"provider":"inline","trusted_ca_certs":output});
        }
        Some("combined") => {
            if let Some(Value::Array(sources)) = value.get_mut("sources") {
                for source in sources {
                    transform(source, snapshots, count, der_bytes)?;
                }
            }
        }
        _ => {}
    }
    Ok(())
}
impl CertificateServices {
    #[cfg(feature = "native-run")]
    pub(super) async fn prepare_pki_pools(
        self: &Arc<Self>,
        config: crate::http_config::PreparedConfig,
        cancel: CancellationToken,
    ) -> Result<crate::http_config::PreparedConfig> {
        self.owned(cancel, move |this, token| {
            Box::pin(async move {
                let (mut config, ids, found) = crate::cert_cpu::run(
                    this.context.resources.cpu.clone(),
                    token.clone(),
                    move || {
                        let mut ids = BTreeSet::new();
                        let mut found = false;
                        let mut references = 0;
                        for server in &config.servers {
                            for policy in &server.tls_policies {
                                if let Some(value) = policy
                                    .client_auth
                                    .as_ref()
                                    .and_then(|auth| auth.ca.as_ref())
                                {
                                    scan(value, 0, &mut ids, &mut found, &mut references)?;
                                }
                            }
                        }
                        Ok((config, ids, found))
                    },
                )
                .await?;
                if !found {
                    return Ok(config);
                }
                let default_identity_internal = this
                    .plan
                    .identity
                    .as_ref()
                    .is_some_and(|identity| identity.issuers.is_empty());
                let configured_internal = default_identity_internal
                    || this
                        .plan
                        .policies
                        .iter()
                        .flat_map(|p| &p.issuers)
                        .chain(this.plan.identity.iter().flat_map(|i| &i.issuers))
                        .any(|issuer| matches!(issuer, Issuer::Internal { .. }));
                ensure!(
                    !this.plan.authorities.is_empty()
                        || configured_internal
                        || !this.state.lock().await.pki.is_empty(),
                    "PKI client trust pool requires a configured PKI application"
                );
                let guard = token.clone().drop_guard();
                let snapshots: Vec<_> = stream::iter(ids)
                    .map(|id| {
                        let this = this.clone();
                        let token = token.clone();
                        async move {
                            let authority = this.authority(&id, token.clone()).await?;
                            let snapshot = authority.provision(&id, token).await?;
                            Ok::<_, anyhow::Error>((id, snapshot))
                        }
                    })
                    .buffered(4)
                    .try_collect()
                    .await?;
                let snapshots: BTreeMap<_, _> = snapshots.into_iter().collect();
                let result =
                    crate::cert_cpu::run(this.context.resources.cpu.clone(), token, move || {
                        let mut referenced_pem = 0usize;
                        for server in &config.servers {
                            for policy in &server.tls_policies {
                                if let Some(value) = policy
                                    .client_auth
                                    .as_ref()
                                    .and_then(|auth| auth.ca.as_ref())
                                {
                                    input_bound(value, &snapshots, &mut referenced_pem)?;
                                }
                            }
                        }
                        let input = snapshots.values().try_fold(0usize, |sum, s| {
                            sum.checked_add(s.root_certificate_pem.len())
                                .and_then(|n| n.checked_add(s.intermediate_chain_pem.len()))
                                .ok_or(crate::cert_transient::ResourceDenied)
                        })?;
                        let scratch = referenced_pem
                            .checked_mul(4)
                            .and_then(|n| n.checked_add(input))
                            .and_then(|n| n.checked_add(1024 * 1024))
                            .ok_or(crate::cert_transient::ResourceDenied)?;
                        // Short transformation scratch only: persistent prepared config/trust
                        // material retains its existing separate control/output budget boundary.
                        let _credit = crate::cert_transient::reserve(scratch)?;
                        let mut count = 0usize;
                        let mut bytes = 0usize;
                        for server in &mut config.servers {
                            for policy in &mut Arc::make_mut(server).tls_policies {
                                if let Some(value) = policy
                                    .client_auth
                                    .as_mut()
                                    .and_then(|auth| auth.ca.as_mut())
                                {
                                    transform(value, &snapshots, &mut count, &mut bytes)?;
                                }
                            }
                        }
                        Ok(config)
                    })
                    .await;
                drop(guard);
                result
            })
        })
        .await
    }
}
