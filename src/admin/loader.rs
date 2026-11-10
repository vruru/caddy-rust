//! HTTP config acquisition is independent of the serialized publication queue.
//! A generation fence prevents old upstream results overriding a newer config.
use super::{
    AdminError,
    controller::Inner,
    loader_schema::{HttpLoader, LoaderPlan},
};
use serde_json::Value;
use std::sync::{Arc, Weak};
use tokio_util::sync::CancellationToken;
#[path = "loader_fetch.rs"]
mod fetch;

pub(super) enum Loaded {
    Json(Vec<u8>),
    Adapted(Value),
}
impl Loaded {
    pub fn decode(self) -> Result<Value, AdminError> {
        match self {
            Self::Json(bytes) => crate::admin_json::decoded(&bytes)
                .map_err(|e| AdminError::new(e.status, e.category)),
            Self::Adapted(value) => Ok(value),
        }
    }
}
fn cancelled() -> AdminError {
    AdminError::new(503, "config_loader_cancelled")
}
fn expand(mut loader: HttpLoader) -> Result<HttpLoader, AdminError> {
    let failed = std::cell::Cell::new(false);
    let lookup = |name: &str| {
        if let Some(result) = crate::http_config::helpers::prepare_file_lookup(name) {
            return Some(result.unwrap_or_else(|_| {
                failed.set(true);
                String::new()
            }));
        }
        crate::http_config::helpers::global_lookup(name)
    };
    let replace = |input: &str, unknown| {
        crate::http_config::helpers::replace(input, unknown, lookup)
            .map_err(|_| AdminError::new(400, "config_loader_placeholder_invalid"))
    };
    loader.method = replace(&loader.method, true)?;
    loader.url = replace(&loader.url, true)?;
    let mut headers = std::collections::BTreeMap::<String, Vec<String>>::new();
    for (key, values) in loader.header {
        let key = replace(&key, true)?;
        for value in values {
            headers
                .entry(key.clone())
                .or_default()
                .push(replace(&value, false)?);
        }
    }
    if failed.get() {
        return Err(AdminError::new(
            400,
            "config_loader_non_utf8_file_placeholder",
        ));
    }
    loader.header = headers;
    Ok(loader)
}

pub(super) async fn load(
    inner: &Arc<Inner>,
    plan: LoaderPlan,
    candidate: Arc<Value>,
    cancel: CancellationToken,
) -> Result<Loaded, AdminError> {
    let http = inner.offload(move || expand(plan.http)).await?;
    if cancel.is_cancelled() {
        return Err(cancelled());
    }
    let identity = if http.tls.as_ref().is_some_and(|t| t.use_server_identity) {
        let copy = inner
            .offload(move || Ok(candidate.as_ref().clone()))
            .await?;
        Some(
            tokio::select! {_ = cancel.cancelled()=>return Err(cancelled()),result=inner.backend.identity_client(copy)=>result?},
        )
    } else {
        None
    };
    let adapter = http.adapter.clone();
    let (bytes, content) = fetch::fetch(http, identity, cancel.clone(), inner.cpu.clone()).await?;
    let adapter = if adapter.is_empty() {
        super::server::content_adapter(content.as_deref())?
    } else {
        super::server::content_adapter(Some(&format!("text/{adapter}")))?
    };
    if adapter.is_none() {
        return Ok(Loaded::Json(bytes));
    }
    let value = tokio::select! {_=cancel.cancelled()=>return Err(cancelled()),result=inner.backend.adapt(bytes,adapter,None)=>result?.result};
    Ok(Loaded::Adapted(value))
}

/// Called only after publication. Replacing this token never cancels a queued
/// accepted mutation; its expected-generation check remains the final fence.
pub(super) fn restart(
    inner: &Arc<Inner>,
    plan: Option<LoaderPlan>,
    initial: Option<Loaded>,
    generation: u64,
    budget: u8,
) {
    let cancel = inner.cancel.child_token();
    let mut current = inner
        .loader
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(old) = current.replace(cancel.clone()) {
        old.cancel();
    }
    drop(current);
    let Some(plan) = plan else { return };
    let weak = Arc::downgrade(inner);
    tokio::spawn(async move {
        if let Some(value) = initial {
            if budget == 0 {
                eprintln!("admin event=config_loader_stopped category=config_loader_chain_limit");
                return;
            }
            submit(&weak, value, generation, budget - 1, &cancel).await;
            return;
        }
        if plan.delay.is_zero() {
            return;
        }
        loop {
            tokio::select! {_ = cancel.cancelled()=>return,_ = tokio::time::sleep(plan.delay)=>{}}
            let Some(inner) = weak.upgrade() else { return };
            if inner.state.load().generation != generation {
                return;
            }
            let snapshot = inner.state.load_full();
            if snapshot.generation != generation {
                return;
            }
            let candidate = snapshot.raw.clone();
            let value = match load(&inner, plan.clone(), candidate, cancel.clone()).await {
                Ok(value) => value,
                Err(error) => {
                    if cancel.is_cancelled() {
                        return;
                    }
                    eprintln!(
                        "admin event=config_loader_retry category={}",
                        error.category
                    );
                    continue;
                }
            };
            drop(inner);
            match submit(&weak, value, generation, 16, &cancel).await {
                Some(Ok(false)) => continue,
                _ => return,
            }
        }
    });
}
async fn submit(
    weak: &Weak<Inner>,
    value: Loaded,
    generation: u64,
    budget: u8,
    cancel: &CancellationToken,
) -> Option<Result<bool, AdminError>> {
    let inner = weak.upgrade()?;
    let result = inner
        .enqueue_loader(value, generation, budget, cancel)
        .await;
    if let Err(error) = &result
        && !cancel.is_cancelled()
    {
        eprintln!(
            "admin event=config_loader_apply_failed category={}",
            error.category
        );
    }
    Some(result)
}
