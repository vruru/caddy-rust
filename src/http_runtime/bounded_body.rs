//! Strict, complete body admission using the proxy's real replay/spool owners.
//!
//! Positive proxy buffer limits implement CopyN and can return a partial source.
//! This handler instead validates the input and buffers to actual EOS. The
//! resulting ReplaySource owns all memory/anonymous-file credits throughout
//! downstream body reads, retries, cancellation and in-flight file workers.
#[path = "bounded_body/strict.rs"]
mod strict;

use super::{
    proxy_replay::ReplaySource,
    request::{Context, failure_with_cause},
};
use crate::http_config::bounded_body::Plan;
use anyhow::Result;
use http::{HeaderValue, Method, StatusCode, Version, header};
use http_body_util::BodyExt;
use hyper::body::Body as _;
use std::sync::{
    Arc,
    atomic::{AtomicU16, Ordering},
};

fn extended_websocket(ctx: &Context) -> bool {
    let request = ctx.req();
    request.method() == Method::CONNECT
        && match request.version() {
            Version::HTTP_2 => request
                .extensions()
                .get::<hyper::ext::Protocol>()
                .is_some_and(|protocol| protocol.as_str() == "websocket"),
            Version::HTTP_3 => request
                .extensions()
                .get::<::h3::ext::Protocol>()
                .is_some_and(|protocol| protocol.as_str() == "websocket"),
            _ => false,
        }
}

fn failed(ctx: &mut Context, status: StatusCode) -> anyhow::Error {
    ctx.cel_body_failure = Some(status);
    ctx.cel_body = None;
    *ctx.req_mut().body_mut() = strict::poison();
    if let Some(source) = ctx.req_mut().extensions_mut().remove::<ReplaySource>() {
        source.discard();
    }
    ctx.fastcgi_body_claimed = true;
    // The original unread H1 entity must never be reused as a new request.
    if matches!(ctx.req().version(), Version::HTTP_10 | Version::HTTP_11) {
        ctx.close_after_response = true;
    }
    failure_with_cause(status, strict::ReadFailure(status).into())
}

pub(super) async fn apply(ctx: &mut Context, plan: &Plan) -> Result<()> {
    // Extended CONNECT carries an unbounded tunnel, not an entity to buffer.
    // H1 Upgrade requests deliberately follow ordinary entity rules.
    if extended_websocket(ctx) {
        return Ok(());
    }
    // Retirement closes new admission; already accepted uploads must drain.
    // Only the hard-stop token may abort their complete-body validation.
    let cancel = ctx.business.generation().hard_stop.clone();
    if cancel.is_cancelled() {
        return Err(failed(ctx, StatusCode::BAD_REQUEST));
    }
    if let Some(status) = ctx.cel_body_failure {
        return Err(failed(ctx, status));
    }
    let previous = ctx.req().extensions().get::<ReplaySource>().cloned();
    if previous.is_none() && ctx.fastcgi_body_claimed {
        return Err(failed(ctx, StatusCode::BAD_REQUEST));
    }
    if previous.is_none() && ctx.req().body().is_end_stream() {
        return Ok(());
    }
    let declared = ctx.template_content_length();
    if declared > plan.max_size as i64 {
        return Err(failed(ctx, StatusCode::PAYLOAD_TOO_LARGE));
    }

    // Cover the one transient copy block independently from retained prefix
    // memory. Admission never waits while this request owns a partial body.
    let copy_units = (32 * 1024u64).div_ceil(super::fastcgi::admission::MEMORY_UNIT) as u32;
    let _copy_credit = ctx
        .resources
        .fastcgi_admission
        .prefix_memory
        .clone()
        .try_acquire_many_owned(copy_units)
        .map_err(|_| failed(ctx, StatusCode::SERVICE_UNAVAILABLE))?;

    // Poison before transferring ownership or awaiting. A cancelled handler
    // cannot leave an empty successful body for an error route to forward.
    ctx.cel_body = None;
    ctx.cel_body_failure = Some(StatusCode::BAD_REQUEST);
    let original = std::mem::replace(ctx.req_mut().body_mut(), strict::poison());
    ctx.req_mut().extensions_mut().remove::<ReplaySource>();
    ctx.req_mut()
        .extensions_mut()
        .remove::<super::fastcgi::PreparedLength>();
    ctx.fastcgi_body_claimed = true;
    let body = match previous {
        Some(source) => {
            drop(original);
            let body = source
                .take_unconsumed()
                .map_err(|_| failed(ctx, StatusCode::BAD_REQUEST))?;
            source.discard();
            body
        }
        None => original,
    };
    let read_status = Arc::new(AtomicU16::new(0));
    let body =
        strict::Checked::new(body, plan.max_size, declared, read_status.clone()).boxed_unsync();
    let result = tokio::select! { biased;
        _ = cancel.cancelled() => return Err(failed(ctx, StatusCode::BAD_REQUEST)),
        result = super::proxy_buffer::prepare(ctx, body, -1) => result,
    };
    let source = match result {
        Ok(source) => source,
        Err(_) => {
            // Checked marks every source/framing failure. Unmarked errors
            // originate in prefix admission or anonymous spool storage.
            let status = StatusCode::from_u16(read_status.load(Ordering::Acquire))
                .unwrap_or(StatusCode::SERVICE_UNAVAILABLE);
            return Err(failed(ctx, status));
        }
    };
    if cancel.is_cancelled() {
        return Err(failed(ctx, StatusCode::BAD_REQUEST));
    }
    let length = source
        .complete_length()
        .ok_or_else(|| failed(ctx, StatusCode::BAD_REQUEST))?;
    let body = source
        .take_unconsumed()
        .map_err(|_| failed(ctx, StatusCode::BAD_REQUEST))?;
    *ctx.req_mut().body_mut() = body;
    ctx.req_mut().extensions_mut().insert(source);
    ctx.req_mut()
        .headers_mut()
        .remove(header::TRANSFER_ENCODING);
    ctx.req_mut()
        .headers_mut()
        .insert(header::CONTENT_LENGTH, HeaderValue::from(length));
    ctx.set_content_length(length);
    ctx.body_limit = None;
    ctx.cel_body_failure = None;
    Ok(())
}
