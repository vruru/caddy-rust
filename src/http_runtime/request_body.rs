// Copyright 2015 Matthew Holt and The Caddy Authors.
// SPDX-License-Identifier: Apache-2.0
//! Lazy request limits and owned replacement bodies. No client body is read
//! merely because its declared length exceeds a configured limit.
#[path = "request_body/limit.rs"]
mod limit;
pub(super) use limit::State as LimitState;

use super::{
    Body, BoxError, full,
    request::{Context, budget_failure, failure},
};
use crate::http_config::{helpers::replace_accounted, types::RequestBodyConfig};
use anyhow::Result;
use bytes::Bytes;
use futures_util::FutureExt;
use http::{HeaderMap, HeaderValue, StatusCode, Version, header};
use http_body_util::BodyExt;
use hyper::body::Body as _;
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

const UNIT: usize = 4096;
pub(super) const REPLACEMENT_UNITS: usize = 32 * 1024 * 1024 / UNIT;
const H1_DRAIN_LIMIT: usize = 256 * 1024;

#[derive(Clone)]
pub(super) struct Replacement {
    pub(super) length: u64,
    chunked: bool,
    trailers: Option<Arc<HeaderMap>>,
}

#[derive(Debug)]
struct MemoryBusy;
impl std::fmt::Display for MemoryBusy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("request body replacement memory unavailable")
    }
}
impl std::error::Error for MemoryBusy {}

struct OwnedReplacement {
    bytes: Vec<u8>,
    _credit: Option<OwnedSemaphorePermit>,
}
impl AsRef<[u8]> for OwnedReplacement {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

fn charge(
    pool: &Arc<Semaphore>,
    held: &mut Option<OwnedSemaphorePermit>,
    bytes: usize,
) -> Result<()> {
    let units = bytes.div_ceil(UNIT);
    let previous = held.as_ref().map_or(0, OwnedSemaphorePermit::num_permits);
    if units <= previous {
        return Ok(());
    }
    let delta = u32::try_from(units - previous).map_err(|_| MemoryBusy)?;
    let acquired = pool
        .clone()
        .try_acquire_many_owned(delta)
        .map_err(|_| MemoryBusy)?;
    if let Some(held) = held {
        held.merge(acquired);
    } else {
        *held = Some(acquired);
    }
    Ok(())
}

fn h1(version: Version) -> bool {
    matches!(version, Version::HTTP_10 | Version::HTTP_11)
}

pub(super) struct OriginalFraming {
    chunked: bool,
    closing: bool,
}

pub(super) fn original_framing<B>(request: &http::Request<B>) -> OriginalFraming {
    let version = request.version();
    let headers = request.headers();
    OriginalFraming {
        chunked: h1(version)
            && super::proxy::header_has_token(headers, header::TRANSFER_ENCODING, "chunked"),
        closing: h1(version)
            && (super::proxy::header_has_token(headers, header::CONNECTION, "close")
                || (version == Version::HTTP_10
                    && !super::proxy::header_has_token(headers, header::CONNECTION, "keep-alive"))),
    }
}

async fn close_original(
    ctx: &mut Context,
    mut body: Body,
    chunked: bool,
) -> Result<Option<Arc<HeaderMap>>> {
    let version = ctx.req().version();
    if !h1(version) || body.is_end_stream() {
        return Ok(None);
    }
    if (!chunked && ctx.original_framing.closing)
        || body
            .size_hint()
            .exact()
            .is_some_and(|n| n > H1_DRAIN_LIMIT as u64)
    {
        ctx.close_after_response = true;
        return Ok(None);
    }
    let mut seen = 0usize;
    loop {
        let next = tokio::select! { biased;
            _ = ctx.drain.cancelled() => return Err(failure(StatusCode::SERVICE_UNAVAILABLE)),
            frame = body.frame() => frame,
        };
        match next {
            None => return Ok(None),
            Some(Err(error)) => {
                ctx.close_after_response = true;
                return Err(anyhow::Error::from_boxed(error));
            }
            Some(Ok(frame)) => match frame.into_data() {
                Ok(data) => {
                    seen = seen.saturating_add(data.len());
                    if seen > H1_DRAIN_LIMIT {
                        ctx.close_after_response = true;
                        // Like a buffered Go read, preserve a terminal trailer
                        // already delivered with the final data. Do not wait
                        // for more input after crossing the close-drain bound.
                        return Ok(body
                            .frame()
                            .now_or_never()
                            .flatten()
                            .and_then(|frame| frame.ok())
                            .and_then(|frame| frame.into_trailers().ok())
                            .map(Arc::new));
                    }
                }
                Err(frame) => return Ok(frame.into_trailers().ok().map(Arc::new)),
            },
        }
    }
}

pub(super) async fn apply(ctx: &mut Context, plan: &RequestBodyConfig) -> Result<()> {
    if !plan.set.is_empty() {
        if let Some(state) = ctx.body_limit.take() {
            // Close on a Go MaxBytesReader delegates directly to the old
            // source; replacing a body does not consume its prior limit.
            state.bypass();
        }
        let previous = ctx.req().extensions().get::<Replacement>().cloned();
        let chunked = previous
            .as_ref()
            .map_or(ctx.original_framing.chunked, |prior| prior.chunked);
        let old = std::mem::replace(ctx.req_mut().body_mut(), full(Bytes::new()));
        let trailers = if let Some(prior) = previous {
            // io.NopCloser on an earlier replacement has no network drain.
            drop(old);
            prior.trailers
        } else if ctx.req().version() == Version::HTTP_2 && !old.is_end_stream() {
            // Keep the flow-controlled receive half through response sending.
            // Dropping it in the handler can race the response with a reset
            // when a client still has DATA in flight. Do not copy or drain it.
            ctx.replaced_receive = Some(old);
            None
        } else {
            close_original(ctx, old, chunked).await?
        };
        let mut credit = None;
        let text = replace_accounted(
            &plan.set,
            false,
            |name| match name {
                "http.request.body" | "http.request.body_base64" => Some(String::new()),
                _ => ctx.lookup(name),
            },
            |bytes| charge(&ctx.resources.request_body_bytes, &mut credit, bytes),
        );
        let text = match text {
            Ok(text) => text,
            Err(error) if error.is::<MemoryBusy>() => {
                return Err(budget_failure(
                    ctx,
                    super::resource_budget::BudgetError::Overloaded,
                ));
            }
            Err(error) => return Err(error),
        };
        let length = text.len() as u64;
        let bytes = Bytes::from_owner(OwnedReplacement {
            bytes: text.into_bytes(),
            _credit: credit,
        });
        *ctx.req_mut().body_mut() = full(bytes);
        ctx.req_mut().extensions_mut().insert(Replacement {
            length,
            chunked,
            trailers,
        });
    }
    if plan.max_size > 0 {
        if let Some(state) = &ctx.body_limit {
            state.tighten(plan.max_size as u64);
        } else {
            let old = std::mem::replace(ctx.req_mut().body_mut(), full(Bytes::new()));
            let (body, state) = limit::wrap(old, plan.max_size as u64);
            *ctx.req_mut().body_mut() = body;
            ctx.body_limit = Some(state);
        }
    }
    Ok(())
}

pub(super) fn limit_error(error: &(dyn std::error::Error + 'static)) -> bool {
    limit::is_limit(error)
}

pub(super) fn limit_hit(state: Option<&LimitState>) -> bool {
    state.is_some_and(LimitState::exceeded)
}

pub(super) fn retain_receive(
    response: http::Response<Body>,
    receive: Body,
) -> http::Response<Body> {
    response.map(|body| {
        body.map_frame(move |frame| {
            let _owner = &receive;
            frame
        })
        .boxed_unsync()
    })
}

pub(super) fn outgoing_headers(
    replacement: Option<&Replacement>,
    headers: &mut HeaderMap,
    h2: bool,
) {
    if let Some(replacement) = replacement {
        headers.remove(header::TRANSFER_ENCODING);
        if replacement.chunked && !h2 {
            headers.remove(header::CONTENT_LENGTH);
            headers.insert(
                header::TRANSFER_ENCODING,
                HeaderValue::from_static("chunked"),
            );
        } else {
            headers.insert(
                header::CONTENT_LENGTH,
                HeaderValue::from(replacement.length),
            );
        }
    }
}

pub(super) fn outgoing_body(body: Body, replacement: Option<Replacement>) -> Body {
    let body = super::trailer_policy::policy(body, true);
    let Some(trailers) = replacement.and_then(|state| state.trailers) else {
        return body;
    };
    // A Set already completed the old-body read, so these are known values
    // at request cloning time, rather than late trailers from the new body.
    let body = body
        .with_trailers(
            async move { Some(Ok::<HeaderMap, BoxError>(Arc::unwrap_or_clone(trailers))) },
        )
        .boxed_unsync();
    super::trailer_policy::policy(body, false)
}
