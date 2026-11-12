// Copyright 2015 Matthew Holt and The Caddy Authors.
// SPDX-License-Identifier: Apache-2.0
//! Response middleware and scoped access to an upstream response.
use super::super::{
    ActiveServer, Body, BoxError, Bytes, Inner, Response, StatusCode, encode_body, full,
    proxy::PreparedResponse,
};
use super::{
    Context, Flow, Next, ResponseFuture, chained_routes, continue_chain, failure,
    finalize_transforms, log_append, take_writer_headers,
};
use crate::http_config::types::{ResponseHeaderFilter, ResponseRoute};
use anyhow::Result;
use http::{HeaderMap, HeaderName, HeaderValue};
use http_body_util::BodyExt;
use hyper::body::{Body as _, Frame, SizeHint};
use std::{
    pin::Pin,
    sync::Arc,
    task::{Context as TaskContext, Poll},
};

const MAX_ACTIVE_RESPONSE_ROUTES: u8 = 64;

fn enter(ctx: &mut Context) -> Result<()> {
    if ctx.response_route_depth >= MAX_ACTIVE_RESPONSE_ROUTES {
        return Err(failure(StatusCode::INTERNAL_SERVER_ERROR));
    }
    ctx.response_route_depth += 1;
    Ok(())
}

fn chosen<'a>(routes: &'a [ResponseRoute], response: &Response<Body>) -> Option<&'a ResponseRoute> {
    routes.iter().find(|route| {
        route
            .matcher
            .as_ref()
            .is_none_or(|matcher| matcher.matches(response.status().as_u16(), response.headers()))
    })
}

fn replacement_status(
    ctx: &Context,
    template: &str,
    zero_original: bool,
) -> Result<Option<StatusCode>> {
    if template.is_empty() {
        return Ok(None);
    }
    let bad = || failure(StatusCode::INTERNAL_SERVER_ERROR);
    let status = ctx.expand(template)?.parse::<i64>().map_err(|_| bad())?;
    if status == 0 && zero_original {
        return Ok(None);
    }
    let status = u16::try_from(status)
        .ok()
        .and_then(|number| StatusCode::from_u16(number).ok());
    status.map(Some).ok_or_else(bad)
}

fn canonical_header(name: &HeaderName) -> String {
    let mut word_start = true;
    name.as_str()
        .bytes()
        .map(|byte| {
            let result = if word_start {
                byte.to_ascii_uppercase()
            } else {
                byte
            };
            word_start = byte == b'-';
            char::from(result)
        })
        .collect()
}

fn publish(ctx: &mut Context, prefix: &str, status: StatusCode, headers: &HeaderMap) {
    ctx.values
        .insert(format!("{prefix}.status_code"), status.as_str().to_owned());
    for name in headers.keys() {
        let mut text = String::new();
        for (index, value) in headers.get_all(name).iter().enumerate() {
            if index != 0 {
                text.push(',');
            }
            text.push_str(&String::from_utf8_lossy(value.as_bytes()));
        }
        ctx.values
            .insert(format!("{prefix}.header.{}", canonical_header(name)), text);
    }
}

fn consumed(flow: Flow) -> Flow {
    if matches!(flow, Flow::Continue) {
        Flow::Stop
    } else {
        flow
    }
}

pub(super) fn reverse_proxy<'a>(
    mut source: PreparedResponse,
    rules: &'a [ResponseRoute],
    next: Next<'a>,
    ctx: &'a mut Context,
    inner: &'a Arc<Inner>,
    server: &'a Arc<ActiveServer>,
) -> ResponseFuture<'a> {
    Box::pin(async move {
        ctx.values
            .retain(|name, _| !name.starts_with("http.reverse_proxy.header."));
        publish(
            ctx,
            "http.reverse_proxy",
            source.response.status(),
            source.response.headers(),
        );
        ctx.values.insert(
            "http.reverse_proxy.status_text".into(),
            std::mem::take(&mut source.status_text),
        );
        let Some(rule) = chosen(rules, &source.response) else {
            return finish(source, ctx, inner).await;
        };
        if !rule.status.is_empty() {
            if let Some(status) = replacement_status(ctx, &rule.status, true)? {
                *source.response.status_mut() = status;
            }
            return finish(source, ctx, inner).await;
        }

        enter(ctx)?;
        let outer_source = ctx.proxy_response.replace(Box::new(source));
        let inner_result = match &rule.routes {
            Some(routes) => chained_routes(routes, ctx, inner, server, &next).await,
            None => Ok(Flow::Continue),
        };
        let result = match inner_result {
            Ok(Flow::Continue) => continue_chain(next, ctx, inner, server).await,
            flow => flow,
        };
        // The context follows Go's derived request: the matching routes and
        // their continuation may copy the origin, but no parent can reuse it.
        ctx.proxy_response = outer_source;
        ctx.response_route_depth -= 1;
        result.map(consumed)
    })
}

pub(super) async fn copy_response(
    ctx: &mut Context,
    status: &str,
    inner: &Arc<Inner>,
) -> Result<Flow> {
    let mut source = ctx
        .proxy_response
        .take()
        .ok_or_else(|| failure(StatusCode::INTERNAL_SERVER_ERROR))?;
    if let Some(status) = replacement_status(ctx, status, false)? {
        *source.response.status_mut() = status;
    }
    finish(*source, ctx, inner).await
}

pub(super) fn copy_headers(ctx: &mut Context, filter: &ResponseHeaderFilter) -> Result<()> {
    let source = ctx
        .proxy_response
        .as_ref()
        .ok_or_else(|| failure(StatusCode::INTERNAL_SERVER_ERROR))?;
    for (name, value) in source.response.headers() {
        // Framing belongs to the source body, not a new entity written by
        // this route. copy_response retains the source's own framing.
        if name == http::header::CONTENT_LENGTH || name == http::header::TRANSFER_ENCODING {
            continue;
        }
        if (filter.include.is_empty() || filter.include.contains(name.as_str()))
            && !filter.exclude.contains(name.as_str())
        {
            ctx.immediate.append(name, value.clone());
        }
    }
    Ok(())
}

async fn finish(source: PreparedResponse, ctx: &mut Context, inner: &Arc<Inner>) -> Result<Flow> {
    source
        .finish(ctx, inner)
        .await
        .map(Flow::Response)
        .map_err(|error| {
            if error.is::<super::HttpError>() {
                error
            } else {
                failure(StatusCode::BAD_GATEWAY)
            }
        })
}

pub(super) fn intercept<'a>(
    rules: &'a [ResponseRoute],
    next: Next<'a>,
    ctx: &'a mut Context,
    inner: &'a Arc<Inner>,
    server: &'a Arc<ActiveServer>,
) -> ResponseFuture<'a> {
    Box::pin(async move {
        enter(ctx)?;
        let result = intercept_inner(rules, next, ctx, inner, server).await;
        ctx.response_route_depth -= 1;
        result
    })
}

async fn intercept_inner(
    rules: &[ResponseRoute],
    next: Next<'_>,
    ctx: &mut Context,
    inner: &Arc<Inner>,
    server: &Arc<ActiveServer>,
) -> Result<Flow> {
    let deferred_mark = ctx.deferred.len();
    let metrics_mark=ctx.metrics.as_ref().map(|group|group.mark());
    let log_mark = log_append::mark(ctx);
    let flow = continue_chain(next, ctx, inner, server).await?;
    let Flow::Response(mut original) = flow else {
        return Ok(consumed(flow));
    };
    if original.status().is_informational() {
        return Ok(Flow::Response(original));
    }

    materialize(&mut original, deferred_mark, log_mark, ctx).await?;
    let Some(rule) = chosen(rules, &original) else {
        return Ok(Flow::Response(original));
    };
    publish(ctx, "http.intercept", original.status(), original.headers());

    let Some(routes) = &rule.routes else {
        if let Some(status) = replacement_status(ctx, &rule.status, true)
            .unwrap_or(Some(StatusCode::INTERNAL_SERVER_ERROR))
        {
            *original.status_mut() = status;
        }
        suppress_forbidden_body(&mut original);
        return Ok(Flow::Response(original));
    };

    // The replacement sees the same writer headers. Its routes have an
    // independent end and cannot execute the original downstream chain again.
    // The original entity's length applies only when that entity is retained.
    // Replacement writers and transforms must start without its framing.
    let discarded_metrics=ctx.metrics.as_ref().zip(metrics_mark).and_then(|(group,mark)|group.scope(mark));
    ctx.immediate = std::mem::take(original.headers_mut());
    let inherited_length = ctx.immediate.remove(http::header::CONTENT_LENGTH);
    let replacement = chained_routes(routes, ctx, inner, server, &Next::End).await?;
    let mut replacement = match replacement {
        Flow::Response(response) => response,
        Flow::ImplicitResponse(mut response) => {
            ctx.deferred.truncate(deferred_mark);
            *original.headers_mut() = take_writer_headers(&mut response, ctx);
            set_entity_length(original.headers_mut(), inherited_length);
            log_append::unwind(ctx, log_mark, Some(original.headers())).await;
            return Ok(Flow::Response(original));
        }
        Flow::Continue | Flow::Stop => {
            ctx.deferred.truncate(deferred_mark);
            *original.headers_mut() = std::mem::take(&mut ctx.immediate);
            set_entity_length(original.headers_mut(), inherited_length);
            log_append::unwind(ctx, log_mark, Some(original.headers())).await;
            return Ok(Flow::Response(original));
        }
    };
    materialize(&mut replacement, deferred_mark, log_mark, ctx).await?;

    match first_payload(replacement.body_mut()).await? {
        BodyWrites::Data => {
            if let Some(mut scope)=discarded_metrics{
                if original.extensions().get::<crate::metrics::discarded::PreparedEntity>().is_some(){
                    let body=std::mem::replace(original.body_mut(),full(Bytes::new()));
                    crate::metrics::discarded::observe(body,scope,&inner.tasks,ctx.business.generation().hard_stop.clone(),ctx.business.clone());
                }else{
                    // Native can replace before reading an upstream entity.
                    // Metrics must not turn that cancellation into a download.
                    scope.abandon();
                }
            }
        }
        BodyWrites::Empty(trailers) => {
            let body = std::mem::replace(original.body_mut(), full(Bytes::new()));
            *replacement.body_mut() = if let Some(trailers) = trailers {
                AppendTrailers {
                    inner: body,
                    trailers: Some(trailers),
                }
                .boxed_unsync()
            } else {
                body
            };
            set_entity_length(replacement.headers_mut(), inherited_length);
        }
    }
    suppress_forbidden_body(&mut replacement);
    Ok(Flow::Response(replacement))
}

fn set_entity_length(headers: &mut HeaderMap, length: Option<HeaderValue>) {
    headers.remove(http::header::CONTENT_LENGTH);
    if let Some(length) = length {
        headers.insert(http::header::CONTENT_LENGTH, length);
    }
}

async fn materialize(
    response: &mut Response<Body>,
    deferred_mark: usize,
    log_mark: usize,
    ctx: &mut Context,
) -> Result<()> {
    let mut headers = take_writer_headers(response, ctx);
    finalize_transforms(&mut headers, response, true, deferred_mark, ctx).await?;
    log_append::unwind(ctx, log_mark, Some(&headers)).await;
    *response.headers_mut() = headers;
    Ok(())
}

fn suppress_forbidden_body(response: &mut Response<Body>) {
    if matches!(
        response.status(),
        StatusCode::NO_CONTENT | StatusCode::NOT_MODIFIED
    ) || response.status().is_informational()
    {
        let headers = response.headers_mut();
        headers.remove(http::header::CONTENT_LENGTH);
        headers.remove(http::header::TRANSFER_ENCODING);
        if response.status() == StatusCode::NOT_MODIFIED {
            response.headers_mut().remove(http::header::CONTENT_TYPE);
        }
        *response.body_mut() = full(Bytes::new());
    }
}

enum BodyWrites {
    Data,
    Empty(Option<HeaderMap>),
}

async fn first_payload(body: &mut Body) -> Result<BodyWrites> {
    if body.size_hint().lower() > 0 {
        return Ok(BodyWrites::Data);
    }
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(anyhow::Error::from_boxed)?;
        if frame.data_ref().is_some_and(|data| !data.is_empty()) {
            let rest = std::mem::replace(body, full(Bytes::new()));
            *body = encode_body::with_prefix(rest, Some(frame));
            return Ok(BodyWrites::Data);
        }
        if let Ok(trailers) = frame.into_trailers() {
            return Ok(BodyWrites::Empty(Some(trailers)));
        }
        tokio::task::consume_budget().await;
    }
    Ok(BodyWrites::Empty(None))
}

struct AppendTrailers {
    inner: Body,
    trailers: Option<HeaderMap>,
}

impl hyper::body::Body for AppendTrailers {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        match Pin::new(&mut self.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(mut frame))) if frame.is_trailers() => {
                if let Some(extra) = self.trailers.take() {
                    let trailers = frame.trailers_mut().expect("trailer frame");
                    for (name, value) in &extra {
                        trailers.append(name, value.clone());
                    }
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(None) => Poll::Ready(
                self.trailers
                    .take()
                    .map(|trailers| Ok(Frame::trailers(trailers))),
            ),
            other => other,
        }
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }

    fn is_end_stream(&self) -> bool {
        self.trailers.is_none() && self.inner.is_end_stream()
    }
}
