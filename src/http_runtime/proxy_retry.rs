// Copyright 2015 Matthew Holt and The Caddy Authors.
// SPDX-License-Identifier: Apache-2.0
use super::{proxy_replay::ReplaySource, request::Context};
use crate::http_config::proxy_ext::RetryCfg;
use anyhow::Result;
use http::Method;
use std::{fmt, time::Instant};

#[derive(Debug)]
pub(super) struct NoUpstream;
impl fmt::Display for NoUpstream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("no upstreams available")
    }
}

#[derive(Debug)]
pub(super) struct DialFailure;
impl fmt::Display for DialFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("upstream dial failed")
    }
}
pub(super) fn is_dial(error: &anyhow::Error) -> bool {
    error.is::<DialFailure>()
        || error
            .chain()
            .any(|source| source.is::<super::upstream_tls::TcpDialError>())
}

pub(super) async fn allowed(
    ctx: &mut Context,
    cfg: &RetryCfg,
    start: Instant,
    retries: u32,
    error: &anyhow::Error,
    source: &ReplaySource,
) -> Result<bool> {
    if cfg.retries == 0 && cfg.try_duration.is_zero() {
        return Ok(false);
    }
    if cfg.retries > 0 && retries >= cfg.retries {
        return Ok(false);
    }
    if !cfg.try_duration.is_zero() && start.elapsed() >= cfg.try_duration {
        return Ok(false);
    }
    if !source.replayable() {
        return Ok(false);
    }
    let no_upstream = error.is::<NoUpstream>();
    let dial = is_dial(error);
    if !dial && !no_upstream {
        if let Some(sets) = &cfg.retry_match {
            let key = "http.reverse_proxy.is_transport_error";
            let previous = ctx.values.insert(key.into(), "true".into());
            let matched = super::request::match_sets(sets, ctx).await;
            match previous {
                Some(value) => {
                    ctx.values.insert(key.into(), value);
                }
                None => {
                    ctx.values.remove(key);
                }
            }
            if !matched? {
                return Ok(false);
            }
        } else if ctx.req().method() != Method::GET {
            return Ok(false);
        }
    }
    if cfg.try_interval.is_zero() {
        tokio::task::yield_now().await;
    } else {
        let stop = ctx.business.generation().hard_stop.clone();
        tokio::select! {
            biased;
            _ = stop.cancelled() => return Ok(false),
            _ = tokio::time::sleep(cfg.try_interval) => {},
        }
    }
    Ok(!ctx.business.generation().hard_stop.is_cancelled())
}
