use super::request::{Context, failure};
use crate::{
    go_regexp::{OperationError, ReplaceBudget},
    http_config::types::RequestRegex,
};
use anyhow::Result;
use http::StatusCode;
use std::time::{Duration, Instant};

pub(super) const CAPTURE_BYTES: usize = 256 << 10;

pub(super) async fn matches(
    plan: &RequestRegex,
    inputs: Vec<String>,
    ctx: &mut Context,
) -> Result<bool> {
    if inputs.is_empty() {
        return Ok(false);
    }
    let regex = plan.regex.clone();
    let remaining = ctx.regex_capture_budget;
    let captures = ctx
        .resources
        .request_regexp
        .run(move || {
            let budget = ReplaceBudget::new(
                regex.search_memory(),
                Some(Instant::now() + Duration::from_millis(150)),
            );
            for input in inputs {
                if let Some(captures) = regex.first_match_limited(&input, &budget, remaining)? {
                    return Ok::<_, OperationError>(Some(captures));
                }
            }
            Ok(None)
        })
        .await
        .map_err(|_| failure(StatusCode::SERVICE_UNAVAILABLE))?
        .map_err(|_| failure(StatusCode::SERVICE_UNAVAILABLE))?;
    let Some(captures) = captures else {
        return Ok(false);
    };
    for (key, value) in captures {
        let basic = format!("http.regexp.{key}");
        let extra = (!plan.name.is_empty()).then(|| format!("http.regexp.{}.{key}", plan.name));
        let bytes =
            basic.len() + value.len() + extra.as_ref().map_or(0, |key| key.len() + value.len());
        ctx.regex_capture_budget = ctx
            .regex_capture_budget
            .checked_sub(bytes)
            .ok_or_else(|| failure(StatusCode::SERVICE_UNAVAILABLE))?;
        if let Some(key) = extra {
            ctx.values.insert(key, value.clone());
        }
        ctx.values.insert(basic, value);
    }
    Ok(true)
}
