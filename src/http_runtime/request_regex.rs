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
            ctx.raw_regex_captures.values.remove(&key);
            ctx.values.insert(key, value.clone());
        }
        ctx.raw_regex_captures.values.remove(&basic);
        ctx.values.insert(basic, value);
    }
    Ok(true)
}

/// Raw capture storage dies before its backing allocation credits. Values move
/// between exclusive Context views; clones returned to template workers receive
/// those workers' own prepaid copies.
#[derive(Default)]
pub(super) struct RawCaptures{
    values:std::collections::HashMap<String,bytes::Bytes>,
    credits:Vec<native_write_policy::Lease>,
}
impl RawCaptures{pub(super) fn get(&self,key:&str)->Option<&[u8]>{self.values.get(key).map(bytes::Bytes::as_ref)}}
pub(super) async fn matches_bytes(plan:&RequestRegex,input:Vec<u8>,input_credit:native_write_policy::Lease,ctx:&mut Context)->Result<bool>{
    let regex=plan.regex.clone();let remaining=ctx.regex_capture_budget;let pool=ctx.resources.rewrite_bytes.clone();let prefix_bytes=plan.name.len().saturating_add(32).saturating_mul(8);
    // Input is at most the admitted URI limit. Normalization grows invalid
    // bytes to one RuneError each; returned captures retain separate credit.
    let scratch_bytes=input.len().checked_mul(32).and_then(|n|n.checked_add(regex.search_memory())).and_then(|n|n.checked_add(4096)).ok_or_else(||failure(StatusCode::SERVICE_UNAVAILABLE))?;
    let scratch=pool.reserve(scratch_bytes).map_err(|_|failure(StatusCode::SERVICE_UNAVAILABLE))?;
    let captures=ctx.resources.request_regexp.run(move||{
        let _scratch=scratch;let _input_credit=input_credit;
        let input=super::rewrite_ops::clean(&input,true);
        let budget=ReplaceBudget::new(regex.search_memory().saturating_add(input.len().saturating_mul(8)),Some(Instant::now()+Duration::from_millis(150)));
        let mut credits=Vec::new();
        let value=regex.first_match_bytes_limited(&input,&budget,remaining,|n|{
            let credit=pool.reserve(n.saturating_add(prefix_bytes)).map_err(|_|OperationError::ByteLimit)?;credits.push(credit);Ok(())
        })?;
        Ok::<_,OperationError>((value,credits))
    }).await.map_err(|_|failure(StatusCode::SERVICE_UNAVAILABLE))?.map_err(|_|failure(StatusCode::SERVICE_UNAVAILABLE))?;
    let(Some(captures),credits)=captures else{return Ok(false)};
    let total=captures.iter().try_fold(0usize,|total,(key,value)|{
        let basic=13usize.saturating_add(key.len());
        let extra=if plan.name.is_empty(){0}else{14usize.saturating_add(plan.name.len()).saturating_add(key.len()).saturating_add(value.len())};
        total.checked_add(basic.saturating_add(value.len()).saturating_add(extra))
    }).ok_or_else(||failure(StatusCode::SERVICE_UNAVAILABLE))?;
    ctx.regex_capture_budget=ctx.regex_capture_budget.checked_sub(total).ok_or_else(||failure(StatusCode::SERVICE_UNAVAILABLE))?;
    for(key,value)in captures{
        let basic=format!("http.regexp.{key}");
        let extra=(!plan.name.is_empty()).then(||format!("http.regexp.{}.{key}",plan.name));
        let value=bytes::Bytes::from(value);
        for name in std::iter::once(basic).chain(extra){
            // The empty textual marker makes the key visible to the existing
            // template snapshot iterator; lookup_bytes reads the exact bytes.
            ctx.values.insert(name.clone(),String::new());ctx.raw_regex_captures.values.insert(name,value.clone());
        }
    }
    ctx.raw_regex_captures.credits.extend(credits);Ok(true)
}
