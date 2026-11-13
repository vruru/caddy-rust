//! Ordered rewrite execution. Blocking work is admitted through the existing
//! request-regexp lane; live URI metadata carries an atomic allocation lease.
use super::{
    request::{Context, failure},
    rewrite_ops::{self as ops, State},
};
use crate::{
    go_regexp::GoRegexp,
    http_config::{helpers::replace_bytes_accounted, types::*},
};
use anyhow::{Result, ensure};
use http::{Method, StatusCode, Uri};
use native_write_policy::{Lease, Pool};
use std::sync::Arc;

#[derive(Clone)]
pub(crate) struct Projection {
    pub(super) state: Arc<State>,
    pub(crate) request_uri: Arc<[u8]>,
    _lease: Arc<Lease>,
}
pub(crate) fn projection(req: &http::Request<super::Body>) -> Option<&Projection> {
    req.extensions().get()
}
// Go's proxy rewrites a request clone while its replacer still refers to the
// inbound request. Only direct matcher/transport metadata gets the clone view.
#[derive(Clone)]
pub(super) struct Original {
    pub uri: Uri,
    pub method: Method,
    pub projection: Option<Projection>,
}
pub(super) fn lookup_projection(req: &http::Request<super::Body>) -> Option<&Projection> {
    if let Some(original) = req.extensions().get::<Original>() {
        original.projection.as_ref()
    } else {
        projection(req)
    }
}
struct Args {
    pool: Pool,
    leases: Vec<Lease>,
    lookup: Option<Lease>,
    bytes: usize,
}
impl Args {
    fn new(pool: Pool) -> Result<Self> {
        let fixed = pool.reserve(ops::CAP + 4096)?;
        Ok(Self {
            pool,
            leases: Vec::new(),
            lookup: Some(fixed),
            bytes: 0,
        })
    }
    async fn expand(&mut self,view:super::request::ReplacerView<'_>,text:&str,known:bool)->Result<Vec<u8>>{
        let out=view.expand_resolved(text,!known).await?;
        self.bytes=self.bytes.checked_add(out.len()).filter(|n|*n<=ops::CAP).ok_or_else(||anyhow::anyhow!("rewrite expanded arguments exceed limit"))?;
        self.leases.push(self.pool.reserve(out.len().saturating_mul(2)+1024)?);
        Ok(out.to_vec())
    }
    async fn pairs(&mut self,view:super::request::ReplacerView<'_>,list:&[RewriteArgument],skip_empty:bool)->Result<Vec<(Vec<u8>,Vec<u8>)>>{
        self.leases.push(self.pool.reserve(list.len().saturating_mul(128)+1024)?);
        let mut out=Vec::with_capacity(list.len());
        for v in list{let key=self.expand(view,&v.key,false).await?;if skip_empty&&key.is_empty(){continue}out.push((key,self.expand(view,&v.val,false).await?));}
        Ok(out)
    }

}
enum Op {
    Identity,
    Strip(Vec<u8>, bool),
    Substring(Vec<u8>, Vec<u8>, i64, bool),
    Regex(Arc<GoRegexp>, Vec<u8>),
    Query(ops::Query),
}
async fn transform(
    ctx: &mut Context,
    old: Option<Arc<State>>,
    uri: Uri,
    op: Op,
    mut args: Args,
) -> Result<Projection> {
    drop(args.lookup.take());
    let pool = args.pool.clone();
    let state = ctx
        .resources
        .request_regexp
        .run(move || -> Result<Projection> {
            let old_size = old
                .as_ref()
                .map_or_else(|| ops::uri_bytes(&uri), |v| v.bytes());
            let rows = match &op {
                Op::Query(q) => {
                    old.as_ref().map_or_else(
                        || {
                            uri.query()
                                .unwrap_or_default()
                                .bytes()
                                .filter(|b| *b == b'&')
                                .count()
                        },
                        |state| state.query.iter().filter(|b| **b == b'&').count(),
                    ) + q.rename.len()
                        + q.set.len()
                        + q.add.len()
                        + q.replace.len()
                        + 1
                }
                _ => 0,
            };
            let regex_size = match &op {
                Op::Regex(re, _) => re.search_memory() * 2,
                Op::Query(q) => q
                    .replace
                    .iter()
                    .filter_map(|v| v.3.as_ref())
                    .map(|re| re.search_memory() * 2)
                    .max()
                    .unwrap_or_default(),
                _ => 0,
            };
            let scratch = old_size
                .checked_mul(32)
                .and_then(|n| rows.checked_mul(1024).and_then(|rows| n.checked_add(rows)))
                .and_then(|n| n.checked_add(regex_size))
                .and_then(|n| n.checked_add(16 << 20))
                .ok_or_else(|| anyhow::anyhow!("rewrite workspace overflow"))?;
            let _scratch = pool.reserve(scratch)?;
            let _args = args;
            let mut state = if let Some(old) = old {
                (*old).clone()
            } else {
                State::read(&uri)?
            };
            match op {
                Op::Identity => {}
                Op::Strip(pattern, suffix) => state.strip(&pattern, suffix)?,
                Op::Substring(find, replace, limit, merge) => {
                    state
                        .change(|p| ops::replace(&ops::clean(p, merge), &find, &replace, limit))?;
                    state.query = ops::replace(&state.query, &find, &replace, limit)?;
                }
                Op::Regex(regex, replace) => state.change(|p| ops::regex(&regex, p, &replace))?,
                Op::Query(query) => state.query = ops::query(&state.query, query)?,
            }
            ensure!(
                state.bytes() <= ops::CAP * 4,
                "rewritten components exceed limit"
            );
            let request_uri = state.target_bytes(true)?;
            let _lease = Arc::new(pool.reserve(state.bytes() * 4 + request_uri.len() * 4 + 4096)?);
            Ok(Projection {
                state: Arc::new(state),
                request_uri: request_uri.into(),
                _lease,
            })
        })
        .await
        .map_err(|_| failure(StatusCode::SERVICE_UNAVAILABLE))??;
    Ok(state)
}
fn commit(ctx: &mut Context, projection: Projection) -> Result<()> {
    let target = projection.state.target(false)?;
    ensure!(
        !target.contains(['\r', '\n', '\0']),
        "invalid rewritten request URI"
    );
    let mut parts = http::uri::Parts::default();
    parts.path_and_query = Some(http::uri::PathAndQuery::from_native_rewrite_path_query(
        target,
    )?);
    *ctx.req_mut().uri_mut() = Uri::from_parts(parts)?;
    ctx.req_mut().extensions_mut().insert(projection);
    Ok(())
}
pub(super) struct Upstream {
    pub method: Method,
    pub projection: Projection,
    pub omit_body: bool,
}
impl Upstream {
    pub fn uri(&self) -> Result<Uri> {
        let mut parts = http::uri::Parts::default();
        parts.path_and_query = Some(http::uri::PathAndQuery::from_native_rewrite_path_query(
            self.projection.state.target(false)?,
        )?);
        Ok(Uri::from_parts(parts)?)
    }
}
pub(super) async fn apply(plan: &Arc<RewritePlan>, ctx: &mut Context) -> Result<()> {
    apply_plan(plan, ctx, false)
        .await
        .map(|_| ())
        .map_err(resource_error)
}
pub(super) async fn upstream(plan: &Arc<RewritePlan>, ctx: &mut Context) -> Result<Upstream> {
    apply_plan(plan, ctx, true).await.map_err(resource_error)
}
fn resource_error(error: anyhow::Error) -> anyhow::Error {
    if error.is::<native_write_policy::Denied>() {
        failure(StatusCode::SERVICE_UNAVAILABLE)
    } else {
        error
    }
}
async fn advance(
    ctx: &mut Context,
    current: &mut Option<Projection>,
    op: Op,
    args: Args,
    upstream: bool,
) -> Result<()> {
    let old = current
        .as_ref()
        .or_else(|| projection(ctx.req()))
        .map(|p| p.state.clone());
    let uri = ctx.req().uri().clone();
    let next = transform(ctx, old, uri, op, args).await?;
    if !upstream {
        commit(ctx, next.clone())?;
    }
    *current = Some(next);
    Ok(())
}
async fn apply_plan(
    plan: &Arc<RewritePlan>,
    ctx: &mut Context,
    upstream: bool,
) -> Result<Upstream> {
    let original_method = ctx.req().method().clone();
    let mut method = original_method.clone();
    let mut current = None;
    let original_uri = ctx.req().uri().clone();
    let original_projection = projection(ctx.req()).cloned();
    if !plan.method.is_empty() {
        method = ctx.expand_text_resolved(&plan.method,true).await?.to_uppercase().parse::<Method>()?;
        if !upstream {
            *ctx.req_mut().method_mut() = method.clone();
        }
    }
    if !plan.uri.is_empty() {
        let next = setter(plan, ctx).await?;
        if !upstream {
            commit(ctx, next.clone())?;
        }
        current = Some(next);
    }
    for (pattern, suffix) in [
        (&plan.strip_path_prefix, false),
        (&plan.strip_path_suffix, true),
    ] {
        if !pattern.is_empty() {
            let mut args = Args::new(ctx.resources.rewrite_bytes.clone())?;
            let pattern = args.expand(ctx.lookup_view(), pattern, false).await?;
            advance(
                ctx,
                &mut current,
                Op::Strip(pattern, suffix),
                args,
                upstream,
            )
            .await?;
        }
    }
    for rule in &plan.uri_substring {
        if rule.find.is_empty() {
            continue;
        }
        let mut args = Args::new(ctx.resources.rewrite_bytes.clone())?;
        let find = args.expand(ctx.lookup_view(), &rule.find, false).await?;
        let replace = args.expand(ctx.lookup_view(), &rule.replace, false).await?;
        let merge = !rule.find.contains("//");
        advance(
            ctx,
            &mut current,
            Op::Substring(find, replace, rule.limit, merge),
            args,
            upstream,
        )
        .await?;
    }
    for rule in &plan.path_regexp {
        let Some(regex) = &rule.regex else { continue };
        let mut args = Args::new(ctx.resources.rewrite_bytes.clone())?;
        let replacement = args.expand(ctx.lookup_view(), &rule.replace, false).await?;
        advance(
            ctx,
            &mut current,
            Op::Regex(regex.clone(), replacement),
            args,
            upstream,
        )
        .await?;
    }
    if let Some(query) = &plan.query {
        let mut args = Args::new(ctx.resources.rewrite_bytes.clone())?;
        let rename=args.pairs(ctx.lookup_view(),&query.rename,false).await?;
        let set=args.pairs(ctx.lookup_view(),&query.set,true).await?;
        let add=args.pairs(ctx.lookup_view(),&query.add,true).await?;
        let mut replace = Vec::with_capacity(query.replace.len());
        for r in &query.replace {
            replace.push((
                args.expand(ctx.lookup_view(), &r.key, false).await?,
                args.expand(ctx.lookup_view(), &r.search, true).await?,
                args.expand(ctx.lookup_view(), &r.replace, true).await?,
                r.regex.clone(),
            ));
        }
        let mut delete=Vec::with_capacity(query.delete.len());
        for value in &query.delete{delete.push(args.expand(ctx.lookup_view(),value,false).await?);}
        advance(
            ctx,
            &mut current,
            Op::Query(ops::Query {
                rename,
                set,
                add,
                replace,
                delete,
            }),
            args,
            upstream,
        )
        .await?;
    }
    let projection = if let Some(p) = current.or_else(|| projection(ctx.req()).cloned()) {
        p
    } else {
        transform(
            ctx,
            None,
            ctx.req().uri().clone(),
            Op::Identity,
            Args::new(ctx.resources.rewrite_bytes.clone())?,
        )
        .await?
    };
    let changed = method != original_method
        || projection.request_uri.as_ref()
            != original_projection.as_ref().map_or_else(
                || {
                    original_uri
                        .path_and_query()
                        .map_or("/", |p| p.as_str())
                        .as_bytes()
                },
                |p| p.request_uri.as_ref(),
            );
    if !upstream {
        ctx.req_mut().extensions_mut().insert(projection.clone());
    }
    Ok(Upstream {
        omit_body: !plan.method.is_empty()
            && changed
            && matches!(method, Method::GET | Method::HEAD),
        method,
        projection,
    })
}

async fn setter(plan: &Arc<RewritePlan>, ctx: &mut Context) -> Result<Projection> {
    let pool = ctx.resources.rewrite_bytes.clone();
    let mut args = Args::new(pool.clone())?;
    let mut values = std::collections::BTreeMap::<String, Vec<u8>>::new();
    let bytes = plan.uri.as_bytes();
    let mut at = 0usize;
    while at < bytes.len() {
        if bytes[at] != b'{' || (at > 0 && bytes[at - 1] == b'\\') {
            at += 1;
            continue;
        }
        let mut end = at + 1;
        while end < bytes.len()
            && (bytes[end] != b'}' || (bytes[end - 1] == b'\\' && end + 1 < bytes.len()))
        {
            end += 1;
        }
        if end == bytes.len() {
            break;
        }
        let name = &plan.uri[at + 1..end];
        if !values.contains_key(name) && crate::http_config::helpers::global_lookup(name).is_none()
        {
            ensure!(
                !ctx.values.get(name).is_some_and(|v| v.len() > ops::CAP),
                "rewrite placeholder exceeds limit"
            );
            if let Some(value) = ctx.lookup_resolved(name).await? {
                ensure!(value.len() <= ops::CAP, "rewrite placeholder exceeds limit");
                args.bytes = args
                    .bytes
                    .checked_add(name.len() + value.len())
                    .filter(|n| *n <= ops::CAP)
                    .ok_or_else(|| anyhow::anyhow!("rewrite snapshot limit exceeded"))?;
                args.leases
                    .push(pool.reserve(name.len() * 2 + value.len() * 2 + 1024)?);
                values.insert(name.to_owned(), value.to_vec());
            }
        }
        at = end + 1;
    }
    let old = projection(ctx.req()).map(|p| p.state.clone());
    let uri = ctx.req().uri().clone();
    let plan = plan.clone();
    drop(args.lookup.take());
    ctx.resources
        .request_regexp
        .run(move || -> Result<Projection> {
            let size = old
                .as_ref()
                .map_or_else(|| ops::uri_bytes(&uri), |p| p.bytes());
            args.leases.push(pool.reserve(size * 16 + 4096)?);
            let mut state = if let Some(old) = old {
                (*old).clone()
            } else {
                State::read(&uri)?
            };
            let bank = std::cell::RefCell::new(Vec::new());
            let denied = std::cell::Cell::new(false);
            let lookup = |name: &str| {
                let value = crate::http_config::helpers::global_lookup(name)
                    .map(String::into_bytes)
                    .or_else(|| values.get(name).cloned())?;
                if value.len() > ops::CAP {
                    denied.set(true);
                    return None;
                }
                match pool.reserve(value.len() * 8 + 128) {
                    Ok(credit) => bank.borrow_mut().push(credit),
                    Err(_) => {
                        denied.set(true);
                        return None;
                    }
                }
                Some(value)
            };
            let result = super::rewrite_uri::rewrite_uri(&plan.uri, &uri, lookup, |n| {
                bank.borrow_mut().push(pool.reserve(n + 128)?);
                Ok(())
            });
            args.leases.extend(bank.into_inner());
            ensure!(
                !denied.get(),
                "rewrite placeholder allocation limit exceeded"
            );
            let target = result?;
            if let Some(path) = target.path {
                state.path = path;
                state.raw_path.clear();
            }
            if let Some(query) = target.query {
                state.query = query;
            }

            if let Some((_, fragment)) = plan.uri.split_once('#') {
                state.fragment = replace_bytes_accounted(
                    fragment,
                    true,
                    |name| {
                        crate::http_config::helpers::global_lookup(name)
                            .map(String::into_bytes)
                            .or_else(|| values.get(name).cloned())
                    },
                    |n| {
                        args.leases.push(pool.reserve(n + 128)?);
                        Ok(())
                    },
                )?;
            }
            let request_uri = state.target_bytes(true)?;
            let credit = Arc::new(pool.reserve(state.bytes() * 4 + request_uri.len() * 4 + 4096)?);
            Ok(Projection {
                state: Arc::new(state),
                request_uri: request_uri.into(),
                _lease: credit,
            })
        })
        .await
        .map_err(|_| failure(StatusCode::SERVICE_UNAVAILABLE))?
}
