//! Response template middleware. Rendering and file access use a bounded
//! blocking lane; unrelated streaming responses never enter that lane.

#[path = "templates/render.rs"]
pub(super) mod render;
#[path = "templates/pool.rs"]
mod pool;
#[path = "templates/virtual.rs"]
mod virtual_request;
pub(super) use pool::Budget;
/// Prepare immutable host and lexer metadata before accepting requests.
pub(crate) fn prepare_metadata()->gotmpl::Result<()>{render::prepare_metadata()}

use super::{
    Body, full, request::Context,
    resource_budget::BudgetError,
};
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, StatusCode, header};
use http_body_util::BodyExt;
use std::{path::PathBuf, sync::Arc, time::Duration};

use tokio_util::sync::CancellationToken;

const BODY_LIMIT: usize = 1024 * 1024;
const RESPONSE_HEADERS_LIMIT: usize = 128 * 1024;
const BODY_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone)]
pub(crate) struct TemplatePlan {
    pub root: String,
    pub mime_types: Vec<String>,
    pub delimiters: [String; 2],
}

#[derive(Debug)]
pub(super) struct TemplateFailure(pub StatusCode);

impl std::fmt::Display for TemplateFailure {
    fn fmt(&self, writer: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writer.write_str("response template failed")
    }
}

impl std::error::Error for TemplateFailure {}

struct StopOnDrop(CancellationToken);
impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

struct BufferedBytes {
    bytes: Vec<u8>,
    _tree: Arc<pool::Tree>,
}
impl AsRef<[u8]> for BufferedBytes {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

fn bounded_headers(headers: &HeaderMap) -> bool {
    headers
        .iter()
        .map(|(name, value)| 64 + name.as_str().len() + value.as_bytes().len())
        .try_fold(0usize, |sum, size| {
            sum.checked_add(size).filter(|sum| *sum <= RESPONSE_HEADERS_LIMIT)
        })
        .is_some()
}

pub(super) async fn finish(
    plan: &Arc<TemplatePlan>,
    headers: &mut HeaderMap,
    mut body: Body,
    ctx: &mut Context,
    inner: &Arc<super::Inner>,
    server: &Arc<super::ActiveServer>,
) -> Result<Body, TemplateFailure> {
    // Go tests only the first Content-Type value, case-sensitive substring.
    let content_type = headers.get(header::CONTENT_TYPE).map_or(b"".as_slice(), HeaderValue::as_bytes);
    if !plan.mime_types.iter().any(|mime| {
        let mime = mime.as_bytes();
        mime.is_empty() || content_type.windows(mime.len()).any(|window| window == mime)
    }) {
        return Ok(body);
    }

    let unavailable = || TemplateFailure(StatusCode::SERVICE_UNAVAILABLE);
    let broken = || TemplateFailure(StatusCode::INTERNAL_SERVER_ERROR);
    let inherited=ctx.req().extensions().get::<pool::Inherited>().cloned();
    let memory=if inherited.is_none(){Some(ctx.resources.templates.reserve().map_err(|_|unavailable())?)}else{None};
    let control=inherited.as_ref().map_or_else(||render::Control::new(CancellationToken::new()),|inherited|inherited.tree.control.clone());
    let _stop=if inherited.is_none(){Some(StopOnDrop(control.cancel.clone()))}else{None};
    if !bounded_headers(headers) || !bounded_headers(ctx.req().headers()) {
        return Err(broken());
    }
    let root = crate::http_config::helpers::replace(&plan.root, true, |key| {
        ctx.lookup(key).or_else(|| Some(".".into()))
    })
    .map(PathBuf::from)
    .map_err(|_| broken())?;
    let request = render::RequestData::capture(ctx).map_err(|_| broken())?;

    let mut rendered_headers = headers.clone();
    // All further awaits own their request context. In particular, a template
    // job never holds a borrow to the streaming request's non-Sync Body.
    let head=ctx.req().method()==http::Method::HEAD;
    let collected = tokio::time::timeout(BODY_TIMEOUT, async {
        let mut input = Vec::new();let mut trailers=None;
        if head{return Ok((input,trailers));}
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|error| {
                if super::request_body::limit_error(error.as_ref()) {
                    TemplateFailure(StatusCode::PAYLOAD_TOO_LARGE)
                } else {
                    broken()
                }
            })?;
            match frame.into_data() {Ok(data) => {
                if data.len() > BODY_LIMIT.saturating_sub(input.len()) {
                    return Err(broken());
                }
                control.charge_bytes(data.len()).map_err(|_|broken())?;
                input.extend_from_slice(&data);
            },Err(frame)=>{if let Ok(value)=frame.into_trailers(){if !bounded_headers(&value){return Err(broken());}trailers=Some(value);}}}
        }
        Ok((input,trailers))
    })
    .await
    .map_err(|_| broken())??;

    let (collected,trailers)=collected;
    let root_owner=if inherited.is_none(){Some(ctx.resources.templates.admit(control.clone(),memory.ok_or_else(broken)?).await.map_err(|error|match error{BudgetError::Overloaded=>unavailable(),BudgetError::WorkerFailed=>broken()})?)}else{None};
    let tree=if let Some(inherited)=&inherited{inherited.tree.clone()}else{root_owner.as_ref().ok_or_else(broken)?.tree()};
    let depth=inherited.as_ref().map_or(0,|inherited|inherited.depth);
    let virtual_include=virtual_request::make(inner.clone(),server.clone(),ctx.business.clone(),request.clone(),tree.clone(),depth,ctx.local.clone());
    let mut form_reads=request.form.attach().map_err(|_|broken())?;
    let resources=ctx.resources.clone();let reading_control=control.clone();
    let plan=plan.clone();let owner=tree.clone();let name=request.uri.path().to_owned();
    let job=resources.templates.run(tree,move||{
        let result=render::execute_named(&plan,root,request,&mut rendered_headers,&name,collected,control,Some(virtual_include),std::collections::BTreeMap::new());
        (result,rendered_headers)
    });
    tokio::pin!(job);
    let result=loop{tokio::select!{
        Some(read)=form_reads.recv()=>{
            let result=read_form_body(ctx.req_mut().body_mut(),&reading_control).await;
            let _=read.reply.send(result);
        }
        result=&mut job=>break result,
    }};
    if let Some(owner)=root_owner.as_ref(){owner.finish();}
    let (result,mut rendered_headers)=result.map_err(|error|match error{BudgetError::Overloaded=>unavailable(),BudgetError::WorkerFailed=>broken()})?;
    *headers=rendered_headers.clone();
    let output=BufferedBytes{bytes:result?,_tree:owner};
    rendered_headers.insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&output.bytes.len().to_string()).map_err(|_| broken())?,
    );
    for field in [header::ACCEPT_RANGES, header::LAST_MODIFIED, header::ETAG] {
        rendered_headers.remove(field);
    }
    *headers = rendered_headers;
    let body=full(Bytes::from_owner(output));
    Ok(if let Some(trailers)=trailers{body.with_trailers(async move{Some(Ok(trailers))}).boxed_unsync()}else{body})
}

pub(super) fn finish_empty(headers:&mut HeaderMap)->Body{
    headers.insert(header::CONTENT_LENGTH,HeaderValue::from_static("0"));
    for field in [header::ACCEPT_RANGES,header::LAST_MODIFIED,header::ETAG]{headers.remove(field);}
    full(Bytes::new())
}

async fn read_form_body(body:&mut Body,control:&Arc<render::Control>)->gotmpl::Result<render::forms::BodyRead>{
    use render::forms::BodyRead;
    let read=async{
        let mut bytes=Vec::new();
        while let Some(frame)=body.frame().await{
            let frame=match frame{Ok(frame)=>frame,Err(error)=>return Ok(BodyRead::Io(if super::request_body::limit_error(error.as_ref()){"http: request body too large".into()}else{error.to_string()}))};
            if let Ok(data)=frame.into_data(){
                control.charge_bytes(data.len())?;
                if data.len()>BODY_LIMIT.saturating_sub(bytes.len()){return Ok(BodyRead::TooLarge);}
                bytes.extend_from_slice(&data);
            }
        }
        Ok(BodyRead::Bytes(bytes))
    };
    tokio::select!{
        result=read=>result,
        _=control.cancel.cancelled()=>Err(gotmpl::TemplateError::Exec("template body read cancelled".into())),
        _=tokio::time::sleep_until(tokio::time::Instant::from_std(control.deadline()))=>{control.cancel.cancel();Err(gotmpl::TemplateError::Exec("template body read timed out".into()))},
    }
}
