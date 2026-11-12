use super::code_info::{self,CodeBlockAttrs};
use self::{lexer::Engine,vm::{Budget,Error}};
pub(crate) use lexer::Registry;
#[path="chroma/captures.rs"]mod captures;
#[path="chroma/classes.rs"]mod classes;
#[path="chroma/formatter.rs"]mod formatter;
#[path="chroma/lexer/mod.rs"]mod lexer;
#[path="chroma/vm/mod.rs"]mod vm;
use gotmpl::{BudgetAccount,BudgetMeter,BudgetedBytes,TemplateError};
use std::sync::{Arc,OnceLock};
static REGISTRY:OnceLock<std::result::Result<Registry,String>>=OnceLock::new();
/// Load and validate immutable lexer programs during module provisioning.
pub(crate) fn prepare()->gotmpl::Result<&'static Registry> {
    match REGISTRY.get_or_init(||{
        let db=serde_json::from_slice(include_bytes!("../../../assets/chroma-programs.json"))
            .map_err(|error|format!("invalid Chroma program asset: {error}"))?;
        Registry::new(db).map_err(|error|error.to_string())
    }) {
        Ok(registry)=>Ok(registry),
        Err(error)=>Err(TemplateError::Exec(error.clone())),
    }
}
/// Rendering cannot perform a hidden first-request registry initialization.
pub(crate) fn prepared()->gotmpl::Result<&'static Registry> {
    match REGISTRY.get() {
        Some(Ok(registry))=>Ok(registry),
        Some(Err(error))=>Err(TemplateError::Exec(error.clone())),
        None=>Err(TemplateError::Exec("Chroma registry was not provisioned".into())),
    }
}
pub(crate) enum Rendered { Html(BudgetedBytes), Fallback }
fn failure(error:Error)->TemplateError {
    match error {Error::Template(original)=>original,other=>TemplateError::Exec(format!("Chroma: {other}"))}
}
/// Tokens never escape the Engine's allocation owner. On both success and `?`
/// unwinding the declaration order frees tokens before their Engine, then its
/// shared account. Only the output transfers its reservation into a byte lease.
pub(crate) fn render(registry:&Registry,language:&[u8],input:&[u8],attrs:&CodeBlockAttrs,meter:Arc<BudgetMeter>)->gotmpl::Result<Rendered> {
    if attrs.no_highlight { return Ok(Rendered::Fallback); }
    let account=BudgetAccount::new(meter)?;
    render_with_account(registry,language,input,attrs,&account)
}
/// Markdown parsing, code-info parsing and highlighting share one allocation
/// owner. This entry does not create a second account or an independent limit.
pub(crate) fn render_with_account(registry:&Registry,language:&[u8],input:&[u8],attrs:&CodeBlockAttrs,account:&BudgetAccount)->gotmpl::Result<Rendered> {
    if attrs.no_highlight { return Ok(Rendered::Fallback); }
    let mut engine=Engine::new(registry,Budget::with_shared(account.clone()));
    let Some(tokens)=engine.highlight(language,input).map_err(failure)? else { return Ok(Rendered::Fallback); };
    let mut formatting=Budget::with_shared(account.clone());
    let output=formatter::format(&tokens,attrs,&mut formatting).map_err(failure)?;
    Ok(Rendered::Html(output))
}
