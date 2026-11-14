//! Handler-local forwarding trust and RFC9209 Incremental refusal.
use super::{request::Context,resource_budget::BudgetError};
use crate::http_config::types::ProxyConfig;
use http::{HeaderMap,HeaderValue,StatusCode,Method};
use sfv::visitor::{ListVisitor,EntryVisitor,ItemVisitor,ParameterVisitor,InnerListVisitor,Never};
use std::convert::Infallible;
pub(super) fn trusted(ctx:&Context,config:&ProxyConfig)->bool{
    ctx.trusted||ctx.peer.ip().is_some_and(|ip|config.handler.trusted_proxies.iter().any(|range|range.contains(&ip)))
}
pub(super) fn request_has_content(ctx:&Context,method:&Method,omitted:bool)->bool{
    if omitted{return false}
    let n=ctx.proxy_content_length();
    n>0 || n<0&&!matches!(*method,Method::GET|Method::HEAD|Method::OPTIONS|Method::DELETE|Method::TRACE|Method::CONNECT)
}
pub(super) fn response_has_content(method:&Method,response:&http::Response<super::Body>)->bool{
    use hyper::body::Body;
    method!=Method::HEAD&&!response.body().is_end_stream()
        && response.headers().get(http::header::CONTENT_LENGTH).is_none_or(|v|v.as_bytes()!=b"0")
        && !(100..200).contains(&response.status().as_u16())
        && !matches!(response.status(),StatusCode::NO_CONTENT|StatusCode::RESET_CONTENT|StatusCode::NOT_MODIFIED)
}
pub(super) fn refuse(ctx:&mut Context,name:&str,upstream:Option<&HeaderMap>)->anyhow::Error{
    match status(ctx,name,upstream){
        Ok(Some(value))=>{ctx.immediate.insert("proxy-status",value);},
        Ok(None)=>{},Err(error)=>return error,
    }
    super::request::failure(StatusCode::NOT_IMPLEMENTED)
}
struct StatusBytes{bytes:String,_credit:native_write_policy::Lease}
impl AsRef<[u8]> for StatusBytes{fn as_ref(&self)->&[u8]{self.bytes.as_bytes()}}
fn status(ctx:&mut Context,name:&str,headers:Option<&HeaderMap>)->anyhow::Result<Option<HeaderValue>>{
    if name.is_empty(){return Ok(None)}
    let size=headers.map_or(0,|h|h.get_all("proxy-status").iter().fold(0usize,|n,v|n.saturating_add(v.len()).saturating_add(2)));
    let cost=size.checked_add(name.len().checked_mul(2).ok_or_else(||super::request::budget_failure(ctx,BudgetError::Overloaded))?).and_then(|n|n.checked_mul(8)).and_then(|n|n.checked_add(2048)).ok_or_else(||super::request::budget_failure(ctx,BudgetError::Overloaded))?;
    let credit=ctx.resources.transfer_deadlines.reserve(cost).map_err(|_|super::request::budget_failure(ctx,BudgetError::Overloaded))?;
    let own=if let Ok(token)=sfv::TokenRef::from_str(name){sfv::ItemSerializer::new().bare_item(token).parameter(sfv::key_ref("error"),sfv::TokenRef::from_str("incremental_refused")?).finish()}
        else if let Ok(text)=sfv::StringRef::from_str(name){sfv::ItemSerializer::new().bare_item(text).parameter(sfv::key_ref("error"),sfv::TokenRef::from_str("incremental_refused")?).finish()}
        else{return Ok(None)};
    let mut chain=String::new();chain.try_reserve_exact(size)?;
    if let Some(headers)=headers{for(i,value) in headers.get_all("proxy-status").iter().enumerate(){
        if i>0{chain.push_str(", ");}
        let Ok(value)=std::str::from_utf8(value.as_bytes())else{chain.clear();break};chain.push_str(value);
    }}
    let trimmed=chain.trim_matches([' ','\t']);
    if trimmed.len()!=chain.len(){chain=trimmed.to_owned();}
    if !valid_chain(chain.as_bytes()){chain.clear();}
    if !chain.is_empty(){chain.push_str(", ");}chain.push_str(&own);
    let bytes=bytes::Bytes::from_owner(StatusBytes{bytes:chain,_credit:credit});
    Ok(Some(HeaderValue::from_maybe_shared(bytes)?))
}
#[derive(Debug)]struct Invalid;
impl std::fmt::Display for Invalid{fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{f.write_str("invalid Proxy-Status member")}}
impl std::error::Error for Invalid{}
struct Chain;
impl<'a> ListVisitor<'a> for Chain{
    type Out=();type Error=Infallible;
    fn entry(&mut self)->Result<impl EntryVisitor<'a>,Self::Error>{Ok(Chain)}
    fn finish(self)->Result<(),Self::Error>{Ok(())}
}
impl<'a> EntryVisitor<'a> for Chain{
    type Error=Invalid;
    fn item(self)->Result<impl ItemVisitor<'a>,Self::Error>{Ok(Chain)}
    fn inner_list(self)->Result<impl InnerListVisitor<'a>,Self::Error>{Err::<Never,_>(Invalid)}
}
impl<'a> ItemVisitor<'a> for Chain{
    type Out=();type Error=Invalid;
    fn bare_item(self,value:sfv::BareItemFromInput<'a>)->Result<impl ParameterVisitor<'a,Out=()>,Self::Error>{
        if matches!(value,sfv::BareItemFromInput::String(_)|sfv::BareItemFromInput::Token(_)){Ok(sfv::visitor::Ignored)}else{Err(Invalid)}
    }
}
fn valid_chain(input:&[u8])->bool{sfv::Parser::new(input).with_version(sfv::Version::Rfc8941).parse_list_with_visitor(Chain).is_ok()}
