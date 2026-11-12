//! In-memory subrequests: these never open a network socket for the include URI.
use super::{pool::{Inherited,Tree},render::{RequestData,VirtualInclude}};
use crate::http_runtime::{ActiveServer,BusinessGuard,Inner,full,request::{RequestOrigin,handle_business}};
use http::{Request,Uri,header};
use http_body_util::BodyExt;
use std::{net::{IpAddr,Ipv4Addr,SocketAddr},sync::Arc};
fn error(message:&str)->gotmpl::TemplateError{gotmpl::TemplateError::Exec(message.into())}
#[derive(Clone)]
pub(super) struct VirtualTarget {pub uri:Uri}
pub(super) fn make(inner:Arc<Inner>,server:Arc<ActiveServer>,business:Arc<BusinessGuard>,parent:RequestData,tree:Arc<Tree>,depth:u8,local:SocketAddr)->VirtualInclude{
    let runtime=tokio::runtime::Handle::current();
    Arc::new(move|target,control|{
        control.check()?;
        if runtime.runtime_flavor()!=tokio::runtime::RuntimeFlavor::MultiThread{return Err(error("virtual templates require a multithread runtime"));}
        if depth>=3{return Err(error("virtual request cycle"));}
        let mut count=1i64;
        if let Some(raw)=parent.headers.get("caddy-templates-include"){
            if !raw.is_empty(){let previous=raw.to_str().ok().and_then(|s|s.parse::<i64>().ok()).ok_or_else(||error("invalid virtual request recursion header"))?;if previous>=3{return Err(error("virtual request cycle"));}count=previous.checked_add(1).ok_or_else(||error("virtual recursion count overflow"))?;}
        }
        let target=target.split_once('#').map_or(target,|(before,_)|before);
        let uri:Uri=target.parse().map_err(|_|error("invalid virtual request URI"))?;
        let path=uri.path_and_query().map_or("/",|p|p.as_str()).parse::<Uri>().map_err(|_|error("invalid virtual request target"))?;
        let mut request=Request::builder().method("GET").uri(path).body(full(bytes::Bytes::new())).map_err(|_|error("virtual request construction failed"))?;
        *request.headers_mut()=parent.headers.clone();
        request.headers_mut().insert(header::HOST,header::HeaderValue::from_str(&parent.host).map_err(|_|error("invalid virtual request Host"))?);
        request.headers_mut().insert(header::ACCEPT_ENCODING,header::HeaderValue::from_static("identity"));
        request.headers_mut().insert("caddy-templates-include",header::HeaderValue::from_str(&count.to_string()).map_err(|_|error("invalid virtual recursion count"))?);
        request.extensions_mut().insert(Inherited{tree:tree.clone(),depth:depth+1});
        request.extensions_mut().insert(VirtualTarget{uri});
        let inner=inner.clone();let server=server.clone();let business=business.clone();
        runtime.block_on(async{
            let future=async{
                let origin=RequestOrigin{peer:SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST),10_000),local,tls:false,sni:None};
                let response=Box::pin(handle_business(inner,server,request,origin,business,None)).await;
                let status=response.status();let mut body=response.into_body();let mut bytes=Vec::new();
                while let Some(frame)=body.frame().await{
                    let frame=frame.map_err(|_|error("virtual response body failed"))?;
                    if let Ok(data)=frame.into_data(){if data.len()>(1usize<<20).saturating_sub(bytes.len()){return Err(error("virtual response exceeds byte limit"));}control.charge_bytes(data.len())?;bytes.extend_from_slice(&data);}
                }
                if status.as_u16()>=400{return Err(error("virtual HTTP request failed"));}
                Ok(bytes)
            };
            tokio::select!{
                result=future=>result,
                _=control.cancel.cancelled()=>Err(error("virtual request cancelled")),
                _=tokio::time::sleep_until(tokio::time::Instant::from_std(control.deadline()))=>Err(error("virtual request timed out")),
            }
        })
    })
}
