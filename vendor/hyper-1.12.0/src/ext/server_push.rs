//! Opt-in owned HTTP/2 push commands. Protocol work stays on its H2 stream task;
//! no extra bounds are placed on unrelated application Services or executors.
use super::ResponseWriteControl;
use bytes::Bytes;
use http::{HeaderMap,Request,Response};
use std::{fmt,sync::Arc,task::{Context,Poll}};
use tokio::sync::{mpsc,oneshot};

/// Bounded per-parent push queues. Zero disables the optional extension.
#[derive(Clone,Debug)]
pub(crate) struct PushLimits { pub(crate) pending:usize,pub(crate) live:usize,pub(crate) pool:native_write_policy::Pool }
impl PushLimits {
    pub(crate) fn new(pending:usize,live:usize,pool:native_write_policy::Pool)->Option<Self>{
        (pending>0 && pending<=16 && live>0 && live<=64).then_some(Self{pending,live,pool})
    }
}
/// Failure to admit or write one pushed resource. The parent remains independent.
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum PushError {
    /// The writer, parent admission or client connection has closed.
    Closed,
    /// The bounded promise or writer mailbox has no admission capacity.
    Full,
    /// Request/response headers or target exceed the metadata limit.
    HeadersTooLarge,
    /// One source item exceeds the 16 KiB output boundary.
    BodyTooLarge,
    /// Invalid stream order, handshake or write-control identity.
    Protocol,
    /// The child's actual transport output failed or expired.
    Write,
}
impl fmt::Display for PushError {
    fn fmt(&self,f:&mut fmt::Formatter<'_>)->fmt::Result{write!(f,"HTTP/2 push {:?}",self)}
}
impl std::error::Error for PushError {}

/// A request extension installed only by an opted-in HTTP/2 listener.
#[derive(Clone,Debug)]
pub struct ServerPush { tx:mpsc::Sender<PushRequest>, _credit:Arc<native_write_policy::Lease> }
impl ServerPush {
    /// Enqueue one owned promise. `retained` must own concrete prepaid request,
    /// child protocol, queue and response-metadata allocation credit; it may
    /// remain with connection tables after logical completion. Source DATA has
    /// its own ownership. Admission never creates unbounded waiting producers.
    pub async fn promise(&self,request:Request<()>,control:ResponseWriteControl,retained:Bytes)->Result<PushWriter,PushError>{
        check_headers(request.headers())?;
        let uri=request.uri();
        let uri_bytes=uri.scheme_str().map_or(0,str::len)
            .saturating_add(uri.authority().map_or(0,|a|a.as_str().len()))
            .saturating_add(uri.path_and_query().map_or(0,|p|p.as_str().len())).saturating_add(4);
        if uri_bytes>65536{return Err(PushError::HeadersTooLarge)}
        let (reply,receive)=oneshot::channel();
        self.tx.try_send(PushRequest{request,control,retained,reply}).map_err(map_send)?;
        receive.await.map_err(|_|PushError::Closed)?
    }
}
/// A uniquely owned, one-item-at-a-time writer for one promised stream.
#[derive(Debug)]
pub struct PushWriter { tx:mpsc::Sender<PushWrite>, abort:Option<oneshot::Sender<()>>, informational:Option<super::InformationalSender>, _retained:Bytes, _allocation:Arc<native_write_policy::Lease> }
impl Drop for PushWriter { fn drop(&mut self){drop(self.abort.take());} }
impl PushWriter {
    /// Claim this pushed response's unique interim writer before dispatch.
    pub fn take_informational(&mut self)->Option<super::InformationalSender>{self.informational.take()}

    /// Wait for this response HEADERS boundary to physically flush.
    pub async fn send_response(&mut self,response:Response<()>,end:bool)->Result<(),PushError>{
        check_headers(response.headers())?;
        let (reply,receive)=oneshot::channel();
        self.tx.try_send(PushWrite::Head{response,end,reply}).map_err(map_send)?;
        receive.await.map_err(|_|PushError::Closed)?
    }
    /// Retain one actual source chunk through flow control and physical flush.
    pub async fn send_data(&mut self,bytes:Bytes,end:bool)->Result<(),PushError>{
        if bytes.len()>16<<10{return Err(PushError::BodyTooLarge)}
        let (reply,receive)=oneshot::channel();
        self.tx.try_send(PushWrite::Data{bytes,end,reply}).map_err(map_send)?;
        receive.await.map_err(|_|PushError::Closed)?
    }
    /// Flush the final trailer boundary on this child only.
    pub async fn send_trailers(&mut self,headers:HeaderMap)->Result<(),PushError>{
        check_headers(&headers)?;
        let (reply,receive)=oneshot::channel();
        self.tx.try_send(PushWrite::Trailers{headers,reply}).map_err(map_send)?;
        receive.await.map_err(|_|PushError::Closed)?
    }
}
fn map_send<T>(error:mpsc::error::TrySendError<T>)->PushError{
    match error{mpsc::error::TrySendError::Full(_)=>PushError::Full,mpsc::error::TrySendError::Closed(_)=>PushError::Closed}
}
fn check_headers(headers:&HeaderMap)->Result<(),PushError>{
    let mut n=0usize;
    for(name,value)in headers{
        n=n.checked_add(name.as_str().len()).and_then(|n|n.checked_add(value.len())).and_then(|n|n.checked_add(32)).ok_or(PushError::HeadersTooLarge)?;
        if n>65536{return Err(PushError::HeadersTooLarge)}
    }
    Ok(())
}
#[derive(Debug)]
pub(crate) struct PushRequest {
    pub(crate) request:Request<()>,
    pub(crate) control:ResponseWriteControl,
    pub(crate) reply:oneshot::Sender<Result<PushWriter,PushError>>,
    pub(crate) retained:Bytes,
}
#[derive(Debug)]
pub(crate) enum PushWrite {
    Head{response:Response<()>,end:bool,reply:oneshot::Sender<Result<(),PushError>>},
    Data{bytes:Bytes,end:bool,reply:oneshot::Sender<Result<(),PushError>>},
    Trailers{headers:HeaderMap,reply:oneshot::Sender<Result<(),PushError>>},
}
pub(crate) struct PushReceiver { rx:mpsc::Receiver<PushRequest>,pub(crate) limit:usize,pub(crate) pool:native_write_policy::Pool,_credit:Arc<native_write_policy::Lease> }
impl PushReceiver {
    pub(crate) fn poll(&mut self,cx:&mut Context<'_>)->Poll<Option<PushRequest>>{self.rx.poll_recv(cx)}
    pub(crate) fn close(&mut self){self.rx.close()}
}
pub(crate) fn install<B>(request:&mut Request<B>,limits:&PushLimits)->Option<PushReceiver> {
    // Includes Tokio's first 32-cell MPSC block, shared channel/slot state,
    // extension/Arc cells and bounded pending promise reply metadata. Native
    // child protocol/body/message allocations are separately prepaid by promise.
    let bytes=std::mem::size_of::<PushRequest>().checked_mul(64)?.checked_add(8192)?;
    let credit=Arc::new(limits.pool.reserve(bytes).ok()?);
    let(tx,rx)=mpsc::channel(limits.pending);
    request.extensions_mut().insert(ServerPush{tx,_credit:credit.clone()});
    Some(PushReceiver{rx,limit:limits.live,pool:limits.pool.clone(),_credit:credit})
}
pub(crate) fn writer(retained:Bytes,limits:Option<super::InformationalLimits>,allocation:Arc<native_write_policy::Lease>)->(PushWriter,mpsc::Receiver<PushWrite>,oneshot::Receiver<()>,Option<super::InformationalReceiver>) {
    let(tx,rx)=mpsc::channel(1);let(abort,cancel)=oneshot::channel();
    let(sender,receiver)=limits.map(|limits|super::informational_channel(limits,true)).map_or((None,None),|(s,r)|(Some(s),Some(r)));
    (PushWriter{tx,abort:Some(abort),informational:sender,_retained:retained,_allocation:allocation},rx,cancel,receiver)
}

// Accepted reserved streams are real active requests even before their response
// HEADERS is generated. RFC stream-concurrency counts exclude those states;
// connection idle detection must not reuse that narrower count.
pub(crate) struct PushActivity{
    active:std::sync::atomic::AtomicUsize,waker:std::sync::Mutex<Option<std::task::Waker>>,
    _credit:native_write_policy::Lease,
}
impl PushActivity{
 pub(crate) fn new(limits:&PushLimits)->Option<Arc<Self>>{
    let credit=limits.pool.reserve(std::mem::size_of::<Self>()+256).ok()?;
    Some(Arc::new(Self{active:std::sync::atomic::AtomicUsize::new(0),waker:std::sync::Mutex::new(None),_credit:credit}))
 }
 pub(crate) fn register(&self,cx:&Context<'_>){
    let incoming=cx.waker().clone();let old={let mut slot=self.waker.lock().unwrap_or_else(|e|e.into_inner());if slot.as_ref().is_some_and(|w|w.will_wake(&incoming)){None}else{slot.replace(incoming)}};drop(old);
 }
 pub(crate) fn active(&self)->bool{self.active.load(std::sync::atomic::Ordering::Acquire)>0}
 fn wake(&self){let wake=self.waker.lock().unwrap_or_else(|e|e.into_inner()).take();if let Some(w)=wake{w.wake();}}
 pub(crate) fn acquire(self:&Arc<Self>)->PushActivityGuard{
    if self.active.fetch_add(1,std::sync::atomic::Ordering::AcqRel)==0{self.wake();}
    PushActivityGuard(self.clone())
 }
}
pub(crate) struct PushActivityGuard(Arc<PushActivity>);
impl Drop for PushActivityGuard{fn drop(&mut self){if self.0.active.fetch_sub(1,std::sync::atomic::Ordering::AcqRel)==1{self.0.wake();}}}
