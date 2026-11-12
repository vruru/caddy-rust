//! Extended CONNECT translation; no whole-stream buffering or wire callbacks.
use super::*;
use std::{future::Future, pin::Pin, sync::OnceLock, task::{Context as TaskContext, Poll}};
use tokio::io::AsyncWriteExt;
use futures_util::Stream;

const CREDIT: usize = 256 << 10;
const LIMIT: usize = 64 << 20;
static POOL: OnceLock<native_write_policy::Pool> = OnceLock::new();
static PAYLOAD_POOL: OnceLock<native_write_policy::Pool> = OnceLock::new();
const CHUNK_CREDIT:usize=(16<<10)+256;
pub(super) struct Prepared {
    upload: Mutex<Option<Body>>,
    _credit: native_write_policy::Lease,
}
pub(super) fn is_extended(request: &Request<Body>) -> bool {
    request.method() == http::Method::CONNECT && match request.version() {
        Version::HTTP_2 => request.extensions().get::<hyper::ext::Protocol>().is_some_and(|p|p.as_str()=="websocket"),
        Version::HTTP_3 => request.extensions().get::<::h3::ext::Protocol>().is_some_and(|p|p.as_str()=="websocket"),
        _ => false,
    }
}
pub(super) fn prepare(upload: Body) -> Result<Arc<Prepared>> {
    let credit = POOL.get_or_init(||native_write_policy::Pool::new(LIMIT)).reserve(CREDIT)
        .map_err(|_|super::super::request::failure(StatusCode::SERVICE_UNAVAILABLE))?;
    Ok(Arc::new(Prepared { upload: Mutex::new(Some(upload)), _credit: credit }))
}
impl Prepared {
    fn take_upload(&self) -> Option<Body> {
        let body = self.upload.lock().unwrap_or_else(|e|e.into_inner()).take();
        body
    }
}
struct Hold {
    trace: Option<Arc<super::super::tracing::Tunnel>>,
    _prepared: Arc<Prepared>,
    _client: HyperClient,
    _admission: Arc<super::super::proxy_policy::RequestLease>,
    _business: Arc<BusinessGuard>,
    _metrics: Option<(Arc<crate::metrics::observe::Group>,Option<crate::metrics::observe::Tunnel>)>,
}
// One actual application owner, not a separated marker. Body and writer are
// destroyed before the shared admission/observation owner on every exit path.
struct UploadIo{
    body:Body,
    writer:tokio::io::WriteHalf<TokioIo<hyper::upgrade::Upgraded>>,
    hold:Arc<Hold>,
}
impl UploadIo{
    fn trace(&self)->Option<Arc<super::super::tracing::Tunnel>>{self.hold.trace.clone()}
    async fn copy(&mut self)->std::io::Result<()>{
        while let Some(frame)=self.body.frame().await{
            let frame=frame.map_err(std::io::Error::other)?;
            if let Ok(data)=frame.into_data(){self.writer.write_all(&data).await?;}
        }
        self.writer.shutdown().await
    }
}
// No client, callback, semaphore or waker in this actual codec owner.
struct Chunk { bytes: Bytes, _credit: native_write_policy::Lease }
impl AsRef<[u8]> for Chunk { fn as_ref(&self)->&[u8]{&self.bytes} }
type Reader = tokio_util::io::ReaderStream<tokio::io::ReadHalf<TokioIo<hyper::upgrade::Upgraded>>>;
struct Download {
    reader: Reader,
    _hold: Arc<Hold>,
    cancel: CancellationToken,
    cancelled: Pin<Box<dyn Future<Output=()>+Send>>,
    done: bool,
    payload_credit: Option<native_write_policy::Lease>,
    pressure_timer: Option<Pin<Box<tokio::time::Sleep>>>,
}
impl Drop for Download { fn drop(&mut self){self.cancel.cancel();} }
impl hyper::body::Body for Download {
    type Data = Bytes;
    type Error = BoxError;
    fn poll_frame(mut self: Pin<&mut Self>,cx:&mut TaskContext<'_>)->Poll<Option<Result<hyper::body::Frame<Bytes>,BoxError>>>{
        if self.done {return Poll::Ready(None)}
        if self.cancelled.as_mut().poll(cx).is_ready(){
            self.done = true;
            return Poll::Ready(Some(Err(std::io::Error::new(std::io::ErrorKind::Interrupted,"WebSocket stream cancelled").into())));
        }
        if self.payload_credit.is_none() {
            loop {
                match PAYLOAD_POOL.get_or_init(||native_write_policy::Pool::new(64<<20)).reserve(CHUNK_CREDIT) {
                    Ok(credit)=>{self.payload_credit=Some(credit);self.pressure_timer=None;break},
                    Err(_)=>{
                        // The final codec owner releases only pure atomic state.
                        // Its destructor never calls a task waker under Quinn's
                        // lock. One existing-body timer retries bounded pressure.
                        let timer=self.pressure_timer.get_or_insert_with(||Box::pin(tokio::time::sleep(Duration::from_millis(10))));
                        if timer.as_mut().poll(cx).is_pending(){return Poll::Pending}
                        self.pressure_timer=None;
                    }
                }
            }
        }
        match Pin::new(&mut self.reader).poll_next(cx) {
            Poll::Ready(Some(Ok(bytes)))=>{
                let bytes = Bytes::from_owner(Chunk{bytes,_credit:self.payload_credit.take().expect("payload prepaid before read")});
                Poll::Ready(Some(Ok(hyper::body::Frame::data(bytes))))
            }
            Poll::Ready(Some(Err(error)))=>{self.done=true;self.cancel.cancel();Poll::Ready(Some(Err(error.into())))},
            Poll::Ready(None)=>{self.done=true;self.cancel.cancel();Poll::Ready(None)},
            Poll::Pending=>Poll::Pending,
        }
    }
    fn is_end_stream(&self)->bool{self.done}
}
pub(super) async fn h3_body(
    upstream: hyper::upgrade::OnUpgrade,
    prepared: Arc<Prepared>,
    ctx: &mut Context,
    inner: &Arc<Inner>,
    client: HyperClient,
    admission: Arc<super::super::proxy_policy::RequestLease>,
    close_delay: Option<Duration>,
) -> Result<Body> {
    let upstream = upstream.await?;
    let upload = prepared.take_upload().ok_or_else(||anyhow::anyhow!("WebSocket upload already claimed"))?;
    let (reader,writer) = tokio::io::split(TokioIo::new(upstream));
    let hold = Arc::new(Hold{
        trace:ctx.trace_tunnel(),
        _prepared:prepared,_client:client,_admission:admission,_business:ctx.business.clone(),
        _metrics:ctx.metrics.as_ref().map(|g|(g.clone(),g.retain_tunnel())),
    });
    let cancel = CancellationToken::new();
    let upload_cancel = cancel.clone();
    let hard_stop = ctx.business.generation().hard_stop.clone();
    let drain = ctx.drain.clone();
    let mut upload_io=UploadIo{body:upload,writer,hold:hold.clone()};
    inner.upgrades.spawn(async move {
        let mut trace_actor=super::super::tracing::TunnelActor::new(upload_io.trace());
        let copy=upload_io.copy();
        tokio::pin!(copy);
        let deadline = async {
            match close_delay {
                Some(delay)=>{drain.cancelled().await;tokio::time::sleep(delay).await;},
                None=>std::future::pending().await,
            }
        };
        tokio::select!{biased;
            _=hard_stop.cancelled()=>upload_cancel.cancel(),
            _=upload_cancel.cancelled()=>{},
            _=deadline=>upload_cancel.cancel(),
            result=&mut copy=>if result.is_err(){upload_cancel.cancel()}else{trace_actor.success()},
        }
    });
    Ok(Download{
        reader:tokio_util::io::ReaderStream::with_capacity(reader,16<<10),_hold:hold,
        cancelled:Box::pin(cancel.clone().cancelled_owned()),cancel,done:false,payload_credit:None,pressure_timer:None,
    }.boxed_unsync())
}


struct Allocation{_prepared:Arc<Prepared>}
impl AsRef<[u8]> for Allocation{fn as_ref(&self)->&[u8]{&[]}}
pub(super)fn write_allocation(prepared:&Arc<Prepared>,pool:&native_write_policy::Pool)->hyper::ext::ConnectWriteAllocation{
    // H2's receive stream belongs to the actual upgrade bridge. Its application
    // body is empty and must be retired outside all stream/store locks first.
    let body=prepared.take_upload();drop(body);
    hyper::ext::ConnectWriteAllocation{retained:Bytes::from_owner(Allocation{_prepared:prepared.clone()}),pool:pool.clone()}
}


// RFC 6455: the proxy is the WebSocket client for this one HTTP/1 attempt.
// Fixed-size state stays in Upgrade, never in the replay/shared Prepared cell.
pub(super) fn expected_accept(headers:&HeaderMap)->Result<[u8;28]>{
    use base64::Engine;
    use sha1::{Digest,Sha1};
    let key=single_ows_header(headers,http::header::SEC_WEBSOCKET_KEY)?;
    anyhow::ensure!(!key.contains(&b','),"WebSocket challenge contains multiple values");
    let mut digest=Sha1::new();
    digest.update(key);
    digest.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    let mut expected=[0u8;28];
    let len=base64::engine::general_purpose::STANDARD.encode_slice(digest.finalize(),&mut expected)?;
    anyhow::ensure!(len==expected.len(),"invalid WebSocket digest encoding length");
    Ok(expected)
}
pub(super) fn validate_accept(headers:&HeaderMap,expected:&[u8;28])->Result<()>{
    let received=single_ows_header(headers,http::header::SEC_WEBSOCKET_ACCEPT)?;
    anyhow::ensure!(received==expected,"upstream WebSocket accept mismatch");
    Ok(())
}
fn single_ows_header(headers:&HeaderMap,name:HeaderName)->Result<&[u8]>{
    let mut values=headers.get_all(name).iter();
    let value=values.next().ok_or_else(||anyhow::anyhow!("WebSocket handshake header missing"))?;
    anyhow::ensure!(values.next().is_none(),"WebSocket handshake header repeated");
    let mut value=value.as_bytes();
    while matches!(value.first(),Some(b' '|b'\t')){value=&value[1..];}
    while matches!(value.last(),Some(b' '|b'\t')){value=&value[..value.len()-1];}
    anyhow::ensure!(!value.is_empty(),"WebSocket handshake header empty");
    Ok(value)
}
