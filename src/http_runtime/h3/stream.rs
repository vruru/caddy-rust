//! Translate HTTP/3 frames without collecting or replaying message bodies.
use bytes::{Buf, Bytes};
use h3::error::Code;
use h3::server::RequestStream;
use http::{HeaderMap, HeaderName, HeaderValue, Request, Response, StatusCode, Version, header};
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, SizeHint};
use std::error::Error;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

pub type Failure = Box<dyn Error + Send + Sync>;
type Receiving = RequestStream<h3_quinn::RecvStream, Bytes>;
pub type Sending = RequestStream<h3_quinn::SendStream<Bytes>, Bytes>;
pub type Stream = RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

fn malformed(message: &'static str) -> Failure {
    io::Error::new(io::ErrorKind::InvalidData, message).into()
}

fn content_length(headers: &HeaderMap) -> Result<Option<u64>, Failure> {
    let mut result = None;
    for value in headers.get_all(header::CONTENT_LENGTH) {
        let raw = value.as_bytes();
        if raw.is_empty() || !raw.iter().all(u8::is_ascii_digit) {
            return Err(malformed("invalid HTTP/3 content-length"));
        }
        let length = value.to_str()?.parse()?;
        if result.is_some_and(|prior| prior != length) {
            return Err(malformed("conflicting HTTP/3 content-length"));
        }
        result = Some(length);
    }
    Ok(result)
}

fn is_hop(name: &str) -> bool {
    matches!(
        name,
        "connection" | "proxy-connection" | "keep-alive" | "transfer-encoding" | "upgrade" | "te"
    )
}

fn strip_hop(headers: &mut HeaderMap) {
    let nominated: Vec<HeaderName> = headers
        .get_all(header::CONNECTION)
        .iter()
        .flat_map(|value| value.as_bytes().split(|byte| *byte == b','))
        .filter_map(|raw| HeaderName::from_bytes(raw.trim_ascii()).ok())
        .collect();
    for name in nominated {
        headers.remove(name);
    }
    for name in [
        "connection",
        "proxy-connection",
        "keep-alive",
        "transfer-encoding",
        "upgrade",
        "te",
    ] {
        headers.remove(name);
    }
}

#[derive(Clone, Copy)]
enum Phase {
    Data,
    Trailers,
    Done,
}

pub struct Incoming {
    stream: Option<Receiving>,
    phase: Phase,
    remaining: Option<u64>,
}

impl Incoming {
    fn fail(&mut self, error: Failure) -> Poll<Option<Result<Frame<Bytes>, Failure>>> {
        self.phase = Phase::Done;
        // h3-quinn moves the native receive stream into the pending read
        // future. Dropping that owned future lets Quinn cancel safely even
        // when the shim's explicit stop_sending handle is temporarily empty.
        drop(self.stream.take());
        Poll::Ready(Some(Err(error)))
    }
}

impl Body for Incoming {
    type Data = Bytes;
    type Error = Failure;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Failure>>> {
        if matches!(self.phase, Phase::Data) {
            // Convert the opaque Buf while the recv stream is mutably borrowed.
            let polled = ready!(
                self.stream
                    .as_mut()
                    .expect("live request stream")
                    .poll_recv_data(cx)
            )
            .map(|data| data.map(|mut data| data.copy_to_bytes(data.remaining())));
            match polled {
                Ok(Some(bytes)) => {
                    if let Some(n) = self.remaining {
                        let Some(left) = n.checked_sub(bytes.len() as u64) else {
                            return self.fail(malformed("HTTP/3 data exceeded content-length"));
                        };
                        self.remaining = Some(left);
                    }
                    return Poll::Ready(Some(Ok(Frame::data(bytes))));
                }
                Ok(None) => {
                    if self.remaining.is_some_and(|n| n != 0) {
                        return self.fail(malformed("HTTP/3 data ended before content-length"));
                    }
                    self.phase = Phase::Trailers;
                }
                Err(error) => return self.fail(Box::new(error)),
            }
        }
        if matches!(self.phase, Phase::Trailers) {
            let next = ready!(
                self.stream
                    .as_mut()
                    .expect("live request stream")
                    .poll_recv_trailers(cx)
            );
            self.phase = Phase::Done;
            return Poll::Ready(match next {
                Ok(Some(headers)) => Some(Ok(Frame::trailers(headers))),
                Ok(None) => None,
                Err(error) => Some(Err(Box::new(error))),
            });
        }
        Poll::Ready(None)
    }
    fn is_end_stream(&self) -> bool {
        matches!(self.phase, Phase::Done)
    }
    fn size_hint(&self) -> SizeHint {
        self.remaining
            .map_or_else(SizeHint::new, SizeHint::with_exact)
    }
}

pub fn start(
    request: Request<()>,
    stream: Stream,
) -> Result<(Request<Incoming>, Sending), Failure> {
    let mut invalid = request
        .headers()
        .keys()
        .any(|name| name != header::TE && is_hop(name.as_str()));
    invalid |= request
        .headers()
        .get_all(header::TE)
        .iter()
        .any(|v| !v.as_bytes().trim_ascii().eq_ignore_ascii_case(b"trailers"));
    let length = content_length(request.headers());
    let (mut send, mut recv) = stream.split();
    if invalid || length.is_err() {
        recv.stop_sending(Code::H3_MESSAGE_ERROR);
        send.stop_stream(Code::H3_MESSAGE_ERROR);
        return Err(malformed("invalid HTTP/3 request framing"));
    }
    let (mut parts, _) = request.into_parts();
    parts.version = Version::HTTP_3;
    Ok((
        Request::from_parts(
            parts,
            Incoming {
                stream: Some(recv),
                phase: Phase::Data,
                remaining: length?,
            },
        ),
        send,
    ))
}

/// One in-flight informational frame per request. The handler continues only
/// after its own stream accepted the frame; unrelated streams are independent.
pub struct InterimWriter {
    sender: tokio::sync::mpsc::Sender<Interim>,
    count: usize,
    bytes: usize,
}

pub struct Interim {
    response: Response<()>,
    acknowledged: tokio::sync::oneshot::Sender<bool>,
}

pub fn interim_channel() -> (InterimWriter, tokio::sync::mpsc::Receiver<Interim>) {
    let (sender, receiver) = tokio::sync::mpsc::channel(1);
    (
        InterimWriter {
            sender,
            count: 0,
            bytes: 0,
        },
        receiver,
    )
}

impl InterimWriter {
    pub async fn send(&mut self, mut response: Response<()>) -> anyhow::Result<bool> {
        anyhow::ensure!(
            response.status().is_informational()
                && response.status() != StatusCode::SWITCHING_PROTOCOLS,
            "invalid HTTP/3 informational response status"
        );
        strip_hop(response.headers_mut());
        response.headers_mut().remove(header::CONTENT_LENGTH);
        response.headers_mut().remove(header::TRAILER);
        let size = response
            .headers()
            .iter()
            .try_fold(48usize, |sum, (name, value)| {
                sum.checked_add(32)?
                    .checked_add(name.as_str().len())?
                    .checked_add(value.as_bytes().len())
            });
        let Some(total) = size
            .and_then(|n| self.bytes.checked_add(n))
            .filter(|&n| n <= 64 * 1024)
        else {
            return Ok(true);
        };
        if self.count >= 64 {
            return Ok(true);
        }
        self.bytes = total;
        self.count += 1;
        let (acknowledged, wait) = tokio::sync::oneshot::channel();
        self.sender
            .send(Interim {
                response,
                acknowledged,
            })
            .await
            .map_err(|_| anyhow::anyhow!("HTTP/3 response stream closed"))?;
        wait.await
            .map_err(|_| anyhow::anyhow!("HTTP/3 response stream closed"))
    }
}

fn bind_writer(
    writer:&mut Option<super::write_control::Writer>,
    control:Option<hyper::ext::ResponseWriteControl>,
    connection:&quinn::Connection,
    id:quinn::StreamId,
)->Result<(),Failure>{
    if let Some(control)=control {
        if let Some(existing)=writer {
            if !existing.same_control(&control){return Err(malformed("HTTP/3 response write control changed"))}
        }else{*writer=Some(super::write_control::Writer::new(connection.clone(),id,control)?);}
    }
    Ok(())
}

pub async fn drive<B>(
    mut stream: Sending,
    mut interim: tokio::sync::mpsc::Receiver<Interim>,
    response: impl std::future::Future<Output = Response<B>>,
    head: bool,
    connection: quinn::Connection,
) -> Result<(), Failure>
where
    B: Body<Data = Bytes, Error = Failure> + Unpin,
{
    enum Event<B>{Interim(Option<Interim>),Final(Response<B>)}
    tokio::pin!(response);
    let id=quinn::StreamId::from(quinn::VarInt::from_u64(stream.send_id().into_inner())?);
    let mut writer:Option<super::write_control::Writer>=None;
    let mut open = true;
    loop {
        let next=async{tokio::select! {
            biased;
            next=interim.recv(),if open=>Event::Interim(next),
            response=&mut response=>Event::Final(response),
        }};
        let event=if let Some(writer)=&mut writer{writer.action(next).await?}else{next.await};
        match event {
            Event::Interim(Some(Interim{mut response,acknowledged})) if !acknowledged.is_closed()=>{
                let control=response.extensions_mut().remove::<hyper::ext::ResponseWriteControl>();
                bind_writer(&mut writer,control,&connection,id)?;
                let suppressed=if let Some(writer)=&mut writer {
                    writer.begin_wire()?;
                    match writer.action(stream.send_response(response)).await? {
                        Ok(())=>{writer.seal_wire(false)?;writer.boundary().await?;false},
                        Err(h3::error::StreamError::HeaderTooBig{..})=>{writer.discard_rejected_wire()?;true},
                        Err(error)=>return Err(error.into()),
                    }
                }else{match stream.send_response(response).await {
                    Ok(())=>false,
                    Err(h3::error::StreamError::HeaderTooBig{..})=>true,
                    Err(error)=>return Err(error.into()),
                }};
                let _=acknowledged.send(suppressed);
            },
            Event::Interim(Some(_))=>{},
            Event::Interim(None)=>open=false,
            Event::Final(response)=>return send_with_writer(stream,response,head,connection,writer).await,
        }
    }
}

pub async fn send<B>(stream:Sending,response:Response<B>,head:bool,connection:quinn::Connection)->Result<(),Failure>
where B:Body<Data=Bytes,Error=Failure>+Unpin {
    send_with_writer(stream,response,head,connection,None).await
}

async fn send_with_writer<B>(mut stream:Sending,response:Response<B>,head:bool,connection:quinn::Connection,mut writer:Option<super::write_control::Writer>)->Result<(),Failure>
where B:Body<Data=Bytes,Error=Failure>+Unpin {
    let (mut parts, mut body) = response.into_parts();
    let control=parts.extensions.remove::<hyper::ext::ResponseWriteControl>();
    let id=quinn::StreamId::from(quinn::VarInt::from_u64(stream.send_id().into_inner())?);
    bind_writer(&mut writer,control,&connection,id)?;
    let no_payload = head
        || parts.status == StatusCode::NO_CONTENT
        || parts.status == StatusCode::NOT_MODIFIED
        || parts.status.is_informational();
    if parts.status.is_informational() {
        stream.stop_stream(Code::H3_INTERNAL_ERROR);
        return Err(malformed("HTTP/3 final response cannot be informational"));
    }
    parts.version = Version::HTTP_3;
    strip_hop(&mut parts.headers);
    if parts.status == StatusCode::NO_CONTENT {
        parts.headers.remove(header::CONTENT_LENGTH);
    }
    if !head && !parts.headers.contains_key(header::CONTENT_LENGTH)
        && parts.status != StatusCode::NO_CONTENT
        && parts.status != StatusCode::NOT_MODIFIED
        && let Some(length) = body.size_hint().exact()
    {
        parts.headers.insert(
            header::CONTENT_LENGTH,
            HeaderValue::from_str(&length.to_string())?,
        );
    }
    let mut remaining = content_length(&parts.headers)?;
    if let Some(writer)=&mut writer {
        writer.begin_wire()?;
        writer.action(stream.send_response(Response::from_parts(parts, ()))).await??;
        writer.seal_wire(false)?;writer.boundary().await?;
    } else {
        stream.send_response(Response::from_parts(parts, ())).await?;
    }
    if !no_payload {
        let mut trailers_sent = false;
        loop {
            let next=if let Some(writer)=&mut writer {writer.action(body.frame()).await?}else{body.frame().await};
            let Some(next)=next else{break};
            let result: Result<(), Failure> = match next {
                Ok(frame) => match frame.into_data() {
                    Ok(data) => {
                        if trailers_sent || remaining.is_some_and(|n| n < data.len() as u64) {
                            Err(malformed("HTTP/3 response body violated framing"))
                        } else {
                            remaining = remaining.map(|n| n - data.len() as u64);
                            if let Some(writer)=&mut writer {
                                let mut data=data;
                                while !data.is_empty() {
                                    let chunk=data.split_to(data.len().min(16<<10));
                                    // Retain the actual source through local output. Quinn's
                                    // independently bounded copied/retransmit storage is separate.
                                    let retained=chunk.clone();
                                    writer.begin_data(chunk.len())?;
                                    writer.action(stream.send_data(chunk)).await??;
                                    writer.boundary().await?;
                                    drop(retained);
                                }
                                Ok(())
                            }else{stream.send_data(data).await.map_err(Into::into)}
                        }
                    }
                    Err(frame) => match frame.into_trailers() {
                        Ok(mut fields) if !trailers_sent && !remaining.is_some_and(|n| n != 0) => {
                            strip_hop(&mut fields);
                            fields.remove(header::CONTENT_LENGTH);
                            fields.remove(header::TRAILER);
                            trailers_sent = true;
                            if let Some(writer)=&mut writer {
                                writer.begin_wire()?;
                                writer.action(stream.send_trailers(fields)).await??;
                                writer.seal_wire(false)?;writer.boundary().await?;Ok(())
                            }else{stream.send_trailers(fields).await.map_err(Into::into)}
                        }
                        _ => Err(malformed("invalid HTTP/3 response trailers")),
                    },
                },
                Err(error) => Err(error),
            };
            if let Err(error) = result {
                stream.stop_stream(Code::H3_INTERNAL_ERROR);
                return Err(error);
            }
        }
        if remaining.is_some_and(|n| n != 0) {
            stream.stop_stream(Code::H3_INTERNAL_ERROR);
            return Err(malformed("HTTP/3 response ended before content-length"));
        }
    }
    if let Some(writer)=&mut writer {
        writer.begin_wire()?;writer.action(stream.finish()).await??;
        writer.seal_wire(true)?;writer.boundary().await?;writer.finish()?;
    }else{stream.finish().await?;}
    Ok(())
}
