//! Static-identity client using the same owned SSL record engine as managed TLS.
use super::{ClientConfig,Guard,ServerStream};
use crate::server_engine::{Admission,ServerEngine};
use std::{io,pin::Pin,sync::{Arc,Mutex,atomic::Ordering},task::{Context,Poll}};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead,AsyncWrite,ReadBuf};

impl ClientConfig {
    /// All SSL construction, handshake and record crypto use the bounded owned
    /// engine. The legacy public `connect`/`Stream` interface remains unchanged.
    pub async fn connect_owned_with_alpn<S:AsyncRead+AsyncWrite+Unpin>(
        self:&Arc<Self>,name:ServerName<'static>,io:S,alpn:Option<&[u8]>,
    )->io::Result<OwnedClientStream<S>>{
        let base=self.clone();let scope=base.scope.clone();let credits=base.connection_credits.clone();
        let result=async {
        let mut input=crate::connection_credits::ClientFactoryInput::new(base,name,alpn);
        let output=Arc::new(Mutex::new(None));let handoff=output.clone();
        let stream=ServerStream::prepare(io,scope,move||{
            let result=(||{
            let (ssl,guard)=input.configure()?;
            let gate=guard.clone();let admission:Admission=Arc::new(move||gate.check().is_ok());
            let engine=ServerEngine::new_client(ssl,guard.clone(),admission)?;
            let prior=handoff.lock().map_err(|_|io::Error::other("client identity handoff poisoned"))?.replace(guard);
            drop(prior);Ok(engine)
            })();input.retained(result)
        }).await.map_err(|e|crate::connection_credits::retain_error(e,&credits))?;
        let guard=output.lock().map_err(|_|io::Error::other("client identity handoff poisoned"))?.take().ok_or_else(||io::Error::other("client identity handoff missing"))?;
        guard.check()?;
        if guard.completed.load(Ordering::Acquire)!=1{return Err(io::Error::new(io::ErrorKind::InvalidData,"TLS handshake facts incomplete"));}
        let (stream,alpn)=stream.inspect(|ssl|ssl.selected_alpn_protocol().unwrap_or_default().to_vec()).await?;
        guard.check()?;Ok(OwnedClientStream{stream,alpn,guard})
        }.await;
        result.map_err(|e|crate::connection_credits::retain_error(e,&credits))
    }
}
pub struct OwnedClientStream<S>{
    stream:ServerStream<S>,
    alpn:Vec<u8>,
    guard:Arc<Guard>,
}
impl<S:AsyncRead+AsyncWrite+Unpin> OwnedClientStream<S>{
    pub fn get_ref(&self)->&S{self.stream.get_ref()}
    pub fn selected_alpn_protocol(&self)->&[u8]{&self.alpn}
    pub fn ssl_if_idle(&self)->Option<&openssl::ssl::SslRef>{self.stream.ssl()}
    pub fn completed_handshakes(&self)->usize{self.guard.completed.load(Ordering::Acquire)}
}
impl<S:AsyncRead+AsyncWrite+Unpin> AsyncRead for OwnedClientStream<S>{
    fn poll_read(self:Pin<&mut Self>,cx:&mut Context<'_>,buf:&mut ReadBuf<'_>)->Poll<io::Result<()>>{
        let this=self.get_mut();this.guard.check()?;let before=buf.filled().len();
        let result=Pin::new(&mut this.stream).poll_read(cx,buf);
        if let Err(error)=this.guard.check(){buf.filled_mut()[before..].fill(0);buf.set_filled(before);return Poll::Ready(Err(error));}
        result.map(|r|r.map_err(|e|this.guard.retained_error(e)))
    }
}
impl<S:AsyncRead+AsyncWrite+Unpin> AsyncWrite for OwnedClientStream<S>{
    fn poll_write(self:Pin<&mut Self>,cx:&mut Context<'_>,buf:&[u8])->Poll<io::Result<usize>>{
        let this=self.get_mut();this.guard.check()?;let result=Pin::new(&mut this.stream).poll_write(cx,buf);
        if matches!(result,Poll::Ready(Ok(_))){this.guard.check()?;}result.map(|r|r.map_err(|e|this.guard.retained_error(e)))
    }
    fn poll_flush(self:Pin<&mut Self>,cx:&mut Context<'_>)->Poll<io::Result<()>>{
        let this=self.get_mut();this.guard.check()?;let result=Pin::new(&mut this.stream).poll_flush(cx);
        if matches!(result,Poll::Ready(Ok(()))){this.guard.check()?;}result.map(|r|r.map_err(|e|this.guard.retained_error(e)))
    }
    fn poll_shutdown(self:Pin<&mut Self>,cx:&mut Context<'_>)->Poll<io::Result<()>>{
        let this=self.get_mut();this.guard.check()?;let result=Pin::new(&mut this.stream).poll_shutdown(cx);
        if matches!(result,Poll::Ready(Ok(()))){this.guard.check()?;}result.map(|r|r.map_err(|e|this.guard.retained_error(e)))
    }
    fn is_write_vectored(&self)->bool{self.stream.is_write_vectored()}
    fn poll_write_vectored(self:Pin<&mut Self>,cx:&mut Context<'_>,buf:&[io::IoSlice<'_>])->Poll<io::Result<usize>>{
        let this=self.get_mut();this.guard.check()?;let result=Pin::new(&mut this.stream).poll_write_vectored(cx,buf);
        if matches!(result,Poll::Ready(Ok(_))){this.guard.check()?;}result.map(|r|r.map_err(|e|this.guard.retained_error(e)))
    }
}
