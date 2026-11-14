//! Optional DEBUG-only proxy events through the existing bounded logging app.
//! Only numeric protocol facts: never headers, credentials, body or URL secrets.
use super::{Body,BoxError,Bytes};
use crate::logging::{Logging,Event,Origin,Level,Field,FieldValue};
use std::{sync::Arc,pin::Pin,task::{Context,Poll}};
use http_body_util::BodyExt;
#[derive(Clone)]pub(super) struct Verbose{logging:Arc<Logging>}
const MODULE:&str="http.handlers.reverse_proxy";
const LOGGER:&str="http.handlers.reverse_proxy";
impl Verbose{
    pub(super) fn capture(logging:Option<&Arc<Logging>>,enabled:bool)->Option<Self>{
        if !enabled{return None}let logging=logging?;
        logging.module_enabled(MODULE,LOGGER,Level::Debug).then(||Self{logging:logging.clone()})
    }
    pub(super) fn emit(&self,message:&'static str,fields:Vec<Field>){
        if let Ok(mut event)=Event::new(Origin::Module{module_id:MODULE.into()},LOGGER,Level::Debug,message){event.fields=fields;let _=self.logging.try_emit(event);}
    }
    pub(super) fn number(&self,message:&'static str,key:&'static str,n:u64){self.emit(message,vec![Field::new(key,FieldValue::U64(n))]);}
    pub(super) fn body(&self,body:Body)->Body{if hyper::body::Body::is_end_stream(&body){self.number("closed response body from upstream","bytes",0);self.emit("response finalized",Vec::new());return body}VerboseBody{body,log:self.clone(),bytes:0,done:false}.boxed_unsync()}
}
struct VerboseBody{body:Body,log:Verbose,bytes:u64,done:bool}
impl hyper::body::Body for VerboseBody{
    type Data=Bytes;type Error=BoxError;
    fn poll_frame(mut self:Pin<&mut Self>,cx:&mut Context<'_>)->Poll<Option<Result<hyper::body::Frame<Bytes>,BoxError>>>{
        let result=Pin::new(&mut self.body).poll_frame(cx);
        match &result{
            Poll::Ready(Some(Ok(frame)))=>if let Some(data)=frame.data_ref(){self.bytes=self.bytes.saturating_add(data.len()as u64);self.log.number("read response body from upstream","bytes",data.len()as u64);},
            Poll::Ready(Some(Err(_)))=>{self.done=true;self.log.number("closed response body from upstream","bytes",self.bytes);},
            Poll::Ready(None) if !self.done=>{self.done=true;self.log.number("closed response body from upstream","bytes",self.bytes);self.log.emit("response finalized",Vec::new());},_=>{}
        }
        if result.is_ready()&&!self.done&&self.body.is_end_stream(){self.done=true;self.log.number("closed response body from upstream","bytes",self.bytes);self.log.emit("response finalized",Vec::new());}
        result
    }
    fn is_end_stream(&self)->bool{self.body.is_end_stream()}
    fn size_hint(&self)->hyper::body::SizeHint{self.body.size_hint()}
}
