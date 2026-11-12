//! One promised response's actual protocol owner. No application callbacks or
//! request Context enters h2 locks, and no extra Send/Clone bound is imposed.
use super::{SendBuf,response_write::{Controlled,compiled_policy}};
use crate::{common::{date,time::Time},ext::{PushError,PushWrite,ResponseWriteControl,ResponseWriteOwner}};
use bytes::{Buf,Bytes};
use std::{future::Future,pin::Pin,sync::Arc,task::{Context,Poll}};
use tokio::sync::{mpsc,oneshot};
enum Ack{Write(oneshot::Sender<Result<(),PushError>>),Info(oneshot::Sender<()>)}
impl Ack{fn complete(self,result:Result<(),PushError>){match self{Self::Write(reply)=>{let _=reply.send(result);},Self::Info(reply)=>{if result.is_ok(){let _=reply.send(());}}}}}
pub(super) struct Child<D:Buf> {
    response:Option<h2::server::SendPushedResponse<SendBuf<D>>>,
    tx:Option<h2::SendStream<SendBuf<D>>>,
    output:Controlled<D>,
    rx:mpsc::Receiver<PushWrite>,
    abort:oneshot::Receiver<()>,
    pending:Option<Ack>,
    informational:Option<crate::ext::InformationalReceiver>,
    ready_final:Option<PushWrite>,
    timer:Time,
    finished:bool,
    date_header:bool,
    _retained:Bytes,
    _activity:crate::ext::PushActivityGuard,
    _allocation:Arc<native_write_policy::Lease>,
}
impl<D:Buf+'static> Child<D> {
    pub(super) fn new(
        response:h2::server::SendPushedResponse<SendBuf<D>>,owner:ResponseWriteOwner,
        promise:h2::ext::DataWriteReceipt<SendBuf<D>>,timer:Time,rx:mpsc::Receiver<PushWrite>,
        abort:oneshot::Receiver<()>,retained:Bytes,date_header:bool,allocation:Arc<native_write_policy::Lease>,informational:Option<crate::ext::InformationalReceiver>,activity:crate::ext::PushActivityGuard,
    )->Self {
        Self{response:Some(response),tx:None,output:Controlled::new(owner,timer.clone(),Some(promise),false),
            rx,abort,pending:None,informational,ready_final:None,timer,finished:false,date_header,_retained:retained,_activity:activity,_allocation:allocation}
    }
    pub(super) fn poll(&mut self,cx:&mut Context<'_>)->Poll<Result<(),PushError>> {
        if self.finished{return Poll::Ready(Ok(()))}
        if Pin::new(&mut self.abort).poll(cx).is_ready(){return self.fail(PushError::Closed)}
        // Re-enter output after every accepted source item. Returning Pending
        // immediately after queue_output would leave no actual write wake armed.
        for _ in 0..32 {
            let output=if let Some(tx)=self.tx.as_mut(){
                if tx.poll_reset(cx).is_ready(){return self.fail(PushError::Write)}
                self.output.poll_output(tx,cx)
            }else{
                if self.response.as_mut().expect("live promised reply").poll_reset(cx).is_ready(){return self.fail(PushError::Write)}
                self.output.poll_header(cx).map(|result|result.map(|()|false))
            };
            match output {
                Poll::Pending=>return Poll::Pending,
                Poll::Ready(Err(_))=>return self.fail(PushError::Write),
                Poll::Ready(Ok(ended))=>{
                    if ended{self.finished=true;}
                    if let Some(reply)=self.pending.take(){reply.complete(Ok(()));}
                    if ended{return Poll::Ready(Ok(()))}
                }
            }
            if let Some(info)=self.informational.as_mut(){
                if let Some(control)=info.poll_write_control(cx){
                    if !self.output.owner().same_control(&control){return self.fail(PushError::Protocol)}
                }
            }
            if let Some(command)=self.ready_final.take(){
                if let Err(error)=self.command(command){return self.fail(error)}
                continue;
            }
            if let Some(info)=self.informational.as_mut(){
                if let Poll::Ready(head)=info.poll_take(cx){
                    self.pending=Some(Ack::Info(head.ack));
                    if let Err(error)=self.head(head.response,false){return self.fail(error)}
                    continue;
                }
            }
            let command=match self.rx.poll_recv(cx){
                Poll::Pending=>return Poll::Pending,
                Poll::Ready(None)=>return self.fail(PushError::Closed),
                Poll::Ready(Some(command))=>command,
            };
            if matches!(&command,PushWrite::Head{response,..} if !response.status().is_informational()){
                if let Some(head)=self.informational.as_mut().and_then(|info|info.close_take()){
                    self.ready_final=Some(command);
                    self.pending=Some(Ack::Info(head.ack));
                    if let Err(error)=self.head(head.response,false){return self.fail(error)}
                    continue;
                }
            }
            if let Err(error)=self.command(command){return self.fail(error)}
        }
        cx.waker().wake_by_ref();Poll::Pending
    }
    fn command(&mut self,command:PushWrite)->Result<(),PushError>{
        match command {
            PushWrite::Head{response,end,reply}=>{
                self.pending=Some(Ack::Write(reply));
                self.head(response,end)?;
            }
            PushWrite::Data{bytes,end,reply}=>{
                self.pending=Some(Ack::Write(reply));
                if self.tx.is_none(){return Err(PushError::Protocol)}
                if bytes.len()>16<<10{return Err(PushError::BodyTooLarge)}
                self.output.queue_output(bytes,end);
            }
            PushWrite::Trailers{headers,reply}=>{
                self.pending=Some(Ack::Write(reply));
                let tx=self.tx.as_mut().ok_or(PushError::Protocol)?;
                let owner=self.output.owner();
                owner.start_boundary(0,self.timer.now()).map_err(|_|PushError::Write)?;
                let receipt=tx.send_trailers_observed_with_policy(headers,owner.retention(),Some(compiled_policy(owner).map_err(|_|PushError::Write)?)).map_err(|_|PushError::Write)?;
                self.output.set_header(receipt,true);
            }
        }
        Ok(())
    }
    fn head(&mut self,mut response:http::Response<()>,end:bool)->Result<(),PushError>{
                if self.response.is_none()||response.status().as_u16()==101{return Err(PushError::Protocol)}
                if let Some(control)=response.extensions_mut().remove::<ResponseWriteControl>(){
                    if !self.output.owner().same_control(&control){return Err(PushError::Protocol)}
                }
                super::strip_connection_headers(response.headers_mut(),super::MessageKind::Response);
                let interim=response.status().is_informational();
                if interim&&end{return Err(PushError::Protocol)}
                if !interim&&self.date_header{
                    response.headers_mut().entry(http::header::DATE).or_insert_with(date::update_and_header_value);
                }
                let owner=self.output.owner();
                owner.start_boundary(0,self.timer.now()).map_err(|_|PushError::Write)?;
                let policy=Some(compiled_policy(owner).map_err(|_|PushError::Write)?);
                let reply=self.response.as_mut().expect("checked promised response");
                if interim{
                    let receipt=reply.send_informational_observed_with_policy(response,owner.retention(),policy).map_err(|_|PushError::Write)?;
                    self.output.set_header(receipt,false);
                }else{
                    let(tx,receipt)=reply.send_response_observed_with_policy(response,end,owner.retention(),policy).map_err(|_|PushError::Write)?;
                    self.tx=Some(tx);self.output.set_header(receipt,end);
                    // send_response has returned: no h2 lock is held here.
                    drop(self.response.take());
                }
        Ok(())
    }
}
impl<D:Buf> Child<D>{
    fn reset(&mut self,error:PushError){
        if self.finished{return}self.finished=true;
        if let Some(tx)=self.tx.as_mut(){tx.send_reset(h2::Reason::CANCEL);}
        else if let Some(response)=self.response.as_mut(){response.send_reset(h2::Reason::CANCEL);}
        self.output.owner().abandon();
        // Every h2 call above has returned before an external task can wake.
        if let Some(reply)=self.pending.take(){reply.complete(Err(error));}
    }
    fn fail(&mut self,error:PushError)->Poll<Result<(),PushError>>{self.reset(error);Poll::Ready(Err(error))}
}
impl<D:Buf> Drop for Child<D>{fn drop(&mut self){self.reset(PushError::Write)}}
