//! Opt-in HTTP/3 physical-output controller. No per-frame task or
//! polling interval: the socket owner wakes this existing request future.
use super::stream::Failure;
use hyper::ext::{ResponseWriteControl,ResponseWriteOwner};
use quinn::{Connection,StreamId,StreamTransmitObservation,StreamTransmitSnapshot};
use std::{future::Future,io,pin::Pin,task::{Context,Poll},time::Instant};

pub(super) struct Writer {
    owner:ResponseWriteOwner,
    observe:StreamTransmitObservation,
    connection:Connection,
    id:StreamId,
    timer:Pin<Box<tokio::time::Sleep>>,
    reported:u64,
    last_report:Option<Instant>,
    active:bool,
}
fn invalid(message:&'static str)->Failure {io::Error::other(message).into()}
impl Writer {
    pub(super) fn new(connection:Connection,id:StreamId,control:ResponseWriteControl)->Result<Self,Failure> {
        let owner=control.claim()?;
        let observe=connection.observe_stream_transmit(id)?;
        Ok(Self{owner,observe,connection,id,timer:Box::pin(tokio::time::sleep(std::time::Duration::ZERO)),reported:0,last_report:None,active:false})
    }
    fn policy(&self)->Result<quinn::StreamWritePolicy,Failure> {
        let p=self.owner.policy();let s=self.owner.snapshot();
        Ok(quinn::StreamWritePolicy {installed:p.installed,idle:p.idle,minimum_rate:p.minimum_rate,hard:p.hard,
            pending_since:s.pending_since.ok_or_else(||invalid("missing HTTP/3 physical boundary"))?,
            last_flush:s.last_flush,flushed_before:s.flushed_bytes})
    }
    pub(super) fn begin_wire(&mut self)->Result<(),Failure> {
        self.owner.start_boundary(0,Instant::now())?;
        let policy=self.policy()?;
        if let Some(scope)=self.owner.scoped_boundary()?{self.observe.begin_wire_scoped(policy,scope)?}else{self.observe.begin_wire(policy)?}
        self.reported=0;self.last_report=None;self.active=true;Ok(())
    }
    pub(super) fn begin_data(&mut self,length:usize)->Result<(),Failure> {
        // HTTP/3 DATA = one-byte type0 + QUIC varint length + payload.
        let n=u64::try_from(length).map_err(|_|invalid("HTTP/3 DATA length overflow"))?;
        let varint=match n {0..=63=>1,64..=16383=>2,16384..=1073741823=>4,1073741824..=4611686018427387903=>8,_=>return Err(invalid("HTTP/3 DATA length outside QUIC range"))};
        let start=self.connection.stream_written_offset(self.id)?.checked_add(1+varint)
            .ok_or_else(||invalid("HTTP/3 DATA offset overflow"))?;
        self.owner.start_boundary(length,Instant::now())?;
        let policy=self.policy()?;
        if let Some(scope)=self.owner.scoped_boundary()?{self.observe.begin_data_scoped(start,length,policy,scope)?}else{self.observe.begin_data(start,length,policy)?}
        self.reported=0;self.last_report=None;self.active=true;Ok(())
    }
    pub(super) fn seal_wire(&mut self,fin:bool)->Result<(),Failure> {
        let end=match self.connection.stream_written_offset(self.id) {
            Ok(end)=>end,
            Err(error)=>{let snapshot=self.observe.snapshot();if fin&&snapshot.fin{snapshot.end}else{return Err(error.into())}}
        };
        self.observe.seal_wire(end,fin)?;Ok(())
    }
    fn report(&mut self,snapshot:StreamTransmitSnapshot)->Result<bool,Failure> {
        if !self.active {return Ok(true)}
        let s=snapshot.operation.ok_or_else(||invalid("HTTP/3 physical observation missing"))?;
        if s.expired {self.owner.expire();}
        let added=s.flushed_payload.checked_sub(self.reported).ok_or_else(||invalid("HTTP/3 progress regressed"))?;
        if added!=0 {
            self.owner.flushed(usize::try_from(added).map_err(|_|invalid("HTTP/3 progress exceeds platform range"))?,
                s.last_wire.ok_or_else(||invalid("HTTP/3 progress has no physical clock"))?)?;
            self.reported=s.flushed_payload;
        } else if s.last_wire!=self.last_report && self.owner.snapshot().pending_since.is_some()
            && let Some(at)=s.last_wire {
            self.owner.wire_flushed(at)?;
        }
        self.last_report=s.last_wire;
        if s.expired {return Err(invalid("HTTP/3 actual output exceeded write deadline"))}
        if s.completed {
            if self.owner.snapshot().pending_since.is_some(){self.owner.flushed(0,s.last_wire.ok_or_else(||invalid("HTTP/3 completion has no physical clock"))?)?;}
            self.active=false;return Ok(true)
        }
        Ok(false)
    }
    fn poll_deadline(&mut self,cx:&mut Context<'_>)->Poll<Result<(),Failure>> {
        let at=match self.owner.deadline(){Ok(at)=>at,Err(e)=>return Poll::Ready(Err(e.into()))};
        let Some(at)=at else{return Poll::Pending};
        self.timer.as_mut().reset(tokio::time::Instant::from_std(at));
        if Instant::now()>=at || self.timer.as_mut().poll(cx).is_ready() {
            self.owner.expire();return Poll::Ready(Err(invalid("HTTP/3 response write deadline expired")))
        }
        Poll::Pending
    }
    fn poll_pending(&mut self,cx:&mut Context<'_>,want_boundary:bool)->Poll<Result<(),Failure>> {
        // Register under the same concrete observation lock used by the socket
        // owner; re-read racing progress before checking a stale timer.
        for _ in 0..16 {
            let snapshot=self.observe.snapshot();
            match self.report(snapshot){Ok(true)if want_boundary=>return Poll::Ready(Ok(())),Ok(_)=>{},Err(e)=>return Poll::Ready(Err(e))}
            if !self.active {return self.poll_deadline(cx)}
            match self.observe.poll_progress(cx,snapshot.end,snapshot.fin){
                Poll::Ready(next)=>{if let Err(e)=self.report(next){return Poll::Ready(Err(e))}},
                Poll::Pending=>return self.poll_deadline(cx),
            }
        }
        cx.waker().wake_by_ref();Poll::Pending
    }
    /// Output acceptance is separately awaited; a Ready producer does not
    /// complete its physical boundary. Poll it before checking a wall clock so
    /// an already flushed, sealed boundary isn't retroactively timed out.
    pub(super) async fn action<F:Future>(&mut self,future:F)->Result<F::Output,Failure> {
        tokio::pin!(future);
        std::future::poll_fn(|cx| {
            if let Err(e)=self.report(self.observe.snapshot()){return Poll::Ready(Err(e))}
            if let Poll::Ready(value)=future.as_mut().poll(cx){return Poll::Ready(Ok(value))}
            match self.poll_pending(cx,false){Poll::Ready(Err(e))=>Poll::Ready(Err(e)),_=>Poll::Pending}
        }).await
    }
    pub(super) async fn boundary(&mut self)->Result<(),Failure> {
        std::future::poll_fn(|cx|self.poll_pending(cx,true)).await
    }
    pub(super) fn finish(&self)->Result<(),Failure>{self.owner.finish()?;Ok(())}
}

impl Drop for Writer {
    fn drop(&mut self) {
        if self.owner.snapshot().terminal!=Some(hyper::ext::WriteTerminal::Success) {
            // The transport owns retransmission buffers independently of the
            // logical producer; cancellation affects only this send stream.
            let _=self.connection.reset_observed_stream(self.id,quinn::VarInt::from_u32(0x10c));
        }
    }
}
