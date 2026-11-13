//! Request-local route clauses, with actual transport enforcement delegated to
//! the shared HTTP/1, HTTP/2 and QUIC physical-output controls.
use super::{Body,BoxError};
use bytes::Bytes;
use http::{Response,Version};
use hyper::{body::{Body as _,Frame,SizeHint},ext::{ResponseWriteControl,WritePolicy}};
use native_write_policy::{Lease,Pool,PolicySet,Rule,MAX_RULES};
use std::{num::NonZeroU64,pin::Pin,task::{Context,Poll},time::{Duration,Instant}};
use super::read_deadline::{ReadBody,ReadPolicy,SharedRead};
use http_body_util::BodyExt;

pub(super) struct RequestTimeouts {
    reads:Vec<SharedRead>,
    writes:Vec<Rule>,
    write:Option<ResponseWriteControl>,
    chunk:Option<usize>,
    scopes:usize,
    version:Version,
    _credit:Lease,
}
fn denied()->anyhow::Error {anyhow::anyhow!("request timeout allocation or policy budget exhausted")}
impl RequestTimeouts {
    fn new(pool:&Pool,version:Version,capacity:usize)->anyhow::Result<Box<Self>> {
        let bytes=Self::allocation_bound(capacity)?;
        let credit=pool.reserve(bytes)?;
        let(mut reads,mut writes)=(Vec::new(),Vec::new());
        reads.try_reserve_exact(capacity)?;writes.try_reserve_exact(capacity)?;
        anyhow::ensure!(reads.capacity()==capacity&&writes.capacity()==capacity,"unexpected timeout clause allocation capacity");
        Ok(Box::new(Self{reads,writes,write:None,chunk:None,scopes:0,version,_credit:credit}))
    }
    fn allocation_bound(capacity:usize)->anyhow::Result<usize>{
        anyhow::ensure!((1..=MAX_RULES).contains(&capacity),"invalid timeout clause capacity");
        let entry=std::mem::size_of::<SharedRead>()+std::mem::size_of::<Rule>();
        std::mem::size_of::<Self>().checked_add(entry.checked_mul(capacity).ok_or_else(denied)?).and_then(|n|n.checked_add(256)).ok_or_else(denied)
    }
    fn ensure_route_capacity(&mut self,pool:&Pool)->anyhow::Result<()> {
        if self.reads.capacity()==MAX_RULES&&self.writes.capacity()==MAX_RULES{return Ok(())}
        // Server-only requests need one slot, not sixty-four. When an actual
        // route installs a clause, prepay both new buffers before allocating.
        // The old lease remains live through the real old buffer destruction.
        let credit=pool.reserve(Self::allocation_bound(MAX_RULES)?)?;
        let(mut reads,mut writes)=(Vec::new(),Vec::new());
        reads.try_reserve_exact(MAX_RULES)?;writes.try_reserve_exact(MAX_RULES)?;
        anyhow::ensure!(reads.capacity()==MAX_RULES&&writes.capacity()==MAX_RULES,"unexpected timeout clause allocation capacity");
        reads.append(&mut self.reads);writes.append(&mut self.writes);
        let old_reads=std::mem::replace(&mut self.reads,reads);
        let old_writes=std::mem::replace(&mut self.writes,writes);
        let old_credit=std::mem::replace(&mut self._credit,credit);
        drop(old_reads);drop(old_writes);drop(old_credit);
        Ok(())
    }
    pub(super) fn read_expired(&self)->bool {self.reads.iter().any(SharedRead::deadline_expired)}
    pub(super) fn unread(&self)->bool {self.reads.iter().any(|state|!state.finished())}
    pub(super) fn close_unread_h1(&self)->bool{matches!(self.version,Version::HTTP_10|Version::HTTP_11)&&(self.unread()||self.read_expired())}
    pub(super) fn control(&self)->Option<ResponseWriteControl>{self.write.clone()}
}
#[derive(Clone,Copy,Default)]
pub(super) struct Mark {reads:usize,writes:usize,chunk:Option<usize>}
pub(super) fn mark(state:Option<&RequestTimeouts>)->Mark{state.map_or(Mark::default(),|state|Mark{reads:state.reads.len(),writes:state.writes.len(),chunk:state.chunk})}
pub(super) fn unwind(ctx:&mut super::request::Context,mark:Mark)->anyhow::Result<()> {
    let Some(state)=ctx.timeouts.as_mut()else{return Ok(())};
    for read in &state.reads[mark.reads..]{read.disable()?;}
    state.writes.truncate(mark.writes);state.chunk=mark.chunk;
    if let Some(control)=&state.write {
        // The same producer has not emitted final payload. A physically
        // acknowledged interim keeps its owner, while popped route clauses
        // cease governing the enclosing error handler.
        let policies=PolicySet::compile(&ctx.resources.transfer_deadlines,&state.writes)?;
        control.replace_scoped_policies(policies)?;
    }
    Ok(())
}
pub(super) fn install(ctx:&mut super::request::Context,plan:&crate::http_config::route_timeouts::RouteTimeouts)->anyhow::Result<()> {
    if !plan.enabled(){return Ok(())}
    let pool=ctx.resources.transfer_deadlines.clone();
    if ctx.timeouts.is_none(){ctx.timeouts=Some(RequestTimeouts::new(&pool,ctx.req().version(),MAX_RULES)?);}
    let state=ctx.timeouts.as_mut().expect("initialized timeout state");
    if state.scopes>=MAX_RULES{return Err(denied())}
    state.ensure_route_capacity(&pool)?;
    state.scopes+=1;
    let now=Instant::now();
    if plan.read_timeout_ns>0 && ctx.request.as_ref().is_some_and(|request|!request.body().is_end_stream()) {
        let shared=SharedRead::with_budget(ReadPolicy{idle:Some(Duration::from_nanos(plan.read_timeout_ns as u64)),minimum_rate:plan.read_min_rate.max(0)as u64,installed:now,hard:None},&pool)?;
        let request=ctx.request.as_mut().ok_or_else(denied)?;
        let prior=std::mem::replace(request.body_mut(),super::full(Bytes::new()));
        let wrapped=ReadBody::with_budget(prior,shared.clone(),&pool)?;
        *request.body_mut()=wrapped.boxed_unsync();
        state.reads.push(shared);
    }
    if plan.write_timeout_ns>0 {
        let rule=Rule{installed:now,idle:Some(Duration::from_nanos(plan.write_timeout_ns as u64)),rate:NonZeroU64::new(plan.write_min_rate.max(0)as u64),hard:None};
        state.writes.push(rule);
        install_control(state,&pool,rule)?;
        let chunk=plan.write_chunk()?;
        state.chunk=Some(state.chunk.map_or(chunk,|old|old.min(chunk)));
    }
    if let Some(control)=state.control(){ctx.bind_timeout_control(control)?;}
    Ok(())
}
// A server clause is outside the route stack: error-route unwind cannot
// erase it. Header parsing and body reading share the original H1 epoch;
// multiplexed protocols supply an independent per-stream epoch.
pub(super) fn install_server(ctx:&mut super::request::Context,server:&crate::http_config::ServerConfig)->anyhow::Result<()> {
    let plan=&server.transfers;
    let read_idle=(!server.read_idle_timeout.is_zero()).then_some(server.read_idle_timeout);
    let read_enabled=(read_idle.is_some()||plan.read_hard.is_some())&&!ctx.req().body().is_end_stream();
    let write_enabled=plan.write_idle.is_some()||plan.write_hard.is_some();
    if !read_enabled && !write_enabled{return Ok(())}
    let now=ctx.request_started;
    let read_started=ctx.req().extensions().get::<hyper::ext::RequestReadStarted>().map_or(now,|at|at.0);
    let version=ctx.req().version();
    let pool=ctx.resources.transfer_deadlines.clone();
    let mut state=RequestTimeouts::new(&pool,version,1)?;
    state.scopes=1;
    if read_enabled {
        let hard=plan.read_hard.map(|limit|read_started.checked_add(limit).ok_or_else(denied)).transpose()?;
        let shared=SharedRead::with_budget(ReadPolicy{idle:read_idle,minimum_rate:plan.read_min_rate.max(0)as u64,installed:now,hard},&pool)?;
        let request=ctx.request.as_mut().ok_or_else(denied)?;
        let prior=std::mem::replace(request.body_mut(),super::full(Bytes::new()));
        let wrapped=ReadBody::with_budget(prior,shared.clone(),&pool)?;
        *request.body_mut()=wrapped.boxed_unsync();
        state.reads.push(shared);
    }
    if write_enabled {
        server_write(&mut state,&pool,server,now)?;
    }
    let control=state.control();
    ctx.timeouts=Some(state);
    if let Some(control)=control{ctx.bind_timeout_control(control)?;}
    Ok(())
}
fn server_write(state:&mut RequestTimeouts,pool:&Pool,server:&crate::http_config::ServerConfig,now:Instant)->anyhow::Result<()> {
    let plan=&server.transfers;
    let hard=plan.write_hard.map(|limit|now.checked_add(limit).ok_or_else(denied)).transpose()?;
    let rule=Rule{installed:now,idle:plan.write_idle,rate:NonZeroU64::new(plan.write_min_rate.max(0)as u64),hard};
    state.writes.push(rule);install_control(state,pool,rule)?;state.chunk=Some(plan.max_write_chunk);Ok(())
}
// A seed is protocol state only: failed promises do not create a business
// Context, access-log entry or metrics observation. Exactly one child takes it.
#[derive(Clone)]
pub(super) struct PushSeed {state:std::sync::Arc<std::sync::Mutex<Option<Box<RequestTimeouts>>>>,pub(super) started:Instant}
impl PushSeed {
    pub(super) fn new(pool:&Pool,server:&crate::http_config::ServerConfig)->anyhow::Result<(Self,ResponseWriteControl)>{
        let started=Instant::now();let mut state=RequestTimeouts::new(pool,Version::HTTP_2,1)?;
        if server.transfers.write_idle.is_some()||server.transfers.write_hard.is_some(){state.scopes=1;server_write(&mut state,pool,server,started)?;}
        else{install_control(&mut state,pool,Rule{installed:started,idle:None,rate:None,hard:None})?;}
        let control=state.control().ok_or_else(denied)?;
        Ok((Self{state:std::sync::Arc::new(std::sync::Mutex::new(Some(state))),started},control))
    }
    pub(super) fn take(&self)->Option<Box<RequestTimeouts>>{self.state.lock().unwrap_or_else(|e|e.into_inner()).take()}
}
fn install_control(state:&mut RequestTimeouts,pool:&Pool,rule:Rule)->anyhow::Result<()> {
    let policies=PolicySet::compile(pool,&state.writes)?;
    if let Some(control)=&state.write {control.replace_scoped_policies(policies)?;}
    else {
        let protocol=match state.version {
            Version::HTTP_2=>ResponseWriteControl::native_h2_protocol_allocation_upper_bytes::<Body>().ok_or_else(denied)?,
            Version::HTTP_3=>0,
            _=>ResponseWriteControl::native_h1_protocol_allocation_upper_bytes::<Body>().ok_or_else(denied)?,
        };
        let credit=pool.reserve(ResponseWriteControl::ALLOCATION_UPPER_BYTES.checked_add(protocol).ok_or_else(denied)?)?;
        state.write=Some(ResponseWriteControl::new_with_policies(WritePolicy{installed:rule.installed,idle:rule.idle,minimum_rate:rule.rate,hard:rule.hard},policies,Some(Bytes::from_owner(credit))));
    }
    Ok(())
}
pub(super) fn attach(state:Option<&RequestTimeouts>,response:&mut Response<Body>,pool:&Pool)->anyhow::Result<()> {
    let Some(state)=state else{return Ok(())};
    if let Some(control)=&state.write {response.extensions_mut().insert(control.clone());}
    if let Some(chunk)=state.chunk {
        // The source Bytes remains owned until all slices have been consumed;
        // this caps application chunks without copying or crediting progress.
        let credit=pool.reserve(std::mem::size_of::<ChunkBody>()+128)?;
        let body=std::mem::replace(response.body_mut(),super::full(Bytes::new()));
        *response.body_mut()=ChunkBody{body,pending:Bytes::new(),cap:chunk,_credit:credit}.boxed_unsync();
    }
    Ok(())
}
struct ChunkBody {body:Body,pending:Bytes,cap:usize,_credit:Lease}
impl hyper::body::Body for ChunkBody {
 type Data=Bytes;type Error=BoxError;
 fn poll_frame(self:Pin<&mut Self>,cx:&mut Context<'_>)->Poll<Option<Result<Frame<Bytes>,BoxError>>>{
    let this=self.get_mut();
    if !this.pending.is_empty(){let n=this.pending.len().min(this.cap);return Poll::Ready(Some(Ok(Frame::data(this.pending.split_to(n)))))}
    match Pin::new(&mut this.body).poll_frame(cx){
        Poll::Ready(Some(Ok(frame)))=>match frame.into_data(){
            Ok(mut data)=>{let n=data.len().min(this.cap);let output=data.split_to(n);this.pending=data;Poll::Ready(Some(Ok(Frame::data(output))))},
            Err(frame)=>Poll::Ready(Some(Ok(frame))),
        },
        other=>other,
    }
 }
 fn is_end_stream(&self)->bool{self.pending.is_empty()&&self.body.is_end_stream()}
 fn size_hint(&self)->SizeHint{let hint=self.body.size_hint();let mut result=SizeHint::new();result.set_lower(hint.lower().saturating_add(self.pending.len()as u64));if let Some(upper)=hint.upper().and_then(|n|n.checked_add(self.pending.len()as u64)){result.set_upper(upper);}result}
}
