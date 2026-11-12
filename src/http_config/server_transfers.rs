//! Typed server read/write limits for the native transport lifecycle.
use anyhow::{Result,ensure};
use serde_json::{Map,Value};
use std::time::Duration;
use crate::http_config::helpers::signed_duration;
#[derive(Clone,Debug,Eq,PartialEq)]
pub(crate) struct ServerTransfers {
 pub(crate) read_hard:Option<Duration>,
 pub(crate) write_hard:Option<Duration>,
 pub(crate) write_idle:Option<Duration>,
 pub(crate) read_min_rate:i64,
 pub(crate) write_min_rate:i64,
 pub(crate) max_write_chunk:usize,
}
impl Default for ServerTransfers {
 fn default()->Self{Self{read_hard:None,write_hard:None,write_idle:Some(Duration::from_secs(60)),read_min_rate:0,write_min_rate:0,max_write_chunk:64<<10}}
}
pub(crate) fn parse(m:&Map<String,Value>,path:&str)->Result<ServerTransfers>{
 let duration=|key:&str|->Result<i64>{m.get(key).filter(|v|!v.is_null()).map(|v|signed_duration(v,&format!("{path}/{key}"))).transpose().map(|v|v.unwrap_or(0))};
 let number=|key:&str|->Result<i64>{match m.get(key){None|Some(Value::Null)=>Ok(0),Some(Value::Number(n))=>n.as_go_i64().ok_or_else(||anyhow::anyhow!("integer required at {path}/{key}")),Some(_)=>anyhow::bail!("integer required at {path}/{key}")}};
 let hard=|ns:i64|if ns>0{Some(Duration::from_nanos(ns as u64))}else{None};
 let idle=duration("write_idle_timeout")?;
 let chunk=number("max_write_chunk")?;
 let max_write_chunk=if chunk<=0{64<<10}else{usize::try_from(chunk)?};
 ensure!(max_write_chunk>0,"invalid server write chunk");
 Ok(ServerTransfers{read_hard:hard(duration("read_timeout")?),write_hard:hard(duration("write_timeout")?),write_idle:if idle==0{Some(Duration::from_secs(60))}else{hard(idle)},read_min_rate:number("read_min_rate")?,write_min_rate:number("write_min_rate")?,max_write_chunk})
}
