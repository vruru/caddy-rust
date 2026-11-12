//! Strict route deadline configuration; JSON durations use integer nanoseconds.
use anyhow::{Result,ensure};
use serde_json::Value;
#[derive(Clone,Copy,Debug,Default,Eq,PartialEq)]
pub(crate) struct RouteTimeouts {
    pub read_timeout_ns:i64,pub read_min_rate:i64,
    pub write_timeout_ns:i64,pub write_min_rate:i64,pub max_write_chunk:i64,
}
impl RouteTimeouts {
    pub(crate) fn enabled(self)->bool {self.read_timeout_ns>0||self.write_timeout_ns>0}
    pub(crate) fn write_chunk(self)->Result<usize> {
        if self.max_write_chunk<=0 {return Ok(64<<10);}
        usize::try_from(self.max_write_chunk).map_err(|_|anyhow::anyhow!("timeout chunk exceeds platform range"))
    }
}
pub(crate) fn parse(value:&Value,path:&str)->Result<RouteTimeouts> {
    let m=value.as_object().ok_or_else(||anyhow::anyhow!("timeout object required at {path}"))?;
    ensure!(m.get("handler").and_then(Value::as_str)==Some("timeouts"),"invalid timeout handler at {path}");
    ensure!(m.keys().all(|key|matches!(key.as_str(),"handler"|"@id"|"read_timeout"|"read_min_rate"|"write_timeout"|"write_min_rate"|"max_write_chunk")),"unknown timeout field at {path}");
    let number=|key|match m.get(key) {
        None|Some(Value::Null)=>Ok(0),
        // The existing Go DOM parser retains lexical integer -0 separately
        // from floating -0.0. Ordinary Number::as_i64 loses this distinction.
        Some(Value::Number(n))=>n.as_go_i64().ok_or_else(||anyhow::anyhow!("timeout integer required at {path}/{key}")),
        Some(_)=>Err(anyhow::anyhow!("timeout integer required at {path}/{key}")),
    };
    Ok(RouteTimeouts {read_timeout_ns:number("read_timeout")?,read_min_rate:number("read_min_rate")?,write_timeout_ns:number("write_timeout")?,write_min_rate:number("write_min_rate")?,max_write_chunk:number("max_write_chunk")?})
}
