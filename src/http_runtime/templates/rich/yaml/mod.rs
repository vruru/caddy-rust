//! Native first-document YAML front matter support.
mod libyaml;
mod reader;

mod resolve;
mod decode;
use super::allocation;
pub(super) fn front_matter(input:&[u8],maps:&gotmpl::MapContext,meter:std::sync::Arc<gotmpl::BudgetMeter>)->gotmpl::Result<gotmpl::Value>{
    let account=gotmpl::BudgetAccount::new(meter)?;
    let arena=reader::parse(input,&account)?;
    let value=if let Some(arena)=&arena{decode::convert(arena,maps,&account)?}else{account.reserve(128)?;maps.map(Default::default())?};
    value.measured_bytes(1<<20)?;
    drop(arena);
    // Returned Values use the same conservative retained policy as the
    // engine bridge. No parser or arena survives this handoff.
    account.transfer(account.reserved_bytes())?.commit_retained();
    Ok(value)
}
