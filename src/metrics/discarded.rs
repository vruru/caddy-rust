//! Finish observations only for producer-proven, prepared in-memory entities.
//! Unknown file/network bodies are cancelled by the intercept caller instead.
use super::observe::Scope;
use crate::http_runtime::Body;
use http_body_util::BodyExt;
use tokio_util::{sync::CancellationToken, task::TaskTracker};
/// Only actual bounded in-memory producers may install this marker. Neither a
/// Content-Length nor an exact size hint proves the absence of external reads.
#[derive(Clone, Copy)]
pub(crate) struct PreparedEntity;

pub(crate) fn observe<H: Send + 'static>(
    body: Body,
    mut scope: Scope,
    tasks: &TaskTracker,
    stop: CancellationToken,
    hold: H,
) {
    let Some(slot) = scope.admit_discard() else {
        scope.abandon();
        return;
    };
    tasks.spawn(async move{
        let _hold=hold;let _slot=slot;let mut original=body;
        let done=tokio::select!{biased;
            _=stop.cancelled()=>false,
            result=tokio::time::timeout(std::time::Duration::from_secs(10),async{
                while let Some(frame)=original.frame().await{if frame.is_err(){return false;}tokio::task::consume_budget().await;}true
            })=>result.unwrap_or(false),
        };
        if !done{scope.abandon();}
    });
}
