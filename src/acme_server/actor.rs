//! One accepted transaction at a time per Bolt descriptor. Queue/CPU/data owners
//! survive a caller dropping its receiver. The actor owns no strong sender.
use super::{
    resources::{Leased, Meter, Resources, Scope},
    store::Database,
};
use anyhow::{Result, anyhow};
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

pub(super) struct DatabaseOwner {
    sender: mpsc::Sender<Box<dyn Command>>,
}
struct State {
    database: Database,
    metadata: Arc<Scope>,
}
trait Command: Send {
    fn run(self: Box<Self>, db: &mut Database);
}
struct Job<F, R> {
    operation: F,
    reply: oneshot::Sender<Result<Leased<R>>>,
    scope: Arc<Scope>,
}
impl<F, R> Command for Job<F, R>
where
    R: Send + 'static,
    F: FnOnce(&mut Database, &mut Meter) -> Result<R> + Send + 'static,
{
    fn run(self: Box<Self>, db: &mut Database) {
        let Self {
            operation,
            reply,
            scope,
        } = *self;
        let mut meter = Meter(scope.clone());
        let result = operation(db, &mut meter)
            .map(|value| Leased {
                value,
                scope: scope.clone(),
            })
            .map_err(|e| {
                if matches!(
                    e.downcast_ref::<super::store::Error>(),
                    Some(super::store::Error::Storage(super::bolt::Error::Limit))
                ) {
                    scope.reject_capacity();
                }
                crate::cert_cpu::retained_error(e, scope)
            });
        // A lost receiver drops the value before its credit, not the reverse.
        let _ = reply.send(result);
    }
}
impl State {
    fn execute(mut self, command: Box<dyn Command>) -> Result<Self> {
        command.run(&mut self.database);
        Ok(self)
    }
}
impl DatabaseOwner {
    pub async fn open(
        path: PathBuf,
        resources: Arc<Resources>,
        cancel: CancellationToken,
    ) -> Result<Arc<Self>> {
        let metadata = resources.scope(cancel.clone(), true)?;
        let keeper = metadata.clone();
        let mut meter = Meter(metadata);
        let slots = resources.cpu.clone();
        let state = resources
            .owned(async move {
                crate::cert_cpu::run(slots, cancel.clone(), move || {
                    let database = Database::open(
                        &path,
                        64 * 1024 * 1024,
                        4 * 1024 * 1024,
                        Duration::from_secs(1),
                        &mut meter,
                    )?;
                    // Constructor temporaries retired before this persistent owner shrinks.
                    keeper.retain(database.retained_bytes())?;
                    Ok(State {
                        database,
                        metadata: keeper,
                    })
                })
                .await
            })?
            .await
            .map_err(|_| anyhow!("ACME preparation worker failed"))??;
        let (sender, mut receiver) = mpsc::channel::<Box<dyn Command>>(8);
        let owner = Arc::new(Self { sender });
        let cpu = resources.cpu.clone();
        let stop = resources.cancel.clone();
        resources.owned(async move {
            let mut state=state;
            loop {
                let command=tokio::select! {biased;_ = stop.cancelled()=>break,command=receiver.recv()=>match command {Some(c)=>c,None=>break}};
                match crate::cert_cpu::run_committed(cpu.clone(),stop.clone(),move||state.execute(command)).await {
                    Ok(returned)=>state=returned,
                    Err(_)=>break,
                }
            }
        })?;
        Ok(owner)
    }
    pub async fn call<R, F>(&self, scope: Arc<Scope>, operation: F) -> Result<Leased<R>>
    where
        R: Send + 'static,
        F: FnOnce(&mut Database, &mut Meter) -> Result<R> + Send + 'static,
    {
        scope.check()?;
        scope.reserve(std::mem::size_of::<Job<F, R>>() + 256)?;
        let (reply, wait) = oneshot::channel();
        self.sender
            .try_send(Box::new(Job {
                operation,
                reply,
                scope: scope.clone(),
            }))
            .map_err(|_| anyhow!(scope.reject_capacity()))?;
        // Dropping this wait cannot remove an accepted command or its credit.
        wait.await
            .map_err(|_| anyhow!("ACME transaction worker unavailable"))?
    }
}
