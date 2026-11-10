//! Candidate-specific administration, prepared before root publication.
use super::{
    AdminError, AdminFinisher, AdminTransaction, Committed,
    controller::Inner,
    loader::{self, LoaderContext},
    policy::LocalPolicy,
    remote::RemoteAccess,
    server::{ModeChange, PermissionPublication, Prepared},
};
use std::sync::{Arc, Mutex};

#[derive(Default)]
pub(super) struct AdminStage {
    pub local: Option<Prepared>,
    pub remote: Option<Prepared>,
    pub access: Option<Arc<RemoteAccess>>,
    pub loaded: Option<loader::Loaded>,
    pub modes: Vec<ModeChange>,
}

/// Once Root publishes, an early return, panic or cancellation must stop the
/// rejected generation rather than leave the control plane reporting its predecessor.
pub(super) struct ActivationGuard {
    pub stage: AdminStage,
    checkpoint: Arc<Mutex<Checkpoint>>,
    inner: Arc<Inner>,
    armed: bool,
}
enum Checkpoint {
    Pending,
    Staged(Box<AdminStage>),
    Abandoned,
}
impl ActivationGuard {
    fn rejected(mut self, error: &AdminError) -> Result<(), AdminError> {
        if error.category == "backend_runtime_halted" {
            self.inner.halt();
        }
        let fence = self.inner.cancel.is_cancelled()
            || self.inner.check_readable().is_err()
            || matches!(
                error.category,
                "backend_commit_discarded" | "backend_stopping" | "admin_activation_cancelled"
            );
        let staged = std::mem::replace(
            &mut *self
                .checkpoint
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            Checkpoint::Abandoned,
        );
        if let Checkpoint::Staged(mut stage) = staged {
            if fence {
                for mode in &mut stage.modes {
                    mode.fence();
                }
            } else {
                // A normal backend Err explicitly guarantees that Root is P.
                // Default Drop never restores broad admission without this proof.
                for mode in &mut stage.modes {
                    mode.restore()
                        .map_err(|_| AdminError::new(503, "admin_listener_rollback_failed"))?;
                }
                for mode in &mut stage.modes {
                    mode.disarm(PermissionPublication::Predecessor);
                }
            }
        }
        self.armed = false;
        Ok(())
    }
    pub fn complete(mut self, publication: PermissionPublication) -> AdminStage {
        for mode in &mut self.stage.modes {
            mode.disarm(publication);
        }
        self.armed = false;
        std::mem::take(&mut self.stage)
    }
}
impl Drop for ActivationGuard {
    fn drop(&mut self) {
        if self.armed {
            // Permission restoration is explicit after a successful rollback.
            // A catastrophic failure must never widen a socket while halting.
            self.inner.halt();
            for mode in &mut self.stage.modes {
                mode.fence();
            }
            let mut checkpoint = self
                .checkpoint
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Checkpoint::Staged(stage) = &mut *checkpoint {
                for mode in &mut stage.modes {
                    mode.fence();
                }
            }
            *checkpoint = Checkpoint::Abandoned;
        }
    }
}

pub(super) async fn transact_admin(
    inner: &Arc<Inner>,
    transaction: AdminTransaction,
    policy: LocalPolicy,
    local: Option<Prepared>,
    remote_same: bool,
    mut modes: Vec<ModeChange>,
) -> Result<(Committed, ActivationGuard), AdminError> {
    let slot = Arc::new(Mutex::new(Checkpoint::Pending));
    let output = slot.clone();
    let options = inner.options.clone();
    let cancel = inner.cancel.child_token();
    let ctx = LoaderContext::new(inner, None);
    let finisher: AdminFinisher = Box::new(move |handle| {
        Box::pin(async move {
            let scope_cancel = handle.cancellation()?;
            let prepare = async {
                let resolver = if policy.identity.is_some() {
                    Some(handle.identity().await?)
                } else {
                    None
                };
                let access = if let Some(remote) = policy.remote.clone() {
                    let resolver = resolver
                        .ok_or_else(|| AdminError::new(400, "remote_admin_requires_identity"))?;
                    Some(
                        ctx.offload(move || RemoteAccess::new(&remote, resolver))
                            .await?,
                    )
                } else {
                    None
                };
                let remote = if !remote_same {
                    match (&policy.remote, &access) {
                        (Some(config), Some(access)) => {
                            Some(Prepared::prepare_remote(config, access.clone(), &options).await?)
                        }
                        _ => None,
                    }
                } else {
                    None
                };
                let loaded = if let Some(plan) = policy.loader.clone().filter(|p| p.delay.is_zero())
                {
                    let ctx = ctx.with_candidate(handle);
                    Some(loader::load(&ctx, plan, cancel.clone()).await?)
                } else {
                    None
                };
                let mut checkpoint = output
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if matches!(*checkpoint, Checkpoint::Abandoned) {
                    for mode in &mut modes {
                        mode.fence();
                    }
                    return Err(AdminError::new(503, "admin_activation_abandoned"));
                }
                *checkpoint = Checkpoint::Staged(Box::new(AdminStage {
                    local,
                    remote,
                    access,
                    loaded,
                    modes,
                }));
                if let Checkpoint::Staged(stage) = &mut *checkpoint {
                    for mode in &mut stage.modes {
                        mode.commit_restrictions()?;
                    }
                }
                Ok(())
            };
            tokio::select! {
                biased;
                _ = cancel.cancelled() => Err(AdminError::new(503, "admin_activation_cancelled")),
                _ = scope_cancel.cancelled() => Err(AdminError::new(503, "admin_activation_cancelled")),
                result = prepare => result,
            }
        })
    });
    // Never race this future against client/admin cancellation: the backend
    // owns the accepted transaction and may already have published its result.
    let mut guard = ActivationGuard {
        stage: AdminStage::default(),
        checkpoint: slot.clone(),
        inner: inner.clone(),
        armed: true,
    };
    let committed =
        match super::controller::transaction_scope(inner.backend.transact(transaction, finisher))
            .await
        {
            Ok(committed) => committed,
            Err(error) => {
                guard.rejected(&error)?;
                return Err(error);
            }
        };
    let staged = std::mem::replace(
        &mut *slot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
        Checkpoint::Abandoned,
    );
    guard.stage = match staged {
        Checkpoint::Staged(stage) => *stage,
        _ => return Err(AdminError::new(500, "admin_activation_finisher_not_run")),
    };
    Ok((committed, guard))
}
