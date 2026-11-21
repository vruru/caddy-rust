use std::sync::{Arc, Once};
use std::time::Duration;
use tokio::time::MissedTickBehavior;
use tokio_util::{sync::CancellationToken, task::TaskTracker};

use super::super::h3::{CONNECTION_RECEIVE_WINDOW, CONNECTION_SEND_WINDOW};
use super::{descriptor_limit, file_body_limit, file_capacity, file_streams::Admission};

pub(super) fn quic_limit(cpu: usize, memory: Option<usize>) -> usize {
    // Leave half of the sampled headroom to TCP, the file pool and other app
    // work. Budget for both QUIC flow-control windows and connection overhead.
    let connection_bytes =
        CONNECTION_RECEIVE_WINDOW as usize + CONNECTION_SEND_WINDOW as usize + (1 << 20);
    memory.map_or_else(
        || cpu.saturating_mul(8).max(32),
        |bytes| (bytes / 2 / connection_bytes).max(1),
    )
}

pub(super) struct Refresh {
    started: Once,
    stop: CancellationToken,
    tasks: TaskTracker,
}

impl Refresh {
    pub(super) fn new() -> Self {
        Self {
            started: Once::new(),
            stop: CancellationToken::new(),
            tasks: TaskTracker::new(),
        }
    }

    pub(super) fn start(&self, file: Option<Arc<Admission>>, quic: Arc<Admission>) {
        self.started.call_once(|| {
            if self.stop.is_cancelled() {
                return;
            }
            let stop = self.stop.clone();
            let cpu = std::thread::available_parallelism().map_or(1, |n| n.get());
            self.tasks.spawn(async move {
                let mut ticks = tokio::time::interval(Duration::from_secs(1));
                ticks.set_missed_tick_behavior(MissedTickBehavior::Skip);
                loop {
                    tokio::select! {
                        biased;
                        _ = stop.cancelled() => break,
                        _ = ticks.tick() => {}
                    }
                    let Ok((soft, memory)) = tokio::task::spawn_blocking(|| {
                        (descriptor_limit(), file_capacity::memory_headroom())
                    })
                    .await
                    else {
                        continue;
                    };
                    if let Some(file) = &file {
                        file.update(file_body_limit(cpu, soft, memory), memory.is_some(), true);
                    }
                    quic.update(quic_limit(cpu, memory), memory.is_some(), false);
                }
            });
        });
    }

    pub(super) fn close(&self) {
        self.stop.cancel();
        self.tasks.close();
    }

    pub(super) async fn wait(&self) {
        self.tasks.wait().await;
    }
}

impl Drop for Refresh {
    fn drop(&mut self) {
        self.close();
    }
}
