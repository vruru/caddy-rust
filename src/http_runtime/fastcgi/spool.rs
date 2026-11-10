//! Positional access to an anonymous request buffer. Credits live as long
//! as the actual open file, including an in-flight worker after cancellation.
use super::super::{
    request::{Context, budget_failure, failure, file_io_failure},
    resource_budget::BlockingBudget,
};
use bytes::Bytes;
use http::StatusCode;
use std::{
    fs::File,
    io,
    sync::{Arc, Mutex},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

const UNIT: usize = 64 * 1024;
pub(super) const MEMORY_PREFIX: usize = 128 * 1024;

struct Storage {
    file: File,
    _fd: OwnedSemaphorePermit,
    credits: Mutex<Vec<OwnedSemaphorePermit>>,
}

pub(super) struct Spool {
    storage: Arc<Storage>,
    io: BlockingBudget,
    credits: Arc<Semaphore>,
    size: u64,
    allocated: u64,
}

impl Spool {
    pub(super) async fn create(ctx: &mut Context) -> anyhow::Result<Self> {
        let io = ctx.resources.fastcgi_spool_io.clone();
        let budget = ctx.resources.fastcgi_spool_fds.clone();
        let fd = budget
            .acquire()
            .await
            .map_err(|error| budget_failure(ctx, error))?;
        let (file, fd) = io
            .run(move || tempfile::tempfile().map(|file| (file, fd)))
            .await
            .map_err(|error| budget_failure(ctx, error))?
            .map_err(|error| file_io_failure(ctx, &error))?;
        Ok(Self {
            storage: Arc::new(Storage {
                file,
                _fd: fd,
                credits: Mutex::new(Vec::new()),
            }),
            io,
            credits: ctx.resources.fastcgi_spool_bytes.clone(),
            size: 0,
            allocated: 0,
        })
    }

    pub(super) async fn append(&mut self, ctx: &mut Context, bytes: Bytes) -> anyhow::Result<()> {
        let size = self
            .size
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| failure(StatusCode::PAYLOAD_TOO_LARGE))?;
        let units = size.div_ceil(UNIT as u64);
        if units > self.allocated {
            let increase = u32::try_from(units - self.allocated)
                .map_err(|_| failure(StatusCode::PAYLOAD_TOO_LARGE))?;
            // Never wait while holding a partial reservation; other uploads
            // must be able to finish and return their buffers.
            let credit = self
                .credits
                .clone()
                .try_acquire_many_owned(increase)
                .map_err(|_| failure(StatusCode::PAYLOAD_TOO_LARGE))?;
            self.storage
                .credits
                .lock()
                .expect("spool credit mutex not poisoned")
                .push(credit);
            self.allocated = units;
        }
        let data = self.storage.clone();
        let start = self.size;
        self.io
            .run(move || write_at(&data.file, &bytes, start))
            .await
            .map_err(|error| budget_failure(ctx, error))?
            .map_err(|error| file_io_failure(ctx, &error))?;
        self.size = size;
        Ok(())
    }

    pub(super) async fn read(
        &self,
        ctx: &mut Context,
        start: u64,
    ) -> anyhow::Result<Option<Bytes>> {
        let Some(remaining @ 1..) = self.size.checked_sub(start) else {
            return Ok(None);
        };
        let data = self.storage.clone();
        let count = remaining.min(UNIT as u64) as usize;
        let bytes = self
            .io
            .run(move || {
                let mut bytes = vec![0; count];
                read_at(&data.file, &mut bytes, start)?;
                Ok::<_, io::Error>(Bytes::from(bytes))
            })
            .await
            .map_err(|error| budget_failure(ctx, error))?
            .map_err(|error| file_io_failure(ctx, &error))?;
        Ok(Some(bytes))
    }
}

#[cfg(unix)]
fn write_at(file: &File, bytes: &[u8], start: u64) -> io::Result<()> {
    use std::os::unix::fs::FileExt;
    file.write_all_at(bytes, start)
}
#[cfg(unix)]
fn read_at(file: &File, bytes: &mut [u8], start: u64) -> io::Result<()> {
    use std::os::unix::fs::FileExt;
    file.read_exact_at(bytes, start)
}
#[cfg(not(unix))]
fn write_at(_file: &File, _bytes: &[u8], _start: u64) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "FastCGI buffer storage",
    ))
}
#[cfg(not(unix))]
fn read_at(_file: &File, _bytes: &mut [u8], _start: u64) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "FastCGI buffer storage",
    ))
}
