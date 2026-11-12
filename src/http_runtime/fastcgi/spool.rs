//! Positional access to an anonymous request buffer. Credits live as long
//! as the actual open file, including an in-flight worker after cancellation.
use super::super::{
    Body, BoxError,
    request::{Context, budget_failure, failure, file_io_failure},
    resource_budget::{BlockingBudget, BudgetError},
};
use bytes::Bytes;
use http::StatusCode;
use http_body_util::{BodyExt, StreamBody};
use hyper::body::Frame;
use std::{
    fs::File,
    io,
    sync::{Arc, Mutex},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

const UNIT: usize = 64 * 1024;
pub(in crate::http_runtime) const MEMORY_PREFIX: usize = 128 * 1024;

struct Storage {
    file: File,
    _fd: OwnedSemaphorePermit,
    credits: Mutex<Vec<OwnedSemaphorePermit>>,
}

pub(in crate::http_runtime) struct Spool {
    storage: Arc<Storage>,
    io: BlockingBudget,
    credits: Arc<Semaphore>,
    size: u64,
    allocated: u64,
}

impl Spool {
    pub(in crate::http_runtime) async fn create(ctx: &mut Context) -> anyhow::Result<Self> {
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

    pub(in crate::http_runtime) async fn append(
        &mut self,
        ctx: &mut Context,
        bytes: Bytes,
    ) -> anyhow::Result<()> {
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

    pub(in crate::http_runtime) async fn read(
        &self,
        ctx: &mut Context,
        start: u64,
    ) -> anyhow::Result<Option<Bytes>> {
        self.reader()
            .read_at(start)
            .await
            .map_err(|error| error.to_failure(ctx))
    }

    pub(in crate::http_runtime) fn reader(&self) -> SpoolReader {
        SpoolReader {
            storage: self.storage.clone(),
            io: self.io.clone(),
            size: self.size,
        }
    }
}

#[derive(Debug)]
pub(in crate::http_runtime) enum SpoolReadError {
    Budget(BudgetError),
    Io(io::Error),
}
impl std::fmt::Display for SpoolReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Budget(_) => f.write_str("spool read admission unavailable"),
            Self::Io(error) => write!(f, "spool read failed: {error}"),
        }
    }
}
impl std::error::Error for SpoolReadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Budget(_) => None,
        }
    }
}
impl SpoolReadError {
    pub(in crate::http_runtime) fn to_failure(&self, ctx: &mut Context) -> anyhow::Error {
        match self {
            Self::Io(error) => file_io_failure(ctx, error),
            Self::Budget(BudgetError::Overloaded) => budget_failure(ctx, BudgetError::Overloaded),
            Self::Budget(BudgetError::WorkerFailed) => {
                budget_failure(ctx, BudgetError::WorkerFailed)
            }
        }
    }
}

#[derive(Clone)]
pub(in crate::http_runtime) struct SpoolReader {
    storage: Arc<Storage>,
    io: BlockingBudget,
    size: u64,
}
impl SpoolReader {
    pub(in crate::http_runtime) fn len(&self) -> u64 {
        self.size
    }

    pub(in crate::http_runtime) async fn read_at(
        &self,
        start: u64,
    ) -> Result<Option<Bytes>, SpoolReadError> {
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
            .map_err(SpoolReadError::Budget)?
            .map_err(SpoolReadError::Io)?;
        Ok(Some(bytes))
    }

    pub(in crate::http_runtime) fn into_body(self) -> Body {
        let stream =
            futures_util::stream::try_unfold((self, 0u64), |(reader, offset)| async move {
                match reader.read_at(offset).await? {
                    Some(bytes) => {
                        let next = offset + bytes.len() as u64;
                        Ok::<_, SpoolReadError>(Some((Frame::data(bytes), (reader, next))))
                    }
                    None => Ok(None),
                }
            });
        // This stream has an unknown hint. ReplayBuffer supplies its known
        // complete entity length independently when preparing the request.
        StreamBody::new(stream)
            .map_err(|error| -> BoxError { Box::new(error) })
            .boxed_unsync()
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
