//! Complete OpenSSL SSL processing with network I/O outside the CPU worker.
//!
//! This is a stepping interface, not a TLS record implementation. OpenSSL owns
//! record authentication, padding, transcript, handshake signatures and secrets.
use crate::{Guard, VerificationScope};
use openssl::ssl::{ErrorCode, Ssl, SslStream};
use std::{
    collections::VecDeque,
    io::{self, Read, Write},
    sync::Arc,
};
use zeroize::{Zeroize, Zeroizing};
#[path = "server_buffers.rs"]
mod buffers;
use buffers::Credit;
pub use buffers::{EncryptedInput, OwnedWrite, StepData};
const WINDOW: usize = 32 * 1024;
const CLEAR: usize = 16 * 1024;
const ENGINE_CREDIT: usize = 2 * WINDOW + 1024;
pub fn server_input_usage() -> (usize, usize) {
    Credit::input_usage()
}
pub fn server_buffer_usage() -> (usize, usize) {
    Credit::usage()
}
/// A final live certificate/status fence. Implementations must be bounded and
/// perform no I/O. The caller rechecks before publishing encrypted/plain bytes.
pub type Admission = Arc<dyn Fn() -> bool + Send + Sync>;
struct MemoryIo {
    input: VecDeque<u8>,
    output: Vec<u8>,
    admission: Admission,
    _credit: Arc<Credit>,
}
impl MemoryIo {
    fn new(admission: Admission, credit: Arc<Credit>) -> io::Result<Self> {
        let mut input = VecDeque::new();
        input.try_reserve_exact(WINDOW).map_err(io::Error::other)?;
        let mut output = Vec::new();
        output.try_reserve_exact(WINDOW).map_err(io::Error::other)?;
        Ok(Self {
            input,
            output,
            admission,
            _credit: credit,
        })
    }
    fn live(&self) -> io::Result<()> {
        if (self.admission)() {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "SSL certificate admission withdrawn",
            ))
        }
    }
}
impl Read for MemoryIo {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.live()?;
        if out.is_empty() {
            return Ok(0);
        }
        if self.input.is_empty() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let n = out.len().min(self.input.len());
        for byte in &mut out[..n] {
            *byte = self.input.pop_front().expect("bounded input length");
        }
        Ok(n)
    }
}
impl Write for MemoryIo {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.live()?;
        if data.is_empty() {
            return Ok(0);
        }
        let n = data.len().min(WINDOW - self.output.len());
        if n == 0 {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        self.output.extend_from_slice(&data[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.live()
    }
}
/// Exactly one CPU step owns this complete SSL object at a time. There is no
/// synchronous network object behind its BIO and no borrowed socket in a job.
pub struct ServerEngine {
    ssl: SslStream<MemoryIo>,
    admission: Admission,
    _credit: Arc<Credit>,
    output_credit: Option<Credit>,
    spare_credit: Option<Credit>,
    client: Option<Arc<Guard>>,
    pending_verification: bool,
}
pub enum Operation {
    Handshake,
    Read,
    Write(OwnedWrite),
    Shutdown,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Progress {
    Complete,
    Read,
    Write,
    Closed,
    Fatal,
}
pub(crate) struct ReturnedCredit(Credit);
pub(crate) fn retire(data: StepData) -> ReturnedCredit {
    ReturnedCredit(data.recycle())
}
pub struct Step {
    pub engine: ServerEngine,
    pub progress: Progress,
    pub transferred: usize,
    pub error: Option<io::Error>,
    pub data: StepData,
}

impl ServerEngine {
    /// SSL/context/credentials are prepared before calling this function. Their
    /// native ownership/accounting remains with the caller's credential scope.
    pub fn new(ssl: Ssl, admission: Admission) -> io::Result<Self> {
        let credit = Arc::new(Credit::reserve(ENGINE_CREDIT)?);
        let output_credit = Some(StepData::reserve_output()?);
        let spare_credit = Some(StepData::reserve_output()?);
        let io = MemoryIo::new(admission.clone(), credit.clone())?;
        Ok(Self {
            ssl: SslStream::new(ssl, io).map_err(io::Error::other)?,
            admission,
            _credit: credit,
            output_credit,
            spare_credit,
            client: None,
            pending_verification: false,
        })
    }
    /// Complete client SSL uses the same owned record engine and budgets.
    /// The public legacy client Stream interface remains unchanged.
    pub(crate) fn new_client(
        ssl: Ssl,
        guard: Arc<Guard>,
        admission: Admission,
    ) -> io::Result<Self> {
        let mut engine = Self::new(ssl, admission)?;
        engine.client = Some(guard);
        Ok(engine)
    }
    pub(crate) fn admission(&self) -> Admission {
        self.admission.clone()
    }
    pub fn can_recycle(&self) -> bool {
        self.output_credit.is_none() || self.spare_credit.is_none()
    }
    pub(crate) fn connection_credits(&self)->Option<Arc<crate::ConnectionCredits>> { self.client.as_ref().and_then(|g|g.connection_credits.clone()) }
    pub fn ssl(&self) -> &openssl::ssl::SslRef {
        self.ssl.ssl()
    }
    pub fn input_capacity(&self) -> usize {
        WINDOW - self.ssl.get_ref().input.len()
    }
    /// This consumes the engine, so cancellation cannot leave concurrent access to
    /// SSL. Started workers/abandoned outputs retain the actual engine and credit.
    pub async fn step(
        mut self,
        scope: Arc<VerificationScope>,
        op: Operation,
        input: EncryptedInput,
    ) -> io::Result<Step> {
        let credits=self.client.as_ref().and_then(|g|g.connection_credits.clone());
        if input.bytes().len() > WINDOW
            || matches!(&op,Operation::Write(p)if p.remaining().len()>CLEAR)
        {
            return Err(crate::connection_credits::retain_error(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SSL step input exceeds bounds",
            ),&credits));
        }
        if self.pending_verification {
            let guard = self
                .client
                .as_ref()
                .ok_or_else(|| io::Error::other("SSL retry verification without client owner"))?
                .clone();
            // The previous SSL step has already returned its CPU permit. This
            // verifier can acquire the same shared lane without recursive
            // permit ownership; raw evidence retains its actual owner.
            guard.verify_initial(&scope).await?;
            self.pending_verification = false;
        }
        let output = self
            .output_credit
            .take()
            .or_else(|| self.spare_credit.take())
            .map(Ok)
            .unwrap_or_else(StepData::reserve_output)
            .map_err(|e|crate::connection_credits::retain_error(e,&credits))?;
        let worker_credits=credits.clone();
        scope.run(move || {
            self.process(op,input,output).map(|mut step|{
                step.error=step.error.map(|e|crate::connection_credits::retain_error(e,&worker_credits));step
            }).map_err(|e|crate::connection_credits::retain_error(e,&worker_credits))
        }).await.map_err(|e|crate::connection_credits::retain_error(e,&credits))?
    }
    fn process(
        mut self,
        op: Operation,
        input: EncryptedInput,
        output_credit: Credit,
    ) -> io::Result<Step> {
        self.ssl.get_ref().live()?;
        if input.bytes().len() > self.input_capacity() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SSL encrypted input window full",
            ));
        }
        self.ssl
            .get_mut()
            .input
            .extend(input.bytes().iter().copied());
        drop(input);
        let mut plain = Zeroizing::new(Vec::new());
        let mut retry_write = None;
        let result = match op {
            Operation::Handshake => {
                if self.client.is_some() {
                    self.ssl.connect().map(|()| 0)
                } else {
                    self.ssl.accept().map(|()| 0)
                }
            }
            Operation::Read => {
                plain.try_reserve_exact(CLEAR).map_err(io::Error::other)?;
                plain.resize(CLEAR, 0);
                self.ssl.ssl_read(&mut plain)
            }
            Operation::Write(mut bytes) => {
                let result = self.ssl.ssl_write(bytes.remaining());
                match &result {
                    Ok(n) if *n < bytes.remaining().len() => {
                        bytes.advance(*n);
                        retry_write = Some(bytes);
                    }
                    Err(e)
                        if e.code() == ErrorCode::WANT_READ
                            || e.code() == ErrorCode::WANT_WRITE
                            || (self.client.is_some() && e.code().as_raw() == 12) =>
                    {
                        retry_write = Some(bytes)
                    }
                    _ => {}
                }
                result
            }
            Operation::Shutdown => self.ssl.shutdown().map(|_| 0),
        };
        // Recheck after all native crypto, before any produced data escapes this job.
        self.ssl.get_ref().live()?;
        let (progress, transferred, error) = match result {
            Ok(n) => (Progress::Complete, n, None),
            Err(e) if e.code() == ErrorCode::WANT_READ => (Progress::Read, 0, None),
            Err(e) if e.code() == ErrorCode::WANT_WRITE => (Progress::Write, 0, None),
            Err(e) if self.client.is_some() && e.code().as_raw() == 12 => {
                self.pending_verification = true;
                // No wire progress is required; the next owned step first
                // completes the explicit public retry-verification boundary.
                (Progress::Write, 0, None)
            }
            Err(e) if e.code() == ErrorCode::ZERO_RETURN => (Progress::Closed, 0, None),
            Err(e) => (Progress::Fatal, 0, Some(io::Error::other(e))),
        };
        if !plain.is_empty() {
            if transferred == 0 {
                plain.as_mut_slice().zeroize();
            }
            plain.truncate(transferred)
        }
        let mut replacement = Vec::new();
        replacement
            .try_reserve_exact(WINDOW)
            .map_err(io::Error::other)?;
        let wire = std::mem::replace(&mut self.ssl.get_mut().output, replacement);
        Ok(Step {
            engine: self,
            progress,
            transferred,
            error,
            data: StepData::new(wire, plain, retry_write, output_credit),
        })
    }
    /// Consume all previous produced buffers before returning their reusable
    /// output credit. A caller retaining old outputs must independently admit
    /// another step; the correct network driver recycles after real consumption.
    pub(crate) fn restore(&mut self, credit: ReturnedCredit) -> io::Result<()> {
        self.restore_credit(credit.0)
    }
    fn restore_credit(&mut self, credit: Credit) -> io::Result<()> {
        if self.output_credit.is_none() {
            self.output_credit = Some(credit);
            Ok(())
        } else if self.spare_credit.is_none() {
            self.spare_credit = Some(credit);
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SSL output credits already available",
            ))
        }
    }
    pub fn recycle(&mut self, data: StepData) -> io::Result<()> {
        self.restore_credit(data.recycle())
    }
    /// The asynchronous network wrapper checks this again before every actual
    /// socket write and before exposing plaintext to its caller.
    pub fn admitted(&self) -> bool {
        (self.admission)()
    }
}
