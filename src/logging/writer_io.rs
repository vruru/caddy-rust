//! Physical writer implementations. Each instance is owned by one I/O actor;
//! process stdout/stderr handles are borrowed standard handles, never raw Files.
use super::{
    file_open,
    net_writer::NetWriter,
    resolver_lane::Resolver,
    rotation_writer::RollingWriter,
    writer_pool::{Error, WriterIo, Written},
    writer_spec::WriterSpec,
};
use std::{
    fs::File,
    io::{self, Write},
    sync::Arc,
};
enum Output {
    Stdout,
    Stderr,
    Discard,
    File(File),
}
pub(super) fn open(
    spec: WriterSpec,
    resolver: Arc<Resolver>,
) -> std::result::Result<Box<dyn WriterIo>, Error> {
    let output = match spec {
        WriterSpec::Stdout => Output::Stdout,
        WriterSpec::Stderr => Output::Stderr,
        WriterSpec::Discard => Output::Discard,
        WriterSpec::File(spec) => {
            if spec.roll {
                return Ok(Box::new(
                    RollingWriter::open(spec).map_err(|_| Error::Open)?,
                ));
            }
            Output::File(file_open::prepare_plain(&spec).map_err(|_| Error::Open)?)
        }
        WriterSpec::Net(spec) => return Ok(Box::new(NetWriter::open(spec, resolver)?)),
    };
    Ok(Box::new(output))
}
impl WriterIo for Output {
    fn write(&mut self, bytes: &[u8]) -> std::result::Result<Written, Error> {
        match self {
            Self::Stdout => io::stdout().lock().write_all(bytes),
            Self::Stderr => io::stderr().lock().write_all(bytes),
            Self::Discard => Ok(()),
            Self::File(file) => file.write_all(bytes),
        }
        .map_err(|_| Error::Write)?;
        Ok(Written::Bytes(bytes.len()))
    }
    fn flush(&mut self) -> std::result::Result<(), Error> {
        match self {
            Self::Stdout => io::stdout().lock().flush(),
            Self::Stderr => io::stderr().lock().flush(),
            Self::Discard => Ok(()),
            Self::File(file) => file.sync_all(),
        }
        .map_err(|_| Error::Flush)
    }
}
