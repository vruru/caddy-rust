// Copyright (c) 2025 Dean Ruina. MIT.
//! Independent retention/compression of already committed rolling log files.
use super::{
    rotation_fs::{Identity, Paths, attributes, warning},
    time_layout::Layout,
    types::Timestamp,
};
use flate2::{Compression, read::MultiGzDecoder, write::GzEncoder};
use rustix::fs::Dir;
use std::{
    fs::File,
    io::{self, BufReader, Read},
    sync::{Arc, Condvar, Mutex, OnceLock, mpsc},
    thread,
};

const MAX_DIRECTORY_ENTRIES: usize = 65_536;
const BUFSIZE: usize = 32 * 1024;

pub(super) struct MillPlan {
    pub paths: Arc<Paths>,
    pub layout: Arc<Layout>,
    pub local: bool,
    pub keep: i64,
    pub keep_days: i64,
    pub compression: Algorithm,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Algorithm {
    None,
    Gzip,
    Zstd,
}
impl Algorithm {
    pub(super) fn from_name(name: &str) -> io::Result<Self> {
        match name {
            "none" => Ok(Self::None),
            "gzip" => Ok(Self::Gzip),
            "zstd" => Ok(Self::Zstd),
            _ => Err(io::ErrorKind::InvalidInput.into()),
        }
    }
    fn suffix(self) -> &'static str {
        match self {
            Self::None => "",
            Self::Gzip => ".gz",
            Self::Zstd => ".zst",
        }
    }
}
pub(super) struct Mill {
    sender: Option<mpsc::SyncSender<()>>,
    thread: Option<thread::JoinHandle<()>>,
}
impl Mill {
    pub(super) fn start(plan: MillPlan, startup: Timestamp) -> io::Result<Self> {
        let (sender, receiver) = mpsc::sync_channel(1);
        let thread = thread::Builder::new()
            .name("caddy-log-retention".into())
            .spawn(move || {
                let mut first = true;
                while receiver.recv().is_ok() {
                    let _permit = MillPermit::acquire();
                    if plan.maintain(first.then_some(startup)).is_err() {
                        warning(b"timberjack: log backup maintenance did not complete\n");
                    }
                    first = false;
                }
            })?;
        Ok(Self {
            sender: Some(sender),
            thread: Some(thread),
        })
    }
    pub(super) fn request(&self) {
        if let Some(sender) = &self.sender {
            let _ = sender.try_send(());
        }
    }
}
impl Drop for Mill {
    fn drop(&mut self) {
        drop(self.sender.take());
        if let Some(worker) = self.thread.take()
            && worker.join().is_err()
        {
            warning(b"timberjack: log backup worker terminated unexpectedly\n");
        }
    }
}
// Separate from request, encoding and DNS pools. A bounded number of
// retention scans/codecs may use buffers/CPU regardless of writer count.
struct MillPermit;
fn mill_slots() -> &'static (Mutex<usize>, Condvar) {
    static SLOTS: OnceLock<(Mutex<usize>, Condvar)> = OnceLock::new();
    SLOTS.get_or_init(|| {
        (
            Mutex::new(
                thread::available_parallelism()
                    .map_or(1, |n| n.get())
                    .min(8),
            ),
            Condvar::new(),
        )
    })
}
impl MillPermit {
    fn acquire() -> Self {
        let (slots, wake) = mill_slots();
        let mut count = wake
            .wait_while(
                slots
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner),
                |count| *count == 0,
            )
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *count -= 1;
        Self
    }
}
impl Drop for MillPermit {
    fn drop(&mut self) {
        let (slots, wake) = mill_slots();
        *slots
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) += 1;
        wake.notify_one();
    }
}
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct BackupTime(i64, u32);
impl From<Timestamp> for BackupTime {
    fn from(value: Timestamp) -> Self {
        Self(value.seconds, value.nanosecond)
    }
}
impl BackupTime {
    fn nanos(self) -> i128 {
        i128::from(self.0) * 1_000_000_000 + i128::from(self.1)
    }
}
struct Backup {
    name: String,
    stamp: BackupTime,
    identity: Identity,
    compressed: bool,
}
impl MillPlan {
    fn maintain(&self, startup: Option<Timestamp>) -> io::Result<()> {
        let paths = &self.paths;
        let now: BackupTime = Timestamp::now().map_err(io::Error::other)?.into();
        let cutoff = self
            .keep_days
            .checked_mul(86_400)
            .filter(|&n| n > 0)
            .map(|days| now.nanos() - i128::from(days) * 1_000_000_000);
        let mut backups = Vec::new();
        let mut incomplete = false;
        for (index, entry) in Dir::read_from(&paths.directory)?.enumerate() {
            if index == MAX_DIRECTORY_ENTRIES {
                incomplete = true;
                warning(b"timberjack: backup scan limit reached; preserved backups with unverified ranking\n");
                break;
            }
            let entry = entry?;
            let Ok(name) = entry.file_name().to_str() else {
                continue;
            };
            if let Some(startup) = startup
                && paths.is_temp_name(name)
                && let Ok(identity) = paths.stat(name)
                && identity.modified < BackupTime::from(startup).nanos()
                && paths.archivable(name, identity)
            {
                if paths.remove_archive(name, identity).is_err() {
                    warning(b"timberjack: orphan backup temporary file was retained\n");
                }
                continue;
            }
            let Some((stamp, compressed)) = self.backup_name(name) else {
                continue;
            };
            let Ok(identity) = paths.stat(name) else {
                continue;
            };
            if !paths.archivable(name, identity) {
                continue;
            }
            backups.push(Backup {
                name: name.into(),
                stamp,
                identity,
                compressed,
            });
        }
        backups.sort_unstable_by(|a, b| b.stamp.cmp(&a.stamp).then_with(|| a.name.cmp(&b.name)));
        let mut stamp = None;
        let mut position = 0i64;
        let mut compress = Vec::new();
        let mut failed = incomplete;
        for backup in backups {
            if stamp != Some(backup.stamp) {
                position += 1;
                stamp = Some(backup.stamp);
            }
            if (!incomplete && self.keep > 0 && position > self.keep)
                || cutoff.is_some_and(|before| backup.stamp.nanos() < before)
            {
                if paths.remove_archive(&backup.name, backup.identity).is_err() {
                    failed = true;
                }
            } else if !incomplete && self.compression != Algorithm::None && !backup.compressed {
                compress.push(backup);
            }
        }
        // Always apply verified expiration before spending space on compression.
        for backup in compress {
            if self.compress(backup).is_err() {
                failed = true;
            }
        }
        if failed {
            Err(io::Error::other("log backup maintenance incomplete"))
        } else {
            Ok(())
        }
    }
    fn backup_name(&self, name: &str) -> Option<(BackupTime, bool)> {
        let tail = name.strip_prefix(&self.paths.prefix)?;
        let (core, compressed) = if let Some(tail) = tail
            .strip_suffix(".gz")
            .or_else(|| tail.strip_suffix(".zst"))
            && tail.ends_with(&self.paths.extension)
        {
            (tail, true)
        } else {
            (tail, false)
        };
        let tail = core.strip_suffix(&self.paths.extension)?;
        let (stamp, reason) = tail.rsplit_once('-')?;
        let (reason, sequence) = reason
            .split_once('_')
            .map_or((reason, None), |(reason, suffix)| (reason, Some(suffix)));
        if !matches!(reason, "size" | "time" | "initial")
            || sequence.is_some_and(|n| n.is_empty() || !n.bytes().all(|b| b.is_ascii_digit()))
        {
            return None;
        }
        self.layout
            .parse_timestamp(stamp, self.local)
            .map(|ts| (ts.into(), compressed))
    }
    fn compress(&self, backup: Backup) -> io::Result<()> {
        let paths = &self.paths;
        let (mut source, source_id) = paths.read(&backup.name)?;
        if source_id != backup.identity || !paths.archivable(&backup.name, source_id) {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let target = format!("{}{}", backup.name, self.compression.suffix());
        if paths.occupied(&target)? {
            let (compressed, compressed_id) = paths.read(&target)?;
            if !paths.archivable(&target, compressed_id)
                || !self.matches_archive(&mut source, source_id.size, &compressed)?
                || Identity::for_file(&compressed)? != compressed_id
                || paths.stat(&target)? != compressed_id
                || Identity::for_file(&source)? != source_id
            {
                return Err(io::ErrorKind::InvalidData.into());
            }
            // Resume a crash between publication and source removal. An
            // unrelated nonempty destination is never accepted as proof.
            compressed.sync_all()?;
            paths.directory.sync_all()?;
            paths.remove_archive(&backup.name, source_id)?;
            paths.directory.sync_all()?;
            return Ok(());
        }
        let (name, mut temporary, temp_id) = paths.temp()?;
        let result = (|| -> io::Result<()> {
            let copied = match self.compression {
                Algorithm::None => return Err(io::ErrorKind::InvalidInput.into()),
                Algorithm::Gzip => {
                    let mut encoder = GzEncoder::new(&mut temporary, Compression::default());
                    let copied = io::copy(
                        &mut (&mut source).take(source_id.size.saturating_add(1)),
                        &mut encoder,
                    )?;
                    encoder.finish()?;
                    copied
                }
                Algorithm::Zstd => {
                    let mut encoder = zstd::stream::write::Encoder::new(&mut temporary, 0)?;
                    let copied = io::copy(
                        &mut (&mut source).take(source_id.size.saturating_add(1)),
                        &mut encoder,
                    )?;
                    encoder.finish()?;
                    copied
                }
            };
            if copied != source_id.size
                || Identity::for_file(&source)? != source_id
                || paths.stat(&backup.name)? != source_id
                || !paths.archivable(&backup.name, source_id)
            {
                return Err(io::ErrorKind::InvalidData.into());
            }
            attributes(&temporary, Some(source_id), source_id.mode)?;
            temporary.sync_all()?;
            paths.move_exclusive(&name, &target)?;
            paths.directory.sync_all()?;
            paths.remove_archive(&backup.name, source_id)?;
            paths.directory.sync_all()?;
            Ok(())
        })();
        if result.is_err() && paths.occupied(&name).unwrap_or(false) {
            let _ = paths.remove_created(&name, temp_id);
        }
        result
    }
    fn matches_archive(
        &self,
        source: &mut File,
        length: u64,
        compressed: &File,
    ) -> io::Result<bool> {
        match self.compression {
            Algorithm::None => Ok(false),
            Algorithm::Gzip => compare(source, length, &mut MultiGzDecoder::new(compressed)),
            Algorithm::Zstd => {
                let mut decoder =
                    zstd::stream::read::Decoder::with_buffer(BufReader::new(compressed))?;
                decoder.window_log_max(24)?;
                compare(source, length, &mut decoder)
            }
        }
    }
}
fn compare(source: &mut File, mut length: u64, decoder: &mut dyn Read) -> io::Result<bool> {
    let mut a = [0; BUFSIZE];
    let mut b = [0; BUFSIZE];
    while length > 0 {
        let count = length.min(BUFSIZE as u64) as usize;
        source.read_exact(&mut a[..count])?;
        decoder.read_exact(&mut b[..count])?;
        if a[..count] != b[..count] {
            return Ok(false);
        }
        length -= count as u64;
    }
    Ok(source.read(&mut a[..1])? == 0 && decoder.read(&mut b[..1])? == 0)
}
