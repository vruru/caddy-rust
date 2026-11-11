// Copyright (c) 2025 Dean Ruina. MIT.
//! Rolling files keep the active file under a serial actor. Compression and
//! retention run on a separate bounded maintenance lane after commit.
use super::{
    rotation_fs::{Identity, MAX_NAME_ATTEMPTS, Paths, Transition, attributes, warning},
    rotation_mill::{Algorithm, Mill, MillPlan},
    rotation_schedule::{self, Due, Moment, RotationTime, Schedule},
    time_layout::Layout,
    types::Timestamp,
    writer_pool::{Error, WriterIo, Written},
    writer_spec::FileSpec,
};
use std::{
    fs::File,
    io::{self, Write},
    sync::Arc,
    time::{Duration, Instant},
};

const DEFAULT_LAYOUT: &str = "2006-01-02T15-04-05.000";
const FILE_STAMP_LIMIT: usize = 1024;
const IO_BACKOFF: Duration = Duration::from_secs(1);
pub(super) struct RollingWriter {
    paths: Arc<Paths>,
    spec: FileSpec,
    layout: Arc<Layout>,
    compression: Algorithm,
    schedule: Option<Schedule>,
    due: Option<Due>,
    last: Option<RotationTime>,
    file: Option<File>,
    size: u64,
    mill: Option<Mill>,
    backoff: Option<Instant>,
    durability_pending: bool,
    opened: Timestamp,
}
impl RollingWriter {
    pub(super) fn open(spec: FileSpec) -> io::Result<Self> {
        let paths = Paths::open(&spec)?;
        let compression = Algorithm::from_name(&spec.compression)?;
        let layout = Arc::new(backup_layout(&spec.backup_format)?);
        let opened = Timestamp::now().map_err(io::Error::other)?;
        Ok(Self {
            paths,
            spec,
            layout,
            compression,
            schedule: None,
            due: None,
            last: None,
            file: None,
            size: 0,
            mill: None,
            backoff: None,
            durability_pending: false,
            opened,
        })
    }
    fn maintenance(&mut self) {
        if self.mill.is_none() {
            let plan = MillPlan {
                paths: self.paths.clone(),
                layout: self.layout.clone(),
                local: self.spec.local,
                keep: self.spec.keep,
                keep_days: self.spec.keep_days,
                compression: self.compression,
            };
            match Mill::start(plan, self.opened) {
                Ok(mill) => self.mill = Some(mill),
                Err(_) => warning(b"timberjack: could not start log backup maintenance\n"),
            }
        }
        if let Some(mill) = &self.mill {
            mill.request();
        }
    }
    fn start_schedule(&mut self, now: Moment) {
        if self.schedule.is_none() {
            let schedule = Schedule::new(&self.spec.minutes, &self.spec.times, self.spec.local);
            self.due = schedule.next(now);
            self.schedule = Some(schedule);
        }
    }
    fn commit_directory(&mut self) -> io::Result<()> {
        if self.durability_pending {
            self.paths.directory.sync_all()?;
            self.paths.clear_transition();
            self.durability_pending = false;
            self.maintenance();
        }
        Ok(())
    }
    fn load(&mut self, write_len: u64, now: Moment) -> io::Result<()> {
        self.maintenance();
        match self.paths.append() {
            Ok((file, identity)) => {
                self.file = Some(file);
                self.size = identity.size;
                if i128::from(self.size) + i128::from(write_len)
                    >= i128::from(Paths::max_bytes(&self.spec))
                {
                    self.rotate("size", now)?;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                self.rotate("initial", now)?;
            }
            Err(error) => return Err(error),
        }
        if self.last.is_none() {
            self.last = Some(RotationTime::write(now));
        }
        Ok(())
    }
    fn rotate(&mut self, reason: &str, now: Moment) -> io::Result<()> {
        self.commit_directory()?;
        let paths = self.paths.clone();
        let old = self.file.as_ref().map(Identity::for_file).transpose()?;
        if let Some(old) = old {
            if !paths.matches_inode(&paths.active_name, old)? {
                return Err(io::ErrorKind::InvalidData.into());
            }
            self.file
                .as_ref()
                .ok_or(io::ErrorKind::NotFound)?
                .sync_data()?;
        }
        let archived = old
            .map(|old| self.archive(&paths, reason, now.wall, old))
            .transpose()?;
        let created = paths.create(&paths.active_name);
        let next = match created {
            Ok((file, identity)) => {
                let metadata_result = attributes(&file, old, Paths::mode_for(&self.spec, old))
                    .and_then(|()| file.sync_all());
                if let Err(error) = metadata_result {
                    let _ = paths.remove_created(&paths.active_name, identity);
                    self.restore(&paths, archived, old);
                    return Err(error);
                }
                (file, identity)
            }
            Err(error) => {
                self.restore(&paths, archived, old);
                return Err(error);
            }
        };
        paths.set_active(Some(next.1));
        self.file = Some(next.0);
        self.size = 0;
        if let Err(error) = paths.directory.sync_all() {
            self.durability_pending = true;
            if let Some((_, transition)) = archived {
                transition.defer();
            }
            return Err(error);
        }
        drop(archived);
        self.maintenance();
        Ok(())
    }
    fn restore(
        &mut self,
        paths: &Paths,
        archive: Option<(String, Transition<'_>)>,
        old: Option<Identity>,
    ) {
        let Some((name, _transition)) = archive else {
            return;
        };
        let restored = old.is_some_and(|old| paths.matches_inode(&name, old).unwrap_or(false))
            && paths.move_exclusive(&name, &paths.active_name).is_ok();
        if !restored {
            // The old data still has its backup name. Do not let a later
            // write append to a file that no longer occupies the active name.
            self.file.take();
            warning(b"timberjack: log rotation rollback did not restore the active pathname\n");
        } else if paths.directory.sync_all().is_err() {
            warning(b"timberjack: restored log pathname could not be synced\n");
        }
    }
    fn archive<'a>(
        &self,
        paths: &'a Paths,
        reason: &str,
        now: Timestamp,
        old: Identity,
    ) -> io::Result<(String, Transition<'a>)> {
        let components = rotation_schedule::components(now, self.spec.local)
            .ok_or(io::ErrorKind::InvalidData)?;
        let stamp = self
            .layout
            .format(&components, FILE_STAMP_LIMIT)
            .map_err(io::Error::other)?;
        for index in 0..=MAX_NAME_ATTEMPTS {
            let reason = if index == 0 {
                reason.into()
            } else {
                format!("{reason}_{index}")
            };
            let name = format!("{}{stamp}-{reason}{}", paths.prefix, paths.extension);
            if paths.occupied(&name)?
                || paths.occupied(&format!("{name}.gz"))?
                || paths.occupied(&format!("{name}.zst"))?
            {
                continue;
            }
            if !paths.matches_inode(&paths.active_name, old)? {
                return Err(io::ErrorKind::InvalidData.into());
            }
            let transition = paths.transition(name.clone());
            match paths.move_exclusive(&paths.active_name, &name) {
                Ok(()) => return Ok((name, transition)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
        Err(io::ErrorKind::AlreadyExists.into())
    }
    fn write_frame(&mut self, mut bytes: &[u8], now: Moment) -> io::Result<()> {
        self.start_schedule(now);
        let length = bytes.len() as u64;
        let max = i128::from(Paths::max_bytes(&self.spec));
        if i128::from(length) > max {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        self.commit_directory()?;
        if self.file.is_none() {
            self.load(length, now)?;
        }
        if self
            .last
            .is_some_and(|last| last.interval_due(now, self.spec.interval))
        {
            self.rotate("time", now)?;
            self.last = Some(RotationTime::write(now));
        }
        if let Some(mark) = self.last.and_then(|last| {
            self.schedule
                .as_ref()
                .and_then(|schedule| schedule.crossed(now, last))
        }) {
            self.rotate("time", now)?;
            self.last = Some(RotationTime::mark(mark));
        }
        if i128::from(self.size) + i128::from(length) > max {
            self.rotate("size", now)?;
        }
        let file = self.file.as_mut().ok_or(io::ErrorKind::NotFound)?;
        while !bytes.is_empty() {
            match file.write(bytes) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(count) => {
                    self.size = self.size.saturating_add(count as u64);
                    bytes = &bytes[count..];
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
}
impl WriterIo for RollingWriter {
    fn write(&mut self, bytes: &[u8]) -> Result<Written, Error> {
        let now = Moment::now().map_err(|_| Error::Write)?;
        if self.backoff.is_some_and(|end| now.monotonic < end) {
            return Err(Error::Write);
        }
        if let Err(error) = self.write_frame(bytes, now) {
            if error.kind() != io::ErrorKind::InvalidInput {
                self.backoff = now.monotonic.checked_add(IO_BACKOFF);
            }
            return Err(Error::Write);
        }
        self.backoff = None;
        Ok(Written::Bytes(bytes.len()))
    }
    fn flush(&mut self) -> Result<(), Error> {
        self.commit_directory().map_err(|_| Error::Flush)?;
        if let Some(file) = &self.file {
            file.sync_all().map_err(|_| Error::Flush)?;
        }
        Ok(())
    }
    fn idle_deadline(&self) -> Option<Instant> {
        self.due.map(|due| due.deadline)
    }
    fn idle(&mut self) {
        let Ok(now) = Moment::now() else {
            self.due = None;
            return;
        };
        let mark = self.due.take().and_then(|due| due.mark);
        if let Some(mark) = mark
            && self.last.is_none_or(|last| last.before(mark))
        {
            // A write larger than MaxSize can still start the original
            // scheduled loop before opening a handle for the first time.
            if self.file.is_none() {
                self.file = self.paths.append().ok().map(|(file, identity)| {
                    self.size = identity.size;
                    file
                });
            }
            if self.rotate("time", now).is_ok() {
                self.last = Some(RotationTime::mark(mark));
            } else {
                warning(b"timberjack: scheduled log rotation did not complete\n");
            }
        }
        self.due = Moment::now().ok().and_then(|fresh| {
            self.schedule
                .as_ref()
                .and_then(|schedule| schedule.next(fresh))
        });
    }
}
impl Drop for RollingWriter {
    fn drop(&mut self) {
        // The actor is not reported quiesced until the actual FD and maintenance
        // thread have both retired. The shared gate remains held during join.
        self.file.take();
        self.mill.take();
    }
}
fn backup_layout(format: &str) -> io::Result<Layout> {
    if !format.is_empty() {
        let layout = Layout::compile(format).map_err(io::Error::other)?;
        let sample = chrono::NaiveDate::from_ymd_opt(2025, 5, 22)
            .and_then(|date| date.and_hms_opt(23, 41, 59))
            .ok_or(io::ErrorKind::InvalidInput)?;
        let precision = fraction_precision(format);
        if precision <= 9 {
            let divisor = 10u32.pow((9 - precision) as u32);
            let input = Timestamp {
                seconds: sample.and_utc().timestamp(),
                nanosecond: 987_654_321 / divisor * divisor,
            };
            if let Some(parts) = rotation_schedule::components(input, false)
                && let Ok(stamp) = layout.format(&parts, FILE_STAMP_LIMIT)
                && !stamp.contains(['/', '\0'])
                && let Some(parsed) = layout.parse_timestamp(&stamp, false)
                && parsed.seconds == input.seconds
                && parsed.nanosecond == input.nanosecond
            {
                return Ok(layout);
            }
        }
        warning(b"timberjack: invalid backup time format; using the default\n");
    }
    Layout::compile(DEFAULT_LAYOUT).map_err(io::Error::other)
}
fn fraction_precision(layout: &str) -> usize {
    let bytes = layout.as_bytes();
    for (index, &character) in bytes.iter().enumerate() {
        if !matches!(character, b'.' | b',') {
            continue;
        }
        let rest = &bytes[index + 1..];
        let Some(&digit @ (b'0' | b'9')) = rest.first() else {
            continue;
        };
        let count = rest.iter().take_while(|&&b| b == digit).count();
        if !rest.get(count).is_some_and(u8::is_ascii_digit) {
            return count;
        }
    }
    0
}
