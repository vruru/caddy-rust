//! Startup-only password utility. Secret input is never included in errors.
use super::{
    Result,
    args::{self, Flag, Kind},
    ensure,
};
use caddy_compat_native::password::{Algorithm, HashOptions};
use std::{
    io::{IsTerminal, Write},
    os::unix::ffi::OsStrExt,
    sync::atomic::{AtomicPtr, Ordering},
};
use zeroize::Zeroizing;
const LIMIT: usize = 1 << 20;
static TERMINAL: AtomicPtr<libc::termios> = AtomicPtr::new(std::ptr::null_mut());
extern "C" fn interrupt(_: libc::c_int) {
    let state = TERMINAL.load(Ordering::Acquire);
    // Only async-signal-safe POSIX calls are made here. The startup guard keeps
    // this pinned state alive until the previous signal disposition is restored.
    unsafe {
        if !state.is_null() {
            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, state);
        }
        libc::_exit(1);
    }
}
struct Terminal {
    state: Box<libc::termios>,
    previous: libc::sighandler_t,
}
impl Terminal {
    /// The CLI entry guarantees no concurrent terminal/password invocation.
    unsafe fn open() -> Result<Self> {
        let mut state = std::mem::MaybeUninit::uninit();
        ensure!(
            unsafe { libc::tcgetattr(libc::STDIN_FILENO, state.as_mut_ptr()) } == 0,
            "cannot read terminal state"
        );
        let state = Box::new(unsafe { state.assume_init() });
        TERMINAL.store(
            (&*state as *const libc::termios).cast_mut(),
            Ordering::Release,
        );
        let previous =
            unsafe { libc::signal(libc::SIGINT, interrupt as *const () as libc::sighandler_t) };
        if previous == libc::SIG_ERR {
            TERMINAL.store(std::ptr::null_mut(), Ordering::Release);
            return Err(anyhow::anyhow!("cannot guard terminal interruption"));
        }
        let guard = Self { state, previous };
        let mut mode = *guard.state;
        mode.c_lflag &= !libc::ECHO;
        mode.c_lflag |= libc::ICANON | libc::ISIG;
        mode.c_iflag |= libc::ICRNL;
        ensure!(
            unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &mode) } == 0,
            "cannot protect terminal input"
        );
        Ok(guard)
    }
}
impl Drop for Terminal {
    fn drop(&mut self) {
        // Restore the terminal before removing the SIGINT restoration handler.
        unsafe {
            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &*self.state);
            libc::signal(libc::SIGINT, self.previous);
        }
        TERMINAL.store(std::ptr::null_mut(), Ordering::Release);
    }
}
fn input_line() -> Result<Zeroizing<Vec<u8>>> {
    let mut result = Zeroizing::new(Vec::new());
    let mut buffer = Zeroizing::new([0u8; 512]);
    loop {
        let count =
            unsafe { libc::read(libc::STDIN_FILENO, buffer.as_mut_ptr().cast(), buffer.len()) };
        if count < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(anyhow::anyhow!("cannot read password input"));
        }
        if count == 0 {
            return Ok(result);
        }
        let read = &buffer[..count as usize];
        let end = read.iter().position(|b| *b == b'\n').unwrap_or(read.len());
        ensure!(
            result.len() + end <= LIMIT,
            "password input exceeds byte limit"
        );
        result.extend_from_slice(&read[..end]);
        if end < read.len() {
            return Ok(result);
        }
    }
}
fn number<T: std::str::FromStr>(flags: &args::Flags, name: &str, default: T) -> Result<T> {
    match flags.text(name) {
        Some(v) => v
            .to_str()
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| anyhow::anyhow!("invalid numeric password-hash option")),
        None => Ok(default),
    }
}
/// # Safety
/// Called only by the single-threaded CLI startup dispatcher, before serving.
pub(super) unsafe fn command(input: &[std::ffi::OsString]) -> Result<i32> {
    let specs = [
        Flag {
            name: "plaintext",
            short: Some(b'p'),
            kind: Kind::Text,
        },
        Flag {
            name: "algorithm",
            short: Some(b'a'),
            kind: Kind::Text,
        },
        Flag {
            name: "bcrypt-cost",
            short: None,
            kind: Kind::Text,
        },
        Flag {
            name: "argon2id-time",
            short: None,
            kind: Kind::Text,
        },
        Flag {
            name: "argon2id-memory",
            short: None,
            kind: Kind::Text,
        },
        Flag {
            name: "argon2id-threads",
            short: None,
            kind: Kind::Text,
        },
        Flag {
            name: "argon2id-keylen",
            short: None,
            kind: Kind::Text,
        },
        Flag {
            name: "help",
            short: Some(b'h'),
            kind: Kind::Bool,
        },
    ];
    let flags = args::parse(input, &specs)?;
    if flags.boolean("help") {
        println!(
            "Usage: caddy-compat-native hash-password [--plaintext PASSWORD] [--algorithm bcrypt|argon2id] [--bcrypt-cost N] [--argon2id-time N] [--argon2id-memory KiB] [--argon2id-threads N] [--argon2id-keylen N]\nOmitting plaintext reads stdin; a terminal hides and confirms input."
        );
        return Ok(0);
    }
    ensure!(
        flags.positional.is_empty(),
        "hash-password takes no positional arguments"
    );
    let mut options = HashOptions::default();
    options.algorithm = match flags
        .text("algorithm")
        .map(std::ffi::OsStr::as_bytes)
        .unwrap_or(b"bcrypt")
    {
        b"bcrypt" => Algorithm::Bcrypt,
        b"argon2id" => Algorithm::Argon2id,
        _ => return Err(anyhow::anyhow!("unrecognized password hash algorithm")),
    };
    options.bcrypt_cost = number(&flags, "bcrypt-cost", options.bcrypt_cost)?;
    options.argon2id_time = number(&flags, "argon2id-time", options.argon2id_time)?;
    options.argon2id_memory = number(&flags, "argon2id-memory", options.argon2id_memory)?;
    options.argon2id_threads = number(&flags, "argon2id-threads", options.argon2id_threads)?;
    options.argon2id_keylen = number(&flags, "argon2id-keylen", options.argon2id_keylen)?;
    let mut plaintext = Zeroizing::new(
        flags
            .text("plaintext")
            .map_or(&[][..], std::ffi::OsStr::as_bytes)
            .to_vec(),
    );
    ensure!(
        plaintext.len() <= LIMIT,
        "password input exceeds byte limit"
    );
    if plaintext.is_empty() {
        if std::io::stdin().is_terminal() {
            let terminal = unsafe { Terminal::open()? };
            let mut stderr = std::io::stderr().lock();
            stderr.write_all(b"Enter password: ")?;
            stderr.flush()?;
            plaintext = input_line()?;
            stderr.write_all(b"\nConfirm password: ")?;
            stderr.flush()?;
            let confirmation = input_line()?;
            stderr.write_all(b"\n")?;
            ensure!(
                plaintext.len() == confirmation.len()
                    && openssl::memcmp::eq(&plaintext, &confirmation),
                "password does not match"
            );
            drop(terminal);
        } else {
            plaintext = input_line()?;
        }
        ensure!(!plaintext.is_empty(), "plaintext is required");
    }
    let hash = caddy_compat_native::password::hash(&options, &plaintext)?;
    let mut output = std::io::stdout().lock();
    output.write_all(hash.as_bytes())?;
    output.write_all(b"\n")?;
    output.flush()?;
    Ok(0)
}
