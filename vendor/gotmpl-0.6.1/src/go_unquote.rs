// Derived from Go 1.27.3 strconv.UnquoteChar (Go Authors, BSD-3-Clause; see LICENSE-GO).


use alloc::string::String;
use alloc::vec::Vec;

// ── helpers ──────────────────────────────────────────────────────────────

const BYTE_LIMIT: usize = 1_048_576; // 1 MiB

fn over_limit() -> String {
    String::from("quoted string exceeds byte limit")
}

fn bad_string() -> String {
    String::from("invalid Go quoted string")
}

#[inline]
fn hex_digit(b: u8) -> Option<u32> {
    match b {
        b'0'..=b'9' => Some((b - b'0') as u32),
        b'a'..=b'f' => Some((b - b'a') as u32 + 10),
        b'A'..=b'F' => Some((b - b'A') as u32 + 10),
        _ => core::option::Option::None,
    }
}

#[inline]
fn oct_digit(b: u8) -> Option<u32> {
    if b >= b'0' && b <= b'7' {
        Some((b - b'0') as u32)
    } else {
        core::option::Option::None
    }
}

#[inline]
fn is_valid_scalar(v: u32) -> bool {
    v <= 0x10FFFF && !(0xD800 <= v && v <= 0xDFFF)
}

fn emit_codepoint(out: &mut Vec<u8>, cp: u32) -> Result<(), String> {
    let len: usize = if cp < 0x80 {
        1
    } else if cp < 0x800 {
        2
    } else if cp < 0x10000 {
        3
    } else {
        4
    };
    check_capacity(out, len)?;
    if cp < 0x80 {
        out.push(cp as u8);
    } else if cp < 0x800 {
        out.push((0xC0 | (cp >> 6)) as u8);
        out.push((0x80 | (cp & 0x3F)) as u8);
    } else if cp < 0x10000 {
        out.push((0xE0 | (cp >> 12)) as u8);
        out.push((0x80 | ((cp >> 6) & 0x3F)) as u8);
        out.push((0x80 | (cp & 0x3F)) as u8);
    } else {
        out.push((0xF0 | (cp >> 18)) as u8);
        out.push((0x80 | ((cp >> 12) & 0x3F)) as u8);
        out.push((0x80 | ((cp >> 6) & 0x3F)) as u8);
        out.push((0x80 | (cp & 0x3F)) as u8);
    }
    Ok(())
}

fn emit_fffd(out: &mut Vec<u8>) -> Result<(), String> {
    check_capacity(out, 3)?;
    out.push(0xEF);
    out.push(0xBF);
    out.push(0xBD);
    Ok(())
}

fn check_capacity(out: &Vec<u8>, add: usize) -> Result<(), String> {
    match out.len().checked_add(add) {
        core::option::Option::Some(total) if total <= BYTE_LIMIT => Ok(()),
        _ => core::result::Result::Err(over_limit()),
    }
}

fn emit_byte(out: &mut Vec<u8>, b: u8) -> Result<(), String> {
    check_capacity(out, 1)?;
    out.push(b);
    Ok(())
}

// ── main entry ───────────────────────────────────────────────────────────

pub(crate) fn unquote_bytes(
    inner: &[u8],
    raw: bool,
) -> core::result::Result<alloc::vec::Vec<u8>, alloc::string::String> {
    // ── raw (backtick) mode: strip every CR, pass bytes through ──
    if raw {
        let mut out: Vec<u8> = Vec::new();
        for &b in inner {
            if b == b'\r' {
                continue;
            }
            check_capacity(&out, 1)?;
            out.push(b);
        }
        return core::result::Result::Ok(out);
    }

    // ── interpreted (double-quote) mode ──
    let mut out: Vec<u8> = Vec::new();
    let mut i: usize = 0;
    let n: usize = inner.len();

    while i < n {
        let b: u8 = inner[i];

        // ── literal newline / literal double-quote → error ──
        if b == b'\n' || b == b'"' {
            return core::result::Result::Err(bad_string());
        }

        // ── non-ASCII: delegate to crate::decode_go_rune ──
        if b >= 0x80 {
            match crate::decode_go_rune(&inner[i..]) {
                core::option::Option::Some((ch, width)) => {
                    emit_codepoint(&mut out, ch as u32)?;
                    i += width;
                }
                core::option::Option::None => {
                    // each bad byte → U+FFFD (3 bytes), advance 1
                    emit_fffd(&mut out)?;
                    i += 1;
                }
            }
            continue;
        }

        // ── ASCII, not backslash: literal pass-through (CR, NUL, printable…) ──
        if b != b'\\' {
            emit_byte(&mut out, b)?;
            i += 1;
            continue;
        }

        // ── backslash: must have at least one byte after ──
        i += 1;
        if i >= n {
            // trailing backslash
            return core::result::Result::Err(bad_string());
        }
        let esc: u8 = inner[i];
        i += 1;

        match esc {
            b'a' => emit_byte(&mut out, 0x07)?,
            b'b' => emit_byte(&mut out, 0x08)?,
            b'f' => emit_byte(&mut out, 0x0C)?,
            b'n' => emit_byte(&mut out, 0x0A)?,
            b'r' => emit_byte(&mut out, 0x0D)?,
            b't' => emit_byte(&mut out, 0x09)?,
            b'v' => emit_byte(&mut out, 0x0B)?,
            b'\\' => emit_byte(&mut out, b'\\')?,
            b'"' => emit_byte(&mut out, b'"')?,

            // \' is legal only inside single-quote literals → rejected here
            b'\'' => return core::result::Result::Err(bad_string()),

            // ── \x  (exactly 2 hex digits → raw byte 0x00..0xFF) ──
            b'x' => {
                if i + 2 > n {
                    return core::result::Result::Err(bad_string());
                }
                let hi = match hex_digit(inner[i]) {
                    core::option::Option::Some(v) => v,
                    core::option::Option::None => return core::result::Result::Err(bad_string()),
                };
                let lo = match hex_digit(inner[i + 1]) {
                    core::option::Option::Some(v) => v,
                    core::option::Option::None => return core::result::Result::Err(bad_string()),
                };
                i += 2;
                let val: u8 = ((hi << 4) | lo) as u8;
                emit_byte(&mut out, val)?;
            }

            // ── \u  (exactly 4 hex digits → valid scalar) ──
            b'u' => {
                if i + 4 > n {
                    return core::result::Result::Err(bad_string());
                }
                let mut v: u32 = 0;
                let mut ok = true;
                for j in 0..4usize {
                    match hex_digit(inner[i + j]) {
                        core::option::Option::Some(d) => {
                            // 4 hex digits max 0xFFFF, no u32 overflow
                            v = (v << 4) | d;
                        }
                        core::option::Option::None => {
                            ok = false;
                            break;
                        }
                    }
                }
                i += 4;
                if !ok {
                    return core::result::Result::Err(bad_string());
                }
                if !is_valid_scalar(v) {
                    return core::result::Result::Err(bad_string());
                }
                emit_codepoint(&mut out, v)?;
            }

            // ── \U  (exactly 8 hex digits, checked u32 arithmetic) ──
            b'U' => {
                if i + 8 > n {
                    return core::result::Result::Err(bad_string());
                }
                let mut v: u32 = 0;
                let mut ok = true;
                for j in 0..8usize {
                    match hex_digit(inner[i + j]) {
                        core::option::Option::Some(d) => {
                            v = match v.checked_shl(4).and_then(|s| s.checked_add(d)) {
                                core::option::Option::Some(nv) => nv,
                                core::option::Option::None => {
                                    ok = false;
                                    break;
                                }
                            };
                        }
                        core::option::Option::None => {
                            ok = false;
                            break;
                        }
                    }
                }
                i += 8;
                if !ok {
                    return core::result::Result::Err(bad_string());
                }
                if !is_valid_scalar(v) {
                    return core::result::Result::Err(bad_string());
                }
                emit_codepoint(&mut out, v)?;
            }

            // ── \ooo  (exactly 3 octal digits, value ≤ 255 → raw byte) ──
            b'0'..=b'7' => {
                // esc is the first octal digit; need two more
                if i + 2 > n {
                    return core::result::Result::Err(bad_string());
                }
                let d0 = (esc - b'0') as u32; // 0..7
                let d1 = match oct_digit(inner[i]) {
                    core::option::Option::Some(v) => v,
                    core::option::Option::None => return core::result::Result::Err(bad_string()),
                };
                let d2 = match oct_digit(inner[i + 1]) {
                    core::option::Option::Some(v) => v,
                    core::option::Option::None => return core::result::Result::Err(bad_string()),
                };
                i += 2;
                let val: u32 = (d0 << 6) | (d1 << 3) | d2;
                if val > 255 {
                    return core::result::Result::Err(bad_string());
                }
                emit_byte(&mut out, val as u8)?;
            }

            // ── everything else: unknown escape ──
            _ => return core::result::Result::Err(bad_string()),
        }
    }

    core::result::Result::Ok(out)
}
