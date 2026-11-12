// HTML text writer ported from Goldmark 1.8.6 renderer/html/html.go (MIT).
use super::output::Output;
use super::entities::lookup;
use gotmpl::Result;
const REPLACEMENT: &[u8] = "\u{FFFD}".as_bytes();
#[inline]
fn escape_byte(b: u8) -> Option<&'static [u8]> {
    match b {
        b'\0' => Some(REPLACEMENT),
        b'"' => Some(b"&quot;"),
        b'&' => Some(b"&amp;"),
        b'<' => Some(b"&lt;"),
        b'>' => Some(b"&gt;"),
        _ => None,
    }
}
pub(super) fn raw_write(out: &mut Output, source: &[u8]) -> Result<()> {
    let l = source.len();
    let mut n = 0usize;
    let mut i = 0usize;
    while i < l {
        if let Some(v) = escape_byte(source[i]) {
            if n < i {
                out.write(&source[n..i])?;
            }
            out.write(v)?;
            n = i + 1;
            i += 1;
            continue;
        }
        i += 1;
    }
    if n < l {
        out.write(&source[n..])?;
    }
    Ok(())
}
pub(super) fn secure_write(out: &mut Output, source: &[u8]) -> Result<()> {
    let l = source.len();
    let mut n = 0usize;
    let mut i = 0usize;
    while i < l {
        if source[i] == b'\0' {
            if n < i {
                out.write(&source[n..i])?;
            }
            out.write(REPLACEMENT)?;
            n = i + 1;
            i += 1;
            continue;
        }
        i += 1;
    }
    if n < l {
        out.write(&source[n..])?;
    }
    Ok(())
}
fn escape_rune(out:&mut Output,codepoint:u32)->Result<()>{
    if codepoint<256{if let Some(bytes)=escape_byte(codepoint as u8){return out.write(bytes);}}
    let ch=char::from_u32(codepoint).filter(|ch|*ch!='\0').unwrap_or('\u{fffd}');
    let mut buffer=[0;4];out.write(ch.encode_utf8(&mut buffer).as_bytes())
}
pub(super) fn write(out: &mut Output, source: &[u8], escaped_space: bool) -> Result<()> {
    let limit = source.len();
    let mut n = 0usize;
    let mut i = 0usize;
    let mut escaped = false;
    while i < limit {
        let c = source[i];
        if escaped {
            if c.is_ascii_punctuation() {
                if n < i - 1 {
                    raw_write(out, &source[n..i - 1])?;
                }
                n = i;
                escaped = false;
                i += 1;
                continue;
            }
            if escaped_space && c == b' ' {
                if n < i - 1 {
                    raw_write(out, &source[n..i - 1])?;
                }
                n = i + 1;
                escaped = false;
                i += 1;
                continue;
            }
        }
        if c == b'\0' {
            if n < i {
                raw_write(out, &source[n..i])?;
            }
            out.write(REPLACEMENT)?;
            n = i + 1;
            escaped = false;
            i += 1;
            continue;
        }
        if c == b'&' {
            let pos = i;
            let next = i + 1;
            if next < limit && source[next] == b'#' {
                let nnext = next + 1;
                if nnext < limit {
                    let nc = source[nnext];
                    if nc == b'x' || nc == b'X' {
                        let start = nnext + 1;
                        let mut j = start;
                        while j < limit && source[j].is_ascii_hexdigit() {
                            j += 1;
                        }
                        if j > start && j < limit && source[j] == b';' && (j - start) < 7 {
                            let slice = &source[start..j];
                            if let Some(v) = parse_hex(slice) {
                                if n < pos {
                                    raw_write(out, &source[n..pos])?;
                                }
                                n = j + 1;
                                escape_rune(out, v)?;
                                i = j + 1;
                                continue;
                            }
                        }
                        i = next - 1;
                    }
                    else if nc >= b'0' && nc <= b'9' {
                        let start = nnext;
                        let mut j = start;
                        while j < limit && source[j].is_ascii_digit() {
                            j += 1;
                        }
                        if j > start && j < limit && (j - start) < 8 && source[j] == b';' {
                            let slice = &source[start..j];
                            if let Some(v) = parse_dec(slice) {
                                if n < pos {
                                    raw_write(out, &source[n..pos])?;
                                }
                                n = j + 1;
                                escape_rune(out, v)?;
                                i = j + 1;
                                continue;
                            }
                        }
                        i = next - 1;
                    }
                    else {
                        i = next - 1;
                    }
                } else {
                    i = next - 1;
                }
            } else if next < limit {
                let start = next;
                let mut j = start;
                while j < limit && source[j].is_ascii_alphanumeric() {
                    j += 1;
                }
                if j > start && j < limit && source[j] == b';' {
                    let name = &source[start..j];
                    if let Some(entity) = lookup(name) {
                        if n < pos {
                            raw_write(out, &source[n..pos])?;
                        }
                        n = j + 1;
                        raw_write(out, entity)?;
                        i = j + 1;
                        continue;
                    }
                }
                i = next - 1;
            } else {
                i = next - 1;
            }
        }
        if c == b'\\' {
            escaped = true;
            i += 1;
            continue;
        }
        escaped = false;
        i += 1;
    }
    if n < limit {
        raw_write(out, &source[n..])?;
    }
    Ok(())
}
fn parse_hex(b: &[u8]) -> Option<u32> {
    let mut val: u32 = 0;
    for &c in b {
        val = val << 4;
        match c {
            b'0'..=b'9' => val |= (c - b'0') as u32,
            b'a'..=b'f' => val |= (c - b'a' + 10) as u32,
            b'A'..=b'F' => val |= (c - b'A' + 10) as u32,
            _ => return None,
        }
    }
    Some(val)
}
fn parse_dec(b: &[u8]) -> Option<u32> {
    let mut val: u32 = 0;
    for &c in b {
        val = val * 10 + (c - b'0') as u32;
        if val > 0x10FFFF {
            return Some(0);
        }
    }
    Some(val)
}
