// Copyright (c) 2015 Huan Du. MIT; see LICENSE-xstrings.
// Port of pinned github.com/huandu/xstrings v1.6.1 convert.go and count.go.
use super::super::MAX_BYTES;
use super::super::err;
use super::go_case::{upper, lower, is_upper, is_letter, is_number, is_punct};
use gotmpl::{decode_go_rune,Result as GResult};
#[inline]
fn append_rune(buf: &mut Vec<u8>, r: char) -> GResult<()> {
    let mut tmp = [0u8; 4];
    let len = r.encode_utf8(&mut tmp).len();
    append_bytes(buf, &tmp[..len])
}
#[inline]
fn append_bytes(buf: &mut Vec<u8>, s: &[u8]) -> GResult<()> {
    let new_len = buf.len().checked_add(s.len()).ok_or_else(|| {
        err("byte slice too long for output")
    })?;
    if new_len > MAX_BYTES {
        return Err(err("output exceeds MAX_BYTES"));
    }
    buf.extend_from_slice(s);
    Ok(())
}
#[inline]
fn append_byte(buf: &mut Vec<u8>, b: u8) -> GResult<()> {
    if buf.len() >= MAX_BYTES {
        return Err(err("output exceeds MAX_BYTES"));
    }
    buf.push(b);
    Ok(())
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum WordType {
    Invalid,
    Number,
    UpperCase,
    Alphabet,
    Connector,
    Punct,
    Other,
}
fn is_connector(r: char) -> bool {
    r == '-' || r == '_' || r.is_whitespace()
}
fn is_alphabet(r: char) -> bool {
    if !is_letter(r) {
        return false;
    }
    if r < '\u{3400}' {
        return true;
    }
    if r >= '\u{4E00}' && r <= '\u{9FCC}' {
        return false;
    }
    if r >= '\u{3400}' && r <= '\u{4D85}' {
        return false;
    }
    if r >= '\u{20000}' && r <= '\u{2B81D}' {
        return false;
    }
    true
}
fn next_valid(input: &[u8], prev: char) -> (char, usize) {
    let mut size_accum = 0;
    let mut curr_str = input;
    while !curr_str.is_empty() {
        if let Some((r, w)) = decode_go_rune(curr_str) {
            size_accum += w;
            if r != '\u{FFFD}' {
                return (r, size_accum);
            }
            if w == 0 {
                break;
            }
            curr_str = &curr_str[w..];
        } else {
            break;
        }
    }
    (prev, size_accum)
}
fn next_word(input: &[u8]) -> (WordType, &[u8], &[u8]) {
    if input.is_empty() {
        return (WordType::Invalid, &[], &[]);
    }
    let mut offset = 0;
    let mut remaining = input;
    let (mut r, size) = next_valid(remaining, '\u{FFFD}');
    offset += size;
    remaining = &remaining[size..];
    if r == '\u{FFFD}' {
        return (WordType::Invalid, &input[..offset], remaining);
    }
    let wt;
    if is_connector(r) {
        wt = WordType::Connector;
        while !remaining.is_empty() {
            let (next_r, sz) = next_valid(remaining, r);
            if !is_connector(next_r) {
                break;
            }
            offset += sz;
            remaining = &remaining[sz..];
            r = next_r; // Update r for next iteration's prev?
        }
    } else if is_punct(r) {
        wt = WordType::Punct;
        while !remaining.is_empty() {
            let (next_r, sz) = next_valid(remaining, r);
            if !is_punct(next_r) {
                break;
            }
            offset += sz;
            remaining = &remaining[sz..];
            r = next_r;
        }
    } else if is_upper(r) {
        wt = WordType::UpperCase;
        if remaining.is_empty() {
        } else {
            let (next_r, sz) = next_valid(remaining, r);

            if is_upper(next_r) {
                r = next_r;
                let mut prev_size = sz;
                offset += sz;
                remaining=&remaining[sz..];
                while !remaining.is_empty() {
                    let (next_r2, sz2) = next_valid(remaining, r);
                    r=next_r2;
                    if !is_upper(next_r2) {
                        break;
                    }
                    prev_size = sz2;
                    offset += sz2;
                    remaining = &remaining[sz2..];
                    r = next_r2;
                }


                if !remaining.is_empty() && is_alphabet(r) {
                     offset -= prev_size;
                     remaining = &input[offset..];
                }
            } else if is_alphabet(next_r) {
                offset += sz;
                remaining = &remaining[sz..];
                r = next_r;
                while !remaining.is_empty() {
                    let (next_r2, sz2) = next_valid(remaining, r);
                    if !is_alphabet(next_r2) || is_upper(next_r2) {
                        break;
                    }
                    offset += sz2;
                    remaining = &remaining[sz2..];
                    r = next_r2;
                }
            }
        }
    } else if is_alphabet(r) {
        wt = WordType::Alphabet;
        while !remaining.is_empty() {
            let (next_r, sz) = next_valid(remaining, r);
            if !is_alphabet(next_r) || is_upper(next_r) {
                break;
            }
            offset += sz;
            remaining = &remaining[sz..];
            r = next_r;
        }
    } else if is_number(r) {
        wt = WordType::Number;
        while !remaining.is_empty() {
            let (next_r, sz) = next_valid(remaining, r);
            if !is_number(next_r) {
                break;
            }
            offset += sz;
            remaining = &remaining[sz..];
            r = next_r;
        }
    } else {
        wt = WordType::Other;
        while !remaining.is_empty() {
            let (next_r, sz) = next_valid(remaining, r);
            if sz == 0 {
                break;
            }
            if is_connector(next_r) || is_alphabet(next_r) || is_number(next_r) || is_punct(next_r) {
                break;
            }
            offset += sz;
            remaining = &remaining[sz..];
            r = next_r;
        }
    }
    let word = &input[..offset];
    (wt, word, remaining)
}
fn to_lower_buf(buf: &mut Vec<u8>, wt: WordType, word: &[u8], connector: u8) -> GResult<()> {
    if wt != WordType::UpperCase && wt != WordType::Connector {
        return append_bytes(buf, word);
    }
    let mut str_slice = word;
    while !str_slice.is_empty() {
        if let Some((r, size)) = decode_go_rune(str_slice) {
            str_slice = &str_slice[size..];
            if is_connector(r) {
                append_byte(buf, connector)?;
            } else if is_upper(r) {
                let lr = lower(r);
                append_rune(buf, lr)?;
            } else {
                append_rune(buf, r)?;
            }
        } else {
            break;
        }
    }
    Ok(())
}
fn to_camel_case(input: &[u8], is_big: bool) -> GResult<Vec<u8>> {
    if input.is_empty() {
        return Ok(Vec::new());
    }
    let mut buf = Vec::new();
    let mut str_slice = input;
    let mut is_first_rune_upper = false;
    let mut r0: char = '\0';
    let mut has_r0 = false;
    while !str_slice.is_empty() {
        if let Some((r, sz)) = decode_go_rune(str_slice) {
            r0 = r;
            let size=sz;
            str_slice = &str_slice[size..];
            if !is_connector(r0) {
                is_first_rune_upper = is_upper(r0);
                if is_big {
                    r0 = upper(r0);
                } else {
                    r0 = lower(r0);
                }
                has_r0 = true;
                break;
            }
            append_rune(&mut buf, r0)?;
        } else {
            break;
        }
    }
    if str_slice.is_empty() {
        if has_r0 && !is_connector(r0) {
             append_rune(&mut buf, r0)?;
        }
        return Ok(buf);
    }
    while !str_slice.is_empty() {
        let r1=r0;
        if let Some((r, sz)) = decode_go_rune(str_slice) {
            r0 = r;
            let size=sz;
            str_slice = &str_slice[size..];
        } else {
            break;
        }
        if is_connector(r0) && is_connector(r1) {
            append_rune(&mut buf, r1)?;
            continue;
        }
        if is_connector(r1) {
            is_first_rune_upper = is_upper(r0);
            r0 = upper(r0);
        } else {
            if is_first_rune_upper {
                if is_upper(r0) {
                    r0 = lower(r0);
                } else {
                    is_first_rune_upper = false;
                }
            }
            append_rune(&mut buf, r1)?;
        }
    }
    append_rune(&mut buf, r0)?;
    Ok(buf)
}
pub(super) fn pascal(input: &[u8]) -> GResult<Vec<u8>> {
    to_camel_case(input, true)
}
pub(super) fn separated(input: &[u8], connector: u8) -> GResult<Vec<u8>> {
    if input.is_empty() {
        return Ok(Vec::new());
    }
    let mut buf = Vec::new();
    let (mut wt, mut word, mut remaining) = next_word(input);

    while !remaining.is_empty() {
        if wt != WordType::Connector {
            to_lower_buf(&mut buf, wt, word, connector)?;
        }
        let prev = wt;
        let last = word;
        (wt, word, remaining) = next_word(remaining);
        'decision: { match prev {
            WordType::Number => {
                while wt == WordType::Alphabet || wt == WordType::Number {
                    to_lower_buf(&mut buf, wt, word, connector)?;
                    (wt, word, remaining) = next_word(remaining);
                }
                if wt != WordType::Invalid && wt != WordType::Punct && wt != WordType::Connector {
                    append_byte(&mut buf, connector)?;
                }
            }
            WordType::Connector => {
                to_lower_buf(&mut buf, prev, last, connector)?;
            }
            WordType::Punct => {
            }
            _ => {
                if wt != WordType::Number {
                    if wt != WordType::Connector && wt != WordType::Punct {
                        append_byte(&mut buf, connector)?;
                    }
                    break 'decision;
                }
                if remaining.is_empty() {
                    break 'decision;
                }
                let last_num = word;
                (wt, word, remaining) = next_word(remaining);
                if wt != WordType::Alphabet {
                    to_lower_buf(&mut buf, WordType::Number, last_num, connector)?;
                    if wt != WordType::Connector && wt != WordType::Punct {
                        append_byte(&mut buf, connector)?;
                    }
                    break 'decision;
                }
                append_byte(&mut buf, connector)?;
                to_lower_buf(&mut buf, WordType::Number, last_num, connector)?;
                while wt == WordType::Alphabet || wt == WordType::Number {
                    to_lower_buf(&mut buf, wt, word, connector)?;
                    (wt, word, remaining) = next_word(remaining);
                }
                if wt != WordType::Invalid && wt != WordType::Connector && wt != WordType::Punct {
                    append_byte(&mut buf, connector)?;
                }
            }
        }}
    }
    to_lower_buf(&mut buf, wt, word, connector)?;
    Ok(buf)
}
