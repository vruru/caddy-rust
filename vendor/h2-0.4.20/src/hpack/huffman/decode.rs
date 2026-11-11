//! Huffman decoding for HPACK (RFC 7541 §5.2).
//!
//! The decoder has a fast path which decodes 12 bits a time. The decoder
//! looks the next 12 bits up in `FAST_TABLE`, which maps directly to either
//! one or two symbols to decode. Since ASCII letters and digits have 5-7 bit
//! codes, one lookup usually decodes two symbols at once.
//!
//! Two situations fall off this fast path:
//!
//! - Codes longer than 12 bits: control characters and bytes >= 0x80
//! - The end of the input, when fewer than 12 bits remain.
//!
//! These are decoded by walking the generated `DECODE_TABLE` one input byte at a time.

use crate::hpack::huffman::table::{DECODE_TABLE, ENCODE_CODES, ENCODE_CODE_LENGTHS};
use crate::hpack::DecoderError;

use bytes::BytesMut;

// DECODE_TABLE (in the generated `table.rs`) is a series of 256-entry
// tables, walked one input byte at a time. A leaf entry (BRANCH bit clear)
// holds a decoded symbol and the number of bits its code used. A branch
// entry (BRANCH bit set) holds the index of the table for the next byte.
// No valid code leads back to table 0, so a branch to 0 means the input is
// not a valid code.
const BRANCH: u16 = 0x8000;
const TABLE_INDEX_MASK: u16 = 0x7f00;
const TABLE_WIDTH: usize = 256;

// Maps each possible 12-bit chunk of input to the symbol(s) it starts
// with. Entry layout (u32):
//
//   bits  0..8   first decoded byte
//   bits  8..16  second decoded byte (if any)
//   bits 16..24  number of symbols decoded: 1, 2, or 0, where 0 means the
//                code is longer than 12 bits and the slow path must run
//   bits 24..32  how many of the 12 bits the decoded symbols used
const FAST_BITS: usize = 12;
const FAST_DECODE_TABLE: [u32; 1 << FAST_BITS] = build_fast_table();

const fn build_fast_table() -> [u32; 1 << FAST_BITS] {
    let mut table = [0; 1 << FAST_BITS];

    // First fill in every index that starts with one whole code
    let mut a = 0;
    while a < 256 {
        let len1 = ENCODE_CODE_LENGTHS[a] as usize;
        let code1 = ENCODE_CODES[a] as u64;
        if len1 <= FAST_BITS {
            let rem = FAST_BITS - len1;
            let base = (code1 as usize) << rem;
            let single = (1 << 16) | ((len1 as u32) << 24) | a as u32;
            let mut i = 0;
            while i < (1 << rem) {
                table[base + i] = single;
                i += 1;
            }
        }
        a += 1;
    }

    // Overwrite the indices where a second whole code fit right after the first
    let mut a = 0;
    while a < 256 {
        let len1 = ENCODE_CODE_LENGTHS[a] as usize;
        let code1 = ENCODE_CODES[a] as u64;
        // A second code needs at least 5 more bits (the shortest code)
        if len1 + 5 <= FAST_BITS {
            let rem = FAST_BITS - len1;
            let mut b = 0;
            while b < 256 {
                let len2 = ENCODE_CODE_LENGTHS[b] as usize;
                let code2 = ENCODE_CODES[b] as u64;
                if len2 <= rem {
                    let rem2 = rem - len2;
                    let base = ((code1 as usize) << rem) | ((code2 as usize) << rem2);
                    let pair =
                        (2 << 16) | (((len1 + len2) as u32) << 24) | ((b as u32) << 8) | a as u32;
                    let mut i = 0;
                    while i < (1 << rem2) {
                        table[base + i] = pair;
                        i += 1;
                    }
                }
                b += 1;
            }
        }
        a += 1;
    }

    table
}

// Decodes one code of any length by walking DECODE_TABLE one input byte at
// a time, and writes the symbol to `dst[*o]`. Used for codes longer than
// FAST_BITS bits and for the tail of the input.
//
// Inlining avoids a 35% performance regression on ASCII benchmarks.
#[inline(always)]
fn decode_code_slow(
    acc: &mut u64,
    bits: &mut usize,
    dst: &mut [u8],
    o: &mut usize,
) -> Result<(), DecoderError> {
    let mut table = 0;
    loop {
        let e = DECODE_TABLE[table * TABLE_WIDTH + (*acc >> 56) as usize];
        if e & BRANCH == 0 {
            let used = (e >> 8) as usize;
            if used > *bits {
                return Err(DecoderError::InvalidHuffmanCode);
            }
            dst[*o] = e as u8;
            *o += 1;
            *acc <<= used;
            *bits -= used;
            return Ok(());
        }
        if *bits < 8 {
            return Err(DecoderError::InvalidHuffmanCode);
        }
        table = ((e & TABLE_INDEX_MASK) >> 8) as usize;
        if table == 0 {
            return Err(DecoderError::InvalidHuffmanCode);
        }
        *acc <<= 8;
        *bits -= 8;
    }
}

// Decodes a Huffman encoded string into the provided buffer.
pub fn decode(src: &[u8], buf: &mut BytesMut) -> Result<BytesMut, DecoderError> {
    let len = src.len();
    let base_len = buf.len();

    // Reserve the worst case output size. Every code is at least 5 bits,
    // so `len` input bytes can't decode to more than `len * 8 / 5` output
    // bytes. One more byte covers the fast path always writing two bytes
    // even when it decoded only one symbol.
    buf.resize(base_len + len * 8 / 5 + 1, 0);
    let dst = &mut buf[base_len..];
    let mut o = 0;

    let mut acc: u64 = 0;
    let mut bits: usize = 0;
    let mut pos: usize = 0;

    'outer: loop {
        // Fill the bit buffer. While 8 or more input bytes remain, load
        // the next 8 in one go and count as many whole bytes as fit under
        // the bits already in the buffer (bringing it to 56-63 bits). The
        // bytes that didn't fit still land in the low end of `acc`; the
        // next refill just ORs the same values over them, so no harm done.
        if pos + 8 <= len {
            let word = u64::from_be_bytes(src[pos..pos + 8].try_into().unwrap());
            acc |= word >> bits;
            pos += (63 - bits) >> 3; // bytes now accounted for in `bits`
            bits |= 56; // equals bits + 8 * (bytes added)
        } else {
            while bits <= 56 && pos < len {
                acc |= (src[pos] as u64) << (56 - bits);
                pos += 1;
                bits += 8;
            }
        }

        while bits >= FAST_BITS {
            let entry = FAST_DECODE_TABLE[(acc >> (64 - FAST_BITS)) as usize];
            let count = (entry >> 16) & 0xff;
            if count == 0 {
                // The next code is longer than 12 bits. Refill first if it
                // might not be in the buffer yet (the longest code is 30
                // bits), then decode it by walking DECODE_TABLE.
                if bits < 30 && pos < len {
                    continue 'outer;
                }
                decode_code_slow(&mut acc, &mut bits, dst, &mut o)?;
                continue;
            }
            let consumed = (entry >> 24) as usize;
            dst[o] = entry as u8;
            dst[o + 1] = (entry >> 8) as u8;
            o += count as usize;
            acc <<= consumed;
            bits -= consumed;
        }

        if pos >= len {
            break;
        }
    }

    // Tail: the input is exhausted and fewer than 12 bits remain.
    while bits > 0 {
        // The encoder pads the last byte with up to 7 one-bits, which are
        // valid only between symbols. Anything else must decode.
        if bits < 8 && (acc >> (64 - bits)) == (1 << bits) - 1 {
            break;
        }
        decode_code_slow(&mut acc, &mut bits, dst, &mut o)?;
    }

    buf.truncate(base_len + o);
    Ok(buf.split())
}
