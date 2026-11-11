use crate::hpack::huffman::table::{ENCODE_CODES, ENCODE_CODE_LENGTHS};

use bytes::{BufMut, BytesMut};

pub fn encode(src: &[u8], dst: &mut BytesMut) {
    let mut bits = 0u64;
    let mut bits_len = 0;

    for &b in src {
        let nbits = ENCODE_CODE_LENGTHS[b as usize] as usize;
        let code = ENCODE_CODES[b as usize] as u64;

        bits = (bits << nbits) | code;
        bits_len += nbits;

        if bits_len >= 32 {
            let remaining = bits_len - 32;
            dst.put_u32((bits >> remaining) as u32);

            bits_len = remaining;
            if remaining == 0 {
                bits = 0;
            } else {
                bits &= (1 << remaining) - 1;
            }
        }
    }

    if bits_len != 0 {
        // Pad the final byte with the EOS prefix (all ones).
        let padding = 8 - (bits_len % 8);
        let padding = if padding == 8 { 0 } else { padding };
        bits = (bits << padding) | ((1 << padding) - 1);
        bits_len += padding;

        while bits_len != 0 {
            bits_len -= 8;
            dst.put_u8((bits >> bits_len) as u8);
        }
    }
}
