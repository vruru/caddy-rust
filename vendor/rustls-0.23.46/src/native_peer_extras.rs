use alloc::vec::Vec;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct NativePeerExtras {
    pub(crate) ocsp: Vec<u8>,
    pub(crate) scts: Vec<Vec<u8>>,
}

pub(crate) const MAX_PEER_EXTRA_BYTES: usize = 64 * 1024;

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Cursor { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if n > self.remaining() {
            return None;
        }
        let slice = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Some(slice)
    }

    fn take_u16be(&mut self) -> Option<u16> {
        let bytes = self.take(2)?;
        let val = u16::from_be_bytes([bytes[0], bytes[1]]);
        Some(val)
    }

    fn take_u24be(&mut self) -> Option<u32> {
        let bytes = self.take(3)?;
        let val = u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]);
        Some(val)
    }

    fn is_empty(&self) -> bool {
        self.pos == self.data.len()
    }
}

pub(crate) fn encode_scts(scts: &[Vec<u8>]) -> Option<Vec<u8>> {
    if scts.is_empty() {
        return None;
    }

    let mut content_len: usize = 0;

    for sct in scts {
        let sct_len = sct.len();
        if sct_len == 0 {
            return None;
        }
        if sct_len > 65535 {
            return None;
        }
        content_len = content_len.checked_add(2)?;
        content_len = content_len.checked_add(sct_len)?;
    }

    if content_len == 0 {
        return None;
    }
    if content_len > 65535 {
        return None;
    }

    let total_len = content_len.checked_add(2)?;

    let mut out = Vec::with_capacity(total_len);

    out.extend_from_slice(&(content_len as u16).to_be_bytes());

    for sct in scts {
        out.extend_from_slice(&(sct.len() as u16).to_be_bytes());
        out.extend_from_slice(sct);
    }

    Some(out)
}

pub(crate) fn decode_scts(input: &[u8]) -> Option<Vec<Vec<u8>>> {
    if input.len() > 65537 {
        return None;
    }

    if input.len() < 2 {
        return None;
    }

    let mut cursor = Cursor::new(input);

    let content_len_u16 = cursor.take_u16be()?;
    let content_len = content_len_u16 as usize;

    if content_len == 0 {
        return None;
    }

    if content_len > cursor.remaining() {
        return None;
    }

    if cursor.remaining() > content_len {
        // trailing bytes
        return None;
    }

    let mut scts = Vec::new();

    while !cursor.is_empty() {
        let sct_len_u16 = cursor.take_u16be()?;
        let sct_len = sct_len_u16 as usize;

        if sct_len == 0 {
            return None;
        }

        if sct_len > cursor.remaining() {
            return None;
        }

        let sct_bytes = cursor.take(sct_len)?;
        scts.push(sct_bytes.to_vec());
    }

    if scts.is_empty() {
        return None;
    }

    Some(scts)
}

impl NativePeerExtras {
    pub(crate) fn encode_session(&self) -> Option<Vec<u8>> {
        let ocsp_len = self.ocsp.len();

        if ocsp_len > MAX_PEER_EXTRA_BYTES {
            return None;
        }

        let sct_payload = if self.scts.is_empty() {
            Vec::new()
        } else {
            match encode_scts(&self.scts) {
                Some(p) => p,
                None => return None,
            }
        };

        // Total: 3 (ocspLen) + ocsp_len + 2 (sctPayloadLen) + sct_payload.len()
        let mut total = 0usize;
        total = total.checked_add(3)?;
        total = total.checked_add(ocsp_len)?;
        total = total.checked_add(2)?;
        total = total.checked_add(sct_payload.len())?;

        if total > 65535 {
            return None;
        }

        let mut out = Vec::with_capacity(total);

        // u24BE ocspLen
        let ocsp_len_u24 = ocsp_len as u32;
        out.extend_from_slice(&[
            (ocsp_len_u24 >> 16) as u8,
            (ocsp_len_u24 >> 8) as u8,
            ocsp_len_u24 as u8,
        ]);

        out.extend_from_slice(&self.ocsp);

        // u16BE sctPayloadLen
        let sct_payload_len = sct_payload.len();
        if sct_payload_len > 65535 {
            return None;
        }
        out.extend_from_slice(&(sct_payload_len as u16).to_be_bytes());

        out.extend_from_slice(&sct_payload);

        Some(out)
    }

    pub(crate) fn decode_session(input: &[u8]) -> Option<Self> {
        if input.is_empty() {
            return None;
        }
        if input.len() < 5 {
            return None;
        }
        if input.len() > 65535 {
            return None;
        }

        let mut cursor = Cursor::new(input);

        let ocsp_len_u32 = cursor.take_u24be()?;

        if ocsp_len_u32 > MAX_PEER_EXTRA_BYTES as u32 {
            return None;
        }
        let ocsp_len = ocsp_len_u32 as usize;

        if ocsp_len > cursor.remaining() {
            return None;
        }

        let ocsp_bytes = cursor.take(ocsp_len)?;

        let sct_payload_len_u16 = cursor.take_u16be()?;
        let sct_payload_len = sct_payload_len_u16 as usize;

        if sct_payload_len > cursor.remaining() {
            return None;
        }

        let sct_payload = cursor.take(sct_payload_len)?;

        if !cursor.is_empty() {
            return None;
        }

        let ocsp = ocsp_bytes.to_vec();

        let scts = if sct_payload.is_empty() {
            Vec::new()
        } else {
            match decode_scts(sct_payload) {
                Some(scts) => scts,
                None => return None,
            }
        };

        let total_extras = ocsp.len().checked_add(scts.iter().map(|s| s.len()).sum::<usize>())?;

        if total_extras > MAX_PEER_EXTRA_BYTES {
            return None;
        }

        Some(NativePeerExtras { ocsp, scts })
    }
}
