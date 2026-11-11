// Go net/http ReadRequest and textproto header semantics (Go Authors, BSD-3-Clause).
use super::url;

pub(super) fn token(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

fn trim(mut value: &[u8]) -> &[u8] {
    while value
        .first()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        value = &value[1..];
    }
    while value
        .last()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        value = &value[..value.len() - 1];
    }
    value
}

#[derive(Clone, Copy)]
enum Kind {
    Other,
    Host,
    Length,
    Encoding,
    Trailer,
}

fn kind(name: &[u8]) -> Result<Kind, ()> {
    if name.is_empty() || !name.iter().all(|&byte| token(byte) || byte == b' ') {
        return Err(());
    }
    Ok(if name.eq_ignore_ascii_case(b"host") {
        Kind::Host
    } else if name.eq_ignore_ascii_case(b"content-length") {
        Kind::Length
    } else if name.eq_ignore_ascii_case(b"transfer-encoding") {
        Kind::Encoding
    } else if name.eq_ignore_ascii_case(b"trailer") {
        Kind::Trailer
    } else {
        Kind::Other
    })
}

#[derive(Default)]
struct Headers {
    host: Vec<Vec<u8>>,
    length: Vec<Vec<u8>>,
    encoding: Vec<Vec<u8>>,
    trailer: Vec<Vec<u8>>,
}

impl Headers {
    fn values(&mut self, kind: Kind) -> Option<&mut Vec<Vec<u8>>> {
        match kind {
            Kind::Host => Some(&mut self.host),
            Kind::Length => Some(&mut self.length),
            Kind::Encoding => Some(&mut self.encoding),
            Kind::Trailer => Some(&mut self.trailer),
            Kind::Other => None,
        }
    }

    fn validate(&self, major: u8, minor: u8) -> Result<(), ()> {
        if self.host.len() > 1 {
            return Err(());
        }
        let (major, minor) = if major == 0 && minor == 0 {
            (1, 1)
        } else {
            (major, minor)
        };
        let chunked = if major > 1 || major == 1 && minor >= 1 {
            match self.encoding.as_slice() {
                [] => false,
                [value] if value.eq_ignore_ascii_case(b"chunked") => true,
                _ => return Err(()),
            }
        } else {
            false
        };
        if let Some(first) = self.length.first() {
            if first.is_empty()
                || !first.iter().all(u8::is_ascii_digit)
                || self.length.iter().any(|value| value != first)
            {
                return Err(());
            }
            let mut length = 0i64;
            for byte in first {
                length = length
                    .checked_mul(10)
                    .and_then(|n| n.checked_add(i64::from(byte - b'0')))
                    .ok_or(())?;
            }
        }
        if chunked {
            for line in &self.trailer {
                for name in line.split(|&byte| byte == b',').map(trim) {
                    if name.eq_ignore_ascii_case(b"transfer-encoding")
                        || name.eq_ignore_ascii_case(b"trailer")
                        || name.eq_ignore_ascii_case(b"content-length")
                    {
                        return Err(());
                    }
                }
            }
        }
        Ok(())
    }
}

pub(super) fn location(header: &[u8]) -> Result<Vec<u8>, ()> {
    let mut lines = header
        .split(|&byte| byte == b'\n')
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line));
    let request_line = lines.next().ok_or(())?;
    let first = request_line
        .iter()
        .position(|&byte| byte == b' ')
        .ok_or(())?;
    let method = &request_line[..first];
    let rest = &request_line[first + 1..];
    let second = rest.iter().position(|&byte| byte == b' ').ok_or(())?;
    let target = &rest[..second];
    let proto = &rest[second + 1..];
    if method.is_empty()
        || !method.iter().all(|&byte| token(byte))
        || proto.len() != 8
        || !proto.starts_with(b"HTTP/")
        || proto[6] != b'.'
        || !proto[5].is_ascii_digit()
        || !proto[7].is_ascii_digit()
    {
        return Err(());
    }
    let major = proto[5] - b'0';
    let minor = proto[7] - b'0';
    let (uri_host, uri) = url::request_uri(target)?;
    let mut headers = Headers::default();
    let mut previous = None;
    for line in lines {
        if line.is_empty() {
            break;
        }
        if !line
            .iter()
            .all(|&byte| byte == b'\t' || byte >= 32 && byte != 127)
        {
            return Err(());
        }
        if matches!(line.first(), Some(b' ' | b'\t')) {
            let kind = previous.ok_or(())?;
            if let Some(values) = headers.values(kind) {
                let value = values.last_mut().ok_or(())?;
                value.push(b' ');
                value.extend_from_slice(trim(line));
            }
            continue;
        }
        let colon = line.iter().position(|&byte| byte == b':').ok_or(())?;
        let kind = kind(&line[..colon])?;
        if let Some(values) = headers.values(kind) {
            values.push(trim(&line[colon + 1..]).to_vec());
        }
        previous = Some(kind);
    }
    headers.validate(major, minor)?;
    let host = if uri_host.is_empty() {
        headers.host.first().map_or(&[][..], Vec::as_slice)
    } else {
        &uri_host
    };
    let mut output = Vec::with_capacity(8 + host.len() + uri.len());
    output.extend_from_slice(b"https://");
    output.extend_from_slice(host);
    output.extend_from_slice(&uri);
    Ok(output)
}
