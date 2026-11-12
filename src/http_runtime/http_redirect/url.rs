// Go net/url ParseRequestURI and URL.String semantics (Go Authors, BSD-3-Clause).
use std::net::Ipv6Addr;

fn nibble(byte: u8) -> Result<u8, ()> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(()),
    }
}
fn host_allowed(byte: u8) -> bool {
    byte >= 128 || byte.is_ascii_alphanumeric() || b"-_.~!$&'()*+,;=:[]<>\"".contains(&byte)
}
fn path_allowed(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"-_.~$&+,/:;=@".contains(&byte)
}
fn user_allowed(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"-_.~$&+,;=".contains(&byte)
}
fn escape(input: &[u8], allowed: fn(u8) -> bool) -> Vec<u8> {
    let mut output = Vec::new();
    for &byte in input {
        if allowed(byte) {
            output.push(byte);
        } else {
            output.push(b'%');
            output.push(b"0123456789ABCDEF"[usize::from(byte >> 4)]);
            output.push(b"0123456789ABCDEF"[usize::from(byte & 15)]);
        }
    }
    output
}
fn unescape(input: &[u8], mode: u8) -> Result<Vec<u8>, ()> {
    let mut output = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        let byte = input[i];
        if byte == b'%' {
            if i + 2 >= input.len() {
                return Err(());
            }
            let decoded = nibble(input[i + 1])? * 16 + nibble(input[i + 2])?;
            if mode == 1 && decoded < 128 && decoded != b'%' {
                return Err(());
            }
            if mode == 2
                && decoded != b'%'
                && decoded != b' '
                && (decoded >= 128 || !host_allowed(decoded))
            {
                return Err(());
            }
            output.push(decoded);
            i += 3;
        } else {
            if (mode == 1 || mode == 2) && byte < 128 && !host_allowed(byte) {
                return Err(());
            }
            output.push(byte);
            i += 1;
        }
    }
    Ok(output)
}
fn port(input: &[u8]) -> bool {
    input.is_empty() || input.first() == Some(&b':') && input[1..].iter().all(u8::is_ascii_digit)
}
fn parse_host(input: &[u8], scheme: &[u8]) -> Result<Vec<u8>, ()> {
    if input
        .iter()
        .rposition(|&b| b == b'[')
        .is_some_and(|i| i > 0)
    {
        return Err(());
    }
    if input.first() == Some(&b'[') {
        let end = input.iter().rposition(|&b| b == b']').ok_or(())?;
        if !port(&input[end + 1..]) {
            return Err(());
        }
        let name = &input[1..end];
        let decoded = if let Some(zone) = name.windows(3).position(|w| w == b"%25") {
            let mut decoded = unescape(&name[..zone], 1)?;
            decoded.extend(unescape(&name[zone..], 2)?);
            decoded
        } else {
            unescape(name, 1)?
        };
        if decoded.last() == Some(&b'%') {
            return Err(());
        }
        let address = decoded.split(|&b| b == b'%').next().ok_or(())?;
        std::str::from_utf8(address)
            .map_err(|_| ())?
            .parse::<Ipv6Addr>()
            .map_err(|_| ())?;
        let mut result = vec![b'['];
        result.extend(decoded);
        result.push(b']');
        result.extend(unescape(&input[end + 1..], 1)?);
        return Ok(result);
    }
    if let Some(first) = input.iter().position(|&b| b == b':') {
        let last = input.iter().rposition(|&b| b == b':').ok_or(())?;
        let i = if matches!(scheme, b"http" | b"https") {
            first
        } else {
            last
        };
        if !port(&input[i..]) {
            return Err(());
        }
    }
    unescape(input, 1)
}
fn authority(input: &[u8], scheme: &[u8]) -> Result<(Vec<u8>, Vec<u8>), ()> {
    let (userinfo, raw_host) = match input.iter().rposition(|&b| b == b'@') {
        Some(i) => (Some(&input[..i]), &input[i + 1..]),
        None => (None, input),
    };
    let host = parse_host(raw_host, scheme)?;
    let mut rendered = Vec::new();
    if let Some(user) = userinfo {
        if !user
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:%@".contains(&b))
        {
            return Err(());
        }
        if let Some(colon) = user.iter().position(|&b| b == b':') {
            rendered.extend(escape(&unescape(&user[..colon], 0)?, user_allowed));
            rendered.push(b':');
            rendered.extend(escape(&unescape(&user[colon + 1..], 0)?, user_allowed));
        } else {
            rendered.extend(escape(&unescape(user, 0)?, user_allowed));
        }
        rendered.push(b'@');
    }
    rendered.extend(escape(&host, |b| b < 128 && host_allowed(b)));
    Ok((host, rendered))
}
fn escaped_path(raw: &[u8]) -> Result<Vec<u8>, ()> {
    let decoded = unescape(raw, 0)?;
    if raw
        .iter()
        .all(|&b| path_allowed(b) || b"!$&'()*+,;=:@[]%".contains(&b))
    {
        Ok(raw.to_vec())
    } else {
        Ok(escape(&decoded, path_allowed))
    }
}
pub(crate) fn request_uri(raw: &[u8]) -> Result<(Vec<u8>, Vec<u8>), ()> {
    if raw.is_empty() || raw.iter().any(|&b| b < 32 || b == 127) {
        return Err(());
    }
    if raw == b"*" {
        return Ok((Vec::new(), raw.to_vec()));
    }
    let mut scheme = Vec::new();
    let mut rest = raw;
    for (index, &byte) in raw.iter().enumerate() {
        if byte == b':' {
            if index == 0 {
                return Err(());
            }
            scheme = raw[..index].iter().map(u8::to_ascii_lowercase).collect();
            rest = &raw[index + 1..];
            break;
        }
        if !(byte.is_ascii_alphabetic()
            || index > 0 && (byte.is_ascii_digit() || b"+-.".contains(&byte)))
        {
            break;
        }
    }
    if !rest.starts_with(b"/") {
        if scheme.is_empty() {
            return Err(());
        }
        let mut output = scheme;
        output.push(b':');
        output.extend_from_slice(rest);
        return Ok((Vec::new(), output));
    }
    let (raw_path, query) = match rest.iter().position(|&b| b == b'?') {
        Some(i) => (&rest[..i], Some(&rest[i + 1..])),
        None => (rest, None),
    };
    let mut path = raw_path;
    let mut host = Vec::new();
    let mut rendered_host = Vec::new();
    let has_authority = !scheme.is_empty() && path.starts_with(b"//");
    if has_authority {
        let after = &path[2..];
        let end = after.iter().position(|&b| b == b'/').unwrap_or(after.len());
        (host, rendered_host) = authority(&after[..end], &scheme)?;
        path = &after[end..];
    }
    let mut output = scheme.clone();
    if !scheme.is_empty() {
        output.push(b':');
    }
    if has_authority && (!rendered_host.is_empty() || !path.is_empty()) {
        output.extend_from_slice(b"//");
        output.extend(rendered_host);
    }
    let escaped = escaped_path(path)?;
    output.extend(escaped);
    if let Some(query) = query {
        output.push(b'?');
        output.extend(query);
    }
    Ok((host, output))
}

/// Go url.Parse(false), then the active check's Path/RawQuery-only URL.
/// Scheme, authority, opaque and fragment are validated but not copied.
pub(crate) fn health_uri_path_query(raw: &str) -> Result<String, ()> {
    let (raw, fragment) = raw.split_once('#').unwrap_or((raw, ""));
    if raw.bytes().any(|b| b < 32 || b == 127) {
        return Err(());
    }
    unescape(fragment.as_bytes(), 0)?;
    let mut rest = raw.as_bytes();
    let mut scheme = Vec::new();
    for (index, &byte) in rest.iter().enumerate() {
        if byte == b':' {
            if index == 0 {
                return Err(());
            }
            scheme = rest[..index].iter().map(u8::to_ascii_lowercase).collect();
            rest = &rest[index + 1..];
            break;
        }
        if !(byte.is_ascii_alphabetic()
            || index > 0 && (byte.is_ascii_digit() || b"+-.".contains(&byte)))
        {
            break;
        }
    }
    let (mut path, query) = match rest.iter().position(|&b| b == b'?') {
        Some(i) => (&rest[..i], &rest[i + 1..]),
        None => (rest, &b""[..]),
    };
    if !path.starts_with(b"/") {
        if !scheme.is_empty() {
            // A rootless absolute URI has Opaque, and its Path is empty.
            path = b"";
        } else if path
            .split(|&b| b == b'/')
            .next()
            .is_some_and(|p| p.contains(&b':'))
        {
            return Err(());
        }
    }
    if path.starts_with(b"//") && (!scheme.is_empty() || !path.starts_with(b"///")) {
        let after = &path[2..];
        let end = after.iter().position(|&b| b == b'/').unwrap_or(after.len());
        authority(&after[..end], &scheme)?;
        path = &after[end..];
    }
    let decoded = unescape(path, 0)?;
    let escaped = if decoded == b"*" {
        decoded
    } else {
        escape(&decoded, path_allowed)
    };
    let mut out = Vec::with_capacity(1 + escaped.len() + query.len());
    if !escaped.starts_with(b"/") {
        out.push(b'/');
    }
    out.extend(escaped);
    if !query.is_empty() {
        out.push(b'?');
        out.extend(query);
    }
    String::from_utf8(out).map_err(|_| ())
}
// Shared pure URL primitives for text/template helpers. No listener behavior is changed.
pub(crate) fn template_authority(scheme:&str,raw:&str)->Result<(String,Option<String>),()>{
    let(host,rendered)=authority(raw.as_bytes(),scheme.as_bytes())?;
    let user=if raw.contains('@'){let at=rendered.iter().rposition(|b|*b==b'@').ok_or(())?;Some(String::from_utf8(rendered[..at].to_vec()).map_err(|_|())?)}else{None};
    Ok((String::from_utf8(host).map_err(|_|())?,user))
}
pub(crate) fn template_decode(raw:&str)->Result<String,()>{String::from_utf8(unescape(raw.as_bytes(),0)?).map_err(|_|())}
pub(crate) fn template_path(raw:&str)->Result<String,()>{String::from_utf8(escaped_path(raw.as_bytes())?).map_err(|_|())}
pub(crate) fn template_encode_path(raw:&str)->String{String::from_utf8(escape(raw.as_bytes(),path_allowed)).expect("ASCII URL escape")}
pub(crate) fn template_encode_host(raw:&str)->String{String::from_utf8(escape(raw.as_bytes(),|b|b<128&&host_allowed(b))).expect("ASCII URL escape")}

/// Strict Go URL host decoding while preserving non-UTF8 wire bytes.
pub(crate) fn template_decode_host_bytes(scheme:&[u8],raw:&[u8])->Result<Vec<u8>,()>{parse_host(raw,scheme)}
pub(crate) fn template_encode_host_bytes(raw:&[u8])->Vec<u8>{escape(raw,|byte|byte<128&&host_allowed(byte))}

// Template request URL views retain native Go-string path/user bytes.
pub(crate) fn template_decode_bytes(raw:&[u8])->Result<Vec<u8>,()>{unescape(raw,0)}
pub(crate) fn template_encode_path_bytes(raw:&[u8])->Vec<u8>{escape(raw,path_allowed)}
pub(crate) fn template_encode_user_bytes(raw:&[u8])->Vec<u8>{escape(raw,user_allowed)}
