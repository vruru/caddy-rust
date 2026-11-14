// Copyright 2010 The Go Authors. BSD-3-Clause; mechanical Go mime parser port.
use std::collections::BTreeMap;

pub(crate) struct Parsed {
    pub media_type: String,
    pub params: Option<BTreeMap<String, Vec<u8>>>,
    pub error: Option<String>,
}

fn is_t_special(c: u8) -> bool {
    matches!(c, b'(' | b')' | b'<' | b'>' | b'@' | b',' | b';' | b':' | b'\\' | b'"' | b'/' | b'[' | b']' | b'?' | b'=')
}

fn is_token_char(c: u8) -> bool {
    c > 32 && c < 127 && !is_t_special(c)
}

fn is_hex(c: u8) -> bool {
    matches!(c, b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F')
}

fn unhex(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => 0,
    }
}

fn whitespace_prefix(s:&[u8])->usize {
    match s.first().copied() {
        Some(9..=13)|Some(32)=>1,
        Some(0xc2)if matches!(s.get(1),Some(0x85|0xa0))=>2,
        Some(0xe1)if s.get(1..3)==Some(&[0x9a,0x80])=>3,
        Some(0xe2)if s.get(1)==Some(&0x80)&&s.get(2).is_some_and(|b|matches!(*b,0x80..=0x8a|0xa8|0xa9|0xaf))=>3,
        Some(0xe2)if s.get(1..3)==Some(&[0x81,0x9f])=>3,
        Some(0xe3)if s.get(1..3)==Some(&[0x80,0x80])=>3,
        _=>0,
    }
}
fn trim_left_unicode(mut s:&[u8])->&[u8] {
    loop { let n=whitespace_prefix(s);if n==0{return s}s=&s[n..]; }
}
fn trim_unicode(s:&[u8])->&[u8] {
    let mut s=trim_left_unicode(s);
    loop {let n=(1..=3).find(|n|s.len()>=*n&&whitespace_prefix(&s[s.len()-n..])==*n);
        let Some(n)=n else{return s};s=&s[..s.len()-n];}
}

fn consume_token(s: &[u8]) -> (&[u8], &[u8]) {
    for i in 0..s.len() {
        if !is_token_char(s[i]) {
            return (&s[..i], &s[i..]);
        }
    }
    (s, b"")
}

fn consume_value(s: &[u8]) -> (Vec<u8>, &[u8]) {
    if s.is_empty() {
        return (Vec::new(), s);
    }

    if s[0] != b'"' {
        let (tok, rest) = consume_token(s);
        return (tok.to_vec(), rest);
    }

    let mut buffer = Vec::new();
    let mut i = 1;
    while i < s.len() {
        let r = s[i];
        if r == b'"' {
            return (buffer, &s[i+1..]);
        }

        if r == b'\\' {
            if i + 1 < s.len() && is_t_special(s[i + 1]) {
                buffer.push(s[i + 1]);
                i += 2;
                continue;
            }
        }

        if r == b'\r' || r == b'\n' {
            return (Vec::new(), s);
        }

        buffer.push(r);
        i += 1;
    }

    (Vec::new(), s)
}

fn consume_media_param(v: &[u8]) -> (String, Vec<u8>, &[u8]) {
    let mut rest = trim_left_unicode(v);

    if !rest.starts_with(b";") {
        return (String::new(), Vec::new(), v);
    }
    rest = &rest[1..];

    rest = trim_left_unicode(rest);
    let (param_bytes, rest2) = consume_token(rest);
    rest = rest2;

    let param_str = match std::str::from_utf8(param_bytes) {
        Ok(st) => st.to_lowercase(),
        Err(_) => String::new(),
    };

    if param_str.is_empty() {
        return (String::new(), Vec::new(), v);
    }

    rest = trim_left_unicode(rest);
    if !rest.starts_with(b"=") {
        return (String::new(), Vec::new(), v);
    }
    rest = &rest[1..];

    rest = trim_left_unicode(rest);
    let (value, rest3) = consume_value(rest);

    if value.is_empty() && rest3.len() == rest.len() {
        return (String::new(), Vec::new(), v);
    }

    (param_str, value, rest3)
}

fn percent_hex_unescape(s: &[u8]) -> Result<Vec<u8>, ()> {
    let mut percents = 0;
    let mut i = 0;
    while i < s.len() {
        if s[i] != b'%' {
            i += 1;
            continue;
        }
        percents += 1;
        if i + 2 >= s.len() || !is_hex(s[i + 1]) || !is_hex(s[i + 2]) {
            return Err(());
        }
        i += 3;
    }

    if percents == 0 {
        return Ok(s.to_vec());
    }

    let mut t = Vec::with_capacity(s.len() - 2 * percents);
    i = 0;
    while i < s.len() {
        match s[i] {
            b'%' => {
                let hi = unhex(s[i + 1]);
                let lo = unhex(s[i + 2]);
                t.push((hi << 4) | lo);
                i += 3;
            }
            c => {
                t.push(c);
                i += 1;
            }
        }
    }

    Ok(t)
}

fn decode_2231_enc(v: &[u8]) -> Option<Vec<u8>> {
    let mut parts = v.splitn(2, |&b| b == b'\'');
    let charset_bytes = parts.next()?;
    let rest_of_v = parts.next()?;

    let charset_str = match std::str::from_utf8(charset_bytes) {
        Ok(st) => st.to_lowercase(),
        Err(_) => return None,
    };

    let mut parts2 = rest_of_v.splitn(2, |&b| b == b'\'');
    parts2.next()?; // lang
    let ext_other_vals = parts2.next()?;

    if charset_str != "us-ascii" && charset_str != "utf-8" {
        return None;
    }

    percent_hex_unescape(ext_other_vals).ok()
}

fn check_media_type_disposition(s: &[u8]) -> Result<(), String> {
    let (typ, rest) = consume_token(s);
    if typ.is_empty() {
        return Err("mime: no media type".to_string());
    }
    if rest.is_empty() {
        return Ok(());
    }
    if !rest.starts_with(b"/") {
        return Err("mime: expected slash after first token".to_string());
    }
    let rest = &rest[1..];
    let (subtype, rest) = consume_token(rest);
    if subtype.is_empty() {
        return Err("mime: expected token after slash".to_string());
    }
    if !rest.is_empty() {
        return Err("mime: unexpected content after media subtype".to_string());
    }
    Ok(())
}

pub(crate) fn parse(v: &[u8]) -> Parsed {
    if v.len() > 1<<20 {
        return Parsed{media_type:String::new(),params:None,error:Some("template MIME source exceeds byte limit".into())};
    }

    let mut entries = 0usize;
    let base = match v.iter().position(|b|*b==b';') {
        Some(i) => &v[..i],
        None => v,
    };

    let mediatype_bytes = trim_unicode(base);

    let mediatype_str = match std::str::from_utf8(mediatype_bytes) {
        Ok(st) => st.to_lowercase(),
        Err(_) => return Parsed {
            media_type: String::new(),
            params: None,
            error: Some("mime: no media type".to_string()), // Fallback, invalid encoding implies no valid ASCII token stream essentially
        },
    };

    if let Err(e) = check_media_type_disposition(mediatype_bytes) {
        return Parsed {
            media_type: String::new(),
            params: None,
            error: Some(e),
        };
    }

    let mut params: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut continuation: BTreeMap<String, BTreeMap<String, Vec<u8>>> = BTreeMap::new();

    let mut v_rest = &v[base.len()..];

    while !v_rest.is_empty() {
        v_rest = trim_left_unicode(v_rest);
        if v_rest.is_empty() {
            break;
        }

        let (key, value, rest) = consume_media_param(v_rest);
        if key.is_empty() {
            if trim_unicode(rest) == b";" {
                break;
            }
            return Parsed {
                media_type: mediatype_str,
                params: None,
                error: Some("mime: invalid media parameter".to_string()),
            };
        }

        let mut use_continuation = false;
        let mut base_name = String::new();

        if key.contains('*') {
            let pos = key.find('*').unwrap();
            base_name = key[..pos].to_string();
            use_continuation = true;
        }

        if use_continuation {
            let pmap = continuation.entry(base_name).or_insert_with(BTreeMap::new);
            if let Some(existing) = pmap.get(&key) {
                if existing != &value {
                    return Parsed {
                        media_type: String::new(),
                        params: None,
                        error: Some("mime: duplicate parameter name".to_string()),
                    };
                }
            }
            if !pmap.contains_key(&key){entries+=1;}
            pmap.insert(key, value);
        } else {
            if let Some(existing) = params.get(&key) {
                if existing != &value {
                    return Parsed {
                        media_type: String::new(),
                        params: None,
                        error: Some("mime: duplicate parameter name".to_string()),
                    };
                }
            }
            if !params.contains_key(&key){entries+=1;}
            params.insert(key, value);
        }

        if entries > 16_384 {
            return Parsed{media_type:mediatype_str,params:None,error:Some("template MIME parameter count limit exceeded".into())};
        }
        v_rest = rest;
    }

    for (key, piece_map) in continuation {
        let single_part_key = format!("{}*", key);
        if let Some(v_bytes) = piece_map.get(&single_part_key) {
            if let Some(decv) = decode_2231_enc(v_bytes) {
                params.insert(key.clone(), decv);
            }
            continue;
        }

        let mut buf = Vec::new();
        let mut valid = false;
        let mut n = 0;
        loop {
            let simple_part = format!("{}*{}", key, n);
            if let Some(v_bytes) = piece_map.get(&simple_part) {
                valid = true;
                buf.extend_from_slice(v_bytes);
                n += 1;
                continue;
            }

            let encoded_part = format!("{}*", simple_part);
            if let Some(v_bytes) = piece_map.get(&encoded_part) {
                valid = true;
                if n == 0 {
                    if let Some(decv) = decode_2231_enc(v_bytes) {
                        buf.extend_from_slice(&decv);
                    }
                } else {
                    if let Ok(decv) = percent_hex_unescape(v_bytes) {
                        buf.extend_from_slice(&decv);
                    }
                }
            } else {
                break;
            }
            n += 1;
        }

        if valid {
            params.insert(key, buf);
        }
    }

    Parsed {
        media_type: mediatype_str,
        params: Some(params),
        error: None,
    }
}
