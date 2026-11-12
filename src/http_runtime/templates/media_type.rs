// Copyright 2010 The Go Authors. BSD-3-Clause; mechanical Go mime parser port.
use std::collections::BTreeMap;

pub(crate) struct Parsed {
    pub media_type: String,
    pub params: Option<BTreeMap<String, String>>,
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

fn trim_left_unicode(s:&str)->&str{s.trim_start_matches(char::is_whitespace)}
fn trim_unicode(s:&str)->&str{s.trim_matches(char::is_whitespace)}

fn consume_token(s: &str) -> (&str, &str) {
    let bytes = s.as_bytes();
    for i in 0..bytes.len() {
        if !is_token_char(bytes[i]) {
            return (&s[..i], &s[i..]);
        }
    }
    (s, "")
}

fn consume_value(s: &str) -> (String, &str) {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return (String::new(), s);
    }

    if bytes[0] != b'"' {
        let (tok, rest) = consume_token(s);
        return (tok.to_string(), rest);
    }

    let mut buffer = Vec::new();

    let mut i = 1;
    while i < bytes.len() {
        let r = bytes[i];
        if r == b'"' {
            match String::from_utf8(buffer) {
                Ok(value) => return (value, &s[i+1..]),
                Err(_) => return (String::new(), s),
            }
        }

        if r == b'\\' {
            if i + 1 < bytes.len() && is_t_special(bytes[i + 1]) {
                buffer.push(bytes[i + 1]);
                i += 2;
                continue;
            }
        }

        if r == b'\r' || r == b'\n' {
            return (String::new(), s);
        }

        buffer.push(r);
        i += 1;
    }

    (String::new(), s)
}

fn consume_media_param(v: &str) -> (String, String, &str) {
    let mut rest = trim_left_unicode(v);

    if !rest.starts_with(';') {
        return (String::new(), String::new(), v);
    }
    rest = &rest[1..];

    rest = trim_left_unicode(rest);
    let (param, rest2) = consume_token(rest);
    rest = rest2;

    let param_lower = param.to_lowercase();
    if param_lower.is_empty() {
        return (String::new(), String::new(), v);
    }

    rest = trim_left_unicode(rest);
    if !rest.starts_with('=') {
        return (String::new(), String::new(), v);
    }
    rest = &rest[1..];

    rest = trim_left_unicode(rest);
    let (value, rest3) = consume_value(rest);

    if value.is_empty() && rest3.len() == rest.len() {
        return (String::new(), String::new(), v);
    }

    (param_lower, value, rest3)
}

fn percent_hex_unescape(s: &str) -> Result<Vec<u8>, ()> {
    let bytes = s.as_bytes();
    let mut percents = 0;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'%' {
            i += 1;
            continue;
        }
        percents += 1;
        if i + 2 >= bytes.len() || !is_hex(bytes[i + 1]) || !is_hex(bytes[i + 2]) {
            return Err(());
        }
        i += 3;
    }

    if percents == 0 {
        return Ok(s.as_bytes().to_vec());
    }

    let mut t = Vec::with_capacity(bytes.len() - 2 * percents);
    i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let hi = unhex(bytes[i + 1]);
                let lo = unhex(bytes[i + 2]);
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

fn decode_2231_enc(v: &str) -> Option<Vec<u8>> {
    let mut parts = v.splitn(2, '\'');
    let charset = parts.next()?.to_lowercase();
    let v = parts.next()?;

    let mut parts2 = v.splitn(2, '\'');
    parts2.next()?; // lang
    let ext_other_vals = parts2.next()?;

    if charset != "us-ascii" && charset != "utf-8" {
        return None;
    }

    percent_hex_unescape(ext_other_vals).ok()
}

fn check_media_type_disposition(s: &str) -> Result<(), String> {
    let (typ, rest) = consume_token(s);
    if typ.is_empty() {
        return Err("mime: no media type".to_string());
    }
    if rest.is_empty() {
        return Ok(());
    }
    if !rest.starts_with('/') {
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

pub(crate) fn parse(v: &str) -> Parsed {
    if v.len()>1<<20{return Parsed{media_type:String::new(),params:None,error:Some("template MIME source exceeds byte limit".into())};}
    let mut entries=0usize;
    let base = match v.find(';') {
        Some(i) => &v[..i],
        None => v,
    };

    let mediatype = trim_unicode(base).to_lowercase();

    if let Err(e) = check_media_type_disposition(&mediatype) {
        return Parsed {
            media_type: String::new(),
            params: None,
            error: Some(e),
        };
    }

    let mut params = BTreeMap::new();
    let mut continuation: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();

    let mut v_rest = &v[base.len()..];

    while !v_rest.is_empty() {
        v_rest = trim_left_unicode(v_rest);
        if v_rest.is_empty() {
            break;
        }

        let (key, value, rest) = consume_media_param(v_rest);
        if key.is_empty() {
            if trim_unicode(rest) == ";" {
                break;
            }
            return Parsed {
                media_type: mediatype,
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

        if entries>16_384{return Parsed{media_type:mediatype,params:None,error:Some("template MIME parameter count limit exceeded".into())};}
        v_rest = rest;
    }

    for (key, piece_map) in continuation {
        let single_part_key = format!("{}*", key);
        if let Some(v) = piece_map.get(&single_part_key) {
            if let Some(decv) = decode_2231_enc(v) {
                let Ok(decv)=String::from_utf8(decv)else{return Parsed{media_type:mediatype,params:None,error:Some("template MIME parameter contains unrepresentable byte string".into())};};
                params.insert(key.clone(), decv);
            }
            continue;
        }

        let mut buf = Vec::new();
        let mut valid = false;
        let mut n = 0;
        loop {
            let simple_part = format!("{}*{}", key, n);
            if let Some(v) = piece_map.get(&simple_part) {
                valid = true;
                buf.extend_from_slice(v.as_bytes());
                n += 1;
                continue;
            }

            let encoded_part = format!("{}*", simple_part);
            if let Some(v) = piece_map.get(&encoded_part) {
                valid = true;
                if n == 0 {
                    if let Some(decv) = decode_2231_enc(v) {
                        buf.extend_from_slice(&decv);
                    }
                } else {
                    if let Ok(decv) = percent_hex_unescape(v) {
                        buf.extend_from_slice(&decv);
                    }
                }
            } else {
                break;
            }
            n += 1;
        }

        if valid {
            let Ok(buf)=String::from_utf8(buf)else{return Parsed{media_type:mediatype,params:None,error:Some("template MIME parameter contains unrepresentable byte string".into())};};
            params.insert(key, buf);
        }
    }

    Parsed {
        media_type: mediatype,
        params: Some(params),
        error: None,
    }
}
