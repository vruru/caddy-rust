use anyhow::{Result, anyhow, bail};
use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    os::unix::ffi::{OsStrExt, OsStringExt},
};

#[derive(Clone, Copy)]
pub enum Kind {
    Text,
    Bool,
    List,
}
#[derive(Clone, Copy)]
pub struct Flag {
    pub name: &'static str,
    pub short: Option<u8>,
    pub kind: Kind,
}
#[derive(Default)]
pub struct Flags {
    pub values: BTreeMap<&'static str, Vec<OsString>>,
    pub positional: Vec<OsString>,
}
impl Flags {
    pub fn text(&self, name: &str) -> Option<&OsStr> {
        self.values
            .get(name)
            .and_then(|v| v.last())
            .map(OsString::as_os_str)
    }
    pub fn boolean(&self, name: &str) -> bool {
        self.text(name).is_some_and(|v| v == "true")
    }
    pub fn list(&self, name: &str) -> &[OsString] {
        self.values.get(name).map_or(&[], Vec::as_slice)
    }
}
fn boolean(input: &[u8]) -> Result<OsString> {
    match input {
        b"1" | b"t" | b"T" | b"TRUE" | b"true" | b"True" => Ok("true".into()),
        b"0" | b"f" | b"F" | b"FALSE" | b"false" | b"False" => Ok("false".into()),
        _ => bail!("invalid boolean flag value"),
    }
}
/// pflag stringSlice consumes one CSV record, not whitespace-separated paths.
fn csv(input: &[u8]) -> Result<Vec<OsString>> {
    if input.is_empty() {
        return Ok(Vec::new());
    }
    let input = input.strip_suffix(b"\r").unwrap_or(input);
    let mut p = 0;
    let mut fields = Vec::new();
    // encoding/csv ignores initially empty LF/CRLF records.
    while p < input.len() {
        if input[p] == b'\n' {
            p += 1
        } else if input[p..].starts_with(b"\r\n") {
            p += 2
        } else {
            break;
        }
    }
    if p == input.len() {
        bail!("empty CSV record")
    }
    loop {
        let mut field = Vec::new();
        if input.get(p) == Some(&b'"') {
            p += 1;
            loop {
                match input.get(p) {
                    None => bail!("unterminated CSV field"),
                    Some(b'"') => {
                        p += 1;
                        if input.get(p) == Some(&b'"') {
                            field.push(b'"');
                            p += 1
                        } else {
                            break;
                        }
                    }
                    Some(b'\r') if input.get(p + 1) == Some(&b'\n') => {
                        field.push(b'\n');
                        p += 2
                    }
                    Some(&byte) => {
                        field.push(byte);
                        p += 1
                    }
                }
            }
            if input.get(p) == Some(&b'\r') && input.get(p + 1) == Some(&b'\n') {
                p += 1;
            }
            if input.get(p).is_some_and(|b| !matches!(b, b',' | b'\n')) {
                bail!("invalid CSV field suffix")
            }
        } else {
            while let Some(&byte) = input.get(p) {
                if matches!(byte, b',' | b'\n') {
                    break;
                }
                if byte == b'"' {
                    bail!("bare quote in CSV field")
                }
                field.push(byte);
                p += 1;
            }
            if input.get(p) != Some(&b',') && field.last() == Some(&b'\r') {
                field.pop();
            }
        }
        fields.push(OsString::from_vec(field));
        match input.get(p) {
            Some(b',') => p += 1,
            _ => return Ok(fields),
        }
    }
}
fn store(flags: &mut Flags, spec: Flag, raw: &[u8]) -> Result<()> {
    match spec.kind {
        Kind::Bool => {
            flags.values.insert(spec.name, vec![boolean(raw)?]);
        }
        Kind::Text => {
            flags
                .values
                .insert(spec.name, vec![OsString::from_vec(raw.to_vec())]);
        }
        Kind::List => {
            flags.values.entry(spec.name).or_default().extend(csv(raw)?);
        }
    };
    Ok(())
}
pub fn parse(input: &[OsString], specs: &[Flag]) -> Result<Flags> {
    let mut flags = Flags::default();
    let mut index = 0;
    let mut literal = false;
    while let Some(arg) = input.get(index) {
        index += 1;
        let raw = arg.as_bytes();
        if literal || !raw.starts_with(b"-") || raw == b"-" {
            flags.positional.push(arg.clone());
            continue;
        }
        if raw == b"--" {
            literal = true;
            continue;
        }
        if let Some(long) = raw.strip_prefix(b"--") {
            let equal = long.iter().position(|b| *b == b'=');
            let name = &long[..equal.unwrap_or(long.len())];
            let spec = *specs
                .iter()
                .find(|f| f.name.as_bytes() == name)
                .ok_or_else(|| anyhow!("unknown command flag"))?;
            let value = if let Some(equal) = equal {
                &long[equal + 1..]
            } else if matches!(spec.kind, Kind::Bool) {
                b"true"
            } else {
                let value = input
                    .get(index)
                    .ok_or_else(|| anyhow!("flag requires a value"))?;
                index += 1;
                value.as_bytes()
            };
            store(&mut flags, spec, value)?;
        } else {
            let mut pos = 1;
            while pos < raw.len() {
                let spec = *specs
                    .iter()
                    .find(|f| f.short == Some(raw[pos]))
                    .ok_or_else(|| anyhow!("unknown shorthand flag"))?;
                pos += 1;
                if raw.get(pos) == Some(&b'=') {
                    store(&mut flags, spec, &raw[pos + 1..])?;
                    break;
                }
                if matches!(spec.kind, Kind::Bool) {
                    store(&mut flags, spec, b"true")?;
                    continue;
                }
                let value = if pos < raw.len() {
                    &raw[pos..]
                } else {
                    let value = input
                        .get(index)
                        .ok_or_else(|| anyhow!("flag requires a value"))?;
                    index += 1;
                    value.as_bytes()
                };
                store(&mut flags, spec, value)?;
                break;
            }
        }
    }
    Ok(flags)
}
