use std::collections::BTreeMap;
use std::sync::Arc;

use opentelemetry::Context;
use opentelemetry::propagation::text_map_propagator::FieldIter;
use opentelemetry::propagation::{Extractor, Injector, TextMapPropagator};

const HEADER_NAME: &str = "baggage";
const MAX_BYTES: usize = 8192;
const MAX_MEMBERS: usize = 64;
const LIST_DELIM: char = ',';
const PROP_DELIM: char = ';';
const KV_DELIM: char = '=';
const OT_BAGGAGE_PREFIX: &str = "ot-baggage-";

#[derive(Clone, Debug)]
pub struct Property {
    pub key: String,
    pub value: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Member {
    pub key: String,
    pub value: String,
    pub properties: Vec<Property>,
}

#[derive(Clone, Debug)]
struct Bag(Arc<BTreeMap<String, Member>>);

#[derive(Clone, Debug)]
pub struct Baggage;

impl Baggage {
    pub fn new() -> Self {
        Baggage
    }
}

impl Default for Baggage {
    fn default() -> Self {
        Self::new()
    }
}

fn is_token_char(c: char) -> bool {
    matches!(c,
        'A'..='Z' | 'a'..='z' | '0'..='9'
        | '!' | '#' | '$' | '%' | '&' | '\'' | '*' | '+' | '-' | '.'
        | '^' | '_' | '`' | '|' | '~'
    )
}

fn is_valid_key(s: &str) -> bool {
    !s.is_empty() && s.chars().all(is_token_char)
}

fn is_value_char(c: char) -> bool {
    let o = c as u32;
    if o >= 0x80 {
        return false;
    }
    let b = o as u8;
    b == 0x21
        || (0x23..=0x2b).contains(&b)
        || (0x2d..=0x3a).contains(&b)
        || (0x3c..=0x5b).contains(&b)
        || (0x5d..=0x7e).contains(&b)
}

fn is_valid_value(s: &str) -> bool {
    s.chars().all(is_value_char)
}

fn is_ows(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

fn skip_ows(s: &str, mut index: usize) -> usize {
    let bytes = s.as_bytes();
    while index < bytes.len() && is_ows(bytes[index]) {
        index += 1;
    }
    index
}

fn percent_decode(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return None;
            }
            let hi = hex_val(bytes[i + 1])?;
            let lo = hex_val(bytes[i + 2])?;
            out.push(hi << 4 | lo);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    Some(out)
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn replace_invalid_utf8(mut raw: &[u8]) -> String {
    let mut out=String::with_capacity(raw.len());
    while !raw.is_empty(){match std::str::from_utf8(raw){
        Ok(value)=>{out.push_str(value);break}
        Err(error)=>{let n=error.valid_up_to();out.push_str(std::str::from_utf8(&raw[..n]).expect("validated prefix"));out.push('\u{FFFD}');raw=&raw[n+1..];}
    }}out
}

fn parse_property(s: &str) -> Option<Property> {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return Some(Property {
            key: String::new(),
            value: None,
        });
    }
    let mut index = skip_ows(s, 0);
    let key_start = index;
    let key_end = {
        let mut e = key_start;
        for c in s[key_start..].chars() {
            if !is_token_char(c) {
                break;
            }
            e += c.len_utf8();
        }
        e
    };
    if key_start == key_end {
        return None;
    }
    index = skip_ows(s, key_end);
    if index == bytes.len() {
        return Some(Property {
            key: s[key_start..key_end].to_string(),
            value: None,
        });
    }
    if bytes[index] != b'=' {
        return None;
    }
    index = skip_ows(s, index + 1);
    let value_start = index;
    let value_end = {
        let mut e = value_start;
        for c in s[value_start..].chars() {
            if !is_value_char(c) {
                break;
            }
            e += c.len_utf8();
        }
        e
    };
    index = skip_ows(s, value_end);
    if index != bytes.len() {
        return None;
    }
    let raw_val = &s[value_start..value_end];
    let decoded = percent_decode(raw_val)?;
    let value = replace_invalid_utf8(&decoded);
    Some(Property {
        key: s[key_start..key_end].to_string(),
        value: Some(value),
    })
}

fn parse_member(member: &str) -> Option<Member> {
    let (kv_part, props_str, found_props) = match member.find(PROP_DELIM) {
        Some(pos) => (&member[..pos], &member[pos + 1..], true),
        None => (member, "", false),
    };
    let mut props: Vec<Property> = Vec::new();
    if found_props {
        for p_str in split_char(props_str, PROP_DELIM) {
            match parse_property(p_str) {
                Some(p) => props.push(p),
                None => return None,
            }
        }
    }
    let (k, v) = match kv_part.find(KV_DELIM) {
        Some(pos) => (&kv_part[..pos], &kv_part[pos + 1..]),
        None => return None,
    };
    let key = k.trim();
    if !is_valid_key(key) {
        return None;
    }
    let raw_val = v.trim();
    if !is_valid_value(raw_val) {
        return None;
    }
    let decoded = percent_decode(raw_val)?;
    let value = replace_invalid_utf8(&decoded);
    Some(Member {
        key: key.to_string(),
        value,
        properties: props,
    })
}

fn split_char(s: &str, delim: char) -> impl Iterator<Item = &str> {
    s.split(delim)
}

fn encoded_value_len(s: &str) -> usize {
    let mut n = 0;
    for b in s.bytes() {
        if b == b'%' || !is_value_char(b as char) {
            n += 3;
        } else {
            n += 1;
        }
    }
    n
}

fn escape_value(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b == b'%' || !is_value_char(b as char) {
            out.push('%');
            out.push(UPPER_HEX[(b >> 4) as usize]);
            out.push(UPPER_HEX[(b & 0xF) as usize]);
        } else {
            out.push(b as char);
        }
    }
    out
}

const UPPER_HEX: [char; 16] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F',
];

fn serialize_member(m:&Member)->String {
 let mut s=format!("{}={}",m.key,escape_value(&m.value));
 if !m.properties.is_empty(){s.push(';');let mut first=true;for p in &m.properties{
  if p.key.is_empty(){continue}if !first{s.push(';')}first=false;s.push_str(&p.key);
  if let Some(v)=&p.value{s.push('=');s.push_str(&escape_value(v));}
 }}s
}
fn insert(bag:&mut BTreeMap<String,Member>,sizes:&mut BTreeMap<String,usize>,total:&mut usize,m:Member)->bool{
 let mut size=serialize_member(&m).len();
 if !bag.contains_key(&m.key)&&!bag.is_empty(){size+=1;}
 let next=*total-sizes.get(&m.key).copied().unwrap_or(0)+size;
 if next>MAX_BYTES{return false}*total=next;sizes.insert(m.key.clone(),size);bag.insert(m.key.clone(),m);true
}
fn parse_baggage_string(raw:&str)->BTreeMap<String,Member>{
 let mut bag=BTreeMap::new();if raw.is_empty()||raw.len()>MAX_BYTES{return bag}
 let mut sizes=BTreeMap::new();let mut total=0;
 for raw in raw.split(','){if bag.len()>=MAX_MEMBERS{break}if let Some(m)=parse_member(raw){if !insert(&mut bag,&mut sizes,&mut total,m){break}}}bag
}
fn attach(cx:&Context,bag:BTreeMap<String,Member>)->Context{
 if bag.is_empty(){cx.clone()}else{cx.with_value(Bag(Arc::new(bag)))}
}
impl TextMapPropagator for Baggage{
 fn fields(&self)->FieldIter<'_>{
  static FIELDS:std::sync::OnceLock<[String;1]>=std::sync::OnceLock::new();
  FieldIter::new(FIELDS.get_or_init(||[HEADER_NAME.into()]))
 }
 fn extract_with_context(&self,cx:&Context,e:&dyn Extractor)->Context{
  e.get(HEADER_NAME).map_or_else(||cx.clone(),|raw|attach(cx,parse_baggage_string(raw)))
 }
 fn inject_context(&self,cx:&Context,i:&mut dyn Injector){
  let Some(bag)=cx.get::<Bag>()else{return};let mut output=String::new();
  for m in bag.0.values(){if !is_valid_key(&m.key){continue}if !output.is_empty(){output.push(',')}output.push_str(&serialize_member(m));}
  if !output.is_empty(){i.set(HEADER_NAME,output)}
 }
}
pub(super) fn extract_ot(cx:&Context,e:&dyn Extractor)->Context{
 let keys=e.keys();let mut raw_bytes=0usize;
 for key in &keys{
  if key.len()<OT_BAGGAGE_PREFIX.len()||!key.as_bytes()[..OT_BAGGAGE_PREFIX.len()].eq_ignore_ascii_case(OT_BAGGAGE_PREFIX.as_bytes()){continue}
  raw_bytes=raw_bytes.saturating_add(key.len()).saturating_add(e.get(key).map_or(0,str::len));if raw_bytes>MAX_BYTES{return cx.clone()}
 }
 let mut bag=BTreeMap::new();let mut sizes=BTreeMap::new();let mut total=0;
 for key in keys {
  if bag.len()>=MAX_MEMBERS{break}
  if key.len()<OT_BAGGAGE_PREFIX.len()||!key.as_bytes()[..OT_BAGGAGE_PREFIX.len()].eq_ignore_ascii_case(OT_BAGGAGE_PREFIX.as_bytes()){continue}
  let name=key[OT_BAGGAGE_PREFIX.len()..].to_ascii_lowercase();
  let raw=e.get(key).unwrap_or_default();
  if !is_valid_key(&name)||!is_valid_value(raw){continue}
  let Some(bytes)=percent_decode(raw)else{continue};
  let m=Member{key:name,value:replace_invalid_utf8(&bytes),properties:Vec::new()};
  if !insert(&mut bag,&mut sizes,&mut total,m){break}
 }attach(cx,bag)
}
pub(super) fn inject_ot(cx:&Context,i:&mut dyn Injector){
 if let Some(bag)=cx.get::<Bag>(){for m in bag.0.values(){i.set(&format!("{OT_BAGGAGE_PREFIX}{}",m.key),m.value.clone())}}
}
