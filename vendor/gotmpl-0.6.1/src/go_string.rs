use alloc::{collections::{BTreeMap, btree_map}, sync::Arc};
use core::{borrow::Borrow, cmp::Ordering};
use crate::Value;

#[derive(Clone, Debug)]
pub struct GoBytes(Arc<[u8]>);

impl GoBytes {
    /// Constructs a GoBytes from raw bytes.
    ///
    /// Debug assertion checks that the input is NOT valid UTF-8 (if compiled in debug mode).
    /// This constructor is crate-private and intended for use when raw byte content is known
    /// to be invalid UTF-8 (i.e., a Go ByteString source).
    pub(crate) fn from_invalid(data: Arc<[u8]>) -> Self {
        debug_assert!(!data.is_empty() && core::str::from_utf8(&data).is_err(),
            "GoBytes::from_invalid expects invalid UTF-8 data in debug builds");
        Self(data)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Eq for GoBytes {}

impl PartialEq for GoBytes {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_ref() == other.0.as_ref()
    }
}

impl Ord for GoBytes {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.as_ref().cmp(other.0.as_ref())
    }
}

impl PartialOrd for GoBytes {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Borrow<[u8]> for GoBytes {
    fn borrow(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Debug)]
pub enum GoKey {
    Utf8(Arc<str>),
    Bytes(GoBytes),
}

impl GoKey {
    pub fn from_bytes(bytes:impl Into<Arc<[u8]>>)->Self{let bytes=bytes.into();match core::str::from_utf8(&bytes){Ok(text)=>Self::Utf8(Arc::from(text)),Err(_)=>Self::Bytes(GoBytes::from_invalid(bytes))}}

    pub fn len(&self)->usize{self.as_bytes().len()}
    pub fn is_empty(&self)->bool{self.as_bytes().is_empty()}
    pub fn as_str(&self)->Option<&str>{match self{Self::Utf8(value)=>Some(value),Self::Bytes(_)=>None}}

    /// Constructs a GoKey from a Value.
    /// Accepts Value::String (mapped to Utf8) and Value::ByteString (mapped to Bytes).
    /// Other variants result in a template execution error.
    pub fn from_value(v: &Value) -> crate::Result<Self> {
        match v {
            Value::String(s) => Ok(GoKey::Utf8(s.clone())),
            Value::ByteString(b) => Ok(GoKey::Bytes(b.clone())),
            _ => Err(crate::TemplateError::Exec(
                alloc::string::String::from("key type not supported"),
            )),
        }
    }

    /// Converts a GoKey into a Value.
    /// Utf8 -> Value::String, Bytes -> Value::ByteString.
    pub fn to_value(&self) -> Value {
        match self {
            GoKey::Utf8(s) => Value::String(s.clone()),
            GoKey::Bytes(b) => Value::ByteString(b.clone()),
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            GoKey::Utf8(s) => s.as_bytes(),
            GoKey::Bytes(b) => b.as_bytes(),
        }
    }
}

impl From<Arc<str>> for GoKey {
    fn from(s: Arc<str>) -> Self {
        GoKey::Utf8(s)
    }
}

impl From<alloc::string::String> for GoKey {
    fn from(s: alloc::string::String) -> Self {
        GoKey::Utf8(Arc::from(s))
    }
}

impl From<&str> for GoKey {
    fn from(s: &str) -> Self {
        GoKey::Utf8(Arc::from(s))
    }
}

impl Eq for GoKey {}

impl PartialEq for GoKey {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Ord for GoKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_bytes().cmp(other.as_bytes())
    }
}

impl PartialOrd for GoKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Borrow<[u8]> for GoKey {
    fn borrow(&self) -> &[u8] {
        self.as_bytes()
    }
}

#[derive(Clone, Debug)]
pub enum GoMapSnapshot {
    Utf8(Arc<BTreeMap<Arc<str>, Value>>),
    Keyed(Arc<BTreeMap<GoKey, Value>>),
}

impl GoMapSnapshot {
    pub fn len(&self) -> usize {
        match self {
            GoMapSnapshot::Utf8(m) => m.len(),
            GoMapSnapshot::Keyed(m) => m.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Looks up a key by its raw byte representation.
    /// For Utf8 maps, the key is interpreted as a UTF-8 string; if invalid, lookup fails (returns None).
    /// Keyed maps use borrowed byte lookup without allocating.
    pub fn get(&self, key: &[u8]) -> Option<&Value> {
        match self {
            GoMapSnapshot::Utf8(m) => {
                // Attempt to interpret bytes as valid UTF-8 string to lookup in the map
                let s = core::str::from_utf8(key).ok()?;
                m.get(s)
            }
            GoMapSnapshot::Keyed(m) => {
                m.get(key)
            }
        }
    }

    pub fn iter(&self) -> GoMapIter<'_> {
        match self {
            GoMapSnapshot::Utf8(m) => GoMapIter::Utf8(m.iter()),
            GoMapSnapshot::Keyed(m) => GoMapIter::Keyed(m.iter()),
        }
    }
}

#[derive(Clone, Debug)]
pub enum GoMapKeyRef<'a> {
    Utf8(&'a Arc<str>),
    Keyed(&'a GoKey),
}

impl<'a> GoMapKeyRef<'a> {
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            GoMapKeyRef::Utf8(s) => s.as_bytes(),
            GoMapKeyRef::Keyed(k) => k.as_bytes(),
        }
    }

    pub fn to_value(&self) -> Value {
        match self {
            GoMapKeyRef::Utf8(s) => Value::String((*s).clone()),
            GoMapKeyRef::Keyed(k) => k.to_value(),
        }
    }
}

pub enum GoMapIter<'a> {
    Utf8(btree_map::Iter<'a, Arc<str>, Value>),
    Keyed(btree_map::Iter<'a, GoKey, Value>),
}

impl<'a> Iterator for GoMapIter<'a> {
    type Item = (GoMapKeyRef<'a>, &'a Value);

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            GoMapIter::Utf8(it) => it.next().map(|(k, v)| (GoMapKeyRef::Utf8(k), v)),
            GoMapIter::Keyed(it) => it.next().map(|(k, v)| (GoMapKeyRef::Keyed(k), v)),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match self {
            GoMapIter::Utf8(it) => it.size_hint(),
            GoMapIter::Keyed(it) => it.size_hint(),
        }
    }
}

impl<'a> ExactSizeIterator for GoMapIter<'a> {
    fn len(&self) -> usize {
        match self {
            GoMapIter::Utf8(it) => it.len(),
            GoMapIter::Keyed(it) => it.len(),
        }
    }
}


/// Go's utf8.DecodeRune semantics: malformed input advances by exactly one byte.
/// A valid U+FFFD advances by three bytes and remains distinguishable by width.
pub fn decode_go_rune(bytes:&[u8])->Option<(char,usize)>{
    let first=*bytes.first()?;
    if first<0x80{return Some((char::from(first),1));}
    let width=match first{0xc2..=0xdf=>2,0xe0..=0xef=>3,0xf0..=0xf4=>4,_=>return Some(('\u{fffd}',1))};
    if let Some(part)=bytes.get(..width){if let Ok(text)=core::str::from_utf8(part){if let Some(rune)=text.chars().next(){return Some((rune,width));}}}
    Some(('\u{fffd}',1))
}
#[derive(Clone)]pub struct GoRunes<'a>{remaining:&'a[u8]}
pub fn go_runes(bytes:&[u8])->GoRunes<'_>{GoRunes{remaining:bytes}}
impl Iterator for GoRunes<'_>{type Item=(char,usize);fn next(&mut self)->Option<Self::Item>{let value=decode_go_rune(self.remaining)?;self.remaining=&self.remaining[value.1..];Some(value)}}
/// Replace each malformed byte with one U+FFFD, as Go's []rune conversion does.
/// This is only for APIs whose Go behavior decodes runes; raw output keeps bytes.
pub fn go_utf8_text(bytes:&[u8])->alloc::borrow::Cow<'_,str>{
    if let Ok(text)=core::str::from_utf8(bytes){return alloc::borrow::Cow::Borrowed(text);}
    alloc::borrow::Cow::Owned(go_runes(bytes).map(|(rune,_)|rune).collect())
}
