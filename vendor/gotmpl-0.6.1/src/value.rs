//! Dynamic value system for template data.
//!
//! Go's template engine inspects arbitrary types at runtime through
//! reflection. Rust has no such reflection, so data is carried through the
//! engine as a [`Value`] enum, similar in spirit to `serde_json::Value`.
//!
//! The [`ToValue`](crate::ToValue) trait converts Rust types into [`Value`]s,
//! and the [`tmap!`](crate::tmap) macro builds data maps.
//!
//! # Examples
//!
//! ```
//! use gotmpl::{tmap, ToValue};
//!
//! let data = tmap! {
//!     "Name" => "Alice",
//!     "Age" => 30i64,
//!     "Tags" => vec!["admin".to_string(), "user".to_string()],
//! };
//! ```

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;

use crate::error::Result;

/// Alias for a callable function stored inside [`Value::Function`].
///
/// Wrapped in `Arc` so that [`Value`] remains [`Clone`].
///
/// # Examples
///
/// ```
/// use std::sync::Arc;
/// use gotmpl::{Value, ValueFunc};
///
/// let add: ValueFunc = Arc::new(|args| {
///     let sum: i64 = args.iter().filter_map(|a| a.as_int()).sum();
///     Ok(Value::Int(sum))
/// });
///
/// let result = add(&[Value::Int(2), Value::Int(3)]).unwrap();
/// assert_eq!(result, Value::Int(5));
/// ```
pub type ValueFunc = Arc<dyn Fn(&[Value]) -> Result<Value> + Send + Sync>;

/// The dynamic type for template data.
///
/// Dot, variables, function arguments, and pipeline results are all carried
/// as a `Value`. Plays the role that `reflect.Value` plays in Go's template
/// engine.
///
/// # Truthiness
///
/// [`Value::is_truthy`] follows Go's semantics:
///
/// | Value | Truthy? |
/// |-------|---------|
/// | `Nil` | `false` |
/// | `Bool(false)` | `false` |
/// | `Int(0)` | `false` |
/// | `Uint(0)` | `false` |
/// | `Float(0.0)` | `false` |
/// | `String("")` | `false` |
/// | Empty `List` or `Map` | `false` |
/// | Everything else | `true` |
///
/// # Display
///
/// The [`Display`](fmt::Display) implementation matches Go's default formatting:
/// - `Nil` → `<nil>`
/// - `List` → `[a b c]`
/// - `Map` → `map[k1:v1 k2:v2]`
/// - `Function` → `<func>`
pub enum Value {
    /// The nil value, represents absence of data.
    Nil,
    /// Nil error interface returned as a single Go method result.
    NilError,
    /// A boolean value.
    Bool(bool),
    /// A 64-bit signed integer.
    Int(i64),
    /// Go int64, distinct from the platform int for reflection.
    Int64(i64),
    NamedInt64(i64, Arc<Int64Type>),
    /// A 64-bit unsigned integer.
    ///
    /// Produced by [`ToValue`] for every unsigned Rust integer type
    /// (`u8`/`u16`/`u32`/`u64`/`usize`), mirroring Go's distinct unsigned
    /// reflect kinds. Kept separate from [`Value::Int`] so values above
    /// `i64::MAX` (e.g. `u64::MAX`) render and compare as their true unsigned
    /// value instead of wrapping to a negative `i64`.
    Uint(u64),
    Uint32(u32),
    Uint8(u8),
    Uint16(u16),
    /// A 64-bit floating-point number.
    Float(f64),
    /// A UTF-8 string.
    String(Arc<str>),
    /// Go string containing bytes which cannot be represented as UTF-8.
    ByteString(crate::GoBytes),
    /// An ordered list of values.
    ///
    /// Uses [`Arc<[Value]>`] for cheap cloning and single-allocation storage.
    List(Arc<[Value]>),
    Slice(crate::TypedSlice),
    /// A sorted string-keyed map of values.
    ///
    /// Uses [`BTreeMap`] with [`Arc<str>`] keys to ensure deterministic
    /// iteration order (matching Go's sorted map key iteration in templates)
    /// and to let `{{range}}` over a map refcount-bump the key into
    /// [`Value::String`] instead of allocating.
    Map(Arc<BTreeMap<Arc<str>, Value>>),
    #[cfg(feature = "std")]
    SharedMap(Arc<crate::MapCell>),
    #[cfg(feature="std")]
    GenericMap(Arc<crate::GenericMapCell>),
    /// A callable function value, invoked via the `call` builtin.
    ///
    /// See [`ValueFunc`] for the expected signature.
    Function(ValueFunc),
    /// Host fields and methods, distinct from a Go map.
    Object(Arc<Object>),

    /// Trusted content that bypasses context-aware escaping in its matching
    /// context. Produced by the [`html`](crate::html) module's safe-content
    /// wrappers ([`HTML`](crate::html::HTML), etc.). Available only with the
    /// `html` feature; the default build's `Value` has no such variant, so this
    /// addition is not a breaking change for `text/template` users.
    #[cfg(feature = "html")]
    #[cfg_attr(docsrs, doc(cfg(feature = "html")))]
    Safe {
        /// Which content type this string is trusted as.
        kind: SafeKind,
        /// The trusted string, emitted verbatim in its matching context.
        s: Arc<str>,
    },
}

/// The content type of a [`Value::Safe`] — the seven trusted-content kinds of
/// Go's `html/template` (`template.HTML`, `template.JS`, …). Available only with
/// the `html` feature.
#[cfg(feature = "html")]
#[cfg_attr(docsrs, doc(cfg(feature = "html")))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SafeKind {
    /// Known-safe HTML markup ([`html::HTML`](crate::html::HTML)).
    Html,
    /// A known-safe HTML attribute fragment ([`html::HTMLAttr`](crate::html::HTMLAttr)).
    HtmlAttr,
    /// Known-safe JavaScript source ([`html::JS`](crate::html::JS)).
    Js,
    /// A known-safe JavaScript string-literal body ([`html::JSStr`](crate::html::JSStr)).
    JsStr,
    /// Known-safe CSS source ([`html::CSS`](crate::html::CSS)).
    Css,
    /// A known-safe URL ([`html::URL`](crate::html::URL)).
    Url,
    /// A known-safe `srcset` value ([`html::Srcset`](crate::html::Srcset)).
    Srcset,
}

/// A named Go integer type. Host factories share this immutable descriptor.
pub type Int64Method=Arc<dyn Fn(i64,&[Value])->Result<Value>+Send+Sync>;
pub struct Int64Type {
    pub name:&'static str,
    pub kind:&'static str,
    pub stringer:Option<fn(i64)->String>,
    pub methods:BTreeMap<Arc<str>,Int64Method>,
    pub signatures:BTreeMap<Arc<str>,crate::Signature>,
}
/// An explicit host object. Unspecified fields are errors even when map keys are optional.
pub type HostMapSnapshot = Arc<dyn Fn() -> Result<crate::GoMapSnapshot> + Send + Sync>;
pub struct MapView {
    pub is_nil: Arc<dyn Fn()->bool+Send+Sync>,
    pub type_name: &'static str,
    pub snapshot: HostMapSnapshot,
    pub zero: Value,
}
#[derive(Clone)]
pub struct JsonField {pub source:&'static str,pub name:&'static str,pub omit_empty:bool}
/// Constant method metadata. No receiver or per-render state is stored here.
pub struct HostMethod {pub name:&'static str,pub invoke:fn(&Object,&[Value])->Result<Value>,pub signature:Option<&'static crate::Signature>}
pub struct HostType {pub methods:&'static[HostMethod]}
pub(crate) enum MethodRef<'a>{Dynamic(&'a ValueFunc,Option<&'a crate::Signature>),Static(&'static HostMethod)}
impl MethodRef<'_>{pub(crate) fn signature(&self)->Option<&crate::Signature>{match self{Self::Dynamic(_,signature)=>*signature,Self::Static(method)=>method.signature}}}
#[derive(Default)]
pub struct Object {
    pub fields: BTreeMap<Arc<str>, Value>,
    pub dynamic_fields:Option<Arc<dyn Fn(&str)->Result<Option<Value>>+Send+Sync>>,
    /// Lazy host fields are measured without calling accessors.
    pub lazy_fields:bool,
    /// Every materialized lazy field passes this shared host budget boundary.
    pub field_charge:Option<Arc<dyn Fn(&Value)->Result<()>+Send+Sync>>,
    pub nil_pointer:Option<Arc<dyn Fn()->bool+Send+Sync>>,
    pub methods: BTreeMap<Arc<str>, ValueFunc>,
    pub method_signatures:BTreeMap<Arc<str>,crate::Signature>,
    pub host_type:Option<&'static HostType>,
    /// Canonical identity of the underlying Go pointer. Factories which wrap
    /// one pointee repeatedly provide the same token; distinct wrappers alone
    /// are not evidence of distinct pointees. Ignored for non-pointer types.
    pub pointer_identity:Option<usize>,
    pub map_view: Option<MapView>,
    /// Go fmt.Formatter hook. The host admits allocation/work before entering
    /// this callback; output must be a Go string and includes its own padding.
    pub formatter:Option<fn(&Object,char,&crate::HostFormat)->Result<Value>>,
    pub display: Option<Arc<str>>,
    pub go_type: Option<&'static str>,
    pub field_order:Option<Arc<[Arc<str>]>>,
    pub json:Option<core::result::Result<Arc<str>,Arc<str>>>,
    /// Current host JSON representation. The host charges allocation and work
    /// before generating a Go string; serialization validates the returned JSON.
    pub json_dynamic:Option<fn(&Object)->Result<Value>>,
    pub json_fields:Option<Arc<[JsonField]>>,
    /// Immutable host state; it is never visible to template field lookup.
    pub data: Option<Arc<dyn core::any::Any + Send + Sync>>,
    /// Size charged by the host factory for the immutable opaque payload.
    pub data_bytes: usize,
    /// Go == for host structs. Pointer objects use their Arc identity.
    pub equal: Option<fn(&Object, &Object) -> bool>,
    pub key_order:Option<fn(&Object,&Object)->Result<core::cmp::Ordering>>,
    pub deep_equal:Option<fn(&Object,&Object)->bool>,
}

impl Object {
    pub(crate) fn pointer_key(&self)->Option<usize>{if self.is_nil_pointer(){None}else{Some(self.pointer_identity.unwrap_or(self as *const Self as usize))}}
    pub(crate) fn method(&self,name:&str)->Option<MethodRef<'_>>{
        if let Some(method)=self.methods.get(name){return Some(MethodRef::Dynamic(method,self.method_signatures.get(name)));}
        self.host_type.and_then(|host|host.methods.iter().find(|method|method.name==name)).map(MethodRef::Static)
    }
    pub(crate) fn validate_lazy(&self)->Result<()>{
        if self.lazy_fields&&(self.map_view.is_some()||self.json.is_some()||self.json_dynamic.is_some()||self.display.is_some()||self.nil_pointer.is_some()||self.field_charge.is_none()||self.fields.values().any(|value|!matches!(value,Value::Nil))){return Err(crate::TemplateError::Exec("invalid lazy host object".into()));}Ok(())
    }
    pub fn is_nil_pointer(&self)->bool{self.nil_pointer.as_ref().is_some_and(|is_nil|is_nil())}
    pub fn field_value(&self,name:&str)->Result<Option<Value>>{
        self.validate_lazy()?;
        if !self.fields.contains_key(name){return Ok(None);}
        if self.is_nil_pointer(){return Err(crate::error::TemplateError::Exec(format!("nil pointer evaluating {}.{name}",self.go_type.unwrap_or("host pointer"))));}
        let value=if let Some(fields)=&self.dynamic_fields{fields(name)?}else{self.fields.get(name).cloned()};
        if self.lazy_fields{if let Some(value)=&value{self.field_charge.as_ref().ok_or_else(||crate::TemplateError::Exec("lazy host value has no budget boundary".into()))?(value)?;}}
        Ok(value)
    }
    pub fn host_data<T: core::any::Any>(&self, go_type: &str) -> Option<&T> {
        if self.go_type != Some(go_type) { return None; }
        self.data.as_ref()?.downcast_ref::<T>()
    }
}

impl Clone for Value {
    fn clone(&self) -> Self {
        match self {
            Value::Nil => Value::Nil,
            Value::NilError=>Value::NilError,
            Value::Bool(b) => Value::Bool(*b),
            Value::Int(n) => Value::Int(*n),
            Value::Int64(n) => Value::Int64(*n),
            Value::NamedInt64(n,kind)=>Value::NamedInt64(*n,kind.clone()),
            Value::Uint(n) => Value::Uint(*n),
            Value::Uint32(n) => Value::Uint32(*n),
            Value::Uint8(n) => Value::Uint8(*n),
            Value::Uint16(n) => Value::Uint16(*n),
            Value::Float(f) => Value::Float(*f),
            Value::String(s) => Value::String(Arc::clone(s)),
            Value::ByteString(s)=>Value::ByteString(s.clone()),
            Value::List(v) => Value::List(Arc::clone(v)),
            Value::Slice(v)=>Value::Slice(v.clone()),
            Value::Map(m) => Value::Map(Arc::clone(m)),
            #[cfg(feature = "std")]
            Value::SharedMap(m) => Value::SharedMap(Arc::clone(m)),
            #[cfg(feature="std")] Value::GenericMap(m)=>Value::GenericMap(m.clone()),
            Value::Function(f) => Value::Function(Arc::clone(f)),
            Value::Object(object) => Value::Object(Arc::clone(object)),
            #[cfg(feature = "html")]
            Value::Safe { kind, s } => Value::Safe {
                kind: *kind,
                s: Arc::clone(s),
            },
        }
    }
}

impl fmt::Debug for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Nil => write!(f, "Nil"),
            Value::NilError=>write!(f,"NilError"),
            Value::Bool(b) => write!(f, "Bool({b:?})"),
            Value::Int(n) => write!(f, "Int({n:?})"),
            Value::Int64(n) => write!(f, "Int64({n:?})"),
            Value::NamedInt64(n,kind)=>write!(f,"{}({n})",kind.name),
            Value::Uint(n) => write!(f, "Uint({n:?})"),
            Value::Uint32(n) => write!(f, "Uint32({n:?})"),
            Value::Uint8(n) => write!(f, "Uint8({n:?})"),
            Value::Uint16(n) => write!(f, "Uint16({n:?})"),
            Value::Float(v) => write!(f, "Float({v:?})"),
            Value::String(s) => write!(f, "String({s:?})"),
            Value::ByteString(s)=>f.debug_tuple("ByteString").field(&s.as_bytes()).finish(),
            Value::List(v) => write!(f, "List({v:?})"),
            Value::Slice(v)=>write!(f,"Slice({v:?})"),
            Value::Map(m) => write!(f, "Map({m:?})"),
            #[cfg(feature = "std")]
            Value::SharedMap(_) => write!(f, "SharedMap(...)"),
            #[cfg(feature="std")] Value::GenericMap(_)=>f.write_str("GenericMap(...)"),
            Value::Function(_) => write!(f, "Function(...)"),
            Value::Object(_) => write!(f, "Object(...)"),
            #[cfg(feature = "html")]
            Value::Safe { kind, s } => write!(f, "Safe({kind:?}, {s:?})"),
        }
    }
}

impl Value {
    pub fn measured_bytes(&self,limit:usize)->Result<usize>{crate::exec::measured_values(core::slice::from_ref(self),limit)}
    pub fn from_go_bytes(bytes:impl Into<Arc<[u8]>>)->Self{
        let bytes=bytes.into();match core::str::from_utf8(&bytes){Ok(text)=>Self::String(Arc::from(text)),Err(_)=>Self::ByteString(crate::GoBytes::from_invalid(bytes))}
    }
    pub fn as_go_bytes(&self)->Option<&[u8]>{match self{Self::String(text)=>Some(text.as_bytes()),Self::ByteString(bytes)=>Some(bytes.as_bytes()),_=>None}}
    pub fn as_sequence(&self)->Option<crate::SliceRef<'_>>{match self{Self::List(v)=>Some(crate::SliceRef::List(v)),Self::Slice(s)=>Some(crate::SliceRef::Typed(s)),_=>None}}
    pub fn map_snapshot(&self)->Result<Option<crate::GoMapSnapshot>>{
        match self{
            Self::Object(object)=>{object.validate_lazy()?;object.map_view.as_ref().map(|view|(view.snapshot)()).transpose()},
            #[cfg(feature="std")] Self::SharedMap(map)=>map.snapshot_go().map(|map|Some(crate::GoMapSnapshot::Keyed(map))),
            _=>self.as_map_view().map(|map|map.map(crate::GoMapSnapshot::Utf8)),
        }
    }

    pub fn is_go_nil(&self)->bool{match self{Self::Nil|Self::NilError=>true,Self::Slice(slice)=>slice.is_nil(),#[cfg(feature="std")]Self::SharedMap(map)=>map.is_nil(),Self::Object(o)=>!o.lazy_fields&&(o.is_nil_pointer()||o.map_view.as_ref().is_some_and(|v|(v.is_nil)())),_=>false}}

    /// Obtain an O(1), immutable map view. No lock survives the call.
    pub fn as_map_view(&self) -> Result<Option<Arc<BTreeMap<Arc<str>,Value>>>> {
        match self {
            Self::Map(map)=>Ok(Some(map.clone())),
            Self::Object(object)=>{object.validate_lazy()?;match &object.map_view {
                Some(view)=>match (view.snapshot)()? {crate::GoMapSnapshot::Utf8(map)=>Ok(Some(map)),crate::GoMapSnapshot::Keyed(_)=>Err(crate::TemplateError::Exec("byte-keyed map requires map_snapshot".into()))},
                None=>Ok(None)}},
            #[cfg(feature = "std")]
            Self::SharedMap(map)=>Ok(Some(map.snapshot()?)),
            _=>Ok(None),
        }
    }

    /// Returns whether this value is "truthy" according to Go's template semantics.
    ///
    /// See the [type-level docs](Value) for the full truthiness table.
    pub fn is_truthy(&self) -> bool {
        match self {
            Value::Nil|Value::NilError => false,
            Value::Bool(b) => *b,
            Value::Int(n) | Value::Int64(n) | Value::NamedInt64(n,_) => *n != 0,
            Value::Uint(n) => *n != 0,
            Value::Uint32(n) => *n != 0,
            Value::Uint8(n) => *n != 0,
            Value::Uint16(n) => *n != 0,
            Value::Float(f) => *f != 0.0,
            Value::String(s) => !s.is_empty(),
            Value::ByteString(s)=>!s.as_bytes().is_empty(),
            Value::List(v) => !v.is_empty(),
            Value::Slice(s)=>s.len()!=0,
            Value::Map(m) => !m.is_empty(),
            #[cfg(feature = "std")]
            Value::SharedMap(m) => m.snapshot_go().is_ok_and(|m|!m.is_empty()),
            #[cfg(feature="std")] Value::GenericMap(m)=>m.snapshot().is_ok_and(|m|!m.is_empty()),
            Value::Function(_) => true,
            Value::Object(object) => if object.lazy_fields{true}else{match &object.map_view { Some(view)=>(view.snapshot)().is_ok_and(|m|!m.is_empty()),None=>!object.is_nil_pointer() }},
            #[cfg(feature = "html")]
            Value::Safe { s, .. } => !s.is_empty(),
        }
    }

    /// Look up a field by name on a [`Value::Map`].
    ///
    /// Returns `Some(&value)` when the key exists (the value may itself be
    /// [`Value::Nil`]), and `None` when the key is absent or the receiver is
    /// not a map. This lets callers distinguish "key set to nil" from
    /// "key missing", which matters for the `missingkey=error` option.
    ///
    /// In Go, the equivalent lookup uses reflection on struct fields or map
    /// keys.
    ///
    /// # Examples
    ///
    /// ```
    /// use gotmpl::tmap;
    /// use gotmpl::Value;
    ///
    /// let data = tmap! { "Name" => "Alice", "Empty" => Value::Nil };
    /// assert_eq!(data.field("Name"), Some(&Value::String("Alice".into())));
    /// assert_eq!(data.field("Empty"), Some(&Value::Nil));   // key exists
    /// assert_eq!(data.field("Missing"), None);               // key absent
    /// assert_eq!(Value::Int(1).field("x"), None);            // not a map
    /// ```
    pub fn field(&self, name: &str) -> Option<&Value> {
        match self {
            Value::Map(m) => m.get(name),
            Value::Object(o) => o.fields.get(name),
            _ => None,
        }
    }

    /// Index into a [`Value::List`] (by integer), [`Value::Map`] (by string),
    /// or [`Value::String`] (by integer, returning the raw byte).
    ///
    /// Mirrors Go's `index` builtin semantics:
    /// - **List + Int**: returns the element, or an error if out of bounds.
    /// - **Map + String**: returns the value, or [`Value::Nil`] for missing keys.
    /// - **String + Int**: returns the byte at that offset as a [`Value::Int`]
    ///   (Go indexes strings as `[]byte`; mid-codepoint offsets are valid).
    /// - **Nil + anything**: returns an error (`index of untyped nil`).
    /// - **Other combinations**: returns an error (type mismatch).
    ///
    /// # Errors
    ///
    /// Returns an error on out-of-bounds list access, indexing with an
    /// incompatible key type, or indexing a non-indexable value.
    pub fn index(&self, idx: &Value) -> Result<Value> {
        // Resolve an integer index (signed or unsigned) to a usize offset,
        // bounds-checking against `len`. A `Value::Uint` above `i64::MAX`
        // wraps to a negative `i64` here and fails the lower-bound check —
        // correct, since it can never be a valid offset.
        fn check_bounds(idx: &Value, len: usize) -> Result<usize> {
            let i = match idx {
                Value::Int(i) | Value::Int64(i) | Value::NamedInt64(i,_) => *i,
                Value::Uint(i) => *i as i64,
                Value::Uint32(i) => i64::from(*i),
                Value::Uint8(i) => i64::from(*i),
                Value::Uint16(i) => i64::from(*i),
                #[allow(
                    clippy::unreachable,
                    reason = "callers guard with a Value::Int | Value::Uint pattern"
                )]
                _ => unreachable!(),
            };
            if i < 0 || (i as usize) >= len {
                Err(crate::error::TemplateError::IndexOutOfRange { index: i })
            } else {
                Ok(i as usize)
            }
        }
        fn bad_index(kind: &str, idx: &Value) -> crate::error::TemplateError {
            crate::error::TemplateError::Exec(format!(
                "cannot index {} with type {}",
                kind,
                idx.type_name()
            ))
        }
        if let Some(bytes)=self.as_go_bytes(){
            if matches!(idx,Value::Int(_)|Value::Int64(_)|Value::NamedInt64(_,_)|Value::Uint(_)|Value::Uint32(_)|Value::Uint8(_)|Value::Uint16(_)){return Ok(Value::Uint8(bytes[check_bounds(idx,bytes.len())?]));}
            return Err(bad_index("string",idx));
        }
        #[cfg(feature="std")] if let Self::GenericMap(map)=self{return Ok(map.get(idx)?.unwrap_or(Self::Nil));}
        if let Some(map)=self.map_snapshot()?{
            let Some(key)=idx.as_go_bytes()else{return Err(bad_index("map",idx));};
            let zero=if let Self::Object(object)=self{object.map_view.as_ref().map(|view|view.zero.clone()).unwrap_or(Self::Nil)}else{Self::Nil};
            return Ok(map.get(key).cloned().unwrap_or(zero));
        }
        if let Self::Slice(s)=self {let i=check_bounds(idx,s.len())?;return s.get(i).ok_or_else(||crate::TemplateError::Exec("slice index out of range".into()));}
        match (self, idx) {
            (Value::List(v), Value::Int(_) | Value::Int64(_) | Value::NamedInt64(_,_) | Value::Uint(_) | Value::Uint32(_) | Value::Uint8(_) | Value::Uint16(_)) => {
                Ok(v[check_bounds(idx, v.len())?].clone())
            }
            (Value::List(_), _) => Err(bad_index("list", idx)),
            (Value::Map(m), Value::String(k)) => {
                Ok(m.get(k.as_ref()).cloned().unwrap_or(Value::Nil))
            }
            (Value::Map(_), _) => Err(bad_index("map", idx)),
            #[cfg(feature = "std")]
            (Value::SharedMap(m), Value::String(key)) => Ok(m.get(key)?.unwrap_or(Value::Nil)),
            #[cfg(feature = "std")]
            (Value::SharedMap(_), _) => Err(bad_index("map", idx)),
            (Value::Object(object), Value::String(key)) if object.map_view.is_some() => {
                let Some(view)=&object.map_view else { return Err(crate::TemplateError::Exec("map view absent".into())) };
                Ok((view.snapshot)()?.get(key.as_bytes()).cloned().unwrap_or_else(||view.zero.clone()))
            }
            // Go indexes strings as `[]byte` — mid-codepoint offsets are
            // valid since Go has no UTF-8 invariant. We surface the byte as
            // a `Value::Uint8` to keep that semantic without breaking ours.
            (Value::String(s), Value::Int(_) | Value::Int64(_) | Value::NamedInt64(_,_) | Value::Uint(_) | Value::Uint32(_) | Value::Uint8(_) | Value::Uint16(_)) => {
                let bytes = s.as_bytes();
                Ok(Value::Uint8(bytes[check_bounds(idx, bytes.len())?]))
            }
            (Value::String(_), _) => Err(bad_index("string", idx)),
            (Value::Nil, _) => Err(crate::error::TemplateError::Exec(
                "index of untyped nil".into(),
            )),
            _ => Err(crate::error::TemplateError::Exec(format!(
                "cannot index type {}",
                self.type_name()
            ))),
        }
    }

    /// Returns a short type name for use in error messages.
    pub fn type_name(&self) -> &'static str {
        match self {
            Value::Nil => "nil",
            Value::NilError=>"error",
            Value::Bool(_) => "bool",
            Value::Int(_) => "int",
            Value::Int64(_) => "int64",
            Value::NamedInt64(_,kind)=>kind.name,
            Value::Uint(_) => "uint64",
            Value::Uint32(_) => "uint32",
            Value::Uint8(_) => "uint8",
            Value::Uint16(_) => "uint16",
            Value::Float(_) => "float64",
            Value::String(_) | Value::ByteString(_) => "string",
            Value::List(_) => "list",
            Value::Slice(s)=>s.go_type(),
            Value::Map(_) => "map",
            #[cfg(feature = "std")]
            Value::SharedMap(_) => "map",
            #[cfg(feature="std")] Value::GenericMap(_)=>"map",
            Value::Function(_) => "func",
            Value::Object(object) => object.go_type.unwrap_or_else(||object.map_view.as_ref().map_or("object",|view|view.type_name)),
            // Safe content compares and formats as its underlying string, so it
            // reports "string" (matching Go's basicKind for template.HTML etc.).
            #[cfg(feature = "html")]
            Value::Safe { .. } => "string",
        }
    }

    /// Returns the length of a string, list, or map.
    ///
    /// Returns `None` for types that have no concept of length.
    /// Mirrors Go's `len` builtin.
    pub fn len(&self) -> Option<usize> {
        match self {
            Value::String(s) => Some(s.len()),
            Value::ByteString(s)=>Some(s.as_bytes().len()),
            Value::List(v) => Some(v.len()),
            Value::Slice(s)=>Some(s.len()),
            Value::Map(m) => Some(m.len()),
            #[cfg(feature="std")] Value::GenericMap(m)=>m.snapshot().ok().map(|m|m.len()),
            Value::Object(object) => if object.lazy_fields{None}else{object.map_view.as_ref().and_then(|view|(view.snapshot)().ok()).map(|m|m.len())},
            #[cfg(feature = "std")]
            Value::SharedMap(m) => m.snapshot_go().ok().map(|m|m.len()),
            _ => None,
        }
    }

    /// Returns `Some(true)` if the value has a length and that length is zero.
    ///
    /// Returns `None` for types that have no concept of length.
    pub fn is_empty(&self) -> Option<bool> {
        self.len().map(|n| n == 0)
    }

    /// Slice a [`Value::List`] or [`Value::String`] by byte range.
    ///
    /// Mirrors Go's `slice` builtin: `slice x`, `slice x i`, `slice x i j`.
    /// Omitted bounds default to `0` (start) and `len` (end).
    ///
    /// # Errors
    ///
    /// Returns an error if the indices are out of range, inverted, on a
    /// non-UTF-8-char boundary (strings), or the value is not sliceable.
    pub fn slice(&self, start: Option<i64>, end: Option<i64>) -> Result<Value> {
        // Resolve caller-supplied i64 bounds into usize indices in [0, len].
        // `len as i64` is lossless: Rust caps allocations at isize::MAX, which
        // fits in i64 on every supported target.
        fn resolve(
            kind: &str,
            start: Option<i64>,
            end: Option<i64>,
            len: usize,
        ) -> Result<(usize, usize)> {
            let len_i = len as i64;
            let start = start.unwrap_or(0);
            let end = end.unwrap_or(len_i);
            if start < 0 || end < 0 || start > len_i || end > len_i || start > end {
                return Err(crate::error::TemplateError::Exec(format!(
                    "slice: {kind} index out of range [{start}:{end}] with length {len}"
                )));
            }
            Ok((start as usize, end as usize))
        }
        match self {
            Value::List(v)=>{let(s,e)=resolve("slice",start,end,v.len())?;Ok(Value::Slice(crate::TypedSlice::from_list(v.clone()).reslice(s,e)?))},
            Value::Slice(v)=>{let default_end=end.unwrap_or(v.len()as i64);let(s,e)=resolve("slice",start,Some(default_end),v.cap())?;Ok(Value::Slice(v.reslice(s,e)?))},
            Value::String(_) | Value::ByteString(_) => {
                let bytes=self.as_go_bytes().ok_or_else(||crate::TemplateError::Exec("expected Go string".into()))?;
                let(start,end)=resolve("string",start,end,bytes.len())?;
                if start==0&&end==bytes.len(){return Ok(self.clone());}
                Ok(Self::from_go_bytes(Arc::<[u8]>::from(&bytes[start..end])))
            }
            _ => Err(crate::error::TemplateError::Exec(format!(
                "slice: cannot slice type {}",
                self.type_name()
            ))),
        }
    }

    /// Extracts a string slice if this is a [`Value::String`].
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }

    /// Extracts an `i64`: returned directly for a [`Value::Int`], reinterpreted
    /// from a [`Value::Uint`] (`u64 as i64`, which wraps to a negative value
    /// above `i64::MAX`), or truncated from a [`Value::Float`].
    ///
    /// The `Uint` path is lossy as a *signed value* above `i64::MAX` — only the
    /// bit pattern survives (`n as i64 as u64 == n`), not the magnitude. Anything
    /// that must see a uint's true magnitude matches [`Value::Uint`] directly
    /// instead: the `%d` / `%x` / `%X` / `%o` / `%b` / `%U` printf verbs and the
    /// index/slice paths all do. The sole remaining uint consumer here is `%c`,
    /// where a value outside the rune range is invalid regardless of sign, so the
    /// wrap is harmless (it maps to U+FFFD either way).
    pub fn as_go_integer(&self)->Option<i128>{match self{Self::NamedInt64(n,kind)if kind.kind.starts_with("uint")=>Some(i128::from(*n as u64)),Self::Int(n)|Self::Int64(n)|Self::NamedInt64(n,_)=>Some(i128::from(*n)),Self::Uint(n)=>Some(i128::from(*n)),Self::Uint32(n)=>Some(i128::from(*n)),Self::Uint8(n)=>Some(i128::from(*n)),Self::Uint16(n)=>Some(i128::from(*n)),_=>None}}
    pub fn as_go_signed(&self) -> Option<i64> {
        match self {Self::Int(n)|Self::Int64(n)=>Some(*n),Self::NamedInt64(n,kind)if !kind.kind.starts_with("uint")=>Some(*n),_=>None}
    }
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Value::Int(n) | Value::Int64(n) | Value::NamedInt64(n,_) => Some(*n),
            Value::Uint(n) => Some(*n as i64),
            Value::Uint32(n) => Some(i64::from(*n)),
            Value::Uint8(n) => Some(i64::from(*n)),
            Value::Uint16(n) => Some(i64::from(*n)),
            Value::Float(f) => Some(*f as i64),
            _ => None,
        }
    }

    /// Extracts an `f64` if this is a [`Value::Float`], or widens a
    /// [`Value::Int`] / [`Value::Uint`].
    pub fn as_float(&self) -> Option<f64> {
        match self {
            Value::Float(f) => Some(*f),
            Value::NamedInt64(n,kind)if kind.kind.starts_with("uint")=>Some((*n as u64)as f64),
            Value::Int(n) | Value::Int64(n) | Value::NamedInt64(n,_) => Some(*n as f64),
            Value::Uint(n) => Some(*n as f64),
            Value::Uint32(n) => Some(f64::from(*n)),
            Value::Uint8(n) => Some(f64::from(*n)),
            Value::Uint16(n) => Some(f64::from(*n)),
            _ => None,
        }
    }

    /// Returns `true` if this is a [`Value::Function`].
    pub fn is_function(&self) -> bool {
        matches!(self, Value::Function(_))
    }

    /// Creates a [`Value::Map`] from a fixed-size array of key-value pairs.
    ///
    /// This is the constructor used by the [`tmap!`](crate::tmap) macro.
    #[doc(hidden)]
    pub fn from_entries<const N: usize>(entries: [(String, Value); N]) -> Self {
        Value::Map(Arc::new(
            entries
                .into_iter()
                .map(|(k, v)| (Arc::from(k), v))
                .collect(),
        ))
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Nil|Value::NilError => write!(f, "<nil>"),
            Value::Bool(b) => write!(f, "{b}"),
            Value::Int(n) | Value::Int64(n) => write!(f, "{n}"),
            Value::NamedInt64(n,kind)=>if let Some(stringer)=kind.stringer{f.write_str(&stringer(*n))}else if kind.kind.starts_with("uint"){write!(f,"{}",*n as u64)}else{write!(f,"{n}")},
            Value::Uint(n) => write!(f, "{n}"),
            Value::Uint32(n) => write!(f, "{n}"),
            Value::Uint8(n) => write!(f, "{n}"),
            Value::Uint16(n) => write!(f, "{n}"),
            Value::Float(v) => f.write_str(&crate::format_float_shortest(*v)),
            Value::String(s) => write!(f, "{s}"),
            Value::ByteString(_)=>Err(fmt::Error),
            Value::Slice(v)=>{if let Some(display)=v.string_value().map_err(|_|fmt::Error)?{return write!(f,"{display}");}write!(f,"[")?;for(i,value)in v.iter().enumerate(){if i>0{write!(f," ")?;}write!(f,"{value}")?;}write!(f,"]")},
            Value::List(v) => {
                write!(f, "[")?;
                for (i, item) in v.iter().enumerate() {
                    if i > 0 {
                        write!(f, " ")?;
                    }
                    write!(f, "{item}")?;
                }
                write!(f, "]")
            }
            #[cfg(feature="std")] Value::GenericMap(map)=>{
                let map=map.snapshot().map_err(|_|fmt::Error)?;f.write_str("map[")?;
                for(i,(key,value))in map.iter().enumerate(){if i>0{f.write_str(" ")?;}write!(f,"{key}:{value}")?;}f.write_str("]")
            }
            Value::Map(m) => {
                write!(f, "map[")?;
                for (i, (k, v)) in m.iter().enumerate() {
                    if i > 0 {
                        write!(f, " ")?;
                    }
                    write!(f, "{k}:{v}")?;
                }
                write!(f, "]")
            }
            #[cfg(feature = "std")]
            Value::SharedMap(map) => {
                let map=map.snapshot().map_err(|_|fmt::Error)?;
                write!(f,"map[")?;
                for (i,(key,value)) in map.iter().enumerate() {
                    if i>0 {write!(f," ")?;}
                    write!(f,"{key}:{value}")?;
                }
                write!(f,"]")
            }
            Value::Function(_) => write!(f, "<func>"),
            Value::Object(object) => {
                if object.lazy_fields{return Err(fmt::Error);}
                if let Some(display)=&object.display { return write!(f,"{display}"); }
                if object.is_nil_pointer(){return write!(f,"<nil>");}
                if let Some(view)=&object.map_view {
                    let entries=(view.snapshot)().map_err(|_|fmt::Error)?;
                    write!(f,"map[")?;
                    for(i,(key,value))in entries.iter().enumerate(){if i>0{write!(f," ")?;}write!(f,"{}:{value}",core::str::from_utf8(key.as_bytes()).map_err(|_|fmt::Error)?)?;}
                    write!(f,"]")
                } else if let Some(order)=&object.field_order {
                    write!(f,"{{")?;for(i,name)in order.iter().enumerate(){if i>0{write!(f," ")?;}if let Some(value)=object.field_value(name).map_err(|_|fmt::Error)?{write!(f,"{value}")?;}}write!(f,"}}")
                } else { Err(fmt::Error) }
            },
            // Trusted content renders verbatim, exactly like its string.
            #[cfg(feature = "html")]
            Value::Safe { s, .. } => write!(f, "{s}"),
        }
    }
}

/// Rust-side equality for [`Value`].
///
/// Type-strict: values must have the same variant to compare equal
/// (except `Nil == Nil`).
///
/// Template builtins (`eq`, `ne`) implement Go-compatible comparison error
/// semantics separately in `funcs.rs`.
impl PartialEq for Value {
    fn eq(&self, other: &Self) -> bool {
        if let(Some(a),Some(b))=(self.as_go_bytes(),other.as_go_bytes()){return a==b;}
        match (self, other) {
            (Value::Nil, Value::Nil)|(Value::NilError,Value::NilError) => true,
            (Value::Bool(a), Value::Bool(b)) => a == b,
            (Value::NamedInt64(a,ta),Value::NamedInt64(b,tb))=>ta.name==tb.name&&a==b,
            (Value::Int(a), Value::Int(b)) | (Value::Int64(a), Value::Int64(b)) => a == b,
            (Value::Uint(a), Value::Uint(b)) => a == b,
            (Value::Uint32(a), Value::Uint32(b)) => a == b,
            (Value::Uint8(a), Value::Uint8(b)) => a == b,
            (Value::Uint16(a), Value::Uint16(b)) => a == b,
            (Value::Float(a), Value::Float(b)) => a == b,
            (Value::String(a), Value::String(b)) => a == b,
            (Value::List(a), Value::List(b)) => a == b,
            (Value::Slice(a),Value::Slice(b))=>a==b,
            (Value::Map(a), Value::Map(b)) => a == b,
            #[cfg(feature = "html")]
            (Value::Safe { kind: k1, s: a }, Value::Safe { kind: k2, s: b }) => k1 == k2 && a == b,
            _ => false,
        }
    }
}

/// Rust-side partial ordering for [`Value`].
///
/// Supports ordering for same-type numeric and string variants only:
/// [`Value::Int`], [`Value::Float`], [`Value::String`]. Every other
/// combination returns `None`.
///
/// Template builtins (`lt`, `le`, `gt`, `ge`) implement Go-compatible
/// comparison error semantics separately in `funcs.rs`.
impl PartialOrd for Value {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        match (self, other) {
            (Value::NamedInt64(a,ta),Value::NamedInt64(b,tb))if ta.name==tb.name=>if ta.kind.starts_with("uint"){(*a as u64).partial_cmp(&(*b as u64))}else{a.partial_cmp(b)},
            (Value::Int(a), Value::Int(b)) | (Value::Int64(a), Value::Int64(b)) => a.partial_cmp(b),
            (Value::Uint(a), Value::Uint(b)) => a.partial_cmp(b),
            (Value::Uint32(a), Value::Uint32(b)) => a.partial_cmp(b),
            (Value::Uint8(a), Value::Uint8(b)) => a.partial_cmp(b),
            (Value::Uint16(a), Value::Uint16(b)) => a.partial_cmp(b),
            (Value::Float(a), Value::Float(b)) => a.partial_cmp(b),
            (Value::String(a), Value::String(b)) => a.partial_cmp(b),
            #[cfg(feature = "html")]
            (Value::Safe { s: a, .. }, Value::Safe { s: b, .. }) => a.partial_cmp(b),
            _ => None,
        }
    }
}

/// Trait for converting Rust types into template [`Value`]s.
///
/// Standing in for Go's ability to pass any type to `template.Execute()`.
/// Blanket impls cover common types; implement it on your own types to pass
/// them as template data.
///
/// # Examples
///
/// ```
/// use gotmpl::{Value, ToValue};
///
/// assert_eq!(42i64.to_value(), Value::Int(42));
/// assert_eq!("hello".to_value(), Value::String("hello".into()));
/// assert_eq!(true.to_value(), Value::Bool(true));
///
/// let none: Option<i64> = None;
/// assert_eq!(none.to_value(), Value::Nil);
/// ```
pub trait ToValue {
    /// Convert this value into a template [`Value`].
    fn to_value(&self) -> Value;
}

impl ToValue for Value {
    fn to_value(&self) -> Value {
        self.clone()
    }
}

impl ToValue for bool {
    fn to_value(&self) -> Value {
        Value::Bool(*self)
    }
}

macro_rules! impl_to_value_int {
    ($($t:ty),*) => {
        $(impl ToValue for $t {
            fn to_value(&self) -> Value {
                Value::Int(*self as i64)
            }
        })*
    };
}

macro_rules! impl_to_value_uint {
    ($($t:ty),*) => {
        $(impl ToValue for $t {
            fn to_value(&self) -> Value {
                Value::Uint(*self as u64)
            }
        })*
    };
}

// Signed integers map to `Value::Int`; unsigned integers map to `Value::Uint`,
// mirroring Go's distinct signed/unsigned reflect kinds. Keeping the unsigned
// family in `Value::Uint` is what lets `u64::MAX` render and compare as its
// true value instead of wrapping to `Value::Int(-1)`.
impl_to_value_int!(i8, i16, i32, i64, isize);
impl_to_value_uint!(u32, u64, usize);

impl ToValue for u8 {
    fn to_value(&self) -> Value {
        Value::Uint8(*self)
    }
}

impl ToValue for u16 {
    fn to_value(&self) -> Value {
        Value::Uint16(*self)
    }
}

impl ToValue for f32 {
    fn to_value(&self) -> Value {
        Value::Float(*self as f64)
    }
}

impl ToValue for f64 {
    fn to_value(&self) -> Value {
        Value::Float(*self)
    }
}

impl ToValue for str {
    fn to_value(&self) -> Value {
        Value::String(Arc::from(self))
    }
}

impl ToValue for String {
    fn to_value(&self) -> Value {
        Value::String(Arc::from(self.as_str()))
    }
}

impl ToValue for alloc::borrow::Cow<'_, str> {
    fn to_value(&self) -> Value {
        Value::String(Arc::from(self.as_ref()))
    }
}

impl<T: ToValue + ?Sized> ToValue for &T {
    fn to_value(&self) -> Value {
        (*self).to_value()
    }
}

/// Converts `Some(v)` to `v.to_value()` and `None` to [`Value::Nil`].
impl<T: ToValue> ToValue for Option<T> {
    fn to_value(&self) -> Value {
        match self {
            Some(v) => v.to_value(),
            None => Value::Nil,
        }
    }
}

fn list_from_iter<'a, T: ToValue + 'a, I: IntoIterator<Item = &'a T>>(iter: I) -> Value {
    Value::List(
        iter.into_iter()
            .map(ToValue::to_value)
            .collect::<Vec<_>>()
            .into(),
    )
}

fn map_from_iter_str<'a, T: ToValue + 'a, I: IntoIterator<Item = (&'a str, &'a T)>>(
    iter: I,
) -> Value {
    Value::Map(Arc::new(
        iter.into_iter()
            .map(|(k, v)| (Arc::from(k), v.to_value()))
            .collect(),
    ))
}

impl<T: ToValue> ToValue for [T] {
    fn to_value(&self) -> Value {
        list_from_iter(self.iter())
    }
}

impl<T: ToValue, const N: usize> ToValue for [T; N] {
    fn to_value(&self) -> Value {
        list_from_iter(self.iter())
    }
}

impl<T: ToValue> ToValue for Vec<T> {
    fn to_value(&self) -> Value {
        list_from_iter(self.iter())
    }
}

impl<T: ToValue> ToValue for alloc::collections::VecDeque<T> {
    fn to_value(&self) -> Value {
        list_from_iter(self.iter())
    }
}

impl<T: ToValue> ToValue for alloc::collections::LinkedList<T> {
    fn to_value(&self) -> Value {
        list_from_iter(self.iter())
    }
}

impl<T: ToValue> ToValue for alloc::collections::BTreeSet<T> {
    fn to_value(&self) -> Value {
        list_from_iter(self.iter())
    }
}

#[cfg(feature = "std")]
impl<T: ToValue> ToValue for std::collections::HashSet<T> {
    fn to_value(&self) -> Value {
        // Collect and sort for deterministic output.
        let mut items: Vec<Value> = self.iter().map(ToValue::to_value).collect();
        items.sort_by(|a, b| a.partial_cmp(b).unwrap_or(core::cmp::Ordering::Equal));
        Value::List(items.into())
    }
}

impl<T: ToValue> ToValue for BTreeMap<String, T> {
    fn to_value(&self) -> Value {
        map_from_iter_str(self.iter().map(|(k, v)| (k.as_str(), v)))
    }
}

impl<T: ToValue> ToValue for BTreeMap<&str, T> {
    fn to_value(&self) -> Value {
        map_from_iter_str(self.iter().map(|(k, v)| (*k, v)))
    }
}

#[cfg(feature = "std")]
impl<T: ToValue> ToValue for std::collections::HashMap<String, T> {
    fn to_value(&self) -> Value {
        map_from_iter_str(self.iter().map(|(k, v)| (k.as_str(), v)))
    }
}

#[cfg(feature = "std")]
impl<T: ToValue> ToValue for std::collections::HashMap<&str, T> {
    fn to_value(&self) -> Value {
        map_from_iter_str(self.iter().map(|(k, v)| (*k, v)))
    }
}

impl From<&str> for Value {
    fn from(s: &str) -> Self {
        Value::String(Arc::from(s))
    }
}

impl From<String> for Value {
    fn from(s: String) -> Self {
        Value::String(Arc::from(s))
    }
}

impl From<BTreeMap<String, Value>> for Value {
    fn from(m: BTreeMap<String, Value>) -> Self {
        Value::Map(Arc::new(
            m.into_iter().map(|(k, v)| (Arc::from(k), v)).collect(),
        ))
    }
}

impl From<BTreeMap<Arc<str>, Value>> for Value {
    fn from(m: BTreeMap<Arc<str>, Value>) -> Self {
        Value::Map(Arc::new(m))
    }
}

impl From<Vec<Value>> for Value {
    fn from(v: Vec<Value>) -> Self {
        Value::List(v.into())
    }
}

impl From<Arc<str>> for Value {
    fn from(s: Arc<str>) -> Self {
        Value::String(s)
    }
}

impl From<Arc<[Value]>> for Value {
    fn from(v: Arc<[Value]>) -> Self {
        Value::List(v)
    }
}

impl From<Arc<BTreeMap<Arc<str>, Value>>> for Value {
    fn from(m: Arc<BTreeMap<Arc<str>, Value>>) -> Self {
        Value::Map(m)
    }
}

/// Converts a [`std::collections::HashMap<String, Value>`] into a [`Value::Map`].
///
/// Useful when data is already in a `HashMap` and should be passed to a
/// template without first converting to `BTreeMap`.
///
/// # Examples
///
/// ```
/// use std::collections::HashMap;
/// use gotmpl::Value;
///
/// let mut hm = HashMap::new();
/// hm.insert("key".to_string(), Value::Int(42));
/// let val = Value::from(hm);
/// assert!(matches!(val, Value::Map(_)));
/// ```
#[cfg(feature = "std")]
impl From<std::collections::HashMap<String, Value>> for Value {
    fn from(m: std::collections::HashMap<String, Value>) -> Self {
        Value::Map(Arc::new(
            m.into_iter().map(|(k, v)| (Arc::from(k), v)).collect(),
        ))
    }
}

/// Creates a [`Value::Map`] from key-value pairs, similar to Go's map literals.
///
/// Keys are converted to strings via `.to_string()`, and values are converted
/// via [`ToValue::to_value`].
///
/// # Examples
///
/// ```
/// use gotmpl::{tmap, ToValue};
/// use gotmpl::Value;
///
/// let data = tmap! {
///     "name" => "Alice",
///     "age" => 30i64,
///     "scores" => vec![95i64, 87, 92],
///     "address" => tmap! { "city" => "Paris" },
/// };
///
/// assert!(matches!(data, Value::Map(_)));
/// ```
#[macro_export]
macro_rules! tmap {
    () => {
        $crate::Value::from_entries([])
    };
    ($($key:expr => $val:expr),+ $(,)?) => {
        $crate::Value::from_entries([
            $(($key.to_string(), $crate::ToValue::to_value(&$val)),)+
        ])
    };
}
