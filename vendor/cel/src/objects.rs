use crate::common::ast::{operators, ComprehensionExpr, EntryExpr, Expr};
use crate::common::types::bool::Bool;
use crate::common::types::map;
use crate::common::types::optional::{unwrap_optional, Unwrapped};
use crate::common::types::*;
use crate::common::value::{BuiltinRef, CowVal, FromVal, StaticVal, Val};
use crate::context::Context;
use crate::{ExecutionError, Expression, FunctionContext};
#[cfg(feature = "chrono")]
use chrono::TimeZone;
use std::any::Any;
use std::borrow::Borrow;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::convert::{Infallible, TryFrom, TryInto};
use std::fmt::{Debug, Display, Formatter};
use std::ops;
use std::ops::Deref;
use std::sync::Arc;
#[cfg(feature = "chrono")]
use std::sync::LazyLock;

/// Timestamp values are limited to the range of values which can be serialized as a string:
/// `["0001-01-01T00:00:00Z", "9999-12-31T23:59:59.999999999Z"]`. Since the max is a smaller
/// and the min is a larger timestamp than what is possible to represent with
/// [`chrono::DateTime`], we need to perform our own spec-compliant overflow checks.
///
/// <https://github.com/google/cel-spec/blob/master/doc/langdef.md#overflow>
#[cfg(feature = "chrono")]
static MAX_TIMESTAMP: LazyLock<chrono::DateTime<chrono::FixedOffset>> = LazyLock::new(|| {
    let naive = chrono::NaiveDate::from_ymd_opt(9999, 12, 31)
        .unwrap()
        .and_hms_nano_opt(23, 59, 59, 999_999_999)
        .unwrap();
    chrono::FixedOffset::east_opt(0)
        .unwrap()
        .from_utc_datetime(&naive)
});

#[cfg(feature = "chrono")]
static MIN_TIMESTAMP: LazyLock<chrono::DateTime<chrono::FixedOffset>> = LazyLock::new(|| {
    let naive = chrono::NaiveDate::from_ymd_opt(1, 1, 1)
        .unwrap()
        .and_hms_opt(0, 0, 0)
        .unwrap();
    chrono::FixedOffset::east_opt(0)
        .unwrap()
        .from_utc_datetime(&naive)
});

#[derive(Debug, PartialEq, Clone)]
pub struct Map {
    pub map: Arc<HashMap<Key, Value>>,
}

impl PartialOrd for Map {
    fn partial_cmp(&self, _: &Self) -> Option<Ordering> {
        None
    }
}

impl Map {
    /// Returns a reference to the value corresponding to the key. Implicitly converts between int
    /// and uint keys.
    pub fn get(&self, key: &(dyn AsKeyRef + '_)) -> Option<&Value> {
        self.map.get(key).or_else(|| {
            // Also check keys that are cross type comparable.
            let keyref = key.as_keyref();
            match keyref {
                KeyRef::Int(k) => {
                    let converted = u64::try_from(k).ok()?;
                    self.map.get(&Key::Uint(converted))
                }
                KeyRef::Uint(k) => {
                    let converted = i64::try_from(k).ok()?;
                    self.map.get(&Key::Int(converted))
                }
                _ => None,
            }
        })
    }
}

#[derive(Debug, Eq, PartialEq, Hash, Ord, Clone, PartialOrd)]
pub enum Key {
    Int(i64),
    Uint(u64),
    Bool(bool),
    String(Arc<String>),
}

impl From<CelMapKey<'_>> for Key {
    fn from(value: CelMapKey<'_>) -> Self {
        match value {
            CelMapKey::Bool(b) => b.into_inner().into(),
            CelMapKey::Int(i) => i.into_inner().into(),
            CelMapKey::String(s) => s.into_inner().into(),
            CelMapKey::UInt(u) => u.into_inner().into(),
        }
    }
}

impl From<Key> for CelMapKey<'_> {
    fn from(key: Key) -> Self {
        match key {
            Key::Int(i) => CelMapKey::from(i),
            Key::Uint(u) => CelMapKey::from(u),
            Key::Bool(b) => CelMapKey::from(b),
            Key::String(s) => CelMapKey::from(Arc::unwrap_or_clone(s)),
        }
    }
}

/// A borrowed version of [`Key`] that avoids allocating for lookups.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum KeyRef<'a> {
    Int(i64),
    Uint(u64),
    Bool(bool),
    String(&'a str),
}

/// Trait for converting to a borrowed [`KeyRef`] for efficient lookups.
pub trait AsKeyRef {
    fn as_keyref(&self) -> KeyRef<'_>;
}

impl AsKeyRef for Key {
    fn as_keyref(&self) -> KeyRef<'_> {
        match self {
            Key::Int(i) => KeyRef::Int(*i),
            Key::Uint(u) => KeyRef::Uint(*u),
            Key::Bool(b) => KeyRef::Bool(*b),
            Key::String(s) => KeyRef::String(s.as_str()),
        }
    }
}

impl<'a> AsKeyRef for KeyRef<'a> {
    fn as_keyref(&self) -> KeyRef<'a> {
        *self
    }
}

/// Trait object implementations for `dyn AsKeyRef` to enable hashing and comparison.
impl<'a> PartialEq for dyn AsKeyRef + 'a {
    fn eq(&self, other: &Self) -> bool {
        self.as_keyref().eq(&other.as_keyref())
    }
}

impl<'a> Eq for dyn AsKeyRef + 'a {}

impl<'a> std::hash::Hash for dyn AsKeyRef + 'a {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.as_keyref().hash(state)
    }
}

impl<'a> PartialOrd for dyn AsKeyRef + 'a {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<'a> Ord for dyn AsKeyRef + 'a {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_keyref().cmp(&other.as_keyref())
    }
}

/// Implement `Borrow<dyn AsKeyRef>` for `Key` to enable efficient lookups.
impl<'a> Borrow<dyn AsKeyRef + 'a> for Key {
    fn borrow(&self) -> &(dyn AsKeyRef + 'a) {
        self
    }
}

/// Implement conversions from primitive types to [`Key`]
impl From<String> for Key {
    fn from(v: String) -> Self {
        Key::String(v.into())
    }
}

impl From<Arc<String>> for Key {
    fn from(v: Arc<String>) -> Self {
        Key::String(v)
    }
}

impl<'a> From<&'a str> for Key {
    fn from(v: &'a str) -> Self {
        Key::String(Arc::new(v.into()))
    }
}

impl From<bool> for Key {
    fn from(v: bool) -> Self {
        Key::Bool(v)
    }
}

impl From<i64> for Key {
    fn from(v: i64) -> Self {
        Key::Int(v)
    }
}

impl From<i32> for Key {
    fn from(v: i32) -> Self {
        Key::Int(v as i64)
    }
}

impl From<u64> for Key {
    fn from(v: u64) -> Self {
        Key::Uint(v)
    }
}

impl From<u32> for Key {
    fn from(v: u32) -> Self {
        Key::Uint(v as u64)
    }
}

impl serde::Serialize for Key {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Key::Int(v) => v.serialize(serializer),
            Key::Uint(v) => v.serialize(serializer),
            Key::Bool(v) => v.serialize(serializer),
            Key::String(v) => v.serialize(serializer),
        }
    }
}

impl Display for Key {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Key::Int(v) => write!(f, "{v}"),
            Key::Uint(v) => write!(f, "{v}"),
            Key::Bool(v) => write!(f, "{v}"),
            Key::String(v) => write!(f, "{v}"),
        }
    }
}

/// Implement conversions from [`Key`] into [`Value`]
impl TryInto<Key> for Value {
    type Error = Value;

    #[inline(always)]
    fn try_into(self) -> Result<Key, Self::Error> {
        match self {
            Value::Int(v) => Ok(Key::Int(v)),
            Value::UInt(v) => Ok(Key::Uint(v)),
            Value::String(v) => Ok(Key::String(v)),
            Value::Bool(v) => Ok(Key::Bool(v)),
            _ => Err(self),
        }
    }
}

/// Implement conversions from [`KeyRef`] into [`Value`]
impl<'a> TryFrom<&'a Value> for KeyRef<'a> {
    type Error = Value;

    fn try_from(value: &'a Value) -> Result<Self, Self::Error> {
        match value {
            Value::Int(v) => Ok(KeyRef::Int(*v)),
            Value::UInt(v) => Ok(KeyRef::Uint(*v)),
            Value::String(v) => Ok(KeyRef::String(v.as_str())),
            Value::Bool(v) => Ok(KeyRef::Bool(*v)),
            _ => Err(value.clone()),
        }
    }
}

// Implement conversion from HashMap<K, V> into CelMap
impl<K: Into<Key>, V: Into<Value>> From<HashMap<K, V>> for Map {
    fn from(map: HashMap<K, V>) -> Self {
        let mut new_map = HashMap::with_capacity(map.len());
        for (k, v) in map {
            new_map.insert(k.into(), v.into());
        }
        Map {
            map: Arc::new(new_map),
        }
    }
}

/// Equality helper for [`Opaque`] values.
///
/// Implementors define how two values of the same runtime type compare for
/// equality when stored as [`Value::Opaque`].
///
/// You normally don't implement this trait manually. It is automatically
/// provided for any `T: Eq + PartialEq + Any + Opaque` (see the blanket impl
/// below). The runtime will first ensure the two values have the same
/// [`Opaque::runtime_type_name`], and only then attempt a downcast and call
/// `Eq::eq`.
pub trait OpaqueEq {
    /// Compare with another [`Opaque`] erased value.
    ///
    /// Implementations should return `false` if `other` does not have the same
    /// runtime type, or if it cannot be downcast to the concrete type of `self`.
    fn opaque_eq(&self, other: &dyn Opaque) -> bool;
}

impl<T> OpaqueEq for T
where
    T: Eq + PartialEq + Any + Opaque,
{
    fn opaque_eq(&self, other: &dyn Opaque) -> bool {
        if self.runtime_type_name() != other.runtime_type_name() {
            return false;
        }
        if let Some(other) = other.downcast_ref::<T>() {
            self.eq(other)
        } else {
            false
        }
    }
}

/// Helper trait to obtain a `&dyn Debug` view.
///
/// This is auto-implemented for any `T: Debug` and is used by the runtime to
/// format [`Opaque`] values without knowing their concrete type.
pub trait AsDebug {
    /// Returns `self` as a `&dyn Debug` trait object.
    fn as_debug(&self) -> &dyn Debug;
}

impl<T> AsDebug for T
where
    T: Debug,
{
    fn as_debug(&self) -> &dyn Debug {
        self
    }
}

/// Trait for user-defined opaque values stored inside [`Value::Opaque`].
///
/// Implement this trait for types that should participate in CEL evaluation as
/// opaque/user-defined values. An opaque value:
/// - must report a stable runtime type name via [`Opaque::runtime_type_name`];
/// - participates in equality via the blanket [`OpaqueEq`] implementation;
/// - can be formatted via [`AsDebug`];
/// - must be thread-safe (`Send + Sync`).
///
/// When the `json` feature is enabled you may optionally provide a JSON
/// representation for diagnostics, logging or interop. Returning `None` keeps the
/// value non-serializable for JSON.
///
/// Example
/// ```rust
/// use std::fmt::{Debug, Formatter, Result as FmtResult};
/// use std::sync::Arc;
/// use cel::common::types::Type;
/// use cel::objects::{Opaque, Value};
/// use cel::{Context, Env};
///
/// #[derive(Eq, PartialEq)]
/// struct MyId(u64);
///
/// impl Debug for MyId {
///     fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult { write!(f, "MyId({})", self.0) }
/// }
///
/// impl Opaque for MyId {
///     fn runtime_type_name(&self) -> &str { "example.MyId" }
/// }
///
/// // Values of `MyId` can now be wrapped in `Value::Opaque` and compared.
/// let a = Value::Opaque(Arc::new(MyId(7)));
/// let b = Value::Opaque(Arc::new(MyId(7)));
/// assert_eq!(a, b);
///
/// // Registering its type lets expressions name it.
/// let mut env = Env::stdlib();
/// env.add_type(Type::new_opaque_type("example.MyId")).unwrap();
/// let program = env.compile("type(id) == example.MyId").unwrap();
/// let mut context = Context::with_env(Arc::new(env));
/// context.add_variable_from_value("id", a);
///
/// assert_eq!(program.execute(&context), Ok(Value::Bool(true)));
/// ```
pub trait Opaque: Any + OpaqueEq + AsDebug + Send + Sync {
    /// Returns a stable, fully-qualified type name for this value's runtime type.
    ///
    /// This name is used to check type compatibility before attempting downcasts
    /// during equality checks and other operations. It should be stable across
    /// versions and unique within your application or library (e.g., a package
    /// qualified name like `my.pkg.Type`).
    fn runtime_type_name(&self) -> &str;

    /// Optional JSON representation (requires the `json` feature).
    ///
    /// The default implementation returns `None`, indicating that the value
    /// cannot be represented as JSON.
    #[cfg(feature = "json")]
    fn json(&self) -> Option<serde_json::Value> {
        None
    }
}

impl dyn Opaque {
    pub fn downcast_ref<T: Any>(&self) -> Option<&T> {
        let any: &dyn Any = self;
        any.downcast_ref()
    }
}

struct OpaqueVal {
    r#type: Type,
    val: Arc<dyn Opaque>,
}

impl Debug for OpaqueVal {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "OpaqueVal<{}>", self.val.runtime_type_name())
    }
}

impl Val for OpaqueVal {
    fn get_type(&self) -> &Type {
        &self.r#type
    }

    /// `OpaqueVal`'s runtime type is per-instance - the opaque type name is part of
    /// the value - so there is no single static `Type` to return, and it
    /// cannot be named in the overload-registration macros. Use
    /// [`get_type`](Val::get_type) on a value instead.
    fn cel_type() -> &'static Type {
        panic!("`OpaqueVal` has no static `Val::cel_type()`: its type varies per value")
    }

    fn equals(&self, other: &dyn Val) -> bool {
        if other.get_type() != self.get_type() {
            false
        } else {
            match other.downcast_ref::<OpaqueVal>() {
                None => false,
                Some(other) => self.val.opaque_eq(other.val.deref()),
            }
        }
    }

    fn clone_as_boxed<'v>(&self) -> Box<dyn Val + 'v>
    where
        Self: 'v,
    {
        Box::new(Self {
            r#type: Type::new_opaque_type(self.val.runtime_type_name().to_owned()),
            val: self.val.clone(),
        })
    }

    fn as_any(&self) -> Option<&dyn Any> {
        Some(self)
    }
}

impl StaticVal for OpaqueVal {}

impl OpaqueVal {
    fn new(val: Arc<dyn Opaque>) -> Self {
        Self {
            r#type: Type::new_opaque_type(val.runtime_type_name().to_owned()),
            val,
        }
    }

    fn clone_inner(&self) -> Arc<dyn Opaque> {
        self.val.clone()
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct OptionalValue {
    value: Option<Value>,
}

impl OptionalValue {
    pub fn of(value: Value) -> Self {
        OptionalValue { value: Some(value) }
    }
    pub fn none() -> Self {
        OptionalValue { value: None }
    }
    pub fn value(&self) -> Option<&Value> {
        self.value.as_ref()
    }

    pub(crate) fn inner(&self) -> Option<&Value> {
        self.value.as_ref()
    }
}

impl Opaque for OptionalValue {
    fn runtime_type_name(&self) -> &str {
        "optional_type"
    }
}

impl From<OptionalValue> for Option<Value> {
    fn from(value: OptionalValue) -> Self {
        value.value
    }
}

impl<'a> TryFrom<&'a Value> for &'a OptionalValue {
    type Error = ExecutionError;

    fn try_from(value: &'a Value) -> Result<Self, Self::Error> {
        match value {
            Value::Opaque(opaque) if opaque.runtime_type_name() == "optional_type" => opaque
                .downcast_ref::<OptionalValue>()
                .ok_or_else(|| ExecutionError::function_error("optional", "failed to downcast")),
            Value::Opaque(opaque) => Err(ExecutionError::UnexpectedType {
                got: opaque.runtime_type_name().to_string(),
                want: "optional_type".to_string(),
            }),
            v => Err(ExecutionError::UnexpectedType {
                got: v.type_of().to_string(),
                want: "optional_type".to_string(),
            }),
        }
    }
}

pub trait TryIntoValue {
    type Error: std::error::Error + 'static + Send + Sync;
    fn try_into_value(self) -> Result<Value, Self::Error>;
}

impl<T: serde::Serialize> TryIntoValue for T {
    type Error = crate::ser::SerializationError;
    fn try_into_value(self) -> Result<Value, Self::Error> {
        crate::ser::to_value(self)
    }
}
impl TryIntoValue for Value {
    type Error = Infallible;
    fn try_into_value(self) -> Result<Value, Self::Error> {
        Ok(self)
    }
}

#[derive(Clone)]
pub enum Value {
    List(Arc<Vec<Value>>),
    Map(Map),

    Function(Arc<String>, Option<Box<Value>>),

    // Atoms
    Int(i64),
    UInt(u64),
    Float(f64),
    String(Arc<String>),
    Bytes(Arc<Vec<u8>>),
    Bool(bool),
    #[cfg(feature = "chrono")]
    Duration(chrono::Duration),
    #[cfg(feature = "chrono")]
    Timestamp(chrono::DateTime<chrono::FixedOffset>),
    Opaque(Arc<dyn Opaque>),
    Struct(Arc<CelStruct<'static>>),
    Null,
}

impl Debug for Value {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Value::List(l) => write!(f, "List({:?})", l),
            Value::Map(m) => write!(f, "Map({:?})", m),
            Value::Function(name, func) => write!(f, "Function({:?}, {:?})", name, func),
            Value::Int(i) => write!(f, "Int({:?})", i),
            Value::UInt(u) => write!(f, "UInt({:?})", u),
            Value::Float(d) => write!(f, "Float({:?})", d),
            Value::String(s) => write!(f, "String({:?})", s),
            Value::Bytes(b) => write!(f, "Bytes({:?})", b),
            Value::Bool(b) => write!(f, "Bool({:?})", b),
            #[cfg(feature = "chrono")]
            Value::Duration(d) => write!(f, "Duration({:?})", d),
            #[cfg(feature = "chrono")]
            Value::Timestamp(t) => write!(f, "Timestamp({:?})", t),
            Value::Opaque(o) => write!(f, "Opaque<{}>({:?})", o.runtime_type_name(), o.as_debug()),
            Value::Null => write!(f, "Null"),
            Value::Struct(s) => write!(f, "{} {{}}", s.name()),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum ValueType {
    List,
    Map,
    Function,
    Int,
    UInt,
    Float,
    String,
    Bytes,
    Bool,
    Duration,
    Timestamp,
    Opaque,
    Null,
    Struct,
}

impl Display for ValueType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ValueType::List => write!(f, "list"),
            ValueType::Map => write!(f, "map"),
            ValueType::Function => write!(f, "function"),
            ValueType::Int => write!(f, "int"),
            ValueType::UInt => write!(f, "uint"),
            ValueType::Float => write!(f, "float"),
            ValueType::String => write!(f, "string"),
            ValueType::Bytes => write!(f, "bytes"),
            ValueType::Bool => write!(f, "bool"),
            ValueType::Opaque => write!(f, "opaque"),
            ValueType::Duration => write!(f, "duration"),
            ValueType::Timestamp => write!(f, "timestamp"),
            ValueType::Null => write!(f, "null"),
            ValueType::Struct => write!(f, "struct"),
        }
    }
}

impl Value {
    pub fn type_of(&self) -> ValueType {
        match self {
            Value::List(_) => ValueType::List,
            Value::Map(_) => ValueType::Map,
            Value::Function(_, _) => ValueType::Function,
            Value::Int(_) => ValueType::Int,
            Value::UInt(_) => ValueType::UInt,
            Value::Float(_) => ValueType::Float,
            Value::String(_) => ValueType::String,
            Value::Bytes(_) => ValueType::Bytes,
            Value::Bool(_) => ValueType::Bool,
            Value::Opaque(_) => ValueType::Opaque,
            #[cfg(feature = "chrono")]
            Value::Duration(_) => ValueType::Duration,
            #[cfg(feature = "chrono")]
            Value::Timestamp(_) => ValueType::Timestamp,
            Value::Null => ValueType::Null,
            Value::Struct(_) => ValueType::Struct,
        }
    }

    pub fn is_zero(&self) -> bool {
        match self {
            Value::List(v) => v.is_empty(),
            Value::Map(v) => v.map.is_empty(),
            Value::Int(0) => true,
            Value::UInt(0) => true,
            Value::Float(f) => *f == 0.0,
            Value::String(v) => v.is_empty(),
            Value::Bytes(v) => v.is_empty(),
            Value::Bool(false) => true,
            #[cfg(feature = "chrono")]
            Value::Duration(v) => v.is_zero(),
            Value::Null => true,
            _ => false,
        }
    }

    pub fn error_expected_type(&self, expected: ValueType) -> ExecutionError {
        ExecutionError::UnexpectedType {
            got: self.type_of().to_string(),
            want: expected.to_string(),
        }
    }
}

impl From<&Value> for Value {
    fn from(value: &Value) -> Self {
        value.clone()
    }
}

impl PartialEq for Value {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Value::Map(a), Value::Map(b)) => a == b,
            (Value::List(a), Value::List(b)) => a == b,
            (Value::Function(a1, a2), Value::Function(b1, b2)) => a1 == b1 && a2 == b2,
            (Value::Int(a), Value::Int(b)) => a == b,
            (Value::UInt(a), Value::UInt(b)) => a == b,
            (Value::Float(a), Value::Float(b)) => a == b,
            (Value::String(a), Value::String(b)) => a == b,
            (Value::Bytes(a), Value::Bytes(b)) => a == b,
            (Value::Bool(a), Value::Bool(b)) => a == b,
            (Value::Null, Value::Null) => true,
            #[cfg(feature = "chrono")]
            (Value::Duration(a), Value::Duration(b)) => a == b,
            #[cfg(feature = "chrono")]
            (Value::Timestamp(a), Value::Timestamp(b)) => a == b,
            // Allow different numeric types to be compared without explicit casting.
            (Value::Int(a), Value::UInt(b)) => a
                .to_owned()
                .try_into()
                .map(|a: u64| a == *b)
                .unwrap_or(false),
            (Value::Int(a), Value::Float(b)) => (*a as f64) == *b,
            (Value::UInt(a), Value::Int(b)) => a
                .to_owned()
                .try_into()
                .map(|a: i64| a == *b)
                .unwrap_or(false),
            (Value::UInt(a), Value::Float(b)) => (*a as f64) == *b,
            (Value::Float(a), Value::Int(b)) => *a == (*b as f64),
            (Value::Float(a), Value::UInt(b)) => *a == (*b as f64),
            (Value::Opaque(a), Value::Opaque(b)) => a.opaque_eq(b.deref()),
            (_, _) => false,
        }
    }
}

impl Eq for Value {}

impl PartialOrd for Value {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match (self, other) {
            (Value::Int(a), Value::Int(b)) => Some(a.cmp(b)),
            (Value::UInt(a), Value::UInt(b)) => Some(a.cmp(b)),
            (Value::Float(a), Value::Float(b)) => a.partial_cmp(b),
            (Value::String(a), Value::String(b)) => Some(a.cmp(b)),
            (Value::Bool(a), Value::Bool(b)) => Some(a.cmp(b)),
            (Value::Null, Value::Null) => Some(Ordering::Equal),
            #[cfg(feature = "chrono")]
            (Value::Duration(a), Value::Duration(b)) => Some(a.cmp(b)),
            #[cfg(feature = "chrono")]
            (Value::Timestamp(a), Value::Timestamp(b)) => Some(a.cmp(b)),
            // Allow different numeric types to be compared without explicit casting.
            (Value::Int(a), Value::UInt(b)) => Some(
                a.to_owned()
                    .try_into()
                    .map(|a: u64| a.cmp(b))
                    // If the i64 doesn't fit into a u64 it must be less than 0.
                    .unwrap_or(Ordering::Less),
            ),
            (Value::Int(a), Value::Float(b)) => (*a as f64).partial_cmp(b),
            (Value::UInt(a), Value::Int(b)) => Some(
                a.to_owned()
                    .try_into()
                    .map(|a: i64| a.cmp(b))
                    // If the u64 doesn't fit into a i64 it must be greater than i64::MAX.
                    .unwrap_or(Ordering::Greater),
            ),
            (Value::UInt(a), Value::Float(b)) => (*a as f64).partial_cmp(b),
            (Value::Float(a), Value::Int(b)) => a.partial_cmp(&(*b as f64)),
            (Value::Float(a), Value::UInt(b)) => a.partial_cmp(&(*b as f64)),
            _ => None,
        }
    }
}

impl From<&Key> for Value {
    fn from(value: &Key) -> Self {
        match value {
            Key::Int(v) => Value::Int(*v),
            Key::Uint(v) => Value::UInt(*v),
            Key::Bool(v) => Value::Bool(*v),
            Key::String(v) => Value::String(v.clone()),
        }
    }
}

impl From<Key> for Value {
    fn from(value: Key) -> Self {
        match value {
            Key::Int(v) => Value::Int(v),
            Key::Uint(v) => Value::UInt(v),
            Key::Bool(v) => Value::Bool(v),
            Key::String(v) => Value::String(v),
        }
    }
}

impl From<&Key> for Key {
    fn from(key: &Key) -> Self {
        key.clone()
    }
}

// Convert Vec<T> to Value
impl<T: Into<Value>> From<Vec<T>> for Value {
    fn from(v: Vec<T>) -> Self {
        Value::List(v.into_iter().map(|v| v.into()).collect::<Vec<_>>().into())
    }
}

// Convert Vec<u8> to Value
impl From<Vec<u8>> for Value {
    fn from(v: Vec<u8>) -> Self {
        Value::Bytes(v.into())
    }
}

#[cfg(feature = "bytes")]
// Convert Bytes to Value
impl From<::bytes::Bytes> for Value {
    fn from(v: ::bytes::Bytes) -> Self {
        Value::Bytes(v.to_vec().into())
    }
}

#[cfg(feature = "bytes")]
// Convert &Bytes to Value
impl From<&::bytes::Bytes> for Value {
    fn from(v: &::bytes::Bytes) -> Self {
        Value::Bytes(v.to_vec().into())
    }
}

// Convert String to Value
impl From<String> for Value {
    fn from(v: String) -> Self {
        Value::String(v.into())
    }
}

impl From<&str> for Value {
    fn from(v: &str) -> Self {
        Value::String(v.to_string().into())
    }
}

// Convert Option<T> to Value
impl<T: Into<Value>> From<Option<T>> for Value {
    fn from(v: Option<T>) -> Self {
        match v {
            Some(v) => v.into(),
            None => Value::Null,
        }
    }
}

// Convert HashMap<K, V> to Value
impl<K: Into<Key>, V: Into<Value>> From<HashMap<K, V>> for Value {
    fn from(v: HashMap<K, V>) -> Self {
        Value::Map(v.into())
    }
}

impl From<ExecutionError> for ResolveResult {
    fn from(value: ExecutionError) -> Self {
        Err(value)
    }
}

pub type ResolveResult = Result<Value, ExecutionError>;

impl From<Value> for ResolveResult {
    fn from(value: Value) -> Self {
        Ok(value)
    }
}

/// The error returned when a `dyn Val` has no `Value` representation.
fn no_value_repr(v: &dyn Val) -> ExecutionError {
    ExecutionError::UnexpectedType {
        got: v.get_type().name().to_string(),
        want: "a type representable as `Value`".to_string(),
    }
}

/// Downcasts a `dyn Val` to the built-in type its [`Kind`] implies.
///
/// `Val` is public and not sealed, so a foreign implementation may report a
/// `Kind` without being the built-in value that carries it - a custom lazy list
/// reports `Kind::List` but is not a [`CelList`]. Those reach `Value` as an
/// error, not a panic.
fn built_in<'b, 'v, T: FromVal<'b, 'v>>(v: &'b (dyn Val + 'v)) -> Result<&'b T, ExecutionError> {
    v.downcast_ref::<T>().ok_or_else(|| no_value_repr(v))
}

impl<'b, 'v> TryFrom<&'b (dyn Val + 'v)> for Value {
    type Error = ExecutionError;
    fn try_from(v: &'b (dyn Val + 'v)) -> Result<Self, Self::Error> {
        match v.get_type().kind() {
            Kind::Boolean => Ok(Value::Bool(*built_in::<CelBool>(v)?.inner())),
            Kind::Int => Ok(Value::Int(*built_in::<CelInt>(v)?.inner())),
            Kind::UInt => Ok(Value::UInt(*built_in::<CelUInt>(v)?.inner())),
            Kind::Double => Ok(Value::Float(*built_in::<CelDouble>(v)?.inner())),
            Kind::String => Ok(Value::String(Arc::new(
                built_in::<CelString>(v)?.inner().to_string(),
            ))),
            Kind::NullType => Ok(Value::Null),
            Kind::Bytes => Ok(Value::Bytes(Arc::new(
                built_in::<CelBytes>(v)?.inner().to_vec(),
            ))),
            #[cfg(feature = "chrono")]
            Kind::Duration => Ok(Value::Duration(*built_in::<CelDuration>(v)?.inner())),
            #[cfg(feature = "chrono")]
            Kind::Timestamp => Ok(Value::Timestamp(*built_in::<CelTimestamp>(v)?.inner())),
            Kind::List => {
                let list = built_in::<CelList>(v)?.inner();
                let items = list
                    .iter()
                    .map(|i| Value::try_from(i.as_ref()))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(Value::List(Arc::new(items)))
            }
            Kind::Map => {
                let map = built_in::<CelMap>(v)?.inner();
                let entries = map
                    .iter()
                    .map(|(k, v)| Ok((Key::from(k.clone()), Value::try_from(v.as_ref())?)))
                    .collect::<Result<HashMap<_, _>, ExecutionError>>()?;
                Ok(Value::Map(Map {
                    map: Arc::new(entries),
                }))
            }
            Kind::Type => Ok(Value::String(Arc::new(
                built_in::<CelType>(v)?.name().to_string(),
            ))),
            Kind::Opaque => Ok(Value::Opaque(match v.downcast_ref::<CelOptional>() {
                None => built_in::<OpaqueVal>(v)?.clone_inner(),
                // A present optional whose value has no `Value` representation is
                // an error, not an absent one.
                Some(opt) => match opt.option() {
                    None => Arc::new(OptionalValue::none()),
                    Some(v) => Arc::new(OptionalValue::of(Value::try_from(v)?)),
                },
            })),
            _ => {
                if let Some(v) = v.downcast_ref::<CelStruct>() {
                    return Ok(Value::Struct(Arc::new(v.to_static()?)));
                }
                if let Some(opaque) = v.downcast_ref::<OpaqueVal>() {
                    Ok(Value::Opaque(opaque.val.clone()))
                } else {
                    Err(no_value_repr(v))
                }
            }
        }
    }
}

impl TryFrom<Value> for Box<dyn Val> {
    type Error = ExecutionError;
    fn try_from(value: Value) -> Result<Self, Self::Error> {
        match value {
            Value::Bool(b) => Ok(Box::new(CelBool::from(b))),
            Value::Int(i) => Ok(Box::new(CelInt::from(i))),
            Value::UInt(u) => Ok(Box::new(CelUInt::from(u))),
            Value::Float(f) => Ok(Box::new(CelDouble::from(f))),
            Value::String(s) => Ok(Box::new(CelString::from(Arc::unwrap_or_clone(s)))),
            Value::Null => Ok(Box::new(CelNull)),
            Value::Bytes(b) => Ok(Box::new(CelBytes::from(b.as_slice().to_vec()))),
            #[cfg(feature = "chrono")]
            Value::Duration(d) => Ok(Box::new(CelDuration::from(d))),
            #[cfg(feature = "chrono")]
            Value::Timestamp(ts) => Ok(Box::new(CelTimestamp::from(ts))),
            Value::List(l) => {
                let result: Result<Vec<Box<dyn Val>>, ExecutionError> =
                    (*l).clone().into_iter().map(|i| i.try_into()).collect();
                Ok(Box::new(CelList::from(result?)))
            }
            Value::Map(map) => {
                let result: Result<HashMap<CelMapKey, Box<dyn Val>>, ExecutionError> = (*map.map)
                    .clone()
                    .into_iter()
                    .map(|(k, v)| v.clone().try_into().map(|v| (k.clone().into(), v)))
                    .collect();
                Ok(Box::new(CelMap::from(result?)))
            }
            Value::Opaque(o) => {
                let v: Box<dyn Val> = if let Some(value) = o.downcast_ref::<OptionalValue>() {
                    match value.inner() {
                        None => Box::new(CelOptional::none()),
                        Some(v) => Box::new(CelOptional::of(v.clone().try_into()?)),
                    }
                } else {
                    Box::new(OpaqueVal::new(o))
                };
                Ok(v)
            }
            Value::Struct(s) => Ok(Arc::try_unwrap(s)
                .map(|s| Box::new(s) as Box<dyn Val>)
                .unwrap_or_else(|arc| arc.clone_as_boxed())),
            _ => Err(ExecutionError::UnsupportedTargetType { target: value }),
        }
    }
}

impl Value {
    pub fn resolve_all(expr: &[Expression], ctx: &Context) -> ResolveResult {
        let mut res = Vec::with_capacity(expr.len());
        for expr in expr {
            res.push(Value::resolve(expr, ctx)?);
        }
        Ok(Value::List(res.into()))
    }

    pub fn resolve(expr: &Expression, ctx: &Context) -> ResolveResult {
        Self::resolve_val(expr, ctx)?.as_ref().try_into()
    }

    /// Evaluates `expr` against `ctx`.
    ///
    /// The result borrows where it can: a literal borrows the AST (`'e`), a
    /// variable borrows the context (`'e`), and anything carrying data the
    /// context's resolver or values borrow is bounded by `'v`. Nothing is
    /// copied unless an operation produces a new value.
    #[inline(always)]
    pub fn resolve_val<'e, 'p, 'v>(
        expr: &'e Expression,
        ctx: &'e Context<'p, 'v>,
    ) -> Result<CowVal<'e, 'v>, ExecutionError> {
        match &expr.expr {
            Expr::Literal(literal) => Ok(literal.to_val()),
            Expr::Call(call) => {
                // START OF SPECIAL CASES FOR operators::...
                if call.args.len() == 3 && call.func_name == operators::CONDITIONAL {
                    let cond = Value::resolve_val(&call.args[0], ctx);
                    return if try_bool(cond)? {
                        Value::resolve_val(&call.args[1], ctx)
                    } else {
                        Value::resolve_val(&call.args[2], ctx)
                    };
                }
                if call.args.len() == 2 {
                    match call.func_name.as_str() {
                        operators::LOGICAL_OR => {
                            let left = try_bool(Value::resolve_val(&call.args[0], ctx));
                            return if Ok(true) == left {
                                Ok(bool(true))
                            } else {
                                let right_value = Value::resolve_val(&call.args[1], ctx)?;
                                let right =
                                    right_value.downcast_ref::<CelBool>().map(|b| *b.inner());
                                match (left, right) {
                                    (Ok(false), Some(right)) => Ok(bool(right)),
                                    (Err(_), Some(true)) => Ok(bool(true)),
                                    (left, _) => Err(boolean_operator_error(
                                        &call.func_name,
                                        left,
                                        right_value.as_ref(),
                                    )),
                                }
                            };
                        }
                        operators::LOGICAL_AND => {
                            let left = try_bool(Value::resolve_val(&call.args[0], ctx));
                            return if Ok(false) == left {
                                Ok(bool(false))
                            } else {
                                let right_value = Value::resolve_val(&call.args[1], ctx)?;
                                let right =
                                    right_value.downcast_ref::<CelBool>().map(|b| *b.inner());
                                match (left, right) {
                                    (Ok(true), Some(right)) => Ok(bool(right)),
                                    (Err(_), Some(false)) => Ok(bool(false)),
                                    (left, _) => Err(boolean_operator_error(
                                        &call.func_name,
                                        left,
                                        right_value.as_ref(),
                                    )),
                                }
                            };
                        }
                        operators::EQUALS => {
                            return Ok(bool(
                                Value::resolve_val(&call.args[0], ctx)?
                                    == Value::resolve_val(&call.args[1], ctx)?,
                            ))
                        }
                        operators::NOT_EQUALS => {
                            return Ok(bool(
                                Value::resolve_val(&call.args[0], ctx)?
                                    != Value::resolve_val(&call.args[1], ctx)?,
                            ))
                        }
                        operators::INDEX | operators::OPT_INDEX => {
                            let mut is_optional = call.func_name == operators::OPT_INDEX;
                            let value = Value::resolve_val(&call.args[0], ctx)?;

                            let value = match unwrap_optional(value) {
                                Unwrapped::NotOptional(value) => value,
                                Unwrapped::Some(value) => {
                                    is_optional = true;
                                    value
                                }
                                Unwrapped::None => return Ok(CowVal::owned(CelOptional::none())),
                            };

                            let index = Self::resolve_val(&call.args[1], ctx)?;
                            let result =
                                index_into(value, index.as_ref(), &call.func_name, |value| {
                                    ExecutionError::overload_for_values(
                                        &call.func_name,
                                        [value, index.as_ref()],
                                        false,
                                    )
                                });
                            return if is_optional {
                                Ok(CowVal::owned(match result {
                                    Ok(val) => CelOptional::of(val.into_owned()),
                                    Err(_) => CelOptional::none(),
                                }))
                            } else {
                                result
                            };
                        }
                        operators::OPT_SELECT => {
                            let operand = Value::resolve_val(&call.args[0], ctx)?;
                            let field_literal = Value::resolve_val(&call.args[1], ctx)?;
                            let field = match field_literal.get_type().kind() {
                                Kind::String => field_literal
                                    .downcast_ref::<CelString>()
                                    .expect("field must be string"),
                                _ => {
                                    return Err(ExecutionError::function_error(
                                        "_?._",
                                        "field must be string",
                                    ))
                                }
                            };
                            // Unwrap outer optional if present — a `None`
                            // short-circuits to `Optional::none()`. Otherwise
                            // the operand is the target itself. A missing
                            // key/field maps to `Optional::none()` per
                            // cel-spec (mirrors OPT_INDEX semantics).
                            let target = match unwrap_optional(operand) {
                                Unwrapped::NotOptional(v) | Unwrapped::Some(v) => v,
                                Unwrapped::None => return Ok(CowVal::owned(CelOptional::none())),
                            };
                            let result = match index_into(target, field, "_?._", |value| {
                                ExecutionError::overload_for_values("_?._", [value, field], false)
                            }) {
                                Ok(v) => CelOptional::of(v.into_owned()),
                                Err(_) => CelOptional::none(),
                            };
                            return Ok(CowVal::owned(result));
                        }
                        // END OF SPECIAL CASES

                        // all below is NOT special in the interpreter
                        operators::ADD => {
                            let lhs = Value::resolve_val(&call.args[0], ctx)?;
                            let rhs = Value::resolve_val(&call.args[1], ctx)?;
                            return Ok(CowVal::Owned(
                                lhs.as_adder()
                                    .ok_or_else(|| {
                                        ExecutionError::unsupported_binary_operator(
                                            "add",
                                            lhs.as_ref(),
                                            rhs.as_ref(),
                                        )
                                    })?
                                    .add(rhs.as_ref())?
                                    .into_owned(),
                            ));
                        }
                        operators::SUBSTRACT => {
                            let lhs = Value::resolve_val(&call.args[0], ctx)?;
                            let rhs = Value::resolve_val(&call.args[1], ctx)?;
                            return Ok(CowVal::Owned(
                                lhs.as_subtractor()
                                    .ok_or_else(|| {
                                        ExecutionError::unsupported_binary_operator(
                                            "sub",
                                            lhs.as_ref(),
                                            rhs.as_ref(),
                                        )
                                    })?
                                    .sub(rhs.as_ref())?
                                    .into_owned(),
                            ));
                        }
                        operators::DIVIDE => {
                            let lhs = Value::resolve_val(&call.args[0], ctx)?;
                            let rhs = Value::resolve_val(&call.args[1], ctx)?;
                            return Ok(CowVal::Owned(
                                lhs.as_divider()
                                    .ok_or_else(|| {
                                        ExecutionError::unsupported_binary_operator(
                                            "div",
                                            lhs.as_ref(),
                                            rhs.as_ref(),
                                        )
                                    })?
                                    .div(rhs.as_ref())?
                                    .into_owned(),
                            ));
                        }
                        operators::MULTIPLY => {
                            let lhs = Value::resolve_val(&call.args[0], ctx)?;
                            let rhs = Value::resolve_val(&call.args[1], ctx)?;
                            return Ok(CowVal::Owned(
                                lhs.as_multiplier()
                                    .ok_or_else(|| {
                                        ExecutionError::unsupported_binary_operator(
                                            "mul",
                                            lhs.as_ref(),
                                            rhs.as_ref(),
                                        )
                                    })?
                                    .mul(rhs.as_ref())?
                                    .into_owned(),
                            ));
                        }
                        operators::MODULO => {
                            let lhs = Value::resolve_val(&call.args[0], ctx)?;
                            let rhs = Value::resolve_val(&call.args[1], ctx)?;
                            return Ok(CowVal::Owned(
                                lhs.as_modder()
                                    .ok_or_else(|| {
                                        ExecutionError::unsupported_binary_operator(
                                            "rem",
                                            lhs.as_ref(),
                                            rhs.as_ref(),
                                        )
                                    })?
                                    .modulo(rhs.as_ref())?
                                    .into_owned(),
                            ));
                        }
                        operators::LESS => {
                            let lhs = Value::resolve_val(&call.args[0], ctx)?;
                            let rhs = Value::resolve_val(&call.args[1], ctx)?;
                            return Ok(bool(
                                compare_values(&call.func_name, lhs.as_ref(), rhs.as_ref())?
                                    == Ordering::Less,
                            ));
                        }
                        operators::LESS_EQUALS => {
                            let lhs = Value::resolve_val(&call.args[0], ctx)?;
                            let rhs = Value::resolve_val(&call.args[1], ctx)?;
                            return Ok(bool(
                                compare_values(&call.func_name, lhs.as_ref(), rhs.as_ref())?
                                    != Ordering::Greater,
                            ));
                        }
                        operators::GREATER => {
                            let lhs = Value::resolve_val(&call.args[0], ctx)?;
                            let rhs = Value::resolve_val(&call.args[1], ctx)?;
                            return Ok(bool(
                                compare_values(&call.func_name, lhs.as_ref(), rhs.as_ref())?
                                    == Ordering::Greater,
                            ));
                        }
                        operators::GREATER_EQUALS => {
                            let lhs = Value::resolve_val(&call.args[0], ctx)?;
                            let rhs = Value::resolve_val(&call.args[1], ctx)?;
                            return Ok(bool(
                                compare_values(&call.func_name, lhs.as_ref(), rhs.as_ref())?
                                    != Ordering::Less,
                            ));
                        }
                        operators::IN => {
                            let lhs = Value::resolve_val(&call.args[0], ctx)?;
                            let rhs = Value::resolve_val(&call.args[1], ctx)?;
                            let overload_error = || {
                                ExecutionError::overload_for_values(
                                    &call.func_name,
                                    [lhs.as_ref(), rhs.as_ref()],
                                    false,
                                )
                            };
                            let container = rhs.as_container().ok_or_else(overload_error)?;
                            return container
                                .contains(lhs.as_ref())
                                .map(bool)
                                .map_err(|error| error.with_overload_context(overload_error()));
                        }
                        _ => (),
                    }
                }
                if call.args.len() == 1 {
                    match call.func_name.as_str() {
                        operators::LOGICAL_NOT => {
                            let expr = Value::resolve_val(&call.args[0], ctx)?;
                            let overload_error = ExecutionError::overload_for_values(
                                &call.func_name,
                                [expr.as_ref()],
                                false,
                            );
                            return expr
                                .downcast_ref::<CelBool>()
                                .map(Bool::negate)
                                .ok_or(overload_error)
                                .map(|b| bool(b.into_inner()));
                        }
                        operators::NEGATE => {
                            let val = Value::resolve_val(&call.args[0], ctx)?;
                            let overload_error = ExecutionError::overload_for_values(
                                &call.func_name,
                                [val.as_ref()],
                                false,
                            );
                            return Ok(CowVal::Owned(
                                val.as_negator()
                                    .ok_or_else(|| overload_error.clone())?
                                    .negate()
                                    .map_err(|error| error.with_overload_context(overload_error))?,
                            ));
                        }
                        operators::NOT_STRICTLY_FALSE => {
                            return Ok(bool(
                                try_bool(Value::resolve_val(&call.args[0], ctx)).unwrap_or(true),
                            ));
                        }
                        _ => (),
                    }
                }
                match &call.target {
                    None => {
                        // TODO: Optimize for the 1 and 2 arg cases and avoid the Vec altogether
                        let args: Result<Vec<CowVal<'e, 'v>>, ExecutionError> = call
                            .args
                            .iter()
                            .map(|a| Value::resolve_val(a, ctx))
                            .collect();
                        let name = ctx.resolve_function(&call.func_name);
                        call_function(ctx, &name, &call.func_name, args?)
                    }
                    Some(target_expr) => {
                        let args: Result<Vec<CowVal<'e, 'v>>, ExecutionError> = call
                            .args
                            .iter()
                            .map(|a| Value::resolve_val(a, ctx))
                            .collect();
                        let mut args = args?;
                        // As in cel-go, a call whose target spells a qualified
                        // name that, with the function's, names a function is
                        // a call to that function: `optional.of(x)` calls
                        // `optional.of`.
                        if let Some(name) =
                            ctx.resolve_qualified_function(target_expr, &call.func_name)
                        {
                            return call_function(ctx, &name, &call.func_name, args);
                        }
                        let target = Value::resolve_val(target_expr, ctx)?;
                        args.insert(0, target);
                        if let Some(op) = ctx.env().find_member_overload(&call.func_name, &args) {
                            return op(args);
                        }
                        let func = match ctx.get_function(&call.func_name) {
                            Some(func) => func,
                            None => {
                                return Err(if ctx.env().has_member_overload(&call.func_name) {
                                    ExecutionError::overload_for_values(
                                        &call.func_name,
                                        args.iter().map(|arg| arg.as_ref()),
                                        true,
                                    )
                                } else {
                                    ExecutionError::UndeclaredReference(
                                        call.func_name.clone().into(),
                                    )
                                });
                            }
                        };
                        let target = args.remove(0);
                        let mut ctx =
                            FunctionContext::new(&call.func_name, Some(target), ctx, args);
                        (func)(&mut ctx)
                    }
                }
            }
            Expr::Ident(name) => ctx
                .resolve_ident(name)
                .ok_or_else(|| ExecutionError::UndeclaredReference(Arc::new(name.to_string()))),
            Expr::Select(select) => {
                // `has(a.b.c)` tests for `c` on `a.b`: only its operand is a name
                let name = if select.test {
                    select.operand.expr.qualified_name_segments()
                } else {
                    expr.expr.qualified_name_segments()
                };
                let Some(name) = name else {
                    let left = Value::resolve_val(select.operand.deref(), ctx)?;
                    return select_field(left, &select.field, select.test);
                };
                let (mut value, fields) = ctx.resolve_qualified(&name)?;
                for field in fields {
                    value = select_field(value, field, false)?;
                }
                if select.test {
                    select_field(value, &select.field, true)
                } else {
                    Ok(value)
                }
            }
            Expr::List(list_expr) => {
                let mut list: Vec<Box<dyn Val + 'v>> = Vec::with_capacity(list_expr.elements.len());
                for (idx, element) in list_expr.elements.iter().enumerate() {
                    let value = Value::resolve_val(element, ctx)?;
                    if list_expr.optional_indices.contains(&idx) {
                        match unwrap_optional(value) {
                            Unwrapped::NotOptional(v) | Unwrapped::Some(v) => {
                                list.push(v.into_owned())
                            }
                            Unwrapped::None => {}
                        }
                    } else {
                        list.push(value.into_owned());
                    }
                }
                Ok(CowVal::owned(CelList::from(list)))
            }
            Expr::Map(map_expr) => {
                let mut map: HashMap<CelMapKey<'v>, Box<dyn Val + 'v>> =
                    HashMap::with_capacity(map_expr.entries.len());
                for entry in map_expr.entries.iter() {
                    let (k, v, is_optional) = match &entry.expr {
                        EntryExpr::StructField(_) => panic!("WAT?"),
                        EntryExpr::MapEntry(e) => (&e.key, &e.value, e.optional),
                    };
                    let key: CelMapKey<'v> = Value::resolve_val(k, ctx)?.try_into()?;
                    let value = Value::resolve_val(v, ctx)?;

                    // An optional entry holding no value adds nothing, not even its key.
                    let value = if is_optional {
                        match unwrap_optional(value) {
                            Unwrapped::NotOptional(v) | Unwrapped::Some(v) => Some(v),
                            Unwrapped::None => None,
                        }
                    } else {
                        Some(value)
                    };

                    if let Some(value) = value {
                        if ctx.env().error_on_duplicate_map_keys() && map::has_key(&map, &key) {
                            return Err(ExecutionError::DuplicateKey(Key::from(key).into()));
                        }
                        map.insert(key, value.into_owned());
                    }
                }
                Ok(CowVal::owned(CelMap::from(map)))
            }
            Expr::Comprehension(comprehension) => {
                let accu_init = Value::resolve_val(&comprehension.accu_init, ctx)?;
                let iter = Value::resolve_val(&comprehension.iter_range, ctx)?;

                // Mirror cel-go's optimization (see `folder.ResolveName` in
                // `cel-go/interpreter/interpretable.go`): when the
                // accumulator starts out as an empty list and the loop step
                // only ever appends to it (`map` / `filter`), build the
                // result in a single preallocated `MutableList` instead of
                // paying O(n) clone-and-extend on every iteration
                // (`@result + [expr]`).
                if let Some(step) = AppendStep::of(comprehension) {
                    if accu_init
                        .downcast_ref::<CelList>()
                        .is_some_and(|list| list.inner().is_empty())
                    {
                        return step.run(comprehension, &iter, ctx);
                    }
                }

                let mut ctx = ctx.new_inner_scope();
                ctx.add_variable_as_val(&comprehension.accu_var, accu_init.into_owned());

                let mut items = iter
                    .as_iterable()
                    .ok_or_else(|| ExecutionError::UnexpectedType {
                        got: iter.get_type().name().to_owned(),
                        want: "iterable".to_owned(),
                    })?
                    .iter();
                let mut deferred = DeferredErrors::of(comprehension);
                while let Some(item) = items.next() {
                    if !try_bool(Value::resolve_val(&comprehension.loop_cond, &ctx))? {
                        break;
                    }
                    ctx.add_variable_as_val(&comprehension.iter_var, item.clone_as_boxed());
                    let step = Value::resolve_val(&comprehension.loop_step, &ctx);
                    if let Some(accu) = deferred.step(step)? {
                        ctx.add_variable_as_val(&comprehension.accu_var, accu.into_owned());
                    }
                }
                deferred.finish()?;
                Ok(CowVal::Owned(
                    Value::resolve_val(&comprehension.result, &ctx)?.into_owned(),
                ))
            }
            Expr::Struct(strct) => {
                let name = strct.type_name.clone();
                let struct_type = ctx
                    .find_struct(&name)
                    .ok_or(ExecutionError::UnexpectedType {
                        got: name.to_owned(),
                        want: "known struct".to_owned(),
                    })?;
                let mut fields = std::collections::BTreeMap::new();
                for entry in &strct.entries {
                    match &entry.expr {
                        EntryExpr::StructField(expr) => {
                            let f = expr.field.clone();
                            fields.insert(f, Value::resolve_val(&expr.value, ctx)?);
                        }
                        EntryExpr::MapEntry(entry) => {
                            return Err(ExecutionError::InternalError(format!(
                                "Expected struct_field_expr, got {entry:?}"
                            )))
                        }
                    }
                }
                Ok(CowVal::Owned(struct_type.new_value(fields)?))
            }
            Expr::Unspecified => panic!("Can't evaluate Unspecified Expr"),
        }
    }
}

/// A boolean result, borrowed from a constant: no allocation.
fn bool<'b, 'v>(boolean: bool) -> CowVal<'b, 'v> {
    CowVal::Borrowed(if boolean { &Bool::TRUE } else { &Bool::FALSE })
}

fn compare_values(
    operator: &str,
    lhs: &dyn Val,
    rhs: &dyn Val,
) -> Result<Ordering, ExecutionError> {
    let context = ExecutionError::overload_for_values(operator, [lhs, rhs], false);
    lhs.as_comparer()
        .ok_or_else(|| context.clone())
        .and_then(|comparer| comparer.compare(rhs))
        .map_err(|error| error.with_overload_context(context))
}

fn boolean_operator_error(
    operator: &str,
    left: Result<bool, ExecutionError>,
    right: &dyn Val,
) -> ExecutionError {
    let right_type = right.get_type().name().to_owned();
    match left {
        Err(ExecutionError::UnexpectedType { got, want }) if want == "bool" => {
            ExecutionError::no_such_overload(operator, vec![got, right_type])
        }
        Err(error) => error,
        Ok(_) => ExecutionError::no_such_overload(operator, vec!["bool".to_owned(), right_type]),
    }
}

/// The connective of an `all()` / `exists()` loop step: `@result && x` or
/// `@result || x`.
#[derive(Clone, Copy)]
enum LogicalFold {
    And,
    Or,
}

impl LogicalFold {
    fn of(comprehension: &ComprehensionExpr) -> Option<Self> {
        let Expr::Call(call) = &comprehension.loop_step.expr else {
            return None;
        };
        let folds_accu = call.target.is_none()
            && matches!(
                call.args.first().map(|arg| &arg.expr),
                Some(Expr::Ident(name)) if *name == comprehension.accu_var
            );
        match call.func_name.as_str() {
            operators::LOGICAL_AND if folds_accu => Some(Self::And),
            operators::LOGICAL_OR if folds_accu => Some(Self::Or),
            _ => None,
        }
    }

    /// The operand that decides the result regardless of any error beside
    /// it: `false` for `&&`, `true` for `||`.
    fn absorbing(self) -> bool {
        matches!(self, Self::Or)
    }

    fn absorbs(self, value: &dyn Val) -> bool {
        value
            .downcast_ref::<CelBool>()
            .is_some_and(|b| *b.inner() == self.absorbing())
    }
}

/// Errors from an `all()` / `exists()` loop step that a later element may
/// still override, as in cel-go's `evalAnd` / `evalOr`: `error && false` is
/// `false`, while `error && true` stays the error.
struct DeferredErrors {
    fold: Option<LogicalFold>,
    pending: Option<ExecutionError>,
}

impl DeferredErrors {
    fn of(comprehension: &ComprehensionExpr) -> Self {
        Self {
            fold: LogicalFold::of(comprehension),
            pending: None,
        }
    }

    /// Feeds one loop-step result. Returns the new accumulator, or `None`
    /// when it must be left unchanged because an error is pending.
    fn step<'b, 'v>(
        &mut self,
        step: Result<CowVal<'b, 'v>, ExecutionError>,
    ) -> Result<Option<CowVal<'b, 'v>>, ExecutionError> {
        match (step, self.fold) {
            (Err(err), Some(_)) => {
                self.pending = Some(err);
                Ok(None)
            }
            (Err(err), None) => Err(err),
            (Ok(accu), Some(fold)) if self.pending.is_some() && !fold.absorbs(&*accu) => Ok(None),
            (Ok(accu), _) => {
                self.pending = None;
                Ok(Some(accu))
            }
        }
    }

    /// Fails with the error still pending once the loop ends.
    fn finish(self) -> Result<(), ExecutionError> {
        self.pending.map_or(Ok(()), Err)
    }
}

/// The loop step of a `map` / `filter` comprehension: `@result + [expr]`,
/// optionally guarded as `cond ? @result + [expr] : @result`, with `@result`
/// as the comprehension's result.
///
/// Evaluating it generically clones the whole accumulator on every
/// iteration; recognising the shape lets [`AppendStep::run`] append to a
/// [`MutableList`] in place instead. `@result` cannot be written in CEL
/// source, so nothing but the step itself can observe the accumulator.
struct AppendStep<'e> {
    /// The `cond` of a guarded step.
    guard: Option<&'e Expression>,
    /// The `[expr]` list appended on every iteration.
    items: &'e Expression,
}

impl<'e> AppendStep<'e> {
    fn of(comprehension: &'e ComprehensionExpr) -> Option<Self> {
        let accu = comprehension.accu_var.as_str();
        let is_accu = |e: &Expression| matches!(&e.expr, Expr::Ident(name) if name == accu);
        let items_of = |e: &'e Expression| match &e.expr {
            Expr::Call(call) if call.func_name == operators::ADD && call.target.is_none() => {
                match call.args.as_slice() {
                    [lhs, rhs] if is_accu(lhs) && matches!(rhs.expr, Expr::List(_)) => Some(rhs),
                    _ => None,
                }
            }
            _ => None,
        };

        if !is_accu(&comprehension.result)
            || !matches!(comprehension.loop_cond.expr, Expr::Literal(_))
        {
            return None;
        }
        match &comprehension.loop_step.expr {
            Expr::Call(call)
                if call.func_name == operators::CONDITIONAL && call.target.is_none() =>
            {
                match call.args.as_slice() {
                    [guard, step, otherwise] if is_accu(otherwise) => Some(AppendStep {
                        guard: Some(guard),
                        items: items_of(step)?,
                    }),
                    _ => None,
                }
            }
            _ => Some(AppendStep {
                guard: None,
                items: items_of(&comprehension.loop_step)?,
            }),
        }
    }

    /// Runs the comprehension over `iter`, starting from an empty list.
    fn run<'p, 'v>(
        &self,
        comprehension: &'e ComprehensionExpr,
        iter: &CowVal<'e, 'v>,
        ctx: &'e Context<'p, 'v>,
    ) -> Result<CowVal<'e, 'v>, ExecutionError> {
        let size_hint = iter
            .as_sizer()
            .map(|s| *s.size().inner() as usize)
            .unwrap_or(0);
        let mut accu = MutableList::with_capacity(size_hint);

        let mut ctx = ctx.new_inner_scope();
        let mut items = iter
            .as_iterable()
            .ok_or_else(|| ExecutionError::UnexpectedType {
                got: iter.get_type().name().to_owned(),
                want: "iterable".to_owned(),
            })?
            .iter();
        while let Some(item) = items.next() {
            if !try_bool(Value::resolve_val(&comprehension.loop_cond, &ctx))? {
                break;
            }
            ctx.add_variable_as_val(&comprehension.iter_var, item.clone_as_boxed());
            if let Some(guard) = self.guard {
                if !try_bool(Value::resolve_val(guard, &ctx))? {
                    continue;
                }
            }
            accu.extend(Value::resolve_val(self.items, &ctx)?.as_ref())?;
        }
        Ok(CowVal::owned(accu.to_immutable()))
    }
}

fn try_bool(val: Result<CowVal<'_, '_>, ExecutionError>) -> Result<bool, ExecutionError> {
    match val {
        Ok(val) => val
            .downcast_ref::<CelBool>()
            .map(|b| *b.inner())
            .ok_or_else(|| ExecutionError::UnexpectedType {
                got: val.get_type().name().to_owned(),
                want: "bool".to_owned(),
            }),
        Err(err) => Result::Err(err),
    }
}

/// Calls the global function `name` with `args`. The function is told
/// `ftx_name`, borrowed for as long as the result: a qualified function is
/// told its unqualified name.
#[inline(always)]
fn call_function<'e, 'p, 'v>(
    ctx: &'e Context<'p, 'v>,
    name: &str,
    ftx_name: &'e str,
    args: Vec<CowVal<'e, 'v>>,
) -> Result<CowVal<'e, 'v>, ExecutionError> {
    if let Some(op) = ctx.env().find_overload(name, &args) {
        return op(args);
    }
    let func = match ctx.get_function(name) {
        Some(func) => func,
        None if ctx.env().has_overload(name) => {
            return Err(ExecutionError::overload_for_values(
                name,
                args.iter().map(|arg| arg.as_ref()),
                false,
            ));
        }
        None => {
            return Err(ExecutionError::UndeclaredReference(name.to_owned().into()));
        }
    };
    let mut ctx = FunctionContext::new(ftx_name, None, ctx, args);
    (func)(&mut ctx)
}

/// Selects `field` on `left`, the already resolved operand of a select:
/// `left.field`, or `has(left.field)` when `test` is set.
#[inline(always)]
fn select_field<'b, 'v>(
    left: CowVal<'b, 'v>,
    field: &str,
    test: bool,
) -> Result<CowVal<'b, 'v>, ExecutionError> {
    // borrows the field name from the AST
    let key: CelString = field.into();
    let no_such_key = || ExecutionError::NoSuchKey(Arc::new(field.to_owned()));
    let overload_error =
        |value: &dyn Val| ExecutionError::overload_for_values("_._", [value, &key], false);

    // Plain `.field` on an `Optional` propagates optional-ness
    // per cel-spec — matches cel-go `applyQualifiers` at
    // `interpreter/attributes.go:1259` where an initial optional
    // operand makes the whole qualifier chain optional. `has()`
    // (test=true) on the same shape returns Bool(false) when the
    // chain is empty.
    let left = match unwrap_optional(left) {
        Unwrapped::NotOptional(left) => left,
        // Optional::none() short-circuits — the chain stops.
        Unwrapped::None => {
            return if test {
                Ok(bool(false))
            } else {
                Ok(CowVal::owned(CelOptional::none()))
            }
        }
        // Otherwise unwrap and access the field. A missing key on
        // a real container maps to Optional::none(); a field
        // access on a value that isn't a container at all
        // (Null, Int, …) is an error, matching cel-go's
        // `errorOnBadPresenceTest=true` mode which the cel-spec
        // conformance runner enables (see
        // `interpreter/attributes.go:1382` and
        // `conformance/conformance_test.go:87`).
        Unwrapped::Some(inner) => {
            return if test {
                let has = inner
                    .as_indexer()
                    .ok_or_else(no_such_key)?
                    .get(&key)
                    .is_ok();
                Ok(bool(has))
            } else {
                // a non-container operand is an error, a missing
                // key maps to `optional.none()`
                if inner.as_indexer().is_none() {
                    return Err(no_such_key());
                }
                Ok(CowVal::owned(
                    match index_into(inner, &key, "_._", |_| no_such_key()) {
                        Ok(v) => CelOptional::of(v.into_owned()),
                        Err(_) => CelOptional::none(),
                    },
                ))
            };
        }
    };

    if test {
        let indexer = left
            .as_indexer()
            .ok_or_else(|| overload_error(left.as_ref()))?;
        match indexer.get(&key) {
            Ok(_) => Ok(bool(true)),
            Err(ExecutionError::NoSuchKey(_)) => Ok(bool(false)),
            Err(error) => Err(error.with_lazy_overload_context(|| overload_error(left.as_ref()))),
        }
    } else {
        let is_map = left.get_type().kind() == Kind::Map;
        index_into(left, &key, "_._", |value| {
            if is_map {
                no_such_key()
            } else {
                overload_error(value)
            }
        })
    }
}

/// Indexes `value` with `idx`: a borrowed container hands out a borrow of
/// the element, an owned one moves the element out. `missing` is given `value`
/// and returns the error when it cannot be indexed at all.
///
/// A lookup that fails for want of a matching overload (say, a list indexed
/// with a string) reports `function` applied to the types of `value` and `idx`.
/// That error is only built when there is one.
///
/// Only the built-in containers are known to be able to give up their
/// elements; any other owned value is indexed in place and the element is
/// copied out, so a `Val` need only implement [`Val::as_indexer`].
fn index_into<'b, 'v>(
    value: CowVal<'b, 'v>,
    idx: &dyn Val,
    function: &str,
    missing: impl FnOnce(&dyn Val) -> ExecutionError,
) -> Result<CowVal<'b, 'v>, ExecutionError> {
    let overload = |value_type: &Type| {
        ExecutionError::no_such_overload(
            function,
            vec![
                value_type.name().to_owned(),
                idx.get_type().name().to_owned(),
            ],
        )
    };
    match value {
        CowVal::Borrowed(v) => v
            .as_indexer()
            .ok_or_else(|| missing(v))?
            .get(idx)
            .map_err(|error| error.with_lazy_overload_context(|| overload(v.get_type()))),
        CowVal::Owned(b) => {
            let indexer = b.as_indexer().ok_or_else(|| missing(b.as_ref()))?;
            if matches!(b.as_builtin(), BuiltinRef::Other) {
                return indexer
                    .get(idx)
                    .map(|v| CowVal::Owned(v.into_owned()))
                    .map_err(|error| error.with_lazy_overload_context(|| overload(b.get_type())));
            }
            // `b` is consumed below: keep what an error would need to say about it
            let value_type = b.get_type().to_owned();
            b.into_indexer()
                .ok_or_else(|| overload(&value_type))?
                .steal(idx)
                .map(CowVal::Owned)
                .map_err(|error| error.with_lazy_overload_context(|| overload(&value_type)))
        }
    }
}

impl ops::Add<Value> for Value {
    type Output = ResolveResult;

    #[inline(always)]
    fn add(self, rhs: Value) -> Self::Output {
        match (self, rhs) {
            (Value::Int(l), Value::Int(r)) => l
                .checked_add(r)
                .ok_or_else(|| ExecutionError::Overflow("add", l.into(), r.into()))
                .map(Value::Int),

            (Value::UInt(l), Value::UInt(r)) => l
                .checked_add(r)
                .ok_or_else(|| ExecutionError::Overflow("add", l.into(), r.into()))
                .map(Value::UInt),

            (Value::Float(l), Value::Float(r)) => Value::Float(l + r).into(),

            (Value::List(mut l), Value::List(mut r)) => {
                {
                    // If this is the only reference to `l`, we can append to it in place.
                    // `l` is replaced with a clone otherwise.
                    let l = Arc::make_mut(&mut l);

                    // Likewise, if this is the only reference to `r`, we can move its values
                    // instead of cloning them.
                    match Arc::get_mut(&mut r) {
                        Some(r) => l.append(r),
                        None => l.extend(r.iter().cloned()),
                    }
                }

                Ok(Value::List(l))
            }
            (Value::String(mut l), Value::String(r)) => {
                // If this is the only reference to `l`, we can append to it in place.
                // `l` is replaced with a clone otherwise.
                Arc::make_mut(&mut l).push_str(&r);
                Ok(Value::String(l))
            }
            #[cfg(feature = "chrono")]
            (Value::Duration(l), Value::Duration(r)) => l
                .checked_add(&r)
                .ok_or_else(|| ExecutionError::Overflow("add", l.into(), r.into()))
                .map(Value::Duration),
            #[cfg(feature = "chrono")]
            (Value::Timestamp(l), Value::Duration(r)) => checked_op(TsOp::Add, &l, &r),
            #[cfg(feature = "chrono")]
            (Value::Duration(l), Value::Timestamp(r)) => r
                .checked_add_signed(l)
                .ok_or_else(|| ExecutionError::Overflow("add", l.into(), r.into()))
                .map(Value::Timestamp),
            (left, right) => Err(ExecutionError::UnsupportedBinaryOperator(
                "add", left, right,
            )),
        }
    }
}

impl ops::Sub<Value> for Value {
    type Output = ResolveResult;

    #[inline(always)]
    fn sub(self, rhs: Value) -> Self::Output {
        match (self, rhs) {
            (Value::Int(l), Value::Int(r)) => l
                .checked_sub(r)
                .ok_or_else(|| ExecutionError::Overflow("sub", l.into(), r.into()))
                .map(Value::Int),

            (Value::UInt(l), Value::UInt(r)) => l
                .checked_sub(r)
                .ok_or_else(|| ExecutionError::Overflow("sub", l.into(), r.into()))
                .map(Value::UInt),

            (Value::Float(l), Value::Float(r)) => Value::Float(l - r).into(),

            #[cfg(feature = "chrono")]
            (Value::Duration(l), Value::Duration(r)) => l
                .checked_sub(&r)
                .ok_or_else(|| ExecutionError::Overflow("sub", l.into(), r.into()))
                .map(Value::Duration),
            #[cfg(feature = "chrono")]
            (Value::Timestamp(l), Value::Duration(r)) => checked_op(TsOp::Sub, &l, &r),
            #[cfg(feature = "chrono")]
            (Value::Timestamp(l), Value::Timestamp(r)) => {
                Value::Duration(l.signed_duration_since(r)).into()
            }
            (left, right) => Err(ExecutionError::UnsupportedBinaryOperator(
                "sub", left, right,
            )),
        }
    }
}

impl ops::Div<Value> for Value {
    type Output = ResolveResult;

    #[inline(always)]
    fn div(self, rhs: Value) -> Self::Output {
        match (self, rhs) {
            (Value::Int(l), Value::Int(r)) => {
                if r == 0 {
                    Err(ExecutionError::DivisionByZero(l.into()))
                } else {
                    l.checked_div(r)
                        .ok_or_else(|| ExecutionError::Overflow("div", l.into(), r.into()))
                        .map(Value::Int)
                }
            }

            (Value::UInt(l), Value::UInt(r)) => l
                .checked_div(r)
                .ok_or_else(|| ExecutionError::DivisionByZero(l.into()))
                .map(Value::UInt),

            (Value::Float(l), Value::Float(r)) => Value::Float(l / r).into(),

            (left, right) => Err(ExecutionError::UnsupportedBinaryOperator(
                "div", left, right,
            )),
        }
    }
}

impl ops::Mul<Value> for Value {
    type Output = ResolveResult;

    #[inline(always)]
    fn mul(self, rhs: Value) -> Self::Output {
        match (self, rhs) {
            (Value::Int(l), Value::Int(r)) => l
                .checked_mul(r)
                .ok_or_else(|| ExecutionError::Overflow("mul", l.into(), r.into()))
                .map(Value::Int),

            (Value::UInt(l), Value::UInt(r)) => l
                .checked_mul(r)
                .ok_or_else(|| ExecutionError::Overflow("mul", l.into(), r.into()))
                .map(Value::UInt),

            (Value::Float(l), Value::Float(r)) => Value::Float(l * r).into(),

            (left, right) => Err(ExecutionError::UnsupportedBinaryOperator(
                "mul", left, right,
            )),
        }
    }
}

impl ops::Rem<Value> for Value {
    type Output = ResolveResult;

    #[inline(always)]
    fn rem(self, rhs: Value) -> Self::Output {
        match (self, rhs) {
            (Value::Int(l), Value::Int(r)) => {
                if r == 0 {
                    Err(ExecutionError::RemainderByZero(l.into()))
                } else {
                    l.checked_rem(r)
                        .ok_or_else(|| ExecutionError::Overflow("rem", l.into(), r.into()))
                        .map(Value::Int)
                }
            }

            (Value::UInt(l), Value::UInt(r)) => l
                .checked_rem(r)
                .ok_or_else(|| ExecutionError::RemainderByZero(l.into()))
                .map(Value::UInt),

            (left, right) => Err(ExecutionError::UnsupportedBinaryOperator(
                "rem", left, right,
            )),
        }
    }
}

/// Op represents a binary arithmetic operation supported on a timestamp
///
#[cfg(feature = "chrono")]
enum TsOp {
    Add,
    Sub,
}

#[cfg(feature = "chrono")]
impl TsOp {
    fn str(&self) -> &'static str {
        match self {
            TsOp::Add => "add",
            TsOp::Sub => "sub",
        }
    }
}

/// Performs a checked arithmetic operation [`TsOp`] on a timestamp and a duration and ensures that
/// the resulting timestamp does not overflow the data type internal limits, as well as the timestamp
/// limits defined in the cel-spec. See [`MAX_TIMESTAMP`] and [`MIN_TIMESTAMP`] for more details.
#[cfg(feature = "chrono")]
fn checked_op(
    op: TsOp,
    lhs: &chrono::DateTime<chrono::FixedOffset>,
    rhs: &chrono::Duration,
) -> ResolveResult {
    // Add lhs and rhs together, checking for data type overflow
    let result = match op {
        TsOp::Add => lhs.checked_add_signed(*rhs),
        TsOp::Sub => lhs.checked_sub_signed(*rhs),
    }
    .ok_or_else(|| ExecutionError::Overflow(op.str(), (*lhs).into(), (*rhs).into()))?;

    // Check for cel-spec limits
    if result > *MAX_TIMESTAMP || result < *MIN_TIMESTAMP {
        Err(ExecutionError::Overflow(
            op.str(),
            (*lhs).into(),
            (*rhs).into(),
        ))
    } else {
        Value::Timestamp(result).into()
    }
}
