//! serde integration: convert any [`serde::Serialize`] type into a [`Value`].
//!
//! Available only with the `serde` feature. This is the *eager* path: like
//! [`ToValue`](crate::ToValue), serializing walks the whole value and
//! materializes a full [`Value`] tree. The point of it, over a hand-written
//! `ToValue` impl, is that there's no boilerplate: any `#[derive(Serialize)]`
//! type becomes template data.
//!
//! Two entry points, both fallible (serde serialization can fail on
//! unrepresentable map keys or out-of-range 128-bit integers):
//! - the free function [`to_value`], mirroring `serde_json::to_value`, and
//! - the [`ToSerdeValue`] extension trait, giving a `.to_serde_value()` method
//!   on every `Serialize` type.
//!
//! # Field-name casing
//!
//! Go templates access exported PascalCase fields (`{{.Name}}`), but serde
//! derives field names verbatim from the Rust identifiers (`name`). Add
//! `#[serde(rename_all = "PascalCase")]` (or a per-field `#[serde(rename = "...")]`)
//! so the map keys match what the template dots into.
//!
//! # Map keys
//!
//! [`Value::Map`] is string-keyed, so a non-string map key (an integer, `bool`,
//! or `char`) is stringified via its `Display` impl, so `1u32` becomes `"1"`.
//! Because the resulting keys are ordinary strings, `{{range}}` iterates them in
//! **lexical** order, not the key's natural order. This differs from Go, which
//! sorts numeric map keys numerically: a `map[int]V` with keys `1, 2, 10` ranges
//! as `1, 2, 10` in Go but as `1, 10, 2` here. Compound keys (structs, tuples,
//! sequences) cannot be stringified and produce an error.
//!
//! # Examples
//!
//! ```
//! use gotmpl::{to_value, Value};
//! use serde::Serialize;
//!
//! #[derive(Serialize)]
//! #[serde(rename_all = "PascalCase")]
//! struct User { name: String, age: u8 }
//!
//! let v = to_value(&User { name: "Alice".into(), age: 30 }).unwrap();
//! assert_eq!(v.field("Name"), Some(&Value::String("Alice".into())));
//! assert_eq!(v.field("Age"), Some(&Value::Uint(30)));
//! ```

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;

use serde::Serialize;
use serde::ser::{self, Impossible};

use crate::error::{Result, TemplateError};
use crate::value::Value;

/// Convert a [`serde::Serialize`] value into a template [`Value`].
///
/// The eager counterpart to [`ToValue`](crate::ToValue) for serde types.
/// Mirrors `serde_json::to_value`, but borrows its argument (`&T`) rather than
/// consuming it, so the source value stays usable afterwards. See the
/// [module docs](self) for the serde-to-`Value` mapping and the field-name
/// casing note.
///
/// # Errors
///
/// Returns [`TemplateError::Exec`] if the value cannot be represented: a map
/// key that does not serialize to a string, or an `i128`/`u128` outside the
/// `i64`/`u64` range.
pub fn to_value<T: ?Sized + Serialize>(value: &T) -> Result<Value> {
    value.serialize(ValueSerializer)
}

/// Extension trait adding [`to_serde_value`](ToSerdeValue::to_serde_value) to
/// every [`serde::Serialize`] type.
///
/// A thin method-style wrapper over [`to_value`]. Named `to_serde_value` rather
/// than `to_value` so it never collides with [`ToValue::to_value`](crate::ToValue::to_value)
/// on types (like `String` or `i32`) that implement both traits.
///
/// # Examples
///
/// ```
/// use gotmpl::{ToSerdeValue, Value};
///
/// let v = 42u32.to_serde_value().unwrap();
/// assert_eq!(v, Value::Uint(42));
/// ```
pub trait ToSerdeValue {
    /// Convert `self` into a template [`Value`] via its [`serde::Serialize`] impl.
    ///
    /// # Errors
    ///
    /// See [`to_value`].
    fn to_serde_value(&self) -> Result<Value>;
}

impl<T: Serialize + ?Sized> ToSerdeValue for T {
    fn to_serde_value(&self) -> Result<Value> {
        to_value(self)
    }
}

/// A [`serde::Serializer`] that produces a [`Value`]. Modelled on
/// `serde_json::value::Serializer`.
struct ValueSerializer;

macro_rules! serialize_int {
    ($($method:ident($ty:ty) => $variant:ident;)*) => {
        $(fn $method(self, v: $ty) -> Result<Value> {
            Ok(Value::$variant(v as _))
        })*
    };
}

impl ser::Serializer for ValueSerializer {
    type Ok = Value;
    type Error = TemplateError;

    type SerializeSeq = SerializeVec;
    type SerializeTuple = SerializeVec;
    type SerializeTupleStruct = SerializeVec;
    type SerializeTupleVariant = SerializeTupleVariant;
    type SerializeMap = SerializeMap;
    type SerializeStruct = SerializeMap;
    type SerializeStructVariant = SerializeStructVariant;

    serialize_int! {
        serialize_i8(i8) => Int;
        serialize_i16(i16) => Int;
        serialize_i32(i32) => Int;
        serialize_i64(i64) => Int;
        serialize_u8(u8) => Uint;
        serialize_u16(u16) => Uint;
        serialize_u32(u32) => Uint;
        serialize_u64(u64) => Uint;
    }

    fn serialize_bool(self, v: bool) -> Result<Value> {
        Ok(Value::Bool(v))
    }

    fn serialize_i128(self, v: i128) -> Result<Value> {
        i64::try_from(v).map(Value::Int).map_err(|_| {
            TemplateError::Exec(format!("i128 value {v} out of range for a template int"))
        })
    }

    fn serialize_u128(self, v: u128) -> Result<Value> {
        u64::try_from(v).map(Value::Uint).map_err(|_| {
            TemplateError::Exec(format!("u128 value {v} out of range for a template uint"))
        })
    }

    fn serialize_f32(self, v: f32) -> Result<Value> {
        Ok(Value::Float(v as f64))
    }

    fn serialize_f64(self, v: f64) -> Result<Value> {
        Ok(Value::Float(v))
    }

    fn serialize_char(self, v: char) -> Result<Value> {
        let mut buf = [0u8; 4];
        Ok(Value::String(Arc::from(&*v.encode_utf8(&mut buf))))
    }

    fn serialize_str(self, v: &str) -> Result<Value> {
        Ok(v.into())
    }

    fn serialize_bytes(self, v: &[u8]) -> Result<Value> {
        // Matches serde_json: a byte slice becomes a list of numbers.
        Ok(v.iter()
            .map(|b| Value::Uint(u64::from(*b)))
            .collect::<Vec<_>>()
            .into())
    }

    fn serialize_none(self) -> Result<Value> {
        Ok(Value::Nil)
    }

    fn serialize_some<T: ?Sized + Serialize>(self, value: &T) -> Result<Value> {
        value.serialize(self)
    }

    fn serialize_unit(self) -> Result<Value> {
        Ok(Value::Nil)
    }

    fn serialize_unit_struct(self, _name: &'static str) -> Result<Value> {
        Ok(Value::Nil)
    }

    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
    ) -> Result<Value> {
        Ok(Value::String(Arc::from(variant)))
    }

    fn serialize_newtype_struct<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<Value> {
        value.serialize(self)
    }

    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<Value> {
        Ok(singleton_map(Arc::from(variant), to_value(value)?))
    }

    fn serialize_seq(self, len: Option<usize>) -> Result<SerializeVec> {
        Ok(SerializeVec {
            vec: Vec::with_capacity(len.unwrap_or(0)),
        })
    }

    fn serialize_tuple(self, len: usize) -> Result<SerializeVec> {
        self.serialize_seq(Some(len))
    }

    fn serialize_tuple_struct(self, _name: &'static str, len: usize) -> Result<SerializeVec> {
        self.serialize_seq(Some(len))
    }

    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<SerializeTupleVariant> {
        Ok(SerializeTupleVariant {
            variant: Arc::from(variant),
            vec: Vec::with_capacity(len),
        })
    }

    fn serialize_map(self, _len: Option<usize>) -> Result<SerializeMap> {
        Ok(SerializeMap {
            map: BTreeMap::new(),
            next_key: None,
        })
    }

    fn serialize_struct(self, _name: &'static str, _len: usize) -> Result<SerializeMap> {
        Ok(SerializeMap {
            map: BTreeMap::new(),
            next_key: None,
        })
    }

    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
        _len: usize,
    ) -> Result<SerializeStructVariant> {
        Ok(SerializeStructVariant {
            variant: Arc::from(variant),
            map: BTreeMap::new(),
        })
    }
}

/// Build a single-entry `Value::Map`, used for serde's externally-tagged
/// enum representations (newtype/tuple/struct variants).
fn singleton_map(key: Arc<str>, value: Value) -> Value {
    let mut map = BTreeMap::new();
    map.insert(key, value);
    map.into()
}

/// Accumulator for sequences and tuples → [`Value::List`].
struct SerializeVec {
    vec: Vec<Value>,
}

impl ser::SerializeSeq for SerializeVec {
    type Ok = Value;
    type Error = TemplateError;

    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<()> {
        self.vec.push(to_value(value)?);
        Ok(())
    }

    fn end(self) -> Result<Value> {
        Ok(self.vec.into())
    }
}

impl ser::SerializeTuple for SerializeVec {
    type Ok = Value;
    type Error = TemplateError;

    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<()> {
        ser::SerializeSeq::serialize_element(self, value)
    }

    fn end(self) -> Result<Value> {
        ser::SerializeSeq::end(self)
    }
}

impl ser::SerializeTupleStruct for SerializeVec {
    type Ok = Value;
    type Error = TemplateError;

    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<()> {
        ser::SerializeSeq::serialize_element(self, value)
    }

    fn end(self) -> Result<Value> {
        ser::SerializeSeq::end(self)
    }
}

/// Accumulator for a tuple enum variant → externally-tagged
/// `{ variant: [elements…] }`.
struct SerializeTupleVariant {
    variant: Arc<str>,
    vec: Vec<Value>,
}

impl ser::SerializeTupleVariant for SerializeTupleVariant {
    type Ok = Value;
    type Error = TemplateError;

    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<()> {
        self.vec.push(to_value(value)?);
        Ok(())
    }

    fn end(self) -> Result<Value> {
        Ok(singleton_map(self.variant, self.vec.into()))
    }
}

/// Accumulator for maps and structs → [`Value::Map`].
struct SerializeMap {
    map: BTreeMap<Arc<str>, Value>,
    next_key: Option<Arc<str>>,
}

impl ser::SerializeMap for SerializeMap {
    type Ok = Value;
    type Error = TemplateError;

    fn serialize_key<T: ?Sized + Serialize>(&mut self, key: &T) -> Result<()> {
        self.next_key = Some(key.serialize(MapKeySerializer)?);
        Ok(())
    }

    fn serialize_value<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<()> {
        let key = self.next_key.take().ok_or_else(|| {
            <TemplateError as ser::Error>::custom("serialize_value called before serialize_key")
        })?;
        self.map.insert(key, to_value(value)?);
        Ok(())
    }

    fn end(self) -> Result<Value> {
        Ok(self.map.into())
    }
}

impl ser::SerializeStruct for SerializeMap {
    type Ok = Value;
    type Error = TemplateError;

    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<()> {
        self.map.insert(Arc::from(key), to_value(value)?);
        Ok(())
    }

    fn end(self) -> Result<Value> {
        Ok(self.map.into())
    }
}

/// Accumulator for a struct enum variant → externally-tagged
/// `{ variant: { fields… } }`.
struct SerializeStructVariant {
    variant: Arc<str>,
    map: BTreeMap<Arc<str>, Value>,
}

impl ser::SerializeStructVariant for SerializeStructVariant {
    type Ok = Value;
    type Error = TemplateError;

    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<()> {
        self.map.insert(Arc::from(key), to_value(value)?);
        Ok(())
    }

    fn end(self) -> Result<Value> {
        Ok(singleton_map(self.variant, self.map.into()))
    }
}

/// Serializes a map key into an `Arc<str>`. Accepts strings and stringifies
/// primitive keys (bool, char, integers); rejects everything else. This is the
/// same policy as `serde_json`, since [`Value::Map`] is string-keyed.
struct MapKeySerializer;

fn key_must_be_string() -> TemplateError {
    TemplateError::Exec("map key must serialize to a string or primitive".into())
}

macro_rules! serialize_key_via_display {
    ($($method:ident($ty:ty);)*) => {
        $(fn $method(self, v: $ty) -> Result<Arc<str>> {
            Ok(Arc::from(v.to_string().as_str()))
        })*
    };
}

/// Every serde `serialize_*` form that can't produce a string key rejects with
/// the same error; list them declaratively instead of writing each body out.
macro_rules! reject_key {
    ($($method:ident($($param:ident: $ty:ty),*) -> $ret:ty;)*) => {
        $(fn $method(self, $($param: $ty),*) -> Result<$ret> {
            Err(key_must_be_string())
        })*
    };
}

impl ser::Serializer for MapKeySerializer {
    type Ok = Arc<str>;
    type Error = TemplateError;

    type SerializeSeq = Impossible<Arc<str>, TemplateError>;
    type SerializeTuple = Impossible<Arc<str>, TemplateError>;
    type SerializeTupleStruct = Impossible<Arc<str>, TemplateError>;
    type SerializeTupleVariant = Impossible<Arc<str>, TemplateError>;
    type SerializeMap = Impossible<Arc<str>, TemplateError>;
    type SerializeStruct = Impossible<Arc<str>, TemplateError>;
    type SerializeStructVariant = Impossible<Arc<str>, TemplateError>;

    serialize_key_via_display! {
        serialize_bool(bool);
        serialize_i8(i8);
        serialize_i16(i16);
        serialize_i32(i32);
        serialize_i64(i64);
        serialize_i128(i128);
        serialize_u8(u8);
        serialize_u16(u16);
        serialize_u32(u32);
        serialize_u64(u64);
        serialize_u128(u128);
        serialize_char(char);
    }

    fn serialize_str(self, v: &str) -> Result<Arc<str>> {
        Ok(Arc::from(v))
    }

    // A newtype struct is transparent, so serialize the inner key.
    fn serialize_newtype_struct<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<Arc<str>> {
        value.serialize(self)
    }

    // A unit variant serializes as its name, which is a valid string key.
    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
    ) -> Result<Arc<str>> {
        Ok(Arc::from(variant))
    }

    // The two forms carrying a `?Sized + Serialize` payload can't go through
    // the macro (it doesn't take type parameters); the rest do.
    fn serialize_some<T: ?Sized + Serialize>(self, _value: &T) -> Result<Arc<str>> {
        Err(key_must_be_string())
    }
    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _value: &T,
    ) -> Result<Arc<str>> {
        Err(key_must_be_string())
    }

    reject_key! {
        serialize_f32(_v: f32) -> Arc<str>;
        serialize_f64(_v: f64) -> Arc<str>;
        serialize_bytes(_v: &[u8]) -> Arc<str>;
        serialize_none() -> Arc<str>;
        serialize_unit() -> Arc<str>;
        serialize_unit_struct(_name: &'static str) -> Arc<str>;
        serialize_seq(_len: Option<usize>) -> Self::SerializeSeq;
        serialize_tuple(_len: usize) -> Self::SerializeTuple;
        serialize_tuple_struct(_name: &'static str, _len: usize) -> Self::SerializeTupleStruct;
        serialize_tuple_variant(_name: &'static str, _index: u32, _variant: &'static str, _len: usize) -> Self::SerializeTupleVariant;
        serialize_map(_len: Option<usize>) -> Self::SerializeMap;
        serialize_struct(_name: &'static str, _len: usize) -> Self::SerializeStruct;
        serialize_struct_variant(_name: &'static str, _index: u32, _variant: &'static str, _len: usize) -> Self::SerializeStructVariant;
    }
}
