use crate::common::traits::Negator;
use crate::common::traits::{self, Comparer};
use crate::common::types::{CelDouble, CelString, CelUInt, Type};
use crate::common::value::{CowVal, StaticVal, Val};
use crate::{ExecutionError, Value};
use std::any::Any;
use std::cmp::Ordering;
use std::ops::Deref;

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, PartialOrd, Ord)]
/// A CEL `int`, of type [`INT_TYPE`](super::INT_TYPE): an `i64`.
///
/// Arithmetic takes another `int`, and fails on overflow, on division by zero
/// and on remainder by zero; `-` negates it, and fails on overflow too.
/// Comparisons and equality also take a `uint` or a `double`, and compare
/// numerically: `1 == 1u`, and `1 < 1.5`.
pub struct Int(i64);

impl Int {
    /// The `i64`.
    pub fn into_inner(self) -> i64 {
        self.0
    }

    /// A reference to the `i64`.
    pub fn inner(&self) -> &i64 {
        &self.0
    }
}

impl Deref for Int {
    type Target = i64;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Val for Int {
    fn get_type(&self) -> &Type {
        <Self as Val>::cel_type()
    }

    fn cel_type() -> &'static Type {
        &super::INT_TYPE
    }

    fn as_adder<'b, 'v>(&'b self) -> Option<&'b (dyn traits::Adder + 'v)>
    where
        Self: 'v,
    {
        Some(self)
    }

    fn as_comparer(&self) -> Option<&dyn traits::Comparer> {
        Some(self)
    }

    fn as_divider<'b, 'v>(&'b self) -> Option<&'b (dyn traits::Divider + 'v)>
    where
        Self: 'v,
    {
        Some(self)
    }

    fn as_modder<'b, 'v>(&'b self) -> Option<&'b (dyn traits::Modder + 'v)>
    where
        Self: 'v,
    {
        Some(self)
    }

    fn as_multiplier<'b, 'v>(&'b self) -> Option<&'b (dyn traits::Multiplier + 'v)>
    where
        Self: 'v,
    {
        Some(self)
    }

    fn as_negator<'b, 'v>(&'b self) -> Option<&'b (dyn Negator + 'v)>
    where
        Self: 'v,
    {
        Some(self)
    }

    fn as_subtractor<'b, 'v>(&'b self) -> Option<&'b (dyn traits::Subtractor + 'v)>
    where
        Self: 'v,
    {
        Some(self)
    }

    fn as_zeroer(&self) -> Option<&dyn traits::Zeroer> {
        Some(self)
    }

    fn equals(&self, other: &dyn Val) -> bool {
        self.compare(other)
            .map(|r| r == Ordering::Equal)
            .unwrap_or(false)
    }

    fn clone_as_boxed<'v>(&self) -> Box<dyn Val + 'v>
    where
        Self: 'v,
    {
        Box::new(*self)
    }

    fn as_any(&self) -> Option<&dyn Any> {
        Some(self)
    }
}

impl StaticVal for Int {}

impl traits::Adder for Int {
    fn add<'b, 'v>(&'b self, other: &(dyn Val + 'v)) -> Result<CowVal<'b, 'v>, ExecutionError>
    where
        Self: 'v,
    {
        if let Some(i) = other.downcast_ref::<Int>() {
            let t: Self = self
                .0
                .checked_add(i.0)
                .ok_or_else(|| ExecutionError::Overflow("add", self.0.into(), i.0.into()))?
                .into();
            Ok(CowVal::owned(t))
        } else {
            Err(ExecutionError::unsupported_binary_operator(
                "add", self, other,
            ))
        }
    }
}

impl traits::Comparer for Int {
    fn compare(&self, rhs: &dyn Val) -> Result<Ordering, ExecutionError> {
        if let Some(i) = rhs.downcast_ref::<Self>() {
            Ok(self.0.cmp(&i.0))
        } else if let Some(u) = rhs.downcast_ref::<CelUInt>() {
            Ok((*self.inner())
                .try_into()
                .map(|a: u64| a.cmp(u.inner()))
                // If the i64 doesn't fit into a u64 it must be less than 0.
                .unwrap_or(Ordering::Less))
        } else if let Some(d) = rhs.downcast_ref::<CelDouble>() {
            Ok((*self.inner() as f64)
                .partial_cmp(d.inner())
                .ok_or_else(|| ExecutionError::values_not_comparable(self, rhs))?)
        } else {
            Err(ExecutionError::values_not_comparable(self, rhs))
        }
    }
}

impl traits::Divider for Int {
    fn div<'b, 'v>(&'b self, rhs: &(dyn Val + 'v)) -> Result<CowVal<'b, 'v>, ExecutionError>
    where
        Self: 'v,
    {
        if let Some(i) = rhs.downcast_ref::<Int>() {
            if i.0 == 0 {
                return Err(ExecutionError::DivisionByZero(self.0.into()));
            }
            let t: Self = (self
                .0
                .checked_div(i.0)
                .ok_or_else(|| ExecutionError::Overflow("div", self.0.into(), i.0.into()))?)
            .into();
            Ok(CowVal::owned(t))
        } else {
            Err(ExecutionError::unsupported_binary_operator(
                "div", self, rhs,
            ))
        }
    }
}

impl traits::Modder for Int {
    fn modulo<'b, 'v>(&'b self, rhs: &(dyn Val + 'v)) -> Result<CowVal<'b, 'v>, ExecutionError>
    where
        Self: 'v,
    {
        if let Some(i) = rhs.downcast_ref::<Int>() {
            if i.0 == 0 {
                return Err(ExecutionError::RemainderByZero(self.0.into()));
            }
            let t: Self = (self
                .0
                .checked_rem(i.0)
                .ok_or_else(|| ExecutionError::Overflow("rem", self.0.into(), i.0.into()))?)
            .into();
            Ok(CowVal::owned(t))
        } else {
            Err(ExecutionError::unsupported_binary_operator(
                "rem", self, rhs,
            ))
        }
    }
}

impl traits::Multiplier for Int {
    fn mul<'b, 'v>(&'b self, rhs: &(dyn Val + 'v)) -> Result<CowVal<'b, 'v>, ExecutionError>
    where
        Self: 'v,
    {
        if let Some(i) = rhs.downcast_ref::<Int>() {
            let t: Self = (self
                .0
                .checked_mul(i.0)
                .ok_or_else(|| ExecutionError::Overflow("mul", self.0.into(), i.0.into()))?)
            .into();
            Ok(CowVal::owned(t))
        } else {
            Err(ExecutionError::unsupported_binary_operator(
                "mul", self, rhs,
            ))
        }
    }
}

impl Negator for Int {
    fn negate<'v>(&self) -> Result<Box<dyn Val + 'v>, ExecutionError>
    where
        Self: 'v,
    {
        let t: Self = self
            .0
            .checked_neg()
            .ok_or_else(|| ExecutionError::Overflow("negate", self.0.into(), Value::Null))?
            .into();
        Ok(Box::new(t))
    }
}

impl traits::Subtractor for Int {
    fn sub<'b, 'v>(&'b self, rhs: &(dyn Val + 'v)) -> Result<CowVal<'b, 'v>, ExecutionError>
    where
        Self: 'v,
    {
        if let Some(i) = rhs.downcast_ref::<Int>() {
            Ok(CowVal::owned(Self::from(
                self.0
                    .checked_sub(i.0)
                    .ok_or_else(|| ExecutionError::Overflow("sub", self.0.into(), i.0.into()))?,
            )))
        } else {
            Err(ExecutionError::unsupported_binary_operator(
                "sub", self, rhs,
            ))
        }
    }
}

impl traits::Zeroer for Int {
    fn is_zero_value(&self) -> bool {
        self.0 == 0
    }
}

impl From<Int> for i64 {
    fn from(value: Int) -> Self {
        value.0
    }
}

impl From<i64> for Int {
    fn from(value: i64) -> Self {
        Self(value)
    }
}

impl<'v> TryFrom<Box<dyn Val + 'v>> for i64 {
    type Error = Box<dyn Val + 'v>;

    fn try_from(value: Box<dyn Val + 'v>) -> Result<Self, Self::Error> {
        if let Some(i) = value.downcast_ref::<Int>() {
            return Ok(i.0);
        }
        Err(value)
    }
}

impl<'a, 'v> TryFrom<&'a (dyn Val + 'v)> for &'a i64 {
    type Error = &'a (dyn Val + 'v);

    fn try_from(value: &'a (dyn Val + 'v)) -> Result<Self, Self::Error> {
        if let Some(i) = value.downcast_ref::<Int>() {
            return Ok(&i.0);
        }
        Err(value)
    }
}

fn int_from_int(this: &Int) -> Int {
    *this
}

fn int_from_uint(this: &CelUInt) -> Result<Int, ExecutionError> {
    match i64::try_from(*this.inner()) {
        Ok(value) => Ok(Int::from(value)),
        Err(_) => Err(ExecutionError::FunctionError {
            function: "int".to_owned(),
            message: "integer overflow".to_owned(),
        }),
    }
}

fn int_from_double(this: &CelDouble) -> Result<Int, ExecutionError> {
    let value = *this.inner();
    // Double to int conversions are limited to (minInt, maxInt) non-inclusive.
    // 'i64::MAX as f64' rounds up to 2^63, and the largest double below that
    // is 2^63 - 2^10, so the check also keeps 'value as i64' from saturating.
    // 'i64::MIN as f64' is exactly -(2^63), so the exclusive lower bound
    // rejects a double that i64 could actually hold. NaN, -infinity and
    // infinity will also be rejected.
    if !(value > (i64::MIN as f64) && value < (i64::MAX as f64)) {
        Err(ExecutionError::FunctionError {
            function: "int".to_owned(),
            message: "integer overflow".to_owned(),
        })
    } else {
        Ok(Int::from(value as i64))
    }
}

fn int_from_string(this: &CelString<'_>) -> Result<Int, ExecutionError> {
    this.inner()
        .parse::<i64>()
        .map(Int::from)
        .map_err(|e| ExecutionError::FunctionError {
            function: "int".to_owned(),
            message: format!("string parse error: {e}"),
        })
}

pub(crate) fn stdlib(env: &mut crate::Env) {
    env.add_type(crate::common::types::INT_TYPE)
        .expect("Must be unique");
    crate::add_overload!(env, fn int_from_int: (Int) -> Int,
        name = "int", id = "int64_to_int64")
    .expect("Must be unique id");
    crate::add_overload!(env, fn int_from_uint: (CelUInt) -> Result<Int>,
        name = "int", id = "uint64_to_int64")
    .expect("Must be unique id");
    crate::add_overload!(env, fn int_from_double: (CelDouble) -> Result<Int>,
        name = "int", id = "double_to_int64")
    .expect("Must be unique id");
    crate::add_overload!(env, fn int_from_string: (CelString) -> Result<Int>,
        name = "int", id = "string_to_int64")
    .expect("Must be unique id");
}
