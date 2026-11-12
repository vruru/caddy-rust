#[cfg(feature = "ext_encoders")]
mod encoders;
mod lists;
mod math;
mod strings;

#[cfg(feature = "ext_encoders")]
pub use encoders::extension as encoders;
pub use lists::extension as lists;
pub use math::extension as math;
pub use strings::extension as strings;

use crate::common::traits::Iterable;
use crate::common::value::{FromVal, Val};
use crate::ExecutionError;

/// `list` as an iterable, for an overload that takes any `list`, not just a
/// `CelList`.
fn iterable<'b, 'v>(list: &'b (dyn Val + 'v)) -> Result<&'b (dyn Iterable + 'v), ExecutionError> {
    list.as_iterable()
        .ok_or_else(|| ExecutionError::UnexpectedType {
            got: list.get_type().name().to_owned(),
            want: "iterable".to_owned(),
        })
}

/// `val` downcast to the `T` its overload was registered with.
fn arg<'b, 'v, T: FromVal<'b, 'v> + Val>(val: &'b (dyn Val + 'v)) -> Result<&'b T, ExecutionError> {
    val.downcast_ref::<T>()
        .ok_or_else(|| ExecutionError::UnexpectedType {
            got: val.get_type().name().to_owned(),
            want: T::cel_type().name().to_owned(),
        })
}
