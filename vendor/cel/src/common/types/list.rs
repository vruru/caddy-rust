use crate::common::traits::{Adder, Container, Indexer, Iterable, Sizer, Zeroer};
use crate::common::types::map::double_to_int_lossless;
use crate::common::types::{CelDouble, CelInt, CelUInt, Kind, Type};
use crate::common::value::{Builtin, BuiltinRef, CowVal, Val};
use crate::common::{traits, types};
use crate::ExecutionError;
use std::ops::Deref;

/// A CEL list whose elements may borrow data for `'v`.
///
/// Of type [`LIST_TYPE`](super::LIST_TYPE), `list(dyn)`, whatever its
/// elements, which can be values of any type. It supports `+` with any
/// [`Iterable`] on the right, `in` (an element [equals](Val::equals) the
/// value), `[i]` with an `int`, `uint` or whole `double` index, `size()`, and
/// the comprehensions, which iterate over its elements in order. Two lists
/// are equal when their elements are, pairwise.
#[derive(Debug, Default)]
pub struct DefaultList<'v>(Vec<Box<dyn Val + 'v>>);

impl<'v> DefaultList<'v> {
    /// The elements.
    pub fn into_inner(self) -> Vec<Box<dyn Val + 'v>> {
        self.0
    }

    /// The elements, borrowed from `self`.
    pub fn inner(&self) -> &[Box<dyn Val + 'v>] {
        &self.0
    }
}

impl<'v> Clone for DefaultList<'v> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<'v> Deref for DefaultList<'v> {
    type Target = [Box<dyn Val + 'v>];

    fn deref(&self) -> &Self::Target {
        self.inner()
    }
}

impl<'v> Val for DefaultList<'v> {
    fn get_type(&self) -> &Type {
        <Self as Val>::cel_type()
    }

    fn cel_type() -> &'static Type {
        &types::LIST_TYPE
    }

    fn as_adder<'b, 'w>(&'b self) -> Option<&'b (dyn Adder + 'w)>
    where
        Self: 'w,
    {
        Some(self)
    }

    fn as_container(&self) -> Option<&dyn Container> {
        Some(self)
    }

    fn as_indexer<'b, 'w>(&'b self) -> Option<&'b (dyn Indexer + 'w)>
    where
        Self: 'w,
    {
        Some(self)
    }

    fn into_indexer<'w>(self: Box<Self>) -> Option<Box<dyn Indexer + 'w>>
    where
        Self: 'w,
    {
        Some(self)
    }

    fn as_iterable<'b, 'w>(&'b self) -> Option<&'b (dyn Iterable + 'w)>
    where
        Self: 'w,
    {
        Some(self)
    }

    fn as_sizer(&self) -> Option<&dyn Sizer> {
        Some(self)
    }

    fn as_zeroer(&self) -> Option<&dyn Zeroer> {
        Some(self)
    }

    fn equals(&self, other: &dyn Val) -> bool {
        other.downcast_ref::<DefaultList>().is_some_and(|other| {
            self.0.len() == other.0.len()
                && self
                    .0
                    .iter()
                    .zip(other.0.iter())
                    .all(|(a, b)| a.equals(b.as_ref()))
        })
    }

    fn clone_as_boxed<'w>(&self) -> Box<dyn Val + 'w>
    where
        Self: 'w,
    {
        Box::new(self.clone())
    }

    fn as_builtin<'b, 'w>(&'b self) -> BuiltinRef<'b, 'w>
    where
        Self: 'w,
    {
        BuiltinRef::List(self)
    }

    fn into_builtin<'w>(self: Box<Self>) -> Option<Builtin<'w>>
    where
        Self: 'w,
    {
        Some(Builtin::List(*self))
    }
}

impl<'v> Adder for DefaultList<'v> {
    fn add<'b, 'w>(&'b self, rhs: &(dyn Val + 'w)) -> Result<CowVal<'b, 'w>, ExecutionError>
    where
        Self: 'w,
    {
        let mut rhs = rhs
            .as_iterable()
            .ok_or_else(|| ExecutionError::unsupported_binary_operator("add", self, rhs))?
            .iter();
        let mut list: Vec<Box<dyn Val + 'w>> = self.0.iter().map(|i| i.clone_as_boxed()).collect();
        while let Some(other) = rhs.next() {
            list.push(other.clone_as_boxed());
        }
        Ok(CowVal::owned(DefaultList(list)))
    }
}

impl Container for DefaultList<'_> {
    fn contains(&self, value: &dyn Val) -> Result<bool, ExecutionError> {
        for i in &self.0 {
            if i.equals(value) {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

fn index(list: &dyn Val, idx: &dyn Val) -> Result<usize, ExecutionError> {
    match idx.get_type().kind() {
        Kind::Int => {
            let idx: i64 = *idx
                .downcast_ref::<CelInt>()
                .ok_or_else(|| ExecutionError::overload_for_values("_[_]", [list, idx], false))?
                .inner();
            usize::try_from(idx).map_err(|_| ExecutionError::IndexOutOfBounds(idx.into()))
        }
        Kind::UInt => {
            let idx: u64 = *idx
                .downcast_ref::<CelUInt>()
                .ok_or_else(|| ExecutionError::overload_for_values("_[_]", [list, idx], false))?
                .inner();
            usize::try_from(idx).map_err(|_| ExecutionError::IndexOutOfBounds(idx.into()))
        }
        Kind::Double => {
            let d: f64 = *idx
                .downcast_ref::<CelDouble>()
                .ok_or_else(|| ExecutionError::overload_for_values("_[_]", [list, idx], false))?
                .inner();
            // Whole-number doubles index like an int; fractional ones have no overload.
            let idx = double_to_int_lossless(d).ok_or_else(|| {
                ExecutionError::UnsupportedIndex(
                    idx.try_into().unwrap_or(crate::Value::Null),
                    list.try_into().unwrap_or(crate::Value::Null),
                )
            })?;
            usize::try_from(idx).map_err(|_| ExecutionError::IndexOutOfBounds(idx.into()))
        }
        _ => Err(ExecutionError::UnexpectedType {
            got: idx.get_type().runtime_type_name.to_string(),
            want: format!(
                "{}|{}|{}",
                types::INT_TYPE.runtime_type_name,
                types::UINT_TYPE.runtime_type_name,
                types::DOUBLE_TYPE.runtime_type_name
            ),
        }),
    }
}

fn out_of_bounds(idx: &dyn Val) -> ExecutionError {
    ExecutionError::IndexOutOfBounds(idx.try_into().unwrap_or(crate::Value::Null))
}

impl<'v> Indexer for DefaultList<'v> {
    fn get<'b, 'w>(&'b self, idx: &dyn Val) -> Result<CowVal<'b, 'w>, ExecutionError>
    where
        Self: 'w,
    {
        let i = index(self, idx)?;
        self.0
            .get(i)
            .map(|v| CowVal::Borrowed(v.as_ref()))
            .ok_or_else(|| out_of_bounds(idx))
    }

    fn steal<'w>(self: Box<Self>, idx: &dyn Val) -> Result<Box<dyn Val + 'w>, ExecutionError>
    where
        Self: 'w,
    {
        let mut list = self;
        let i = index(list.as_ref(), idx)?;
        if i >= list.0.len() {
            return Err(out_of_bounds(idx));
        }
        Ok(list.0.swap_remove(i))
    }
}

impl<'v> Iterable for DefaultList<'v> {
    fn iter<'b, 'w>(&'b self) -> Box<dyn traits::Iterator<'b, 'w> + 'b>
    where
        Self: 'w,
    {
        Box::new(SliceIterator::new(self.0.as_slice()))
    }
}

impl Sizer for DefaultList<'_> {
    fn size(&self) -> CelInt {
        (self.inner().len() as i64).into()
    }
}

impl Zeroer for DefaultList<'_> {
    fn is_zero_value(&self) -> bool {
        self.inner().is_empty()
    }
}

impl<'v> From<Vec<Box<dyn Val + 'v>>> for DefaultList<'v> {
    fn from(v: Vec<Box<dyn Val + 'v>>) -> Self {
        Self(v)
    }
}

impl<'v> TryFrom<Box<dyn Val + 'v>> for Vec<Box<dyn Val + 'v>> {
    type Error = Box<dyn Val + 'v>;

    fn try_from(value: Box<dyn Val + 'v>) -> Result<Self, Self::Error> {
        match super::into_builtin(value) {
            Ok(Builtin::List(l)) => Ok(l.into_inner()),
            Ok(other) => Err(other.into_boxed()),
            Err(value) => Err(value),
        }
    }
}

impl<'a, 'v> TryFrom<&'a (dyn Val + 'v)> for &'a [Box<dyn Val + 'v>] {
    type Error = &'a (dyn Val + 'v);

    fn try_from(value: &'a (dyn Val + 'v)) -> Result<Self, Self::Error> {
        if let Some(list) = value.downcast_ref::<DefaultList>() {
            return Ok(list.inner());
        }
        Err(value)
    }
}

pub struct SliceIterator<'b, 'v> {
    list: &'b [Box<dyn Val + 'v>],
    pos: usize,
}

impl<'b, 'v> SliceIterator<'b, 'v> {
    fn new(list: &'b [Box<dyn Val + 'v>]) -> Self {
        Self { list, pos: 0 }
    }
}

impl<'b, 'v: 'w, 'w> traits::Iterator<'b, 'w> for SliceIterator<'b, 'v> {
    fn next(&mut self) -> Option<&'b (dyn Val + 'w)> {
        if self.pos >= self.list.len() {
            None
        } else {
            let r = &self.list[self.pos];
            self.pos += 1;
            Some(r.as_ref())
        }
    }
}

/// A list under construction, appended to in place.
///
/// `MutableList` is an internal helper used by the comprehension evaluator
/// (see [`crate::objects::Value::resolve_val`]) to build up the accumulator
/// of `map` / `filter` comprehensions, avoiding the quadratic
/// clone-on-add cost that a [`DefaultList`] would incur when the
/// comprehension expands to `@result = @result + [expr]` on every iteration.
///
/// It is deliberately not a [`Val`]: the evaluator owns it for the duration
/// of the loop and never binds it to a variable, so no expression can observe
/// it half-built. Appending goes through [`MutableList::extend`] rather than
/// [`Adder`], because growing the list in place is only sound for elements
/// that live as long as the list does (`'v`), which the generic
/// `Adder::add<'b, 'w>` cannot express. When the loop completes, the
/// evaluator converts it into a [`DefaultList`] via
/// [`MutableList::to_immutable`].
#[derive(Debug, Default)]
#[doc(hidden)]
pub struct MutableList<'v>(Vec<Box<dyn Val + 'v>>);

impl<'v> MutableList<'v> {
    pub fn with_capacity(cap: usize) -> Self {
        Self(Vec::with_capacity(cap))
    }

    /// Appends a copy of every element of `rhs`, which must be a list.
    pub fn extend(&mut self, rhs: &(dyn Val + 'v)) -> Result<(), ExecutionError> {
        let mut items = rhs
            .as_iterable()
            .ok_or_else(|| ExecutionError::UnexpectedType {
                got: rhs.get_type().name().to_owned(),
                want: "iterable".to_owned(),
            })?
            .iter();
        while let Some(item) = items.next() {
            self.0.push(item.clone_as_boxed());
        }
        Ok(())
    }

    /// Converts the mutable list into an immutable [`DefaultList`], reusing
    /// the backing storage.
    pub fn to_immutable(self) -> DefaultList<'v> {
        DefaultList(self.0)
    }


}

pub(crate) fn stdlib(env: &mut crate::Env) {
    env.add_type(crate::common::types::LIST_TYPE)
        .expect("Must be unique");
    env.add_overload(
        "size",
        "size_list",
        vec![super::LIST_TYPE],
        traits::adapter::sizer_size,
    )
    .expect("Must be unique id");
    env.add_member_overload(
        "size",
        "list_size",
        super::LIST_TYPE,
        vec![],
        traits::adapter::sizer_size,
    )
    .expect("Must be unique id");
}
