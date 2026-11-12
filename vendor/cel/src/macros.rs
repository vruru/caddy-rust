#[macro_export]
macro_rules! impl_conversions {
    // Capture triples separated by commas: the Rust type a function signature can
    // use, the `Value` variant it corresponds to at the library boundary, and the
    // concrete `Val` implementation that backs it internally. The latter lets both
    // argument extraction and return-value construction go straight to/from the
    // `Val`, without materializing an intermediate `Value`.
    ($($target_type:ty => $value_variant:path as $cel_type:ty),* $(,)?) => {
        $(
            impl From<$target_type> for Value {
                fn from(value: $target_type) -> Self {
                    $value_variant(value)
                }
            }

            impl<'context, 'call> $crate::magic::IntoResolveResult<'context, 'call> for $target_type {
                fn into_resolve_result(self) -> Result<$crate::common::value::CowVal<'context, 'call>, ExecutionError> {
                    Ok($crate::common::value::CowVal::owned(<$cel_type>::from(self)))
                }
            }

            impl<'context, 'call> $crate::magic::IntoResolveResult<'context, 'call> for Result<$target_type, ExecutionError> {
                fn into_resolve_result(self) -> Result<$crate::common::value::CowVal<'context, 'call>, ExecutionError> {
                    $crate::magic::IntoResolveResult::into_resolve_result(self?)
                }
            }

            impl<'a, 'context, 'call> FromContext<'a, 'context, 'call> for $target_type {
                fn from_context(ctx: &'a mut FunctionContext<'context, 'call>) -> Result<Self, ExecutionError>
                where
                    Self: Sized,
                {
                    $crate::magic::arg_val_from_context(ctx)
                        .and_then(|v| $crate::magic::FromVal::from_val(v.as_ref()))
                }
            }
        )*
    }
}

#[macro_export]
macro_rules! impl_handler {
    ($($t:ty),*) => {
        pastey::paste! {
            impl<F, $($t,)* R> IntoFunction<($($t,)*)> for F
            where
                F: Fn($($t,)*) -> R + Send + Sync + 'static,
                $($t: for<'a, 'context, 'call> $crate::FromContext<'a, 'context, 'call>,)*
                R: for<'context, 'call> IntoResolveResult<'context, 'call>,
            {
                fn into_function(self) -> Function {
                    Box::new(move |_ftx| {
                        $(
                            let [<arg_ $t:lower>] = $t::from_context(_ftx)?;
                        )*
                        self($([<arg_ $t:lower>],)*).into_resolve_result()
                    })
                }
            }

            impl<F, $($t,)* R> IntoFunction<(WithFunctionContext, $($t,)*)> for F
            where
                F: Fn(&FunctionContext, $($t,)*) -> R + Send + Sync + 'static,
                $($t: for<'a, 'context, 'call> $crate::FromContext<'a, 'context, 'call>,)*
                R: for<'context, 'call> IntoResolveResult<'context, 'call>,
            {
                fn into_function(self) -> Function {
                    Box::new(move |_ftx| {
                        $(
                            let [<arg_ $t:lower>] = $t::from_context(_ftx)?;
                        )*
                        self(_ftx, $([<arg_ $t:lower>],)*).into_resolve_result()
                    })
                }
            }
        }
    };
}

pub(crate) use impl_conversions;

/// Converts a Rust `snake_case` identifier to CEL `camelCase`.
///
/// Used by [`add_overload!`](crate::add_overload) and
/// [`add_member_overload!`](crate::add_member_overload) to derive the default
/// CEL name from the Rust fn ident. Leading and trailing underscores are
/// dropped; internal runs of underscores collapse (i.e. `foo__bar` becomes
/// `fooBar`). Non-alphabetic characters are left as-is.
#[doc(hidden)]
pub fn to_camel_case(snake: &str) -> String {
    let mut out = String::with_capacity(snake.len());
    let mut upper_next = false;
    for c in snake.chars() {
        if c == '_' {
            upper_next = !out.is_empty();
        } else if upper_next {
            out.push(c.to_ascii_uppercase());
            upper_next = false;
        } else {
            out.push(c);
        }
    }
    out
}

/// How a registered fn hands its result back, and the conversion into a
/// [`CowVal`](crate::common::value::CowVal). Not for direct use.
///
/// The `$ret` the caller wrote in the macro is used as the type annotation on
/// the call's result, so a fn whose return type does not match is a compile
/// error at the registration site rather than a surprise at runtime.
#[doc(hidden)]
#[macro_export]
macro_rules! __overload_result {
    // `-> T`: an owned value, boxed into the `CowVal`.
    (owned, $ret:ty, $call:expr) => {{
        let __v: $ret = $call;
        ::std::result::Result::Ok($crate::common::value::CowVal::owned(__v))
    }};
    // `-> &T`: kept as a borrow. The reference has to outlive the call, so it
    // cannot point into the arguments - those are owned by the wrapper.
    (borrowed, $ret:ty, $call:expr) => {{
        let __v: &$ret = $call;
        ::std::result::Result::Ok($crate::common::value::CowVal::Borrowed(__v))
    }};
    // `-> Result<T>`: as `owned`, short-circuiting on the error.
    (try_owned, $ret:ty, $call:expr) => {{
        let __v: $ret = $call?;
        ::std::result::Result::Ok($crate::common::value::CowVal::owned(__v))
    }};
    // `-> Result<&T>`: as `borrowed`, short-circuiting on the error.
    (try_borrowed, $ret:ty, $call:expr) => {{
        let __v: &$ret = $call?;
        ::std::result::Result::Ok($crate::common::value::CowVal::Borrowed(__v))
    }};
}

/// Register a member-function overload on an `Env` from a typed Rust `fn`
/// item, generating the arg-downcast and result-wrapping at expansion time.
///
/// The syntax carries the CEL name (defaults to the Rust fn ident converted
/// from `snake_case` to `camelCase`, so `fn ends_with` becomes `endsWith`),
/// the overload id (defaults to `"{receiver}.{name}({rest_arg_types})"`,
/// matching cel-cpp's `MakeOverloadSignature` format), the receiver +
/// argument types (Rust types that implement
/// [`Val`](crate::common::value::Val)), and how the fn returns its result.
///
/// # Shape
///
/// ```ignore
/// add_member_overload!(
///     env,
///     fn <fn_ident>: (<Receiver>[, <Arg>]*) -> <Ret>
///     [, name = "<cel-name>"]
///     [, id   = "<overload-id>"]
/// );
/// ```
///
/// The fn takes its receiver and arguments **by reference**, downcast from the
/// call's [`CowVal`](crate::common::value::CowVal)s, and `<Ret>` says how it
/// hands the result back - one of four shapes:
///
/// | `<Ret>` | fn returns | wrapped as |
/// |---|---|---|
/// | `T` | `T` | `CowVal::owned` |
/// | `&T` | `&T` | `CowVal::Borrowed` |
/// | `Result<T>` | `Result<T, ExecutionError>` | `CowVal::owned` |
/// | `Result<&T>` | `Result<&T, ExecutionError>` | `CowVal::Borrowed` |
///
/// `Result<T, ExecutionError>` may also be spelled out in full. `<Ret>` is
/// applied as the type annotation on the call, so a fn whose return type does
/// not match is a compile error here.
///
/// Because the arguments are owned by the generated wrapper, a `&T` result
/// cannot borrow *from them* - the borrow has to outlive the call. Returning a
/// value that borrows from an argument needs a plain
/// [`Function`](crate::common::functions::Function), written by hand.
///
/// # Example
///
/// ```ignore
/// fn matches(this: &CelString<'_>, re: &CelString<'_>) -> Result<CelBool, ExecutionError> { … }
///
/// add_member_overload!(env, fn matches: (String, String) -> Result<CelBool>)?;
/// // → registers CEL name "matches", overload id "string.matches(string)".
/// ```
///
/// # Optional overrides
///
/// `name`, `id` and `receiver` may be given as trailing key-value args, in any
/// order. When only `name` is overridden the default id is built from the
/// resolved name, so `name = "endsWith"` yields id `"string.endsWith(string)"`.
///
/// ```ignore
/// add_member_overload!(env, fn regex_matches: (String, String) -> Result<CelBool>,
///     name = "matches", id = "matches_regex")?;
/// ```
///
/// `receiver = <Type expr>` supplies the receiver's CEL type instead of taking
/// it from `<Receiver as Val>::cel_type()`. It is what makes a receiver whose
/// runtime type is *per-instance* registrable at all - a
/// [`CelStruct`](crate::common::types::CelStruct) is named by its own struct
/// type, so it has no static `cel_type()` and the default would panic. The
/// override is resolved before the id default, so the id still reads
/// `"{receiver}.{name}({rest})"`:
///
/// ```ignore
/// // `fn strip_version(this: &CelStruct<'v>) -> Result<CelString<'v>, _>`
/// add_member_overload!(env, fn strip_version: (CelStruct) -> Result<CelString>,
///     receiver = Type::new_struct_type("HttpRequest"), name = "stripVersion")?;
/// // → CEL name "stripVersion", overload id "HttpRequest.stripVersion()".
/// ```
///
/// A fn whose return type is not the declared `<Ret>` does not compile:
///
/// ```compile_fail
/// use cel::common::types::{CelInt, CelString};
/// use cel::Env;
///
/// fn len(this: &CelString<'_>) -> CelInt {
///     CelInt::from(this.inner().len() as i64)
/// }
///
/// let mut env = Env::default();
/// // `len` returns a `CelInt`, not a `CelString`.
/// cel::add_member_overload!(env, fn len: (CelString) -> CelString);
/// ```
///
/// # Errors
///
/// Evaluates to the `Result<(), DeclarationError>` of the registration, and
/// fails with
/// [`DeclarationError::DuplicateOverload`](crate::DeclarationError::DuplicateOverload)
/// if the `Env` already declares an overload of that name with the same id,
/// or the same signature - e.g. when an extension library registers an
/// overload the `Env` already declares:
///
/// ```
/// use cel::common::types::{CelBool, CelString};
/// use cel::{DeclarationError, Env};
///
/// fn is_empty(this: &CelString<'_>) -> CelBool {
///     CelBool::from(this.inner().is_empty())
/// }
///
/// fn extension(env: &mut Env) -> Result<(), DeclarationError> {
///     cel::add_member_overload!(env, fn is_empty: (CelString) -> CelBool)?;
///     Ok(())
/// }
///
/// let mut env = Env::stdlib();
/// assert_eq!(env.add_extension(extension), Ok(()));
/// assert_eq!(
///     env.add_extension(extension),
///     Err(DeclarationError::duplicate_overload("isEmpty", "string.isEmpty()")),
/// );
/// ```
#[macro_export]
macro_rules! add_member_overload {
    // The four result shapes, most specific first: `$ret:ty` would otherwise
    // swallow `&T` and `Result<T>` whole. `Result`'s error type is always
    // `ExecutionError`, so spelling it out is optional.
    (
        $env:expr,
        fn $fn:ident : ( $this:ty $(, $other:ty )* $(,)? ) -> Result<&$ret:ty $(, $err:ty)?>
        $(, $key:ident = $val:expr )* $(,)?
    ) => {
        $crate::__add_member_overload!(
            try_borrowed, $env, fn $fn: ($this $(, $other)*) -> $ret $(, $key = $val)*)
    };
    (
        $env:expr,
        fn $fn:ident : ( $this:ty $(, $other:ty )* $(,)? ) -> Result<$ret:ty $(, $err:ty)?>
        $(, $key:ident = $val:expr )* $(,)?
    ) => {
        $crate::__add_member_overload!(
            try_owned, $env, fn $fn: ($this $(, $other)*) -> $ret $(, $key = $val)*)
    };
    (
        $env:expr,
        fn $fn:ident : ( $this:ty $(, $other:ty )* $(,)? ) -> &$ret:ty
        $(, $key:ident = $val:expr )* $(,)?
    ) => {
        $crate::__add_member_overload!(
            borrowed, $env, fn $fn: ($this $(, $other)*) -> $ret $(, $key = $val)*)
    };
    (
        $env:expr,
        fn $fn:ident : ( $this:ty $(, $other:ty )* $(,)? ) -> $ret:ty
        $(, $key:ident = $val:expr )* $(,)?
    ) => {
        $crate::__add_member_overload!(
            owned, $env, fn $fn: ($this $(, $other)*) -> $ret $(, $key = $val)*)
    };
}

/// The body behind [`add_member_overload!`], with the result shape resolved
/// to one of [`__overload_result!`]'s tags. Evaluates to the registration's
/// `Result`. Not for direct use.
#[doc(hidden)]
#[macro_export]
macro_rules! __add_member_overload {
    (
        $shape:ident, $env:expr,
        fn $fn:ident : ( $this:ty $(, $other:ty )* ) -> $ret:ty
        $(, $key:ident = $val:expr )*
    ) => {{
        // The wrapper: downcasts each `CowVal` to its declared Rust type,
        // hands the references to the target fn, and wraps what comes back.
        fn __wrapper<'b, 'v>(
            args: ::std::vec::Vec<$crate::common::value::CowVal<'b, 'v>>,
        ) -> ::std::result::Result<
            $crate::common::value::CowVal<'b, 'v>,
            $crate::ExecutionError,
        > {
            // How many arguments this overload takes, against how many it got:
            // all the extractor needs to report a missing one.
            const __ARITY: usize =
                [::std::stringify!($this) $(, ::std::stringify!($other))*].len();
            let __actual = args.len();
            let mut __at = 0usize;
            $crate::__overload_result!($shape, $ret, $fn(
                $crate::__member_overload_extract!(args, __at, $this, __ARITY, __actual)
                $(, $crate::__member_overload_extract!(args, __at, $other, __ARITY, __actual) )*
            ))
        }

        // The receiver's CEL type. `receiver = ...` overrides it, and the
        // default is only evaluated when it does not: a receiver whose type is
        // per-instance has no static `cel_type()` to fall back on.
        let __receiver: ::std::option::Option<$crate::common::types::Type> =
            ::std::option::Option::None;
        $( $crate::__overload_receiver_override!(__receiver, $key = $val); )*
        let __receiver: $crate::common::types::Type = __receiver
            .unwrap_or_else(|| <$this as $crate::common::value::Val>::cel_type().to_owned());

        // CEL name defaults to the fn ident. `name = "..."` overrides apply
        // first so the id default sees the resolved name (matching cel-cpp).
        let __name: ::std::string::String =
            $crate::to_camel_case(::std::stringify!($fn));
        $( $crate::__overload_name_override!(__name, $key = $val); )*

        // Id default follows cel-cpp `MakeOverloadSignature` for member fns:
        // `receiver.name(rest_arg_types_comma_separated)`.
        let __rest_types: ::std::vec::Vec<&str> = ::std::vec![
            $( <$other as $crate::common::value::Val>::cel_type().name() ),*
        ];
        let __id: ::std::string::String = ::std::format!(
            "{}.{}({})",
            __receiver.name(),
            __name,
            __rest_types.join(","),
        );
        $( $crate::__overload_id_override!(__id, $key = $val); )*

        $env.add_member_overload(
            &__name,
            &__id,
            __receiver,
            ::std::vec![
                $( <$other as $crate::common::value::Val>::cel_type().to_owned() ),*
            ],
            __wrapper,
        )
    }};
}

/// Internal helper for [`add_member_overload!`] and [`add_overload!`]: borrows
/// the argument at `$idx` and downcasts it to `$ty`, advancing `$idx`. Not for
/// direct use.
///
/// The overload dispatcher only calls a wrapper with arguments matching the
/// registered signature, so the errors below are defensive. They follow the
/// conventions of the rest of the crate for a call that does not know which
/// function it is part of: a missing argument is an `InvalidArgumentCount`
/// (`$arity` taken, `$actual` given), and a wrongly typed one an
/// `UnexpectedType` naming the runtime type it got and the CEL type it wanted.
#[doc(hidden)]
#[macro_export]
macro_rules! __member_overload_extract {
    ($args:ident, $idx:ident, $ty:ty, $arity:ident, $actual:ident) => {{
        let __arg = $args
            .get($idx)
            .ok_or_else(|| $crate::ExecutionError::invalid_argument_count($arity, $actual))?
            .as_ref();
        $idx += 1;
        __arg
            .downcast_ref::<$ty>()
            .ok_or_else(|| $crate::ExecutionError::UnexpectedType {
                got: __arg.get_type().name().to_owned(),
                want: <$ty as $crate::common::value::Val>::cel_type()
                    .name()
                    .to_owned(),
            })?
    }};
}

/// Internal helper: applies only `name = "..."` overrides (ignoring the other
/// keys) so name resolution happens before id defaulting.
#[doc(hidden)]
#[macro_export]
macro_rules! __overload_name_override {
    ($bind:ident, name = $val:expr) => {
        let $bind: ::std::string::String = ::std::string::String::from($val);
    };
    ($bind:ident, id = $val:expr) => {};
    ($bind:ident, receiver = $val:expr) => {};
}

/// Internal helper: applies only `id = "..."` overrides (ignoring the others).
#[doc(hidden)]
#[macro_export]
macro_rules! __overload_id_override {
    ($bind:ident, id = $val:expr) => {
        let $bind: ::std::string::String = ::std::string::String::from($val);
    };
    ($bind:ident, name = $val:expr) => {};
    ($bind:ident, receiver = $val:expr) => {};
}

/// Internal helper: applies only `receiver = ...` overrides (ignoring the
/// others), so the receiver type is resolved before the id default uses its
/// name.
#[doc(hidden)]
#[macro_export]
macro_rules! __overload_receiver_override {
    ($bind:ident, receiver = $val:expr) => {
        let $bind: ::std::option::Option<$crate::common::types::Type> =
            ::std::option::Option::Some($val);
    };
    ($bind:ident, name = $val:expr) => {};
    ($bind:ident, id = $val:expr) => {};
}

/// Register a global (non-member) function overload on an `Env` from a typed
/// Rust `fn` item, generating the arg-downcast and result-wrapping at
/// expansion time.
///
/// Mirrors [`add_member_overload!`] but delegates to `Env::add_overload` and
/// treats every parameter as a regular arg (no `this`-receiver split).
///
/// # Shape
///
/// ```ignore
/// add_overload!(
///     env,
///     fn <fn_ident>: (<Arg>*) -> <Ret>
///     [, name = "<cel-name>"]
///     [, id   = "<overload-id>"]
/// );
/// ```
///
/// Zero-argument overloads are supported: use `()` for the parameter list.
/// `<Ret>` takes the same four shapes as [`add_member_overload!`]'s, with the
/// same caveat on `&T` results.
///
/// # Default naming
///
/// * `name` defaults to the fn ident converted from `snake_case` to
///   `camelCase` — `fn ends_with` yields the CEL name `"endsWith"`, a
///   single-word ident like `fn matches` stays `"matches"`.
/// * `id` defaults to cel-cpp's `MakeOverloadSignature` format:
///   `"{name}({arg_types_comma_separated})"` — e.g. `size(string)` for a
///   one-arg fn, `matches(string,string)` for two args, `now()` when there
///   are no args. When `name = "..."` is overridden the id default uses the
///   resolved name.
///
/// Either may be overridden via trailing `name = "..."` / `id = "..."`
/// key-value args, in either order.
///
/// # Errors
///
/// Evaluates to the `Result<(), DeclarationError>` of the registration, and
/// fails with
/// [`DeclarationError::DuplicateOverload`](crate::DeclarationError::DuplicateOverload)
/// if the `Env` already declares an overload of that name with the same id,
/// or the same signature:
///
/// ```
/// use cel::common::types::{CelInt, CelString};
/// use cel::{DeclarationError, Env};
///
/// fn size(this: &CelString<'_>) -> CelInt {
///     CelInt::from(this.inner().len() as i64)
/// }
///
/// let mut env = Env::stdlib();
/// assert_eq!(
///     cel::add_overload!(env, fn size: (CelString) -> CelInt, id = "size_string"),
///     Err(DeclarationError::duplicate_overload("size", "size_string")),
/// );
/// ```
#[macro_export]
macro_rules! add_overload {
    // The four result shapes, most specific first - see
    // `add_member_overload!`.
    (
        $env:expr,
        fn $fn:ident : ( $($arg:ty),* $(,)? ) -> Result<&$ret:ty $(, $err:ty)?>
        $(, $key:ident = $val:expr )* $(,)?
    ) => {
        $crate::__add_overload!(try_borrowed, $env, fn $fn: ($($arg),*) -> $ret $(, $key = $val)*)
    };
    (
        $env:expr,
        fn $fn:ident : ( $($arg:ty),* $(,)? ) -> Result<$ret:ty $(, $err:ty)?>
        $(, $key:ident = $val:expr )* $(,)?
    ) => {
        $crate::__add_overload!(try_owned, $env, fn $fn: ($($arg),*) -> $ret $(, $key = $val)*)
    };
    (
        $env:expr,
        fn $fn:ident : ( $($arg:ty),* $(,)? ) -> &$ret:ty
        $(, $key:ident = $val:expr )* $(,)?
    ) => {
        $crate::__add_overload!(borrowed, $env, fn $fn: ($($arg),*) -> $ret $(, $key = $val)*)
    };
    (
        $env:expr,
        fn $fn:ident : ( $($arg:ty),* $(,)? ) -> $ret:ty
        $(, $key:ident = $val:expr )* $(,)?
    ) => {
        $crate::__add_overload!(owned, $env, fn $fn: ($($arg),*) -> $ret $(, $key = $val)*)
    };
}

/// The body behind [`add_overload!`], with the result shape resolved to one
/// of [`__overload_result!`]'s tags. Handles the zero-argument case too.
/// Evaluates to the registration's `Result`. Not for direct use.
#[doc(hidden)]
#[macro_export]
macro_rules! __add_overload {
    (
        $shape:ident, $env:expr,
        fn $fn:ident : ( $($arg:ty),* ) -> $ret:ty
        $(, $key:ident = $val:expr )*
    ) => {{
        fn __wrapper<'b, 'v>(
            args: ::std::vec::Vec<$crate::common::value::CowVal<'b, 'v>>,
        ) -> ::std::result::Result<
            $crate::common::value::CowVal<'b, 'v>,
            $crate::ExecutionError,
        > {
            // Spelled out via a slice so that a zero-arg overload, where there
            // is no element to infer from, still has an element type.
            const __ARITY: usize = {
                const __ARGS: &[&str] = &[$(::std::stringify!($arg)),*];
                __ARGS.len()
            };
            let _ = &args;
            let __actual = args.len();
            let mut __at = 0usize;
            let _ = &mut __at;
            $crate::__overload_result!($shape, $ret, $fn(
                $( $crate::__member_overload_extract!(args, __at, $arg, __ARITY, __actual) ),*
            ))
        }

        let __name: ::std::string::String =
            $crate::to_camel_case(::std::stringify!($fn));
        $( $crate::__overload_name_override!(__name, $key = $val); )*

        // Id default: `name(arg_types_comma_separated)` — cel-cpp format.
        let __arg_types: ::std::vec::Vec<&str> = ::std::vec![
            $( <$arg as $crate::common::value::Val>::cel_type().name() ),*
        ];
        let __id: ::std::string::String =
            ::std::format!("{}({})", __name, __arg_types.join(","));
        $( $crate::__overload_id_override!(__id, $key = $val); )*

        $env.add_overload(
            &__name,
            &__id,
            ::std::vec![
                $( <$arg as $crate::common::value::Val>::cel_type().to_owned() ),*
            ],
            __wrapper,
        )
    }};
}

pub(crate) use impl_handler;
