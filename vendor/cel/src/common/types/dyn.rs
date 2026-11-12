use crate::common::value::CowVal;
use crate::ExecutionError;

/// `dyn` has no effect at runtime, it only signals to a type checker that its argument
/// should be treated as dynamically typed. Returning the argument unchanged matches the
/// `identity` binding cel-go declares for the same overload.
// TODO: this overload needs to be parameterized once the type system carries type
// parameters, so that the declared signature is `dyn(A) -> dyn` and a container
// argument yields `list(dyn)` or `map(dyn, dyn)` rather than a bare `dyn`. See #244.
fn to_dyn<'b, 'v>(mut args: Vec<CowVal<'b, 'v>>) -> Result<CowVal<'b, 'v>, ExecutionError> {
    Ok(args.remove(0))
}

pub(crate) fn stdlib(env: &mut crate::Env) {
    env.add_overload("dyn", "to_dyn", vec![super::DYN_TYPE], to_dyn)
        .expect("Must be unique id");
}
