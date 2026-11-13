//! Header-specific construction admission. This temporary process-wide pool
//! is separate from the runtime's cross-generation replacement/output pool.
use crate::go_regexp::GoRegexp;
use anyhow::{Result, ensure};
use native_write_policy::{Lease, Pool};
use std::sync::{Arc, LazyLock};
pub(crate) const COMPILE_LIMIT: usize = 2 << 20;
const TRANSLATION_UPPER: usize = COMPILE_LIMIT * 8;
static CONSTRUCTORS: LazyLock<Pool> = LazyLock::new(|| Pool::new(128 << 20));
#[derive(Debug)]
pub(crate) struct CompileAdmission;
impl std::fmt::Display for CompileAdmission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("header compiler allocation admission exhausted")
    }
}
impl std::error::Error for CompileAdmission {}
pub(crate) fn native_compile_upper(shape: crate::go_regexp::NativeCompileSize) -> Result<usize> {
    // AST/HIR nodes, empty alternation branches, class ranges and names are
    // distinct capacities. Unicode classes must not be priced as short input.
    shape
        .nodes
        .checked_mul(1024)
        .and_then(|n| shape.ranges.checked_mul(256).and_then(|m| n.checked_add(m)))
        .and_then(|n| shape.bytes.checked_mul(4).and_then(|m| n.checked_add(m)))
        .and_then(|n| {
            shape
                .captures
                .checked_mul(256)
                .and_then(|m| n.checked_add(m))
        })
        .and_then(|n| n.checked_add(8 << 20))
        .ok_or_else(|| CompileAdmission.into())
}
pub(crate) fn compile_resource(e: &anyhow::Error) -> bool {
    matches!(
        e.to_string().as_str(),
        "regexp compile memory limit too small"
            | "regexp native state limit exceeded"
            | "regexp native search memory limit exceeded"
            | "regexp compilation failed after native translation"
            | "regexp native engine preparation failed"
            | "regexp compiled memory limit exceeded"
            | "regexp compiled capture size overflow"
            | "regexp translation changed capture group numbering"
            | "regexp translation workspace limit exceeded"
            | "regexp nesting limit exceeded"
            | "regexp syntax node limit exceeded"
            | "regexp group nesting limit exceeded"
            | "regexp capture count limit exceeded"
            | "regexp translated pattern limit exceeded"
            | "regexp source byte limit exceeded"
    )
}

pub(crate) struct Compiled {
    pub(crate) regex: Arc<GoRegexp>,
    // Native strategies/caches retire before both construction phase credits.
    _native: Option<Lease>,
    _translation: Lease,
}
pub(crate) fn compile_dynamic(pattern: &str, pool: &Pool) -> Result<Compiled> {
    let translation = pool
        .reserve(TRANSLATION_UPPER)
        .map_err(|_| CompileAdmission)?;
    let mut native = None;
    let regex = GoRegexp::compile_preflight(pattern, COMPILE_LIMIT, |shape| {
        native = Some(
            pool.reserve(native_compile_upper(shape)?)
                .map_err(|_| CompileAdmission)?,
        );
        Ok(())
    })?;
    Ok(Compiled {
        regex: Arc::new(regex),
        _native: native,
        _translation: translation,
    })
}
pub(crate) fn is_resource(error: &anyhow::Error) -> bool {
    error.is::<CompileAdmission>() || compile_resource(error)
}
pub(super) fn compile_static(pattern: &str, remaining: &mut usize) -> Result<Arc<GoRegexp>> {
    let compiled = compile_dynamic(pattern, &CONSTRUCTORS)?;
    // This is the existing retained configuration limit, not the constructor
    // scratch lease. A handed-off regex can outlive construction and reload.
    let next = remaining.checked_sub(compiled.regex.memory_usage());
    ensure!(
        next.is_some(),
        "HTTP regexp configuration memory budget exceeded"
    );
    *remaining = next.unwrap();
    Ok(compiled.regex.clone())
}

/// Map historically accepted Rust regex syntax. Keep those useful extensions,
/// without treating resource admission as a syntax failure and retrying it.
pub(super) fn compile_map_static(pattern:&str,remaining:&mut usize)->Result<Arc<GoRegexp>>{
    let compiled=match compile_dynamic(pattern,&CONSTRUCTORS){
        Ok(compiled)=>compiled,
        Err(error)if is_resource(&error)=>return Err(error),
        Err(_go_syntax)=>{
            let translation=CONSTRUCTORS.reserve(TRANSLATION_UPPER).map_err(|_|CompileAdmission)?;
            let mut native=None;
            let regex=GoRegexp::compile_map_extension_preflight(pattern,COMPILE_LIMIT,|shape|{
                native=Some(CONSTRUCTORS.reserve(native_compile_upper(shape)?).map_err(|_|CompileAdmission)?);Ok(())
            })?;
            Compiled{regex:Arc::new(regex),_native:native,_translation:translation}
        }
    };
    *remaining=remaining.checked_sub(compiled.regex.memory_usage()).ok_or_else(||anyhow::anyhow!("HTTP regexp configuration memory budget exceeded"))?;
    Ok(compiled.regex.clone())
}
