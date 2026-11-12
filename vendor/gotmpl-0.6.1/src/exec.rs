//! Template execution engine. Walks the AST and writes output.
//!
//! The [`Executor`] evaluates a parsed template tree against a [`Value`] data
//! context, writing results to any [`core::fmt::Write`] destination.
//!
//! Used internally by [`Template::execute`](crate::Template::execute); most
//! users don't need it directly.
//!
//! # Execution model
//!
//! The executor maintains:
//! - **dot**: the current context value (changes inside `range`/`with`).
//! - **`$`**: always the root data passed to [`execute`](Executor::execute).
//! - **variable scopes**: a stack of name-to-[`Value`] frames, pushed and
//!   popped for control blocks.
//! - **recursion depth**: guards against stack overflow from recursive
//!   `{{template}}` calls.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt::Write;

use crate::go_write::{GoWrite,FmtSink};
use crate::parse::SmolStr;

#[cfg(feature = "std")]
use std::any::Any;
#[cfg(feature = "std")]
use std::panic::{AssertUnwindSafe, catch_unwind};

use crate::error::{Result, TemplateError};
use crate::parse::{BranchNode, CommandNode, Expr, ListNode, Node, Number, PipeNode, TemplateNode};
use crate::value::Value;
use crate::value::ValueFunc;
enum BoundMethod { Dynamic(ValueFunc), Static(Arc<crate::Object>, &'static crate::HostMethod), Slice(crate::TypedSlice, &'static crate::SliceMethod) }

/// Maximum total recursion depth across `{{template}}` invocations and
/// nested `{{if}}`/`{{with}}`/`{{range}}` bodies during execution.
///
/// Go uses 100,000; Rust's default thread stack is smaller (2 MB for test
/// threads). 200 gives comfortable headroom on a 2 MB stack and is far
/// beyond any reasonable template nesting.
const MAX_EXEC_DEPTH: usize = 200;

/// Controls behavior when accessing a missing key on a [`Value::Map`]. Set via
/// [`Template::missing_key`](crate::Template::missing_key).
///
/// Parseable from strings through [`FromStr`](core::str::FromStr): `"invalid"`,
/// `"default"`, `"zero"`, and `"error"`.
///
/// ```
/// use gotmpl::MissingKey;
///
/// let mk: MissingKey = "error".parse().unwrap();
/// assert_eq!(mk, MissingKey::Error);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum MissingKey {
    /// Return [`Value::Nil`] for missing keys (the default).
    #[default]
    Invalid,
    /// Return [`Value::Nil`] for missing keys. Kept as a distinct variant
    /// to mirror Go's `{{options "missingkey=zero"}}` directive.
    ZeroValue,
    /// Return a [`TemplateError::MissingKey`] for missing keys.
    Error,
}

impl core::fmt::Display for MissingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            MissingKey::Invalid => f.write_str("invalid"),
            MissingKey::ZeroValue => f.write_str("zero"),
            MissingKey::Error => f.write_str("error"),
        }
    }
}

impl core::str::FromStr for MissingKey {
    type Err = TemplateError;

    fn from_str(s: &str) -> core::result::Result<Self, Self::Err> {
        match s {
            "invalid" | "default" => Ok(MissingKey::Invalid),
            "zero" => Ok(MissingKey::ZeroValue),
            "error" => Ok(MissingKey::Error),
            _ => Err(TemplateError::Exec(format!(
                "unrecognized missingkey value: {s:?}"
            ))),
        }
    }
}

// Internal control-flow signaling
//
// `{{break}}` and `{{continue}}` are not errors; they're control-flow signals
// caught by the range walker. We keep them out of the public `TemplateError`
// enum by using a private error type for the executor's internal methods.

/// Private error type that carries either a real [`TemplateError`] or an
/// internal break/continue signal. Only the public [`Executor::execute`]
/// method converts this into a [`TemplateError`] for the caller.
///
/// The `TemplateError` is boxed to keep `ExecSignal` small (one word plus
/// tag), so that deeply recursive `walk` calls don't blow the stack.
enum ExecSignal {
    /// A real template error to propagate to the caller.
    Err(Box<TemplateError>),
    /// `{{break}}`: exit the innermost range loop.
    Break,
    /// `{{continue}}`: skip to the next range iteration.
    Continue,
}

impl From<TemplateError> for ExecSignal {
    fn from(e: TemplateError) -> Self {
        ExecSignal::Err(Box::new(e))
    }
}

#[cfg(feature = "std")]
impl From<std::io::Error> for ExecSignal {
    fn from(e: std::io::Error) -> Self {
        ExecSignal::Err(Box::new(TemplateError::Io(e)))
    }
}

impl From<core::fmt::Error> for ExecSignal {
    fn from(_: core::fmt::Error) -> Self {
        ExecSignal::Err(Box::new(TemplateError::Write))
    }
}

/// Internal result alias used by the executor's private methods.
type ExecResult<T> = core::result::Result<T, ExecSignal>;

/// Variable scope: a stack of name→value mappings.
/// New scopes are pushed for range/with blocks. Keys are [`SmolStr`] so that
/// short identifiers coming from the parser (already stored as `SmolStr`)
/// inline up to 22 bytes — avoiding the heap allocation and atomic refcount
/// bump that `Arc<str>` would incur on every `set`/`assign`.
struct VarScope {
    frames: Vec<BTreeMap<SmolStr, Value>>,
}

impl VarScope {
    fn new() -> Self {
        VarScope {
            frames: vec![BTreeMap::new()],
        }
    }

    fn push(&mut self) {
        self.frames.push(BTreeMap::new());
    }

    fn pop(&mut self) {
        self.frames.pop();
    }

    fn set(&mut self, name: &SmolStr, val: Value) {
        if let Some(frame) = self.frames.last_mut() {
            frame.insert(name.clone(), val);
        }
    }

    /// Set a variable in any existing scope (for assignment with =).
    fn assign(&mut self, name: &SmolStr, val: Value) {
        for frame in self.frames.iter_mut().rev() {
            if let Some(slot) = frame.get_mut(name.as_str()) {
                *slot = val;
                return;
            }
        }
        self.set(name, val);
    }

    fn get(&self, name: &str) -> Option<&Value> {
        for frame in self.frames.iter().rev() {
            if let Some(v) = frame.get(name) {
                return Some(v);
            }
        }
        None
    }
}

/// Default per-execution iteration budget across all `{{range}}` loops.
/// Caps attacker-controlled `{{range 10000000000}}` / nested-range DoS.
pub(crate) const DEFAULT_MAX_RANGE_ITERS: u64 = 10_000_000;

/// Key used for the template's implicit `$` variable.
const DOLLAR_KEY: SmolStr = SmolStr::new_static("$");

/// Bounds total written bytes before forwarding a chunk to the caller.
struct OutputWriter<'a, W> {
    inner: &'a mut W,
    remaining: Option<usize>,
    charge: Option<crate::ExecutionCharge>,
    error: Option<TemplateError>,
}
impl<W: GoWrite> Write for OutputWriter<'_, W> {
    fn write_str(&mut self,text:&str)->core::fmt::Result{self.write_bytes(text.as_bytes())}
}
impl<W:GoWrite> GoWrite for OutputWriter<'_,W>{
    fn write_bytes(&mut self,text:&[u8])->core::fmt::Result{
        if let Some(left) = &mut self.remaining {
            let Some(next) = left.checked_sub(text.len()) else {
                self.error = Some(TemplateError::Exec("template output limit exceeded".into()));
                return Err(core::fmt::Error);
            };
            *left = next;
        }
        if let Some(charge) = &self.charge {
            if let Err(error) = charge(text.len().div_ceil(128)) {
                self.error = Some(error);
                return Err(core::fmt::Error);
            }
        }
        self.inner.write_bytes(text)
    }
}

/// The template execution context.
///
/// Walks the AST produced by the [`Parser`](crate::parse::Parser), evaluating
/// pipelines, resolving variables, calling functions, and writing output.
/// Created internally by [`Template::execute`](crate::Template::execute).
pub struct Executor<'a> {
    funcs: &'a BTreeMap<String, ValueFunc>,
    templates: &'a BTreeMap<crate::GoKey, Arc<ListNode>>,
    vars: VarScope,
    depth: usize,
    missing_key: MissingKey,
    range_iters_remaining: u64,
    pub(crate) execution_charge: Option<crate::ExecutionCharge>,
    pub(crate) value_limit:usize,pub(crate) output_limit:usize,
    pub(crate) function_signatures:BTreeMap<String,crate::Signature>,
    #[cfg(not(feature = "html"))]
    pub(crate) definition_lookup: Option<crate::GoDefinitionLookup>,
}

/// Returns a short human-readable name for an expression, used in error messages.
fn expr_name(expr: &Expr) -> &'static str {
    match expr {
        Expr::Dot(_) => "<.>",
        Expr::Field(_, _) => "<field>",
        Expr::Variable(_, _, _) => "<variable>",
        Expr::Identifier(_, _) => "<identifier>",
        Expr::String(_, _) => "<string>",
        Expr::Number(_, _) => "<number>",
        Expr::Bool(_, _) => "<bool>",
        Expr::Nil(_) => "<nil>",
        Expr::Pipe(_, _) => "<pipeline>",
        Expr::Chain(_, _, _) => "<chain>",
    }
}

/// Execute a range loop body with break/continue handling.
///
/// `iter` yields `(index_value, element_value)` pairs. The macro is
/// necessary because `break` / `continue` are loop-control keywords
/// that cannot live inside a regular function call.
macro_rules! range_loop {
    ($self:expr, $w:expr, $branch:expr, $iter:expr) => {
        for (idx_val, item) in $iter {
            if $self.range_iters_remaining == 0 {
                return Err(TemplateError::RangeIterLimit.into());
            }
            $self.range_iters_remaining -= 1;
            $self.vars.push();
            if $branch.pipe.is_assign {
                // Assignment form ($v = range ...): modify existing variables
                // in their original (outer) scope so they persist after the loop.
                if $branch.pipe.decl.len() == 1 {
                    $self.vars.assign(&$branch.pipe.decl[0], item.clone());
                } else if $branch.pipe.decl.len() >= 2 {
                    $self.vars.assign(&$branch.pipe.decl[0], idx_val);
                    $self.vars.assign(&$branch.pipe.decl[1], item.clone());
                }
            } else {
                // Declaration form ($v := range ...): create variables in the
                // per-iteration scope (pushed above).
                if $branch.pipe.decl.len() == 1 {
                    $self.vars.set(&$branch.pipe.decl[0], item.clone());
                } else if $branch.pipe.decl.len() >= 2 {
                    $self.vars.set(&$branch.pipe.decl[0], idx_val);
                    $self.vars.set(&$branch.pipe.decl[1], item.clone());
                }
            }
            match $self.walk($w, &$branch.body, &item) {
                Ok(()) => {}
                Err(ExecSignal::Break) => {
                    $self.vars.pop();
                    break;
                }
                Err(ExecSignal::Continue) => {
                    $self.vars.pop();
                    continue;
                }
                Err(e) => {
                    $self.vars.pop();
                    return Err(e);
                }
            }
            $self.vars.pop();
        }
    };
}

/// Go restricts `range` over an integer (Go 1.22+) to a single loop variable:
/// `{{range $i, $v := 3}}` errors at exec with "can't use N to iterate over
/// more than one variable" — for any value, and *before* the empty check.
/// Slices, maps, and channels are unaffected; only the integer kinds are
/// guarded. `val`'s `Display` reproduces Go's `N` (`Int`/`Uint` both print the
/// bare magnitude).
fn ensure_single_range_var(branch: &BranchNode, val: &Value) -> ExecResult<()> {
    if branch.pipe.decl.len() > 1 {
        return Err(TemplateError::Exec(format!(
            "can't use {val} to iterate over more than one variable"
        ))
        .into());
    }
    Ok(())
}

impl<'a> Executor<'a> {
    /// Create a new executor with the given function map and template definitions.
    ///
    /// `funcs` should contain all [built-in](crate::funcs::builtins) and
    /// user-defined functions. `templates` holds the named templates from
    /// `{{define}}` blocks.
    pub fn new(
        funcs: &'a BTreeMap<String, ValueFunc>,
        templates: &'a BTreeMap<crate::GoKey, Arc<ListNode>>,
    ) -> Self {
        Executor {
            funcs,
            templates,
            vars: VarScope::new(),
            depth: 0,
            missing_key: MissingKey::default(),
            range_iters_remaining: DEFAULT_MAX_RANGE_ITERS,
            execution_charge: None,
            value_limit:1<<20,output_limit:1<<20,
            function_signatures:BTreeMap::new(),
            #[cfg(not(feature = "html"))]
            definition_lookup: None,
        }
    }

    /// Set the [`MissingKey`] behavior for this executor.
    pub fn set_missing_key(&mut self, mk: MissingKey) {
        self.missing_key = mk;
    }

    /// Set the total number of `{{range}}` iterations allowed for this
    /// execution (across all nested ranges). Zero disables the limit.
    pub fn set_max_range_iters(&mut self, n: u64) {
        self.range_iters_remaining = if n == 0 { u64::MAX } else { n };
    }

    /// Execute the template tree with the given data, writing output to `writer`.
    ///
    /// The `dot` value is the initial context (`.`) and is also bound to `$`.
    ///
    /// # Errors
    ///
    /// Returns a [`TemplateError`] on undefined references, type errors,
    /// I/O failures, or exceeding the recursion depth limit.
    pub fn execute<W: Write>(
        &mut self,
        writer: &mut W,
        tree: &ListNode,
        dot: &Value,
    ) -> Result<()> {
        let mut sink=FmtSink{inner:writer,non_utf8:false};
        let result=self.execute_go(&mut sink,tree,dot);if sink.non_utf8{Err(TemplateError::NonUtf8Output)}else{result}
    }
    pub(crate) fn execute_go<W:GoWrite>(&mut self,writer:&mut W,tree:&ListNode,dot:&Value)->Result<()>{
        self.vars.set(&DOLLAR_KEY, dot.clone());
        let mut output = OutputWriter {
            inner: writer,
            remaining: self.execution_charge.as_ref().map(|_| self.output_limit),
            charge: self.execution_charge.clone(),
            error: None,
        };
        let result = self.walk(&mut output, tree, dot).map_err(|sig| match sig {
            ExecSignal::Err(e) => *e,
            ExecSignal::Break => TemplateError::Exec("unexpected break outside of range".into()),
            ExecSignal::Continue => {
                TemplateError::Exec("unexpected continue outside of range".into())
            }
        });
        match (result, output.error) {
            (_, Some(error)) => Err(error),
            (result, None) => result,
        }
    }

    // AST walker
    fn walk<W: GoWrite>(&mut self, w: &mut W, list: &ListNode, dot: &Value) -> ExecResult<()> {
        for node in &list.nodes {
            self.walk_node(w, node, dot)?;
        }
        Ok(())
    }

    fn walk_node<W: GoWrite>(&mut self, w: &mut W, node: &Node, dot: &Value) -> ExecResult<()> {
        self.charge(1)?;
        match node {
            Node::Text(text) => {
                w.write_bytes(&text.text)?;
                Ok(())
            }
            Node::Action(action) => {
                let val = self.eval_pipeline(dot, &action.pipe)?;
                // Only print if there are no declarations (side-effect-only)
                if action.pipe.decl.is_empty() {
                    self.charge_values(core::slice::from_ref(&val))?;
                    // Go's template engine prints "<no value>" for nil/missing
                    // values, distinct from fmt.Sprint(nil) which prints "<nil>".
                    match val {
                        Value::Nil => w.write_str("<no value>")?,
                        other => crate::go_write::write_value(w, &other, 0)?,
                    }
                }
                Ok(())
            }
            Node::If(branch) => self.walk_if(w, branch, dot),
            Node::Range(branch) => self.walk_range(w, branch, dot),
            Node::With(branch) => self.walk_with(w, branch, dot),
            Node::Template(tmpl) => self.walk_template(w, tmpl, dot),
            Node::Define(_) => Ok(()), // defines are collected at parse time
            Node::List(list) => self.walk(w, list, dot),
            Node::Break(_) => Err(ExecSignal::Break),
            Node::Continue(_) => Err(ExecSignal::Continue),
        }
    }

    // Control flow
    fn check_depth(&self) -> ExecResult<()> {
        if self.depth > MAX_EXEC_DEPTH {
            return Err(TemplateError::RecursionLimit.into());
        }
        Ok(())
    }

    fn walk_if<W: GoWrite>(&mut self, w: &mut W, branch: &BranchNode, dot: &Value) -> ExecResult<()> {
        self.depth += 1;
        let depth_ok = self.check_depth();
        self.vars.push();
        let result = depth_ok.and_then(|()| match self.eval_pipeline(dot, &branch.pipe) {
            Ok(val) => {
                if val.is_truthy() {
                    self.walk(w, &branch.body, dot)
                } else if let Some(ref else_body) = branch.else_body {
                    self.walk(w, else_body, dot)
                } else {
                    Ok(())
                }
            }
            Err(e) => Err(e),
        });
        self.vars.pop();
        self.depth -= 1;
        result
    }

    fn walk_with<W: GoWrite>(
        &mut self,
        w: &mut W,
        branch: &BranchNode,
        dot: &Value,
    ) -> ExecResult<()> {
        self.depth += 1;
        let depth_ok = self.check_depth();
        self.vars.push();
        let result = depth_ok.and_then(|()| match self.eval_pipeline(dot, &branch.pipe) {
            Ok(val) => {
                if val.is_truthy() {
                    self.walk(w, &branch.body, &val)
                } else if let Some(ref else_body) = branch.else_body {
                    self.walk(w, else_body, dot)
                } else {
                    Ok(())
                }
            }
            Err(e) => Err(e),
        });
        self.vars.pop();
        self.depth -= 1;
        result
    }

    fn walk_range<W: GoWrite>(
        &mut self,
        w: &mut W,
        branch: &BranchNode,
        dot: &Value,
    ) -> ExecResult<()> {
        self.depth += 1;
        let result = self
            .check_depth()
            .and_then(|()| self.walk_range_inner(w, branch, dot));
        self.depth -= 1;
        result
    }

    fn walk_range_inner<W: GoWrite>(
        &mut self,
        w: &mut W,
        branch: &BranchNode,
        dot: &Value,
    ) -> ExecResult<()> {
        // `range` binds its own per-iteration vars via `range_loop!`; use the
        // decl-free evaluator so pipe.decl names do not leak into the outer
        // scope or get pre-bound to the pipeline's final value.
        let val = self.eval_pipeline_value(dot, &branch.pipe)?;
        if let Some(map)=val.map_snapshot()?{
            if map.is_empty(){if let Some(body)=&branch.else_body{self.walk(w,body,dot)?;}}
            else{range_loop!(self,w,branch,map.iter().map(|(key,value)|(key.to_value(),value.clone())));}
            return Ok(());
        }

        #[cfg(feature="std")]
        if let Value::GenericMap(map)=&val{
            let map=map.snapshot()?;
            if map.is_empty(){if let Some(body)=&branch.else_body{self.walk(w,body,dot)?;}}
            else{range_loop!(self,w,branch,map.iter().map(|(key,value)|(key.clone(),value.clone())));}
            return Ok(());
        }
        if let Value::Slice(items)=&val{if items.len()==0{if let Some(body)=&branch.else_body{self.walk(w,body,dot)?;}}else{range_loop!(self,w,branch,items.iter().enumerate().map(|(i,v)|(Value::Int(i as i64),v)));}return Ok(());}
        match &val {
            Value::List(items) if items.is_empty() => {
                if let Some(ref else_body) = branch.else_body {
                    self.walk(w, else_body, dot)?;
                }
            }
            Value::List(items) => {
                range_loop!(
                    self,
                    w,
                    branch,
                    items
                        .iter()
                        .enumerate()
                        .map(|(i, v)| (Value::Int(i as i64), v.clone()))
                );
            }
            Value::Map(map) if map.is_empty() => {
                if let Some(ref else_body) = branch.else_body {
                    self.walk(w, else_body, dot)?;
                }
            }
            Value::Map(map) => {
                range_loop!(
                    self,
                    w,
                    branch,
                    map.iter()
                        .map(|(k, v)| (Value::String(Arc::clone(k)), v.clone()))
                );
            }
            Value::Int(n) | Value::Int64(n) | Value::NamedInt64(n,_) => {
                // Go 1.22+: range over integer
                ensure_single_range_var(branch, &val)?;
                let count = *n;
                if count <= 0 {
                    if let Some(ref else_body) = branch.else_body {
                        self.walk(w, else_body, dot)?;
                    }
                } else {
                    range_loop!(
                        self,
                        w,
                        branch,
                        (0..count).map(|i| {let value=match &val{Value::Int64(_)=>Value::Int64(i),Value::NamedInt64(_,kind)=>Value::NamedInt64(i,kind.clone()),_=>Value::Int(i)};(value.clone(),value)})
                    );
                }
            }
            Value::Uint(n) => {
                // Go 1.22+: range over an unsigned integer yields uint counters.
                ensure_single_range_var(branch, &val)?;
                let count = *n;
                if count == 0 {
                    if let Some(ref else_body) = branch.else_body {
                        self.walk(w, else_body, dot)?;
                    }
                } else {
                    range_loop!(
                        self,
                        w,
                        branch,
                        (0..count).map(|i| (Value::Uint(i), Value::Uint(i)))
                    );
                }
            }
            Value::Nil | Value::NilError => {
                // Nil is treated as empty
                if let Some(ref else_body) = branch.else_body {
                    self.walk(w, else_body, dot)?;
                }
            }
            other => {
                return Err(TemplateError::NotIterable(other.type_name().to_string()).into());
            }
        }

        Ok(())
    }

    fn walk_template<W: GoWrite>(
        &mut self,
        w: &mut W,
        tmpl: &TemplateNode,
        dot: &Value,
    ) -> ExecResult<()> {
        self.depth += 1;
        let result = self
            .check_depth()
            .and_then(|()| self.walk_template_inner(w, tmpl, dot));
        self.depth -= 1;
        result
    }

    fn walk_template_inner<W: GoWrite>(
        &mut self,
        w: &mut W,
        tmpl: &TemplateNode,
        dot: &Value,
    ) -> ExecResult<()> {
        let new_dot = if let Some(ref pipe) = tmpl.pipe {
            self.eval_pipeline(dot, pipe)?
        } else {
            dot.clone()
        };

        #[cfg(not(feature = "html"))]
        let dynamic = match &self.definition_lookup {
            Some(lookup) => lookup(&tmpl.name).map_err(|error| {
                TemplateError::Exec(format!("template {:?}: {error}", tmpl.name))
            })?,
            None => None,
        };
        #[cfg(feature = "html")]
        let dynamic: Option<Arc<ListNode>> = None;
        let tree = dynamic.or_else(|| self.templates.get(tmpl.name.as_bytes()).cloned())
            .ok_or_else(|| TemplateError::UndefinedTemplate(crate::quote_go_string(tmpl.name.as_bytes(),false).unwrap_or_default()))?;

        // Template invocations do not inherit the caller's variables. Swap in
        // a fresh scope containing only `$`, matching Go's walkTemplate which
        // rebuilds `state.vars` as `[{"$", dot}]` before recursing.
        let saved = core::mem::replace(&mut self.vars, VarScope::new());
        self.vars.set(&DOLLAR_KEY, new_dot.clone());
        let result = self.walk(w, &tree, &new_dot);
        self.vars = saved;
        result
    }

    // Pipeline and expression evaluation
    fn eval_pipeline_value(&mut self, dot: &Value, pipe: &PipeNode) -> ExecResult<Value> {
        let mut val = Value::Nil;
        for (i, cmd) in pipe.commands.iter().enumerate() {
            // Move the previous stage's result rather than cloning: it is
            // only used by the next command, and any downstream need for it
            // is already covered by the new `val` we're about to assign.
            let prev = if i > 0 {
                Some(core::mem::replace(&mut val, Value::Nil))
            } else {
                None
            };
            val = self.eval_command(dot, cmd, prev)?;
        }
        Ok(val)
    }

    fn eval_pipeline(&mut self, dot: &Value, pipe: &PipeNode) -> ExecResult<Value> {
        let val = self.eval_pipeline_value(dot, pipe)?;
        match pipe.decl.len() {
            0 => {}
            1 => {
                let name = &pipe.decl[0];
                if pipe.is_assign {
                    self.vars.assign(name, val.clone());
                } else {
                    self.vars.set(name, val.clone());
                }
            }
            n => {
                return Err(TemplateError::Exec(format!(
                    "cannot assign {} variables outside a range pipeline",
                    n
                ))
                .into());
            }
        }
        Ok(val)
    }

    fn eval_command(
        &mut self,
        dot: &Value,
        cmd: &CommandNode,
        piped: Option<Value>,
    ) -> ExecResult<Value> {
        self.charge(1)?;
        let first = &cmd.args[0];

        // If the first arg is an identifier, it's a function call
        if let Expr::Identifier(_, name) = first {
            // Special-case and/or for short-circuit evaluation
            if name.as_str() == "and" || name.as_str() == "or" {
                return self.eval_short_circuit(dot, name, &cmd.args[1..], piped);
            }
            return self.eval_function_call(dot, name, &cmd.args[1..], piped);
        }

        // If the first arg is a Chain with an Identifier inside, it's a function call
        // with field access on the result (e.g., mapOfThree.three)
        if let Expr::Chain(_, inner, fields) = first
            && let Expr::Identifier(_, name) = inner.as_ref()
        {
            if name.as_str() == "and" || name.as_str() == "or" {
                let val = self.eval_short_circuit(dot, name, &cmd.args[1..], piped)?;
                return self.walk_fields(val, fields);
            }
            let val = self.eval_function_call(dot, name, &cmd.args[1..], piped)?;
            return self.walk_fields(val, fields);
        }

        // Non-function command: cannot accept piped values or extra arguments.
        // Go errors with "can't give argument to non-function".
        if piped.is_some() || cmd.args.len() > 1 {
            let method = match first {
                Expr::Field(_, fields) => self.select_method(dot.clone(), fields)?,
                Expr::Variable(_, name, fields) => {
                    let value = self.vars.get(name).cloned().ok_or_else(|| {
                        TemplateError::UndefinedVariable(name.to_string())
                    })?;
                    self.select_method(value, fields)?
                }
                Expr::Chain(_, inner, fields) => {
                    let value = self.eval_expr(dot, inner)?;
                    self.select_method(value, fields)?
                }
                _ => None,
            };
            if let Some((method,signature)) = method {
                let args = self.eval_arguments(dot, &cmd.args[1..], piped, signature.as_ref())?;
                return self.invoke_bound("method", &method, &args);
            }
            return Err(TemplateError::Exec(format!(
                "can't give argument to non-function {}",
                expr_name(first)
            ))
            .into());
        }

        // Go: nil is not a valid command. It cannot be printed or used
        // as a pipeline value. It may only appear as an argument to a function.
        if matches!(first, Expr::Nil(_)) {
            return Err(TemplateError::Exec("nil is not a command".into()).into());
        }

        self.eval_expr(dot, first)
    }

    /// Short-circuit evaluation for `and` and `or`.
    /// Go special-cases these so arguments are evaluated lazily.
    fn eval_short_circuit(
        &mut self,
        dot: &Value,
        name: &str,
        arg_exprs: &[Expr],
        piped: Option<Value>,
    ) -> ExecResult<Value> {
        // Build the full list of expressions: explicit args + piped value
        // Piped value becomes the last argument
        let is_and = name == "and";

        // We need at least 1 argument (plus maybe piped)
        let total = arg_exprs.len() + if piped.is_some() { 1 } else { 0 };
        if total < 1 {
            return Err(TemplateError::ArgCount {
                name: name.to_string(),
                expected: 1,
                got: 0,
            }
            .into());
        }

        let mut last = Value::Nil;

        for expr in arg_exprs {
            let val = self.eval_expr(dot, expr)?;
            if is_and && !val.is_truthy() {
                return Ok(val);
            }
            if !is_and && val.is_truthy() {
                return Ok(val);
            }
            last = val;
        }

        // Handle piped value (becomes last argument)
        if let Some(piped_val) = piped {
            if is_and && !piped_val.is_truthy() {
                return Ok(piped_val);
            }
            if !is_and && piped_val.is_truthy() {
                return Ok(piped_val);
            }
            last = piped_val;
        }

        Ok(last)
    }

    fn eval_function_call(
        &mut self,
        dot: &Value,
        name: &str,
        arg_exprs: &[Expr],
        piped: Option<Value>,
    ) -> ExecResult<Value> {
        let func = self
            .funcs
            .get(name)
            .ok_or_else(|| TemplateError::UndefinedFunction(name.to_string()))?;

        let signature=self.function_signatures.get(name).cloned();
        let args = self.eval_arguments(dot, arg_exprs, piped,signature.as_ref())?;
        self.invoke_func(name, func, &args)
    }

    fn eval_arguments(
        &mut self,
        dot: &Value,
        arg_exprs: &[Expr],
        piped: Option<Value>,
        signature:Option<&crate::Signature>,
    ) -> ExecResult<Vec<Value>> {
        if let Some(signature)=signature{signature.check_len(arg_exprs.len()+usize::from(piped.is_some()))?;}
        let mut args = Vec::with_capacity(arg_exprs.len() + usize::from(piped.is_some()));
        for (index,expr) in arg_exprs.iter().enumerate() {
            self.charge(1)?;
            let kind=signature.map_or(crate::ArgKind::Any,|signature|signature.kind(index));
            let value=match kind.constant(expr)? {Some(value)=>value,None=>{let value=self.eval_expr(dot,expr)?;kind.validate(&value)?;value}};
            args.push(if matches!(kind,crate::ArgKind::Any)&&matches!(value,Value::NilError){Value::Nil}else{value});
        }

        // Piped value becomes the last argument (Go convention)
        if let Some(piped_val) = piped {
            if let Some(signature)=signature{signature.kind(args.len()).validate(&piped_val)?;}
            args.push(if signature.is_none_or(|s|matches!(s.kind(args.len()),crate::ArgKind::Any))&&matches!(piped_val,Value::NilError){Value::Nil}else{piped_val});
        }

        Ok(args)
    }

    fn select_method(&self, value: Value, fields: &[SmolStr]) -> ExecResult<Option<(BoundMethod,Option<crate::Signature>)>> {
        let Some((last, prefix)) = fields.split_last() else { return Ok(None) };
        let value = self.walk_fields(value, prefix)?;
        Ok(match value {
            Value::Object(object) => {
                object.validate_lazy()?;
                object.method(last.as_str()).map(|method|{
                    let signature=method.signature().cloned();
                    let bound=match method{crate::value::MethodRef::Dynamic(function,_)=>BoundMethod::Dynamic(function.clone()),crate::value::MethodRef::Static(method)=>BoundMethod::Static(object.clone(),method)};
                    (bound,signature)
                })
            },
            Value::Slice(slice) => slice.method(last.as_str()).map(|method| {
                (BoundMethod::Slice(slice.clone(),method),method.signature.cloned())
            }),
            Value::NamedInt64(n,kind)=>kind.methods.get(last.as_str()).cloned().map(|method|{
                let signature=kind.signatures.get(last.as_str()).cloned();
                (BoundMethod::Dynamic(Arc::new(move|args:&[Value]|method(n,args))as ValueFunc),signature)
            }),
            _ => None,
        })
    }

    /// Walk a chain of field accesses on `val`.
    fn walk_fields(&self, mut val: Value, fields: &[SmolStr]) -> ExecResult<Value> {
        for field in fields {
            val = self.field_access(&val, field)?;
        }
        Ok(val)
    }

    /// Access a field on a value, respecting missingkey option.
    fn field_access(&self, val: &Value, name: &str) -> ExecResult<Value> {
        self.charge(1)?;
        if let Value::Object(object)=val{object.validate_lazy()?;}
        if let Value::Object(object)=val&&let Some(method)=object.method(name){
            return match method{
                crate::value::MethodRef::Dynamic(function,_)=>self.invoke_func(name,function,&[]),
                crate::value::MethodRef::Static(method)=>self.invoke_callable(name,&[],||(method.invoke)(object,&[])),
            };
        }
        if let Value::Slice(slice)=val && let Some(method)=slice.method(name) {
            return self.invoke_callable(name,&[],||(method.invoke)(slice,&[]));
        }
        if let Value::NamedInt64(n,kind)=val {
            if let Some(method)=kind.methods.get(name){let method=method.clone();let n=*n;return self.invoke_func(name,&(Arc::new(move|args:&[Value]|method(n,args))as ValueFunc),&[]);}
        }
        #[cfg(feature = "std")]
        if let Value::SharedMap(map)=val {
            return match map.get(name)? {
                Some(value)=>{self.charge_values(core::slice::from_ref(&value))?;Ok(value)},
                None if matches!(self.missing_key,MissingKey::Error)=>Err(TemplateError::MissingKey {key:name.to_string()}.into()),
                None=>Ok(Value::Nil),
            };
        }
        #[cfg(feature="std")] if let Value::GenericMap(map)=val{
            return match map.get(&Value::from(name))?{
                Some(value)=>{self.charge_values(core::slice::from_ref(&value))?;Ok(value)},
                None if matches!(self.missing_key,MissingKey::Error)=>Err(TemplateError::MissingKey{key:name.into()}.into()),None=>Ok(Value::Nil),
            };
        }
        if let Value::Object(object)=val {
            if let Some(view)=&object.map_view {
                let snapshot=(view.snapshot)()?;
                return match snapshot.get(name.as_bytes()) {
                    Some(value)=>{self.charge_values(core::slice::from_ref(value))?;Ok(value.clone())},
                    None=>match self.missing_key {
                        MissingKey::Error=>Err(TemplateError::MissingKey{key:name.into()}.into()),
                        MissingKey::ZeroValue=>Ok(view.zero.clone()),
                        _=>Ok(Value::Nil),
                    },
                };
            }
        }
        if let Value::Object(object)=val{if let Some(value)=object.field_value(name)?{self.charge_values(core::slice::from_ref(&value))?;return Ok(value);}}
        match val.field(name) {
            Some(v) => {
                self.charge_values(core::slice::from_ref(v))?;
                Ok(v.clone())
            },
            None if matches!(val, Value::Map(_)) => match self.missing_key {
                MissingKey::Error => Err(TemplateError::MissingKey {
                    key: name.to_string(),
                }
                .into()),
                _ => Ok(Value::Nil),
            },
            None if matches!(val, Value::Nil) => Ok(Value::Nil),
            None => Err(TemplateError::Exec(format!(
                "can't evaluate field {} in type {}",
                name,
                val.type_name()
            ))
            .into()),
        }
    }

    fn charge(&self, units: usize) -> ExecResult<()> {
        if let Some(charge) = &self.execution_charge {
            charge(units)?;
        }
        Ok(())
    }

    fn charge_values(&self, values: &[Value]) -> ExecResult<()> {
        if self.execution_charge.is_none() {
            return Ok(());
        }
        let bytes=measured_values(values,self.value_limit)?;
        self.charge(1+bytes.div_ceil(128))
    }

    fn invoke_bound(&self,name:&str,method:&BoundMethod,args:&[Value])->ExecResult<Value>{
        match method{BoundMethod::Dynamic(function)=>self.invoke_func(name,function,args),BoundMethod::Static(receiver,method)=>self.invoke_callable(name,args,||(method.invoke)(receiver,args)),BoundMethod::Slice(receiver,method)=>self.invoke_callable(name,args,||(method.invoke)(receiver,args))}
    }
    fn invoke_func(&self,name:&str,function:&ValueFunc,args:&[Value])->ExecResult<Value>{self.invoke_callable(name,args,||function(args))}
    #[cfg(feature="std")]
    fn invoke_callable(&self,name:&str,args:&[Value],call:impl FnOnce()->Result<Value>)->ExecResult<Value>{
        self.charge_values(args)?;
        match catch_unwind(AssertUnwindSafe(call)){
            Ok(result)=>{let value=result?;self.charge_values(core::slice::from_ref(&value))?;Ok(value)},
            Err(payload)=>Err(TemplateError::FuncPanic{name:name.into(),message:panic_payload_to_string(payload)}.into()),
        }
    }
    #[cfg(not(feature="std"))]
    fn invoke_callable(&self,_name:&str,args:&[Value],call:impl FnOnce()->Result<Value>)->ExecResult<Value>{
        self.charge_values(args)?;let value=call()?;self.charge_values(core::slice::from_ref(&value))?;Ok(value)
    }

    fn eval_expr(&mut self, dot: &Value, expr: &Expr) -> ExecResult<Value> {
        self.charge(1)?;
        match expr {
            Expr::Dot(_) => Ok(dot.clone()),

            Expr::Field(_, fields) => self.walk_fields(dot.clone(), fields),

            Expr::Variable(_, name, fields) => {
                let val = self
                    .vars
                    .get(name)
                    .cloned()
                    .ok_or_else(|| TemplateError::UndefinedVariable(name.to_string()))?;
                self.walk_fields(val, fields)
            }

            Expr::String(_, s) => Ok(s.to_value()),

            Expr::Number(_, n) => match *n {
                Number::Int(i) => Ok(Value::Int(i)),
                // A uint literal is an untyped constant that overflowed i64.
                // Go narrows untyped numeric constants to `int` when they are
                // used (its `idealConstant`), so such a literal errors at exec
                // with "N overflows int" in every context. We match that — uint
                // *values* (from data) are unaffected; only literals error.
                Number::Uint(u) => Err(TemplateError::Exec(format!("{u} overflows int")).into()),
                Number::Float(f) => Ok(Value::Float(f)),
            },

            Expr::Bool(_, b) => Ok(Value::Bool(*b)),
            Expr::Nil(_) => Ok(Value::Nil),

            Expr::Pipe(_, pipe) => self.eval_pipeline(dot, pipe),

            Expr::Identifier(_, name) => {
                // Bare identifier, could be a zero-arg function call
                if let Some(func) = self.funcs.get(name.as_str()) {
                    return self.invoke_func(name, func, &[]);
                }
                Err(TemplateError::UndefinedFunction(name.to_string()).into())
            }

            Expr::Chain(_, inner, fields) => {
                let val = self.eval_expr(dot, inner)?;
                self.walk_fields(val, fields)
            }
        }
    }
}

pub(crate) fn measured_values(values:&[Value],limit:usize)->Result<usize>{
    let mut remaining=limit;let mut nodes=16_384usize;for value in values.iter(){measure_value(value,&mut remaining,&mut nodes,0)?;}Ok(limit-remaining)
}
fn measure_value(value: &Value, remaining: &mut usize, nodes:&mut usize, depth: usize) -> Result<()> {
    fn limit() -> TemplateError {
        TemplateError::Exec("template value exceeds execution limits".into())
    }
    if depth > 32 {
        return Err(limit());
    }
    *nodes=nodes.checked_sub(1).ok_or_else(limit)?;
    *remaining = remaining.checked_sub(core::mem::size_of::<Value>().max(32)).ok_or_else(limit)?;
    match value {
        Value::ByteString(bytes)=>*remaining=remaining.checked_sub(bytes.as_bytes().len()).ok_or_else(limit)?,
        Value::String(text) => *remaining = remaining.checked_sub(text.len()).ok_or_else(limit)?,
        Value::Slice(slice)=>{if let Some(values)=slice.retained_values(){for value in values.iter(){measure_value(value,remaining,nodes,depth+1)?;}}else{*remaining=remaining.checked_sub(slice.retained_len()).ok_or_else(limit)?;}},
        Value::List(values) => {
            for value in values.iter() {
                measure_value(value, remaining,nodes, depth + 1)?;
            }
        }
        #[cfg(feature="std")] Value::GenericMap(map)=>{
            map.ensure_depth(depth)?;
            for(key,value)in map.snapshot()?.iter(){measure_value(key,remaining,nodes,depth+1)?;measure_value(value,remaining,nodes,depth+1)?;}
        }
        Value::Map(values) => {
            for (key, value) in values.iter() {
                *remaining = remaining.checked_sub(key.len()).ok_or_else(limit)?;
                measure_value(value, remaining,nodes, depth + 1)?;
            }
        }
        #[cfg(feature = "std")]
        Value::SharedMap(map) => {
            map.ensure_depth(depth)?;
            let snapshot=map.snapshot_go()?;
            for (key,value) in snapshot.iter() {
                *remaining=remaining.checked_sub(key.len()).ok_or_else(limit)?;
                measure_value(value,remaining,nodes,depth+1)?;
            }
        }
        Value::NamedInt64(_,kind)=>{
            *remaining=remaining.checked_sub(kind.name.len()+64).ok_or_else(limit)?;
            for key in kind.methods.keys(){*remaining=remaining.checked_sub(key.len()+32).ok_or_else(limit)?;}
        }
        Value::Object(object) => {
            object.validate_lazy()?;
            *remaining=remaining.checked_sub(object.data_bytes).ok_or_else(limit)?;
            if let Some(json)=&object.json{let bytes=match json{Ok(bytes)|Err(bytes)=>bytes};*remaining=remaining.checked_sub(bytes.len()).ok_or_else(limit)?;}
            if let Some(order)=&object.field_order{for name in order.iter(){*remaining=remaining.checked_sub(name.len()+32).ok_or_else(limit)?;}}
            if let Some(fields)=&object.json_fields{for field in fields.iter(){*remaining=remaining.checked_sub(field.name.len()+field.source.len()+32).ok_or_else(limit)?;}}
            if let Some(display)=&object.display{*remaining=remaining.checked_sub(display.len()).ok_or_else(limit)?;}
            if let Some(view)=&object.map_view {
                let snapshot=(view.snapshot)()?;
                for(key,value)in snapshot.iter(){*remaining=remaining.checked_sub(key.as_bytes().len()).ok_or_else(limit)?;measure_value(value,remaining,nodes,depth+1)?;}
            }
            for (key, value) in &object.fields {
                *remaining = remaining.checked_sub(key.len()).ok_or_else(limit)?;
                if !object.lazy_fields&&object.dynamic_fields.is_some()&&!object.is_nil_pointer(){if let Some(value)=object.field_value(key)?{measure_value(&value,remaining,nodes,depth+1)?;}}else{measure_value(value, remaining,nodes, depth + 1)?;}
            }
            for key in object.methods.keys() {
                *remaining = remaining.checked_sub(key.len() + 32).ok_or_else(limit)?;
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(feature = "std")]
fn panic_payload_to_string(payload: Box<dyn Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "panic".to_string()
    }
}
