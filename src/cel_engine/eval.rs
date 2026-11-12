use super::checker::{Checked, ResolvedCall};
use cel::common::ast::{ComprehensionExpr, EntryExpr, Expr, IdedExpr};
use cel::common::types::{CelBool, CelBytes, CelInt, CelList, CelMap, CelMapKey, CelString};
use cel::common::value::Val;
use std::{collections::HashMap, future::Future, pin::Pin, sync::Arc, task::Poll};

pub type V = Arc<dyn Val>;
pub type R = Result<V, EvalError>;
#[derive(Debug, Clone)]
pub struct EvalError {
    pub message: String,
    pub fatal: bool,
}
impl EvalError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            fatal: false,
        }
    }
    pub fn fatal(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            fatal: true,
        }
    }
}
pub trait Host: Send {
    fn invoke<'a>(
        &'a mut self,
        name: &'a str,
        member: bool,
        args: Vec<V>,
    ) -> Pin<Box<dyn Future<Output = R> + Send + 'a>>;
    fn invoke_call<'a>(
        &'a mut self,
        call: &'a ResolvedCall,
        args: Vec<V>,
    ) -> Pin<Box<dyn Future<Output = R> + Send + 'a>> {
        // CEL's standard dyn is identity. Keep the immutable value's Arc;
        // CowVal::into_owned would otherwise clone a whole container tree.
        // Exact overload identity leaves custom/member functions untouched.
        if call.name == "dyn"
            && !call.member
            && args.len() == 1
            && call.overload_ids.len() == 1
            && call.overload_ids[0] == "to_dyn"
        {
            let result = self.tick(1, 256).map(|()| args[0].clone());
            return Box::pin(async move { result });
        }
        self.invoke(&call.name, call.member, args)
    }
    fn tick(&mut self, steps: u64, bytes: usize) -> Result<(), EvalError>;
    /// Materialize a host value only when a local identifier is actually read.
    /// Iteration/binding creation must not eagerly observe unused elements.
    fn observe_value(&mut self, value: V) -> R {
        Ok(value)
    }
    /// Build evaluated interleaved key/value entries. The evaluator has already
    /// reserved the literal's frame/table metadata; implementations charge any
    /// owned value copies or additional native representation here.
    fn make_map(&mut self, values: Vec<V>) -> R {
        default_map(self, values)
    }
    /// Materialize iteration bindings without observing unused host values.
    /// Native map representations can preserve keys in two-variable iteration.
    fn iteration_items(&mut self, value: &V, two_vars: bool) -> Result<Items, EvalError> {
        default_iteration(self, value, two_vars)
    }
}
pub fn string(s: &str) -> V {
    Arc::new(CelString::from(s.to_owned()))
}
pub fn boolean(v: bool) -> V {
    Arc::new(CelBool::from(v))
}
fn as_bool(v: &V) -> Option<bool> {
    v.downcast_ref::<CelBool>().map(|x| *x.inner())
}

/// Charge the exact reachable built-in value graph before cloning it.
pub fn charge_clone(host: &mut (impl Host + ?Sized), value: &dyn Val) -> Result<(), EvalError> {
    fn walk(
        host: &mut (impl Host + ?Sized),
        value: &dyn Val,
        depth: usize,
        nodes: &mut usize,
    ) -> Result<(), EvalError> {
        *nodes += 1;
        if depth > 250 || *nodes > 30_000 {
            return Err(EvalError::fatal("CEL value graph limit"));
        }
        host.tick(1, 128)?;
        if let Some(s) = value.downcast_ref::<CelString>() {
            host.tick(0, s.inner().len())?;
        }
        if let Some(s) = value.downcast_ref::<CelBytes>() {
            host.tick(0, s.inner().len())?;
        }
        if let Some(list) = value.downcast_ref::<CelList>() {
            host.tick(
                0,
                list.inner()
                    .len()
                    .checked_mul(32)
                    .ok_or_else(|| EvalError::fatal("CEL allocation overflow"))?,
            )?;
            for value in list.inner() {
                walk(host, value.as_ref(), depth + 1, nodes)?;
            }
        }
        if let Some(map) = value.downcast_ref::<CelMap>() {
            host.tick(
                0,
                map.inner()
                    .len()
                    .checked_mul(128)
                    .ok_or_else(|| EvalError::fatal("CEL allocation overflow"))?,
            )?;
            for (key, value) in map.inner() {
                walk(host, key.inner(), depth + 1, nodes)?;
                walk(host, value.as_ref(), depth + 1, nodes)?;
            }
        }
        Ok(())
    }
    walk(host, value, 0, &mut 0)
}

fn clone_value(host: &mut (impl Host + ?Sized), v: &(dyn Val + 'static)) -> R {
    charge_clone(host, v)?;
    Ok(Arc::from(v.clone_as_boxed()))
}
pub fn default_map(host: &mut (impl Host + ?Sized), values: Vec<V>) -> R {
    if !values.len().is_multiple_of(2) {
        return Err(EvalError::fatal("CEL map stack underflow"));
    }
    let mut map = HashMap::with_capacity(values.len() / 2);
    let mut pairs = values.into_iter();
    let mut err = None;
    while let Some(key) = pairs.next() {
        let value = pairs
            .next()
            .ok_or_else(|| EvalError::fatal("CEL map stack underflow"))?;
        charge_clone(host, key.as_ref())?;
        charge_clone(host, value.as_ref())?;
        match CelMapKey::try_from(key.clone_as_boxed()) {
            Ok(key) => {
                map.insert(key, value.clone_as_boxed());
            }
            Err(e) => err = Some(EvalError::new(e.to_string())),
        }
    }
    match err {
        Some(e) => Err(e),
        None => Ok(Arc::new(CelMap::from(map)) as V),
    }
}

enum Binding<'a> {
    Ready(R),
    Lazy {
        expression: &'a IdedExpr,
        outer_depth: usize,
    },
}
type Scope<'a> = HashMap<String, Binding<'a>>;
pub type Items = Arc<Vec<(V, Option<V>)>>;
struct Fold<'a> {
    comp: &'a ComprehensionExpr,
    items: Items,
    next: usize,
    depth: usize,
}
enum Finish<'a> {
    Call(&'a ResolvedCall),
    List,
    Map,
}
enum Frame<'a> {
    Sequence {
        nodes: Vec<&'a IdedExpr>,
        next: usize,
        base: usize,
        finish: Finish<'a>,
    },
    FoldRange(&'a ComprehensionExpr),
    Eval(&'a IdedExpr),
    Apply {
        call: &'a ResolvedCall,
        count: usize,
    },
    Select {
        field: &'a str,
        test: bool,
    },
    List(usize),
    Map(usize),
    Logic {
        args: &'a [IdedExpr],
        next: usize,
        or: bool,
        error: Option<EvalError>,
    },
    Conditional {
        yes: &'a IdedExpr,
        no: &'a IdedExpr,
    },
    RestoreLazy {
        scope: usize,
        name: String,
        suspended: Vec<Scope<'a>>,
    },
    FoldNext(Fold<'a>),
    FoldCondition(Fold<'a>),
    FoldStep(Fold<'a>),
    FoldDone(usize),
}
fn take(results: &mut Vec<R>, count: usize) -> Result<Vec<R>, EvalError> {
    let at = results
        .len()
        .checked_sub(count)
        .ok_or_else(|| EvalError::fatal("CEL result stack underflow"))?;
    Ok(results.split_off(at))
}
fn collect(values: Vec<R>) -> Result<Vec<V>, EvalError> {
    values.into_iter().collect()
}
fn stack_pop(results: &mut Vec<R>) -> R {
    results
        .pop()
        .unwrap_or_else(|| Err(EvalError::fatal("CEL result stack underflow")))
}
async fn yield_once() {
    let mut yielded = false;
    std::future::poll_fn(|cx| {
        if yielded {
            Poll::Ready(())
        } else {
            yielded = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    })
    .await
}
pub fn default_iteration(
    host: &mut (impl Host + ?Sized),
    value: &V,
    two_vars: bool,
) -> Result<Items, EvalError> {
    let mut items = Vec::new();
    if let Some(map) = value.downcast_ref::<CelMap>() {
        host.tick(
            0,
            map.inner()
                .len()
                .checked_mul(64)
                .ok_or_else(|| EvalError::fatal("CEL iteration overflow"))?,
        )?;
        for (key, v) in map.inner() {
            let k = clone_value(host, key.inner())?;
            let v = if two_vars {
                Some(clone_value(host, v.as_ref())?)
            } else {
                None
            };
            items.push((k, v));
        }
    } else if let Some(list) = value.as_iterable() {
        let mut iter = list.iter();
        let mut index = 0i64;
        while let Some(v) = iter.next() {
            host.tick(1, 64)?;
            let v = clone_value(host, v)?;
            items.push(if two_vars {
                (Arc::new(CelInt::from(index)) as V, Some(v))
            } else {
                (v, None)
            });
            index = index
                .checked_add(1)
                .ok_or_else(|| EvalError::fatal("CEL iteration overflow"))?;
        }
    } else {
        return Err(EvalError::new("CEL comprehension requires list or map"));
    }
    Ok(Arc::new(items))
}
pub async fn evaluate(root: &IdedExpr, checked: &Checked, host: &mut impl Host) -> R {
    host.tick(0, 1024)?;
    let mut frames = vec![Frame::Eval(root)];
    let mut results: Vec<R> = Vec::new();
    let mut scopes: Vec<Scope> = Vec::new();
    let mut ticks = 0u64;
    while let Some(frame) = frames.pop() {
        // Fatal host failures are execution failures, never CEL ordinary errors.
        // Non-strict helpers may absorb ordinary errors, but not resource,
        // cancellation, or adapter failures actually observed by this execution.
        if matches!(results.last(), Some(Err(error)) if error.fatal) {
            return stack_pop(&mut results);
        }
        host.tick(1, 256)?;
        ticks += 1;
        if ticks.is_multiple_of(128) {
            yield_once().await;
        }
        match frame {
            Frame::Eval(node) if checked.constants.contains_key(&node.id) => {
                let name = &checked.constants[&node.id];
                host.tick(0, name.len() + 64)?;
                results.push(host.invoke("@ident", false, vec![string(name)]).await);
            }
            Frame::Eval(node) => match &node.expr {
                Expr::Literal(lit) => {
                    let val: cel::common::value::CowVal<'_, 'static> = lit.to_val();
                    results.push(clone_value(host, val.as_ref()));
                }
                Expr::Ident(name) => {
                    let local = scopes.iter().rposition(|s| s.contains_key(name));
                    match local {
                        Some(scope) => match scopes[scope].get(name).unwrap() {
                            Binding::Ready(value) => {
                                results.push(
                                    value.clone().and_then(|value| host.observe_value(value)),
                                );
                            }
                            Binding::Lazy {
                                expression,
                                outer_depth,
                            } => {
                                let expression = *expression;
                                let outer_depth = *outer_depth;
                                host.tick(0, name.len() + scopes.len() * 32)?;
                                let suspended = scopes.split_off(outer_depth);
                                frames.push(Frame::RestoreLazy {
                                    scope,
                                    name: name.clone(),
                                    suspended,
                                });
                                frames.push(Frame::Eval(expression));
                            }
                        },
                        None => {
                            host.tick(0, name.len() + 64)?;
                            results.push(host.invoke("@ident", false, vec![string(name)]).await);
                        }
                    }
                }
                Expr::Call(call)
                    if call.target.is_none()
                        && matches!(call.func_name.as_str(), "_&&_" | "_||_") =>
                {
                    if call.args.len() < 2 {
                        return Err(EvalError::fatal("invalid CEL logical arity"));
                    }
                    frames.push(Frame::Logic {
                        args: &call.args,
                        next: 1,
                        or: call.func_name == "_||_",
                        error: None,
                    });
                    frames.push(Frame::Eval(&call.args[0]));
                }
                Expr::Call(call) if call.target.is_none() && call.func_name == "_?_:_" => {
                    if call.args.len() != 3 {
                        return Err(EvalError::fatal("invalid CEL conditional arity"));
                    }
                    frames.push(Frame::Conditional {
                        yes: &call.args[1],
                        no: &call.args[2],
                    });
                    frames.push(Frame::Eval(&call.args[0]));
                }
                Expr::Call(call) => {
                    let resolved = checked
                        .calls
                        .get(&node.id)
                        .ok_or_else(|| EvalError::fatal("CEL call has no checked reference"))?;
                    let member = resolved.member;
                    let count = call.args.len() + usize::from(member);
                    host.tick(
                        count as u64,
                        count
                            .checked_mul(256)
                            .ok_or_else(|| EvalError::fatal("CEL frame overflow"))?,
                    )?;
                    let mut nodes = Vec::with_capacity(count);
                    if member {
                        nodes.push(call.target.as_ref().unwrap().as_ref());
                    }
                    nodes.extend(call.args.iter());
                    frames.push(Frame::Sequence {
                        nodes,
                        next: 0,
                        base: results.len(),
                        finish: Finish::Call(resolved),
                    });
                }
                Expr::Select(sel) => {
                    frames.push(Frame::Select {
                        field: &sel.field,
                        test: sel.test,
                    });
                    frames.push(Frame::Eval(&sel.operand));
                }
                Expr::List(list) => {
                    if !list.optional_indices.is_empty() {
                        return Err(EvalError::fatal("optional CEL syntax not enabled"));
                    }
                    host.tick(
                        0,
                        list.elements
                            .len()
                            .checked_mul(256)
                            .ok_or_else(|| EvalError::fatal("CEL frame overflow"))?,
                    )?;
                    frames.push(Frame::Sequence {
                        nodes: list.elements.iter().collect(),
                        next: 0,
                        base: results.len(),
                        finish: Finish::List,
                    });
                }
                Expr::Map(map) => {
                    host.tick(
                        0,
                        map.entries
                            .len()
                            .checked_mul(512)
                            .ok_or_else(|| EvalError::fatal("CEL frame overflow"))?,
                    )?;
                    let mut nodes = Vec::with_capacity(map.entries.len() * 2);
                    for e in &map.entries {
                        let EntryExpr::MapEntry(e) = &e.expr else {
                            return Err(EvalError::fatal("invalid CEL map entry"));
                        };
                        if e.optional {
                            return Err(EvalError::fatal("optional CEL syntax not enabled"));
                        }
                        nodes.push(&e.key);
                        nodes.push(&e.value);
                    }
                    frames.push(Frame::Sequence {
                        nodes,
                        next: 0,
                        base: results.len(),
                        finish: Finish::Map,
                    });
                }
                Expr::Comprehension(comp) => {
                    frames.push(Frame::FoldRange(comp));
                    frames.push(Frame::Eval(&comp.iter_range));
                }
                _ => results.push(Err(EvalError::new("unregistered CEL object"))),
            },
            Frame::Sequence {
                nodes,
                next,
                base,
                finish,
            } => {
                if next > 0
                    && matches!(results.last(), Some(Err(_)))
                    && !matches!(&finish,Finish::Call(call) if matches!(call.name.as_str(),"@not_strictly_false"|"__not_strictly_false__"))
                {
                    let e = stack_pop(&mut results);
                    results.truncate(base);
                    results.push(e);
                    continue;
                }
                if next < nodes.len() {
                    let e = nodes[next];
                    frames.push(Frame::Sequence {
                        nodes,
                        next: next + 1,
                        base,
                        finish,
                    });
                    frames.push(Frame::Eval(e));
                } else {
                    frames.push(match finish {
                        Finish::Call(call) => Frame::Apply {
                            call,
                            count: nodes.len(),
                        },
                        Finish::List => Frame::List(nodes.len()),
                        Finish::Map => Frame::Map(nodes.len() / 2),
                    });
                }
            }
            Frame::Apply { call, count } => {
                let values = take(&mut results, count)?;
                if matches!(call.name.as_str(),"@not_strictly_false"|"__not_strictly_false__") && count == 1 {
                    let value = &values[0];
                    results.push(Ok(boolean(
                        !matches!(value,Ok(v) if as_bool(v)==Some(false)),
                    )));
                    continue;
                }
                let args = collect(values);
                results.push(match args {
                    Ok(args) => host.invoke_call(call, args).await,
                    Err(e) => Err(e),
                });
            }
            Frame::Select { field, test } => {
                let val = stack_pop(&mut results);
                results.push(match val {
                    Ok(v) => {
                        host.tick(0, field.len() + 64)?;
                        host.invoke(
                            if test { "@has" } else { "_[_]" },
                            false,
                            vec![v, string(field)],
                        )
                        .await
                    }
                    Err(e) => Err(e),
                });
            }
            Frame::List(count) => {
                let values = collect(take(&mut results, count)?);
                results.push(match values {
                    Ok(values) => {
                        let mut list = Vec::with_capacity(count);
                        for v in values {
                            charge_clone(host, v.as_ref())?;
                            list.push(v.clone_as_boxed());
                        }
                        Ok(Arc::new(CelList::from(list)) as V)
                    }
                    Err(e) => Err(e),
                });
            }
            Frame::Map(count) => {
                let values = collect(take(
                    &mut results,
                    count
                        .checked_mul(2)
                        .ok_or_else(|| EvalError::fatal("CEL map overflow"))?,
                )?);
                results.push(match values {
                    Ok(values) => host.make_map(values),
                    Err(e) => Err(e),
                });
            }
            Frame::Logic {
                args,
                next,
                or,
                mut error,
            } => {
                match stack_pop(&mut results) {
                    Ok(v) => match as_bool(&v) {
                        Some(b) if b == or => {
                            results.push(Ok(v));
                            continue;
                        }
                        Some(_) => {}
                        None => {
                            if error.is_none() {
                                error = Some(EvalError::new("CEL logical operand is not bool"));
                            }
                        }
                    },
                    Err(e) => {
                        if e.fatal {
                            return Err(e);
                        }
                        if error.is_none() {
                            error = Some(e);
                        }
                    }
                }
                if next < args.len() {
                    frames.push(Frame::Logic {
                        args,
                        next: next + 1,
                        or,
                        error,
                    });
                    frames.push(Frame::Eval(&args[next]));
                } else {
                    results.push(error.map_or_else(|| Ok(boolean(!or)), Err));
                }
            }
            Frame::Conditional { yes, no } => match stack_pop(&mut results) {
                Ok(v) => match as_bool(&v) {
                    Some(b) => frames.push(Frame::Eval(if b { yes } else { no })),
                    None => results.push(Err(EvalError::new("CEL condition is not bool"))),
                },
                Err(e) => results.push(Err(e)),
            },
            Frame::FoldRange(comp) => match stack_pop(&mut results) {
                Err(e) => results.push(Err(e)),
                Ok(range) => match host.iteration_items(&range, comp.iter_var2.is_some()) {
                    Err(e) => results.push(Err(e)),
                    Ok(items) => {
                        let depth = scopes.len();
                        host.tick(0, comp.accu_var.len() + 128)?;
                        scopes.push(HashMap::from([(
                            comp.accu_var.clone(),
                            Binding::Lazy {
                                expression: &comp.accu_init,
                                outer_depth: depth,
                            },
                        )]));
                        frames.push(Frame::FoldNext(Fold {
                            comp,
                            items,
                            next: 0,
                            depth,
                        }));
                    }
                },
            },
            Frame::RestoreLazy {
                scope,
                name,
                suspended,
            } => {
                let value = stack_pop(&mut results).and_then(|value| host.observe_value(value));
                scopes.extend(suspended);
                scopes[scope].insert(name, Binding::Ready(value.clone()));
                results.push(value);
            }
            Frame::FoldNext(fold) => {
                let comp = fold.comp;
                scopes.truncate(fold.depth + 1);
                if fold.next == fold.items.len() {
                    frames.push(Frame::FoldDone(fold.depth));
                    frames.push(Frame::Eval(&comp.result));
                } else {
                    let (a, b) = &fold.items[fold.next];
                    host.tick(
                        0,
                        comp.iter_var.len() + comp.iter_var2.as_ref().map_or(0, String::len) + 256,
                    )?;
                    let mut local =
                        HashMap::from([(comp.iter_var.clone(), Binding::Ready(Ok(a.clone())))]);
                    if let Some(name) = &comp.iter_var2 {
                        local.insert(
                            name.clone(),
                            Binding::Ready(b.clone().ok_or_else(|| {
                                EvalError::fatal("CEL missing second iteration value")
                            })),
                        );
                    }
                    scopes.push(local);
                    frames.push(Frame::FoldCondition(fold));
                    frames.push(Frame::Eval(&comp.loop_cond));
                }
            }
            Frame::FoldCondition(fold) => {
                let condition = stack_pop(&mut results);
                if matches!(&condition, Ok(v) if as_bool(v) == Some(false)) {
                    scopes.truncate(fold.depth + 1);
                    frames.push(Frame::FoldDone(fold.depth));
                    frames.push(Frame::Eval(&fold.comp.result));
                } else if let Err(e) = condition
                    && e.fatal
                {
                    return Err(e);
                } else {
                    let comp = fold.comp;
                    frames.push(Frame::FoldStep(fold));
                    frames.push(Frame::Eval(&comp.loop_step));
                }
            }
            Frame::FoldStep(mut fold) => {
                let value = stack_pop(&mut results);
                scopes[fold.depth].insert(fold.comp.accu_var.clone(), Binding::Ready(value));
                fold.next += 1;
                frames.push(Frame::FoldNext(fold));
            }
            Frame::FoldDone(depth) => {
                scopes.truncate(depth);
            }
        }
        if let Some(Err(e)) = results.last()
            && e.fatal
        {
            return Err(e.clone());
        }
        if frames.len() > 30_000 || results.len() > 30_000 {
            return Err(EvalError::fatal("CEL evaluation stack limit"));
        }
    }
    if results.len() != 1 {
        return Err(EvalError::fatal("CEL evaluation result imbalance"));
    }
    stack_pop(&mut results)
}
