use cel::common::ast::{
    CallExpr, ComprehensionExpr, EntryExpr, Expr, IdedExpr, ListExpr, LiteralValue, MapExpr,
    SelectExpr, StructExpr,
};
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap};

pub mod k {
    pub const UNSPECIFIED: u8 = 0;
    pub const DYN: u8 = 1;
    pub const ANY: u8 = 2;
    pub const BOOL: u8 = 3;
    pub const BYTES: u8 = 4;
    pub const DOUBLE: u8 = 5;
    pub const DURATION: u8 = 6;
    pub const ERROR: u8 = 7;
    pub const INT: u8 = 8;
    pub const LIST: u8 = 9;
    pub const MAP: u8 = 10;
    pub const NULL: u8 = 11;
    pub const OPAQUE: u8 = 12;
    pub const STRING: u8 = 13;
    pub const STRUCT: u8 = 14;
    pub const TIMESTAMP: u8 = 15;
    pub const TYPE: u8 = 16;
    pub const TYPE_PARAM: u8 = 17;
    pub const UINT: u8 = 18;
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Ty {
    pub kind: u8,
    pub name: String,
    #[serde(default)]
    pub parameters: Vec<Ty>,
}

impl Ty {
    pub fn dyn_() -> Self {
        Self {
            kind: k::DYN,
            name: "dyn".into(),
            parameters: vec![],
        }
    }
    pub fn bool_() -> Self {
        Self {
            kind: k::BOOL,
            name: "bool".into(),
            parameters: vec![],
        }
    }
    pub fn int() -> Self {
        Self {
            kind: k::INT,
            name: "int".into(),
            parameters: vec![],
        }
    }
    pub fn uint() -> Self {
        Self {
            kind: k::UINT,
            name: "uint".into(),
            parameters: vec![],
        }
    }
    pub fn string() -> Self {
        Self {
            kind: k::STRING,
            name: "string".into(),
            parameters: vec![],
        }
    }
    pub fn bytes() -> Self {
        Self {
            kind: k::BYTES,
            name: "bytes".into(),
            parameters: vec![],
        }
    }
    pub fn double() -> Self {
        Self {
            kind: k::DOUBLE,
            name: "double".into(),
            parameters: vec![],
        }
    }
    pub fn null_() -> Self {
        Self {
            kind: k::NULL,
            name: "null_type".into(),
            parameters: vec![],
        }
    }
    pub fn duration() -> Self {
        Self {
            kind: k::DURATION,
            name: "google.protobuf.Duration".into(),
            parameters: vec![],
        }
    }
    pub fn timestamp() -> Self {
        Self {
            kind: k::TIMESTAMP,
            name: "google.protobuf.Timestamp".into(),
            parameters: vec![],
        }
    }
    pub fn list(elem: Ty) -> Self {
        Self {
            kind: k::LIST,
            name: "list".into(),
            parameters: vec![elem],
        }
    }
    pub fn map(k: Ty, v: Ty) -> Self {
        Self {
            kind: k::MAP,
            name: "map".into(),
            parameters: vec![k, v],
        }
    }
    pub fn type_of(inner: Ty) -> Self {
        Self {
            kind: k::TYPE,
            name: "type".into(),
            parameters: vec![inner],
        }
    }
    pub fn type_param(name: &str) -> Self {
        Self {
            kind: k::TYPE_PARAM,
            name: name.into(),
            parameters: vec![],
        }
    }
    pub fn struct_ty(name: &str) -> Self {
        Self {
            kind: k::STRUCT,
            name: name.into(),
            parameters: vec![],
        }
    }
    pub fn any() -> Self {
        Self {
            kind: k::ANY,
            name: "google.protobuf.Any".into(),
            parameters: vec![],
        }
    }
    pub fn error() -> Self {
        Self {
            kind: k::ERROR,
            name: "error".into(),
            parameters: vec![],
        }
    }

    pub fn is_dyn(&self) -> bool {
        self.kind == k::DYN
    }
    pub fn is_any(&self) -> bool {
        self.kind == k::ANY
    }
    pub fn is_type_param(&self) -> bool {
        self.kind == k::TYPE_PARAM
    }
    pub fn is_error(&self) -> bool {
        self.kind == k::ERROR
    }

    pub fn assignable_to(&self, target: &Ty) -> bool {
        // Meta-type values may be compared even when their represented types
        // differ: type("x") == int is a valid false comparison.
        if self.kind == k::TYPE && target.kind == k::TYPE {
            return true;
        }
        if matches!(self.kind, k::DYN | k::ANY | k::TYPE_PARAM)
            || matches!(target.kind, k::DYN | k::ANY | k::TYPE_PARAM)
        {
            return true;
        }
        if self.kind == target.kind && self.name == target.name {
            if self.parameters.len() != target.parameters.len() {
                return false;
            }
            return self
                .parameters
                .iter()
                .zip(target.parameters.iter())
                .all(|(a, b)| a.assignable_to(b));
        }
        if target.kind == k::ANY {
            return true;
        }
        false
    }

    pub fn merge_container(&self, other: &Ty) -> Ty {
        if self.kind == k::DYN || other.kind == k::DYN {
            return Ty::dyn_();
        }
        if self.kind == other.kind && self.name == other.name {
            return self.clone();
        }
        Ty::dyn_()
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Signature {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub member: bool,
    #[serde(default)]
    pub non_strict: bool,
    pub args: Vec<Ty>,
    pub result: Ty,
    #[serde(default)]
    pub type_params: Vec<String>,
}

pub fn signatures_from_json(json: &str) -> Result<Vec<Signature>, String> {
    serde_json::from_str(json).map_err(|e| format!("signature JSON parse error: {e}"))
}

#[derive(Debug, Clone)]
pub struct ResolvedCall {
    pub name: String,
    pub member: bool,
    pub overload_ids: Vec<String>,
}
#[derive(Debug, Clone)]
pub struct Checked {
    pub root_type: Ty,
    pub type_map: BTreeMap<u64, Ty>,
    pub func_map: BTreeMap<u64, String>,
    pub calls: BTreeMap<u64, ResolvedCall>,
    pub constants: BTreeMap<u64, String>,
}

const MAX_DEPTH: usize = 250;
const MAX_NODES: usize = 30_000;

struct Ctx<'a> {
    global_sigs: HashMap<String, Vec<&'a Signature>>,
    member_sigs: HashMap<String, Vec<&'a Signature>>,
    scope: Vec<HashMap<String, Ty>>,
    type_map: BTreeMap<u64, Ty>,
    func_map: BTreeMap<u64, String>,
    calls: BTreeMap<u64, ResolvedCall>,
    constants: BTreeMap<u64, String>,
    node_count: usize,
    depth: usize,
    fresh_counter: u32,
}

impl<'a> Ctx<'a> {
    fn new(signatures: &'a [Signature]) -> Self {
        let mut global_sigs: HashMap<String, Vec<&'a Signature>> = HashMap::new();
        let mut member_sigs: HashMap<String, Vec<&'a Signature>> = HashMap::new();
        for sig in signatures {
            if sig.member {
                member_sigs.entry(sig.name.clone()).or_default().push(sig);
            } else {
                global_sigs.entry(sig.name.clone()).or_default().push(sig);
            }
        }
        Self {
            global_sigs,
            member_sigs,
            scope: vec![HashMap::new()],
            type_map: BTreeMap::new(),
            func_map: BTreeMap::new(),
            calls: BTreeMap::new(),
            constants: BTreeMap::new(),
            node_count: 0,
            depth: 0,
            fresh_counter: 0,
        }
    }

    fn fresh_type_param(&mut self) -> Ty {
        self.fresh_counter += 1;
        Ty::type_param(&format!("#F{}", self.fresh_counter))
    }

    fn push_scope(&mut self) {
        self.scope.push(HashMap::new());
    }
    fn pop_scope(&mut self) {
        self.scope.pop();
    }

    fn declare(&mut self, name: &str, ty: Ty) {
        self.scope.last_mut().unwrap().insert(name.to_string(), ty);
    }

    fn lookup(&self, name: &str) -> Option<&Ty> {
        for frame in self.scope.iter().rev() {
            if let Some(t) = frame.get(name) {
                return Some(t);
            }
        }
        None
    }

    fn register(&mut self, id: u64, ty: Ty) {
        self.type_map.insert(id, ty);
    }

    fn enter(&mut self) -> Result<(), String> {
        self.node_count += 1;
        if self.node_count > MAX_NODES {
            return Err(format!("node limit exceeded (>{} nodes)", MAX_NODES));
        }
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(format!("depth limit exceeded (>{} levels)", MAX_DEPTH));
        }
        Ok(())
    }

    fn leave(&mut self) {
        self.depth -= 1;
    }
}

fn count_nodes(root: &IdedExpr) -> Result<usize, String> {
    let mut count = 0usize;
    let mut stack: Vec<&IdedExpr> = vec![root];
    while let Some(n) = stack.pop() {
        count += 1;
        let children = match &n.expr {
            Expr::Call(c) => c.args.len() + usize::from(c.target.is_some()),
            Expr::Comprehension(_) => 5,
            Expr::List(l) => l.elements.len(),
            Expr::Map(m) => m.entries.len().saturating_mul(2),
            Expr::Select(_) => 1,
            Expr::Struct(st) => st.entries.len().saturating_mul(2),
            _ => 0,
        };
        if count.saturating_add(stack.len()).saturating_add(children) > MAX_NODES {
            return Err(format!("CEL node count exceeds {MAX_NODES}"));
        }
        match &n.expr {
            Expr::Call(c) => {
                if let Some(ref t) = c.target {
                    stack.push(t);
                }
                stack.extend(c.args.iter());
            }
            Expr::Comprehension(c) => {
                stack.push(&c.iter_range);
                stack.push(&c.accu_init);
                stack.push(&c.loop_cond);
                stack.push(&c.loop_step);
                stack.push(&c.result);
            }
            Expr::List(l) => stack.extend(l.elements.iter()),
            Expr::Map(m) => {
                for e in &m.entries {
                    match &e.expr {
                        EntryExpr::MapEntry(me) => {
                            stack.push(&me.key);
                            stack.push(&me.value);
                        }
                        EntryExpr::StructField(sf) => stack.push(&sf.value),
                    }
                }
            }
            Expr::Select(s) => stack.push(&s.operand),
            Expr::Struct(st) => {
                for e in &st.entries {
                    match &e.expr {
                        EntryExpr::StructField(sf) => stack.push(&sf.value),
                        EntryExpr::MapEntry(me) => {
                            stack.push(&me.key);
                            stack.push(&me.value);
                        }
                    }
                }
            }
            _ => {}
        }
    }
    Ok(count)
}

fn check_expr(ctx: &mut Ctx<'_>, node: &IdedExpr) -> Result<Ty, String> {
    ctx.enter()?;
    let r = check_expr_inner(ctx, node);
    ctx.leave();
    r
}

fn check_expr_inner(ctx: &mut Ctx<'_>, node: &IdedExpr) -> Result<Ty, String> {
    match &node.expr {
        Expr::Literal(lit) => {
            let ty = literal_type(lit);
            ctx.register(node.id, ty.clone());
            Ok(ty)
        }
        Expr::Ident(name) => check_ident(ctx, node, name),
        Expr::Call(call) => check_call(ctx, node, call),
        Expr::Select(sel) => check_select(ctx, node, sel),
        Expr::List(l) => check_list(ctx, node, l),
        Expr::Map(m) => check_map(ctx, node, m),
        Expr::Struct(st) => check_struct(ctx, node, st),
        Expr::Comprehension(c) => check_comprehension(ctx, node, c),
        Expr::Unspecified => Err(format!("node {}: unspecified", node.id)),
    }
}

fn literal_type(lit: &LiteralValue) -> Ty {
    match lit {
        LiteralValue::Boolean(_) => Ty::bool_(),
        LiteralValue::Int(_) => Ty::int(),
        LiteralValue::UInt(_) => Ty::uint(),
        LiteralValue::String(_) => Ty::string(),
        LiteralValue::Bytes(_) => Ty::bytes(),
        LiteralValue::Double(_) => Ty::double(),
        LiteralValue::Null => Ty::null_(),
    }
}

fn check_ident(ctx: &mut Ctx<'_>, node: &IdedExpr, name: &str) -> Result<Ty, String> {
    if let Some(ty) = ctx.lookup(name) {
        let ty = ty.clone();
        ctx.register(node.id, ty.clone());
        return Ok(ty);
    }
    if let Some(ty) = type_constant(name) {
        ctx.constants.insert(node.id, name.to_owned());
        ctx.register(node.id, ty.clone());
        return Ok(ty);
    }
    if name == "req" {
        let ty = Ty::struct_ty("http.Request");
        ctx.register(node.id, ty.clone());
        return Ok(ty);
    }
    Err(format!("node {}: unknown identifier '{}'", node.id, name))
}

fn type_constant(name: &str) -> Option<Ty> {
    match name {
        "bool" => Some(Ty::type_of(Ty::bool_())),
        "int" => Some(Ty::type_of(Ty::int())),
        "uint" => Some(Ty::type_of(Ty::uint())),
        "string" => Some(Ty::type_of(Ty::string())),
        "bytes" => Some(Ty::type_of(Ty::bytes())),
        "double" => Some(Ty::type_of(Ty::double())),
        "null_type" => Some(Ty::type_of(Ty::null_())),
        "list" => Some(Ty::type_of(Ty::list(Ty::dyn_()))),
        "map" => Some(Ty::type_of(Ty::map(Ty::dyn_(), Ty::dyn_()))),
        "type" => Some(Ty::type_of(Ty::dyn_())),
        "google.protobuf.Duration" => Some(Ty::type_of(Ty::duration())),
        "google.protobuf.Timestamp" => Some(Ty::type_of(Ty::timestamp())),
        _ => None,
    }
}

fn check_select(ctx: &mut Ctx<'_>, node: &IdedExpr, sel: &SelectExpr) -> Result<Ty, String> {
    if !sel.test
        && let Some(name) = qualified_name(node)
        && let Some(ty) = type_constant(&name)
    {
        ctx.constants.insert(node.id, name);
        ctx.register(node.id, ty.clone());
        return Ok(ty);
    }
    let op = check_expr(ctx, &sel.operand)?;
    let ty = match op.kind {
        k::DYN | k::ANY => Ty::dyn_(),
        k::MAP
            if op.parameters.len() == 2
                && matches!(
                    op.parameters[0].kind,
                    k::STRING | k::DYN | k::ANY | k::TYPE_PARAM
                ) =>
        {
            op.parameters[1].clone()
        }
        _ => {
            return Err(format!(
                "node {}: cannot select {} on {}",
                node.id, sel.field, op.name
            ));
        }
    };
    let ty = if sel.test { Ty::bool_() } else { ty };
    ctx.register(node.id, ty.clone());
    Ok(ty)
}

fn check_list(ctx: &mut Ctx<'_>, node: &IdedExpr, list: &ListExpr) -> Result<Ty, String> {
    if list.elements.is_empty() {
        let fresh = ctx.fresh_type_param();
        let ty = Ty::list(fresh);
        ctx.register(node.id, ty.clone());
        return Ok(ty);
    }
    let mut elem_ty: Option<Ty> = None;
    for elem in &list.elements {
        let t = check_expr(ctx, elem)?;
        elem_ty = Some(match elem_ty {
            None => t,
            Some(prev) => prev.merge_container(&t),
        });
    }
    let inner = elem_ty.unwrap_or(Ty::dyn_());
    let ty = Ty::list(inner);
    ctx.register(node.id, ty.clone());
    Ok(ty)
}

fn check_map(ctx: &mut Ctx<'_>, node: &IdedExpr, map: &MapExpr) -> Result<Ty, String> {
    if map.entries.is_empty() {
        let fk = ctx.fresh_type_param();
        let fv = ctx.fresh_type_param();
        let ty = Ty::map(fk, fv);
        ctx.register(node.id, ty.clone());
        return Ok(ty);
    }
    let mut key_ty: Option<Ty> = None;
    let mut val_ty: Option<Ty> = None;
    for entry in &map.entries {
        match &entry.expr {
            EntryExpr::MapEntry(me) => {
                let k = check_expr(ctx, &me.key)?;
                let v = check_expr(ctx, &me.value)?;
                key_ty = Some(match key_ty {
                    None => k,
                    Some(prev) => prev.merge_container(&k),
                });
                val_ty = Some(match val_ty {
                    None => v,
                    Some(prev) => prev.merge_container(&v),
                });
            }
            EntryExpr::StructField(sf) => {
                let _ = check_expr(ctx, &sf.value)?;
            }
        }
    }
    let k = key_ty.unwrap_or(Ty::dyn_());
    let v = val_ty.unwrap_or(Ty::dyn_());
    let ty = Ty::map(k, v);
    ctx.register(node.id, ty.clone());
    Ok(ty)
}

fn check_struct(_ctx: &mut Ctx<'_>, node: &IdedExpr, st: &StructExpr) -> Result<Ty, String> {
    Err(format!(
        "node {}: unregistered object type {}",
        node.id, st.type_name
    ))
}

fn check_comprehension(
    ctx: &mut Ctx<'_>,
    node: &IdedExpr,
    c: &ComprehensionExpr,
) -> Result<Ty, String> {
    let range_ty = check_expr(ctx, &c.iter_range)?;

    let (elem_ty, elem_ty2): (Ty, Option<Ty>) = match range_ty.kind {
        k::LIST if range_ty.parameters.len() == 1 => (range_ty.parameters[0].clone(), None),
        k::MAP if range_ty.parameters.len() == 2 => (
            range_ty.parameters[0].clone(),
            Some(range_ty.parameters[1].clone()),
        ),
        // A deliberate extension: ph()'s Any may hold a real list or map.
        // Iteration is checked against the actual value by the evaluator.
        k::DYN | k::ANY => (Ty::dyn_(), None),
        _ => {
            return Err(format!(
                "node {}: comprehension iterates over '{}'",
                node.id, range_ty.name
            ));
        }
    };

    let accu_init_ty = check_expr(ctx, &c.accu_init)?;

    ctx.push_scope();
    ctx.declare(&c.iter_var, elem_ty);
    if let Some(ref v2) = c.iter_var2 {
        ctx.declare(v2, elem_ty2.unwrap_or(Ty::dyn_()));
    }
    ctx.declare(&c.accu_var, accu_init_ty.clone());

    let cond_ty = check_expr(ctx, &c.loop_cond)?;
    if cond_ty.kind != k::BOOL && !cond_ty.is_dyn() && !cond_ty.is_type_param() {
        ctx.pop_scope();
        return Err(format!(
            "node {}: comprehension condition must be bool, got '{}'",
            node.id, cond_ty.name
        ));
    }

    let step_ty = check_expr(ctx, &c.loop_step)?;
    if !step_ty.assignable_to(&accu_init_ty)
        && !accu_init_ty.assignable_to(&step_ty)
        && !step_ty.is_dyn()
        && !accu_init_ty.is_dyn()
    {
        ctx.pop_scope();
        return Err(format!(
            "node {}: comprehension step type '{}' not assignable to accu type '{}'",
            node.id, step_ty.name, accu_init_ty.name
        ));
    }

    let result_ty = check_expr(ctx, &c.result)?;

    ctx.pop_scope();
    ctx.register(node.id, result_ty.clone());
    Ok(result_ty)
}

fn check_call(ctx: &mut Ctx<'_>, node: &IdedExpr, call: &CallExpr) -> Result<Ty, String> {
    let qualified = call
        .target
        .as_ref()
        .and_then(|t| qualified_name(t))
        .map(|n| format!("{n}.{}", call.func_name));
    let namespace = qualified
        .as_ref()
        .is_some_and(|n| ctx.global_sigs.contains_key(n));
    let func_name = if namespace {
        qualified.as_deref().unwrap()
    } else {
        call.func_name.as_str()
    };

    let target_ty = if let Some(t) = call.target.as_ref().filter(|_| !namespace) {
        Some(check_expr(ctx, t)?)
    } else {
        None
    };
    let is_member = target_ty.is_some();

    let mut arg_tys: Vec<Ty> = Vec::with_capacity(call.args.len());
    for arg in &call.args {
        arg_tys.push(check_expr(ctx, arg)?);
    }

    if (func_name == "_&&_" || func_name == "_||_") && !is_member {
        return check_logical_variadic(ctx, node, func_name, &arg_tys);
    }

    if func_name == "_?_:_" && !is_member {
        return check_conditional(ctx, node, &arg_tys);
    }

    let candidates: Vec<&Signature> = if is_member {
        ctx.member_sigs.get(func_name).cloned().unwrap_or_default()
    } else {
        ctx.global_sigs.get(func_name).cloned().unwrap_or_default()
    };

    resolve_call(
        ctx,
        node,
        func_name,
        &arg_tys,
        target_ty.as_ref(),
        &candidates,
        is_member,
    )
}

fn check_logical_variadic(
    ctx: &mut Ctx<'_>,
    node: &IdedExpr,
    func_name: &str,
    arg_tys: &[Ty],
) -> Result<Ty, String> {
    if arg_tys.len() < 2 {
        return Err(format!(
            "node {}: '{}' requires at least 2 arguments, got {}",
            node.id,
            func_name,
            arg_tys.len()
        ));
    }
    for (i, t) in arg_tys.iter().enumerate() {
        if t.kind != k::BOOL && !t.is_dyn() && !t.is_any() {
            return Err(format!(
                "node {}: '{}' arg[{}] is '{}', must be bool",
                node.id, func_name, i, t.name
            ));
        }
    }
    ctx.register(node.id, Ty::bool_());
    ctx.func_map.insert(node.id, func_name.to_string());
    Ok(Ty::bool_())
}

fn check_conditional(ctx: &mut Ctx<'_>, node: &IdedExpr, arg_tys: &[Ty]) -> Result<Ty, String> {
    if arg_tys.len() != 3 {
        return Err(format!(
            "node {}: _?_:_ expects 3 args, got {}",
            node.id,
            arg_tys.len()
        ));
    }
    let cond = &arg_tys[0];
    if cond.kind != k::BOOL && !cond.is_dyn() && !cond.is_any() {
        return Err(format!(
            "node {}: _?_:_ condition is '{}', must be bool",
            node.id, cond.name
        ));
    }
    let result = unify_branches(&arg_tys[1], &arg_tys[2]);
    ctx.register(node.id, result.clone());
    ctx.func_map.insert(node.id, "_?_:_".into());
    Ok(result)
}

fn unify_branches(a: &Ty, b: &Ty) -> Ty {
    if a.is_dyn() || b.is_dyn() {
        return Ty::dyn_();
    }
    if a.kind == k::TYPE_PARAM || b.kind == k::TYPE_PARAM {
        return Ty::dyn_();
    }
    if a.kind == b.kind && a.name == b.name && a.parameters.len() == b.parameters.len() {
        let merged: Vec<Ty> = a
            .parameters
            .iter()
            .zip(b.parameters.iter())
            .map(|(x, y)| unify_branches(x, y))
            .collect();
        return Ty {
            kind: a.kind,
            name: a.name.clone(),
            parameters: merged,
        };
    }
    Ty::dyn_()
}

fn resolve_call(
    ctx: &mut Ctx<'_>,
    node: &IdedExpr,
    func_name: &str,
    arg_tys: &[Ty],
    target_ty: Option<&Ty>,
    candidates: &[&Signature],
    is_member: bool,
) -> Result<Ty, String> {
    let effective_args: Vec<Ty> = if is_member {
        let mut v = Vec::with_capacity(1 + arg_tys.len());
        if let Some(t) = target_ty {
            v.push(t.clone());
        }
        v.extend_from_slice(arg_tys);
        v
    } else {
        arg_tys.to_vec()
    };

    let mut matching = Vec::new();
    let mut result_ty: Option<Ty> = None;
    for sig in candidates {
        if sig.args.len() != effective_args.len() {
            continue;
        }

        let mut bindings: HashMap<String, Ty> = HashMap::new();
        let mut deferred: HashMap<String, Ty> = HashMap::new();
        let mut ok = true;
        for (param, actual) in sig.args.iter().zip(effective_args.iter()) {
            if !unify(param, actual, &mut bindings, &mut deferred) {
                ok = false;
                break;
            }
        }
        if !ok {
            continue;
        }
        // A later concrete argument can still determine a generic parameter.
        // Only variables actually encountered under dyn receive this fallback.
        for (name, value) in deferred {
            bindings.entry(name).or_insert(value);
        }

        let all_bound = sig
            .type_params
            .iter()
            .all(|tp| bindings.contains_key(tp.as_str()));
        if !all_bound {
            continue;
        }

        let result = instantiate(&sig.result, &bindings);
        matching.push(sig.id.clone());
        result_ty =
            Some(result_ty.map_or_else(|| result.clone(), |old| unify_branches(&old, &result)));
    }
    if let Some(result) = result_ty {
        ctx.func_map.insert(node.id, matching[0].clone());
        ctx.calls.insert(
            node.id,
            ResolvedCall {
                name: func_name.to_owned(),
                member: is_member,
                overload_ids: matching,
            },
        );
        ctx.register(node.id, result.clone());
        return Ok(result);
    }

    Err(format!(
        "node {}: no overload of '{}({})' matches (args: [{}])",
        node.id,
        func_name,
        if is_member { "member" } else { "global" },
        effective_args
            .iter()
            .map(|t| t.name.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    ))
}

fn bind_params_dyn(param: &Ty, bindings: &mut HashMap<String, Ty>) {
    if param.kind == k::TYPE_PARAM {
        bindings.entry(param.name.clone()).or_insert_with(Ty::dyn_);
    }
    for nested in &param.parameters {
        bind_params_dyn(nested, bindings);
    }
}

fn unify(param: &Ty, actual: &Ty, bindings: &mut HashMap<String, Ty>, deferred: &mut HashMap<String, Ty>) -> bool {
    if param.kind == k::DYN {
        return true;
    }
    if matches!(actual.kind, k::DYN | k::ANY) {
        bind_params_dyn(param, deferred);
        return true;
    }

    if actual.kind == k::TYPE_PARAM && param.kind != k::TYPE_PARAM {
        return true;
    }
    match param.kind {
        k::TYPE_PARAM => {
            let name = param.name.as_str();
            match bindings.get(name) {
                Some(existing) => {
                    if matches!(existing.kind, k::DYN | k::ANY) {
                        return true;
                    }
                    actual.assignable_to(existing) || existing.assignable_to(actual)
                }
                None => {
                    bindings.insert(name.to_string(), actual.clone());
                    true
                }
            }
        }
        k::LIST => {
            if actual.kind != k::LIST {
                return false;
            }
            if param.parameters.len() == 1 && actual.parameters.len() == 1 {
                unify(&param.parameters[0], &actual.parameters[0], bindings, deferred)
            } else {
                false
            }
        }
        k::MAP => {
            if actual.kind != k::MAP {
                return false;
            }
            if param.parameters.len() == 2 && actual.parameters.len() == 2 {
                unify(&param.parameters[0], &actual.parameters[0], bindings, deferred)
                    && unify(&param.parameters[1], &actual.parameters[1], bindings, deferred)
            } else {
                false
            }
        }
        k::TYPE => {
            actual.kind == k::TYPE
        }
        k::ANY => true,
        k::STRUCT => actual.kind == k::STRUCT && actual.name == param.name,
        k::OPAQUE => actual.kind == k::OPAQUE && actual.name == param.name,
        _ => param.kind == actual.kind && param.name == actual.name,
    }
}

fn instantiate(ty: &Ty, bindings: &HashMap<String, Ty>) -> Ty {
    if ty.kind == k::TYPE_PARAM {
        return bindings
            .get(ty.name.as_str())
            .cloned()
            .unwrap_or_else(Ty::dyn_);
    }
    let params: Vec<Ty> = ty
        .parameters
        .iter()
        .map(|p| instantiate(p, bindings))
        .collect();
    Ty {
        kind: ty.kind,
        name: ty.name.clone(),
        parameters: params,
    }
}

pub fn check(root: &IdedExpr, signatures: &[Signature]) -> Result<Checked, String> {
    let pre = check_infer(root, signatures)?;
    if pre.root_type.kind != k::BOOL {
        return Err(format!(
            "root expression type is '{}' (kind={}), must be bool (kind=3)",
            pre.root_type.name, pre.root_type.kind
        ));
    }
    Ok(pre)
}

pub fn check_infer(root: &IdedExpr, signatures: &[Signature]) -> Result<Checked, String> {
    let n = count_nodes(root)?;
    if n > MAX_NODES {
        return Err(format!("node count {} exceeds limit {}", n, MAX_NODES));
    }

    let mut ctx = Ctx::new(signatures);
    let root_ty = check_expr(&mut ctx, root)?;

    Ok(Checked {
        root_type: root_ty,
        type_map: ctx.type_map,
        func_map: ctx.func_map,
        calls: ctx.calls,
        constants: ctx.constants,
    })
}

pub fn qualified_name(node: &IdedExpr) -> Option<String> {
    match &node.expr {
        Expr::Ident(s) => Some(s.clone()),
        Expr::Select(s) if !s.test => {
            qualified_name(&s.operand).map(|p| format!("{p}.{}", s.field))
        }
        _ => None,
    }
}
