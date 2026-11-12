use super::checker::{Signature, Ty};
use cel::common::ast::{
    CallExpr, EntryExpr, Expr, IdedEntryExpr, IdedExpr, ListExpr, LiteralValue, MapEntryExpr,
    MapExpr,
};
use cel::{
    Env,
    parser::{Macro, MacroExprHelper, ParseError},
};

#[derive(Clone, Copy)]
enum Shape {
    List,
    String,
    Pair,
    Triple,
    Map,
}
const FUNCTIONS: &[(&str, &str, Shape)] = &[
    ("host", "host_match_request_list", Shape::List),
    ("path", "path_match_request_list", Shape::List),
    ("method", "method_request_list", Shape::List),
    ("remote_ip", "remote_ip_match_request_list", Shape::List),
    ("client_ip", "client_ip_match_request_list", Shape::List),
    ("protocol", "protocol_request_string", Shape::String),
    ("path_regexp", "path_regexp_request_string", Shape::String),
    (
        "path_regexp",
        "path_regexp_request_string_string",
        Shape::Pair,
    ),
    (
        "header_regexp",
        "header_regexp_request_string_string",
        Shape::Pair,
    ),
    (
        "header_regexp",
        "header_regexp_request_string_string_string",
        Shape::Triple,
    ),
    (
        "vars_regexp",
        "vars_regexp_request_string_string",
        Shape::Pair,
    ),
    (
        "vars_regexp",
        "vars_regexp_request_string_string_string",
        Shape::Triple,
    ),
    ("url_pattern", "url_pattern_request_string", Shape::String),
    (
        "url_pattern",
        "url_pattern_request_string_string",
        Shape::Pair,
    ),
    ("query", "query_matcher_request_map", Shape::Map),
    ("header", "header_matcher_request_map", Shape::Map),
    ("vars", "vars_matcher_request_map", Shape::Map),
];
fn string_literal(e: &IdedExpr) -> bool {
    matches!(&e.expr, Expr::Literal(LiteralValue::String(_)))
}
fn placeholder(e: &IdedExpr) -> bool {
    matches!(&e.expr,Expr::Call(c) if c.func_name=="ph")
}
fn string_expression(e: &IdedExpr) -> bool {
    if string_literal(e) || placeholder(e) {
        return true;
    }
    matches!(&e.expr,Expr::Call(c) if c.target.is_none() && c.func_name=="_+_" && c.args.iter().all(string_expression))
}
fn string_list(e: &IdedExpr) -> bool {
    matches!(&e.expr,Expr::List(l) if l.elements.iter().all(string_expression))
}
fn map_expression(e: &IdedExpr) -> bool {
    matches!(&e.expr,Expr::Map(m) if m.entries.iter().all(|entry|match &entry.expr{
        EntryExpr::MapEntry(e)=>string_expression(&e.key)&&(string_expression(&e.value)||string_list(&e.value)),
        _=>false,
    }))
}
fn file_map(e: &IdedExpr) -> bool {
    matches!(&e.expr,Expr::Map(m) if m.entries.iter().all(|entry|match &entry.expr{
        EntryExpr::MapEntry(e)=>match &e.key.expr{
            Expr::Literal(LiteralValue::String(s))=>match s.inner(){
                "try_files"|"split_path"=>string_list(&e.value),
                "try_policy"|"root"=>string_expression(&e.value),
                _=>false,
            },
            _=>false,
        },
        _=>false,
    }))
}
fn call(helper: &mut MacroExprHelper<'_>, name: &str, data: IdedExpr) -> IdedExpr {
    let req = helper.next_expr(Expr::Ident("req".into()));
    helper.next_expr(Expr::Call(CallExpr {
        func_name: name.into(),
        target: None,
        args: vec![req, data],
    }))
}
fn expand(
    helper: &mut MacroExprHelper<'_>,
    name: &str,
    shape: Shape,
    args: &mut Vec<IdedExpr>,
) -> Result<Option<IdedExpr>, ParseError> {
    let valid = match shape {
        Shape::Map => args.len() == 1 && map_expression(&args[0]),
        _ => !args.is_empty() && args.iter().all(string_expression),
    };
    if !valid {
        return Err(helper.new_error(
            args.first().map_or(0, |e| e.id),
            "invalid Caddy matcher literal arguments",
        ));
    }
    let data = match shape {
        Shape::String | Shape::Map => args.remove(0),
        _ => helper.next_expr(Expr::List(ListExpr::new(std::mem::take(args)))),
    };
    Ok(Some(call(helper, name, data)))
}
pub fn add(env: &mut Env) -> Result<(), String> {
    for &(public, internal, shape) in FUNCTIONS {
        let expander =
            move |h: &mut MacroExprHelper<'_>,
                  _: &mut Option<IdedExpr>,
                  args: &mut Vec<IdedExpr>| expand(h, internal, shape, args);
        let mac = match shape {
            Shape::List => Macro::global_var_arg(public, expander),
            Shape::String | Shape::Map => Macro::global(public, 1, expander),
            Shape::Pair => Macro::global(public, 2, expander),
            Shape::Triple => Macro::global(public, 3, expander),
        };
        env.add_macro(mac).map_err(|e| e.to_string())?;
    }
    env.add_macro(Macro::global_var_arg("file", |h, _, args| {
        let data = if args.len() == 1 && file_map(&args[0]) {
            args.remove(0)
        } else {
            if !args.iter().all(|e| string_literal(e) || placeholder(e)) {
                return Err(h.new_error(
                    args.first().map_or(0, |e| e.id),
                    "file matcher expects literal paths or map",
                ));
            }
            let entries = if args.is_empty() {
                Vec::new()
            } else {
                let key = h.next_expr(Expr::Literal(LiteralValue::String("try_files".into())));
                let value = h.next_expr(Expr::List(ListExpr::new(std::mem::take(args))));
                let temp = h.next_expr(Expr::Literal(LiteralValue::Null));
                vec![IdedEntryExpr {
                    id: temp.id,
                    expr: EntryExpr::MapEntry(MapEntryExpr {
                        key,
                        value,
                        optional: false,
                    }),
                }]
            };
            h.next_expr(Expr::Map(MapExpr { entries }))
        };
        Ok(Some(call(h, "file", data)))
    }))
    .map_err(|e| e.to_string())
}
pub fn signatures() -> Vec<Signature> {
    let mut out = Vec::new();
    for &(_, name, shape) in FUNCTIONS {
        let data = match shape {
            Shape::Map => Ty::map(Ty::string(), Ty::dyn_()),
            Shape::String => Ty::string(),
            _ => Ty::list(Ty::string()),
        };
        out.push(Signature {
            id: name.into(),
            name: name.into(),
            member: false,
            non_strict: false,
            args: vec![Ty::struct_ty("http.Request"), data],
            result: Ty::bool_(),
            type_params: Vec::new(),
        });
    }
    for name in ["file", "file_request_map"] {
        out.push(Signature {
            id: "file_request_map".into(),
            name: name.into(),
            member: false,
            non_strict: false,
            args: vec![
                Ty::struct_ty("http.Request"),
                Ty::map(Ty::string(), Ty::dyn_()),
            ],
            result: Ty::bool_(),
            type_params: Vec::new(),
        });
    }
    out
}
