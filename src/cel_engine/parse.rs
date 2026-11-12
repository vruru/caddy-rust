use super::checker::{self, Checked, Signature, Ty};
use cel::Env;
use cel::common::ast::{ComprehensionExpr, Expr, IdedExpr, ListExpr, LiteralValue};
use cel::parser::Macro;
use regex::Regex;
use std::sync::{Arc, LazyLock};

static PLACEHOLDER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"([^\\]|^)\{([a-zA-Z][a-zA-Z0-9_.-]+)\}").unwrap());
static ESCAPED: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\\\{([a-zA-Z][a-zA-Z0-9_.-]+)\}").unwrap());

pub struct Compiled {
    pub env: Arc<Env>,
    pub expression: Arc<IdedExpr>,
    pub checked: Checked,
    pub expanded: String,
}

pub fn environment() -> Result<Env, String> {
    let mut env = Env::stdlib().with_optional_support(false);
    for extension in [
        cel::extensions::strings,
        cel::extensions::lists,
        cel::extensions::math,
    ] {
        env.add_extension(extension).map_err(|e| e.to_string())?;
    }
    super::caddy_macros::add(&mut env)?;
    env.add_macro(Macro::receiver("bind", 3, |helper, target, args| {
        if !matches!(target.as_ref().map(|x|&x.expr),Some(Expr::Ident(n)) if n=="cel") {
            return Ok(None);
        }
        let Expr::Ident(var) = &args[0].expr else {
            return Err(
                helper.new_error(args[0].id, "cel.bind first argument must be an identifier")
            );
        };
        let var = var.clone();
        let result = args.pop().unwrap();
        let init = args.pop().unwrap();
        let iter_range = helper.next_expr(Expr::List(ListExpr::new(Vec::new())));
        let loop_cond = helper.next_expr(Expr::Literal(LiteralValue::Boolean(false.into())));
        let loop_step = helper.next_expr(Expr::Ident(var.clone()));
        Ok(Some(helper.next_expr(Expr::Comprehension(Box::new(
            ComprehensionExpr {
                iter_range,
                iter_var: "#unused".into(),
                iter_var2: None,
                accu_var: var,
                accu_init: init,
                loop_cond,
                loop_step,
                result,
            },
        )))))
    }))
    .map_err(|e| e.to_string())?;
    Ok(env)
}

pub fn compile(source: &str, custom: &[Signature]) -> Result<Compiled, String> {
    if source.len() > 400_000 || source.chars().count() > 100_000 {
        return Err("CEL source exceeds the 100000 character limit".into());
    }
    // Keep both passes identical to the original textual sugar, including inside quotes.
    let expanded = PLACEHOLDER.replace_all(source, "${1}ph(req, \"${2}\")");
    let expanded = ESCAPED.replace_all(&expanded, "{${1}}").into_owned();
    if expanded.chars().count() > 100_000 {
        return Err("expanded CEL source exceeds the 100000 character limit".into());
    }
    let env = Arc::new(environment()?);
    let expression = env
        .parser()
        .max_recursion_depth(250)
        .parse(&expanded)
        .map_err(|e| e.to_string())?;
    let mut signatures = checker::signatures_from_json(include_str!("standard-signatures.json"))?;
    signatures.push(Signature {
        id: "ph_httpRequest_string".into(),
        name: "ph".into(),
        member: false,
        non_strict: false,
        args: vec![Ty::struct_ty("http.Request"), Ty::string()],
        result: Ty::any(),
        type_params: Vec::new(),
    });
    signatures.extend(super::caddy_macros::signatures());
    signatures.extend_from_slice(custom);
    let checked = checker::check(&expression, &signatures)?;
    Ok(Compiled {
        env,
        expression: Arc::new(expression),
        checked,
        expanded,
    })
}
