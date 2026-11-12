use crate::common::ast;
use crate::common::ast::{
    operators, CallExpr, EntryExpr, Expr, IdedEntryExpr, IdedExpr, ListExpr, LiteralValue,
    MapEntryExpr, MapExpr, SelectExpr, SourceInfo, StructExpr, StructFieldExpr,
};
use crate::parser::gen::{
    BoolFalseContext, BoolTrueContext, BytesContext, CELListener, CELParserContextType,
    CalcContext, CalcContextAttrs, ConditionalAndContext, ConditionalOrContext,
    ConstantLiteralContext, ConstantLiteralContextAttrs, CreateListContext, CreateMessageContext,
    CreateStructContext, DoubleContext, EscapeIdentContextAll, ExprContext,
    Field_initializer_listContext, GlobalCallContext, IdentContext, IndexContext,
    IndexContextAttrs, IntContext, ListInitContextAll, LogicalNotContext, LogicalNotContextAttrs,
    MapInitializerListContextAll, MemberCallContext, MemberCallContextAttrs, MemberExprContext,
    MemberExprContextAttrs, NegateContext, NegateContextAttrs, NestedContext, NullContext,
    OptFieldContextAttrs, PrimaryExprContext, PrimaryExprContextAttrs, RelationContext,
    RelationContextAttrs, SelectContext, SelectContextAttrs, StartContext, StartContextAttrs,
    StringContext, UintContext,
};
use crate::parser::macros::Macros;
use crate::parser::{gen, parse};
use antlr4rust::common_token_stream::CommonTokenStream;
use antlr4rust::error_listener::ErrorListener;
use antlr4rust::error_strategy::{DefaultErrorStrategy, ErrorStrategy};
use antlr4rust::errors::ANTLRError;
use antlr4rust::parser::ParserNodeType;
use antlr4rust::parser_rule_context::ParserRuleContext;
use antlr4rust::recognizer::Recognizer;
use antlr4rust::token::{CommonToken, Token};
use antlr4rust::token_factory::TokenFactory;
use antlr4rust::tree::{ParseTree, ParseTreeListener, ParseTreeVisitorCompat, VisitChildren};
use antlr4rust::{tid, InputStream, Parser as AntlrParser};
use std::cell::RefCell;
use std::error::Error;
use std::fmt::Display;
use std::mem;
use std::ops::Deref;
use std::rc::Rc;
use std::sync::Arc;

/// What a [`Macro`](crate::parser::Macro)'s expander builds its expression
/// with, for the call being expanded.
pub struct MacroExprHelper<'a> {
    pub(crate) helper: &'a mut ParserHelper,
    pub(crate) id: u64,
}

impl MacroExprHelper<'_> {
    /// A node for `expr`, with an id of its own, placed in the source where
    /// the expanded call is.
    pub fn next_expr(&mut self, expr: Expr) -> IdedExpr {
        self.helper.next_expr_for(self.id, expr)
    }

    /// An error for the expression `expr_id`, positioned where that expression
    /// is in the source.
    pub fn new_error(&self, expr_id: u64, msg: impl Into<String>) -> ParseError {
        ParseError {
            source: None,
            pos: self.helper.source_info.pos_for(expr_id).unwrap_or_default(),
            msg: msg.into(),
            expr_id: 0,
            source_info: None,
        }
    }
}

#[derive(Debug)]
pub struct ParseErrors {
    pub errors: Vec<ParseError>,
}

impl Display for ParseErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, e) in self.errors.iter().enumerate() {
            if i != 0 {
                writeln!(f)?;
            }
            write!(f, "{e}")?;
        }
        Ok(())
    }
}

impl Error for ParseErrors {}

#[allow(dead_code)]
#[derive(Debug)]
pub struct ParseError {
    pub source: Option<Box<dyn Error + Send + Sync + 'static>>,
    pub pos: (isize, isize),
    pub msg: String,
    pub expr_id: u64,
    pub source_info: Option<Arc<SourceInfo>>,
}

impl Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ERROR: <input>:{}:{}: {}",
            self.pos.0, self.pos.1, self.msg
        )?;
        if let Some(info) = &self.source_info {
            if let Some(line) = info.snippet(self.pos.0 - 1) {
                write!(f, "\n| {line}")?;
                write!(f, "\n| {:.>width$}", "^", width = self.pos.1 as usize)?;
            }
        }
        Ok(())
    }
}

impl Error for ParseError {}

pub struct Parser {
    ast: ast::Ast,
    helper: ParserHelper,
    errors: Vec<ParseError>,
    macros: Arc<Macros>,
    max_recursion_depth: u16,
    error_recovery_limit: u32,
    enable_optional_syntax: bool,
    enable_ident_escape_syntax: bool,
}

impl Parser {
    pub fn new() -> Self {
        Self {
            ast: ast::Ast {
                expr: IdedExpr::default(),
            },
            helper: ParserHelper::default(),
            errors: Vec::default(),
            macros: Macros::standard(),
            max_recursion_depth: 96,
            error_recovery_limit: 30,
            enable_optional_syntax: false,
            enable_ident_escape_syntax: false,
        }
    }

    /// Expands `macros` instead of the standard ones.
    pub(crate) fn with_macros(mut self, macros: Arc<Macros>) -> Self {
        self.macros = macros;
        self
    }

    pub fn max_recursion_depth(mut self, max: u16) -> Self {
        self.max_recursion_depth = if max == u16::MAX { max } else { max + 1 };
        self
    }

    /// Sets the maximum number of error recovery attempts the parser will make
    /// before aborting the parse. Once the limit is reached, the parser reports
    /// `error recovery attempt limit exceeded` and returns.
    pub fn error_recovery_limit(mut self, limit: u32) -> Self {
        self.error_recovery_limit = limit;
        self
    }

    pub fn enable_optional_syntax(mut self, enable: bool) -> Self {
        self.enable_optional_syntax = enable;
        self
    }

    /// Enables backtick-escaped field identifiers (``` `foo.bar` ```).
    ///
    /// With the flag off (the default) the parser rejects any `` `…` ``
    /// -quoted identifier with an `"unsupported syntax: '`'"` parse error.
    /// With the flag on the surrounding backticks are stripped and the
    /// contents are used verbatim as the field name — matching cel-go's
    /// `EnableIdentEscapeSyntax` (`parser/parser.go:161`).
    pub fn enable_ident_escape_syntax(mut self, enable: bool) -> Self {
        self.enable_ident_escape_syntax = enable;
        self
    }

    /// Returns the field name for an `escapeIdent` context, mirroring
    /// cel-go's `normalizeIdent` (`parser/parser.go:161`). Returns an error
    /// message string if the escape syntax is used without opting in.
    fn normalize_ident(&self, ctx: &EscapeIdentContextAll<'_>) -> Result<String, &'static str> {
        match ctx {
            EscapeIdentContextAll::SimpleIdentifierContext(ident) => Ok(ident.get_text()),
            EscapeIdentContextAll::EscapedIdentifierContext(ident) => {
                if !self.enable_ident_escape_syntax {
                    return Err("unsupported syntax: '`'");
                }
                let raw = ident.get_text();
                // Grammar guarantees a leading and trailing backtick plus at
                // least one interior char, so this slice is always safe.
                Ok(raw[1..raw.len() - 1].to_string())
            }
            EscapeIdentContextAll::Error(_) => Err("unsupported ident kind"),
        }
    }

    fn new_logic_manager(&self, func: &str, term: IdedExpr) -> LogicManager {
        LogicManager {
            function: func.to_string(),
            terms: vec![term],
            ops: vec![],
        }
    }

    fn global_call_or_macro(
        &mut self,
        id: u64,
        func_name: String,
        args: Vec<IdedExpr>,
    ) -> IdedExpr {
        self.call_or_macro(id, func_name, None, args)
    }

    fn receiver_call_or_macro(
        &mut self,
        id: u64,
        func_name: String,
        target: IdedExpr,
        args: Vec<IdedExpr>,
    ) -> IdedExpr {
        self.call_or_macro(id, func_name, Some(target), args)
    }

    /// The expansion of the macro matching the call, if any and if it doesn't
    /// decline it; the call as written otherwise.
    fn call_or_macro(
        &mut self,
        id: u64,
        func_name: String,
        mut target: Option<IdedExpr>,
        mut args: Vec<IdedExpr>,
    ) -> IdedExpr {
        if let Some(m) = self.macros.find(&func_name, target.as_ref(), &args) {
            let mut helper = MacroExprHelper {
                helper: &mut self.helper,
                id,
            };
            match m.expand(&mut helper, &mut target, &mut args) {
                Ok(Some(expr)) => return expr,
                Ok(None) => {}
                Err(err) => return self.report_parse_error(None, err),
            }
        }
        IdedExpr {
            id,
            expr: Expr::Call(CallExpr {
                target: target.map(Box::new),
                func_name,
                args,
            }),
        }
    }

    /// Parse, discarding the source info. See [`Parser::parse_with_source_info`].
    pub fn parse(self, source: &str) -> Result<IdedExpr, ParseErrors> {
        self.parse_with_source_info(source).map(|(expr, _)| expr)
    }

    /// Parse, returning the source info alongside the expression.
    ///
    /// The offsets are computed for every node while parsing; this is the only
    /// way to reach them on the success path.
    pub fn parse_with_source_info(
        mut self,
        source: &str,
    ) -> Result<(IdedExpr, SourceInfo), ParseErrors> {
        let parse_errors = Rc::new(RefCell::new(Vec::<ParseError>::new()));
        let stream = InputStream::new(source);
        let mut lexer = gen::CELLexer::new(stream);
        lexer.remove_error_listeners();
        lexer.add_error_listener(Box::new(ParserErrorListener {
            parse_errors: parse_errors.clone(),
        }));

        // todo! might want to avoid this cloning here...
        self.helper.source_info.source = source.into();

        let mut prsr = gen::CELParser::new(CommonTokenStream::new(lexer));
        prsr.remove_error_listeners();
        prsr.add_error_listener(Box::new(ParserErrorListener {
            parse_errors: parse_errors.clone(),
        }));
        prsr.add_parse_listener(Box::new(RecursionListener {
            max: self.max_recursion_depth,
            depth: 0,
        }));
        prsr.set_error_strategy(Box::new(RecoveryLimitErrorStrategy::<
            gen::CELParserContextType,
        >::new(self.error_recovery_limit)));
        let r = match prsr.start() {
            Ok(t) => Ok(self.visit(t.deref())),
            Err(e) => Err(ParseError {
                source: Some(Box::new(e)),
                pos: (0, 0),
                msg: "UNKNOWN".to_string(),
                expr_id: 0,
                source_info: None,
            }),
        };

        let source_info = self.helper.source_info;

        let mut errors = parse_errors.take();
        errors.extend(self.errors);
        errors.sort_by_key(|a| a.pos);

        if errors.is_empty() {
            r.map(|expr| (expr, source_info))
                .map_err(|e| ParseErrors { errors: vec![e] })
        } else {
            // Every error carries the same source info, so it is shared here and
            // nowhere else.
            let source_info = Arc::new(source_info);
            Err(ParseErrors {
                errors: errors
                    .into_iter()
                    .map(|mut e: ParseError| {
                        e.source_info = Some(source_info.clone());
                        e
                    })
                    .collect(),
            })
        }
    }

    fn field_initializer_list(
        &mut self,
        ctx: &Field_initializer_listContext<'_>,
    ) -> Vec<IdedEntryExpr> {
        let mut fields = Vec::with_capacity(ctx.fields.len());
        for (i, field) in ctx.fields.iter().enumerate() {
            if i >= ctx.cols.len() || i >= ctx.values.len() {
                return vec![];
            }
            let id = self.helper.next_id(&ctx.cols[i]);

            match field.escapeIdent() {
                None => {
                    self.report_error::<ParseError, _>(
                        field.start().deref(),
                        None,
                        "unsupported ident type",
                    );
                    continue;
                }
                Some(ident) => {
                    let field_name = match self.normalize_ident(ident.as_ref()) {
                        Ok(name) => name,
                        Err(msg) => {
                            self.report_error::<ParseError, _>(field.start().deref(), None, msg);
                            continue;
                        }
                    };
                    let value = self.visit(ctx.values[i].as_ref());
                    let is_optional = match (&field.opt, self.enable_optional_syntax) {
                        (Some(opt), false) => {
                            self.report_error::<ParseError, _>(
                                opt.as_ref(),
                                None,
                                "unsupported syntax '?'",
                            );
                            continue;
                        }
                        (Some(_), true) => true,
                        (None, _) => false,
                    };
                    fields.push(IdedEntryExpr {
                        id,
                        expr: EntryExpr::StructField(StructFieldExpr {
                            field: field_name,
                            value,
                            optional: is_optional,
                        }),
                    });
                }
            }
        }
        fields
    }

    fn map_initializer_list(&mut self, ctx: &MapInitializerListContextAll) -> Vec<IdedEntryExpr> {
        if ctx.keys.is_empty() {
            return vec![];
        }
        let mut entries = Vec::with_capacity(ctx.cols.len());
        let keys = &ctx.keys;
        let vals = &ctx.values;
        for (i, col) in ctx.cols.iter().enumerate() {
            if i >= keys.len() || i >= vals.len() {
                return vec![];
            }
            let id = self.helper.next_id(col);
            let key = self.visit(keys[i].as_ref());
            let is_optional = match (keys[i].opt.as_ref(), self.enable_optional_syntax) {
                (Some(opt), false) => {
                    self.report_error::<ParseError, _>(
                        opt.as_ref(),
                        None,
                        "unsupported syntax '?'",
                    );
                    continue;
                }
                (Some(_), true) => true,
                (None, _) => false,
            };
            let value = self.visit(vals[i].as_ref());
            entries.push(IdedEntryExpr {
                id,
                expr: EntryExpr::MapEntry(MapEntryExpr {
                    key,
                    value,
                    optional: is_optional,
                }),
            })
        }
        entries
    }

    fn list_initializer_list(&mut self, ctx: &ListInitContextAll) -> (Vec<IdedExpr>, Vec<usize>) {
        let mut list = Vec::default();
        let mut optionals = Vec::default();
        for (i, e) in ctx.elems.iter().enumerate() {
            match &e.e {
                None => return (Vec::default(), Vec::default()),
                Some(exp) => {
                    if let Some(opt) = &e.opt {
                        if self.enable_optional_syntax {
                            optionals.push(i);
                        } else {
                            self.report_error::<ParseError, _>(
                                opt.as_ref(),
                                None,
                                "unsupported syntax '?'",
                            );
                            continue;
                        }
                    }
                    list.push(self.visit(exp.as_ref()));
                }
            }
        }
        (list, optionals)
    }

    fn report_error<E: Error + Send + Sync + 'static, S: Into<String>>(
        &mut self,
        token: &CommonToken,
        e: Option<E>,
        s: S,
    ) -> IdedExpr {
        let error = ParseError {
            source: e.map(|e| e.into()),
            pos: (token.line, token.column + 1),
            msg: s.into(),
            expr_id: 0,
            source_info: None,
        };
        self.report_parse_error(Some(token), error)
    }

    fn report_parse_error(&mut self, token: Option<&CommonToken>, mut e: ParseError) -> IdedExpr {
        let expr = if let Some(token) = token {
            self.helper.next_expr(token, Expr::default())
        } else {
            IdedExpr {
                id: 0,
                expr: Expr::default(),
            }
        };
        e.expr_id = expr.id;
        self.errors.push(e);
        expr
    }
}

struct RecursionListener {
    max: u16,
    depth: u16,
}

impl<'a> CELListener<'a> for RecursionListener {
    fn enter_expr(&mut self, _ctx: &ExprContext<'a>) {
        self.depth = self.depth.saturating_add(1);
    }

    fn exit_expr(&mut self, _ctx: &ExprContext<'a>) {
        self.depth = self.depth.saturating_sub(1);
    }
}

impl<'a> ParseTreeListener<'a, CELParserContextType> for RecursionListener {
    fn enter_every_rule(
        &mut self,
        ctx: &<CELParserContextType as ParserNodeType>::Type,
    ) -> Result<(), ANTLRError> {
        if self.depth > self.max || self.depth == u16::MAX {
            let pos = (ctx.start().get_start(), ctx.stop().get_stop());
            return Err(ANTLRError::OtherError(Arc::new(ParseError {
                source: None,
                pos,
                msg: format!("Recursion limit of {} exceeded", self.max),
                expr_id: 0,
                source_info: None,
            })));
        }
        Ok(())
    }

    fn exit_every_rule(
        &mut self,
        _ctx: &<CELParserContextType as ParserNodeType>::Type,
    ) -> Result<(), ANTLRError> {
        Ok(())
    }
}

#[derive(Debug)]
struct RecoveryLimitExceeded {
    limit: u32,
}

impl Display for RecoveryLimitExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "error recovery attempt limit exceeded: {}", self.limit)
    }
}

impl Error for RecoveryLimitExceeded {}

/// Error strategy that wraps [`DefaultErrorStrategy`] and aborts parsing when
/// the number of recovery attempts exceeds a configurable limit. Modelled on
/// cel-go's `recoveryLimitErrorStrategy`.
struct RecoveryLimitErrorStrategy<'input, Ctx: ParserNodeType<'input>> {
    inner: DefaultErrorStrategy<'input, Ctx>,
    limit: u32,
    attempts: u32,
}

tid! { impl<'i, Ctx> TidAble<'i> for RecoveryLimitErrorStrategy<'i, Ctx> where Ctx: ParserNodeType<'i> }

impl<'input, Ctx: ParserNodeType<'input>> RecoveryLimitErrorStrategy<'input, Ctx> {
    fn new(limit: u32) -> Self {
        Self {
            inner: DefaultErrorStrategy::new(),
            limit,
            attempts: 0,
        }
    }

    #[allow(clippy::result_large_err)]
    fn check_attempts<T>(&mut self, recognizer: &mut T) -> Result<(), ANTLRError>
    where
        T: AntlrParser<'input, Node = Ctx, TF = Ctx::TF>,
    {
        if self.attempts >= self.limit {
            let msg = format!("error recovery attempt limit exceeded: {}", self.limit);
            recognizer.notify_error_listeners(msg, None, None);
            return Err(ANTLRError::FallThrough(Arc::new(RecoveryLimitExceeded {
                limit: self.limit,
            })));
        }
        self.attempts += 1;
        Ok(())
    }
}

impl<'input, T: AntlrParser<'input>> ErrorStrategy<'input, T>
    for RecoveryLimitErrorStrategy<'input, T::Node>
{
    fn reset(&mut self, recognizer: &mut T) {
        self.inner.reset(recognizer)
    }

    fn recover_inline(
        &mut self,
        recognizer: &mut T,
    ) -> Result<<T::TF as TokenFactory<'input>>::Tok, ANTLRError> {
        self.check_attempts(recognizer)?;
        self.inner.recover_inline(recognizer)
    }

    fn recover(&mut self, recognizer: &mut T, e: &ANTLRError) -> Result<(), ANTLRError> {
        self.check_attempts(recognizer)?;
        self.inner.recover(recognizer, e)
    }

    fn sync(&mut self, recognizer: &mut T) -> Result<(), ANTLRError> {
        self.inner.sync(recognizer)
    }

    fn in_error_recovery_mode(&mut self, recognizer: &mut T) -> bool {
        self.inner.in_error_recovery_mode(recognizer)
    }

    fn report_error(&mut self, recognizer: &mut T, e: &ANTLRError) {
        self.inner.report_error(recognizer, e)
    }

    fn report_match(&mut self, recognizer: &mut T) {
        self.inner.report_match(recognizer)
    }
}

struct ParserErrorListener {
    parse_errors: Rc<RefCell<Vec<ParseError>>>,
}

impl<'a, T: Recognizer<'a>> ErrorListener<'a, T> for ParserErrorListener {
    fn syntax_error(
        &self,
        _recognizer: &T,
        _offending_symbol: Option<&<T::TF as TokenFactory<'a>>::Inner>,
        line: isize,
        column: isize,
        msg: &str,
        _error: Option<&ANTLRError>,
    ) {
        self.parse_errors.borrow_mut().push(ParseError {
            source: None,
            pos: (line, column + 1),
            msg: format!("Syntax error: {msg}"),
            expr_id: 0,
            source_info: None,
        })
    }
}

/// Returns true when `name` is a reserved word that may not be used as a plain
/// identifier or function name.  Mirrors the `reservedIds` check in cel-go.
/// Note: `in`, `true`, `false`, `null` are grammar-level keywords that the
/// lexer never produces as IDENTIFIER tokens, so they are not listed here.
fn is_reserved_id(name: &str) -> bool {
    matches!(
        name,
        "as" | "break"
            | "const"
            | "continue"
            | "else"
            | "for"
            | "function"
            | "if"
            | "import"
            | "let"
            | "loop"
            | "package"
            | "namespace"
            | "return"
            | "var"
            | "void"
            | "while"
    )
}

impl Default for Parser {
    fn default() -> Self {
        Self::new()
    }
}

impl ParseTreeVisitorCompat<'_> for Parser {
    type Node = gen::CELParserContextType;
    type Return = IdedExpr;
    fn temp_result(&mut self) -> &mut Self::Return {
        &mut self.ast.expr
    }

    fn visit(&mut self, node: &<Self::Node as ParserNodeType<'_>>::Type) -> Self::Return {
        //println!("{node:?}");
        self.visit_node(node);
        mem::take(self.temp_result())
    }

    fn aggregate_results(&self, _aggregate: Self::Return, next: Self::Return) -> Self::Return {
        next
    }
}

impl gen::CELVisitorCompat<'_> for Parser {
    fn visit_start(&mut self, ctx: &StartContext<'_>) -> Self::Return {
        match &ctx.expr() {
            None => self.report_error::<ParseError, _>(
                ctx.start().deref(),
                None,
                "No `ExprContextAll`!",
            ),
            Some(expr) => self.visit(expr.as_ref()),
        }
    }

    fn visit_expr(&mut self, ctx: &ExprContext<'_>) -> Self::Return {
        match &ctx.op {
            None => match &ctx.e {
                None => self.report_error::<ParseError, _>(
                    ctx.start().deref(),
                    None,
                    "No `ConditionalOrContextAll`!",
                ),
                Some(e) => <Self as ParseTreeVisitorCompat>::visit(self, e.as_ref()),
            },
            Some(op) => {
                if let (Some(e), Some(e1), Some(e2)) = (&ctx.e, &ctx.e1, &ctx.e2) {
                    let result = self.visit(e.as_ref());
                    let op_id = self.helper.next_id(op);
                    let if_true = self.visit(e1.as_ref());
                    let if_false = self.visit(e2.as_ref());
                    self.global_call_or_macro(
                        op_id,
                        operators::CONDITIONAL.to_string(),
                        vec![result, if_true, if_false],
                    )
                } else {
                    self.report_error::<ParseError, _>(
                        ctx.start().deref(),
                        None,
                        format!(
                            "Incomplete `ExprContext` for `{}` expression!",
                            operators::CONDITIONAL
                        ),
                    )
                }
            }
        }
    }

    fn visit_conditionalOr(&mut self, ctx: &ConditionalOrContext<'_>) -> Self::Return {
        let result = match &ctx.e {
            None => {
                self.report_error::<ParseError, _>(
                    ctx.start().deref(),
                    None,
                    "No `ConditionalAndContextAll`!",
                );
                IdedExpr::default()
            }
            Some(e) => <Self as ParseTreeVisitorCompat>::visit(self, e.as_ref()),
        };
        if ctx.ops.is_empty() {
            result
        } else {
            let mut l = self.new_logic_manager(operators::LOGICAL_OR, result);
            let rest = &ctx.e1;
            if ctx.ops.len() > rest.len() {
                // why is >= not ok?
                self.report_error::<ParseError, _>(
                    &ctx.start(),
                    None,
                    "unexpected character, wanted '||'",
                );
                return IdedExpr::default();
            }
            for (i, op) in ctx.ops.iter().enumerate() {
                let next = self.visit(rest[i].deref());
                let op_id = self.helper.next_id(op);
                l.add_term(op_id, next)
            }
            l.expr()
        }
    }

    fn visit_conditionalAnd(&mut self, ctx: &ConditionalAndContext<'_>) -> Self::Return {
        let result = match &ctx.e {
            None => self.report_error::<ParseError, _>(
                ctx.start().deref(),
                None,
                "No `RelationContextAll`!",
            ),
            Some(e) => <Self as ParseTreeVisitorCompat>::visit(self, e.as_ref()),
        };
        if ctx.ops.is_empty() {
            result
        } else {
            let mut l = self.new_logic_manager(operators::LOGICAL_AND, result);
            let rest = &ctx.e1;
            if ctx.ops.len() > rest.len() {
                // why is >= not ok?
                self.report_error::<ParseError, _>(
                    &ctx.start(),
                    None,
                    "unexpected character, wanted '&&'",
                );
                return IdedExpr::default();
            }
            for (i, op) in ctx.ops.iter().enumerate() {
                let next = self.visit(rest[i].deref());
                let op_id = self.helper.next_id(op);
                l.add_term(op_id, next)
            }
            l.expr()
        }
    }

    fn visit_relation(&mut self, ctx: &RelationContext<'_>) -> Self::Return {
        if ctx.op.is_none() {
            match ctx.calc() {
                None => self.report_error::<ParseError, _>(
                    ctx.start().deref(),
                    None,
                    "No `CalcContextAll`!",
                ),
                Some(calc) => <Self as ParseTreeVisitorCompat>::visit(self, calc.as_ref()),
            }
        } else {
            match &ctx.op {
                None => <Self as ParseTreeVisitorCompat>::visit_children(self, ctx),
                Some(op) => {
                    if let (Some(lhs), Some(rhs)) = (ctx.relation(0), ctx.relation(1)) {
                        let lhs = self.visit(lhs.as_ref());
                        let op_id = self.helper.next_id(op.as_ref());
                        let rhs = self.visit(rhs.as_ref());
                        match operators::find_operator(op.get_text()) {
                            None => {
                                self.report_error::<ParseError, _>(
                                    op.as_ref(),
                                    None,
                                    format!("Unknown `{}` operator!", op.get_text()),
                                );
                                IdedExpr::default()
                            }
                            Some(op) => {
                                self.global_call_or_macro(op_id, op.to_string(), vec![lhs, rhs])
                            }
                        }
                    } else {
                        self.report_error::<ParseError, _>(
                            ctx.start().deref(),
                            None,
                            format!("Incomplete `RelationContext` for `{:?}`!", ctx.op),
                        )
                    }
                }
            }
        }
    }

    fn visit_calc(&mut self, ctx: &CalcContext<'_>) -> Self::Return {
        match &ctx.op {
            None => match &ctx.unary() {
                None => self.report_error::<ParseError, _>(
                    ctx.start().deref(),
                    None,
                    "No `UnaryContextAll`!",
                ),
                Some(unary) => self.visit(unary.as_ref()),
            },
            Some(op) => {
                if let (Some(lhs), Some(rhs)) = (ctx.calc(0), ctx.calc(1)) {
                    let lhs = self.visit(lhs.as_ref());
                    let op_id = self.helper.next_id(op);
                    let rhs = self.visit(rhs.as_ref());
                    match operators::find_operator(op.get_text()) {
                        None => self.report_error::<ParseError, _>(
                            op,
                            None,
                            format!("Unknown `{}` operator!", op.get_text()),
                        ),
                        Some(op) => {
                            self.global_call_or_macro(op_id, op.to_string(), vec![lhs, rhs])
                        }
                    }
                } else {
                    self.report_error::<ParseError, _>(
                        ctx.start().deref(),
                        None,
                        "Incomplete `CalcContext`!",
                    )
                }
            }
        }
    }

    fn visit_MemberExpr(&mut self, ctx: &MemberExprContext<'_>) -> Self::Return {
        match &ctx.member() {
            None => {
                self.report_error::<ParseError, _>(&ctx.start(), None, "No `MemberContextAll`!")
            }
            Some(ctx) => <Self as ParseTreeVisitorCompat>::visit(self, ctx.as_ref()),
        }
    }

    fn visit_LogicalNot(&mut self, ctx: &LogicalNotContext<'_>) -> Self::Return {
        match &ctx.member() {
            None => {
                self.report_error::<ParseError, _>(&ctx.start(), None, "No `MemberContextAll`!");
                IdedExpr::default()
            }
            Some(member) => {
                if ctx.ops.len() % 2 == 0 {
                    // Even number of `!` operators cancel — pass through without
                    // wrapping in a LogicalNot call.  Visiting once here and
                    // returning avoids the double-visit that would otherwise
                    // cause exponential work on deeply nested expressions.
                    return self.visit(member.as_ref());
                }
                let op_id = self.helper.next_id(&ctx.ops[0]);
                let target = self.visit(member.as_ref());
                self.global_call_or_macro(op_id, operators::LOGICAL_NOT.to_string(), vec![target])
            }
        }
    }

    fn visit_Negate(&mut self, ctx: &NegateContext<'_>) -> Self::Return {
        match &ctx.member() {
            None => {
                self.report_error::<ParseError, _>(&ctx.start(), None, "No `MemberContextAll`!")
            }
            Some(member) => {
                if ctx.ops.len() % 2 == 0 {
                    // Even number of `-` operators cancel — pass through without
                    // wrapping in a Negate call.
                    return self.visit(member.as_ref());
                }
                let op_id = self.helper.next_id(&ctx.ops[0]);
                let target = self.visit(member.as_ref());
                self.global_call_or_macro(op_id, operators::NEGATE.to_string(), vec![target])
            }
        }
    }

    fn visit_MemberCall(&mut self, ctx: &MemberCallContext<'_>) -> Self::Return {
        if let (Some(operand), Some(id), Some(open)) = (&ctx.member(), &ctx.id, &ctx.open) {
            let operand = self.visit(operand.as_ref());
            let id = id.get_text();
            let op_id = self.helper.next_id(open.as_ref());
            let args = ctx
                .args
                .iter()
                .flat_map(|arg| &arg.e)
                .map(|arg| self.visit(arg.deref()))
                .collect::<Vec<IdedExpr>>();
            self.receiver_call_or_macro(op_id, id.to_string(), operand, args)
        } else {
            self.report_error::<ParseError, _>(
                &ctx.start(),
                None,
                "Incomplete `MemberCallContext`!",
            )
        }
    }

    fn visit_Select(&mut self, ctx: &SelectContext<'_>) -> Self::Return {
        if let (Some(member), Some(id), Some(op)) = (&ctx.member(), &ctx.id, &ctx.op) {
            let operand = self.visit(member.as_ref());
            let field = match self.normalize_ident(id.as_ref()) {
                Ok(f) => f,
                Err(msg) => {
                    return self.report_error::<ParseError, _>(op.as_ref(), None, msg);
                }
            };
            if let Some(_opt) = &ctx.opt {
                return if self.enable_optional_syntax {
                    let field_literal = self.helper.next_expr(
                        op.as_ref(),
                        Expr::Literal(LiteralValue::String(field.clone().into())),
                    );
                    let op_id = self.helper.next_id(op.as_ref());
                    self.global_call_or_macro(
                        op_id,
                        operators::OPT_SELECT.to_string(),
                        vec![operand, field_literal],
                    )
                } else {
                    self.report_error::<ParseError, _>(op.as_ref(), None, "unsupported syntax '.?'")
                };
            }
            self.helper.next_expr(
                op.as_ref(),
                Expr::Select(SelectExpr {
                    operand: Box::new(operand),
                    field,
                    test: false,
                }),
            )
        } else {
            self.report_error::<ParseError, _>(&ctx.start(), None, "Incomplete `SelectContext`!")
        }
    }

    fn visit_PrimaryExpr(&mut self, ctx: &PrimaryExprContext<'_>) -> Self::Return {
        match &ctx.primary() {
            None => {
                self.report_error::<ParseError, _>(&ctx.start(), None, "No `PrimaryContextAll`!")
            }
            Some(primary) => <Self as ParseTreeVisitorCompat>::visit(self, primary.as_ref()),
        }
    }

    fn visit_Index(&mut self, ctx: &IndexContext<'_>) -> Self::Return {
        if let (Some(member), Some(index)) = (&ctx.member(), &ctx.index) {
            let target = self.visit(member.as_ref());
            match &ctx.op {
                None => self.report_error::<ParseError, _>(&ctx.start(), None, "No `Index`!"),
                Some(op) => {
                    let op_id = self.helper.next_id(op);
                    let index = self.visit(index.as_ref());
                    if let Some(_opt) = &ctx.opt {
                        return if self.enable_optional_syntax {
                            self.global_call_or_macro(
                                op_id,
                                operators::OPT_INDEX.to_string(),
                                vec![target, index],
                            )
                        } else {
                            self.report_error::<ParseError, _>(
                                op.as_ref(),
                                None,
                                "unsupported syntax '[?'",
                            )
                        };
                    }
                    self.global_call_or_macro(
                        op_id,
                        operators::INDEX.to_string(),
                        vec![target, index],
                    )
                }
            }
        } else {
            self.report_error::<ParseError, _>(&ctx.start(), None, "Incomplete `IndexContext`!")
        }
    }

    fn visit_Ident(&mut self, ctx: &IdentContext<'_>) -> Self::Return {
        match &ctx.id {
            None => {
                self.report_error::<ParseError, _>(&ctx.start(), None, "No `Identifier`!");
                IdedExpr::default()
            }
            Some(id) => {
                let mut ident = id.clone().text.to_string();
                if ctx.leadingDot.is_some() {
                    ident = format!(".{ident}");
                }
                if is_reserved_id(ident.trim_start_matches('.')) {
                    return self.report_error::<ParseError, _>(
                        id.deref(),
                        None,
                        format!("reserved identifier: {ident}"),
                    );
                }
                self.helper.next_expr(id.deref(), Expr::Ident(ident))
            }
        }
    }

    fn visit_GlobalCall(&mut self, ctx: &GlobalCallContext<'_>) -> Self::Return {
        match &ctx.id {
            None => IdedExpr::default(),
            Some(id) => {
                let raw = id.get_text().to_string();
                if is_reserved_id(&raw) {
                    return self.report_error::<ParseError, _>(
                        id.deref(),
                        None,
                        format!("reserved identifier: {raw}"),
                    );
                }
                let mut id = raw;
                if ctx.leadingDot.is_some() {
                    id = format!(".{id}");
                }
                let op_id = self.helper.next_id_for_token(ctx.op.as_deref());
                let args = ctx
                    .args
                    .iter()
                    .flat_map(|arg| &arg.e)
                    .map(|arg| self.visit(arg.deref()))
                    .collect::<Vec<IdedExpr>>();
                self.global_call_or_macro(op_id, id, args)
            }
        }
    }

    fn visit_Nested(&mut self, ctx: &NestedContext<'_>) -> Self::Return {
        match &ctx.e {
            None => {
                self.report_error::<ParseError, _>(
                    ctx.start().deref(),
                    None,
                    "No `ExprContextAll`!",
                );
                IdedExpr::default()
            }
            Some(e) => self.visit(e.as_ref()),
        }
    }

    fn visit_CreateList(&mut self, ctx: &CreateListContext<'_>) -> Self::Return {
        let list_id = self.helper.next_id_for_token(ctx.op.as_deref());
        let (elements, optionals) = match &ctx.elems {
            None => (Vec::default(), Vec::default()),
            Some(elements) => self.list_initializer_list(elements.deref()),
        };
        IdedExpr {
            id: list_id,
            expr: Expr::List(ListExpr::new_with_optionals(elements, optionals)),
        }
    }

    fn visit_CreateStruct(&mut self, ctx: &CreateStructContext<'_>) -> Self::Return {
        let struct_id = self.helper.next_id_for_token(ctx.op.as_deref());
        let entries = match &ctx.entries {
            Some(entries) => self.map_initializer_list(entries.deref()),
            None => Vec::default(),
        };
        IdedExpr {
            id: struct_id,
            expr: Expr::Map(MapExpr { entries }),
        }
    }

    fn visit_CreateMessage(&mut self, ctx: &CreateMessageContext<'_>) -> Self::Return {
        let mut message_name = String::new();
        for id in &ctx.ids {
            if !message_name.is_empty() {
                message_name.push('.');
            }
            message_name.push_str(id.get_text());
        }
        if ctx.leadingDot.is_some() {
            message_name = format!(".{message_name}");
        }
        let op_id = match &ctx.op {
            None => {
                self.report_error::<ParseError, _>(&ctx.start(), None, "No `CommonToken`!");
                return IdedExpr::default();
            }
            Some(op) => self.helper.next_id(op.as_ref()),
        };
        let entries = match &ctx.entries {
            None => vec![],
            Some(entries) => self.field_initializer_list(entries),
        };
        IdedExpr {
            id: op_id,
            expr: Expr::Struct(StructExpr {
                type_name: message_name,
                entries,
            }),
        }
    }

    fn visit_ConstantLiteral(&mut self, ctx: &ConstantLiteralContext<'_>) -> Self::Return {
        if let Some(literal) = ctx.literal().as_deref() {
            <Self as ParseTreeVisitorCompat>::visit(self, literal)
        } else {
            self.report_error::<ParseError, _>(&ctx.start(), None, "Incomplete ConstantLiteral!")
        }
    }

    fn visit_Int(&mut self, ctx: &IntContext<'_>) -> Self::Return {
        if let Some(token) = ctx.tok.as_ref() {
            // Strip `0x` from the numeric token first, then re-attach the
            // sign — otherwise `-0x…` would be handed to a base-10 parser.
            let raw = token.get_text();
            let (radix, digits) = match raw.strip_prefix("0x") {
                Some(rest) => (16, rest),
                None => (10, raw),
            };
            let signed = if ctx.sign.is_some() {
                format!("-{digits}")
            } else {
                digits.to_string()
            };
            let val = match i64::from_str_radix(&signed, radix) {
                Ok(v) => v,
                Err(e) => return self.report_error(token, Some(e), "invalid int literal"),
            };
            self.helper
                .next_expr(token, Expr::Literal(LiteralValue::Int(val.into())))
        } else {
            self.report_error::<ParseError, _>(&ctx.start(), None, "Incomplete Int!")
        }
    }

    fn visit_Uint(&mut self, ctx: &UintContext<'_>) -> Self::Return {
        let mut string = ctx.get_text();
        string.truncate(string.len() - 1);
        if let Some(token) = ctx.tok.as_ref() {
            let val = match if let Some(string) = string.strip_prefix("0x") {
                u64::from_str_radix(string, 16)
            } else {
                string.parse::<u64>()
            } {
                Ok(v) => v,
                Err(e) => return self.report_error(token, Some(e), "invalid uint literal"),
            };
            self.helper
                .next_expr(token, Expr::Literal(LiteralValue::UInt(val.into())))
        } else {
            self.report_error::<ParseError, _>(&ctx.start(), None, "Incomplete Uint!")
        }
    }

    fn visit_Double(&mut self, ctx: &DoubleContext<'_>) -> Self::Return {
        let string = ctx.get_text();
        if let Some(token) = ctx.tok.as_ref() {
            match string.parse::<f64>() {
                Ok(d) if d.is_finite() => self
                    .helper
                    .next_expr(token, Expr::Literal(LiteralValue::Double(d.into()))),
                Err(e) => self.report_error(token, Some(e), "invalid double literal"),
                _ => self.report_error(token, None::<ParseError>, "invalid double literal"),
            }
        } else {
            self.report_error::<ParseError, _>(
                &ctx.start(),
                None::<ParseError>,
                "Incomplete double!",
            )
        }
    }

    fn visit_String(&mut self, ctx: &StringContext<'_>) -> Self::Return {
        if let Some(token) = ctx.tok.as_deref() {
            match parse::parse_string(&ctx.get_text()) {
                Ok(string) => self
                    .helper
                    .next_expr(token, Expr::Literal(LiteralValue::String(string.into()))),
                Err(e) => self.report_error::<ParseError, _>(
                    token,
                    None,
                    format!("invalid string literal: {e:?}"),
                ),
            }
        } else {
            self.report_error::<ParseError, _>(
                &ctx.start(),
                None::<ParseError>,
                "Incomplete string!",
            )
        }
    }

    fn visit_Bytes(&mut self, ctx: &BytesContext<'_>) -> Self::Return {
        if let Some(token) = ctx.tok.as_deref() {
            let string = ctx.get_text();
            match parse::parse_bytes(&string) {
                Ok(bytes) => self
                    .helper
                    .next_expr(token, Expr::Literal(LiteralValue::Bytes(bytes.into()))),
                Err(e) => {
                    self.report_error::<ParseError, _>(
                        token,
                        None,
                        format!("invalid bytes literal: {e:?}"),
                    );
                    IdedExpr::default()
                }
            }
        } else {
            self.report_error::<ParseError, _>(
                &ctx.start(),
                None::<ParseError>,
                "Incomplete bytes!",
            )
        }
    }

    fn visit_BoolTrue(&mut self, ctx: &BoolTrueContext<'_>) -> Self::Return {
        match ctx.tok.as_deref() {
            Some(tok) => self
                .helper
                .next_expr(tok, Expr::Literal(LiteralValue::Boolean(true.into()))),
            None => self.report_error::<ParseError, _>(&ctx.start(), None, "Incomplete bool!"),
        }
    }

    fn visit_BoolFalse(&mut self, ctx: &BoolFalseContext<'_>) -> Self::Return {
        match ctx.tok.as_deref() {
            Some(token) => self
                .helper
                .next_expr(token, Expr::Literal(LiteralValue::Boolean(false.into()))),
            None => self.report_error::<ParseError, _>(&ctx.start(), None, "Incomplete bool!"),
        }
    }

    fn visit_Null(&mut self, ctx: &NullContext<'_>) -> Self::Return {
        match ctx.tok.as_deref() {
            Some(token) => self
                .helper
                .next_expr(token, Expr::Literal(LiteralValue::Null)),
            None => self.report_error::<ParseError, _>(&ctx.start(), None, "Incomplete null!"),
        }
    }
}

pub struct ParserHelper {
    pub(crate) source_info: SourceInfo,
    pub(crate) next_id: u64,
}

impl Default for ParserHelper {
    fn default() -> Self {
        Self {
            source_info: SourceInfo::default(),
            next_id: 1,
        }
    }
}

impl ParserHelper {
    fn next_id(&mut self, token: &CommonToken) -> u64 {
        let id = self.next_id;
        self.source_info
            .add_offset(id, token.start as u32, token.stop as u32);
        self.next_id += 1;
        id
    }

    fn next_id_for_token(&mut self, token: Option<&CommonToken>) -> u64 {
        match token {
            None => 0,
            Some(token) => self.next_id(token),
        }
    }

    fn next_id_for(&mut self, id: u64) -> u64 {
        let (start, stop) = self.source_info.offset_for(id).expect("invalid offset");
        let id = self.next_id;
        self.source_info.add_offset(id, start, stop);
        self.next_id += 1;
        id
    }

    pub fn next_expr(&mut self, token: &CommonToken, expr: Expr) -> IdedExpr {
        IdedExpr {
            id: self.next_id(token),
            expr,
        }
    }

    pub fn next_expr_for(&mut self, id: u64, expr: Expr) -> IdedExpr {
        IdedExpr {
            id: self.next_id_for(id),
            expr,
        }
    }
}

struct LogicManager {
    function: String,
    terms: Vec<IdedExpr>,
    ops: Vec<u64>,
}

impl LogicManager {
    pub(crate) fn expr(mut self) -> IdedExpr {
        if self.terms.len() == 1 {
            self.terms.pop().expect("expected at least one term")
        } else {
            self.balanced_tree(0, self.ops.len() - 1)
        }
    }

    pub(crate) fn add_term(&mut self, op_id: u64, expr: IdedExpr) {
        self.terms.push(expr);
        self.ops.push(op_id);
    }

    fn balanced_tree(&mut self, lo: usize, hi: usize) -> IdedExpr {
        let mid = (lo + hi).div_ceil(2);

        let left = if mid == lo {
            mem::take(&mut self.terms[mid])
        } else {
            self.balanced_tree(lo, mid - 1)
        };

        let right = if mid == hi {
            mem::take(&mut self.terms[mid + 1])
        } else {
            self.balanced_tree(mid + 1, hi)
        };

        IdedExpr {
            id: self.ops[mid],
            expr: Expr::Call(CallExpr {
                target: None,
                func_name: self.function.clone(),
                args: vec![left, right],
            }),
        }
    }
}
