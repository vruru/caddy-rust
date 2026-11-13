#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented,
    clippy::unreachable
)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable
    )
)]

extern crate alloc;

pub(crate) mod error;
pub(crate) mod exec;
pub(crate) mod funcs;
pub(crate) mod go;
mod go_string;
mod go_write;
mod go_buffer;
#[cfg(feature="std")]mod formatter_scope;
#[cfg(feature="std")]pub use formatter_scope::{FormatterScope,OwnedFormatterScope,FormatHostGuard};
#[cfg(feature="std")]pub use go::sprintf_with_scope as go_sprintf_with_scope;
mod go_print;
mod go_unquote;
mod go_unicode;
mod go_slice_capacity;
pub use go_slice_capacity::go_slice_capacity;
pub use go_unicode::{is_letter as go_is_letter,is_digit as go_is_digit};
pub use go_string::{GoBytes,GoKey,GoMapSnapshot,GoMapKeyRef,GoMapIter,decode_go_rune,go_runes,go_utf8_text};
/// Parser, lexer, and AST node types for the Go template language.
///
/// This module mirrors Go's `text/template/parse` package. Most users don't
/// need it directly; use [`Template::parse`] instead. The AST types are public
/// for advanced use cases like [`Template::add_parse_tree`].
pub mod parse;
pub(crate) mod value;
mod signature;
mod field_reference;
pub use field_reference::{FieldKind,FieldSource,FieldReference};
pub use signature::{ArgKind,Signature};
#[cfg(feature = "std")]
mod shared_map;
#[cfg(feature = "std")]
pub use shared_map::{MapContext, MapCell,GenericMapCell,GenericMapSnapshot};
#[cfg(feature="std")]
mod generic_key;
#[cfg(feature="std")]
pub use generic_key::key_equal as generic_key_equal;

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
pub mod ser;

/// Go `html/template`-style context-aware auto-escaping.
///
/// Provides [`html::Template`], a drop-in analog of [`Template`] whose output is
/// contextually auto-escaped for HTML text, attributes, URLs, JavaScript, and
/// CSS. Available only with the `html` feature.
#[cfg(feature = "html")]
#[cfg_attr(docsrs, doc(cfg(feature = "html")))]
pub mod html;

// Public re-exports
// All user-facing types are available at the crate root.

#[cfg(feature = "html")]
pub use error::EscapeErrorCode;
pub use error::{Result, TemplateError};
use funcs::builtins;

/// Shared, lazily-constructed builtins map. `Template::new` clones this `Arc`
/// (one atomic op) instead of rebuilding the builtins BTreeMap on every call.
/// Mutation via [`Template::func`] / [`Template::funcs`] goes through
/// `Arc::make_mut`, so registering a custom func triggers a one-time copy and
/// the shared map is never observed in a mutated state.
#[cfg(feature = "std")]
fn shared_builtins() -> Arc<BTreeMap<String, ValueFunc>> {
    use std::sync::LazyLock;
    static BUILTINS: LazyLock<Arc<BTreeMap<String, ValueFunc>>> =
        LazyLock::new(|| Arc::new(builtins()));
    BUILTINS.clone()
}

#[cfg(not(feature = "std"))]
fn shared_builtins() -> Arc<BTreeMap<String, ValueFunc>> {
    Arc::new(builtins())
}

fn col_for_offset(src:impl AsRef<[u8]>,offset:usize)->usize{
    let src=src.as_ref();let end=offset.min(src.len());let start=src[..end].iter().rposition(|byte|*byte==b'\n').map_or(0,|i|i+1);go_runes(&src[start..end]).count()+1
}

pub use go::{quote_go_string,sprint_bytes as go_sprint_bytes,sprintf_bytes as go_sprintf_bytes,float_to_go_i64,format_float_shortest, html_escape, js_escape, url_encode};
#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
pub use ser::{ToSerdeValue, to_value};
#[cfg(feature = "html")]
pub use value::SafeKind;
pub use value::{ToValue, Value, ValueFunc};

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

#[cfg(feature = "std")]
use std::io::Write;

use exec::Executor;
pub use exec::MissingKey;
use parse::{DefineNode, ListNode, Parser};

/// A map from function names to template functions, equivalent to Go's
/// `template.FuncMap`. Pass one to [`Template::funcs`] to register several
/// functions at once.
///
/// # Examples
///
/// ```
/// use std::sync::Arc;
/// use gotmpl::{FuncMap, Value};
///
/// let mut fm = FuncMap::new();
/// fm.insert("double".into(), Arc::new(|args: &[Value]| {
///     let n = args.first().and_then(Value::as_int).unwrap_or(0);
///     Ok(Value::Int(n * 2))
/// }));
/// ```
pub type FuncMap = BTreeMap<String, ValueFunc>;

/// Share an execution budget across related templates.
pub type ExecutionCharge = Arc<dyn Fn(usize) -> Result<()> + Send + Sync>;
/// Request-owned overlay for templates imported during execution.
#[cfg(not(feature = "html"))]
pub type DefinitionLookup = Arc<dyn Fn(&str) -> Result<Option<Arc<ListNode>>> + Send + Sync>;
/// Byte-preserving dynamic namespace lookup for raw template names.
pub type GoDefinitionLookup=Arc<dyn Fn(&GoKey)->Result<Option<Arc<ListNode>>>+Send+Sync>;
pub use value::{Object, MapView,JsonField,Int64Type,Int64Method,HostType,HostMethod};

/// A parsed template, equivalent to Go's
/// [`template.Template`](https://pkg.go.dev/text/template#Template).
///
/// Configure, parse, and execute via the builder-style API:
///
/// ```
/// use gotmpl::{Template, MissingKey, tmap};
///
/// let output = Template::new("greet")
///     .delims("<<", ">>")                        // optional: custom delimiters
///     .missing_key(MissingKey::Error)             // optional: error on missing keys
///     .func("shout", |args| {                     // optional: custom functions
///         let s = args.first().map(|v| v.to_string()).unwrap_or_default();
///         Ok(gotmpl::Value::String(s.to_uppercase().into()))
///     })
///     .parse("Hello, << .Name | shout >>!")       // parse template source
///     .unwrap()
///     .execute_to_string(&tmap! { "Name" => "world" })
///     .unwrap();
///
/// assert_eq!(output, "Hello, WORLD!");
/// ```
pub struct Template {
    name: String,
    tree: Option<ListNode>,
    defines: BTreeMap<GoKey, Arc<ListNode>>,
    funcs: Arc<BTreeMap<String, ValueFunc>>,
    printf_identity:Option<ValueFunc>,
    #[cfg(feature="std")]formatter_scope:Option<Arc<FormatterScope>>,
    left_delim: String,
    right_delim: String,
    missing_key: MissingKey,
    max_range_iters: u64,
    execution_charge: Option<ExecutionCharge>,
    value_limit:usize,output_limit:usize,
    function_signatures: BTreeMap<String,Signature>,
    #[cfg(not(feature = "html"))]
    definition_lookup: Option<GoDefinitionLookup>,
}

/// Adapts a [`std::io::Write`] to [`core::fmt::Write`]. Any [`io::Error`](std::io::Error)
/// gets stashed, since [`fmt::Error`](core::fmt::Error) has no payload to carry it.
#[cfg(feature = "std")]
pub(crate) struct IoAdapter<'a, W> {
    inner: &'a mut W,
    error: Option<std::io::Error>,
}

#[cfg(feature = "std")]
impl<'a, W> IoAdapter<'a, W> {
    pub(crate) fn new(inner: &'a mut W) -> Self {
        IoAdapter { inner, error: None }
    }

    pub(crate) fn err_mapper(self) -> impl FnOnce(TemplateError) -> TemplateError {
        move |e| match e {
            error::TemplateError::Write => error::TemplateError::Io(
                self.error
                    .unwrap_or_else(|| std::io::Error::other("write error")),
            ),
            _ => e,
        }
    }
}

#[cfg(feature = "std")]
impl<W: std::io::Write> core::fmt::Write for IoAdapter<'_, W> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        self.inner.write_all(s.as_bytes()).map_err(|e| {
            self.error = Some(e);
            core::fmt::Error
        })
    }
}

#[cfg(feature="std")]
impl<W:std::io::Write> go_write::GoWrite for IoAdapter<'_,W>{fn write_bytes(&mut self,bytes:&[u8])->core::fmt::Result{self.inner.write_all(bytes).map_err(|error|{self.error=Some(error);core::fmt::Error})}}

impl Template {
    /// Create a new, empty template with the given name.
    ///
    /// The name is used in error messages and when invoking templates via
    /// `{{template "name"}}`. Built-in functions are registered automatically.
    pub fn new(name: &str) -> Self {
        let funcs=shared_builtins();let printf_identity=funcs.get("printf").cloned();
        Template {
            name: name.to_string(),
            tree: None,
            defines: BTreeMap::new(),
            funcs,printf_identity,
            #[cfg(feature="std")]formatter_scope:None,
            left_delim: "{{".to_string(),
            right_delim: "}}".to_string(),
            missing_key: MissingKey::default(),
            max_range_iters: exec::DEFAULT_MAX_RANGE_ITERS,
            execution_charge: None,
            value_limit:1<<20,output_limit:1<<20,
            function_signatures: BTreeMap::new(),
            #[cfg(not(feature = "html"))]
            definition_lookup: None,
        }
    }

    /// Set the total number of `{{range}}` iterations allowed per execution
    /// (across all nested ranges). Defaults to 10,000,000. Set to `0` to
    /// disable the cap entirely (at your own risk with untrusted templates).
    #[must_use]
    pub fn max_range_iters(mut self, n: u64) -> Self {
        self.max_range_iters = n;
        self
    }

    /// Share evaluation work accounting across related templates.
    /// Byte limits for a host that has already admitted its working memory.
    pub fn byte_limits(mut self,value:usize,output:usize)->Self{self.value_limit=value;self.output_limit=output;self}
    pub fn with_execution_charge(mut self, charge: ExecutionCharge) -> Self {
        self.execution_charge = Some(charge);
        self
    }

    /// Attach Go argument kinds without changing the function-map API.
    pub fn function_signatures(mut self,signatures:BTreeMap<String,Signature>)->Self {
        self.function_signatures=signatures;self
    }

    /// Bind only the library's current printf registration. Custom overrides,
    /// before or after this call, retain their original identity and behavior.
    #[cfg(feature="std")]
    pub fn with_formatter_scope(mut self,scope:Arc<FormatterScope>)->Result<Self>{
        self.formatter_scope=Some(scope.clone());
        let original=self.printf_identity.as_ref().is_some_and(|id|self.funcs.get("printf").is_some_and(|current|Arc::ptr_eq(id,current)));
        if original{
            scope.metadata(self.funcs.iter().try_fold(256usize,|n,(key,_)|n.checked_add(key.len()+160)).ok_or_else(||TemplateError::Exec("formatter registration size overflow".into()))?)?;
            let limit=self.value_limit;
            let function:ValueFunc=Arc::new(move|args|{
                funcs::check_min_args("printf",args,1)?;
                let format=args[0].as_go_bytes().ok_or_else(||TemplateError::Exec("printf: first argument must be string".into()))?;
                let bytes=go::sprintf_with_scope(format,&args[1..],scope.clone())?;
                scope.value(bytes,limit)
            });
            Arc::make_mut(&mut self.funcs).insert("printf".into(),function.clone());self.printf_identity=Some(function);
        }Ok(self)
    }

    /// Set a request-local dynamic namespace. The callback must release any
    /// lock before returning its immutable tree; it must not execute templates.
    #[cfg(not(feature = "html"))]
    pub fn with_definition_lookup(mut self,lookup:DefinitionLookup)->Self{
        self.definition_lookup=Some(Arc::new(move|name|match name.as_str(){Some(name)=>lookup(name),None=>Ok(None)}));self
    }
    pub fn with_definition_lookup_go(mut self,lookup:GoDefinitionLookup)->Self{self.definition_lookup=Some(lookup);self}

    pub fn lookup_shared(&self, name: &str) -> Option<Arc<ListNode>> {
        self.defines.get(name.as_bytes()).cloned()
    }
    pub fn lookup_shared_bytes(&self,name:&[u8])->Option<Arc<ListNode>>{self.defines.get(name).cloned()}
    pub fn templates_go(&self)->impl Iterator<Item=(&GoKey,&Arc<ListNode>)>{self.defines.iter()}


    /// Set custom action delimiters (default: `"{{"` and `"}}"`).
    ///
    /// Must be called **before** [`parse`](Self::parse).
    ///
    /// # Examples
    ///
    /// ```
    /// use gotmpl::{Template, tmap};
    ///
    /// let result = Template::new("t")
    ///     .delims("<%", "%>")
    ///     .parse("Hello, <%.Name%>!")
    ///     .unwrap()
    ///     .execute_to_string(&tmap! { "Name" => "World" })
    ///     .unwrap();
    /// assert_eq!(result, "Hello, World!");
    /// ```
    #[must_use]
    pub fn delims(mut self, left: &str, right: &str) -> Self {
        self.left_delim = left.to_string();
        self.right_delim = right.to_string();
        self
    }

    /// Set the behavior for missing map keys.
    ///
    /// # Examples
    ///
    /// ```
    /// use gotmpl::{Template, MissingKey, tmap};
    ///
    /// let result = Template::new("t")
    ///     .missing_key(MissingKey::Error)
    ///     .parse("{{.Y}}")
    ///     .unwrap()
    ///     .execute_to_string(&tmap! { "X" => 1i64 });
    /// assert!(result.is_err());
    /// ```
    #[must_use]
    pub fn missing_key(mut self, mk: MissingKey) -> Self {
        self.missing_key = mk;
        self
    }

    /// Register a custom template function.
    ///
    /// Must be called **before** [`parse`](Self::parse). The function receives
    /// its arguments as a `&[Value]` slice and returns a
    /// [`Result<Value>`](error::Result). It is available inside templates under
    /// the given `name`; registering a name that matches a built-in replaces it.
    ///
    /// # Examples
    ///
    /// ```
    /// use gotmpl::{Template, tmap, Value};
    ///
    /// let result = Template::new("t")
    ///     .func("double", |args| {
    ///         let n = args.first().and_then(Value::as_int).unwrap_or(0);
    ///         Ok(Value::Int(n * 2))
    ///     })
    ///     .parse("{{double 21}}")
    ///     .unwrap()
    ///     .execute_to_string(&tmap!{})
    ///     .unwrap();
    /// assert_eq!(result, "42");
    /// ```
    #[must_use]
    pub fn func(
        mut self,
        name: &str,
        f: impl Fn(&[Value]) -> Result<Value> + Send + Sync + 'static,
    ) -> Self {
        if name=="printf"{self.printf_identity=None;}
        Arc::make_mut(&mut self.funcs).insert(name.to_string(), Arc::new(f));
        self
    }

    /// Register several template functions at once from a [`FuncMap`], the
    /// counterpart to Go's `template.Funcs()`. Must be called **before**
    /// [`parse`](Self::parse).
    ///
    /// # Examples
    ///
    /// ```
    /// use std::sync::Arc;
    /// use gotmpl::{Template, FuncMap, tmap, Value};
    ///
    /// let mut fm = FuncMap::new();
    /// fm.insert("greet".into(), Arc::new(|args: &[Value]| {
    ///     let name = args.first().map(|v| v.to_string()).unwrap_or_default();
    ///     Ok(Value::String(format!("Hello, {name}!").into()))
    /// }));
    ///
    /// let result = Template::new("t")
    ///     .funcs(fm)
    ///     .parse(r#"{{greet "World"}}"#)
    ///     .unwrap()
    ///     .execute_to_string(&tmap!{})
    ///     .unwrap();
    /// assert_eq!(result, "Hello, World!");
    /// ```
    #[must_use]
    pub fn funcs(mut self, func_map: FuncMap) -> Self {
        if func_map.contains_key("printf"){self.printf_identity=None;}
        Arc::make_mut(&mut self.funcs).extend(func_map);
        self
    }

    /// Parse template source and associate it with this template.
    ///
    /// Mirrors Go's `(*Template).Parse` **method**: named template definitions
    /// (`{{define}}` / `{{block}}`) in `src` are extracted into this template's
    /// definition map, and the top-level content becomes this template's body.
    ///
    /// Successive calls can redefine named templates. A body that reduces to
    /// only whitespace is considered empty and will **not** overwrite an
    /// existing body or define of the same name. That is how `parse` can be
    /// used to add named definitions without clobbering the main template.
    /// Comment-only bodies behave as empty because the lexer strips comments
    /// before parsing. If no body has been set yet, an empty body is still
    /// stored (so executing the template yields `""`).
    ///
    /// Within a single call, redeclaring a name with two non-empty bodies is
    /// an error (Go's `template: multiple definition of template "x"`). Across
    /// calls, the later non-empty body replaces the earlier one.
    ///
    /// Call [`delims`](Self::delims) and [`func`](Self::func) first, so the
    /// parser sees the intended configuration.
    ///
    /// # Errors
    ///
    /// Returns [`TemplateError::Lex`] or [`TemplateError::Parse`] if `src`
    /// contains syntax errors, or if two non-empty definitions of the same
    /// name appear in the same parse call.
    pub fn parse(self,src:&str)->Result<Self>{self.parse_bytes(src.as_bytes())}
    pub fn parse_bytes(mut self,src:&[u8])->Result<Self>{
        // Go parity: `(*Template).Parse` tags errors with the receiver's name
        // (its `parseName`). An empty receiver name drops the `<name>:` segment
        // from the error's display, keeping the rest of the format unchanged.
        let parser =
            Parser::with_name_bytes(self.parse_name(), src, &self.left_delim, &self.right_delim)?;
        let (tree, defines) = parser.parse_checked(&self.funcs)?;

        // Go's `parse.(*Tree).add` rejects a non-empty top-level that collides
        // with a same-named non-empty `{{define}}` in the same parse call:
        // both would occupy the `treeSet[name]` slot. Detect the same here so
        // the error path matches Go's "multiple definition of template" output.
        Self::check_in_file_basename_collision(&self.name, &tree, &defines, src)?;

        // Mirror Go's `treeSet[t.Name] = topLevelTree` at parse time: pre-populate
        // the name-keyed slot with the non-empty top so `merge_defines` treats it
        // as an existing entry and drops an in-call *empty* same-name `{{define}}`
        // (Go's `parse.(*Tree).add` rule). An empty top never pre-populates, so a
        // prior call's body survives until a later non-empty entry replaces it.
        // A non-empty same-name define in the same call can't reach here: it
        // already errored out of `check_in_file_basename_collision` above.
        if !self.name.is_empty() && !tree.is_empty_tree() {
            self.defines
                .insert(self.name.clone().into(), Arc::new(tree.clone()));
        }

        if self.tree.is_none() || !tree.is_empty_tree() {
            self.tree = Some(tree);
        }

        self.merge_defines(defines, src)?;

        // Mirror Go's final `AddParseTree` that pairs `t.Tree` with
        // `t.tmpl[t.Name()]`: `self.tree` ends up equal to the entry under
        // `self.defines[self.name]`. No-op for an unnamed receiver. Needed
        // both when a `{{define self.name}}` body replaced the slot via
        // `merge_defines`, and when a prior call's entry needs to propagate
        // into a fresh `self.tree`.
        self.sync_tree_to_own_name();
        Ok(self)
    }

    /// The template's name as a parser tag, or `None` when empty. Matches Go's
    /// `parseName` handling: an unnamed template drops the name segment from
    /// error displays rather than rendering as `template: :<line>:<col>: …`.
    fn parse_name(&self) -> Option<&str> {
        (!self.name.is_empty()).then_some(self.name.as_str())
    }

    /// Merge one parse call's `{{define}}` bodies into `self.defines`,
    /// matching Go's `parse.(*Tree).add` + `parse.associate` in a single pass:
    ///
    ///   - A second non-empty body for the same name *within this call* is a
    ///     parse error (Go's `add`). An empty body after a non-empty one in
    ///     the same call is silently dropped, preserving the non-empty body.
    ///   - An empty body never overwrites an existing non-empty define in
    ///     `self.defines` (Go's `associate` IsEmptyTree guard). Non-empty
    ///     bodies always replace, which is how across-call redefinition works.
    ///
    /// The `seen_non_empty` set tracks names already written non-empty in this
    /// call. That is what distinguishes "in-call duplicate, error" from
    /// "across-call duplicate, replace": `self.defines` alone can't tell them
    /// apart. `src` is used only for error-position reporting.
    fn merge_defines(&mut self, defines: Vec<DefineNode>, src: &[u8]) -> Result<()> {
        let mut seen_non_empty: alloc::collections::BTreeSet<GoKey> =
            alloc::collections::BTreeSet::new();
        for def in defines {
            let new_is_empty = def.body.is_empty_tree();
            if seen_non_empty.contains(&def.name) {
                if new_is_empty {
                    continue;
                }
                return Err(error::TemplateError::Parse {
                    name: self.parse_name().map(String::from),
                    line: def.pos.line,
                    col: col_for_offset(src, def.pos.offset),
                    message: alloc::format!(
                        "multiple definition of template {:?}",
                        def.name.as_bytes()
                    ),
                });
            }
            if new_is_empty && self.defines.contains_key(def.name.as_bytes()) {
                continue;
            }
            if !new_is_empty {
                seen_non_empty.insert(def.name.clone());
            }
            self.defines
                .insert(def.name, Arc::new(def.body));
        }
        Ok(())
    }

    /// Register a parsed body under `name` using Go's `parse.associate` rule.
    /// An empty body does not overwrite an existing non-empty define. Used by
    /// [`parse_files`](Self::parse_files) for the basename registration.
    #[cfg(feature = "std")]
    fn associate_body(&mut self, name: &str, body: ListNode) {
        if body.is_empty_tree() && self.defines.contains_key(name.as_bytes()) {
            return;
        }
        self.defines.insert(name.into(), Arc::new(body));
    }

    /// Mirror Go's `parse.(*Tree).add` in-call conflict check: if the top-level
    /// tree is non-empty *and* the same parse produced a non-empty
    /// `{{define name}}`, both would claim the same slot in Go's treeSet, and
    /// Go errors with "multiple definition of template". `name` is the slot
    /// the top-level occupies: self.name for `parse`, the basename for
    /// `parse_files`. An empty `name` skips the check (the unnamed-receiver
    /// case, like `Template::new("")`, has no define to collide with).
    fn check_in_file_basename_collision(
        name: &str,
        top: &ListNode,
        defines: &[DefineNode],
        src: &[u8],
    ) -> Result<()> {
        if name.is_empty() || top.is_empty_tree() {
            return Ok(());
        }
        if let Some(def) = defines
            .iter()
            .find(|d| d.name.as_bytes() == name.as_bytes() && !d.body.is_empty_tree())
        {
            return Err(error::TemplateError::Parse {
                name: Some(name.to_string()),
                line: def.pos.line,
                col: col_for_offset(src, def.pos.offset),
                message: alloc::format!("multiple definition of template {name:?}"),
            });
        }
        Ok(())
    }

    /// After a parse merge, mirror Go's final `AddParseTree` step that syncs
    /// `t.Tree` with `t.tmpl[t.Name()]`. Needed when a `{{define}}` body has
    /// replaced the top-level entry, so that `execute` and
    /// `execute_template(name)` render the same thing.
    fn sync_tree_to_own_name(&mut self) {
        if self.name.is_empty() {
            return;
        }
        if let Some(entry) = self.defines.get(self.name.as_bytes()) {
            self.tree = Some((**entry).clone());
        }
    }

    /// Parse one or more template files and associate them with this template.
    ///
    /// Mirrors Go's `(*Template).ParseFiles` **method** (not the package-level
    /// `template.ParseFiles` constructor). Each file is read and parsed;
    /// `{{define}}` blocks are hoisted into this template's definition map, and
    /// the file's basename is registered as an associated template whose body
    /// is the file's top-level content.
    ///
    /// If a file's basename matches this template's own name (as set via
    /// [`new`](Self::new)), that file's content also becomes the receiver's
    /// main tree, so [`execute`](Self::execute) works directly. Otherwise the
    /// main tree is left alone and callers must use
    /// [`execute_template`](Self::execute_template) with the basename. This
    /// matches Go's `name == t.Name()` branch in `parseFiles`.
    ///
    /// For the constructor-style behavior (receiver's name and tree synthesized
    /// from the first file's basename), call
    /// `Template::new(basename).parse_files(&[...])` explicitly, or use the
    /// top-level [`execute_file`] helper for the single-file case.
    ///
    /// # Errors
    ///
    /// Returns [`TemplateError::NoFiles`] if `filenames` is empty, or a
    /// read/parse error for the first file that fails.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use gotmpl::Template;
    ///
    /// let tmpl = Template::new("site")
    ///     .parse_files(&["templates/header.html", "templates/footer.html"])
    ///     .unwrap();
    /// ```
    #[cfg(feature = "std")]
    pub fn parse_files(mut self, filenames: &[&str]) -> Result<Self> {
        if filenames.is_empty() {
            return Err(error::TemplateError::NoFiles);
        }

        for filename in filenames {
            let content =
                std::fs::read(filename).map_err(|e| error::TemplateError::ReadFile {
                    path: filename.to_string(),
                    source: e,
                })?;

            // Register the file's top-level content under its basename
            let basename = std::path::Path::new(filename)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(filename);

            // Tag the parser with the basename so parse/lex errors report
            // the originating file (Go's parseName), matching its
            // `template: foo.tmpl:12:5: …` format.
            let parser = Parser::with_name_bytes(
                Some(basename),
                &content,
                &self.left_delim,
                &self.right_delim,
            )?;
            let (tree, defines) = parser.parse_checked(&self.funcs)?;

            // Go parity: if the basename matches the receiver's name, the file's
            // top-level content becomes the receiver's own tree (so `Execute` works
            // directly). Otherwise it is only registered as an associated template.
            // Go's (*Template).ParseFiles dispatches tmpl.Parse(s) per file, so
            // define merging follows the same add+associate rules: an in-file
            // duplicate non-empty define errors, and an empty body never
            // overwrites an existing non-empty one.
            Self::check_in_file_basename_collision(basename, &tree, &defines, &content)?;

            if basename == self.name && (self.tree.is_none() || !tree.is_empty_tree()) {
                self.tree = Some(tree.clone());
            }
            // `associate_body` plays the role of the `parse` pre-populate step:
            // with a non-empty top it seeds `self.defines[basename]` so the
            // subsequent `merge_defines` drops an in-file empty same-name
            // `{{define}}` the same way Go's `parse.(*Tree).add` does.
            self.associate_body(basename, tree);
            self.merge_defines(defines, &content)?;

            // When this file targets the receiver's own slot, pair `self.tree`
            // with the final `self.defines[self.name]` entry (Go's
            // `AddParseTree` invariant). Covers both "empty top + non-empty
            // same-name define replaced the slot" and "prior call's body
            // survives a no-op parse".
            if basename == self.name {
                self.sync_tree_to_own_name();
            }
        }
        Ok(self)
    }

    /// Parse every file matching `pattern` and add it to this template.
    ///
    /// Equivalent to Go's `(*Template).ParseGlob`. Forwards each match to
    /// [`parse_files`](Self::parse_files) in the order the [`glob`] crate
    /// yields them (sorted within each directory, depth-first across
    /// directories). When two matches define the same `{{define "name"}}`
    /// block, the later one wins — so the traversal order is observable for
    /// patterns that cross multiple directories, and may differ from Go's
    /// `filepath.Glob` in that case.
    ///
    /// # Pattern syntax
    ///
    /// Powered by the [`glob`] crate, which accepts a strict superset of
    /// Go's `filepath.Match`:
    ///
    /// - `*` matches any sequence of non-separator characters
    /// - `?` matches any single non-separator character
    /// - `[abc]` / `[!abc]` character classes
    /// - `**` matches zero or more path components (Go does not support this)
    ///
    /// # Matching behavior
    ///
    /// Matching is case-sensitive and `*` matches leading-dot files, so
    /// `*.tmpl` also matches `.hidden.tmpl`. Both properties agree with Go's
    /// `filepath.Match` / `filepath.Glob`, which likewise match dotfiles
    /// (unlike shell globbing). Concretely this is the `glob` crate default
    /// used by `glob::glob` (i.e. `MatchOptions::new()`: `case_sensitive =
    /// true`, `require_literal_leading_dot = false`).
    ///
    /// # Divergences from Go
    ///
    /// - **`**` recursive descent**: not supported by Go's `filepath.Match`.
    /// - **Match ordering across directories** may differ from Go's
    ///   `filepath.Glob`, which matters only when distinct matches redefine
    ///   the same `{{define}}` name (last-wins).
    ///
    /// # Security
    ///
    /// If `pattern` is user-controlled, anchor it to a trusted base directory
    /// before calling — `**` plus a permissive prefix can fan out across the
    /// filesystem. The [`glob`] crate performs no symlink-cycle detection and
    /// classifies entries via `fs::metadata` (which follows symlinks), so `**`
    /// will descend into symlinked directories and traverse a symlink cycle
    /// until the OS symlink-resolution limit (`ELOOP`) breaks it. Nothing here
    /// bounds reachable paths beyond what the pattern allows.
    ///
    /// # Errors
    ///
    /// - [`TemplateError::BadPattern`] for malformed patterns (e.g. unbalanced `[`).
    /// - [`TemplateError::ReadFile`] if a matched path cannot be read, or if a
    ///   matched path is not valid UTF-8 (our [`parse_files`](Self::parse_files)
    ///   API takes `&str`, so non-UTF-8 paths from the OS are rejected up-front
    ///   rather than silently lossy-converted).
    /// - [`TemplateError::NoFiles`] if no file matches the pattern, mirroring
    ///   Go's "pattern matches no files" error.
    /// - Any error returned by [`parse_files`](Self::parse_files) for the
    ///   matched files.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use gotmpl::Template;
    ///
    /// let tmpl = Template::new("site")
    ///     .parse_glob("templates/*.tmpl")
    ///     .unwrap();
    /// ```
    #[cfg(feature = "glob")]
    pub fn parse_glob(self, pattern: &str) -> Result<Self> {
        let paths = glob::glob(pattern).map_err(|e| error::TemplateError::BadPattern {
            pattern: pattern.to_string(),
            pos: e.pos,
            msg: e.msg,
        })?;

        // A per-entry I/O error (e.g. EACCES while traversing a directory) is
        // surfaced as `ReadFile` and takes precedence over the `NoFiles` check
        // below — Go's `filepath.Glob` instead silently ignores such errors.
        // We prefer to surface a genuine I/O problem rather than swallow it.
        let mut matched: Vec<String> = Vec::new();
        for entry in paths {
            let path = entry.map_err(|e| error::TemplateError::ReadFile {
                path: e.path().display().to_string(),
                source: e.into_error(),
            })?;
            // Reject non-UTF-8 paths explicitly. `to_string_lossy` would
            // silently substitute U+FFFD and then `parse_files` would fail at
            // open-time with a misleading ENOENT — surface the real cause.
            let s = path
                .to_str()
                .ok_or_else(|| error::TemplateError::ReadFile {
                    path: path.to_string_lossy().into_owned(),
                    source: std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "path is not valid UTF-8",
                    ),
                })?;
            matched.push(s.to_owned());
        }
        if matched.is_empty() {
            return Err(error::TemplateError::NoFiles);
        }
        let refs: Vec<&str> = matched.iter().map(String::as_str).collect();
        self.parse_files(&refs)
    }

    /// Add a pre-built parse tree as a named template definition, the
    /// counterpart to Go's `template.AddParseTree()`. Useful for injecting
    /// programmatically built ASTs without running the parser.
    ///
    /// Replaces any existing definition with the same `name`.
    ///
    /// # Examples
    ///
    /// ```
    /// use gotmpl::{Template, tmap};
    /// use gotmpl::parse::{ListNode, Node, TextNode, Pos};
    ///
    /// // Build an AST node by hand
    /// let tree = ListNode {
    ///     pos: Pos::new(0, 1),
    ///     nodes: vec![Node::Text(TextNode {
    ///         pos: Pos::new(0, 1),
    ///         text: "injected".into(),
    ///     })],
    /// };
    ///
    /// let result = Template::new("t")
    ///     .parse(r#"{{template "my_tree"}}"#)
    ///     .unwrap()
    ///     .add_parse_tree("my_tree", tree)
    ///     .execute_to_string(&tmap!{})
    ///     .unwrap();
    /// assert_eq!(result, "injected");
    /// ```
    #[must_use]
    pub fn add_parse_tree(mut self, name: &str, tree: ListNode) -> Self {
        self.defines.insert(name.into(), Arc::new(tree));
        self
    }

    /// Build an [`Executor`] over the given func and template maps, applying
    /// this template's execution options. Single place all execute paths route
    /// through so a new option cannot be forgotten on one of them.
    fn make_executor<'a>(
        &self,
        funcs: &'a BTreeMap<String, ValueFunc>,
        templates: &'a BTreeMap<GoKey, Arc<ListNode>>,
    ) -> Executor<'a> {
        let mut executor = Executor::new(funcs, templates);
        executor.set_missing_key(self.missing_key);
        executor.set_max_range_iters(self.max_range_iters);
        executor.execution_charge = self.execution_charge.clone();
        #[cfg(feature="std")] {executor.formatter_scope=self.formatter_scope.clone();}
        executor.value_limit=self.value_limit;executor.output_limit=self.output_limit;
        executor.function_signatures=self.function_signatures.clone();
        #[cfg(not(feature = "html"))]
        { executor.definition_lookup = self.definition_lookup.clone(); }
        executor
    }

    /// Execute the template, writing output to the given [`fmt::Write`](core::fmt::Write) destination.
    ///
    /// The `data` argument becomes the initial dot (`.`) value inside the template.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The template has not been [parsed](Self::parse) yet.
    /// - An undefined function, template, or variable is referenced.
    /// - A type error occurs during execution (e.g., ranging over a non-iterable).
    /// - A write error occurs.
    /// - The recursive template call depth exceeds the safety limit.
    /// - The per-execution `{{range}}` iteration budget
    ///   ([`max_range_iters`](Self::max_range_iters)) is exhausted.
    pub fn execute_fmt<W: core::fmt::Write>(&self, writer: &mut W, data: &Value) -> Result<()> {
        let tree = self.tree.as_ref().ok_or_else(|| {
            error::TemplateError::Exec(format!("template {:?} has not been parsed", self.name))
        })?;

        let mut executor = self.make_executor(&self.funcs, &self.defines);
        executor.execute(writer, tree, data)
    }

    /// Execute a named sub-template, writing output to a [`fmt::Write`](core::fmt::Write) destination.
    ///
    /// Looks up the named template in the definition map and executes it with
    /// the given data. This is the `fmt::Write` counterpart to Go's
    /// `template.ExecuteTemplate()`.
    ///
    /// # Errors
    ///
    /// Returns [`TemplateError::UndefinedTemplate`] if no template with the
    /// given name exists, plus all errors from [`execute_fmt`](Self::execute_fmt)
    /// (including [`TemplateError::RangeIterLimit`] and the recursion-limit error).
    pub fn execute_template_fmt<W: core::fmt::Write>(
        &self,
        writer: &mut W,
        name: &str,
        data: &Value,
    ) -> Result<()> {
        let tree = self
            .defines
            .get(name.as_bytes())
            .ok_or_else(|| error::TemplateError::UndefinedTemplate(name.to_string()))?;

        let mut executor = self.make_executor(&self.funcs, &self.defines);
        executor.execute(writer, tree.as_ref(), data)
    }

    /// Execute the template, writing output to the given [`io::Write`](std::io::Write) destination.
    ///
    /// Convenience wrapper around [`execute_fmt`](Self::execute_fmt) for
    /// `std::io::Write` targets (files, sockets, `Vec<u8>`, etc.).
    ///
    /// # Errors
    ///
    /// Same as [`execute_fmt`](Self::execute_fmt), plus I/O errors from the writer.
    #[cfg(feature = "std")]
    pub fn execute<W: Write>(&self, writer: &mut W, data: &Value) -> Result<()> {
        let mut adapter = IoAdapter::new(writer);
        let tree=self.tree.as_ref().ok_or_else(||TemplateError::Exec(format!("template {:?} has not been parsed",self.name)))?;
        let mut executor=self.make_executor(&self.funcs,&self.defines);
        executor.execute_go(&mut adapter,tree,data).map_err(adapter.err_mapper())
    }

    /// Execute a named sub-template, writing output to an [`io::Write`](std::io::Write) destination.
    ///
    /// # Examples
    ///
    /// ```
    /// use gotmpl::{Template, tmap};
    ///
    /// let tmpl = Template::new("root")
    ///     .parse(r#"{{define "header"}}Header: {{.Title}}{{end}}body"#)
    ///     .unwrap();
    ///
    /// let data = tmap! { "Title" => "Hello" };
    ///
    /// // Execute the main template
    /// assert_eq!(tmpl.execute_to_string(&data).unwrap(), "body");
    ///
    /// // Execute just the "header" sub-template
    /// let mut buf = Vec::new();
    /// tmpl.execute_template(&mut buf, "header", &data).unwrap();
    /// assert_eq!(String::from_utf8(buf).unwrap(), "Header: Hello");
    /// ```
    #[cfg(feature = "std")]
    pub fn execute_template<W: Write>(
        &self,
        writer: &mut W,
        name: &str,
        data: &Value,
    ) -> Result<()> {
        let mut adapter = IoAdapter::new(writer);
        let tree=self.defines.get(name.as_bytes()).ok_or_else(||TemplateError::Exec(format!("template {name:?} not defined")))?;
        let mut executor=self.make_executor(&self.funcs,&self.defines);
        executor.execute_go(&mut adapter,tree,data).map_err(adapter.err_mapper())
    }

    /// Execute and collect the original Go output bytes. Arbitrary string and
    /// map-key bytes are preserved; the normal execution and output budgets apply.
    pub fn execute_to_bytes(&self,data:&Value)->Result<Vec<u8>>{
        let tree=self.tree.as_ref().ok_or_else(||TemplateError::Exec(format!("template {:?} has not been parsed",self.name)))?;
        let mut output=Vec::new();let mut sink=go_write::VecSink(&mut output);
        self.make_executor(&self.funcs,&self.defines).execute_go(&mut sink,tree,data)?;Ok(output)
    }

    /// Execute into UTF-8 text. Invalid Go string bytes return an output error;
    /// use [`execute_to_bytes`](Self::execute_to_bytes) to retain them.
    pub fn execute_to_string(&self, data: &Value) -> Result<String> {
        let mut buf = String::new();
        self.execute_fmt(&mut buf, data)?;
        Ok(buf)
    }

    /// Execute a named sub-template and return the result as a [`String`].
    ///
    /// Convenience wrapper around [`execute_template_fmt`](Self::execute_template_fmt).
    pub fn execute_template_to_string(&self, name: &str, data: &Value) -> Result<String> {
        let mut buf = String::new();
        self.execute_template_fmt(&mut buf, name, data)?;
        Ok(buf)
    }

    /// Returns the template name set in [`new`](Self::new).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Look up a named template definition, the counterpart to Go's
    /// `template.Lookup()`. Returns `None` when no template with the given
    /// name has been defined (via `{{define}}`, `{{block}}`, or
    /// [`add_parse_tree`](Self::add_parse_tree)).
    ///
    /// # Examples
    ///
    /// ```
    /// use gotmpl::Template;
    ///
    /// let tmpl = Template::new("t")
    ///     .parse(r#"{{define "header"}}...{{end}}"#)
    ///     .unwrap();
    ///
    /// assert!(tmpl.lookup("header").is_some());
    /// assert!(tmpl.lookup("footer").is_none());
    /// ```
    pub fn lookup(&self, name: &str) -> Option<&ListNode> {
        self.defines.get(name.as_bytes()).map(Arc::as_ref)
    }

    /// Returns the names of all defined templates, in sorted order.
    ///
    /// The counterpart to Go's `template.Templates()`, returning names rather
    /// than template objects since definitions share the parent's function
    /// map and options.
    ///
    /// # Examples
    ///
    /// ```
    /// use gotmpl::Template;
    ///
    /// let tmpl = Template::new("t")
    ///     .parse(r#"{{define "a"}}...{{end}}{{define "b"}}...{{end}}"#)
    ///     .unwrap();
    ///
    /// assert_eq!(tmpl.templates(), vec!["a", "b"]);
    /// ```
    pub fn templates(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.defines.keys().filter_map(|s| s.as_str()).collect();
        names.sort_unstable();
        names
    }

    /// Returns a human-readable string listing all defined templates, the
    /// counterpart to Go's `template.DefinedTemplates()`. Useful for error
    /// messages when a template invocation fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use gotmpl::Template;
    ///
    /// let tmpl = Template::new("t")
    ///     .parse(r#"{{define "header"}}...{{end}}{{define "footer"}}...{{end}}"#)
    ///     .unwrap();
    ///
    /// let s = tmpl.defined_templates();
    /// assert!(s.contains("header"));
    /// assert!(s.contains("footer"));
    /// ```
    pub fn defined_templates(&self)->String{
        if self.defines.is_empty(){return String::new();}
        let quoted=self.defines.keys().map(|name|quote_go_string(name.as_bytes(),false).unwrap_or_else(|_|"[template name exceeds diagnostic limit]".into())).collect::<Vec<_>>();
        format!("; defined templates are: {}",quoted.join(", "))
    }
    pub fn lookup_bytes(&self,name:&[u8])->Option<&ListNode>{self.defines.get(name).map(Arc::as_ref)}
    pub fn execute_template_to_bytes(&self,name:&[u8],data:&Value)->Result<Vec<u8>>{
        let tree=self.defines.get(name).ok_or_else(||TemplateError::UndefinedTemplate(quote_go_string(name,false).unwrap_or_default()))?;
        let mut output=Vec::new();let mut sink=go_write::VecSink(&mut output);self.make_executor(&self.funcs,&self.defines).execute_go(&mut sink,tree,data)?;Ok(output)
    }

}

/// Internal hooks used by the `html` module's escaping layer: they expose the
/// parsed trees and an execution entry point over caller-supplied (escaped)
/// trees, mirroring [`execute_fmt`](Self::execute_fmt) but with the tree set
/// provided by the html layer instead of taken from `self`.
#[cfg(feature = "html")]
impl Template {
    /// The parsed root tree (`None` until [`parse`](Self::parse) succeeds).
    pub(crate) fn root_tree(&self) -> Option<&ListNode> {
        self.tree.as_ref()
    }

    /// The map of named template definitions (`{{define}}`/`{{block}}`).
    pub(crate) fn define_map(&self) -> &BTreeMap<GoKey, Arc<ListNode>> {
        &self.defines
    }

    /// The shared function map (builtins plus any user-registered functions).
    pub(crate) fn func_map(&self) -> &Arc<BTreeMap<String, ValueFunc>> {
        &self.funcs
    }

    /// Execute a caller-supplied (escaped) tree set with this template's
    /// options and function map. Mirrors [`execute_fmt`](Self::execute_fmt)
    /// but takes the entry tree, template map, and funcs from the html layer.
    pub(crate) fn execute_tree_fmt<W: core::fmt::Write>(
        &self,
        writer: &mut W,
        entry: &ListNode,
        templates: &BTreeMap<GoKey, Arc<ListNode>>,
        funcs: &BTreeMap<String, ValueFunc>,
        data: &Value,
    ) -> Result<()> {
        let mut executor = self.make_executor(funcs, templates);
        executor.execute(writer, entry, data)
    }
}

impl Clone for Template {
    /// Create an independent copy of this template, the counterpart to Go's
    /// `template.Clone()`. The cloned template has its own copy of the define
    /// map and shares the function map (via `Arc`-wrapped closures);
    /// modifications to one do not affect the other.
    ///
    /// # Examples
    ///
    /// ```
    /// use gotmpl::{Template, tmap};
    /// use gotmpl::parse::{ListNode, Node, TextNode, Pos};
    ///
    /// let original = Template::new("t")
    ///     .parse(r#"{{define "x"}}original{{end}}{{template "x"}}"#)
    ///     .unwrap();
    ///
    /// let mut cloned = original.clone();
    ///
    /// // Override "x" in the clone
    /// let cloned = cloned.add_parse_tree("x", ListNode {
    ///     pos: Pos::new(0, 1),
    ///     nodes: vec![Node::Text(TextNode {
    ///         pos: Pos::new(0, 1),
    ///         text: "cloned".into(),
    ///     })],
    /// });
    ///
    /// assert_eq!(original.execute_to_string(&tmap!{}).unwrap(), "original");
    /// assert_eq!(cloned.execute_to_string(&tmap!{}).unwrap(), "cloned");
    /// ```
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            tree: self.tree.clone(),
            defines: self.defines.clone(),
            funcs: self.funcs.clone(),printf_identity:self.printf_identity.clone(),
            #[cfg(feature="std")]formatter_scope:self.formatter_scope.clone(),
            left_delim: self.left_delim.clone(),
            right_delim: self.right_delim.clone(),
            missing_key: self.missing_key,
            max_range_iters: self.max_range_iters,
            execution_charge: self.execution_charge.clone(),
            value_limit:self.value_limit,output_limit:self.output_limit,
            function_signatures: self.function_signatures.clone(),
            #[cfg(not(feature = "html"))]
            definition_lookup: self.definition_lookup.clone(),
        }
    }
}

// Convenience constructors
/// Parse and execute a template in one shot.
///
/// Convenience for simple cases that don't need custom functions, delimiters,
/// or options.
///
/// # Examples
///
/// ```
/// use gotmpl::{execute, tmap};
///
/// let result = execute("Hello, {{.Name}}!", &tmap! { "Name" => "World" }).unwrap();
/// assert_eq!(result, "Hello, World!");
/// ```
///
/// # Errors
///
/// Returns a parse or execution error if the template is invalid or
/// execution fails.
pub fn execute(template_src: &str, data: &Value) -> Result<String> {
    Template::new("")
        .parse(template_src)?
        .execute_to_string(data)
}

/// Parse a template file and execute it in one shot.
///
/// Convenience wrapper around [`Template::parse_files`] for the common single-file
/// case. The file's basename is used as the template name for execution.
///
/// # Examples
///
/// ```no_run
/// use gotmpl::{execute_file, tmap};
///
/// let result = execute_file("templates/greeting.tmpl", &tmap! { "Name" => "World" }).unwrap();
/// # let _ = result;
/// ```
///
/// # Errors
///
/// Returns an error if the file cannot be read, the template is invalid, or
/// execution fails.
#[cfg(feature = "std")]
pub fn execute_file(filename: &str, data: &Value) -> Result<String> {
    let basename = std::path::Path::new(filename)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(filename);
    Template::new(basename)
        .parse_files(&[filename])?
        .execute_to_string(data)
}

/// Reports whether a [`Value`] is "true" according to Go's template truthiness rules.
///
/// The counterpart to Go's `template.IsTrue()`. The second "ok" slot is dropped
/// because every [`Value`] variant is always meaningful for truthiness.
///
/// # Examples
///
/// ```
/// use gotmpl::{is_true, Value};
///
/// assert!(is_true(&Value::Bool(true)));
/// assert!(!is_true(&Value::Int(0)));
/// assert!(!is_true(&Value::Nil));
/// ```
pub fn is_true(val: &Value) -> bool {
    val.is_truthy()
}

mod go_slice;
pub use go_slice::{TypedSlice,SliceRef,SliceIter,SliceType,SliceMethod,PreparedValuesWrites,ValuesWrite,ValuesCommitError};

mod budget;
pub use budget::{BudgetMeter,BudgetAccount,ByteLease,BudgetedBytes};

/// Parsed, bounded printf flags passed to native host formatters.
pub use go::FmtSpec as HostFormat;

// Public name for the existing owned Values snapshot returned by TypedSlice.
pub use go_slice::ValuesView;
