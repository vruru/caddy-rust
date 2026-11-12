use crate::common::{
    decls::FunctionDecl,
    functions::Function,
    types::{self, Type},
    value::CowVal,
};
use crate::container::Container;
use crate::parser::{Macro, Macros, Parser};
use crate::registry::{TypeDecl, TypeRegistry};
use crate::{common::types::CelStruct, common::value::Val, ExecutionError, StructType};
use crate::{DeclarationError, ParseErrors, Program};
use std::collections::{
    btree_map::Entry::{Occupied, Vacant},
    BTreeMap, BTreeSet,
};
use std::sync::Arc;

/// An environment for the CEL execution.
///
/// This is where functions, overloads, and custom structs are defined.
///
/// # Example
///
/// ## Custom Structs
///
/// You can define custom struct types that can be instantiated from CEL expressions.
///
/// ```
/// use cel::{Env, StructDef, common::types, common::types::CelString};
///
/// let mut env = Env::stdlib();
/// env.add_type(
///     StructDef::new("cel.MyStruct".to_owned())
///         .add_field("some_field".to_owned(), types::STRING_TYPE)
///         .add_field_with_default("with_default".to_owned(), Box::new(CelString::from("default_value")))
/// ).unwrap();
/// ```
///
/// ## Function Overloads
///
/// You can add custom function overloads to the environment.
///
/// ```
/// use cel::{Env, common::types, common::value::CowVal};
///
/// let mut env = Env::stdlib();
///
/// // Define a function that takes an integer and returns its square.
/// env.add_overload("square", "int_square", vec![types::INT_TYPE], |args| {
///     let val = args[0].downcast_ref::<types::CelInt>().unwrap();
///     Ok(CowVal::owned(types::CelInt::from(val.inner() * val.inner())))
/// }).unwrap();
/// ```
pub struct Env {
    functions: BTreeMap<String, FunctionDecl>,
    namespaces: BTreeSet<String>,
    types: TypeRegistry,
    macros: Arc<Macros>,
    error_on_duplicate_map_keys: bool,
    optional: bool,
    container: Container,
}

impl Default for Env {
    fn default() -> Self {
        Env {
            functions: BTreeMap::new(),
            namespaces: BTreeSet::new(),
            types: TypeRegistry::default(),
            macros: Arc::default(),
            error_on_duplicate_map_keys: true,
            optional: true,
            container: Container::default(),
        }
    }
}

impl Env {
    /// Returns the standard library environment.
    ///
    /// This environment contains all the standard functions and types as defined by the
    /// CEL specification.
    pub fn stdlib() -> Env {
        Env {
            macros: Macros::standard(),
            ..Default::default()
        }
        .with_stdlib()
    }

    /// Registers the standard types and functions, as defined by the CEL
    /// specification, on this environment and returns it.
    ///
    /// Unlike [`Env::stdlib`], it adds no macros: on an [`Env::default`],
    /// `has`, `all`, `exists`, `exists_one`, `map` and `filter` are left as
    /// the calls they are written as.
    ///
    /// The `duration` and `timestamp` types and functions need the `chrono`
    /// feature; the `optional` ones are only registered while this
    /// environment supports optional values, as it does by default: see
    /// [`Env::with_optional_support`].
    ///
    /// # Panics
    ///
    /// Panics if one of the standard overloads is already declared, as when
    /// called on an [`Env::stdlib`] or twice, or if another type is already
    /// registered under one of the standard types' names.
    ///
    /// # Example
    ///
    /// ```
    /// use cel::{Context, Env, Value};
    /// use std::sync::Arc;
    ///
    /// let env = Env::default().with_stdlib();
    /// let program = env.compile("size('abc') == 3").unwrap();
    /// let context = Context::with_env(Arc::new(env));
    /// assert_eq!(program.execute(&context), Ok(Value::Bool(true)));
    /// ```
    pub fn with_stdlib(mut self) -> Self {
        types::bool::stdlib(&mut self);
        types::bytes::stdlib(&mut self);
        types::double::stdlib(&mut self);
        types::r#dyn::stdlib(&mut self);
        types::int::stdlib(&mut self);
        types::list::stdlib(&mut self);
        types::map::stdlib(&mut self);
        types::null::stdlib(&mut self);
        if self.optional {
            types::optional::stdlib(&mut self);
        }
        types::string::stdlib(&mut self);
        types::type_val::stdlib(&mut self);
        types::uint::stdlib(&mut self);

        #[cfg(feature = "chrono")]
        {
            types::duration::stdlib(&mut self);
            types::timestamp::stdlib(&mut self);
        }
        self
    }

    /// Sets whether this environment supports optional values, as it does by
    /// default, and returns it.
    ///
    /// Without, the parsers it builds with [`Env::parser`], and so
    /// [`Env::compile`], reject the optional syntax (`a.?b`, `a[?b]`, `[?a]`
    /// and `{?k: v}`) as unsupported, and [`Env::with_stdlib`] leaves out the
    /// `optional` library (`optional.of`, `optional.none`, `hasValue`, ...).
    ///
    /// That library is registered when [`Env::with_stdlib`] runs: disable
    /// support before calling it. On an [`Env::stdlib`], or after
    /// [`Env::with_stdlib`], this only disables the syntax.
    ///
    /// # Example
    ///
    /// ```
    /// use cel::{Context, Env};
    /// use std::sync::Arc;
    ///
    /// let env = Env::default().with_optional_support(false).with_stdlib();
    /// assert!(env.compile("{'a': 1}.?a").is_err());
    ///
    /// let program = env.compile("optional.of(1).hasValue()").unwrap();
    /// let context = Context::with_env(Arc::new(env));
    /// assert!(program.execute(&context).is_err());
    /// ```
    pub fn with_optional_support(mut self, optional: bool) -> Self {
        self.optional = optional;
        self
    }

    /// Returns a parser that expands the macros of this environment.
    ///
    /// [`Env::stdlib`] has the standard macros (`has`, `all`, `exists`,
    /// `exists_one`, `map` and `filter`); an [`Env::default`] has none, so its
    /// parser leaves such calls as they are written.
    ///
    /// # Example
    ///
    /// ```
    /// use cel::{Context, Env, Value};
    ///
    /// let env = Env::stdlib();
    /// let expr = env.parser().parse("[1, 2, 3].exists(x, x > 2)").unwrap();
    /// assert_eq!(Value::resolve(&expr, &Context::default()), Ok(Value::Bool(true)));
    /// ```
    pub fn parser(&self) -> Parser {
        Parser::new()
            .enable_optional_syntax(self.optional)
            .with_macros(Arc::clone(&self.macros))
    }

    /// Compiles `source` into a [`Program`], expanding the macros of this
    /// environment: the standard ones of [`Env::stdlib`], and those added with
    /// [`Env::add_macro`], by extensions included.
    ///
    /// Macros are expanded while compiling: the program doesn't depend on the
    /// environment afterwards.
    ///
    /// # Errors
    ///
    /// Fails with the [`ParseErrors`] of `source`, a macro's included.
    ///
    /// # Example
    ///
    /// ```
    /// use cel::{Context, Env, Value};
    /// use std::sync::Arc;
    ///
    /// let env = Env::stdlib();
    /// let program = env.compile("[1, 2, 3].exists(x, x > 2)").unwrap();
    /// let context = Context::with_env(Arc::new(env));
    /// assert_eq!(program.execute(&context), Ok(Value::Bool(true)));
    /// ```
    pub fn compile(&self, source: &str) -> Result<Program, ParseErrors> {
        Program::parse_with(self.parser(), source)
    }

    /// Adds a macro, expanded by the programs this environment compiles with
    /// [`Env::compile`], and by the parsers it builds with [`Env::parser`];
    /// [`Program::compile`] only expands the standard ones.
    ///
    /// # Errors
    ///
    /// Fails with [`DeclarationError::DuplicateMacro`] if a macro for the same
    /// function, called the same way (globally or on a target) with as many
    /// arguments, or with any number of them, is already added: the standard
    /// ones of [`Env::stdlib`] included. A macro for any number of arguments
    /// and one for an exact number coexist: the latter wins for its calls.
    ///
    /// # Example
    ///
    /// ```
    /// use cel::common::ast::{operators, CallExpr, Expr};
    /// use cel::parser::Macro;
    /// use cel::{Context, Env, Value};
    /// use std::sync::Arc;
    ///
    /// // `implies(a, b)` is parsed as `!a || b`: true whenever `a` is false,
    /// // whatever `b` evaluates to.
    /// let implies = Macro::global("implies", 2, |helper, _target, args| {
    ///     let b = args.pop().unwrap();
    ///     let a = args.pop().unwrap();
    ///     let not_a = helper.next_expr(Expr::Call(CallExpr {
    ///         func_name: operators::LOGICAL_NOT.to_string(),
    ///         target: None,
    ///         args: vec![a],
    ///     }));
    ///     Ok(Some(helper.next_expr(Expr::Call(CallExpr {
    ///         func_name: operators::LOGICAL_OR.to_string(),
    ///         target: None,
    ///         args: vec![not_a, b],
    ///     }))))
    /// });
    ///
    /// let mut env = Env::stdlib();
    /// env.add_macro(implies).unwrap();
    /// let program = env.compile("implies(false, 1 / 0 == 1)").unwrap();
    /// let context = Context::with_env(Arc::new(env));
    /// assert_eq!(program.execute(&context), Ok(Value::Bool(true)));
    /// ```
    pub fn add_macro(&mut self, m: Macro) -> Result<(), DeclarationError> {
        // The standard macros are shared by every `Env::stdlib()` and default
        // parser: the first macro added copies them for this environment.
        Arc::make_mut(&mut self.macros).add(m)
    }

    /// Adds a global function overload to the environment.
    ///
    /// The name is the function name (e.g., `_==_`, `size`).
    /// The id is the unique identifier for this overload (e.g., `equals_int64`).
    /// The args are the expected argument types.
    /// The op is the function implementation.
    ///
    /// # Errors
    ///
    /// Fails with [`DeclarationError::DuplicateOverload`] if an overload of that
    /// name is already declared with the same id, or with the same signature.
    pub fn add_overload(
        &mut self,
        name: &str,
        id: &str,
        args: Vec<types::Type>,
        op: Function,
    ) -> Result<(), DeclarationError> {
        match self.functions.entry(name.to_owned()) {
            Vacant(vacant_entry) => {
                let mut value = FunctionDecl::new(name);
                value.add_overload(id.to_string(), false, args, op)?;
                vacant_entry.insert(value);
                if let Some((namespace, _)) = name.split_once('.') {
                    self.namespaces.insert(namespace.to_owned());
                }
                Ok(())
            }
            Occupied(occupied_entry) => {
                occupied_entry
                    .into_mut()
                    .add_overload(id.to_string(), false, args, op)
            }
        }
    }

    pub(crate) fn has_namespace(&self, namespace: &str) -> bool {
        self.namespaces.contains(namespace)
    }

    /// Finds a global function overload that matches the given name and arguments.
    pub fn find_overload(&self, name: &str, args: &[CowVal<'_, '_>]) -> Option<Function> {
        match self.functions.get(name) {
            None => None,
            Some(fn_decl) => fn_decl.find_overload(false, args),
        }
    }

    pub(crate) fn has_overload(&self, name: &str) -> bool {
        self.functions
            .get(name)
            .is_some_and(|function| function.has_overload(false))
    }

    /// Adds a member function overload to the environment.
    ///
    /// A member function is one that is called using the receiver syntax (e.g., `x.matches(y)`).
    /// The name is the function name.
    /// The id is the unique identifier for this overload.
    /// The target is the type of the receiver.
    /// The args are the expected argument types (excluding the receiver).
    /// The op is the function implementation.
    ///
    /// # Errors
    ///
    /// Fails with [`DeclarationError::DuplicateOverload`] if an overload of that
    /// name is already declared with the same id, or with the same signature.
    pub fn add_member_overload(
        &mut self,
        name: &str,
        id: &str,
        target: Type,
        args: Vec<types::Type>,
        op: Function,
    ) -> Result<(), DeclarationError> {
        let mut args = args;
        args.insert(0, target);
        match self.functions.entry(name.to_owned()) {
            Vacant(vacant_entry) => {
                let mut value = FunctionDecl::new(name);
                value.add_overload(id.to_string(), true, args, op)?;
                vacant_entry.insert(value);
                Ok(())
            }
            Occupied(occupied_entry) => {
                occupied_entry
                    .into_mut()
                    .add_overload(id.to_string(), true, args, op)
            }
        }
    }

    /// Finds a member function overload that matches the given name and arguments.
    pub fn find_member_overload(
        &self,
        name: &str,
        args: &[CowVal<'_, '_>],
    ) -> Option<Function> {
        match self.functions.get(name) {
            None => None,
            Some(fn_decl) => fn_decl.find_overload(true, args),
        }
    }

    pub(crate) fn has_member_overload(&self, name: &str) -> bool {
        self.functions
            .get(name)
            .is_some_and(|function| function.has_overload(true))
    }

    /// Registers a type with the environment, so that expressions can refer
    /// to it by name, and, for a struct type, construct it.
    ///
    /// The name resolves to the type value, unless a variable of the same name
    /// shadows it. Values need not be registered to be evaluated: registering
    /// their type is what lets an expression name it.
    ///
    /// ```
    /// use cel::{Context, Env, Value};
    /// use cel::common::types::Type;
    /// use std::sync::Arc;
    ///
    /// let mut env = Env::stdlib();
    /// env.add_type(Type::new_opaque_type("Ip")).unwrap();
    /// let program = env.compile("type(Ip) == type").unwrap();
    /// let context = Context::with_env(Arc::new(env));
    ///
    /// assert_eq!(program.execute(&context), Ok(Value::Bool(true)));
    /// ```
    ///
    /// Registering a `StructType`, e.g. a `StructDef`, also lets struct
    /// literals construct it:
    /// `cel.MyStruct{some_field: 'value'}`.
    ///
    /// # Errors
    ///
    /// Fails with [`DeclarationError::TypeConflict`] if another type, or
    /// another struct type, is already registered under that name, and with
    /// [`DeclarationError::InvalidTypeName`] if the name is not an identifier,
    /// or several separated by dots. Registering an equal type again is fine,
    /// and so is registering a struct type whose type was registered alone.
    pub fn add_type(&mut self, t: impl Into<TypeDecl>) -> Result<(), DeclarationError> {
        self.types.register(t)
    }

    /// Sets the container names are resolved against: with container `x`, an
    /// identifier, qualified identifier, struct type name or function name
    /// `y` also resolves to `x.y`, ahead of the plain `y`. In container `a.b`,
    /// `y` is tried as `a.b.y`, `a.y`, then `y`; a leading dot, as in `.y`,
    /// makes the name absolute, so only `y` is tried.
    ///
    /// Each call replaces the container; an empty name clears it.
    ///
    /// ```
    /// use cel::{Context, Env, Value};
    /// use std::sync::Arc;
    ///
    /// let mut env = Env::stdlib();
    /// env.set_container("x").unwrap();
    /// let program = env.compile("y").unwrap();
    /// let mut context = Context::with_env(Arc::new(env));
    /// context.add_variable_from_value("x.y", true);
    ///
    /// assert_eq!(program.execute(&context), Ok(Value::Bool(true)));
    /// ```
    ///
    /// # Errors
    ///
    /// Fails with [`DeclarationError::InvalidContainerName`] if `name` is
    /// neither empty nor an identifier, or several separated by dots; a
    /// leading dot is rejected.
    pub fn set_container(&mut self, name: &str) -> Result<(), DeclarationError> {
        self.container = Container::new(name)?;
        Ok(())
    }

    /// The name of the container, empty if none is set.
    pub fn container_name(&self) -> &str {
        self.container.name()
    }

    pub(crate) fn container(&self) -> &Container {
        &self.container
    }

    /// The types registered with the environment.
    pub fn types(&self) -> &TypeRegistry {
        &self.types
    }

    /// Adds an extension library, such as [`extensions::strings`], by
    /// handing it this environment to register its types, overloads and
    /// macros on. Compile with [`Env::compile`] for the macros to be expanded.
    ///
    /// ```
    /// use cel::{extensions, Context, Env, Value};
    /// use std::sync::Arc;
    ///
    /// let mut env = Env::stdlib();
    /// env.add_extension(extensions::strings);
    /// let program = env.compile("'TacoCat'.lowerAscii()").unwrap();
    /// let context = Context::with_env(Arc::new(env));
    ///
    /// assert_eq!(program.execute(&context), Ok(Value::from("tacocat")));
    /// ```
    ///
    /// [`extensions::strings`]: crate::extensions::strings
    pub fn add_extension(
        &mut self,
        extension: impl FnOnce(&mut Env) -> Result<(), DeclarationError>,
    ) -> Result<(), DeclarationError> {
        extension(self)
    }

    /// Sets whether a map literal that repeats a key is an error.
    ///
    /// On by default, as the spec requires. Turning it off keeps the last entry
    /// instead, so `{'a': 1, 'a': 2}` evaluates to `{'a': 2}`, which is what
    /// cel-go does. Mirrors cel-java's `CelOptions.errorOnDuplicateMapKeys`,
    /// where the shipped default (`CelOptions.DEFAULT`) also errors.
    ///
    /// Numeric keys compare by value, as the spec requires, so `{0: 1, 0u: 2}`
    /// repeats a key too, which cel-java doesn't catch. With the check off, both
    /// entries are kept, as in cel-go.
    ///
    /// ```
    /// use cel::{Context, Env, Value};
    /// use std::sync::Arc;
    ///
    /// let mut env = Env::stdlib();
    /// env.set_error_on_duplicate_map_keys(false);
    /// let program = env.compile("{'a': 1, 'a': 2}['a']").unwrap();
    /// let context = Context::with_env(Arc::new(env));
    ///
    /// let value: Value = program.execute(&context).unwrap();
    /// assert_eq!(value, 2.into());
    /// ```
    pub fn set_error_on_duplicate_map_keys(&mut self, value: bool) {
        self.error_on_duplicate_map_keys = value;
    }

    pub(crate) fn error_on_duplicate_map_keys(&self) -> bool {
        self.error_on_duplicate_map_keys
    }
}

/// A definition for a custom struct type.
///
/// A struct definition defines the name of the struct, its fields, and any default values
/// for those fields. Struct definitions are added to an [`Env`] to allow them to be
/// instantiated from CEL expressions.
///
/// # Example
///
/// ```
/// use cel::{Env, StructDef, common::types, common::types::CelString};
///
/// let mut env = Env::stdlib();
/// env.add_type(
///     StructDef::new("MyStruct".to_owned())
///         .add_field("some_field".to_owned(), types::STRING_TYPE)
///         .add_field_with_default("with_default".to_owned(), Box::new(CelString::from("default_value")))
/// ).unwrap();
/// ```
pub struct StructDef {
    r#type: Type,
    fields: BTreeMap<String, Type>,
    defaults: BTreeMap<String, Box<dyn Val>>,
}

impl StructDef {
    /// Creates a new struct definition with the given name.
    ///
    /// The name should be the fully qualified name of the struct as it will be
    /// referenced in CEL expressions (e.g., `cel.MyStruct`).
    pub fn new(name: String) -> Self {
        Self {
            r#type: Type::new_struct(name),
            fields: Default::default(),
            defaults: Default::default(),
        }
    }

    /// Adds a field to the struct definition.
    ///
    /// This method adds a field with the given name and type. When the struct is
    /// instantiated in a CEL expression, this field must be provided unless it
    /// has a default value (see [`add_field_with_default`](Self::add_field_with_default)).
    pub fn add_field(self, field: String, t: Type) -> Self {
        self.insert_field(field, t, None)
    }

    /// Adds a field to the struct definition with a default value.
    ///
    /// This method adds a field with the given name and a default value. The type
    /// of the field is automatically inferred from the default value. When the
    /// struct is instantiated in a CEL expression, this field may be omitted, in
    /// which case the default value will be used.
    pub fn add_field_with_default(self, field: String, default: Box<dyn Val>) -> Self {
        self.insert_field(field, default.get_type().to_owned(), Some(default))
    }

    /// Internal method to insert a field into the struct definition.
    fn insert_field(self, field: String, t: Type, default: Option<Box<dyn Val>>) -> Self {
        let mut def = self;
        def.fields.insert(field.clone(), t);
        if let Some(default) = default {
            def.defaults.insert(field, default);
        }
        def
    }

    /// Creates a new instance of the struct with the given field values.
    ///
    /// This method is used internally by the CEL execution engine to instantiate
    /// a struct from a CEL expression.
    ///
    /// # Errors
    ///
    /// Missing fields will be populated with their default values if defined.
    /// Returns an error if:
    /// - A field is missing and has no default value.
    /// - A field's type does not match the type in the definition.
    /// - An unknown field name is provided.
    fn new_struct<'b, 'v>(
        &self,
        fields: BTreeMap<String, CowVal<'b, 'v>>,
    ) -> Result<CelStruct<'v>, ExecutionError> {
        let name = self.r#type.name();
        let mut s = CelStruct::new(name.to_owned());
        let mut fields = fields;
        for (field, default) in &self.defaults {
            if let Some(value) = fields.remove(field) {
                s.add_field_value(field.clone(), value);
            } else {
                s.add_field_value(field.clone(), CowVal::Owned(default.clone_as_boxed()));
            }
        }
        for (field, value) in fields {
            match self.fields.get(&field) {
                Some(t) => {
                    if t != value.get_type() {
                        return Err(ExecutionError::UnexpectedType {
                            got: value.get_type().name().to_owned(),
                            want: format!("{} for field {field} in {name}", t.name()),
                        });
                    }
                    s.add_field_value(field, value);
                }
                None => {
                    return Err(ExecutionError::NoSuchKey(std::sync::Arc::new(format!(
                        "field `{field}` on struct `{name}`"
                    ))))
                }
            }
        }
        Ok(s)
    }
}

impl StructType for StructDef {
    fn get_type(&self) -> &Type {
        &self.r#type
    }

    fn new_value<'b, 'v>(
        &self,
        fields: BTreeMap<String, CowVal<'b, 'v>>,
    ) -> Result<Box<dyn Val + 'v>, ExecutionError> {
        Ok(Box::new(self.new_struct(fields)?))
    }
}
