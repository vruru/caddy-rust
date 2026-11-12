use crate::common::types::Type;
use crate::common::value::{CowVal, Val};
use crate::DeclarationError;
use crate::ExecutionError;
use std::collections::BTreeMap;
use std::fmt::{Debug, Formatter};

/// A struct type that expressions can construct, e.g. `acme.Account{id: 1}`.
///
/// [`StructDef`](crate::StructDef) is one; implementing this trait lets
/// a struct literal construct any other [`Val`], e.g. a Rust type of your own.
pub trait StructType: Send + Sync {
    /// The struct's type: its name is the one struct literals construct it
    /// by, and the one it is registered under.
    fn get_type(&self) -> &Type;

    /// Creates a value of this type from the fields of a struct literal.
    ///
    /// # Errors
    ///
    /// Fails when the fields do not make a value of this type, e.g. an
    /// unknown field or a value of the wrong type.
    fn new_value<'b, 'v>(
        &self,
        fields: BTreeMap<String, CowVal<'b, 'v>>,
    ) -> Result<Box<dyn Val + 'v>, ExecutionError>;
}

/// A type to register with an [`Env`](crate::Env), see
/// [`Env::add_type`](crate::Env::add_type).
///
/// Anything that converts into one can be registered: a [`Type`], which
/// expressions can then name, or a [`StructType`], which they can also
/// construct.
pub enum TypeDecl {
    /// A type expressions can name: `type(x) == my.pkg.Ip`.
    Type(Type),
    /// A struct type, which expressions can also construct:
    /// `acme.Account{id: 1}`.
    Struct(Box<dyn StructType>),
}

impl From<Type> for TypeDecl {
    fn from(t: Type) -> Self {
        TypeDecl::Type(t)
    }
}

impl<T: StructType + 'static> From<T> for TypeDecl {
    fn from(s: T) -> Self {
        TypeDecl::Struct(Box::new(s))
    }
}

/// The types known to an [`Env`](crate::Env), by name.
///
/// A registered type's name can be used in an expression, where it resolves
/// to the type value, e.g. `type(1) == int`. The registry starts out empty:
/// the environment's libraries register their types, e.g. the standard
/// library registers `int` and `optional_type`.
///
/// A struct type, registered as a [`StructType`], can also be constructed.
/// Types are registered with [`Env::add_type`](crate::Env::add_type).
#[derive(Default)]
pub struct TypeRegistry {
    types: BTreeMap<String, Type>,
    structs: BTreeMap<String, Box<dyn StructType>>,
}

impl Debug for TypeRegistry {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TypeRegistry")
            .field("types", &self.types)
            .field("structs", &self.structs.keys())
            .finish()
    }
}

impl TypeRegistry {
    /// Finds the type registered under `name`.
    pub fn find_type(&self, name: &str) -> Option<&Type> {
        self.types.get(name)
    }

    /// Registers `decl`'s type under its name, and a struct type's
    /// constructor with it.
    ///
    /// Registering a type that is already registered is a no-op, so that
    /// libraries can each register a type they share, and a struct type may
    /// be registered after its type was.
    ///
    /// # Errors
    ///
    /// Fails with [`DeclarationError::TypeConflict`] if another type, or
    /// another struct type, is registered under the same name, and with
    /// [`DeclarationError::InvalidTypeName`] if the name is not a, possibly
    /// qualified, identifier, e.g. `int` or `my.pkg.Type`, which no
    /// expression could refer to. A failed registration leaves the registry
    /// as it was.
    pub(crate) fn register(&mut self, decl: impl Into<TypeDecl>) -> Result<(), DeclarationError> {
        match decl.into() {
            TypeDecl::Type(t) => self.register_type(t),
            TypeDecl::Struct(s) => self.register_struct(s),
        }
    }

    fn register_type(&mut self, t: Type) -> Result<(), DeclarationError> {
        if !is_qualified_ident(t.name()) {
            return Err(DeclarationError::invalid_type_name(t.name()));
        }
        match self.types.get(t.name()) {
            Some(existing) if *existing == t => Ok(()),
            Some(_) => Err(DeclarationError::type_conflict(t.name())),
            None => {
                self.types.insert(t.name().to_owned(), t);
                Ok(())
            }
        }
    }

    /// Finds the struct type registered under `name`.
    pub fn find_struct(&self, name: &str) -> Option<&dyn StructType> {
        self.structs.get(name).map(Box::as_ref)
    }

    fn register_struct(&mut self, s: Box<dyn StructType>) -> Result<(), DeclarationError> {
        let name = s.get_type().name();
        if self.structs.contains_key(name) {
            return Err(DeclarationError::type_conflict(name));
        }
        self.register_type(s.get_type().to_owned())?;
        self.structs.insert(name.to_owned(), s);
        Ok(())
    }
}

/// Whether `name` is an identifier, or several separated by dots.
pub(crate) fn is_qualified_ident(name: &str) -> bool {
    name.split('.').all(|ident| {
        let mut chars = ident.chars();
        chars
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
    })
}
