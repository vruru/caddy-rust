use crate::registry::is_qualified_ident;
use crate::DeclarationError;
use std::borrow::Cow;
use std::iter::{once, successors};

/// The namespace an [`Env`](crate::Env) resolves names against, letting an
/// expression written for container `x` say `y` where it would otherwise
/// need `x.y`. Mirrors cel-go's `containers.Container`, without aliases.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Container {
    name: String,
}

impl Container {
    /// A container named `name`, an identifier, possibly qualified, such as
    /// `a.b.c`, or the empty name for no container.
    ///
    /// # Errors
    ///
    /// Fails with [`DeclarationError::InvalidContainerName`] for any other
    /// name, a leading dot included.
    pub(crate) fn new(name: &str) -> Result<Self, DeclarationError> {
        if !name.is_empty() && !is_qualified_ident(name) {
            return Err(DeclarationError::invalid_container_name(name));
        }
        Ok(Container {
            name: name.to_owned(),
        })
    }

    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    /// The names `name` may refer to, most specific first, ending with `name`
    /// itself: in container `a.b.c`, `R.s` is `a.b.c.R.s`, `a.b.R.s`,
    /// `a.R.s`, then `R.s`. A leading dot makes `name` absolute, so it is the
    /// only candidate, without the dot. Mirrors cel-go's
    /// `Container.ResolveCandidateNames`.
    pub(crate) fn candidates<'a, 'n: 'a>(
        &'a self,
        name: &'n str,
    ) -> impl Iterator<Item = Cow<'n, str>> + 'a {
        let (scope, name) = match name.strip_prefix('.') {
            Some(absolute) => ("", absolute),
            None => (self.name.as_str(), name),
        };
        successors(Some(scope).filter(|s| !s.is_empty()), |s| {
            s.rfind('.').map(|i| &s[..i])
        })
        .map(move |scope| Cow::Owned(format!("{scope}.{name}")))
        .chain(once(Cow::Borrowed(name)))
    }
}
