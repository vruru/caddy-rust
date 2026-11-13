/// A single substring replacement rule for URI rewriting.
#[derive(Clone)]
pub(crate) struct RewriteSubstring {
    pub(crate) find: String,
    pub(crate) replace: String,
    pub(crate) limit: i64,
}

impl Default for RewriteSubstring {
    fn default() -> Self {
        Self {
            find: String::new(),
            replace: String::new(),
            limit: 0,
        }
    }
}

/// A single regex replacement rule for URI path rewriting.
#[derive(Clone)]
pub(crate) struct RewriteRegex {
    pub(crate) regex: Option<std::sync::Arc<crate::go_regexp::GoRegexp>>,
    pub(crate) replace: String,
}

/// A key-value pair for query string manipulation.
#[derive(Clone)]
pub(crate) struct RewriteArgument {
    pub(crate) key: String,
    pub(crate) val: String,
}

impl Default for RewriteArgument {
    fn default() -> Self {
        Self {
            key: String::new(),
            val: String::new(),
        }
    }
}

/// A query replace rule with optional precompiled regex.
#[derive(Clone)]
pub(crate) struct RewriteQueryReplace {
    pub(crate) key: String,
    pub(crate) search: String,
    pub(crate) regex: Option<std::sync::Arc<crate::go_regexp::GoRegexp>>,
    pub(crate) replace: String,
}

impl Default for RewriteQueryReplace {
    fn default() -> Self {
        Self {
            key: String::new(),
            search: String::new(),
            regex: None,
            replace: String::new(),
        }
    }
}

/// Query string rewrite configuration.
#[derive(Clone, Default)]
pub(crate) struct RewriteQuery {
    pub(crate) rename: Vec<RewriteArgument>,
    pub(crate) set: Vec<RewriteArgument>,
    pub(crate) add: Vec<RewriteArgument>,
    pub(crate) replace: Vec<RewriteQueryReplace>,
    pub(crate) delete: Vec<String>,
}

/// Top-level rewrite plan.
#[derive(Clone, Default)]
pub(crate) struct RewritePlan {
    pub(crate) method: String,
    pub(crate) uri: String,
    pub(crate) strip_path_prefix: String,
    pub(crate) strip_path_suffix: String,
    pub(crate) uri_substring: Vec<RewriteSubstring>,
    pub(crate) path_regexp: Vec<RewriteRegex>,
    pub(crate) query: Option<RewriteQuery>,
}
