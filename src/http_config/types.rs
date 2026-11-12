#[derive(Clone)]
pub(crate) struct Route {
    pub(crate) group: Option<String>,
    pub(crate) matchers: Vec<MatcherSet>,
    pub(crate) handlers: Vec<Handler>,
    pub(crate) trace_modules: Vec<crate::http_runtime::handler_trace::Module>,
    pub(crate) terminal: bool,
}

pub(crate) type MatcherSet = Vec<Matcher>;

#[derive(Clone)]
pub(crate) enum Matcher {
    Expression(std::sync::Arc<crate::http_runtime::cel_matcher::Plan>),
    Host(Vec<String>),
    Path(Vec<String>),
    PathRegex(RequestRegex),
    HeaderRegex(Vec<(http::HeaderName, RequestRegex)>),
    VarsRegex(Vec<(String, RequestRegex)>),
    Method(Vec<String>),
    Header(Vec<(String, Option<Vec<String>>)>),
    Query(Vec<(String, Vec<String>)>),
    Vars(Vec<(String, Vec<String>)>),
    Tls(Option<bool>),
    UrlPattern(crate::http_runtime::url_pattern::Plan),
    Not(Vec<MatcherSet>),
    RemoteIp(Vec<ipnet::IpNet>),
    ClientIp(Vec<ipnet::IpNet>),
    Protocol(String),
    File {
        root: Option<String>,
        try_files: Vec<String>,
        split_path: Vec<String>,
        policy: FileMatchPolicy,
    },
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum FileMatchPolicy {
    First,
    Fallback,
    Largest,
    Smallest,
    Newest,
}

#[derive(Clone)]
pub(crate) struct RequestRegex {
    pub(crate) name: std::sync::Arc<str>,
    pub(crate) regex: std::sync::Arc<crate::go_regexp::GoRegexp>,
}

#[derive(Clone, Default)]
pub(crate) struct ResponseMatcher {
    pub(crate) status_codes: Option<Vec<i64>>,
    pub(crate) headers: Vec<(String, Option<Vec<String>>)>,
}

#[derive(Clone, Default)]
pub(crate) struct ResponseRoute {
    pub(crate) matcher: Option<ResponseMatcher>,
    pub(crate) status: String,
    pub(crate) routes: Option<Vec<Route>>,
}

#[derive(Clone, Default)]
pub(crate) struct ResponseHeaderFilter {
    pub(crate) include: std::collections::HashSet<String>,
    pub(crate) exclude: std::collections::HashSet<String>,
}

#[derive(Clone, Default)]
pub(crate) struct HeaderOps {
    pub(crate) require: Option<ResponseMatcher>,
    pub(crate) set: Vec<(String, Vec<String>)>,
    pub(crate) add: Vec<(String, Vec<String>)>,
    pub(crate) delete: Vec<String>,
}

#[derive(Clone)]
pub(crate) enum Handler {
    Templates(std::sync::Arc<crate::http_runtime::templates::TemplatePlan>),
    StaticError {
        status: String,
        message: String,
    },
    Invoke(String),
    LogAppend(std::sync::Arc<LogAppendConfig>),
    StaticResponse {
        status: String,
        body: String,
        headers: HeaderOps,
        close: bool,
    },
    Headers {
        request: HeaderOps,
        response: HeaderOps,
        deferred: bool,
    },
    Subroute {
        routes: Vec<Route>,
        errors: Vec<Route>,
        errors_configured: bool,
    },
    Rewrite {
        uri: Option<String>,
        method: Option<String>,
        strip_path_prefix: Option<String>,
        strip_path_suffix: Option<String>,
    },
    Vars(Vec<(String, std::sync::Arc<serde_json::Value>)>),
    Map {
        source: String,
        destinations: Vec<String>,
        mappings: Vec<MapEntry>,
        defaults: Vec<serde_json::Value>,
    },
    Authentication {
        algorithm: crate::http_runtime::auth_hash::Algorithm,
        accounts: Vec<Account>,
        realm: String,
        cache: Option<std::sync::Arc<crate::http_runtime::auth_cache::AuthCache>>,
    },
    FileServer {
        root: Option<String>,
        hide: Vec<String>,
        index_names: Vec<String>,
        pass_thru: bool,
        canonical_uris: bool,
        sidecars: crate::http_runtime::file_sidecars::SidecarPlan,
        browse: Option<crate::http_runtime::browse::BrowsePlan>,
    },
    Encode(std::sync::Arc<crate::http_runtime::encode_response::EncodePlan>),
    RequestBody(RequestBodyConfig),
    Intercept(Vec<ResponseRoute>),
    CopyResponse(String),
    CopyResponseHeaders(ResponseHeaderFilter),
    ReverseProxy(Box<ProxyConfig>),
}

#[derive(Clone)]
pub(crate) struct RequestBodyConfig {
    pub(crate) max_size: i64,
    pub(crate) set: String,
}

#[derive(Clone)]
pub(crate) struct LogAppendConfig {
    pub(crate) key: String,
    pub(crate) value: String,
    pub(crate) early: bool,
}

#[derive(Clone)]
pub(crate) struct MapEntry {
    pub(crate) input: Option<String>,
    pub(crate) regex: Option<regex::Regex>,
    pub(crate) outputs: Vec<serde_json::Value>,
}

#[derive(Clone)]
pub(crate) struct Account {
    pub(crate) username: String,
    pub(crate) password: String,
}

#[derive(Clone)]
pub(crate) struct ProxyConfig {
    pub(crate) ext: std::sync::Arc<super::proxy_ext::ProxyExt>,
    pub(crate) upstreams: Vec<crate::http_runtime::proxy_policy::Upstream>,
    pub(crate) selection: crate::http_runtime::proxy_policy::Selection,
    pub(crate) fastcgi: Option<FastCgiConfig>,
    pub(crate) tls: Option<ProxyTls>,
    pub(crate) http2_only: bool,
    pub(crate) enable_http2: bool,
    pub(crate) compression: bool,
    pub(crate) dial_timeout: std::time::Duration,
    pub(crate) response_header_timeout: Option<i64>,
    pub(crate) read_timeout: Option<std::time::Duration>,
    pub(crate) write_timeout: Option<std::time::Duration>,
    pub(crate) request_headers: HeaderOps,
    pub(crate) response_headers: std::sync::Arc<HeaderOps>,
    pub(crate) response_routes: Vec<ResponseRoute>,
    pub(crate) flush_interval: i64,
    pub(crate) stream_close_delay: Option<std::time::Duration>,
}

#[derive(Clone)]
pub(crate) struct ProxyTls {
    pub(crate) except_ports: Vec<String>,
    pub(crate) server_name: Option<String>,
    pub(crate) insecure_skip_verify: bool,
    pub(crate) root_ca_pem_files: Vec<String>,
    pub(crate) root_ca_pool: Vec<String>,
    pub(crate) client_certificate_file: Option<String>,
    pub(crate) client_certificate_key_file: Option<String>,
    pub(crate) handshake_timeout: Option<std::time::Duration>,
}

impl ProxyConfig {
    pub(crate) fn tls_for_port(&self, port: &str) -> Option<&ProxyTls> {
        self.tls
            .as_ref()
            .filter(|tls| !tls.except_ports.iter().any(|except| except == port))
    }
}

#[derive(Clone)]
pub(crate) struct FastCgiConfig {
    pub(crate) root: Option<String>,
    pub(crate) split_path: Vec<String>,
    pub(crate) resolve_root_symlink: bool,
    pub(crate) env: std::collections::BTreeMap<String, String>,
    pub(crate) request_buffer: Option<u64>,
    pub(crate) explicit_request_buffer: bool,
    pub(crate) capture_stderr: bool,
}
