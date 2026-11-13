//! Borrowed, immutable replacer inputs. No request body, clones, mutation, or
//! independently reimplemented placeholder semantics are introduced here.
use super::*;
struct Head<'a> {
    uri: &'a Uri,
    method: &'a Method,
    headers: &'a HeaderMap,
    extensions: &'a http::Extensions,
    version: Version,
    projection: Option<&'a super::super::rewrite_runtime::Projection>,
}
impl<'a> Head<'a> {
    fn uri(&self) -> &'a Uri {
        self.uri
    }
    fn method(&self) -> &'a Method {
        self.method
    }
    fn headers(&self) -> &'a HeaderMap {
        self.headers
    }
    fn extensions(&self) -> &'a http::Extensions {
        self.extensions
    }
    fn version(&self) -> Version {
        self.version
    }
}
pub(in crate::http_runtime) struct View<'a> {
    request: Option<Head<'a>>,
    values: &'a HashMap<String, String>,
    raw_regex_captures: &'a super::super::request_regex::RawCaptures,
    probe: bool,
    authority: &'a str,
    original_uri: &'a Uri,
    original_method: &'a Method,
    peer: &'a NetAddress,
    local: &'a NetAddress,
    tls: bool,
    client_ip: Option<IpAddr>,
    business: &'a Arc<BusinessGuard>,
    maps: &'a [LazyMap],
}
impl<'a> View<'a> {
    pub(super) fn new(ctx: &'a Context) -> Self {
        Self {
            request: ctx.request.as_ref().map(|r| Head {
                uri: r.uri(),
                method: r.method(),
                headers: r.headers(),
                extensions: r.extensions(),
                version: r.version(),
                projection: super::super::rewrite_runtime::lookup_projection(r),
            }),
            values: &ctx.values,
            raw_regex_captures: &ctx.raw_regex_captures,
            probe: ctx.probe,
            authority: &ctx.authority,
            original_uri: &ctx.original_uri,
            original_method: &ctx.original_method,
            peer: &ctx.peer,
            local: &ctx.local,
            tls: ctx.tls,
            client_ip: ctx.client_ip,
            business: &ctx.business,
            maps: &ctx.maps,
        }
    }
    pub(in crate::http_runtime) fn value(&self, name: &str) -> Option<&'a str> {
        self.values.get(name).map(String::as_str)
    }
    pub(in crate::http_runtime) fn headers(&self) -> Option<&'a HeaderMap> {
        self.request.as_ref().map(Head::headers)
    }
    fn req(&self) -> &Head<'a> {
        self.request
            .as_ref()
            .expect("request is consumed only by terminal proxy")
    }
    pub(in crate::http_runtime) fn lookup_bytes(&self, name: &str) -> Option<Vec<u8>> {
        if let Some(value) = self.raw_regex_captures.get(name) {
            return Some(value.to_vec());
        }
        if !self.values.contains_key(name)
            && let Some(rewrite) = self.request.as_ref().and_then(|r| r.projection)
        {
            if name == "http.request.uri" {
                return Some(rewrite.request_uri.to_vec());
            }
            if name == "http.request.uri.path" {
                return Some(rewrite.state.path.clone());
            }
            if name == "http.request.uri.query" {
                return Some(rewrite.state.query.clone());
            }
        }
        if !self.probe && !self.values.contains_key(name) {
            let address = match name {
                "http.request.remote" | "http.request.remote.host" | "http.request.remote.port" => {
                    Some(self.peer)
                }
                "http.request.local" | "http.request.local.host" | "http.request.local.port" => {
                    Some(self.local)
                }
                _ => None,
            };
            if let Some(address) = address {
                return Some(if name.ends_with(".host") {
                    address.raw_host().into_owned()
                } else if name.ends_with(".port") {
                    address.raw_port().into_owned()
                } else {
                    address.raw_text().into_owned()
                });
            }
        }
        if !self.values.contains_key(name)
            && let Some(req) = self.request.as_ref()
        {
            if matches!(name, "http.request.uri.path" | "http.request.orig_uri.path") {
                let uri = if name == "http.request.orig_uri.path" {
                    &self.original_uri
                } else {
                    req.extensions()
                        .get::<super::super::rewrite_runtime::Original>()
                        .map_or_else(|| req.uri(), |v| &v.uri)
                };
                return super::super::http_redirect::url::template_decode_bytes(
                    uri.path_and_query().map_or("", |p| p.raw_path()).as_bytes(),
                )
                .ok();
            }
            if let Some(field) = name.strip_prefix("http.request.header.") {
                if field.eq_ignore_ascii_case("Host") {
                    return Some(Vec::new());
                }
                let values = req.headers().get_all(field);
                let mut out = Vec::new();
                for (i, value) in values.iter().enumerate() {
                    if i > 0 {
                        out.push(b',');
                    }
                    out.extend_from_slice(value.as_bytes());
                }
                return Some(out);
            }
            if let Some(key) = name.strip_prefix("http.request.uri.query.") {
                let query = self.replacer_query();
                let mut out = Vec::with_capacity(query.len());
                let mut first = true;
                for part in query.split(|b| *b == b'&') {
                    if let Some((k, v)) = super::super::query_match::query_pair(part)
                        && k.as_ref() == key.as_bytes()
                    {
                        if !first {
                            out.push(b',');
                        }
                        first = false;
                        out.extend_from_slice(&v);
                    }
                }
                return Some(out);
            }
        }
        self.lookup(name).map(String::into_bytes)
    }
    pub(super) fn replacer_query(&self) -> &[u8] {
        let req = self.req();
        if let Some(p) = req.projection {
            &p.state.query
        } else {
            let uri = req
                .extensions()
                .get::<super::super::rewrite_runtime::Original>()
                .map_or_else(|| req.uri(), |v| &v.uri);
            uri.query().unwrap_or_default().as_bytes()
        }
    }
    pub(in crate::http_runtime) fn lookup(&self, name: &str) -> Option<String> {
        self.lookup_depth(name, 0)
    }
    fn expand_depth(&self, input: &str, depth: usize) -> Option<String> {
        replace(input, true, |key| self.lookup_depth(key, depth + 1)).ok()
    }
    fn lookup_depth(&self, name: &str, depth: usize) -> Option<String> {
        if let Some(value) = self.raw_regex_captures.get(name) {
            return std::str::from_utf8(value).ok().map(str::to_owned);
        }
        if let Some(value) = crate::http_config::helpers::global_lookup(name) {
            return Some(value);
        }
        if self.probe {
            return None;
        }
        if depth > 64 {
            return None;
        }
        if let Some(value) = self.values.get(name) {
            return Some(value.clone());
        }
        let req = self.request.as_ref();
        let source = req.and_then(|r| {
            r.extensions()
                .get::<super::super::rewrite_runtime::Original>()
        });
        let lookup_uri = source.map(|s| &s.uri).or_else(|| req.map(Head::uri));
        let lookup_method = source.map(|s| &s.method).or_else(|| req.map(Head::method));
        Some(match name {
            "http.shutting_down" => self.business.generation().shutting_down().to_string(),
            "http.time_until_shutdown" => self
                .business
                .generation()
                .time_until_shutdown()
                .unwrap_or_default(),
            "http.request.hostport" => self.authority.to_owned(),
            "http.request.host" => hostname(&self.authority),
            "http.request.port" => self
                .authority
                .parse::<http::uri::Authority>()
                .ok()
                .and_then(|a| a.port_u16())
                .map(|p| p.to_string())
                .unwrap_or_default(),
            "http.request.remote" => self.peer.to_string(),
            "http.request.remote.host" => self.peer.host(),
            "http.request.remote.port" => self.peer.port_text(),
            "http.request.local" => self.local.to_string(),
            "http.request.local.host" => self.local.host(),
            "http.request.local.port" => self.local.port_text(),
            "http.request.client_ip" | "http.vars.client_ip" => {
                self.client_ip.map_or_else(String::new, |ip| ip.to_string())
            }
            "http.request.scheme" => {
                if self.tls {
                    "https".into()
                } else {
                    "http".into()
                }
            }
            "http.request.method" => lookup_method?.to_string(),
            "http.request.orig_method" => self.original_method.to_string(),
            "http.request.uri" if req.and_then(|r| r.projection).is_some() => {
                String::from_utf8(self.lookup_bytes(name)?).ok()?
            }
            "http.request.uri.query" if req.and_then(|r| r.projection).is_some() => {
                String::from_utf8(self.lookup_bytes(name)?).ok()?
            }
            "http.request.uri" => lookup_uri?
                .path_and_query()
                .map(|x| x.as_str())
                .unwrap_or("/")
                .to_owned(),
            "http.request.uri.path" => String::from_utf8(self.lookup_bytes(name)?).ok()?,
            "http.request.uri.query" => lookup_uri?.query().unwrap_or_default().to_owned(),
            "http.request.orig_uri" => self
                .original_uri
                .path_and_query()
                .map(|x| x.as_str())
                .unwrap_or("/")
                .to_owned(),
            "http.request.orig_uri.path" => String::from_utf8(self.lookup_bytes(name)?).ok()?,
            "http.request.orig_uri.query" => {
                self.original_uri.query().unwrap_or_default().to_owned()
            }
            "http.request.orig_uri.prefixed_query" => self
                .original_uri
                .query()
                .filter(|query| !query.is_empty())
                .map(|query| format!("?{query}"))
                .unwrap_or_default(),
            "http.request.proto" => match req?.version() {
                Version::HTTP_3 => "HTTP/3.0",
                Version::HTTP_2 => "HTTP/2.0",
                Version::HTTP_10 => "HTTP/1.0",
                _ => "HTTP/1.1",
            }
            .into(),
            "http.vars.root" => ".".into(),
            _ if name.starts_with("http.request.header.")
                || name.starts_with("http.request.uri.query.") =>
            {
                String::from_utf8(self.lookup_bytes(name)?).ok()?
            }
            _ => {
                for map in self.maps {
                    let Some(index) = map.destinations.iter().position(|dest| dest == name) else {
                        continue;
                    };
                    let input = self.expand_depth(&map.source, depth)?;
                    for entry in &map.mappings {
                        let Some(output) = entry.outputs.get(index).filter(|v| !v.is_null()) else {
                            continue;
                        };
                        let output = if let serde_json::Value::String(s) = output {
                            s.clone()
                        } else {
                            crate::http_config::helpers::value_string(output)
                        };
                        if let Some(regex) = &entry.regex {
                            if let Some(captures) = regex.captures(&input) {
                                let mut expanded = String::new();
                                captures.expand(&output, &mut expanded);
                                return Some(expanded);
                            }
                        } else if entry.input.as_deref().unwrap_or_default() == input {
                            return self.expand_depth(&output, depth);
                        }
                    }
                    return Some(
                        map.defaults
                            .get(index)
                            .and_then(|v| v.as_str())
                            .and_then(|s| self.expand_depth(s, depth))
                            .unwrap_or_default(),
                    );
                }
                return None;
            }
        })
    }
}
