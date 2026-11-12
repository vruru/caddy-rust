#[path="tls_values.rs"]mod tls_values;
use super::{Fields,RenderResult,arity,error,lock,string,text};
use gotmpl::{MapView,Object,Value,ValueFunc};
use http::{HeaderMap,HeaderName,HeaderValue,Method,Uri,Version,header};
use std::{collections::BTreeMap,path::Path,sync::{Arc,Mutex,OnceLock}};
#[derive(Clone)]
pub(crate) struct RequestData {
    dynamic:crate::http_runtime::placeholder_value::Dynamic,
    tls_snapshot:Option<Arc<crate::http_runtime::ConnectionSnapshot>>,
    tls_values:tls_values::Cache,
    url_values:OnceLock<request_url::Cache>,
    pub uri:Uri,pub original_uri:Uri,pub request_uri:String,pub method:Method,pub original_method:Method,
    pub form:Arc<super::forms::Form>,pub headers:HeaderMap,pub version:Version,pub host:String,pub remote:Vec<u8>,
    pub remote_ip:Vec<u8>,pub client_ip:String,pub tls:bool,pub content_length:i64,pub placeholders:BTreeMap<String,(Vec<u8>,bool)>,
}
// H2/H3 reconstruct an absolute Uri from separate pseudo-fields. Go's
// server URL still contains the origin-form path/query; Request.Host remains
// the independent authority. H1 absolute targets and virtual includes retain
// their own provenance. CONNECT retains its authority-form URL.
fn captured_uri(uri:&Uri,version:Version,method:&Method)->Result<Uri,super::super::TemplateFailure>{
    if !matches!(version,Version::HTTP_2|Version::HTTP_3)||method==Method::CONNECT{return Ok(uri.clone());}
    let mut parts=uri.clone().into_parts();parts.scheme=None;parts.authority=None;
    if parts.path_and_query.is_none(){parts.path_and_query=Some(http::uri::PathAndQuery::from_static("/"));}
    Uri::from_parts(parts).map_err(|_|super::super::TemplateFailure(http::StatusCode::BAD_REQUEST))
}
impl RequestData {
    pub(crate) fn capture(ctx:&super::super::super::request::Context)->Result<Self,super::super::TemplateFailure>{
        let req=ctx.req();let mut placeholders=BTreeMap::new();
        for name in ["http.shutting_down","http.time_until_shutdown","http.request.hostport","http.request.host","http.request.port","http.request.remote","http.request.remote.host","http.request.remote.port","http.request.local","http.request.local.host","http.request.local.port","http.request.client_ip","http.vars.client_ip","http.request.scheme","http.request.method","http.request.orig_method","http.request.uri","http.request.uri.path","http.request.uri.query","http.request.orig_uri","http.request.orig_uri.path","http.request.orig_uri.query","http.request.orig_uri.prefixed_query","http.request.proto","http.vars.root","http.error.status_code","http.error.message","http.error.id","http.error.trace"] {
            if let Some(value)=ctx.lookup_bytes(name){placeholders.insert(name.into(),(value,false));}
        }
        for name in ctx.values.keys(){if let Some(value)=ctx.lookup_bytes(name){placeholders.insert(name.clone(),(value,true));}}
        for name in ctx.template_map_destinations(){if let Some(value)=ctx.lookup_bytes(name){placeholders.insert(name.to_owned(),(value,true));}}
        let bytes=placeholders.iter().try_fold(0usize,|n,(key,value)|n.checked_add(key.len()+value.0.len()+64));
        if !bytes.is_some_and(|n|n<=1<<20){return Err(super::super::TemplateFailure(http::StatusCode::INTERNAL_SERVER_ERROR));}
        let target=req.extensions().get::<super::super::virtual_request::VirtualTarget>();
        let uri=match target{Some(target)=>target.uri.clone(),None=>captured_uri(req.uri(),req.version(),req.method())?};
        let original_uri=match target{Some(target)=>target.uri.clone(),None=>captured_uri(&ctx.original_uri,req.version(),ctx.template_original_method())?};
        let request_uri=if target.is_some(){String::new()}else{ctx.original_uri.path_and_query().map_or("/",|v|v.as_str()).to_owned()};
        let form=super::forms::Form::new(req.method().as_str(),uri.query().unwrap_or_default(),req.headers().get(header::CONTENT_TYPE).and_then(|v|v.to_str().ok()).unwrap_or_default());
        // Go's net/http parser promotes the wire Host header into Request.Host
        // and removes it from Request.Header; Hyper retains that wire field.
        let mut headers=req.headers().clone();headers.remove(header::HOST);
        Ok(Self{tls_snapshot:req.extensions().get::<Arc<crate::http_runtime::ConnectionSnapshot>>().cloned(),tls_values:tls_values::cache(),url_values:OnceLock::new(),dynamic:crate::http_runtime::placeholder_value::Dynamic::capture(ctx),uri,original_uri,request_uri,form,method:req.method().clone(),original_method:ctx.lookup("http.request.orig_method").and_then(|s|s.parse().ok()).unwrap_or(Method::GET),headers,version:req.version(),host:ctx.authority.clone(),remote:ctx.peer.raw_text().into_owned(),remote_ip:ctx.peer.raw_host().into_owned(),client_ip:ctx.client_ip.map_or_else(String::new,|ip|ip.to_string()),tls:ctx.tls,content_length:if target.is_some(){0}else{ctx.template_content_length()},placeholders})
    }
    pub(super) fn placeholder(&self,name:&str,control:&Arc<super::Control>)->RenderResult<Value> {
        if let Some(value)=crate::http_config::helpers::global_lookup(name){control.reserve_host_bytes(value.len()+64)?;return Ok(string(value));}
        if !self.placeholders.get(name).is_some_and(|(_,explicit)|*explicit){if let Some(cache)=self.url_values.get(){if let Some(value)=request_url::placeholder(cache,control,name)?{return Ok(value);}}}
        if let Some(value)=self.dynamic.get(name){
            use crate::http_runtime::placeholder_value::Value as P;
            let value=match value{P::Null=>String::new(),P::Bool(v)=>v.to_string(),P::Duration(v)=>crate::duration::format(v),P::Double(v)=>v.to_string(),P::Unavailable(message)=>return Err(error(message)),_=>return Err(error("unexpected dynamic placeholder type"))};
            control.reserve_host_bytes(value.len()+64)?;return Ok(string(value));
        }
        if let Some((value,_))=self.placeholders.get(name){control.reserve_host_bytes(value.len()+64)?;return Ok(Value::from_go_bytes(value.clone()));}
        if let Some(name)=name.strip_prefix("http.request.header."){
            let values=self.headers.get_all(name);let count=values.iter().count();
            let length=values.iter().try_fold(count.saturating_sub(1),|n,v|n.checked_add(v.as_bytes().len())).ok_or_else(||error("header placeholder size overflow"))?;
            control.reserve_host_bytes(length.checked_mul(2).and_then(|n|n.checked_add(64)).ok_or_else(||error("header placeholder size overflow"))?)?;
            let mut bytes=Vec::with_capacity(length);for(index,value)in values.iter().enumerate(){if index!=0{bytes.push(b',');}bytes.extend_from_slice(value.as_bytes());}
            return Ok(Value::from_go_bytes(bytes));
        }
        if let Some(name)=name.strip_prefix("http.request.uri.query."){
            let query=self.uri.query().unwrap_or_default().as_bytes();
            control.reserve_host_bytes(query.len().checked_mul(4).and_then(|n|n.checked_add(128)).ok_or_else(||error("query placeholder size overflow"))?)?;
            let mut bytes=Vec::with_capacity(query.len());let mut first=true;
            for(index,part)in query.split(|byte|*byte==b'&').filter(|part|!part.is_empty()).enumerate(){
                if index>=16_384{return Err(error("query placeholder entry limit exceeded"));}control.charge(1)?;
                if let Some((key,value))=crate::http_runtime::query_match::query_pair(part){if key.as_ref()==name.as_bytes(){if !first{bytes.push(b',');}first=false;bytes.extend_from_slice(&value);}}
            }
            return Ok(Value::from_go_bytes(bytes));
        }
        Ok(string(""))
    }
    pub(super) fn method(&self,name:&str,args:&[Value])->RenderResult<Value>{
        if name=="Cookie"{
            arity(args,1,1)?;let name=text(args,0)?;
            for line in self.headers.get_all(header::COOKIE).iter(){
                if let Ok(line)=line.to_str(){for part in line.split(';'){
                    if let Some((key,value))=part.trim().split_once('='){
                        if key.trim()==name {let value=value.trim();let value=value.strip_prefix('"').and_then(|s|s.strip_suffix('"')).unwrap_or(value);return Ok(string(value));}
                    }
                }}
            }
            return Ok(string(""));
        }
        arity(args,0,0)?;
        if name=="RemoteIP"{return Ok(Value::from_go_bytes(self.remote_ip.clone()));}
        Ok(string(match name{
            "ClientIP"=>self.client_ip.clone(),
            "Host"=>{
                if self.host.starts_with('['){self.host.rsplit_once("]:").map_or_else(||self.host.clone(),|(host,_)|host.trim_start_matches('[').into())}
                else if self.host.bytes().filter(|byte|*byte==b':').count()==1{self.host.split_once(':').map_or_else(||self.host.clone(),|(host,_)|host.into())}
                else{self.host.clone()}
            }
            _=>return Err(error("unknown request template method")),
        }))
    }
    pub(super) fn value(&self,original:bool,control:&Arc<super::Control>)->RenderResult<Value>{
        let uri=if original{&self.original_uri}else{&self.uri};
        if self.url_values.get().is_none(){let prepared=request_url::cache(control)?;let _=self.url_values.set(prepared);}
        let url_cache=self.url_values.get().ok_or_else(||error("request URL cache missing"))?;
        let method=if original{&self.original_method}else{&self.method};
        let headers=if original{HeaderMap::new()}else{self.headers.clone()};
        let request_uri=&self.request_uri;
        let (major,minor,proto)=if original{(0,0,"")}else{match self.version{Version::HTTP_10=>(1,0,"HTTP/1.0"),Version::HTTP_2=>(2,0,"HTTP/2.0"),Version::HTTP_3=>(3,0,"HTTP/3.0"),_=>(1,1,"HTTP/1.1")}};
        let mut fields=Fields::from([
            ("Method".into(),string(method.as_str())),("URL".into(),request_url::cached(uri,control,url_cache,original)?),
            ("Header".into(),header_value(Arc::new(Mutex::new(headers.clone())),false)),
            ("Trailer".into(),header_value(Arc::new(Mutex::new(HeaderMap::new())),false)),
            ("Host".into(),string(if original{""}else{&self.host})),("RemoteAddr".into(),Value::from_go_bytes(self.remote.clone())),
            ("RequestURI".into(),string(request_uri.as_str())),("Proto".into(),string(proto)),
            ("ProtoMajor".into(),Value::Int(major)),("ProtoMinor".into(),Value::Int(minor)),
            ("ContentLength".into(),Value::Int64(if original{0}else{self.content_length})),
            ("Close".into(),Value::Bool(!original&&matches!(self.version,Version::HTTP_10|Version::HTTP_11)&&(crate::http_runtime::proxy::header_has_token(&headers,header::CONNECTION,"close")||(self.version==Version::HTTP_10&&!crate::http_runtime::proxy::header_has_token(&headers,header::CONNECTION,"keep-alive"))))),
            ("TransferEncoding".into(),Value::List(Vec::new().into())),("Body".into(),Value::Nil),
            ("MultipartForm".into(),if original{super::forms::Form::new("GET","","").multipart_value()}else{self.form.multipart_value()}),
        ]);
        fields.insert("Response".into(),nil_pointer("*http.Response",&["Status","StatusCode","Proto","ProtoMajor","ProtoMinor","Header","Body","ContentLength","TransferEncoding","Close","Uncompressed","Trailer","Request","TLS"]));
        fields.insert("Pattern".into(),string(""));
        fields.insert("TLS".into(),tls_values::value(self.tls_snapshot.clone(),&self.tls_values,control,original||!self.tls)?);
        if !original{self.form.set_query_source(request_url::query_source(url_cache,control)?);}
        let mut methods=if original{BTreeMap::new()}else{self.form.methods()};let mut method_signatures=if original{BTreeMap::new()}else{super::forms::Form::signatures()};
        if !original{
            for(name,field)in [("UserAgent",header::USER_AGENT),("Referer",header::REFERER)]{let headers=headers.clone();methods.insert(name.into(),Arc::new(move|args:&[Value]|{arity(args,0,0)?;Ok(string(headers.get(&field).and_then(|v|v.to_str().ok()).unwrap_or_default()))}));}
            methods.insert("ProtoAtLeast".into(),Arc::new(move|args:&[Value]|{arity(args,2,2)?;let want_major=args[0].as_int().ok_or_else(||error("expected int"))?;let want_minor=args[1].as_int().ok_or_else(||error("expected int"))?;Ok(Value::Bool(major>want_major||(major==want_major&&minor>=want_minor)))}));
            method_signatures.insert("ProtoAtLeast".into(),gotmpl::Signature::new(vec![gotmpl::ArgKind::Int,gotmpl::ArgKind::Int],None));
            methods.insert("PathValue".into(),Arc::new(|args:&[Value]|{arity(args,1,1)?;let _=text(args,0)?;Ok(string(""))}));
            method_signatures.insert("PathValue".into(),gotmpl::Signature::new(vec![gotmpl::ArgKind::String],None));
        }
        Ok(Value::Object(Arc::new(Object{method_signatures,methods,json:Some(Err("unsupported Go request JSON function field".into())),fields,pointer_identity:(!original).then_some(self as *const Self as usize),go_type:Some(if original{"http.Request"}else{"*http.Request"}),..Object::default()})))
    }
}
fn object(fields:Fields,methods:BTreeMap<Arc<str>,ValueFunc>)->Value{Value::Object(Arc::new(Object{fields,methods,..Object::default()}))}
fn canonical(name:&str)->String{let mut upper=true;name.chars().map(|c|{let out=if upper{c.to_ascii_uppercase()}else{c.to_ascii_lowercase()};upper=c=='-';out}).collect()}
pub(super) fn response_header(headers:Arc<Mutex<HeaderMap>>)->Value{
    let header=header_value(headers.clone(),false);
    let wrapped=header_value(headers,true);
    let Value::Object(inner)=&wrapped else{return Value::Nil;};
    object(Fields::from([("Header".into(),header)]),inner.methods.clone())
}
pub(super) fn header_format_cost(value:&Value)->RenderResult<Option<usize>>{
    let Value::Object(object)=value else{return Ok(None);};
    let Some(headers)=object.data.as_ref().and_then(|data|data.downcast_ref::<Mutex<HeaderMap>>())else{return Ok(None);};
    let headers=lock(headers)?;let mut bytes=4096usize;
    for name in headers.keys(){bytes=bytes.checked_add(name.as_str().len()*4+512).ok_or_else(||error("header formatting size overflow"))?;for value in headers.get_all(name){bytes=bytes.checked_add(value.as_bytes().len()*4+256).ok_or_else(||error("header formatting size overflow"))?;}}
    Ok(Some(bytes))
}
pub(super) fn header_value(headers:Arc<Mutex<HeaderMap>>,writable:bool)->Value{
    let mut methods=BTreeMap::<Arc<str>,ValueFunc>::new();
    let names=if writable{vec!["Get","Values","Set","Add","Del"]}else{vec!["Get","Values"]};
    for name in names{let headers=headers.clone();methods.insert(name.into(),Arc::new(move|args|{
        arity(args,if name=="Set"||name=="Add"{2}else{1},if name=="Set"||name=="Add"{2}else{1})?;
        let field=match HeaderName::from_bytes(text(args,0)?.as_bytes()){
            Ok(field)=>field,
            Err(_)if name=="Get"=>return Ok(string("")),
            Err(_)if name=="Values"=>return Ok(Value::Slice(gotmpl::TypedSlice::nil("[]string"))),
            Err(_)if name=="Del"=>return Ok(string("")),
            Err(_)=>return Err(error("invalid template response header name")),
        };
        let mut headers=lock(&headers)?;
        match name{
            "Get"=>Ok(Value::from_go_bytes(headers.get(field).map_or(b"".as_slice(),|v|v.as_bytes()))),
            "Values"=>{let values=headers.get_all(field).iter().map(|v|Value::from_go_bytes(v.as_bytes())).collect::<Vec<_>>();Ok(Value::Slice(gotmpl::TypedSlice::values("[]string",(!values.is_empty()).then(||values.into()))?))},
            "Set"|"Add"=>{let value=HeaderValue::from_bytes(args.get(1).and_then(Value::as_go_bytes).ok_or_else(||error("template host requires string argument"))?).map_err(|_|error("invalid template response header value"))?;if name=="Set"{headers.insert(field,value);}else{headers.append(field,value);}Ok(string(""))}
            "Del"=>{headers.remove(field);Ok(string(""))}
            _=>Err(error("unknown header method")),
        }
    }));}
    // Reuse the existing HeaderMap Arc as the preflight payload: no tag allocation.
    let format_data=headers.clone();
    let snapshot=Arc::new(move||{
        let headers=lock(&headers)?;
        let mut fields=Fields::new();
        for name in headers.keys(){let values=headers.get_all(name).iter().map(|v|Value::from_go_bytes(v.as_bytes())).collect::<Vec<_>>();fields.insert(canonical(name.as_str()).into(),Value::Slice(gotmpl::TypedSlice::values("[]string",Some(values.into()))?));}
        Ok(gotmpl::GoMapSnapshot::Utf8(Arc::new(fields)))
    });
    Value::Object(Arc::new(Object{data:Some(format_data),fields:Fields::new(),methods,map_view:Some(MapView{is_nil:Arc::new(||false),type_name:"http.Header",snapshot,zero:Value::Slice(gotmpl::TypedSlice::nil("[]string"))}),..Object::default()}))
}
#[path="request_url.rs"]mod request_url;
fn escape_path(input:&str,slash:bool)->String{let mut out=String::new();for byte in input.bytes(){if byte.is_ascii_alphanumeric()||b"-_.~:@&=+$".contains(&byte)||(slash&&byte==b'/'){out.push(byte as char);}else{out.push_str(&format!("%{byte:02X}"));}}out}
pub(super) fn path_escape(input:&str)->String{escape_path(input,false)}
pub(super) fn strip_html(input:&str)->String{let mut out=String::new();let mut depth=0usize;let mut quote='\0';for ch in input.chars(){match ch{
    '"'|'\'' if depth>0&&quote=='\0'=>quote=ch,
    ch if depth>0&&ch==quote=>quote='\0',
    '<' if quote=='\0'=>depth+=1,
    '>' if quote=='\0'=>{if depth>0{depth-=1;}else{out.push(ch);}},
    ch if depth==0=>out.push(ch),_=>{},
}}out}
pub(super) fn file_info(path:&Path)->RenderResult<Value>{
    let file=std::fs::File::open(path).map_err(|_|error("opening template file failed"))?;
    let metadata=file.metadata().map_err(|_|error("template file metadata failed"))?;
    metadata_info(path,metadata)
}
pub(super) fn metadata_info(path:&Path,metadata:std::fs::Metadata)->RenderResult<Value>{
    let name=path.file_name().and_then(|s|s.to_str()).unwrap_or(".").to_owned();
    let size=metadata.len() as i64;let directory=metadata.is_dir();let modified=metadata.modified().map_err(|_|error("template file modified time failed"))?;
    let mut methods=BTreeMap::<Arc<str>,ValueFunc>::new();
    methods.insert("Name".into(),Arc::new(move|a|{arity(a,0,0)?;Ok(string(name.clone()))}));
    methods.insert("Size".into(),Arc::new(move|a|{arity(a,0,0)?;Ok(Value::Int64(size))}));
    methods.insert("IsDir".into(),Arc::new(move|a|{arity(a,0,0)?;Ok(Value::Bool(directory))}));
    methods.insert("ModTime".into(),Arc::new(move|a|{arity(a,0,0)?;super::sprig::dates::system_time(modified)}));
    let mode=crate::http_runtime::browse::mode(&metadata);
    methods.insert("Mode".into(),Arc::new(move|a|{arity(a,0,0)?;Ok(mode_value(mode))}));
    Ok(Value::Object(Arc::new(Object{methods,go_type:Some("*os.fileStat"),..Object::default()})))
}

fn query_escape(input:&str)->String {
    let mut output=String::new();for byte in input.bytes(){match byte{b' '=>output.push('+'),byte if byte.is_ascii_alphanumeric()||b"-_.~".contains(&byte)=>output.push(byte as char),byte=>output.push_str(&format!("%{byte:02X}"))}}output
}

pub(super) fn values_snapshot(snapshot:Arc<dyn Fn()->RenderResult<Arc<Fields>>+Send+Sync>)->Value{values_dynamic(snapshot,Arc::new(||false))}
pub(super) fn values_dynamic(snapshot:Arc<dyn Fn()->RenderResult<Arc<Fields>>+Send+Sync>,is_nil:Arc<dyn Fn()->bool+Send+Sync>)->Value{
    let mut methods=BTreeMap::<Arc<str>,ValueFunc>::new();
    for name in ["Get","Has","Encode"] {let snapshot=snapshot.clone();methods.insert(name.into(),Arc::new(move|args|{
        arity(args,usize::from(name!="Encode"),usize::from(name!="Encode"))?;let entries=snapshot()?;
        if name=="Encode"{
            let mut output=String::new();
            for(key,values)in entries.iter(){if let Value::List(values)=values{for value in values.iter(){if !output.is_empty(){output.push('&');}output.push_str(&query_escape(key));output.push('=');output.push_str(&query_escape(value.as_str().unwrap_or_default()));if output.len()>1<<20{return Err(error("encoded query byte limit exceeded"));}}}}
            return Ok(string(output));
        }
        let key=text(args,0)?;if name=="Has"{return Ok(Value::Bool(entries.contains_key(key)));}
        Ok(entries.get(key).and_then(|value|if let Value::List(values)=value{values.first()}else{None}).cloned().unwrap_or_else(||string("")))
    }));}
    Value::Object(Arc::new(Object{methods,map_view:Some(MapView{is_nil,type_name:"url.Values",zero:Value::List(Vec::new().into()),snapshot:Arc::new(move||snapshot().map(gotmpl::GoMapSnapshot::Utf8))}),..Object::default()}))
}

fn mode_string(value:i64)->String {
    let value=value as u32;let mut out=String::new();
    for(i,byte)in b"dalTLDpSugct?".iter().enumerate(){if value&(1<<(31-i))!=0{out.push(*byte as char);}}
    if out.is_empty(){out.push('-');}
    for(i,byte)in b"rwxrwxrwx".iter().enumerate(){out.push(if value&(1<<(8-i))!=0{*byte as char}else{'-'});}
    out
}
pub(super) fn mode_value(mode:u32)->Value{
    const TYPE_MASK:u32=(1<<31)|(1<<27)|(1<<26)|(1<<25)|(1<<24)|(1<<21)|(1<<19);
    static TYPE:std::sync::LazyLock<Arc<gotmpl::Int64Type>>=std::sync::LazyLock::new(||{
        let mut methods=BTreeMap::<Arc<str>,gotmpl::Int64Method>::new();
        for name in ["String","IsDir","IsRegular","Perm","Type"]{methods.insert(name.into(),Arc::new(move|value,a|{arity(a,0,0)?;let value=value as u32;Ok(match name{
            "String"=>string(mode_string(i64::from(value))),"IsDir"=>Value::Bool(value&(1<<31)!=0),"IsRegular"=>Value::Bool(value&TYPE_MASK==0),"Perm"=>mode_value(value&0o777),_=>mode_value(value&TYPE_MASK),
        })}));}
        Arc::new(gotmpl::Int64Type{name:"fs.FileMode",kind:"uint32",stringer:Some(mode_string),methods,signatures:BTreeMap::new()})
    });Value::NamedInt64(i64::from(mode),TYPE.clone())
}

pub(super) fn typed_map(type_name:&'static str,entries:Arc<Fields>,zero:Value)->Value{
    Value::Object(Arc::new(Object{map_view:Some(MapView{is_nil:Arc::new(||false),type_name,zero,snapshot:Arc::new(move||Ok(gotmpl::GoMapSnapshot::Utf8(entries.clone())))}),..Object::default()}))
}

fn nil_pointer(go_type:&'static str,names:&[&str])->Value{
    Value::Object(Arc::new(Object{go_type:Some(go_type),nil_pointer:Some(Arc::new(||true)),fields:names.iter().map(|name|(Arc::from(*name),Value::Nil)).collect(),..Object::default()}))
}

// ParseQuery is byte based: malformed pairs are ignored by URL.Query, while
// correctly escaped non-UTF-8 keys and string values remain ordinary Go strings.
pub(super) fn byte_values(query: &[u8], control: &Arc<super::Control>) -> RenderResult<Value> {
    let peak = query
        .len()
        .checked_mul(512)
        .and_then(|n| n.checked_add(16384))
        .ok_or_else(|| error("URI query budget overflow"))?;
    control.reserve_host_bytes(peak)?;
    control.charge(query.len().div_ceil(64) + 1)?;
    let mut pending = BTreeMap::<gotmpl::GoKey, Vec<Value>>::new();
    for (index, part) in query
        .split(|b| *b == b'&')
        .filter(|p| !p.is_empty())
        .enumerate()
    {
        if index >= 16384 {
            return Err(error("URI query entry limit exceeded"));
        }
        control.charge(1)?;
        let Some((key, value)) = crate::http_runtime::query_match::query_pair(part) else {
            continue;
        };
        let value = Value::from_go_bytes(Arc::<[u8]>::from(value.as_ref()));
        pending
            .entry(gotmpl::GoKey::from_bytes(Arc::<[u8]>::from(key.as_ref())))
            .or_default()
            .push(value);
    }
    let mut entries = BTreeMap::new();
    for (key, values) in pending {
        entries.insert(
            key,
            Value::Slice(gotmpl::TypedSlice::values("[]string", Some(values.into()))?),
        );
    }
    let entries = Arc::new(entries);
    let graph_bytes = entries
        .iter()
        .try_fold(0usize, |n, (k, v)| {
            let n = n.checked_add(k.len() + 256)?;
            let Value::Slice(values) = v else {
                return None;
            };
            values.iter().try_fold(n, |n, v| {
                n.checked_add(v.as_go_bytes().map_or(0, |b| b.len()) + 128)
            })
        })
        .ok_or_else(|| error("URI query graph size overflow"))?;
    let mut methods = BTreeMap::<Arc<str>, ValueFunc>::new();
    let mut signatures = BTreeMap::new();
    for name in ["Get", "Has", "Encode"] {
        let owner = Arc::downgrade(control);
        let entries = entries.clone();
        methods.insert(
            name.into(),
            Arc::new(move |args| {
                arity(
                    args,
                    usize::from(name != "Encode"),
                    usize::from(name != "Encode"),
                )?;
                let f = owner
                    .upgrade()
                    .ok_or_else(|| error("template owner retired"))?;
                f.charge(1)?;
                if name == "Encode" {
                    f.reserve_host_bytes(
                        graph_bytes
                            .checked_mul(8)
                            .and_then(|n| n.checked_add(1024))
                            .ok_or_else(|| error("URI encoded query budget overflow"))?,
                    )?;
                    let mut bytes = Vec::with_capacity(graph_bytes.saturating_mul(3).min(1 << 20));
                    for (key, values) in entries.iter() {
                        let Value::Slice(values) = values else {
                            return Err(error("invalid URL.Values value"));
                        };
                        for value in values.iter() {
                            f.charge(1)?;
                            if !bytes.is_empty() {
                                bytes.push(b'&');
                            }
                            query_escape_bytes(&mut bytes, key.as_bytes());
                            bytes.push(b'=');
                            query_escape_bytes(
                                &mut bytes,
                                value
                                    .as_go_bytes()
                                    .ok_or_else(|| error("invalid URL.Values string"))?,
                            );
                            if bytes.len() > 1 << 20 {
                                return Err(error("encoded URI query byte limit exceeded"));
                            }
                        }
                    }
                    return Ok(Value::from_go_bytes(Arc::<[u8]>::from(bytes)));
                }
                let key = args[0]
                    .as_go_bytes()
                    .ok_or_else(|| error("URL.Values key requires string"))?;
                if name == "Has" {
                    return Ok(Value::Bool(entries.contains_key(key)));
                }
                Ok(entries
                    .get(key)
                    .and_then(|v| {
                        if let Value::Slice(values) = v {
                            values.get(0)
                        } else {
                            None
                        }
                    })
                    .unwrap_or_else(|| Value::String("".into())))
            }),
        );
        if name != "Encode" {
            signatures.insert(
                name.into(),
                gotmpl::Signature::from_static(&[gotmpl::ArgKind::String], None),
            );
        }
    }
    let owner = Arc::downgrade(control);
    Ok(Value::Object(Arc::new(Object {
        go_type: Some("url.Values"),
        methods,
        method_signatures: signatures,
        map_view: Some(gotmpl::MapView {
            type_name: "url.Values",
            is_nil: Arc::new(|| false),
            zero: Value::Slice(gotmpl::TypedSlice::nil("[]string")),
            snapshot: Arc::new(move || {
                owner
                    .upgrade()
                    .ok_or_else(|| error("template owner retired"))?
                    .charge(1)?;
                Ok(gotmpl::GoMapSnapshot::Keyed(entries.clone()))
            }),
        }),
        ..Object::default()
    })))
}
fn query_escape_bytes(output: &mut Vec<u8>, value: &[u8]) {
    for b in value {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(b) {
            output.push(*b);
        } else if *b == b' ' {
            output.push(b'+');
        } else {
            output.push(b'%');
            output.push(b"0123456789ABCDEF"[usize::from(b >> 4)]);
            output.push(b"0123456789ABCDEF"[usize::from(b & 15)]);
        }
    }
}

pub(super)fn field_reference_cost(value:&Value,control:&Arc<super::Control>)->RenderResult<Option<usize>>{request_url::field_reference_cost(value,control)}
