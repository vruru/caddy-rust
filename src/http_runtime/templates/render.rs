//! Per-render template namespaces. Files and host functions execute only on the
//! template worker; namespaces and header locks never span template execution.
#[path = "sprig.rs"]
mod sprig;
#[path = "data.rs"]
mod data;
#[path="go_url.rs"]
mod go_url;
#[path="forms.rs"]
pub(super) mod forms;
#[path="media_type.rs"]
mod media_type;
#[path="to_string.rs"]
mod to_string;
#[path="multipart.rs"]
mod multipart;
#[path = "rich.rs"]
pub(crate) mod rich;
pub(crate) use data::RequestData;
use super::{TemplateFailure,TemplatePlan};
use gotmpl::{MapContext,MissingKey,Object,Template,TemplateError,Value,ValueFunc};
use http::{HeaderMap,StatusCode,header};
use std::{collections::BTreeMap,io::Read,path::{Component,Path,PathBuf},sync::{Arc,Mutex,atomic::{AtomicU16,AtomicUsize,Ordering}},time::{Duration,Instant}};
use tokio_util::sync::CancellationToken;
type Fields=BTreeMap<Arc<str>,Value>;
type RenderResult<T>=gotmpl::Result<T>;
pub(super) type VirtualInclude=Arc<dyn Fn(&str,Arc<Control>)->RenderResult<Vec<u8>>+Send+Sync>;
pub(crate) struct Control {
    pub cancel:CancellationToken,
    deadline:Instant,
    work:AtomicUsize,
    source:AtomicUsize,
    allocation:AtomicUsize,
    allocation_limit:usize,
    files:AtomicUsize,
    http_calls:AtomicUsize,
    status:AtomicU16,
    maps:MapContext,
    value_limit:usize,output_limit:usize,
}
fn error(message:impl Into<String>)->TemplateError{TemplateError::Exec(message.into())}
impl Control {
    pub(crate) fn new(cancel:CancellationToken)->Arc<Self>{Arc::new(Self{cancel,deadline:Instant::now()+Duration::from_secs(30),work:AtomicUsize::new(1_000_000),source:AtomicUsize::new(4<<20),allocation:AtomicUsize::new(64<<20),allocation_limit:64<<20,files:AtomicUsize::new(256),http_calls:AtomicUsize::new(64),status:AtomicU16::new(0),maps:MapContext::new(),value_limit:1<<20,output_limit:1<<20})}
    /// The browse caller already owns its existing 32 MiB listing work permit.
    /// Charge host graph construction here before allocating nodes/strings.
    pub(crate) fn for_browse(cancel:CancellationToken)->Arc<Self>{
        Arc::new(Self{cancel,deadline:Instant::now()+Duration::from_secs(30),work:AtomicUsize::new(1_000_000),source:AtomicUsize::new(4<<20),allocation:AtomicUsize::new(32<<20),allocation_limit:32<<20,files:AtomicUsize::new(256),http_calls:AtomicUsize::new(64),status:AtomicU16::new(0),maps:MapContext::new(),value_limit:8<<20,output_limit:8<<20})
    }
    pub(crate) fn reserve_host_bytes(&self,bytes:usize)->RenderResult<()>{self.charge_bytes(bytes)}
    /// Bridge to the same pool; no secondary allowance is created. Adapter
    /// metadata is charged before its four fixed-size Weak captures allocate.
    pub(crate) fn allocation_meter(self:&Arc<Self>)->RenderResult<Arc<gotmpl::BudgetMeter>>{
        self.charge_bytes(256)?;
        let(check,work,reserve,refund)=(Arc::downgrade(self),Arc::downgrade(self),Arc::downgrade(self),Arc::downgrade(self));
        Ok(Arc::new(gotmpl::BudgetMeter::new(
            move||check.upgrade().ok_or_else(||error("template control retired"))?.check(),
            move|units|work.upgrade().ok_or_else(||error("template control retired"))?.charge(units),
            move|bytes|reserve.upgrade().ok_or_else(||error("template control retired"))?.charge_bytes(bytes),
            move|bytes|{if let Some(control)=refund.upgrade(){let _=control.allocation.try_update(Ordering::AcqRel,Ordering::Acquire,|left|left.checked_add(bytes).filter(|left|*left<=control.allocation_limit));}}
        )))
    }

    fn take(counter:&AtomicUsize,units:usize)->RenderResult<()> {counter.try_update(Ordering::AcqRel,Ordering::Acquire,|n|n.checked_sub(units)).map(|_|()).map_err(|_|error("template aggregate budget exhausted"))}
    pub(super) fn deadline(&self)->Instant{self.deadline}
    pub(super) fn check(&self)->RenderResult<()> {if self.cancel.is_cancelled()||Instant::now()>self.deadline{Err(error("template execution cancelled or timed out"))}else{Ok(())}}
    pub(super) fn charge(&self,units:usize)->RenderResult<()> {self.check()?;Self::take(&self.work,units)}
    fn source(&self,length:usize)->RenderResult<()> {self.charge(1+length.div_ceil(64))?;Self::take(&self.source,length)?;Self::take(&self.allocation,length.checked_mul(32).ok_or_else(||error("template source overflow"))?)}
    pub(super) fn charge_bytes(&self,length:usize)->RenderResult<()> {self.check()?;Self::take(&self.allocation,length)}
    pub(super) fn http_call(&self)->RenderResult<()> {self.check()?;Self::take(&self.http_calls,1)}
    fn failure(&self)->TemplateFailure{TemplateFailure(StatusCode::from_u16(self.status.load(Ordering::Acquire)).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR))}
}
struct Frame {
    plan:Arc<TemplatePlan>,root:PathBuf,request:Arc<RequestData>,headers:Arc<Mutex<HeaderMap>>,
    control:Arc<Control>,namespace:Mutex<Option<Template>>,args:gotmpl::TypedSlice,depth:usize,
    virtual_include:Option<VirtualInclude>,extra:Fields,
}
fn lock<T>(mutex:&Mutex<T>)->RenderResult<std::sync::MutexGuard<'_,T>>{mutex.lock().map_err(|_|error("template state lock poisoned"))}
fn string(value:impl Into<Arc<str>>)->Value{Value::String(value.into())}
fn arity(args:&[Value],min:usize,max:usize)->RenderResult<()>{if(min..=max).contains(&args.len()){Ok(())}else{Err(error("incorrect template host argument count"))}}
fn text(args:&[Value],index:usize)->RenderResult<&str>{args.get(index).and_then(Value::as_str).ok_or_else(||error("template host requires string argument"))}

/// The middleware uses the current URL path as name. Browse passes the custom
/// template basename and its actual listing fields. Included files deliberately
/// receive only the inner TemplateContext, just like the Go embedded context.
pub(crate) fn execute_named(plan:&Arc<TemplatePlan>,root:PathBuf,request:RequestData,headers:&mut HeaderMap,name:&str,input:Vec<u8>,control:Arc<Control>,virtual_include:Option<VirtualInclude>,extra:Fields)->Result<Vec<u8>,TemplateFailure>{
    let response_headers=Arc::new(Mutex::new(headers.clone()));
    let frame=Frame::new(plan.clone(),root,Arc::new(request),response_headers.clone(),control.clone(),gotmpl::TypedSlice::nil("[]interface {}"),0,virtual_include,extra);
    let result=frame.and_then(|frame|frame.render(name,input));
    if let Ok(rendered_headers)=response_headers.lock(){*headers=rendered_headers.clone();}
    result.map_err(|_|control.failure())
}
pub(super) fn execute(plan:&Arc<TemplatePlan>,root:PathBuf,request:RequestData,headers:&mut HeaderMap,input:Vec<u8>,cancel:CancellationToken)->Result<Vec<u8>,TemplateFailure>{
    let name=request.uri.path().to_owned();execute_named(plan,root,request,headers,&name,input,Control::new(cancel),None,Fields::new())
}
impl Frame {
    fn new(plan:Arc<TemplatePlan>,root:PathBuf,request:Arc<RequestData>,headers:Arc<Mutex<HeaderMap>>,control:Arc<Control>,args:gotmpl::TypedSlice,depth:usize,virtual_include:Option<VirtualInclude>,extra:Fields)->RenderResult<Arc<Self>>{
        control.check()?;request.form.set_control(control.clone());
        if plan.delimiters.iter().any(|s|s.is_empty()||s.len()>128){return Err(error("invalid effective template delimiters"));}
        if depth>32{return Err(error("template include depth exceeded"));}
        Ok(Arc::new(Self{plan,root,request,headers,control,namespace:Mutex::new(None),args,depth,virtual_include,extra}))
    }
    fn template(self:&Arc<Self>,name:&str)->Template {
        let control=self.control.clone();
        let mut functions=sprig::functions_with_maps(&self.control.maps);
        let derive=functions.remove("derivePassword");
        let mut template=Template::new(name).byte_limits(self.control.value_limit,self.control.output_limit).missing_key(MissingKey::ZeroValue).max_range_iters(100_000)
            .delims(&self.plan.delimiters[0],&self.plan.delimiters[1])
            .with_execution_charge(Arc::new(move|units|control.charge(units)))
            .funcs(functions).function_signatures(sprig::signatures());
        let control=self.control.clone();
        if let Some(original)=derive {
            template=template.func("derivePassword",move|args|{control.charge_bytes(32<<20)?;original(args)});
        }
        for name in ["include","readFile","import","httpInclude","fileExists","fileStat","listFiles","placeholder","ph","httpError","maybe","stripHTML","pathEscape","markdown","splitFrontMatter","humanize"] {
            let weak=Arc::downgrade(self);template=template.func(name,move|args|weak.upgrade().ok_or_else(||error("template context retired"))?.host(name,args));
        }
        template
    }
    fn render(self:&Arc<Self>,name:&str,input:Vec<u8>)->RenderResult<Vec<u8>> {
        self.control.source(input.len())?;
        if !input.windows(self.plan.delimiters[0].len()).any(|part|part==self.plan.delimiters[0].as_bytes()) {return Ok(input);}
        let template=self.template(name).parse_bytes(&input)?;
        *lock(&self.namespace)?=Some(template.clone());
        let weak=Arc::downgrade(self);
        let template=template.with_definition_lookup_go(Arc::new(move|name|{
            let frame=weak.upgrade().ok_or_else(||error("template namespace retired"))?;
            let namespace=lock(&frame.namespace)?;
            Ok(namespace.as_ref().and_then(|template|template.lookup_shared_bytes(name.as_bytes())))
        }));
        let data=self.context()?;
        let output=template.execute_to_bytes(&data)?;self.control.charge_bytes(output.len())?;Ok(output)
    }
    fn context(&self)->RenderResult<Value> {
        let mut fields=self.extra.clone();
        fields.insert("Req".into(),self.request.value(false,&self.control)?);
        fields.insert("OriginalReq".into(),self.request.value(true,&self.control)?);
        fields.insert("Args".into(),Value::Slice(self.args.clone()));
        fields.insert("RespHeader".into(),data::response_header(self.headers.clone()));
        let mut methods=BTreeMap::<Arc<str>,ValueFunc>::new();
        for name in ["Cookie","Host","RemoteIP","ClientIP"] {
            let request=self.request.clone();methods.insert(name.into(),Arc::new(move|args|request.method(name,args)));
        }
        Ok(Value::Object(Arc::new(Object{fields,methods,..Object::default()})))
    }
    fn path(&self,name:&str)->RenderResult<PathBuf>{
        if name.contains('\0'){return Err(error("invalid template file path"));}
        let mut relative=PathBuf::new();for component in Path::new(name).components(){match component {Component::Normal(part)=>relative.push(part),Component::ParentDir=>{relative.pop();},Component::CurDir|Component::RootDir=>{},_=>return Err(error("unsupported template file path")),}}
        Ok(self.root.join(relative))
    }
    fn read(&self,name:&str)->RenderResult<Vec<u8>>{
        self.control.check()?;Control::take(&self.control.files,1)?;
        let path=self.path(name)?;
        let file=crate::http_config::helpers::open_regular_file(path).map_err(|_|error("opening template file failed"))?;
        let metadata=file.metadata().map_err(|_|error("template file metadata failed"))?;
        if metadata.len()>1<<20{return Err(error("template file exceeds byte limit"));}
        self.control.charge_bytes((metadata.len() as usize).saturating_add(1))?;
        let mut bytes=Vec::with_capacity(metadata.len() as usize);
        file.take((1<<20)+1).read_to_end(&mut bytes).map_err(|_|error("reading template file failed"))?;
        if bytes.len()>1<<20{return Err(error("template file exceeds byte limit"));}Ok(bytes)
    }
    fn host(self:&Arc<Self>,name:&str,args:&[Value])->RenderResult<Value>{
        self.control.charge(1)?;
        match name {
            "readFile"=>{arity(args,1,1)?;let bytes=self.read(text(args,0)?)?;Ok(Value::from_go_bytes(bytes))}
            "include"=>{
                arity(args,1,usize::MAX)?;let name=text(args,0)?;let input=self.read(name)?;
                self.control.charge_bytes(args.len().checked_mul(std::mem::size_of::<Value>()).and_then(|n|n.checked_add(128)).ok_or_else(||error("template arguments overflow"))?)?;
                let child=Self::new(self.plan.clone(),self.root.clone(),self.request.clone(),self.headers.clone(),self.control.clone(),gotmpl::TypedSlice::from_list(args[1..].to_vec().into()),self.depth+1,self.virtual_include.clone(),Fields::new())?;
                Ok(Value::from_go_bytes(child.render(name,input)?))
            }
            "import"=>{
                arity(args,1,1)?;let bytes=self.read(text(args,0)?)?;self.control.source(bytes.len())?;
                let mut namespace=lock(&self.namespace)?;
                let candidate=namespace.as_ref().ok_or_else(||error("template namespace absent"))?.clone().parse_bytes(&bytes)?;
                *namespace=Some(candidate);Ok(string(""))
            }
            "httpInclude"=>{
                arity(args,1,1)?;self.control.http_call()?;let uri=text(args,0)?;
                let include=self.virtual_include.as_ref().ok_or_else(||error("virtual template server unavailable"))?;
                let bytes=include(uri,self.control.clone())?;
                let child=Self::new(self.plan.clone(),self.root.clone(),self.request.clone(),self.headers.clone(),self.control.clone(),self.args.clone(),self.depth+1,self.virtual_include.clone(),Fields::new())?;
                Ok(Value::from_go_bytes(child.render(uri,bytes)?))
            }
            "placeholder"|"ph"=>{arity(args,1,1)?;self.request.placeholder(text(args,0)?,&self.control)}
            "fileExists"=>{arity(args,1,1)?;Control::take(&self.control.files,1)?;let path=self.path(text(args,0)?)?;Ok(Value::Bool(std::fs::File::open(path).is_ok()))}
            "fileStat"=>{arity(args,1,1)?;Control::take(&self.control.files,1)?;let path=self.path(text(args,0)?)?;data::file_info(&path)}
            "listFiles"=>{
                arity(args,1,1)?;Control::take(&self.control.files,1)?;let directory=std::fs::read_dir(self.path(text(args,0)?)?).map_err(|_|error("reading template directory failed"))?;
                use std::os::unix::ffi::OsStrExt;
                let mut names=Vec::new();
                for entry in directory {
                    if names.len()>=16_384{return Err(error("template directory exceeds entry limit"));}
                    let entry=entry.map_err(|_|error("reading directory entry failed"))?;
                    let name=entry.file_name();let bytes=name.as_os_str().as_bytes();
                    self.control.reserve_host_bytes(bytes.len().checked_add(128+2*std::mem::size_of::<Value>()).ok_or_else(||error("template filename size overflow"))?)?;
                    names.push(Value::from_go_bytes(Arc::<[u8]>::from(bytes)));
                }
                Ok(Value::Slice(gotmpl::TypedSlice::values("[]string",Some(names.into()))?))
            }
            "httpError"=>{
                arity(args,1,1)?;let status=args[0].as_int().and_then(|n|u16::try_from(n).ok()).and_then(|n|StatusCode::from_u16(n).ok()).ok_or_else(||error("invalid template HTTP error status"))?;
                let mut headers=lock(&self.headers)?;for field in [header::CONTENT_LENGTH,header::CONTENT_TYPE,header::ETAG,header::LAST_MODIFIED,header::ACCEPT_RANGES]{headers.remove(field);}
                self.control.status.store(status.as_u16(),Ordering::Release);Err(error("template HTTP error"))
            }
            "maybe"=>{arity(args,1,usize::MAX)?;let _=text(args,0)?;Ok(string(""))}
            "markdown"=>{
                arity(args,1,1)?;
                let meter=self.control.allocation_meter()?;
                if let Some(input)=args[0].as_go_bytes(){rich::markdown(input,meter)}
                else{let input=to_string::bytes(&args[0],meter.clone())?;rich::markdown(input.as_bytes(),meter)}
            }
            "splitFrontMatter"=>{arity(args,1,1)?;rich::front_matter(&gotmpl::go_sprint_bytes(args,false)?,&self.control.maps,self.control.allocation_meter()?)}
            "humanize"=>rich::humanize(args),
            "pathEscape"=>{arity(args,1,1)?;Ok(string(data::path_escape(text(args,0)?)))}
            "stripHTML"=>{arity(args,1,1)?;Ok(string(data::strip_html(text(args,0)?)))}
            _=>Err(error("unknown template host function")),
        }
    }
}

/// Shared text/template host value for directory-listing timestamps.
pub(crate) fn value_time(time:std::time::SystemTime)->gotmpl::Result<Value>{sprig::dates::system_time(time)}

/// Fixed process metadata is prepared before accepting template requests.
pub(crate) fn prepare_metadata()->gotmpl::Result<()>{sprig::dates::prepare_metadata();let _=rich::chroma::prepare()?;Ok(())}
