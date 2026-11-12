//! The async request owner reads bodies on demand; render workers own form parsing.
use super::{Control,Fields,RenderResult,arity,error,lock,string,text};
use gotmpl::{Object,Value,ValueFunc};
use std::{collections::BTreeMap,sync::{Arc,Mutex,OnceLock,Weak}};
use tokio::sync::{mpsc,oneshot};
type Values=Fields;
#[derive(Default)]struct State {form:Option<Arc<Values>>,post:Option<Arc<Values>>,multipart:Option<Arc<super::multipart::Parsed>>}
pub(crate) struct Form {
    method:String,query:String,content_type:String,state:Mutex<State>,
    sender:OnceLock<mpsc::UnboundedSender<ReadRequest>>,
    control:OnceLock<Weak<Control>>,
}
pub(crate) struct ReadRequest {pub reply:oneshot::Sender<RenderResult<BodyRead>>}
pub(crate) enum BodyRead {Bytes(Vec<u8>),Io(String),TooLarge}
impl Form {
    pub(crate) fn new(method:&str,query:&str,content_type:&str)->Arc<Self>{Arc::new(Self{method:method.into(),query:query.into(),content_type:content_type.into(),state:Mutex::new(State::default()),sender:OnceLock::new(),control:OnceLock::new()})}
    pub(super) fn set_control(&self,control:Arc<Control>){let _=self.control.set(Arc::downgrade(&control));}
    pub(crate) fn attach(&self)->RenderResult<mpsc::UnboundedReceiver<ReadRequest>>{
        let(tx,rx)=mpsc::unbounded_channel();self.sender.set(tx).map_err(|_|error("template body owner was already attached"))?;Ok(rx)
    }
    fn read(&self)->RenderResult<BodyRead>{
        let Some(sender)=self.sender.get()else{return Ok(BodyRead::Io("http: missing form body".into()));};
        let(reply,receiver)=oneshot::channel();sender.send(ReadRequest{reply}).map_err(|_|error("template body owner retired"))?;
        receiver.blocking_recv().map_err(|_|error("template body owner retired"))?
    }
    fn parse_form(&self,state:&mut State)->RenderResult<Option<String>>{
        // Go does not retain the first ParseForm error. Subsequent calls return nil.
        let mut failure=None;
        if state.post.is_none(){
            let mut post=Values::new();
            if matches!(self.method.as_str(),"POST"|"PUT"|"PATCH"){
                let parsed=super::media_type::parse(if self.content_type.is_empty(){"application/octet-stream"}else{&self.content_type});
                if parsed.error.as_deref().is_some_and(|e|e.starts_with("template ")){return Err(error(parsed.error.unwrap_or_default()));}
                failure=parsed.error;
                if parsed.media_type=="application/x-www-form-urlencoded"{
                    match self.read()?{
                        BodyRead::Bytes(bytes)=>{
                            let raw=std::str::from_utf8(&bytes).map_err(|_|error("form contains unrepresentable byte string"))?;
                            let(values,query_error)=parse_query(raw,self.control.get().and_then(Weak::upgrade).as_ref())?;post=values;if failure.is_none(){failure=query_error;}
                        }
                        BodyRead::Io(reason)=>{if failure.is_none(){failure=Some(reason);}}
                        BodyRead::TooLarge=>failure=Some("http: POST too large".into()),
                    }
                }
            }
            state.post=Some(Arc::new(post));
        }
        if state.form.is_none(){
            if let Some(control)=self.control.get().and_then(Weak::upgrade).as_ref(){control.reserve_host_bytes(state.post.as_ref().map_or(0,|values|values.len().saturating_mul(96)))?;}
            let mut form=state.post.as_ref().map(|values|values.as_ref().clone()).unwrap_or_default();let(query,query_error)=parse_query(&self.query,self.control.get().and_then(Weak::upgrade).as_ref())?;
            if failure.is_none(){failure=query_error;}append_values(&mut form,query)?;state.form=Some(Arc::new(form));
        }
        Ok(failure)
    }
    fn parse_multipart(&self,state:&mut State,max_memory:i64)->RenderResult<Option<String>>{
        let failure=if state.form.is_none(){self.parse_form(state)?}else{None};
        if state.multipart.is_some(){return Ok(None);}
        let parsed=super::media_type::parse(&self.content_type);
        if parsed.error.is_some()||parsed.media_type!="multipart/form-data"{return Ok(Some("request Content-Type isn't multipart/form-data".into()));}
        let boundary=parsed.params.as_ref().and_then(|params|params.get("boundary"));
        let Some(boundary)=boundary else{return Ok(Some("no multipart boundary param in Content-Type".into()));};
        let bytes=match self.read()?{BodyRead::Bytes(bytes)=>bytes,BodyRead::Io(message)=>return Ok(Some(message)),BodyRead::TooLarge=>return Ok(Some("multipart: message too large".into()))};
        let parsed=match super::multipart::read_form(&bytes,boundary,max_memory,self.control.get().and_then(Weak::upgrade).as_ref())?{Ok(parsed)=>parsed,Err(message)=>return Ok(Some(message))};
        let mut form=state.form.as_ref().map_or_else(Fields::new,|form|form.as_ref().clone());append_values(&mut form,parsed.values.as_ref().clone())?;state.form=Some(Arc::new(form));
        let mut post=state.post.as_ref().map_or_else(Fields::new,|post|post.as_ref().clone());append_values(&mut post,parsed.values.as_ref().clone())?;state.post=Some(Arc::new(post));
        state.multipart=Some(parsed);Ok(failure)
    }
    pub(super) fn signatures()->BTreeMap<Arc<str>,gotmpl::Signature>{BTreeMap::from([("ParseMultipartForm".into(),gotmpl::Signature::new(vec![gotmpl::ArgKind::Int64],None))])}
    pub(super) fn multipart_value(self:&Arc<Self>)->Value{
        let form=self.clone();let fields_form=self.clone();let remove_form=self.clone();
        Value::Object(Arc::new(Object{go_type:Some("*multipart.Form"),field_order:Some([Arc::from("Value"),Arc::from("File")].into()),fields:Fields::from([("Value".into(),Value::Nil),("File".into(),Value::Nil)]),nil_pointer:Some(Arc::new(move||lock(&form.state).is_ok_and(|state|state.multipart.is_none()))),dynamic_fields:Some(Arc::new(move|name|{
            let parsed=lock(&fields_form.state)?.multipart.clone().ok_or_else(||error("nil multipart form"))?;
            Ok(Some(match name{"Value"=>super::data::typed_map("map[string][]string",parsed.values.clone(),Value::List(Vec::new().into())),"File"=>super::multipart::files_value(&parsed)?,_=>return Ok(None)}))
        })),methods:BTreeMap::from([("RemoveAll".into(),Arc::new(move|args:&[Value]|{arity(args,0,0)?;let parsed=lock(&remove_form.state)?.multipart.clone().ok_or_else(||error("runtime error: invalid memory address or nil pointer dereference"))?;Ok(match parsed.disk.as_ref().map(|disk|disk.remove()).transpose(){Ok(_)=>Value::NilError,Err(reason)=>error_value(reason.to_string())})})as ValueFunc)]),..Object::default()}))
    }
    pub(super) fn methods(self:&Arc<Self>)->BTreeMap<Arc<str>,ValueFunc>{
        let mut methods=BTreeMap::new();
        for name in ["Form","PostForm","ParseForm","ParseMultipartForm","FormFile","FormValue","PostFormValue"]{
            let form=self.clone();methods.insert(name.into(),Arc::new(move|args:&[Value]|{
                if matches!(name,"Form"|"PostForm"){
                    arity(args,0,0)?;let post=name=="PostForm";let form=form.clone();
                    let nil_form=form.clone();
                    return Ok(super::data::values_dynamic(Arc::new(move||{
                        let state=lock(&form.state)?;let values=if post{&state.post}else{&state.form};Ok(values.clone().unwrap_or_else(||Arc::new(Fields::new())))
                    }),Arc::new(move||lock(&nil_form.state).is_ok_and(|state|if post{state.post.is_none()}else{state.form.is_none()}))));
                }
                if name=="FormFile"{return Err(error("invalid function signature for FormFile: expected one or two return values"));}
                if name=="ParseMultipartForm"{arity(args,1,1)?;let memory=args[0].as_go_signed().ok_or_else(||error("expected int64"))?;let mut state=lock(&form.state)?;return Ok(match form.parse_multipart(&mut state,memory)?{Some(message)=>error_value(message),None=>Value::NilError});}
                if name=="ParseForm"{arity(args,0,0)?;let mut state=lock(&form.state)?;return Ok(match form.parse_form(&mut state)?{Some(message)=>error_value(message),None=>Value::NilError});}
                arity(args,1,1)?;let key=text(args,0)?;let mut state=lock(&form.state)?;
                if if name=="FormValue"{state.form.is_none()}else{state.post.is_none()}{let _=form.parse_multipart(&mut state,32<<20)?;}
                let values=if name=="FormValue"{&state.form}else{&state.post};
                Ok(string(values.as_ref().and_then(|values|values.get(key)).and_then(|value|if let Value::List(values)=value{values.first()}else{None}).and_then(Value::as_str).unwrap_or_default()))
            })as ValueFunc);
        }
        methods
    }
}
pub(super) fn append_values(to:&mut Values,from:Values)->RenderResult<()>{
    for(key,values)in from{let current=to.entry(key).or_insert_with(||Value::List(Vec::new().into()));
        let(Value::List(old),Value::List(new))=(current,values)else{return Err(error("invalid form map state"));};
        if old.len()+new.len()>16_384{return Err(error("too many form values"));}let mut values=old.to_vec();values.extend(new.iter().cloned());*old=values.into();
    }
    if to.len()>16_384{return Err(error("too many form keys"));}Ok(())
}
fn escape_error(input:&str)->Option<String>{
    let bytes=input.as_bytes();for(i,byte)in bytes.iter().enumerate(){if *byte==b'%'&&(i+2>=bytes.len()||!bytes[i+1].is_ascii_hexdigit()||!bytes[i+2].is_ascii_hexdigit()){
        let end=(i+3).min(bytes.len());let bad=String::from_utf8_lossy(&bytes[i..end]);return Some(format!("invalid URL escape {}",serde_json::to_string(&bad).unwrap_or_default()));
    }}None
}
pub(super) fn parse_query(raw:&str,control:Option<&Arc<Control>>)->RenderResult<(Values,Option<String>)>{
    if raw.bytes().filter(|b|*b==b'&').count()+1>10_000{return Ok((Values::new(),Some("number of URL query parameters exceeded limit".into())));}
    let mut values=Values::new();let mut failure=None;
    for segment in raw.as_bytes().split(|b|*b==b'&').filter(|part|!part.is_empty()){
        if segment.contains(&b';'){failure=Some("invalid semicolon separator in query".into());continue;}
        let segment_text=std::str::from_utf8(segment).map_err(|_|error("form contains unrepresentable byte string"))?;
        let Some((key,value))=crate::http_runtime::query_match::query_pair(segment)else{if failure.is_none(){failure=escape_error(segment_text.split_once('=').map_or(segment_text,|(key,_)|key)).or_else(||escape_error(segment_text.split_once('=').map_or("",|(_,value)|value)));}continue;};
        let key=std::str::from_utf8(&key).map_err(|_|error("form key contains unrepresentable byte string"))?;let value=std::str::from_utf8(&value).map_err(|_|error("form value contains unrepresentable byte string"))?;
        if let Some(control)=control{control.charge(1)?;control.reserve_host_bytes(key.len()+value.len()+128)?;}
        let entry=values.entry(Arc::from(key)).or_insert_with(||Value::List(Vec::new().into()));
        if let Value::List(values)=entry{let mut next=values.to_vec();next.push(string(value));*values=next.into();}
    }
    Ok((values,failure))
}
pub(super) fn error_value(message:String)->Value{
    let display=message.clone();Value::Object(Arc::new(Object{display:Some(message.into()),go_type:Some("*errors.errorString"),methods:BTreeMap::from([("Error".into(),Arc::new(move|args:&[Value]|{arity(args,0,0)?;Ok(string(display.clone()))})as ValueFunc)]),..Object::default()}))
}
