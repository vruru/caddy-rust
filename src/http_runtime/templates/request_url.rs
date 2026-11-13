// Go 1.27.3 net/url behavior. Copyright 2009 The Go Authors (BSD-3-Clause).
//! Mutable URL state is private to the admitted render graph. Transport request
//! and TLS authentication facts are never modified through these views.
use super::super::Control;
use super::{RenderResult,arity,error};
use crate::http_runtime::http_redirect::url::{template_decode_bytes as decode,template_decode_host_bytes as decode_host,template_encode_path_bytes as escape_path,template_encode_user_bytes as escape_user,template_encode_host_bytes as escape_host};
use gotmpl::{Object,TypedSlice,Value,ValueFunc};
use std::{collections::BTreeMap,sync::{Arc,Weak,Mutex}};
#[path="request_url_core.rs"]mod core;
const FIELDS:[&str;11]=["Scheme","Opaque","User","Host","Path","Fragment","RawQuery","RawPath","RawFragment","ForceQuery","OmitHost"];
struct User{username:Vec<u8>,password:Option<Vec<u8>>}
#[derive(Clone)]struct Facts{scheme:Vec<u8>,opaque:Vec<u8>,host:Vec<u8>,path:Vec<u8>,fragment:Vec<u8>,raw_path:Vec<u8>,raw_fragment:Vec<u8>,query:Vec<u8>,force_query:bool,omit_host:bool,user:Option<Arc<User>>}
impl Facts{
 fn empty()->Self{Self{scheme:Vec::new(),opaque:Vec::new(),host:Vec::new(),path:Vec::new(),fragment:Vec::new(),raw_path:Vec::new(),raw_fragment:Vec::new(),query:Vec::new(),force_query:false,omit_host:false,user:None}}
 fn bytes(&self)->RenderResult<usize>{sum(&[self.scheme.len(),self.opaque.len(),self.host.len(),self.path.len(),self.fragment.len(),self.raw_path.len(),self.raw_fragment.len(),self.query.len(),self.user.as_ref().map_or(0,|u|u.username.len()+u.password.as_ref().map_or(0,Vec::len)),32])}
}
struct State{epoch:u64,facts:Arc<Facts>}
struct View{state:Mutex<State>,owner:Weak<Control>}
#[derive(Clone)]pub(super)struct Cache{slots:Arc<[Mutex<Option<Arc<View>>>;2]>}
pub(super)fn cache(control:&Arc<Control>)->RenderResult<Cache>{control.reserve_host_bytes(std::mem::size_of::<[Mutex<Option<Arc<View>>>;2]>()+64)?;Ok(Cache{slots:Arc::new([Mutex::new(None),Mutex::new(None)])})}
fn sum(parts:&[usize])->RenderResult<usize>{parts.iter().try_fold(0usize,|n,v|n.checked_add(*v)).ok_or_else(||error("request URL allocation size overflow"))}
fn prepay(control:&Arc<Control>,n:usize,factor:usize,fixed:usize)->RenderResult<()>{let peak=n.checked_mul(factor).and_then(|n|n.checked_add(fixed)).ok_or_else(||error("request URL allocation size overflow"))?;control.charge(n.div_ceil(64)+1)?;control.reserve_host_bytes(peak)}
fn live(weak:&Weak<Control>)->RenderResult<Arc<Control>>{let control=weak.upgrade().ok_or_else(||error("request URL owner retired"))?;control.check()?;Ok(control)}
fn owner(weak:&Weak<Control>,bytes:usize)->RenderResult<Arc<Control>>{let control=live(weak)?;prepay(&control,bytes,16,4096)?;Ok(control)}
impl View{
 fn snapshot(&self)->RenderResult<(u64,Arc<Facts>)>{let state=self.state.lock().map_err(|_|error("request URL state poisoned"))?;Ok((state.epoch,state.facts.clone()))}
 fn commit(&self,control:&Arc<Control>,epoch:u64,prepared:Arc<Facts>)->RenderResult<()>{
  if !self.owner.ptr_eq(&Arc::downgrade(control)){return Err(error("foreign request URL owner"));}control.check()?;
  let retired={let mut state=self.state.lock().map_err(|_|error("request URL state poisoned"))?;if state.epoch!=epoch{return Err(error("request URL version changed"));}let next=state.epoch.checked_add(1).ok_or_else(||error("request URL generation overflow"))?;control.check()?;let retired=std::mem::replace(&mut state.facts,prepared);state.epoch=next;retired};drop(retired);Ok(())
 }
 fn field(&self,name:&str)->RenderResult<Option<Value>>{let control=live(&self.owner)?;let(_,facts)=self.snapshot()?;prepay(&control,facts.bytes()?,8,4096)?;Ok(Some(match name{
  "Scheme"=>Value::from_go_bytes(facts.scheme.as_slice()),"Opaque"=>Value::from_go_bytes(facts.opaque.as_slice()),"User"=>user_value(facts.user.as_ref(),&self.owner)?,"Host"=>Value::from_go_bytes(facts.host.as_slice()),"Path"=>Value::from_go_bytes(facts.path.as_slice()),"Fragment"=>Value::from_go_bytes(facts.fragment.as_slice()),"RawQuery"=>Value::from_go_bytes(facts.query.as_slice()),"RawPath"=>Value::from_go_bytes(facts.raw_path.as_slice()),"RawFragment"=>Value::from_go_bytes(facts.raw_fragment.as_slice()),"ForceQuery"=>Value::Bool(facts.force_query),"OmitHost"=>Value::Bool(facts.omit_host),_=>return Ok(None)}))}
}
fn encoded_valid(bytes:&[u8],fragment:bool)->bool{bytes.iter().all(|b|b.is_ascii_alphanumeric()||b"-_.~$&+,/:;=@!\'()*[]%".contains(b)||(fragment&&*b==b'?'))}
fn escaped_path(facts:&Facts)->Vec<u8>{if !facts.raw_path.is_empty()&&encoded_valid(&facts.raw_path,false)&&decode(&facts.raw_path).is_ok_and(|path|path==facts.path){facts.raw_path.clone()}else if facts.path==b"*"{b"*".to_vec()}else{escape_path(&facts.path)}}
fn escape_fragment(bytes:&[u8])->Vec<u8>{let mut result=Vec::new();for b in bytes{if b.is_ascii_alphanumeric()||b"-_.~$&+,/:;=?@!()*".contains(b){result.push(*b);}else{result.push(b'%');result.push(b"0123456789ABCDEF"[usize::from(b>>4)]);result.push(b"0123456789ABCDEF"[usize::from(b&15)]);}}result}
fn escaped_fragment(facts:&Facts)->Vec<u8>{if !facts.raw_fragment.is_empty()&&encoded_valid(&facts.raw_fragment,true)&&decode(&facts.raw_fragment).is_ok_and(|fragment|fragment==facts.fragment){facts.raw_fragment.clone()}else{escape_fragment(&facts.fragment)}}
fn user_text(user:&User,redacted:bool)->Vec<u8>{let mut bytes=escape_user(&user.username);if let Some(password)=&user.password{bytes.push(b':');if redacted{bytes.extend_from_slice(b"xxxxx");}else{bytes.extend_from_slice(&escape_user(password));}}bytes}
fn string(facts:&Facts,redacted:bool)->Vec<u8>{
 let mut bytes=Vec::new();if !facts.scheme.is_empty(){bytes.extend_from_slice(&facts.scheme);bytes.push(b':');}
 if !facts.opaque.is_empty(){bytes.extend_from_slice(&facts.opaque);}else{
  if !facts.scheme.is_empty()||!facts.host.is_empty()||facts.user.is_some(){if !(facts.omit_host&&facts.host.is_empty()&&facts.user.is_none()){if !facts.host.is_empty()||!facts.path.is_empty()||facts.user.is_some(){bytes.extend_from_slice(b"//");}if let Some(user)=&facts.user{bytes.extend_from_slice(&user_text(user,redacted));bytes.push(b'@');}bytes.extend_from_slice(&escape_host(&facts.host));}}
  let path=escaped_path(facts);let path=if facts.omit_host&&facts.host.is_empty()&&facts.user.is_none()&&path.starts_with(b"//"){bytes.extend_from_slice(b"%2F");&path[1..]}else{&path[..]};
  if !path.is_empty()&&!path.starts_with(b"/")&&!facts.host.is_empty(){bytes.push(b'/');}if bytes.is_empty()&&path.split(|b|*b==b'/').next().is_some_and(|part|part.contains(&b':')){bytes.extend_from_slice(b"./");}bytes.extend_from_slice(path);
 }
 if facts.force_query||!facts.query.is_empty(){bytes.push(b'?');bytes.extend_from_slice(&facts.query);}if !facts.fragment.is_empty(){bytes.push(b'#');bytes.extend_from_slice(&escaped_fragment(facts));}bytes
}
fn request_uri(facts:&Facts)->Vec<u8>{let mut bytes=if !facts.opaque.is_empty(){let mut value=Vec::new();if facts.opaque.starts_with(b"//"){value.extend_from_slice(&facts.scheme);value.push(b':');}value.extend_from_slice(&facts.opaque);value}else{let mut value=escaped_path(facts);if value.is_empty(){value.push(b'/');}value};if facts.force_query||!facts.query.is_empty(){bytes.push(b'?');bytes.extend_from_slice(&facts.query);}bytes}
fn host_port(host:&[u8])->(&[u8],&[u8]){let(host,port)=host.iter().rposition(|b|*b==b':').filter(|i|host[i+1..].iter().all(u8::is_ascii_digit)).map_or((host,b"".as_slice()),|i|(&host[..i],&host[i+1..]));(if host.starts_with(b"[")&&host.ends_with(b"]"){&host[1..host.len()-1]}else{host},port)}
fn from_uri(uri:&http::Uri,origin:Option<&http::Uri>,origin_form:bool,control:&Arc<Control>,rewrite:Option<&crate::http_runtime::rewrite_runtime::Projection>)->RenderResult<Facts>{
 let origin=origin.unwrap_or(uri);
 let scheme=if origin_form{""}else{origin.scheme_str().unwrap_or("")};
 let authority=if origin_form{""}else{origin.authority().map_or("",|a|a.as_str())};
 let path=uri.path_and_query().map_or("",|p|p.raw_path());let query=uri.query().unwrap_or("");
 prepay(control,sum(&[scheme.len(),authority.len(),path.len(),query.len(),32])?,32,16384)?;
 let mut facts=Facts::empty();facts.scheme=scheme.as_bytes().iter().map(u8::to_ascii_lowercase).collect();core::authority(&mut facts,authority.as_bytes())?;
 if path=="*"&&scheme.is_empty()&&authority.is_empty()&&uri.query().is_none(){facts.path=b"*".to_vec();}else{core::set_path(&mut facts,path.as_bytes())?;}
 facts.query=query.as_bytes().to_vec();facts.force_query=uri.query()==Some("");if let Some(rewrite)=rewrite{let state=&rewrite.state;prepay(control,state.bytes(),8,1024)?;facts.path=state.path.clone();facts.raw_path=state.raw_path.clone();facts.query=state.query.clone();facts.fragment=state.fragment.clone();facts.force_query=state.force_query;}Ok(facts)
}
fn view(control:&Arc<Control>,facts:Facts)->Arc<View>{Arc::new(View{state:Mutex::new(State{epoch:0,facts:Arc::new(facts)}),owner:Arc::downgrade(control)})}
fn data(object:&Object)->RenderResult<&View>{object.data.as_ref().and_then(|v|v.downcast_ref::<View>()).ok_or_else(||error("invalid URL receiver"))}
fn dynamic_stringer(object:&Object)->RenderResult<Value>{let view=data(object)?;let control=live(&view.owner)?;let(_,facts)=view.snapshot()?;prepay(&control,facts.bytes()?,16,4096)?;Ok(Value::from_go_bytes(string(&facts,false)))}
fn bytes_arg(value:&Value)->RenderResult<TypedSlice>{match value{Value::Nil=>Ok(TypedSlice::nil("[]uint8")),Value::Slice(slice)=>slice.clone().into_plain_bytes(),_=>Err(error("URL method requires []uint8"))}}
fn string_arg(args:&[Value],i:usize)->RenderResult<&[u8]>{args.get(i).and_then(Value::as_go_bytes).ok_or_else(||error("URL method requires string argument"))}
fn method(view:&Arc<View>,name:&str,args:&[Value])->RenderResult<Value>{
 let control=live(&view.owner)?;let(epoch,facts)=view.snapshot()?;
 match name{
  "Parse"=>{arity(args,1,1)?;let raw=string_arg(args,0)?;prepay(&control,sum(&[facts.bytes()?,raw.len()])?,64,32768)?;let reference=core::parse(raw)?;let facts=core::resolve(&facts,&reference)?;control.check()?;make_object(self::view(&control,facts),&control)}
  "ResolveReference"=>{arity(args,1,1)?;if matches!(args[0],Value::Nil){return Err(error("nil URL reference"));}let Value::Object(object)=&args[0]else{return Err(error("URL reference requires *url.URL"));};let other=data(object)?;if !view.owner.ptr_eq(&other.owner){return Err(error("foreign URL reference owner"));}let(_,reference)=other.snapshot()?;prepay(&control,sum(&[facts.bytes()?,reference.bytes()?])?,64,32768)?;let facts=core::resolve(&facts,&reference)?;control.check()?;make_object(self::view(&control,facts),&control)}
  "JoinPath"=>{let n=args.iter().try_fold(facts.bytes()?,|n,v|sum(&[n,v.as_go_bytes().ok_or_else(||error("URL path element requires string"))?.len()]))?;prepay(&control,sum(&[n,args.len().checked_mul(64).ok_or_else(||error("URL path arguments overflow"))?])?,64,32768)?;let parts=args.iter().map(|v|v.as_go_bytes().unwrap()).collect::<Vec<_>>();let joined=core::join(&facts,&parts);control.check()?;make_object(self::view(&control,joined),&control)}
  "UnmarshalBinary"=>{arity(args,1,1)?;let input=bytes_arg(&args[0])?;prepay(&control,sum(&[facts.bytes()?,input.len()])?,64,32768)?;let bytes=input.visible_bytes();let raw=bytes.as_deref().unwrap_or_default();let prepared=Arc::new(core::parse(raw)?);view.commit(&control,epoch,prepared)?;Ok(Value::NilError)}
  "AppendBinary"=>{arity(args,1,1)?;let prefix=bytes_arg(&args[0])?;prepay(&control,sum(&[facts.bytes()?,prefix.byte_backing_len().ok_or_else(||error("invalid byte backing"))?])?,16,4096)?;let suffix=string(&facts,false);append(&control,prefix,&suffix)}
  _=>{arity(args,0,0)?;prepay(&control,facts.bytes()?,16,4096)?;Ok(match name{
   "String"|"Redacted"=>Value::from_go_bytes(string(&facts,name=="Redacted")),"RequestURI"=>Value::from_go_bytes(request_uri(&facts)),"EscapedPath"=>Value::from_go_bytes(escaped_path(&facts)),"EscapedFragment"=>Value::from_go_bytes(escaped_fragment(&facts)),"Hostname"=>Value::from_go_bytes(host_port(&facts.host).0),"Port"=>Value::from_go_bytes(host_port(&facts.host).1),"IsAbs"=>Value::Bool(!facts.scheme.is_empty()),"Query"=>return super::byte_values(&facts.query,&control),"MarshalBinary"=>return append(&control,TypedSlice::nil("[]uint8"),&string(&facts,false)),_=>return Err(error("unknown URL method"))})}
 }
}
fn append(control:&Arc<Control>,prefix:TypedSlice,suffix:&[u8])->RenderResult<Value>{
 let length=prefix.len().checked_add(suffix.len()).ok_or_else(||error("URL binary size overflow"))?;
 // Capacity rounding is supplied by the audited byte-slice growth primitive.
 let capacity=prefix.byte_append_capacity(suffix.len())?;prepay(control,sum(&[capacity,prefix.byte_backing_len().ok_or_else(||error("invalid byte backing"))?])?,2,512)?;
 if length<=prefix.cap(){let output=prefix.reslice(0,length)?;output.write_range(prefix.len(),suffix)?;return Ok(Value::Slice(output));}
 let old=prefix.visible_bytes();let mut bytes=Vec::with_capacity(capacity);if let Some(old)=old{bytes.extend_from_slice(&old);}bytes.extend_from_slice(suffix);bytes.resize(capacity,0);
 let weak=Arc::downgrade(control);Ok(Value::Slice(TypedSlice::bytes(Some(bytes.into())).with_len(length)?.with_host_budget(Arc::new(move|n|live(&weak)?.reserve_host_bytes(n)))))
}
impl gotmpl::FieldSource for View {fn read_field(&self,name:&'static str)->RenderResult<Value>{self.field(name)?.ok_or_else(||error("unknown URL field reference"))}}
fn make_object(view:Arc<View>,control:&Arc<Control>)->RenderResult<Value>{
 prepay(control,0,1,8192)?;let fields=FIELDS.into_iter().map(|name|(Arc::from(name),Value::Nil)).collect();let read=view.clone();let mut methods=BTreeMap::<Arc<str>,ValueFunc>::new();
 for name in ["String","Redacted","RequestURI","EscapedPath","EscapedFragment","Hostname","Port","IsAbs","Query","MarshalBinary","AppendBinary","UnmarshalBinary","Parse","JoinPath","ResolveReference"]{let view=view.clone();methods.insert(name.into(),Arc::new(move|args|method(&view,name,args)));}
 let method_signatures=BTreeMap::from([("Parse".into(),gotmpl::Signature::new(vec![gotmpl::ArgKind::String],None)),("JoinPath".into(),gotmpl::Signature::new(Vec::new(),Some(gotmpl::ArgKind::String))),("AppendBinary".into(),gotmpl::Signature::from_static(&[gotmpl::ArgKind::ByteSlice],None)),("UnmarshalBinary".into(),gotmpl::Signature::from_static(&[gotmpl::ArgKind::ByteSlice],None)),("ResolveReference".into(),gotmpl::Signature::from_static(&[gotmpl::ArgKind::GoPointer("*url.URL")],None))]);
 Ok(Value::Object(Arc::new(Object{fields,dynamic_fields:Some(Arc::new(move|name|{let Some(name)=FIELDS.into_iter().find(|field|*field==name)else{return Ok(None);};let control=live(&read.owner)?;control.reserve_host_bytes(std::mem::size_of::<gotmpl::FieldReference>()+64)?;let kind=match name{"ForceQuery"|"OmitHost"=>gotmpl::FieldKind::Bool,"User"=>gotmpl::FieldKind::Pointer("*url.Userinfo"),_=>gotmpl::FieldKind::String};Ok(Some(Value::Field(Arc::new(gotmpl::FieldReference::new(read.clone(),name,kind)))))})),methods,method_signatures,dynamic_stringer:Some(dynamic_stringer),go_type:Some("*url.URL"),pointer_identity:Some(Arc::as_ptr(&view)as usize),data_bytes:std::mem::size_of::<View>(),data:Some(view),field_order:Some(FIELDS.map(Arc::from).into()),..Object::default()})))
}
pub(super)fn value(uri:&http::Uri,control:&Arc<Control>)->RenderResult<Value>{make_object(view(control,from_uri(uri,None,false,control,None)?),control)}
pub(super)fn cached(uri:&http::Uri,origin:Option<&http::Uri>,origin_form:bool,control:&Arc<Control>,cache:&Cache,original:bool,rewrite:Option<&crate::http_runtime::rewrite_runtime::Projection>)->RenderResult<Value>{
 let owner=Arc::downgrade(control);let index=usize::from(original);let existing={let slot=cache.slots[index].lock().map_err(|_|error("request URL cache poisoned"))?;slot.as_ref().filter(|v|v.owner.ptr_eq(&owner)).cloned()};if let Some(view)=existing{return make_object(view,control);}
 let prepared=view(control,from_uri(uri,origin,origin_form,control,rewrite)?);let(result,retired)={let mut slot=cache.slots[index].lock().map_err(|_|error("request URL cache poisoned"))?;if let Some(existing)=slot.as_ref().filter(|v|v.owner.ptr_eq(&owner)){(existing.clone(),None)}else{let retired=slot.replace(prepared.clone());(prepared.clone(),retired)}};drop(retired);drop(prepared);make_object(result,control)
}

fn user_value(user: Option<&Arc<User>>, weak: &Weak<Control>) -> RenderResult<Value> {
    let mut methods = BTreeMap::<Arc<str>, ValueFunc>::new();
    for name in ["String", "Username", "Password"] {
        let user = user.cloned();
        let weak = weak.clone();
        methods.insert(
            name.into(),
            Arc::new(move |args| {
                arity(args, 0, 0)?;
                let bytes = user.as_ref().map_or(0, |u| {
                    u.username.len() + u.password.as_ref().map_or(0, Vec::len)
                });
                let _owner = owner(&weak, bytes)?;
                if name == "Password" {
                    return Err(error(
                        "invalid function signature: second return value is not error",
                    ));
                }
                Ok(Value::from_go_bytes(user.as_ref().map_or_else(
                    Vec::new,
                    |user| {
                        if name == "String" {
                            user_text(user, false)
                        } else {
                            user.username.clone()
                        }
                    },
                )))
            }),
        );
    }
    let display = String::from_utf8(user.map_or_else(Vec::new, |user| user_text(user, false)))
        .map_err(|_| error("request user encoding is not UTF-8"))?;
    Ok(Value::Object(Arc::new(Object {
        methods,
        display: Some(display.into()),
        reflected_fields:user.map(|user|Arc::from([
            (Arc::from("username"),Value::from_go_bytes(user.username.as_slice())),
            (Arc::from("password"),Value::from_go_bytes(user.password.as_deref().unwrap_or_default())),
            (Arc::from("passwordSet"),Value::Bool(user.password.is_some())),
        ])),
        go_type: Some("*url.Userinfo"),
        nil_pointer: user
            .is_none()
            .then(|| Arc::new(|| true) as Arc<dyn Fn() -> bool + Send + Sync>),
        pointer_identity: user.map(|u| Arc::as_ptr(u) as usize),
        data: user.map(|u| u.clone() as Arc<dyn std::any::Any + Send + Sync>),
        ..Object::default()
    })))
}
fn cache_view(cache:&Cache,control:&Arc<Control>,original:bool)->RenderResult<Option<Arc<View>>>{let owner=Arc::downgrade(control);let slot=cache.slots[usize::from(original)].lock().map_err(|_|error("request URL cache poisoned"))?;Ok(slot.as_ref().filter(|view|view.owner.ptr_eq(&owner)).cloned())}
pub(super)fn query_source(cache:&Cache,control:&Arc<Control>)->RenderResult<Arc<dyn Fn()->RenderResult<Vec<u8>>+Send+Sync>>{
 control.reserve_host_bytes(128)?;let view=cache_view(cache,control,false)?.ok_or_else(||error("request URL query source missing"))?;let weak=Arc::downgrade(&view);
 Ok(Arc::new(move||{let view=weak.upgrade().ok_or_else(||error("request URL query source retired"))?;let control=live(&view.owner)?;let(_,facts)=view.snapshot()?;prepay(&control,facts.query.len(),4,128)?;Ok(facts.query.clone())}))
}
pub(super)fn placeholder(cache:&Cache,control:&Arc<Control>,name:&str)->RenderResult<Option<Value>>{
 let(original,suffix)=if let Some(s)=name.strip_prefix("http.request.orig_uri"){(true,s)}else if let Some(s)=name.strip_prefix("http.request.uri"){(false,s)}else{return Ok(None)};
 if original&&(suffix.is_empty()||suffix.starts_with(".query.")){return Ok(None);}
 if !matches!(suffix,""|".path"|".query"|".prefixed_query")&&!suffix.starts_with(".query."){return Ok(None);}
 let Some(view)=cache_view(cache,control,original)?else{return Ok(None);};let(_,facts)=view.snapshot()?;prepay(control,facts.bytes()?,16,4096)?;
 let bytes=match suffix{
  ""=>request_uri(&facts),".path"=>facts.path.clone(),".query"=>facts.query.clone(),".prefixed_query"=>{let mut bytes=Vec::new();if !facts.query.is_empty(){bytes.push(b'?');bytes.extend_from_slice(&facts.query);}bytes},
  _=>{let key=suffix.strip_prefix(".query.").unwrap().as_bytes();let mut bytes=Vec::new();let mut first=true;for(index,pair)in facts.query.split(|b|*b==b'&').filter(|p|!p.is_empty()).enumerate(){if index>=16384{return Err(error("URL query placeholder entry limit exceeded"));}control.charge(1)?;if let Some((name,value))=crate::http_runtime::query_match::query_pair(pair){if name.as_ref()==key{if !first{bytes.push(b',');}first=false;bytes.extend_from_slice(&value);}}}bytes}
 };Ok(Some(Value::from_go_bytes(bytes)))
}

// Only real URL sources belonging to this render Control may cross the closed
// Frame observer gate. A named Go type alone is never host provenance.
pub(super)fn field_reference_cost(value:&Value,control:&Arc<Control>)->RenderResult<Option<usize>>{
 let Value::Field(reference)=value else{return Ok(None);};
 let source=reference.source::<View>().ok_or_else(||error("unregistered request field reference source"))?;
 if !source.owner.ptr_eq(&Arc::downgrade(control)){return Err(error("foreign request field reference owner"));}
 control.check()?;Ok(Some(0))
}
