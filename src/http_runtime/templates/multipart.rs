//! Bounded Go mime/multipart behavioral port. Parsing and file IO stay on the renderer worker.
use super::{Control,Fields,RenderResult,error,lock,string};
use http::{HeaderMap,header};
use std::{collections::BTreeMap,io::Write,sync::{Arc,Mutex}};
#[path="multipart_headers.rs"] mod mime_headers;
pub(super) struct Disk {pub path:std::path::PathBuf,temporary:Mutex<Option<tempfile::TempPath>>}
impl Disk{
    pub(super) fn remove(&self)->std::io::Result<()>{
        let temp=self.temporary.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take();
        if let Some(temp)=temp{match temp.close(){Err(error)if error.kind()!=std::io::ErrorKind::NotFound=>return Err(error),_=>{}}}Ok(())
    }
}
pub(super) enum Backing {Memory(Arc<[u8]>),Disk{disk:Arc<Disk>,offset:u64,shared:bool}}
pub(super) struct FileHeader {pub filename:String,pub header:HeaderMap,pub size:i64,pub backing:Backing,cached:Mutex<std::sync::Weak<gotmpl::Object>>}
pub(super) struct Parsed {pub values:Arc<Fields>,pub files:BTreeMap<Arc<str>,Vec<Arc<FileHeader>>>,pub disk:Option<Arc<Disk>>}
struct Part {headers:HeaderMap,name:String,filename:String,bytes:Vec<u8>}
fn line<'a>(body:&'a[u8],cursor:&mut usize)->&'a[u8]{let start=*cursor;let end=body[start..].iter().position(|b|*b==b'\n').map_or(body.len(),|n|start+n+1);*cursor=end;&body[start..end]}
fn lws(bytes:&[u8])->&[u8]{let start=bytes.iter().position(|b|!matches!(b,b' '|b'\t')).unwrap_or(bytes.len());&bytes[start..]}
fn boundary_line(line:&[u8],boundary:&[u8],newline:&[u8])->Option<bool>{
    let rest=line.strip_prefix(boundary)?;
    if let Some(rest)=rest.strip_prefix(b"--"){let rest=lws(rest);if rest.is_empty()||rest==newline{return Some(true);}}
    if lws(rest)==newline{return Some(false);}None
}
fn qp(bytes:&[u8])->Result<Vec<u8>,String>{
    let mut out=Vec::with_capacity(bytes.len());let mut i=0;
    while i<bytes.len(){
        if bytes[i]!=b'='{out.push(bytes[i]);i+=1;continue;}
        if bytes.get(i+1)==Some(&b'\n'){i+=2;continue;}
        if bytes.get(i+1..i+3)==Some(b"\r\n"){i+=3;continue;}
        let hex=|c:u8|match c{b'0'..=b'9'=>Some(c-b'0'),b'a'..=b'f'=>Some(c-b'a'+10),b'A'..=b'F'=>Some(c-b'A'+10),_=>None};
        if let(Some(a),Some(b))=(bytes.get(i+1).and_then(|b|hex(*b)),bytes.get(i+2).and_then(|b|hex(*b))){out.push(a*16+b);i+=3;}
        else{return Err("unexpected EOF".into());}
    }Ok(out)
}
fn parts(body:&[u8],boundary:&str,control:Option<&Arc<Control>>)->RenderResult<Result<Vec<Part>,String>>{
    if boundary.is_empty(){return Ok(Err("multipart: boundary is empty".into()));}
    let delimiter=[b"--".as_slice(),boundary.as_bytes()].concat();let mut cursor=0;let mut newline=b"\r\n".as_slice();let mut found=false;
    while cursor<body.len(){let next=line(body,&mut cursor);if boundary_line(next,&delimiter,newline)==Some(true){return Ok(Ok(Vec::new()));}
        if boundary_line(next,&delimiter,newline)==Some(false){found=true;break;}
        if boundary_line(next,&delimiter,b"\n")==Some(false){newline=b"\n";found=true;break;}
    }
    if !found{return Ok(Err("multipart: NextPart: EOF".into()));}
    let mut output=Vec::new();
    loop{
        if let Some(control)=control{control.charge(1)?;}
        if output.len()>=1000{return Ok(Err("multipart: message too large".into()));}
        let mut headers=match mime_headers::headers(body,&mut cursor){Ok(headers)=>headers,Err(message)=>return Ok(Err(message))};
        let start=cursor;let mut scan=start;let mut next_boundary=None;
        while scan<body.len(){
            // Go also accepts a boundary at the beginning of an empty part body.
            let prefix=if scan==start&&body[scan..].starts_with(&delimiter){Some(scan)}else if body[scan..].starts_with(newline){Some(scan+newline.len())}else{None};
            if let Some(position)=prefix{
                if body[position..].starts_with(&delimiter){let mut end=position;let next=line(body,&mut end);if let Some(final_boundary)=boundary_line(next,&delimiter,newline){next_boundary=Some((scan,end,final_boundary));break;}}
            }
            scan+=1;
        }
        let Some((end,next,final_boundary))=next_boundary else{return Ok(Err("unexpected EOF".into()));};cursor=next;
        let mut bytes=body[start..end].to_vec();
        if headers.get("Content-Transfer-Encoding").is_some_and(|value|value.as_bytes().eq_ignore_ascii_case(b"quoted-printable")){
            headers.remove("Content-Transfer-Encoding");bytes=match qp(&bytes){Ok(bytes)=>bytes,Err(message)=>return Ok(Err(message))};
        }
        let disposition=super::media_type::parse(headers.get(header::CONTENT_DISPOSITION).and_then(|value|value.to_str().ok()).unwrap_or_default());
        let mut name=String::new();let mut filename=String::new();
        if disposition.error.is_none()&&disposition.media_type=="form-data"{if let Some(params)=disposition.params{name=params.get("name").cloned().unwrap_or_default();filename=params.get("filename").map(|name|std::path::Path::new(name).file_name().map_or_else(||name.clone(),|name|name.to_string_lossy().into_owned())).unwrap_or_default();}}
        if let Some(control)=control{control.reserve_host_bytes(bytes.len()+name.len()+filename.len()+headers.iter().map(|(key,value)|key.as_str().len()+value.as_bytes().len()+96).sum::<usize>()+192)?;}
        output.push(Part{headers,name,filename,bytes});if final_boundary{break;}
    }Ok(Ok(output))
}
pub(super) fn read_form(body:&[u8],boundary:&str,max_memory:i64,control:Option<&Arc<Control>>)->RenderResult<Result<Arc<Parsed>,String>>{
    if let Some(control)=control{control.reserve_host_bytes(body.len().saturating_mul(16))?;}
    let parts=match parts(body,boundary,control)?{Ok(parts)=>parts,Err(message)=>return Ok(Err(message))};
    let mut max_file=max_memory.max(0);if max_file==i64::MAX{max_file-=1;}
    let mut memory=max_memory.max(0).checked_add(10<<20).unwrap_or(i64::MAX);
    let mut headers_remaining=10_000usize;let mut values=Fields::new();let mut files:BTreeMap<Arc<str>,Vec<(String,HeaderMap,i64,Option<Arc<[u8]>>,u64)>>=BTreeMap::new();
    let mut disk_file:Option<tempfile::NamedTempFile>=None;let mut disk_count=0;let mut disk_offset=0u64;
    for part in parts{
        if part.name.is_empty(){continue;}
        memory=memory.saturating_sub(part.name.len()as i64+200);
        if part.filename.is_empty(){
            memory=memory.saturating_sub(part.bytes.len()as i64);if memory<0{return Ok(Err("multipart: message too large".into()));}
            let text=std::str::from_utf8(&part.bytes).map_err(|_|error("multipart value contains unrepresentable byte string"))?;
            super::forms::append_values(&mut values,Fields::from([(part.name.into(),gotmpl::Value::List(vec![string(text)].into()))]))?;continue;
        }
        let header_size=400+part.headers.keys().map(|key|key.as_str().len()+200+part.headers.get_all(key).iter().map(|value|value.as_bytes().len()).sum::<usize>()).sum::<usize>();
        memory=memory.saturating_sub((header_size+200+100)as i64);if memory<0||part.headers.len()>headers_remaining{return Ok(Err("multipart: message too large".into()));}headers_remaining-=part.headers.len();
        let size=part.bytes.len()as i64;let(offset,content)=if size>max_file{
            if disk_file.is_none(){disk_file=Some(tempfile::Builder::new().prefix("multipart-").tempfile().map_err(|_|error("creating multipart temporary file failed"))?);}
            if let Some(file)=disk_file.as_mut(){file.write_all(&part.bytes).map_err(|_|error("writing multipart temporary file failed"))?;}
            disk_count+=1;let offset=disk_offset;disk_offset=disk_offset.saturating_add(size as u64);(offset,None)
        }else{max_file-=size;memory-=size;if memory<0{return Ok(Err("multipart: message too large".into()));}(0,Some(Arc::from(part.bytes)))};
        files.entry(part.name.into()).or_default().push((part.filename,part.headers,size,content,offset));
    }
    let disk=disk_file.map(|file|{let path=file.path().to_owned();Arc::new(Disk{path,temporary:Mutex::new(Some(file.into_temp_path()))})});
    let mut parsed=BTreeMap::new();
    for(key,entries)in files{let mut headers=Vec::new();for(filename,header,size,content,offset)in entries{
        let backing=match content{Some(content)=>Backing::Memory(content),None=>Backing::Disk{disk:disk.as_ref().ok_or_else(||error("multipart disk storage absent"))?.clone(),offset,shared:disk_count>1}};
        headers.push(Arc::new(FileHeader{filename,header,size,backing,cached:Mutex::new(std::sync::Weak::new())}));
    }parsed.insert(key,headers);}
    Ok(Ok(Arc::new(Parsed{values:Arc::new(values),files:parsed,disk})))
}

pub(super) fn files_value(parsed:&Parsed)->RenderResult<gotmpl::Value>{
    let mut files=Fields::new();
    for(key,entries)in &parsed.files{let values=entries.iter().map(file_header_value).collect::<RenderResult<Vec<_>>>()?;files.insert(key.clone(),gotmpl::Value::List(values.into()));}
    Ok(super::data::typed_map("map[string][]*multipart.FileHeader",Arc::new(files),gotmpl::Value::List(Vec::new().into())))
}
fn file_header_value(header:&Arc<FileHeader>)->RenderResult<gotmpl::Value>{
    use gotmpl::{Object,Value,ValueFunc};
    let mut cached=lock(&header.cached)?;if let Some(value)=cached.upgrade(){return Ok(Value::Object(value));}
    let captured=header.clone();let mut headers=super::data::header_value(Arc::new(Mutex::new(header.header.clone())),false);
    if let Value::Object(object)=&mut headers{if let Some(object)=Arc::get_mut(object){if let Some(map)=object.map_view.as_mut(){map.type_name="textproto.MIMEHeader";}}}
    let object=Arc::new(Object{go_type:Some("*multipart.FileHeader"),field_order:Some(["Filename","Header","Size"].map(Arc::from).into()),fields:Fields::from([("Filename".into(),string(header.filename.clone())),("Header".into(),headers),("Size".into(),Value::Int64(header.size))]),methods:BTreeMap::from([("Open".into(),Arc::new(move|args:&[Value]|{super::arity(args,0,0)?;open_value(&captured)})as ValueFunc)]),..Object::default()});
    *cached=Arc::downgrade(&object);Ok(Value::Object(object))
}
struct FileHandle {position:i64,size:i64,closed:bool,file:Option<std::fs::File>,path:Option<std::path::PathBuf>,_memory:Option<Arc<[u8]>>,_offset:u64,is_disk:bool}
fn open_value(header:&Arc<FileHeader>)->RenderResult<gotmpl::Value>{
    use gotmpl::{Object,Value,ValueFunc};
    let(file,path,is_file,memory,offset)=match &header.backing{
        Backing::Memory(bytes)=>(None,None,false,Some(bytes.clone()),0),
        Backing::Disk{disk,shared,offset}=>{let file=std::fs::File::open(&disk.path).map_err(|e|error(format!("open {}: {e}",disk.path.display())))?;(Some(file),Some(disk.path.clone()),!*shared,None,*offset)}
    };
    let data_bytes=256+memory.as_ref().map_or(0,|bytes|bytes.len());
    let state=Arc::new(Mutex::new(FileHandle{position:0,size:header.size,closed:false,is_disk:file.is_some(),file,path,_memory:memory,_offset:offset}));
    let mut methods=BTreeMap::<Arc<str>,ValueFunc>::new();
    for name in ["Close","Seek","Read","ReadAt","WriteTo","Outer"]{let state=state.clone();methods.insert(name.into(),Arc::new(move|args|{
        if name=="Outer"{return Err(error("invalid function signature for Outer: expected one or two return values"));}
        let mut handle=lock(&state)?;
        if name=="Close"{super::arity(args,0,0)?;if !handle.is_disk{return Ok(Value::NilError);}if handle.closed{return Ok(path_error("close",&handle,"file already closed"));}handle.closed=true;handle.file=None;return Ok(Value::NilError);}
        if is_file&&handle.closed{return Err(error("file already closed"));}
        match name{
            "Seek"=>{super::arity(args,2,2)?;let offset=args[0].as_go_signed().ok_or_else(||error("expected int64 offset"))?;let whence=args[1].as_int().ok_or_else(||error("expected int whence"))?;
                let base=match whence{0=>0,1=>handle.position,2=>handle.size,_=>return Err(error("Seek: invalid whence"))};let position=base.checked_add(offset).filter(|n|*n>=0).ok_or_else(||error("Seek: invalid offset"))?;handle.position=position;Ok(Value::Int64(position))},
            "Read"=>{super::arity(args,1,1)?;if !matches!(args[0],Value::Nil|Value::NilError){return Err(error("expected []uint8 buffer"));}if handle.is_disk&&handle.closed{return Err(error("file already closed"));}if !is_file&&handle.position>=handle.size{return Err(error("EOF"));}Ok(Value::Int(0))},
            "ReadAt"=>{super::arity(args,2,2)?;if !matches!(args[0],Value::Nil|Value::NilError){return Err(error("expected []uint8 buffer"));}let offset=args[1].as_go_signed().ok_or_else(||error("expected int64 offset"))?;if offset<0||offset>=handle.size{return Err(error("EOF"));}Ok(Value::Int(0))},
            _=>Err(error("expected io.Writer")),
        }
    }));}
    if is_file{
        for name in ["Name","Stat","WriteString","Sync"]{let state=state.clone();methods.insert(name.into(),Arc::new(move|args|{
            let handle=lock(&state)?;if name=="Name"{super::arity(args,0,0)?;return Ok(string(handle.path.as_ref().map_or(String::new(),|p|p.to_string_lossy().into_owned())));}
            if handle.closed{if name=="Sync"{return Ok(path_error("sync",&handle,"file already closed"));}return Err(error("file already closed"));}
            match name{
                "Stat"=>{super::arity(args,0,0)?;let metadata=handle.file.as_ref().ok_or_else(||error("file already closed"))?.metadata().map_err(|e|error(e.to_string()))?;super::data::metadata_info(handle.path.as_deref().unwrap_or_else(||std::path::Path::new("")),metadata)},
                "WriteString"=>{super::arity(args,1,1)?;let _=super::text(args,0)?;Err(error("bad file descriptor"))},
                _=>{super::arity(args,0,0)?;Ok(Value::NilError)},
            }
        }));}
    }else{
        let size=header.size;methods.insert("Size".into(),Arc::new(move|args|{super::arity(args,0,0)?;Ok(Value::Int64(size))}));
    }
    let method_signatures=BTreeMap::from([("Seek".into(),gotmpl::Signature::new(vec![gotmpl::ArgKind::Int64,gotmpl::ArgKind::Int],None)),("ReadAt".into(),gotmpl::Signature::new(vec![gotmpl::ArgKind::Any,gotmpl::ArgKind::Int64],None))]);
    Ok(Value::Object(Arc::new(Object{go_type:Some(if is_file{"*os.File"}else{"multipart.sectionReadCloser"}),methods,method_signatures,equal:if is_file{None}else{Some(reader_equal)},data:Some(Arc::new(state)),data_bytes,..Object::default()})))
}

fn path_error(operation:&str,handle:&FileHandle,message:&str)->gotmpl::Value{
    use gotmpl::{Object,Value,ValueFunc};
    let path=handle.path.as_ref().map_or(String::new(),|path|path.to_string_lossy().into_owned());
    let text=format!("{operation} {path}: {message}");let error_text=text.clone();let inner=super::forms::error_value(message.into());let cause=inner.clone();
    Value::Object(Arc::new(Object{go_type:Some("*fs.PathError"),display:Some(text.into()),fields:Fields::from([("Op".into(),string(operation)),("Path".into(),string(path)),("Err".into(),inner)]),methods:BTreeMap::from([("Error".into(),Arc::new(move|args:&[Value]|{super::arity(args,0,0)?;Ok(string(error_text.clone()))})as ValueFunc),("Unwrap".into(),Arc::new(move|args:&[Value]|{super::arity(args,0,0)?;Ok(cause.clone())})as ValueFunc)]),..Object::default()}))
}

fn reader_equal(a:&gotmpl::Object,b:&gotmpl::Object)->bool{
    let(Some(a),Some(b))=(a.host_data::<Arc<Mutex<FileHandle>>>("multipart.sectionReadCloser"),b.host_data::<Arc<Mutex<FileHandle>>>("multipart.sectionReadCloser"))else{return false;};Arc::ptr_eq(a,b)
}
