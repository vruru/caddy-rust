//! http.Header.Clone is a method, not a missing map-key lookup. MIMEHeader
//! deliberately keeps its separate method set in the multipart adapter.
use super::{arity,error,lock,header_with_protocol,string,text};
use gotmpl::Value;
use http::{HeaderMap,HeaderName,HeaderValue};
use std::sync::{Arc,Mutex,Weak};

fn cost(headers:&HeaderMap,protocol:Option<&str>)->gotmpl::Result<usize>{
    // Include retained table capacity, not just current logical field bytes.
    // This named host-copy allowance is not a whole-process heap bound.
    let mut bytes=headers.capacity().checked_mul(256).and_then(|n|n.checked_add(4096))
        .ok_or_else(||error("header clone size overflow"))?;
    for (name,value) in headers {
        bytes=bytes.checked_add(name.as_str().len()).and_then(|n|n.checked_add(value.as_bytes().len().checked_mul(2)?))
            .and_then(|n|n.checked_add(256)).ok_or_else(||error("header clone size overflow"))?;
    }
    bytes.checked_add(protocol.map_or(0,|p|p.len())).ok_or_else(||error("header clone size overflow"))
}

pub(super) fn value(headers:Arc<Mutex<HeaderMap>>,writable:bool,protocol:Option<Arc<str>>,nil:bool,
    control:&Arc<super::super::Control>)->gotmpl::Result<Value>{
    control.reserve_host_bytes(4096)?;
    let mut result=header_with_protocol(headers.clone(),writable,protocol.clone());
    let Value::Object(object)=&mut result else{return Err(error("header object missing"));};
    let object=Arc::get_mut(object).ok_or_else(||error("header object unexpectedly shared"))?;
    object.map_view.as_mut().ok_or_else(||error("header map view missing"))?.is_nil=Arc::new(move||nil);
    if writable {
        for operation in ["Set","Add","Del"] {
            let headers=headers.clone();let owner=Arc::downgrade(control);
            object.methods.insert(operation.into(),Arc::new(move|args|{
                let count=if operation=="Del"{1}else{2};arity(args,count,count)?;
                let control=owner.upgrade().ok_or_else(||error("response header owner retired"))?;
                control.check()?;
                let key=text(args,0)?;
                let raw=if operation=="Del"{b"".as_slice()}else{args[1].as_go_bytes().ok_or_else(||error("template host requires string argument"))?};
                let charge=key.len().checked_add(raw.len()).and_then(|n|n.checked_mul(3)).and_then(|n|n.checked_add(512))
                    .ok_or_else(||error("response header mutation size overflow"))?;
                control.reserve_host_bytes(charge)?;
                let field=match HeaderName::from_bytes(key.as_bytes()) {
                    Ok(field)=>field,
                    Err(_)if operation=="Del"=>return Ok(string("")),
                    Err(_)=>return Err(error("invalid template response header name")),
                };
                let value=if operation=="Del"{None}else{Some(HeaderValue::from_bytes(raw).map_err(|_|error("invalid template response header value"))?)};
                let mut current=lock(&headers)?;
                if let Some(value)=value {
                    let mut size=0usize;
                    for (name,entry) in current.iter() {
                        if operation=="Set"&&name==field {continue;}
                        size=size.checked_add(64+name.as_str().len()+entry.as_bytes().len())
                            .ok_or_else(||error("response header size overflow"))?;
                    }
                    size=size.checked_add(64+field.as_str().len()+value.as_bytes().len()).ok_or_else(||error("response header size overflow"))?;
                    if size>super::super::super::RESPONSE_HEADERS_LIMIT {return Err(error("template response headers exceed limit"));}
                    if operation=="Set"{current.insert(field,value);}else{current.append(field,value);}
                } else {current.remove(field);}
                Ok(string(""))
            }));
        }
    }
    let owner:Weak<super::super::Control>=Arc::downgrade(control);
    object.methods.insert("Clone".into(),Arc::new(move|args|{
        arity(args,0,0)?;
        let control=owner.upgrade().ok_or_else(||error("header clone owner retired"))?;
        control.check()?;
        let needed={let current=lock(&headers)?;cost(&current,protocol.as_deref())?};
        // Control callbacks run without the header mutex. A racing host change
        // must fit this exact prepaid shape; it cannot allocate first and pay
        // afterwards or report an empty successful clone on resource failure.
        control.reserve_host_bytes(needed)?;
        let copied={let current=lock(&headers)?;
            if cost(&current,protocol.as_deref())?>needed{return Err(error("header changed during clone admission"));}
            current.clone()
        };
        value(Arc::new(Mutex::new(copied)),false,protocol.clone(),nil,&control)
    }));
    Ok(result)
}
