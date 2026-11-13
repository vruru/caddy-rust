//! http.Header.Clone is a method, not a missing map-key lookup. MIMEHeader
//! deliberately keeps its separate method set in the multipart adapter.
use super::{arity,error,lock,header_with_protocol};
use gotmpl::Value;
use http::HeaderMap;
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
