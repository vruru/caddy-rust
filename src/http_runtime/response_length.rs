//! An exact final entity length takes precedence over a stale writer header.
//! Bodyless protocol responses cannot carry framing lengths. HEAD and 304
//! lengths describe a representation, so an empty transmitted body proves none.
use http::{HeaderMap,HeaderValue,StatusCode,header};
pub(super) fn apply(headers:&mut HeaderMap,status:StatusCode,is_head:bool,is_connect:bool,exact:Option<u64>){
    if (is_connect&&status.is_success())||status.is_informational()||status==StatusCode::NO_CONTENT {
        headers.remove(header::CONTENT_LENGTH);
        headers.remove(header::TRANSFER_ENCODING);
        return;
    }
    if status==StatusCode::NOT_MODIFIED {
        // This generic finalizer has no selected-200 representation length.
        // Omit the optional field rather than infer it from a bodyless 304.
        headers.remove(header::CONTENT_LENGTH);
        headers.remove(header::TRANSFER_ENCODING);
        return;
    }
    if is_head{return;}
    let Some(actual)=exact else{return;};
    let values=headers.get_all(header::CONTENT_LENGTH);let mut values=values.iter();
    let fix=match values.next(){
        None=>false,
        Some(value)=>{
            let bytes=value.as_bytes();
            let valid=!bytes.is_empty()&&bytes.iter().all(u8::is_ascii_digit)&&std::str::from_utf8(bytes).ok().and_then(|value|value.parse::<u64>().ok())==Some(actual);
            !valid||values.next().is_some()
        }
    };
    if fix{headers.insert(header::CONTENT_LENGTH,HeaderValue::from(actual));}
}
