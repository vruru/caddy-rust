//! An exact final entity length takes precedence over a stale writer header.
//! HEAD representations and bodyless statuses retain their existing semantics.
use http::{HeaderMap,HeaderValue,StatusCode,header};
pub(super) fn apply(headers:&mut HeaderMap,status:StatusCode,is_head:bool,is_connect:bool,exact:Option<u64>){
    if is_head||(is_connect&&status.is_success())||status.is_informational()||matches!(status,StatusCode::NO_CONTENT|StatusCode::NOT_MODIFIED){return;}
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
