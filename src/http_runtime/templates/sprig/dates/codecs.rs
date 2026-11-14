//! Go 1.27.3 time wire codecs, with checked timestamp validity and signed
//! second-resolution offsets. Failed decoding commits no receiver mutation.
use super::*;
const EPOCH:i64=62_135_596_800;
fn decoded_zone(seconds:i64,offset:i32)->Zone{
    if crate::http_config::helpers::local_zone_info(seconds).is_some_and(|(local,_)|local==offset){Zone::Local}else{fixed_zone(offset,String::new())}
}
pub(super)fn decode_binary(data:&[u8])->gotmpl::Result<Time>{
    let Some(version)=data.first().copied()else{return Err(err("Time.UnmarshalBinary: no data"))};
    let expected=match version{1=>15,2=>16,_=>return Err(err("Time.UnmarshalBinary: unsupported version"))};
    if data.len()!=expected{return Err(err("Time.UnmarshalBinary: invalid length"))}
    let seconds=i64::from_be_bytes(data[1..9].try_into().map_err(|_|err("invalid time seconds"))?).checked_sub(EPOCH).ok_or_else(||err("Time.UnmarshalBinary: seconds overflow"))?;
    let nanosecond=u32::from_be_bytes(data[9..13].try_into().map_err(|_|err("invalid time nanoseconds"))?);
    if nanosecond>=1_000_000_000{return Err(err("Time.UnmarshalBinary: invalid nanoseconds"))}
    let minutes=i16::from_be_bytes([data[13],data[14]]);
    let remainder=if version==2{i32::from(data[15]as i8)}else{0};
    if !(-59..=59).contains(&remainder){return Err(err("Time.UnmarshalBinary: invalid offset seconds"))}
    let zone=if minutes== -1&&remainder==0{Zone::Utc}else{decoded_zone(seconds,i32::from(minutes)*60+remainder)};
    Ok(Time{stamp:Timestamp{seconds,nanosecond},zone,monotonic:None})
}
pub(super)fn decode_text(data:&[u8])->gotmpl::Result<Time>{
    if data.len()>128{return Err(err("parsing time as RFC3339 failed"))}
    let text=std::str::from_utf8(data).map_err(|_|err("parsing time as RFC3339 failed"))?;
    let parsed=Layout::compile("2006-01-02T15:04:05.999999999Z07:00").map_err(|e|err(e.to_string()))?.parse_time(text,false).ok_or_else(||err("parsing time as RFC3339 failed"))?;
    let components=time_components::at(parsed.timestamp,parsed.offset,parsed.zone.clone()).map_err(|e|err(e.to_string()))?;
    if !(0..=9999).contains(&components.year)||parsed.timestamp.nanosecond>=1_000_000_000{return Err(err("parsing time as RFC3339 failed"))}
    let zone=if text.ends_with('Z'){Zone::Utc}else{decoded_zone(parsed.timestamp.seconds,parsed.offset)};
    Ok(Time{stamp:parsed.timestamp,zone,monotonic:None})
}
pub(super)fn decode_json(data:&[u8])->gotmpl::Result<Option<Time>>{
    if data==b"null"{return Ok(None)}
    if data.len()<2||data.first()!=Some(&b'"')||data.last()!=Some(&b'"'){return Err(err("Time.UnmarshalJSON: input is not a JSON string"))}
    // Go passes the quoted payload directly to its RFC3339 decoder; JSON
    // backslash escapes are not an alternate timestamp spelling.
    decode_text(&data[1..data.len()-1]).map(Some)
}
