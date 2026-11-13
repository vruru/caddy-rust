use super::*;
use crate::logging::{Timestamp,time_components,time_layout::Layout};
use chrono::{TimeZone,Offset};
#[derive(Clone)]
enum Zone {Utc,Local,Named(Arc<str>),Fixed(Arc<(i32,String)>)}
#[derive(Clone)]
struct Time {stamp:Timestamp,zone:Zone,monotonic:Option<i128>}
fn now()->Time{let now=chrono::Utc::now();Time{stamp:Timestamp{seconds:now.timestamp(),nanosecond:now.timestamp_subsec_nanos()},zone:Zone::Local,monotonic:Some(crate::http_config::helpers::process_elapsed().as_nanos()as i128)}}
fn zone_info(zone:&Zone,seconds:i64)->(i32,String){match zone{
    Zone::Utc=>(0,"UTC".into()),
    Zone::Fixed(value)=>(value.0,value.1.clone()),
    Zone::Local=>crate::http_config::helpers::local_zone_info(seconds).unwrap_or((0,"UTC".into())),
    Zone::Named(name)=>name.parse::<chrono_tz::Tz>().ok().and_then(|zone|zone.timestamp_opt(seconds,0).single()).map(|time|(time.offset().fix().local_minus_utc(),time.format("%Z").to_string())).unwrap_or((0,"UTC".into())),
}}
fn zone(name:&str)->Zone{if name=="Local"{Zone::Local}else if name=="UTC"||name.is_empty(){Zone::Utc}else if name.parse::<chrono_tz::Tz>().is_ok(){Zone::Named(name.into())}else{Zone::Utc}}
fn fixed_zone(offset:i32,name:String)->Zone{
    if name.is_empty()&&offset%3600==0&&(-12..=14).contains(&(offset/3600)){
        static ZONES:std::sync::LazyLock<Vec<Arc<(i32,String)>>>=std::sync::LazyLock::new(||(-12..=14).map(|hour|Arc::new((hour*3600,String::new()))).collect());
        Zone::Fixed(ZONES[(offset/3600+12)as usize].clone())
    }else{Zone::Fixed(Arc::new((offset,name)))}
}
fn location_name(zone:&Zone)->&str{match zone{Zone::Utc=>"UTC",Zone::Local=>"Local",Zone::Named(name)=>name,Zone::Fixed(value)=>&value.1}}
fn format(time:&Time,layout:&str)->gotmpl::Result<String>{
    let(offset,zone)=zone_info(&time.zone,time.stamp.seconds);
    let components=time_components::at(time.stamp,offset,zone).map_err(|e|err(e.to_string()))?;
    Layout::compile(layout).and_then(|layout|layout.format(&components,MAX_BYTES)).map_err(|e|err(e.to_string()))
}
fn extract(value:&V)->gotmpl::Result<Time>{
    let V::Object(object)=value else{return Err(err("expected time.Time"));};
    object.host_data::<Time>("time.Time").cloned().ok_or_else(||err("expected time.Time"))
}
fn date_input(value:&V)->Time{match value{
    V::Int(seconds)|V::Int64(seconds)=>Time{stamp:Timestamp{seconds:*seconds,nanosecond:0},zone:Zone::Local,monotonic:None},
    V::Object(object)if object.go_type==Some("time.Time")=>extract(value).unwrap_or_else(|_|now()),_=>now(),
}}
fn add(time:&Time,nanos:i64)->gotmpl::Result<Time>{
    let total=i128::from(time.stamp.seconds)*1_000_000_000+i128::from(time.stamp.nanosecond)+i128::from(nanos);
    let seconds=i64::try_from(total.div_euclid(1_000_000_000)).map_err(|_|err("time addition exceeds signed seconds"))?;
    let monotonic=time.monotonic.and_then(|mono|{let next=mono+i128::from(nanos);((-2_682_288_000..=5_907_646_591).contains(&seconds)&&i64::try_from(next).is_ok()).then_some(next)});
    Ok(Time{stamp:Timestamp{seconds,nanosecond:total.rem_euclid(1_000_000_000)as u32},zone:time.zone.clone(),monotonic})
}
fn time_equal(a:&gotmpl::Object,b:&gotmpl::Object)->bool {
    let(Some(a),Some(b))=(a.host_data::<Time>("time.Time"),b.host_data::<Time>("time.Time"))else{return false;};
    let location=match(&a.zone,&b.zone){(Zone::Utc,Zone::Utc)|(Zone::Local,Zone::Local)=>true,(Zone::Named(a),Zone::Named(b))=>Arc::ptr_eq(a,b),(Zone::Fixed(a),Zone::Fixed(b))=>Arc::ptr_eq(a,b),_=>false};
    location&&a.stamp.seconds==b.stamp.seconds&&a.stamp.nanosecond==b.stamp.nanosecond&&a.monotonic==b.monotonic
}
fn time_deep_equal(a:&gotmpl::Object,b:&gotmpl::Object)->bool{
    let(Some(a),Some(b))=(a.host_data::<Time>("time.Time"),b.host_data::<Time>("time.Time"))else{return false;};
    let location=match(&a.zone,&b.zone){(Zone::Utc,Zone::Utc)|(Zone::Local,Zone::Local)=>true,(Zone::Named(a),Zone::Named(b))=>a==b,(Zone::Fixed(a),Zone::Fixed(b))=>a==b,_=>false};
    location&&a.stamp.seconds==b.stamp.seconds&&a.stamp.nanosecond==b.stamp.nanosecond&&a.monotonic==b.monotonic
}
fn time_key_order(a:&gotmpl::Object,b:&gotmpl::Object)->gotmpl::Result<std::cmp::Ordering>{
    let(a,b)=(a.host_data::<Time>("time.Time").ok_or_else(||err("invalid time key"))?,b.host_data::<Time>("time.Time").ok_or_else(||err("invalid time key"))?);
    fn location(zone:&Zone)->(u8,usize){match zone{Zone::Utc=>(0,0),Zone::Local=>(1,0),Zone::Named(name)=>(2,name.as_ptr()as usize),Zone::Fixed(value)=>(3,Arc::as_ptr(value)as usize)}}
    Ok((a.stamp.nanosecond,a.stamp.seconds,location(&a.zone)).cmp(&(b.stamp.nanosecond,b.stamp.seconds,location(&b.zone))))
}
#[derive(Clone,Copy)]
pub(crate) struct YamlTimeParts {stamp:Timestamp,offset:i32,utc:bool,numeric_zone:bool}
pub(crate) const YAML_TIME_PARSE_SCRATCH:usize=4096;
pub(crate) const YAML_TIME_BUILD_SCRATCH:usize=4096;
const YAML_TIME_MAX_TEXT:usize=128;
pub(crate) fn yaml_time_retained_bound()->usize{std::mem::size_of::<gotmpl::Object>()+std::mem::size_of::<Time>()+8*std::mem::size_of::<usize>()+2*YAML_TIME_MAX_TEXT+64}
pub(crate) fn parse_yaml_timestamp(input:&str)->gotmpl::Result<Option<YamlTimeParts>>{
    if input.as_bytes().get(4)!=Some(&b'-')||!input.as_bytes()[..4.min(input.len())].iter().all(u8::is_ascii_digit){return Ok(None);}
    for layout in ["2006-1-2T15:4:5.999999999Z07:00","2006-1-2t15:4:5.999999999Z07:00","2006-1-2 15:4:5.999999999","2006-1-2"]{
        let Some(parsed)=Layout::compile(layout).map_err(|e|err(e.to_string()))?.parse_time(input,false)else{continue;};
        let numeric_zone=input.len()>=6&&matches!(input.as_bytes()[input.len()-6],b'+'|b'-')&&input.as_bytes()[input.len()-3]==b':';
        return Ok(Some(YamlTimeParts{stamp:parsed.timestamp,offset:parsed.offset,utc:parsed.zone=="UTC",numeric_zone}));
    }Ok(None)
}
pub(crate) fn yaml_time_value(parts:YamlTimeParts)->R{
    let zone=if parts.utc||!parts.numeric_zone{Zone::Utc}else if crate::http_config::helpers::local_zone_info(parts.stamp.seconds).is_some_and(|(offset,_)|offset==parts.offset){Zone::Local}else{fixed_zone(parts.offset,String::new())};
    time_value(Time{stamp:parts.stamp,zone,monotonic:None})
}
pub(crate) fn yaml_timestamp(input:&str)->gotmpl::Result<Option<V>>{parse_yaml_timestamp(input)?.map(yaml_time_value).transpose()}
pub(crate) fn yaml_time_retained(value:&V)->gotmpl::Result<usize>{
    let V::Object(object)=value else{return Err(err("invalid YAML timestamp object"));};
    let time=object.host_data::<Time>("time.Time").ok_or_else(||err("invalid YAML timestamp payload"))?;
    let mut bytes=std::mem::size_of::<gotmpl::Object>()+std::mem::size_of::<Time>()+4*std::mem::size_of::<usize>();
    if let Some(display)=&object.display{if display.len()>YAML_TIME_MAX_TEXT{return Err(err("YAML timestamp display exceeds precharged layout"));}bytes+=display.len()+2*std::mem::size_of::<usize>();}
    if let Some(json)=&object.json{let text=match json{Ok(text)|Err(text)=>text};if text.len()>YAML_TIME_MAX_TEXT{return Err(err("YAML timestamp JSON exceeds precharged layout"));}bytes+=text.len()+2*std::mem::size_of::<usize>();}
    bytes+=match &time.zone{Zone::Fixed(value)=>std::mem::size_of::<(i32,String)>()+2*std::mem::size_of::<usize>()+value.1.capacity(),Zone::Named(name)=>name.len()+2*std::mem::size_of::<usize>(),_=>0};
    Ok(bytes)
}
pub(crate) fn prepare_metadata(){let _=fixed_zone(0,String::new());let _=duration_kind();let _=calendar_type(false);let _=calendar_type(true);}
fn month_name(value:i64)->String{["January","February","March","April","May","June","July","August","September","October","November","December"].get(value.wrapping_sub(1)as usize).map(|s|(*s).into()).unwrap_or_else(||format!("%!Month({value})"))}
fn weekday_name(value:i64)->String{["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"].get(value as usize).map(|s|(*s).into()).unwrap_or_else(||format!("%!Weekday({value})"))}
fn calendar_type(weekday:bool)->Arc<gotmpl::Int64Type>{
    fn make(weekday:bool)->Arc<gotmpl::Int64Type>{let stringer=if weekday{weekday_name}else{month_name};Arc::new(gotmpl::Int64Type{name:if weekday{"time.Weekday"}else{"time.Month"},kind:"int",stringer:Some(stringer),methods:BTreeMap::from([("String".into(),Arc::new(move|value,args:&[V]|{arity(args,0,0)?;output(stringer(value))})as gotmpl::Int64Method)]),signatures:BTreeMap::new()})}
    static MONTH:std::sync::LazyLock<Arc<gotmpl::Int64Type>>=std::sync::LazyLock::new(||make(false));static WEEKDAY:std::sync::LazyLock<Arc<gotmpl::Int64Type>>=std::sync::LazyLock::new(||make(true));if weekday{WEEKDAY.clone()}else{MONTH.clone()}
}
fn calendar_value(value:i64,weekday:bool)->V{V::NamedInt64(value,calendar_type(weekday))}
static DURATION_SIG: gotmpl::Signature = gotmpl::Signature::from_static(
    &[gotmpl::ArgKind::NamedInt64("time.Duration", duration_value)],
    None,
);

static TIME_TYPE: gotmpl::HostType = gotmpl::HostType {
    methods: &[
        gotmpl::HostMethod { name: "String", invoke: |o, a| time_call("String", o, a), signature: None },
        gotmpl::HostMethod { name: "MarshalText", invoke: |o, a| time_call("MarshalText", o, a), signature: None },
        gotmpl::HostMethod { name: "Unix", invoke: |o, a| time_call("Unix", o, a), signature: None },
        gotmpl::HostMethod { name: "UnixMilli", invoke: |o, a| time_call("UnixMilli", o, a), signature: None },
        gotmpl::HostMethod { name: "UnixMicro", invoke: |o, a| time_call("UnixMicro", o, a), signature: None },
        gotmpl::HostMethod { name: "UnixNano", invoke: |o, a| time_call("UnixNano", o, a), signature: None },
        gotmpl::HostMethod { name: "Nanosecond", invoke: |o, a| time_call("Nanosecond", o, a), signature: None },
        gotmpl::HostMethod { name: "Year", invoke: |o, a| time_call("Year", o, a), signature: None },
        gotmpl::HostMethod { name: "Month", invoke: |o, a| time_call("Month", o, a), signature: None },
        gotmpl::HostMethod { name: "Day", invoke: |o, a| time_call("Day", o, a), signature: None },
        gotmpl::HostMethod { name: "YearDay", invoke: |o, a| time_call("YearDay", o, a), signature: None },
        gotmpl::HostMethod { name: "Weekday", invoke: |o, a| time_call("Weekday", o, a), signature: None },
        gotmpl::HostMethod { name: "Hour", invoke: |o, a| time_call("Hour", o, a), signature: None },
        gotmpl::HostMethod { name: "Minute", invoke: |o, a| time_call("Minute", o, a), signature: None },
        gotmpl::HostMethod { name: "Second", invoke: |o, a| time_call("Second", o, a), signature: None },
        gotmpl::HostMethod { name: "IsZero", invoke: |o, a| time_call("IsZero", o, a), signature: None },
        gotmpl::HostMethod { name: "Format", invoke: |o, a| time_call("Format", o, a), signature: None },
        gotmpl::HostMethod { name: "UTC", invoke: |o, a| time_call("UTC", o, a), signature: None },
        gotmpl::HostMethod { name: "Local", invoke: |o, a| time_call("Local", o, a), signature: None },
        gotmpl::HostMethod { name: "Location", invoke: |o, a| time_call("Location", o, a), signature: None },
        gotmpl::HostMethod { name: "Add", invoke: |o, a| time_call("Add", o, a), signature: Some(&DURATION_SIG) },
        gotmpl::HostMethod { name: "Sub", invoke: |o, a| time_call("Sub", o, a), signature: None },
        gotmpl::HostMethod { name: "Round", invoke: |o, a| time_call("Round", o, a), signature: Some(&DURATION_SIG) },
        gotmpl::HostMethod { name: "Truncate", invoke: |o, a| time_call("Truncate", o, a), signature: Some(&DURATION_SIG) },
        gotmpl::HostMethod { name: "Equal", invoke: |o, a| time_call("Equal", o, a), signature: None },
        gotmpl::HostMethod { name: "Before", invoke: |o, a| time_call("Before", o, a), signature: None },
        gotmpl::HostMethod { name: "After", invoke: |o, a| time_call("After", o, a), signature: None },
        gotmpl::HostMethod { name: "Compare", invoke: |o, a| time_call("Compare", o, a), signature: None },
    ],
};

fn time_call(name: &str, object: &gotmpl::Object, a: &[V]) -> R {
    let time = object.host_data::<Time>("time.Time").ok_or_else(|| err("invalid time.Time"))?;
    let display = object.display.as_deref().ok_or_else(|| err("invalid display"))?;
    match name {
        "Format" => {
            arity(a, 1, 1)?;
            output(format(time, arg_text(a, 0)?)?)
        },
        "Add" => {
            arity(a, 1, 1)?;
            let nanos = a[0].as_go_signed().ok_or_else(|| err("expected time.Duration"))?;
            time_value(add(time, nanos)?)
        },
        "Sub" => {
            arity(a, 1, 1)?;
            let other = extract(&a[0])?;
            let difference = if let (Some(a_mono), Some(b_mono)) = (time.monotonic, other.monotonic) {
                a_mono - b_mono
            } else {
                (i128::from(time.stamp.seconds) - i128::from(other.stamp.seconds)) * 1_000_000_000
                    + i128::from(time.stamp.nanosecond)
                    - i128::from(other.stamp.nanosecond)
            };
            Ok(duration_value(
                difference.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64,
            ))
        },
        "Round" | "Truncate" => {
            arity(a, 1, 1)?;
            let unit = a[0].as_go_signed().ok_or_else(|| err("expected time.Duration"))?;
            let mut new_time = time.clone();
            new_time.monotonic = None;
            if unit <= 0 {
                return time_value(new_time);
            }
            let absolute =
                (i128::from(new_time.stamp.seconds) + 62_135_596_800) * 1_000_000_000
                    + i128::from(new_time.stamp.nanosecond);
            let unit = i128::from(unit);
            let rem = absolute.rem_euclid(unit);
            let change = if name == "Truncate" || rem * 2 < unit {
                -rem
            } else {
                unit - rem
            };
            time_value(add(&new_time, change as i64)?)
        },
        "Equal" | "Before" | "After" | "Compare" => {
            arity(a, 1, 1)?;
            let other = extract(&a[0])?;
            let order = if let (Some(a_mono), Some(b_mono)) = (time.monotonic, other.monotonic) {
                a_mono.cmp(&b_mono)
            } else {
                (time.stamp.seconds, time.stamp.nanosecond).cmp(&(
                    other.stamp.seconds,
                    other.stamp.nanosecond,
                ))
            };
            if name == "Compare" {
                Ok(V::Int(match order {
                    std::cmp::Ordering::Less => -1,
                    std::cmp::Ordering::Equal => 0,
                    std::cmp::Ordering::Greater => 1,
                }))
            } else {
                Ok(V::Bool(match name {
                    "Equal" => order.is_eq(),
                    "Before" => order.is_lt(),
                    _ => order.is_gt(),
                }))
            }
        },
        _ => {
            arity(a, 0, 0)?;
            match name {
                "String" => output(display.to_owned()),
                "MarshalText" => {
                    let (offset, zone) = zone_info(&time.zone, time.stamp.seconds);
                    let components = time_components::at(time.stamp, offset, zone)
                        .map_err(|e| err(e.to_string()))?;
                    if !(0..=9999).contains(&components.year) {
                        return Err(err("Time.MarshalText: year outside of range [0,9999]"));
                    }
                    if !(-86_399..=86_399).contains(&offset) {
                        return Err(err("Time.MarshalText: timezone hour outside of range [0,23]"));
                    }
                    // A validated RFC3339Nano value has at most 35 bytes. Keep
                    // Go's []uint8 result rather than a string or JSON quotes.
                    let text = format(time, "2006-01-02T15:04:05.999999999Z07:00")?;
                    if text.len() > 35 {
                        return Err(err("time text exceeds RFC3339 capacity"));
                    }
                    Ok(V::Slice(gotmpl::TypedSlice::bytes(Some(Arc::from(text.into_bytes())))))
                },
                "Unix" => Ok(V::Int64(time.stamp.seconds)),
                "UnixNano" => Ok(V::Int64(time_components::unix_nano(time.stamp))),
                "UnixMilli" => Ok(V::Int64(
                    time.stamp.seconds.wrapping_mul(1000)
                        + i64::from(time.stamp.nanosecond / 1_000_000),
                )),
                "UnixMicro" => Ok(V::Int64(
                    time.stamp.seconds.wrapping_mul(1_000_000)
                        + i64::from(time.stamp.nanosecond / 1000),
                )),
                "Nanosecond" => Ok(V::Int(i64::from(time.stamp.nanosecond))),
                "IsZero" => Ok(V::Bool(time_components::is_zero(time.stamp))),
                "UTC" | "Local" => time_value(Time {
                    zone: if name == "UTC" { Zone::Utc } else { Zone::Local },
                    monotonic: None,
                    ..time.clone()
                }),
                "Location" => {
                    let name = location_name(&time.zone).to_owned();
                    let text = name.clone();
                    Ok(V::Object(Arc::new(gotmpl::Object {
                        display: Some(name.into()),
                        go_type: Some("*time.Location"),
                        pointer_identity:Some(match &time.zone{Zone::Utc=>1,Zone::Local=>2,Zone::Named(name)=>name.as_ptr()as usize,Zone::Fixed(value)=>Arc::as_ptr(value)as usize}),
                        methods: BTreeMap::from([(
                            "String".into(),
                            Arc::new(
                                move |a: &[V]| {
                                    arity(a, 0, 0)?;
                                    output(text.clone())
                                },
                            ) as gotmpl::ValueFunc,
                        )]),
                        ..gotmpl::Object::default()
                    })))
                },
                _ => {
                    let (offset, zone) = zone_info(&time.zone, time.stamp.seconds);
                    let c = time_components::at(time.stamp, offset, zone)
                        .map_err(|e| err(e.to_string()))?;
                    Ok(V::Int(match name {
                        "Year" => c.year as i64,
                        "Month" => return Ok(calendar_value(i64::from(c.month),false)),
                        "Day" => i64::from(c.day),
                        "YearDay" => i64::from(c.ordinal),
                        "Weekday" => return Ok(calendar_value(i64::from(c.weekday),true)),
                        "Hour" => i64::from(c.hour),
                        "Minute" => i64::from(c.minute),
                        _ => i64::from(c.second),
                    }))
                },
            }
        },
    }
}

fn time_value(time: Time) -> R {
    let json = (|| -> gotmpl::Result<Arc<str>> {
        let (offset, zone) = zone_info(&time.zone, time.stamp.seconds);
        let components = time_components::at(time.stamp, offset, zone)
            .map_err(|e| err(e.to_string()))?;
        if !(0..=9999).contains(&components.year)
            || offset / 3600 <= -24
            || offset / 3600 >= 24
        {
            return Err(err("time.Time JSON date is outside RFC3339 range"));
        }
        Ok(serde_json::to_string(&format(&time, "2006-01-02T15:04:05.999999999Z07:00")?)
            .map_err(|e| err(e.to_string()))?
            .into())
    })()
    .map_err(|e| Arc::from(e.to_string()));
    let mut display = format(&time, "2006-01-02 15:04:05.999999999 -0700 MST")?;
    if let Some(mono) = time.monotonic {
        display.push_str(&format!(
            " m={}{}.{:09}",
            if mono < 0 { "-" } else { "+" },
            mono.unsigned_abs() / 1_000_000_000,
            mono.unsigned_abs() % 1_000_000_000
        ));
    }
    Ok(V::Object(Arc::new(gotmpl::Object {
        json: Some(json),
        host_type: Some(&TIME_TYPE),
        display: Some(display.into()),
        go_type: Some("time.Time"),
        data: Some(Arc::new(time)),
        data_bytes: std::mem::size_of::<Time>(),
        equal: Some(time_equal),
        deep_equal: Some(time_deep_equal),
        key_order: Some(time_key_order),
        ..gotmpl::Object::default()
    })))
}

pub(super) fn add_functions(m:&mut M){for name in ["now","date","dateInZone","date_in_zone","htmlDate","htmlDateInZone","dateModify","date_modify","mustDateModify","must_date_modify","toDate","mustToDate","unixEpoch","ago","duration","durationRound"]{put(m,name,move|a|call(name,a));}}
fn call(name:&str,a:&[V])->R{
    match name{
        "now"=>{arity(a,0,0)?;time_value(now())},
        "date"|"dateInZone"|"date_in_zone"=>{arity(a,if name=="date"{2}else{3},if name=="date"{2}else{3})?;let mut time=date_input(&a[1]);time.zone=if name=="date"{Zone::Local}else{zone(arg_text(a,2)?)};output(format(&time,arg_text(a,0)?)?)},
        "htmlDate"|"htmlDateInZone"=>{arity(a,if name=="htmlDate"{1}else{2},if name=="htmlDate"{1}else{2})?;let mut time=date_input(&a[0]);time.zone=if name=="htmlDate"{Zone::Local}else{zone(arg_text(a,1)?)};output(format(&time,"2006-01-02")?)},
        "dateModify"|"date_modify"|"mustDateModify"|"must_date_modify"=>{
            arity(a,2,2)?;let time=extract(&a[1])?;match crate::duration::parse_go(arg_text(a,0)?){Ok(duration)=>time_value(add(&time,duration)?),Err(error)if name.starts_with("must")=>Err(err(error.to_string())),Err(_)=>Ok(a[1].clone())}
        }
        "toDate"|"mustToDate"=>{
            arity(a,2,2)?;let parsed=Layout::compile(arg_text(a,0)?).map_err(|e|err(e.to_string()))?.parse_time(arg_text(a,1)?,true);
            match parsed{Some(parsed)=>time_value(Time{stamp:parsed.timestamp,zone:if parsed.local{Zone::Local}else if parsed.zone=="UTC"{Zone::Utc}else{fixed_zone(parsed.offset,parsed.zone)},monotonic:None}),None if name=="mustToDate"=>Err(err("parsing date failed")),None=>time_value(Time{stamp:Timestamp{seconds:-62_135_596_800,nanosecond:0},zone:Zone::Utc,monotonic:None})}
        }
        "unixEpoch"=>{arity(a,1,1)?;output(extract(&a[0])?.stamp.seconds.to_string())},
        "duration"=>{arity(a,1,1)?;let seconds=match &a[0]{V::Int64(n)=>*n,V::String(s)=>s.parse().unwrap_or(0),_=>0};output(crate::duration::format(seconds.wrapping_mul(1_000_000_000)))},
        "durationRound"=>{
            arity(a,1,1)?;let duration=match &a[0]{V::Int64(n)=>*n,V::String(s)=>crate::duration::parse_go(s).unwrap_or(0),V::Object(o)if o.go_type==Some("time.Time")=>elapsed(&extract(&a[0])?),_=>0};
            let absolute=duration.unsigned_abs();for(divisor,label)in[(31_536_000_000_000_000u64,"y"),(2_592_000_000_000_000,"mo"),(86_400_000_000_000,"d"),(3_600_000_000_000,"h"),(60_000_000_000,"m"),(1_000_000_000,"s")]{if absolute>divisor{return output(format!("{}{label}",absolute/divisor));}}output("0s")
        }
        "ago"=>{arity(a,1,1)?;let nanos=elapsed(&date_input(&a[0]));let rounded=if nanos>=0{nanos.saturating_add(500_000_000)/1_000_000_000}else{nanos.saturating_sub(500_000_000)/1_000_000_000};output(crate::duration::format(rounded.wrapping_mul(1_000_000_000)))},
        _=>Err(err("unknown date helper")),
    }
}
fn elapsed(time:&Time)->i64{let now=chrono::Utc::now();let difference=(i128::from(now.timestamp())-i128::from(time.stamp.seconds))*1_000_000_000+i128::from(now.timestamp_subsec_nanos())-i128::from(time.stamp.nanosecond);difference.clamp(i128::from(i64::MIN),i128::from(i64::MAX))as i64}
pub(crate) fn system_time(time:std::time::SystemTime)->R{let duration=time.duration_since(std::time::UNIX_EPOCH);let stamp=match duration{Ok(duration)=>Timestamp{seconds:duration.as_secs()as i64,nanosecond:duration.subsec_nanos()},Err(error)=>{let duration=error.duration();Timestamp{seconds:-(duration.as_secs()as i64)-i64::from(duration.subsec_nanos()>0),nanosecond:if duration.subsec_nanos()==0{0}else{1_000_000_000-duration.subsec_nanos()}}}};time_value(Time{stamp,zone:Zone::Local,monotonic:None})}
pub(crate) fn humanize_time(layout:&str,input:&str)->gotmpl::Result<String>{
    let stamp=Layout::compile(layout).map_err(|e|err(e.to_string()))?.parse_timestamp(input,false).ok_or_else(||err("humanize: time cannot be parsed"))?;
    let time=Time{stamp,zone:Zone::Utc,monotonic:None};let elapsed=elapsed(&time);let label=if elapsed<0{"from now"}else{"ago"};let absolute=elapsed.unsigned_abs();
    let sec=1_000_000_000u64;let minute=60*sec;let hour=60*minute;let day=24*hour;let week=7*day;let month=30*day;let year=12*month;
    for(limit,format,divisor)in[(sec,"now",sec),(2*sec,"1 second",1),(minute,"seconds",sec),(2*minute,"1 minute",1),(hour,"minutes",minute),(2*hour,"1 hour",1),(day,"hours",hour),(2*day,"1 day",1),(week,"days",day),(2*week,"1 week",1),(month,"weeks",week),(2*month,"1 month",1),(year,"months",month),(18*month,"1 year",1),(2*year,"2 years",1),(37*year,"years",year),(u64::MAX,"a long while",1)]{
        if absolute<limit{return Ok(if format=="now"{format.into()}else if divisor==1{format!("{format} {label}")}else{format!("{} {format} {label}",absolute/divisor)});}
    }Ok(format!("a long while {label}"))
}

pub(super) fn duration_value(nanos:i64)->V{V::NamedInt64(nanos,duration_type())}
fn duration_kind()->gotmpl::ArgKind{gotmpl::ArgKind::NamedInt64("time.Duration",duration_value)}
fn duration_type()->Arc<gotmpl::Int64Type>{
    static TYPE:std::sync::LazyLock<Arc<gotmpl::Int64Type>>=std::sync::LazyLock::new(||{
        let mut methods=BTreeMap::<Arc<str>,gotmpl::Int64Method>::new();let mut signatures=BTreeMap::new();
        for name in ["String","Nanoseconds","Microseconds","Milliseconds","Seconds","Minutes","Hours","Round","Truncate","Abs"]{
            let parameter=matches!(name,"Round"|"Truncate");
            signatures.insert(Arc::from(name),gotmpl::Signature::new(if parameter{vec![duration_kind()]}else{Vec::new()},None));
            methods.insert(name.into(),Arc::new(move|value,a|{
                arity(a,usize::from(parameter),usize::from(parameter))?;
                match name{
                    "String"=>output(crate::duration::format(value)),"Nanoseconds"=>Ok(V::Int64(value)),"Microseconds"=>Ok(V::Int64(value/1000)),"Milliseconds"=>Ok(V::Int64(value/1_000_000)),
                    "Seconds"|"Minutes"|"Hours"=>{let unit=match name{"Seconds"=>1_000_000_000,"Minutes"=>60_000_000_000,_=>3_600_000_000_000};Ok(V::Float((value/unit)as f64+(value%unit)as f64/unit as f64))},
                    "Abs"=>Ok(duration_value(value.saturating_abs())),
                    "Truncate"|"Round"=>{
                        let unit=a[0].as_go_signed().ok_or_else(||err("expected time.Duration"))?;
                        if unit<=0{return Ok(duration_value(value));}
                        if name=="Truncate"{return Ok(duration_value(value-value%unit));}
                        let magnitude=i128::from(value).abs();let unit=i128::from(unit);let rounded=(magnitude+unit/2)/unit*unit;let rounded=if value<0{-rounded}else{rounded};
                        Ok(duration_value(rounded.clamp(i128::from(i64::MIN),i128::from(i64::MAX))as i64))
                    }
                    _=>Err(err("unknown time.Duration method")),
                }
            }));
        }
        Arc::new(gotmpl::Int64Type{name:"time.Duration",kind:"int64",stringer:Some(crate::duration::format),methods,signatures})
    });TYPE.clone()
}
