//! Go Time's public Stringer and GoStringer, on the existing render CPU lane.
use super::*;

pub(super)fn string(time:&Time)->gotmpl::Result<String>{
    let mut result=format(time,"2006-01-02 15:04:05.999999999 -0700 MST")?;
    if let Some(mono)=time.monotonic{use std::fmt::Write;write!(result," m={}{}.{:09}",if mono<0{"-"}else{"+"},mono.unsigned_abs()/1_000_000_000,mono.unsigned_abs()%1_000_000_000).map_err(|_|err("time display failed"))?;}
    Ok(result)
}

pub(super)fn go_string(time:&Time)->gotmpl::Result<String>{
    let(offset,name)=zone_info(&time.zone,time.stamp.seconds);
    let c=time_components::at(time.stamp,offset,name).map_err(|e|err(e.to_string()))?;
    let location=match &time.zone{Zone::Utc=>"time.UTC".into(),Zone::Local=>"time.Local".into(),zone=>format!("time.Location({})",gotmpl::quote_go_string(location_name(zone).as_bytes(),false)?)};
    Ok(format!("time.Date({}, time.{}, {}, {}, {}, {}, {}, {})",c.year,month_name(i64::from(c.month)),c.day,c.hour,c.minute,c.second,time.stamp.nanosecond,location))
}

pub(super)fn is_dst(time:&Time)->bool{match &time.zone{
    Zone::Utc|Zone::Fixed(_)=>false,
    Zone::Named(name)=>{use chrono_tz::OffsetComponents;name.parse::<chrono_tz::Tz>().ok().and_then(|zone|zone.timestamp_opt(time.stamp.seconds,0).single()).is_some_and(|time|time.offset().dst_offset()!=chrono::Duration::zero())},
    Zone::Local=>{
        #[cfg(unix)]{
            let seconds=match libc::time_t::try_from(time.stamp.seconds){Ok(seconds)=>seconds,Err(_)=>return false};
            let mut tm=std::mem::MaybeUninit::<libc::tm>::uninit();
            // localtime_r writes this caller-owned structure; rendering runs
            // on the existing bounded blocking lane, after TZ preparation.
            let result=unsafe{libc::localtime_r(&seconds,tm.as_mut_ptr())};
            if result.is_null(){false}else{unsafe{tm.assume_init()}.tm_isdst>0}
        }
        #[cfg(not(unix))]{false}
    },
}}

pub(super)fn formatter(object:&gotmpl::Object,verb:char,f:&gotmpl::HostFormat)->R{
    let time=current(object)?;
    let mut spec=String::from("%");
    for(flag,on)in[('-',f.left_align),('+',f.plus),(' ',f.space),('#',f.hash),('0',f.zero)]{if on{spec.push(flag)}}
    if let Some(width)=f.width{if width>MAX_BYTES{return Err(err("time format width exceeds limit"))}spec.push_str(&width.to_string())}
    if let Some(precision)=f.precision{if precision>MAX_BYTES{return Err(err("time format precision exceeds limit"))}spec.push('.');spec.push_str(&precision.to_string())}
    let value=if verb=='v'&&f.hash{
        // GoStringer writes source text; its #/+ flags do not quote it again.
        spec=String::from("%");if f.left_align{spec.push('-')}if let Some(width)=f.width{spec.push_str(&width.to_string())}spec.push('s');
        V::from(go_string(&time)?)
    }else if matches!(verb,'v'|'s'|'q'|'x'|'X'){
        if verb=='v'{spec=String::from("%");if f.left_align{spec.push('-')}if let Some(width)=f.width{spec.push_str(&width.to_string())}if let Some(precision)=f.precision{spec.push('.');spec.push_str(&precision.to_string())}spec.push('s')}else{spec.push(verb)}
        V::from(string(&time)?)
    }else{
        // Numeric/bad verbs see Go's wall/ext/loc representation rather than
        // recursing through this formatter or accidentally printing String().
        spec.push(verb);
        let wall=u64::from(time.stamp.nanosecond)|time.monotonic.map_or(0,|_|(1<<63)|(((time.stamp.seconds+2_682_288_000)as u64)<<30));
        let ext=time.monotonic.map_or_else(||time.stamp.seconds.wrapping_add(62_135_596_800),|v|v as i64);
        let loc=match &time.zone{Zone::Utc=>0,Zone::Local=>2,Zone::Named(n)=>n.as_ptr()as usize,Zone::Fixed(n)=>Arc::as_ptr(n)as usize};
        V::Object(Arc::new(gotmpl::Object{go_type:Some("time.Time"),reflected_fields:Some(vec![("wall".into(),V::Uint(wall)),("ext".into(),V::Int64(ext)),("loc".into(),V::Object(Arc::new(gotmpl::Object{go_type:Some("*time.Location"),pointer_identity:Some(loc),nil_pointer:Some(Arc::new(move||loc==0)),..gotmpl::Object::default()})))].into()),..gotmpl::Object::default()}))
    };
    Ok(V::from_go_bytes(gotmpl::go_sprintf_bytes(spec.as_bytes(),&[value])?))
}
