use super::*;
use crate::go_case;
#[path="byte_ops.rs"]mod byte_ops;
#[path="go_xstrings.rs"]mod go_xstrings;
pub(super) fn add(m: &mut M) {
    for name in ["hello","upper","lower","title","untitle","trim","trimAll","trimall","trimPrefix","trimSuffix","contains","hasPrefix","hasSuffix","repeat","nospace","initials","swapcase","substr","trunc","quote","squote","cat","indent","nindent","replace","plural","join","sortAlpha","split","splitn","splitList","toStrings","abbrev","abbrevboth","wrap","wrapWith","snakecase","camelcase","kebabcase"] {
        put(m,name,move |args| call(name,args));
    }
}
fn arg_bytes(args:&[V],index:usize)->gotmpl::Result<&[u8]>{args.get(index).and_then(V::as_go_bytes).ok_or_else(||err("expected string argument"))}
fn bytes_output(bytes:Vec<u8>)->R{checked_length(0,bytes.len())?;Ok(V::from_go_bytes(bytes))}
fn raw_text(value:&V)->gotmpl::Result<Vec<u8>>{if let Some(bytes)=value.as_go_bytes(){Ok(bytes.to_vec())}else{gotmpl::go_sprint_bytes(std::slice::from_ref(value),false)}}
fn call(name: &str, a: &[V]) -> R {
    match name {
        "hello" => { arity(a,0,0)?; output("Hello!") }
        "upper"|"lower"|"title"|"untitle"|"trim"|"nospace"|"initials"|"swapcase" => {
            arity(a,1,1)?; let raw=arg_bytes(a,0)?;let decoded=gotmpl::go_utf8_text(raw);let input=decoded.as_ref();
            output(match name {
                "upper" => input.chars().map(go_case::upper).collect(), "lower" => input.chars().map(go_case::lower).collect(),
                "trim" => return trim_bytes(raw,|c|c.is_whitespace()),
                // The pinned goutils routines iterate bytes and write each as
                // a rune. Preserve that behavior for non-ASCII input too.
                "nospace"=>{if !raw.iter().any(|byte|char::from(*byte).is_whitespace()){return bytes_output(raw.to_vec());}raw.iter().copied().map(char::from).filter(|c|!c.is_whitespace()).collect()},
                "initials" => {let mut gap=true;raw.iter().copied().map(char::from).filter(|c|{if c.is_whitespace(){gap=true;false}else{let take=gap;gap=false;take}}).collect()},
                "swapcase" => {let mut whitespace=true;input.chars().map(|c|{
                    if go_case::is_upper(c)||go_case::is_title(c){whitespace=false;go_case::lower(c)}
                    else if go_case::is_lower(c){if whitespace{whitespace=false;go_case::title(c)}else{go_case::upper(c)}}
                    else{whitespace=c.is_whitespace();c}
                }).collect()},
                "untitle" => {
                    let mut start=true;let mut output=String::new();
                    for c in input.chars(){if c.is_whitespace(){start=true;output.push(c);}else if start{output.push(go_case::lower(c));start=false;}else{output.push(c);}}output
                }
                _ => {
                    // Go strings.Title retains the remainder of each word.
                    let mut previous = ' '; let mut out = String::new();
                    for c in input.chars() {
                        let boundary = if previous.is_ascii() { !previous.is_ascii_alphanumeric() && previous != '_' }
                            else { previous.is_whitespace() };
                        if boundary { out.push(go_case::title(c)); } else {out.push(c);}
                        previous=c;
                    }
                    out
                }
            })
        }
        "trimAll"|"trimall"|"trimPrefix"|"trimSuffix"|"contains"|"hasPrefix"|"hasSuffix"=>{
            arity(a,2,2)?;let prefix=arg_bytes(a,0)?;let input=arg_bytes(a,1)?;
            match name{
                "contains"=>Ok(V::Bool(memchr::memmem::find(input,prefix).is_some())),
                "hasPrefix"=>Ok(V::Bool(input.starts_with(prefix))),"hasSuffix"=>Ok(V::Bool(input.ends_with(prefix))),
                "trimPrefix"=>bytes_output(input.strip_prefix(prefix).unwrap_or(input).to_vec()),
                "trimSuffix"=>bytes_output(input.strip_suffix(prefix).unwrap_or(input).to_vec()),
                _=>{let runes=gotmpl::go_runes(prefix).map(|(r,_)|r).collect::<std::collections::BTreeSet<_>>();trim_bytes(input,|c|runes.contains(&c))},
            }
        }
        "repeat" => {
            arity(a,2,2)?; let count=usize::try_from(arg_int(a,0)?).map_err(|_|err("negative repeat count"))?;
            let input=arg_bytes(a,1)?;
            let length=count.checked_mul(input.len()).ok_or_else(||err("repeat size overflow"))?;
            checked_length(0,length)?; bytes_output(input.repeat(count))
        }
        "snakecase"|"camelcase"|"kebabcase"=>{arity(a,1,1)?;let input=arg_bytes(a,0)?;bytes_output(if name=="camelcase"{go_xstrings::pascal(input)?}else{go_xstrings::separated(input,if name=="snakecase"{b'_'}else{b'-'})?})}
        "abbrev"|"abbrevboth"=>{
            arity(a,if name=="abbrev"{2}else{3},if name=="abbrev"{2}else{3})?;
            let offset=if name=="abbrev"{0}else{arg_int(a,0)?};let width=arg_int(a,usize::from(name=="abbrevboth"))?;
            let input=arg_bytes(a,if name=="abbrev"{1}else{2})?;
            if width<4||(offset>0&&width<7){return bytes_output(input.to_vec());}
            bytes_output(byte_ops::abbreviate(input,offset,width as usize)?)
        }
        "wrap"|"wrapWith"=>{
            arity(a,if name=="wrap"{2}else{3},if name=="wrap"{2}else{3})?;
            let width=arg_int(a,0)?.max(1)as usize;let sep=if name=="wrap"{b"\n"}else{let s=arg_bytes(a,1)?;if s.is_empty(){b"\n"}else{s}};
            let input=arg_bytes(a,if name=="wrap"{1}else{2})?;
            let mut out=Vec::new();let mut offset=0usize;
            while input.len().saturating_sub(offset)>width{
                if input[offset]==b' '{offset+=1;continue;}
                let end=offset+width+1;
                let split=input[offset..end].iter().rposition(|b|*b==b' ').map(|i|offset+i);
                let (stop,next)=if let Some(stop)=split{(stop,stop+1)}else if name=="wrapWith"{(offset+width,offset+width)}else{
                    input[offset+width..].iter().position(|b|*b==b' ').map(|i|(offset+width+i,offset+width+i+1)).unwrap_or((input.len(),input.len()))
                };
                checked_length(out.len(),stop-offset+if stop<input.len(){sep.len()}else{0})?;
                out.extend_from_slice(&input[offset..stop]);if stop<input.len(){out.extend_from_slice(sep);}offset=next;
            }
            checked_length(out.len(),input.len()-offset)?;out.extend_from_slice(&input[offset..]);
            bytes_output(out)
        }
        "substr"|"trunc" => {
            arity(a,if name=="substr" {3} else {2},if name=="substr" {3} else {2})?;
            let start=arg_int(a,0)?; let input=arg_bytes(a,if name=="substr" {2} else {1})?;
            let len=input.len() as i64;
            let (start,end)=if name=="trunc" {
                if start<0 && len.saturating_add(start)>0 {(len+start,len)}
                else if start>=0 && start<len {(0,start)} else {(0,len)}
            } else {
                let end=arg_int(a,1)?;
                (start.max(0),if end<0 || end>len {len} else {end})
            };
            let range=usize::try_from(start).ok().zip(usize::try_from(end).ok());
            let result=range.and_then(|(s,e)|input.get(s..e)).ok_or_else(||err("template string byte slice is not representable"))?;
            bytes_output(result.to_vec())
        }
        "quote"|"squote"|"cat"=>{
            let mut out=Vec::new();
            for(index,value)in a.iter().filter(|v|!matches!(v,V::Nil)).enumerate(){
                let bytes=raw_text(value)?;
                let part=if name=="quote"{gotmpl::quote_go_string(&bytes,false)?.into_bytes()}else if name=="squote"{let mut part=Vec::with_capacity(bytes.len()+2);part.push(b'\'');part.extend_from_slice(&bytes);part.push(b'\'');part}else{bytes};
                checked_length(out.len(),part.len()+usize::from(index>0))?;if index>0{out.push(b' ');}out.extend_from_slice(&part);
            }bytes_output(out)
        }
        "indent"|"nindent"=>{
            arity(a,2,2)?;let count=usize::try_from(arg_int(a,0)?).map_err(|_|err("negative indentation"))?;let input=arg_bytes(a,1)?;
            let size=checked_length(input.len(),count.checked_mul(input.iter().filter(|b|**b==b'\n').count()+1).ok_or_else(||err("indent size overflow"))?.checked_add(usize::from(name=="nindent")).ok_or_else(||err("indent size overflow"))?)?;
            let mut output=Vec::with_capacity(size);if name=="nindent"{output.push(b'\n');}output.resize(output.len()+count,b' ');
            for byte in input{output.push(*byte);if *byte==b'\n'{output.resize(output.len()+count,b' ');}}bytes_output(output)
        }
        "replace"=>{arity(a,3,3)?;bytes_output(byte_ops::replace(arg_bytes(a,2)?,arg_bytes(a,0)?,arg_bytes(a,1)?)?)}
        "plural" => { arity(a,3,3)?; bytes_output(arg_bytes(a,if arg_int(a,2)?==1 {0}else{1})?.to_vec()) }
        "toStrings"|"sortAlpha"|"join" => {
            arity(a,if name=="join" {2}else{1},if name=="join" {2}else{1})?;
            let value=&a[usize::from(name=="join")];
            if name!="join"{if let V::Slice(slice)=value{if slice.go_type()=="[]string"{if name=="sortAlpha"{slice.sort_strings()?;}return Ok(value.clone());}}}
            let capacity=value.as_sequence().map_or(usize::from(!matches!(value,V::Nil)),|seq|seq.len());
            let mut values=if matches!(value,V::Nil){Vec::new()}else if let Some(seq)=value.as_sequence(){seq.iter().filter(|v|!matches!(v,V::Nil)).map(|v|raw_text(&v)).collect::<gotmpl::Result<Vec<_>>>()?}else{vec![raw_text(value)?]};
            if values.len()>MAX_ITEMS {return Err(err("too many string items"));}
            if name=="join" {
                let sep=arg_bytes(a,0)?;
                let len=values.iter().try_fold(0usize,|n,s|checked_length(n,s.len()))?;
                checked_length(len,sep.len().checked_mul(values.len().saturating_sub(1)).ok_or_else(||err("join size overflow"))?)?;
                bytes_output(values.join(sep))
            } else {if name=="sortAlpha" {values.sort();} strings_value(Some(values.into_iter().map(V::from_go_bytes).collect()),capacity)}
        }
        "split"|"splitn"|"splitList" => {
            arity(a,if name=="splitn" {3}else{2},if name=="splitn" {3}else{2})?;
            let sep=arg_bytes(a,0)?;let src=arg_bytes(a,if name=="splitn"{2}else{1})?;let n=if name=="splitn"{arg_int(a,1)?}else{-1};let parts=byte_ops::split(src,sep,n)?;
            if name=="splitList"{let capacity=parts.len();strings_value(Some(parts.into_iter().map(|part|V::from_go_bytes(part.to_vec())).collect()),capacity)}
            else{Ok(V::Map(Arc::new(parts.into_iter().enumerate().map(|(index,part)|(format!("_{index}").into(),V::from_go_bytes(part.to_vec()))).collect())))}
        }
        _ => Err(err("unregistered string helper")),
    }
}
fn trim_bytes(input:&[u8],mut trim:impl FnMut(char)->bool)->R{
    let mut start=0;for(rune,width)in gotmpl::go_runes(input){if !trim(rune){break;}start+=width;}
    let mut end=start;let mut offset=start;for(rune,width)in gotmpl::go_runes(&input[start..]){offset+=width;if !trim(rune){end=offset;}}
    bytes_output(input[start..end].to_vec())
}
