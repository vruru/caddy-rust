use super::*;
use crate::go_regexp::{GoRegexp,ReplaceBudget,Replacement};
pub(super) fn add(m:&mut M){for name in ["regexMatch","mustRegexMatch","regexFindAll","mustRegexFindAll","regexFind","mustRegexFind","regexReplaceAll","mustRegexReplaceAll","regexReplaceAllLiteral","mustRegexReplaceAllLiteral","regexSplit","mustRegexSplit","regexQuoteMeta"]{put(m,name,move|a|call(name,a));}}
fn call(name:&str,a:&[V])->R{
    if name=="regexQuoteMeta"{arity(a,1,1)?;let mut out=String::new();for c in arg_text(a,0)?.chars(){if "\\.+*?()|[]{}^$".contains(c){out.push('\\');}out.push(c);}return output(out);}
    let canonical=name.strip_prefix("must").map(|name|{let mut name=name.to_owned();if let Some(first)=name.get_mut(..1){first.make_ascii_lowercase();}name}).unwrap_or_else(||name.into());
    let three=matches!(canonical.as_str(),"regexFindAll"|"regexSplit"|"regexReplaceAll"|"regexReplaceAllLiteral");
    arity(a,if three{3}else{2},if three{3}else{2})?;
    let pattern=arg_text(a,0)?;let input=arg_text(a,1)?;
    let regex=match GoRegexp::compile(pattern,4<<20){Ok(regex)=>regex,Err(_)if name=="regexMatch"=>return Ok(V::Bool(false)),Err(error)=>return Err(err(error.to_string()))};
    let mut budget=ReplaceBudget::new(8<<20,Some(std::time::Instant::now()+std::time::Duration::from_secs(5)));
    match canonical.as_str(){
        "regexMatch"=>Ok(V::Bool(regex.first_match(input,&budget).map_err(|e|err(e.to_string()))?.is_some())),
        "regexFind"|"regexFindAll"|"regexSplit"=>{
            let count=if canonical=="regexFind"{1}else{arg_int(a,2)?};
            let ranges=regex.find_all_ranges(input,count,MAX_ITEMS,&budget).map_err(|e|err(e.to_string()))?;
            if canonical=="regexFind"{return output(ranges.first().and_then(|r|input.get(r.clone())).unwrap_or_default());}
            if canonical=="regexFindAll"{if ranges.is_empty(){return strings_value(None,0);}let mut cap=0;for n in 1..=ranges.len(){if n>cap{cap=gotmpl::go_slice_capacity(cap,n,16,true).ok_or_else(||err("regex slice capacity overflow"))?;}}return strings_value(Some(ranges.into_iter().map(|range|V::from(&input[range])).collect()),cap);}
            if count==0{return strings_value(None,0);}
            if !pattern.is_empty()&&input.is_empty(){return strings_value(Some(vec![V::from("")]),1);}
            let(mut beginning,mut end)=(0usize,0usize);let mut cap=ranges.len();let mut out=Vec::new();
            for range in ranges{if count>0&&out.len()>=count as usize-1{break;}end=range.start;if range.end!=0{out.push(V::from(&input[beginning..end]));}beginning=range.end;}
            if end!=input.len(){out.push(V::from(&input[beginning..]));}if out.len()>cap{cap=gotmpl::go_slice_capacity(cap,out.len(),16,true).ok_or_else(||err("regex slice capacity overflow"))?;}strings_value(Some(out),cap)
        }
        "regexReplaceAll"|"regexReplaceAllLiteral"=>{
            let replacement=arg_text(a,2)?;
            let text=if canonical=="regexReplaceAllLiteral"{replacement.replace('$',"$$")}else{replacement.into()};
            let replacement=Replacement::compile(&regex,text,4<<20).map_err(|e|err(e.to_string()))?;
            let result=regex.replace_all(input.as_bytes(),&replacement,MAX_BYTES,false,&mut budget).map_err(|e|err(e.to_string()))?;
            output(String::from_utf8(result).map_err(|_|err("regexp replacement contains unrepresentable byte string"))?)
        }
        _=>Err(err("unknown regexp helper")),
    }
}
