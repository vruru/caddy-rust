//! Go path/filepath Unix lexical helpers. These do not access the filesystem.
use super::*;
pub(super) fn add(m:&mut M){
    for name in ["env","expandenv","base","dir","clean","ext","isAbs","osBase","osDir","osClean","osExt","osIsAbs"]{
        put(m,name,move|a|{arity(a,1,1)?;let input=arg_text(a,0)?;match name{
            "env"=>output(std::env::var(input).unwrap_or_default()),
            "expandenv"=>output(expand(input)?),
            "isAbs"|"osIsAbs"=>Ok(V::Bool(input.starts_with('/'))),
            "clean"|"osClean"=>output(clean(input)),
            "base"|"osBase"=>{let input=input.trim_end_matches('/');output(if input.is_empty(){if a[0].as_str()==Some(""){ "." }else{"/"}}else{input.rsplit('/').next().unwrap_or(".")})},
            "dir"|"osDir"=>output(clean(input.rfind('/').map_or("",|i|&input[..=i]))),
            "ext"|"osExt"=>{let file=input.rsplit('/').next().unwrap_or("");output(file.rfind('.').map_or("",|i|&file[i..]))},
            _=>Err(err("unknown path helper")),
        }})
    }
}
fn clean(input:&str)->String{
    let absolute=input.starts_with('/');let mut parts=Vec::new();
    for part in input.split('/') {match part{
        ""|"."=>{},".."=>{if parts.last().is_some_and(|p|*p!=".."){parts.pop();}else if !absolute{parts.push(part);}},_=>parts.push(part),
    }}
    if parts.is_empty(){return if absolute{"/"}else{"."}.into();}
    let mut out=String::with_capacity(input.len());if absolute{out.push('/');}out.push_str(&parts.join("/"));out
}
fn special(byte:u8)->bool{matches!(byte,b'*'|b'#'|b'$'|b'@'|b'!'|b'?'|b'-'|b'0'..=b'9')}
fn append(out:&mut String,value:&str)->gotmpl::Result<()>{checked_length(out.len(),value.len())?;out.push_str(value);Ok(())}
fn expand(input:&str)->gotmpl::Result<String>{
    let mut out=String::with_capacity(input.len().min(MAX_BYTES));let mut copied=0;let mut at=0;let bytes=input.as_bytes();
    while at+1<bytes.len(){
        if bytes[at]!=b'$'{at+=1;continue;}
        append(&mut out,&input[copied..at])?;let rest=&input[at+1..];let raw=rest.as_bytes();
        let(name,width)=if raw[0]==b'{'{
            // Go getShellName consumes only the opening brace on a missing close.
            if raw.len()>1&&special(raw[1])&&raw.get(2)==Some(&b'}'){(&rest[1..2],3)}
            else if let Some(end)=rest.find('}') {if end==1{("",2)}else{(&rest[1..end],end+1)}}else{("",1)}
        }else if special(raw[0]){(&rest[..1],1)}else{
            let width=raw.iter().take_while(|b|b.is_ascii_alphanumeric()||**b==b'_').count();(&rest[..width],width)
        };
        if name.is_empty()&&width==0{append(&mut out,"$")?;}else if !name.is_empty(){append(&mut out,&std::env::var(name).unwrap_or_default())?;}
        at+=1+width;copied=at;
    }
    append(&mut out,&input[copied..])?;Ok(out)
}
