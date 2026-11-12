// Derived from Masterminds/semver v3.5.0 constraints.go, MIT.
use super::semver_version::Version;
use regex::{Regex,Captures};
use std::{cmp::Ordering,sync::LazyLock};
const CV:&str=r"v?([0-9|x|X|\*]+)(\.[0-9|x|X|\*]+)?(\.[0-9|x|X|\*]+)?(-([0-9A-Za-z\-]+(\.[0-9A-Za-z\-]+)*))?(\+([0-9A-Za-z\-]+(\.[0-9A-Za-z\-]+)*))?";
const OPS:&str=r"=||!=|>|<|>=|=>|<=|=<|~|~>|\^";
fn regex(source:String)->Regex{Regex::new(&source.replace(r"\s",r"[\t\n\f\r ]")).expect("fixed semver grammar")}
static ONE:LazyLock<Regex>=LazyLock::new(||regex(format!(r"^\s*({OPS})\s*({CV})\s*$")));
static FIND:LazyLock<Regex>=LazyLock::new(||regex(format!(r"({OPS})\s*({CV})")));
static VALID:LazyLock<Regex>=LazyLock::new(||regex(format!(r"^(\s*({OPS})\s*({CV})\s*)((?:\s+|,\s*)({OPS})\s*({CV})\s*)*$")));
static RANGE:LazyLock<Regex>=LazyLock::new(||regex(format!(r"\s*({CV})\s+-\s+({CV})\s*")));
struct Constraint {con:Version,op:String,dirty:bool,minor:bool,patch:bool}
fn x(s:&str)->bool{matches!(s,"x"|"X"|"*")}
fn parse(input:&str)->Result<Constraint,String>{
    if input.is_empty(){return Ok(Constraint{con:Version::parse("0.0.0")?,op:String::new(),dirty:true,minor:false,patch:false});}
    let caps=ONE.captures(input).ok_or("improper constraint")?;
    let m=|i|caps.get(i).map_or("",|m|m.as_str());
    let(mut version,mut dirty,mut minor,mut patch)=(m(2).to_owned(),false,false,false);
    if x(m(3))||m(3).is_empty(){version=format!("0.0.0{}",m(6));dirty=true;}
    else if x(m(4).trim_start_matches('.'))||m(4).is_empty(){version=format!("{}.0.0{}",m(3),m(6));dirty=true;minor=true;}
    else if x(m(5).trim_start_matches('.'))||m(5).is_empty(){version=format!("{}{}.0{}",m(3),m(4),m(6));dirty=true;patch=true;}
    Ok(Constraint{con:Version::parse(&version)?,op:m(1).into(),dirty,minor,patch})
}
fn tilde(v:&Version,c:&Constraint)->bool{
    if v.compare(&c.con).is_lt(){return false;}
    if c.con.major==0&&c.con.minor==0&&c.con.patch==0&&!c.minor&&!c.patch{return true;}
    v.major==c.con.major&&(c.minor||v.minor==c.con.minor)
}
fn matches(v:&Version,c:&Constraint,include_pre:bool)->bool{
    if !v.pre.is_empty()&&!include_pre{return false;}
    let order=v.compare(&c.con);let base=&c.con;
    match c.op.as_str(){
        ""|"="=>if c.dirty{tilde(v,c)}else{order.is_eq()},
        "!="=>{
            if c.dirty{
                if base.major!=v.major{return true;}
                if base.minor!=v.minor&&!c.minor{return true;}else if c.minor{return false;}
                else if base.patch!=v.patch&&!c.patch{return true;}else if c.patch{
                    if !v.pre.is_empty()||!base.pre.is_empty(){return v.pre!=base.pre;}
                    return false;
                }
            }
            !order.is_eq()
        }
        ">"=>{
            if !c.dirty{return order==Ordering::Greater;}
            if v.major>base.major{return true;}else if v.major<base.major||c.minor{return false;}else if c.patch{return v.minor>base.minor;}
            order.is_gt()
        }
        "<"=>order.is_lt(),">="|"=>"=>!order.is_lt(),
        "<="|"=<"=>if c.dirty{v.major<base.major||(v.major==base.major&&(c.minor||v.minor<=base.minor))}else{!order.is_gt()},
        "~"|"~>"=>tilde(v,c),
        "^"=>{
            if order.is_lt(){return false;}
            if base.major>0||c.minor{return v.major==base.major;}
            if v.major>0{return false;}
            if base.minor>0||c.patch{return v.minor==base.minor;}
            if v.minor>0{return false;}
            base.patch==v.patch
        }
        _=>false,
    }
}
pub(super) fn check(input:&str,version:&Version)->Result<bool,String>{
    if input.len()>512{return Err("constraint length exceeds 512 bytes".into());}
    let rewritten=RANGE.replace_all(input,|c:&Captures<'_>|format!(">= {}, <= {} ",&c[1],&c[11]));
    let parts=rewritten.split("||").collect::<Vec<_>>();if parts.len()>32{return Err("too many constraint groups".into());}
    let mut groups=Vec::new();
    for part in parts{
        if !VALID.is_match(part){return Err("improper constraint".into());}
        let mut group=FIND.find_iter(part).map(|found|parse(found.as_str())).collect::<Result<Vec<_>,_>>()?;
        if group.is_empty(){group.push(parse(part)?);}groups.push(group);
    }
    Ok(groups.iter().any(|group|{let include_pre=group.iter().any(|c|!c.con.pre.is_empty());group.iter().all(|c|matches(version,c,include_pre))}))
}
