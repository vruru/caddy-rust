use super::*;
use super::{semver_version::Version,semver_constraints};
use std::cmp::Ordering;
fn extract(value:&V)->gotmpl::Result<&Version>{let V::Object(object)=value else{return Err(err("expected *semver.Version"));};object.host_data::<Version>("*semver.Version").ok_or_else(||err("expected *semver.Version"))}
fn equal(a:&gotmpl::Object,b:&gotmpl::Object)->bool{match(a.host_data::<Version>("semver.Version"),b.host_data::<Version>("semver.Version")){(Some(a),Some(b))=>a==b,_=>false}}
fn value(version:Version,pointer:bool)->R{
    let go_type=if pointer{"*semver.Version"}else{"semver.Version"};
    let bytes=128+version.pre.len()+version.metadata.len()+version.original.len();if bytes>MAX_BYTES{return Err(err("semantic version payload exceeds byte limit"));}
    let display=version.to_string();let json=Some(Ok(Arc::from(serde_json::to_string(&display).map_err(|e|err(e.to_string()))?)));let mut methods=BTreeMap::<Arc<str>,gotmpl::ValueFunc>::new();
    let mut names=vec!["String","Major","Minor","Patch","Prerelease","Metadata","IncPatch","IncMinor","IncMajor","SetPrerelease","SetMetadata","Value"];
    if pointer{names.extend(["Original","LessThan","LessThanEqual","GreaterThan","GreaterThanEqual","Equal","Compare"]);}
    for name in names{let version=version.clone();methods.insert(name.into(),Arc::new(move|a|{
        match name{
            "SetPrerelease"|"SetMetadata"=>{arity(a,1,1)?;let next=if name=="SetPrerelease"{version.set_prerelease(arg_text(a,0)?)}else{version.set_metadata(arg_text(a,0)?)}.map_err(err)?;value(next,false)},
            "LessThan"|"LessThanEqual"|"GreaterThan"|"GreaterThanEqual"|"Equal"|"Compare"=>{
                arity(a,1,1)?;if name=="Equal"&&matches!(a[0],V::Nil){return Ok(V::Bool(false));}
                let other=extract(&a[0])?;let order=version.compare(other);
                if name=="Compare"{Ok(V::Int(match order{Ordering::Less=>-1,Ordering::Equal=>0,Ordering::Greater=>1}))}
                else{Ok(V::Bool(match name{"LessThan"=>order.is_lt(),"LessThanEqual"=>!order.is_gt(),"GreaterThan"=>order.is_gt(),"GreaterThanEqual"=>!order.is_lt(),_=>order.is_eq()}))}
            }
            _=>{arity(a,0,0)?;match name{
                "String"|"Value"=>output(version.to_string()),"Original"=>output(version.original.clone()),
                "Major"=>Ok(V::Uint(version.major)),"Minor"=>Ok(V::Uint(version.minor)),"Patch"=>Ok(V::Uint(version.patch)),
                "Prerelease"=>output(version.pre.clone()),"Metadata"=>output(version.metadata.clone()),
                "IncPatch"=>value(version.inc_patch().map_err(err)?,false),"IncMinor"=>value(version.inc_minor().map_err(err)?,false),"IncMajor"=>value(version.inc_major().map_err(err)?,false),
                _=>Err(err("unknown semantic version method")),
            }}
        }
    }));}
    Ok(V::Object(Arc::new(gotmpl::Object{methods,json,go_type:Some(go_type),display:Some(display.into()),data:Some(Arc::new(version)),data_bytes:bytes,equal:Some(equal),..gotmpl::Object::default()})))
}
pub(super) fn add(m:&mut M){
    put(m,"semver",|a|{arity(a,1,1)?;value(Version::parse(arg_text(a,0)?).map_err(err)?,true)});
    put(m,"semverCompare",|a|{arity(a,2,2)?;let version=Version::parse(arg_text(a,1)?).map_err(err)?;Ok(V::Bool(semver_constraints::check(arg_text(a,0)?,&version).map_err(err)?))});
}
