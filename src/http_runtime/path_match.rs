// Copyright The Go Authors; The Caddy Authors. BSD-3-Clause / Apache-2.0.
//! Go/Caddy path normalization is distinct from wire URI validation: invalid
//! UTF-8 path bytes become one RuneError each during strings.ToLower. They do
//! not turn an unrelated route predicate into an HTTP 400 response.
use super::request::clean_path;
pub(crate) fn lower(raw:&[u8])->String{gotmpl::go_runes(raw).map(|(rune,_)|crate::go_case::lower(rune)).collect()}
fn unescape(raw:&[u8])->Option<Vec<u8>>{crate::go_url_compat::template_decode_bytes(raw).ok()}
pub(super) fn matches(patterns:&[String],escaped:&str)->Result<bool,super::path_glob::GlobLimit>{
    let deadline=std::time::Instant::now()+std::time::Duration::from_millis(150);
    let Some(decoded)=unescape(escaped.as_bytes())else{return Ok(false)};
    let path=lower(&decoded);
    #[cfg(windows)]
    let path=normalize_windows(&path);
    for pattern in patterns{
        if std::time::Instant::now()>=deadline{return Err(super::path_glob::GlobLimit)}
        if pattern=="*"{return Ok(true)}
        let merge=!pattern.contains("//");
        if pattern.contains('%'){
            let escaped=clean_path(escaped,merge);
            if escaped_match(&escaped,pattern,deadline)?{return Ok(true)}continue;
        }
        let path=clean_path(&path,merge);let count=pattern.bytes().filter(|b|*b==b'*').count();
        if count==2&&pattern.starts_with('*')&&pattern.ends_with('*'){if path.contains(&pattern[1..pattern.len()-1]){return Ok(true)}continue;}
        if count==1{if let Some(suffix)=pattern.strip_prefix('*'){if path.ends_with(suffix){return Ok(true)}continue;}if let Some(prefix)=pattern.strip_suffix('*'){if path.starts_with(prefix){return Ok(true)}continue;}}
        if glob(pattern,&path,deadline)?{return Ok(true)}
    }Ok(false)
}
#[cfg(windows)]
fn normalize_windows(path:&str)->String{path.replace('\\',"/").split('/').map(|part|if matches!(part,"."|".."){part}else{part.trim_end_matches(['.',' '])}).collect::<Vec<_>>().join("/")}
// Preserve the reference's byte cursors, including its escaped-star behavior.
// Unlike the generated draft, borrowed slices never outlive decoded temporaries
// and Unicode pattern bytes are never individually cast to char.
fn escaped_match(escaped:&str,pattern:&str,deadline:std::time::Instant)->Result<bool,super::path_glob::GlobLimit>{
    let escaped=lower(escaped.as_bytes());let path=escaped.as_bytes();let pat=pattern.as_bytes();
    let(mut pi,mut xi)=(0usize,0usize);let mut out=Vec::with_capacity(path.len());
    while pi<pat.len()&&xi<path.len(){
        let one=[path[xi]];let mut encoded=&b""[..];let decoded;
        let ch=if one[0]==b'%'&&path.len()-xi>=3{
            encoded=&path[xi..xi+3];let Some(value)=unescape(encoded)else{return Ok(false)};decoded=value;xi+=2;&decoded[..]
        }else{&one[..]};
        let(mut wildcard,mut normalize)=(false,true);
        match pat[pi]{
            b'%'=>{
                if pat.len()-pi>=3&&pat[pi+1]!=b'*'{out.extend_from_slice(encoded);xi+=1;pi+=2;}
                else{pi+=1;normalize=false;wildcard=true;}
            },
            b'*'=>wildcard=true,
            _=>{out.extend_from_slice(ch);xi+=1;}
        }
        if wildcard{
            let remaining=&path[xi..];let until=if pi<pat.len()-1{
                let Some(until)=remaining.iter().position(|b|*b==pat[pi+1])else{return Ok(false)};until
            }else{remaining.len()};
            if until!=0{let next=&remaining[..until];if normalize{let Some(next)=unescape(next)else{return Ok(false)};out.extend(next);}else{out.extend_from_slice(next);}xi+=until;}
        }
        pi+=1;
    }
    if xi<path.len(){out.extend(unescape(&path[xi..]).unwrap_or_else(||path[xi..].to_vec()));}
    glob(&pattern.replace("%*","*"),&lower(&out),deadline)
}

// The ordinary exact and one-star forms need neither regexp compilation nor a
// blocking-worker hop. Complex glob syntax retains the existing shared matcher.
fn glob(pattern:&str,value:&str,deadline:std::time::Instant)->Result<bool,super::path_glob::GlobLimit>{super::path_glob::go_path_glob_deadline(pattern,value,Some(deadline))}
pub(super) fn fast(patterns:&[String],escaped:&str)->bool{
    escaped.len()<=4096&&patterns.len()<=16&&patterns.iter().map(String::len).sum::<usize>()<=4096&&patterns.iter().all(|pattern|{
        if pattern.bytes().any(|b|matches!(b,b'?'|b'['|b'\\')){return false}
        let stars=pattern.bytes().filter(|b|*b==b'*').count();stars<=1||!pattern.contains('%')&&stars==2&&pattern.starts_with('*')&&pattern.ends_with('*')
    })
}
