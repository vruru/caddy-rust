// Go net/url resolvePath and path.Clean semantics (Go Authors, BSD-3-Clause).
// The caller prepays allocation and linear work before entering these helpers.
pub(super) fn resolve_path(base:&[u8],reference:&[u8])->Vec<u8>{
    let full=if reference.is_empty(){base.to_vec()}else if reference[0]!=b'/'{let mut full=base.iter().rposition(|b|*b==b'/').map_or_else(Vec::new,|i|base[..=i].to_vec());full.extend_from_slice(reference);full}else{reference.to_vec()};
    if full.is_empty(){return Vec::new();}
    let mut dst=vec![b'/'];let mut first=true;let mut dot=false;
    for segment in full.split(|b|*b==b'/'){
        if segment==b"."{first=false;dot=true;continue;}
        if segment==b".."{if let Some(i)=dst[1..].iter().rposition(|b|*b==b'/'){dst.truncate(i+1);}else{dst.truncate(1);}first=dst.len()==1;dot=true;continue;}
        if !first{dst.push(b'/');}dst.extend_from_slice(segment);first=false;dot=false;
    }
    if dot{dst.push(b'/');}
    if dst.len()>1&&dst[1]==b'/'{dst[1..].to_vec()}else{dst}
}
pub(super) fn clean_join(parts:&[&[u8]])->Vec<u8>{
    let mut joined=Vec::new();let mut found=false;
    for part in parts.iter().filter(|part|!part.is_empty()){if found{joined.push(b'/');}joined.extend_from_slice(part);found=true;}
    if !found{return Vec::new();}
    let rooted=joined.starts_with(b"/");let mut segments:Vec<&[u8]>=Vec::new();
    for segment in joined.split(|b|*b==b'/'){
        if segment.is_empty()||segment==b"."{continue;}
        if segment==b".."{if segments.last().is_some_and(|last|*last!=b".."){segments.pop();}else if !rooted{segments.push(segment);}continue;}
        segments.push(segment);
    }
    let mut output=Vec::new();if rooted{output.push(b'/');}
    for(index,segment)in segments.iter().enumerate(){if index!=0{output.push(b'/');}output.extend_from_slice(segment);}
    if output.is_empty(){output.push(b'.');}output
}
