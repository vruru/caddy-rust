use super::super::{err,MAX_BYTES,MAX_ITEMS};
fn push<'a>(parts:&mut Vec<&'a[u8]>,part:&'a[u8])->gotmpl::Result<()>{if parts.len()>=MAX_ITEMS{return Err(err("too many split items"));}parts.push(part);Ok(())}
pub(super) fn split<'a>(src:&'a[u8],sep:&[u8],n:i64)->gotmpl::Result<Vec<&'a[u8]>>{
    if n==0{return Ok(Vec::new());}let limit=if n<0{usize::MAX}else{n as usize};let mut parts=Vec::new();let mut start=0;
    if sep.is_empty(){
        for(_,width)in gotmpl::go_runes(src){
            if parts.len()+1>=limit{push(&mut parts,&src[start..])?;return Ok(parts);}
            push(&mut parts,&src[start..start+width])?;start+=width;
        }
    }else{
        for index in memchr::memmem::find_iter(src,sep){if parts.len()+1>=limit{break;}push(&mut parts,&src[start..index])?;start=index+sep.len();}
        push(&mut parts,&src[start..])?;
    }Ok(parts)
}
pub(super) fn replace(src:&[u8],old:&[u8],new:&[u8])->gotmpl::Result<Vec<u8>>{
    let count=if old.is_empty(){gotmpl::go_runes(src).count()+1}else{memchr::memmem::find_iter(src,old).count()};
    let size=src.len().checked_sub(count.checked_mul(old.len()).ok_or_else(||err("replace size overflow"))?).and_then(|n|count.checked_mul(new.len()).and_then(|added|n.checked_add(added))).filter(|size|*size<=MAX_BYTES).ok_or_else(||err("replace exceeds byte limit"))?;
    let mut output=Vec::with_capacity(size);let mut start=0;
    if old.is_empty(){output.extend_from_slice(new);for(_,width)in gotmpl::go_runes(src){output.extend_from_slice(&src[start..start+width]);output.extend_from_slice(new);start+=width;}}
    else{for index in memchr::memmem::find_iter(src,old){output.extend_from_slice(&src[start..index]);output.extend_from_slice(new);start=index+old.len();}output.extend_from_slice(&src[start..]);}
    Ok(output)
}
pub(super) fn abbreviate(src:&[u8],offset:i64,width:usize)->gotmpl::Result<Vec<u8>>{
    if src.is_empty()||src.len()<=width{return Ok(src.to_vec());}
    if width<4{return Err(err("abbreviation width too small"));}
    let mut offset=usize::try_from(offset.max(0)).unwrap_or(src.len()).min(src.len());if src.len()-offset<width-3{offset=src.len()-(width-3);}
    if offset<=4{let mut output=src[..width-3].to_vec();output.extend_from_slice(b"...");return Ok(output);}
    if width<7{return Err(err("abbreviation offset width too small"));}
    let mut output=b"...".to_vec();
    if offset+width-3<src.len(){output.extend_from_slice(&abbreviate(&src[offset..],0,width-3)?);}else{output.extend_from_slice(&src[src.len()-(width-3)..]);}
    Ok(output)
}
