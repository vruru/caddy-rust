use super::*;
use base64::Engine;
pub(super) fn add(m:&mut M){
    for name in ["uuidv4","randBytes","randAlphaNum","randAlpha","randNumeric","randAscii","randInt","shuffle"]{put(m,name,move|a|call(name,a));}
}
fn fill(bytes:&mut[u8])->gotmpl::Result<()>{getrandom::fill(bytes).map_err(|_|err("system randomness unavailable"))}
fn uniform(upper:u64)->gotmpl::Result<u64>{
    if upper==0{return Err(err("invalid random range"));}let limit=u64::MAX-(u64::MAX%upper);
    loop{let mut bytes=[0u8;8];fill(&mut bytes)?;let value=u64::from_ne_bytes(bytes);if value<limit{return Ok(value%upper);}}
}
fn call(name:&str,a:&[V])->R{
    match name{
        "uuidv4"=>{arity(a,0,0)?;let mut bytes=[0u8;16];fill(&mut bytes)?;bytes[6]=(bytes[6]&15)|0x40;bytes[8]=(bytes[8]&63)|0x80;let hex=bytes.iter().map(|b|format!("{b:02x}")).collect::<String>();output(format!("{}-{}-{}-{}-{}",&hex[..8],&hex[8..12],&hex[12..16],&hex[16..20],&hex[20..]))}
        "randInt"=>{arity(a,2,2)?;let start=arg_int(a,0)?;let end=arg_int(a,1)?;let width=end.checked_sub(start).filter(|n|*n>0).ok_or_else(||err("invalid random integer range"))?;Ok(V::Int(start+uniform(width as u64)? as i64))}
        "shuffle"=>{arity(a,1,1)?;let mut characters=arg_text(a,0)?.chars().collect::<Vec<_>>();for i in(1..characters.len()).rev(){let other=uniform((i+1)as u64)? as usize;characters.swap(i,other);}output(characters.into_iter().collect::<String>())}
        "randBytes"=>{arity(a,1,1)?;let count=usize::try_from(arg_int(a,0)?).map_err(|_|err("negative random byte count"))?;if count>MAX_BYTES/4*3{return Err(err("random byte output exceeds byte limit"));}let mut bytes=vec![0u8;count];fill(&mut bytes)?;output(base64::engine::general_purpose::STANDARD.encode(bytes))}
        _=>{
            arity(a,1,1)?;let count=usize::try_from(arg_int(a,0)?.max(0)).map_err(|_|err("random string length overflow"))?;
            if count>MAX_BYTES{return Err(err("random string exceeds byte limit"));}
            let alphabet:&[u8]=match name{
                "randAlphaNum"=>b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
                "randAlpha"=>b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
                "randNumeric"=>b"0123456789",
                "randAscii"=>b" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~",
                _=>return Err(err("unknown random string function")),
            };
            let mut bytes=Vec::with_capacity(count);while bytes.len()<count{let mut entropy=[0u8;128];fill(&mut entropy)?;for byte in entropy{let bound=256usize-(256%alphabet.len());if(byte as usize)<bound{bytes.push(alphabet[byte as usize%alphabet.len()]);if bytes.len()==count{break;}}}}
            output(String::from_utf8(bytes).map_err(|_|err("random alphabet invariant"))?)
        }
    }
}
