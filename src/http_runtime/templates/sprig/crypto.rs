//! Sprig 3.3.0 crypto helpers; X.509 helpers live in a separate module.
use super::*;
use base64::Engine;
const SEED:&[u8]=b"com.lyndir.masterpassword";
fn templates(kind:&str)->Option<&'static [&'static str]>{Some(match kind{
    "maximum"=>&["anoxxxxxxxxxxxxxxxxx","axxxxxxxxxxxxxxxxxno"],
    "long"=>&["CvcvnoCvcvCvcv","CvcvCvcvnoCvcv","CvcvCvcvCvcvno","CvccnoCvcvCvcv","CvccCvcvnoCvcv","CvccCvcvCvcvno","CvcvnoCvccCvcv","CvcvCvccnoCvcv","CvcvCvccCvcvno","CvcvnoCvcvCvcc","CvcvCvcvnoCvcc","CvcvCvcvCvccno","CvccnoCvccCvcv","CvccCvccnoCvcv","CvccCvccCvcvno","CvcvnoCvccCvcc","CvcvCvccnoCvcc","CvcvCvccCvccno","CvccnoCvcvCvcc","CvccCvcvnoCvcc","CvccCvcvCvccno"],
    "medium"=>&["CvcnoCvc","CvcCvcno"],"short"=>&["Cvcn"],"basic"=>&["aaanaaan","aannaaan","aaannaaa"],"pin"=>&["nnnn"],_=>return None,
})}
fn alphabet(kind:u8)->&'static [u8]{match kind{
    b'V'=>b"AEIOU",b'C'=>b"BCDFGHJKLMNPQRSTVWXYZ",b'v'=>b"aeiou",b'c'=>b"bcdfghjklmnpqrstvwxyz",b'A'=>b"AEIOUBCDFGHJKLMNPQRSTVWXYZ",b'a'=>b"AEIOUaeiouBCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz",b'n'=>b"0123456789",b'o'=>b"@&%?,=[]_:-+*$#!'^~;()/.",b'x'=>b"AEIOUaeiouBCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz0123456789!@#$%^&*()",_=>unreachable!(),
}}
pub(super) fn add(m:&mut M){
    put(m,"derivePassword",|a|{
        arity(a,5,5)?;let V::Uint32(counter)=a[0]else{return Err(err("expected uint32 counter"));};let kind=arg_text(a,1)?;
        let Some(templates)=templates(kind)else{return output(format!("cannot find password template {kind}"));};
        let(password,user,site)=(arg_text(a,2)?,arg_text(a,3)?,arg_text(a,4)?);
        let mut salt=Vec::with_capacity(SEED.len()+4+user.len());salt.extend_from_slice(SEED);salt.extend_from_slice(&(user.len()as u32).to_be_bytes());salt.extend_from_slice(user.as_bytes());
        let mut key=[0u8;64];openssl::pkcs5::scrypt(password.as_bytes(),&salt,32768,8,2,64<<20,&mut key).map_err(|_|err("scrypt derivation failed"))?;
        salt.truncate(SEED.len());salt.extend_from_slice(&(site.len()as u32).to_be_bytes());salt.extend_from_slice(site.as_bytes());salt.extend_from_slice(&counter.to_be_bytes());
        use hmac::{Hmac,Mac};let mut mac=Hmac::<sha2::Sha256>::new_from_slice(&key).map_err(|_|err("HMAC key failed"))?;mac.update(&salt);let seed=mac.finalize().into_bytes();
        let template=templates[usize::from(seed[0])%templates.len()];let result=template.bytes().enumerate().map(|(i,kind)|{let chars=alphabet(kind);chars[usize::from(seed[i+1])%chars.len()]as char}).collect::<String>();output(result)
    });
    for name in ["bcrypt","htpasswd"]{put(m,name,move|a|{
        arity(a,if name=="bcrypt"{1}else{2},if name=="bcrypt"{1}else{2})?;
        let input=arg_text(a,usize::from(name=="htpasswd"))?;
        let username=if name=="htpasswd"{let user=arg_text(a,0)?;if user.contains(':'){return output(format!("invalid username: {user}"));}Some(user)}else{None};
        let hash=if input.len()>72{"failed to encrypt string with bcrypt: crypto/bcrypt: password length exceeds 72 bytes".into()}
        else{match bcrypt::hash(input,10){Ok(hash)=>hash.replacen("$2b$","$2a$",1),Err(_)=>"failed to encrypt string with bcrypt: random source failed".into()}};
        output(if let Some(user)=username{format!("{user}:{hash}")}else{hash})
    });}
    for name in ["encryptAES","decryptAES"]{put(m,name,move|a|{
        arity(a,2,2)?;let(password,input)=(arg_text(a,0)?,arg_text(a,1)?);if input.is_empty(){return output("");}
        let mut key=[0u8;32];let length=password.len().min(32);key[..length].copy_from_slice(&password.as_bytes()[..length]);
        let cipher=openssl::symm::Cipher::aes_256_cbc();
        if name=="encryptAES"{
            let mut iv=[0u8;16];getrandom::fill(&mut iv).map_err(|_|err("AES IV random source failed"))?;
            let encrypted=openssl::symm::encrypt(cipher,&key,Some(&iv),input.as_bytes()).map_err(|_|err("AES encryption failed"))?;
            let mut bytes=Vec::with_capacity(16+encrypted.len());bytes.extend_from_slice(&iv);bytes.extend_from_slice(&encrypted);let length=bytes.len().div_ceil(3)*4;if length>MAX_BYTES{return Err(err("AES encoded output exceeds byte limit"));}
            output(base64::engine::general_purpose::STANDARD.encode(bytes))
        }else{
            let filtered=input.bytes().filter(|b|!matches!(b,b'\n'|b'\r')).collect::<Vec<_>>();
            let bytes=base64::engine::general_purpose::STANDARD.decode(filtered).map_err(|_|err("invalid AES base64"))?;
            if bytes.len()<32||(bytes.len()-16)%16!=0{return Err(err("invalid AES ciphertext length"));}
            let mut decryptor=openssl::symm::Crypter::new(cipher,openssl::symm::Mode::Decrypt,&key,Some(&bytes[..16])).map_err(|_|err("AES decryptor failed"))?;decryptor.pad(false);
            let mut plain=vec![0;bytes.len()];let length=decryptor.update(&bytes[16..],&mut plain).map_err(|_|err("AES decryption failed"))?;let last=decryptor.finalize(&mut plain[length..]).map_err(|_|err("AES decryption failed"))?;plain.truncate(length+last);
            let padding=usize::from(*plain.last().ok_or_else(||err("invalid AES padding"))?);if padding>plain.len(){return Err(err("invalid AES padding"));}plain.truncate(plain.len()-padding);
            output(String::from_utf8(plain).map_err(|_|err("decrypted AES contains unrepresentable byte string"))?)
        }
    });}
}
