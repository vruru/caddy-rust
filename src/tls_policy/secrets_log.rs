//! Explicit NSS key logging. No environment variable enables this capability.
use anyhow::{Result, ensure};
use std::{fs::{File, OpenOptions}, io::Write, sync::{Arc, Mutex}};

pub(super) fn prepare(raw: &str) -> Result<Arc<dyn rustls::KeyLog>> {
    let cwd=std::env::current_dir()?;
    let token=tokio_util::sync::CancellationToken::new();
    let expanded=crate::tls_app_config::leaf_values::expand(raw,&cwd,&token)?;
    let path=crate::tls_app_config::leaf_values::absolute(expanded.as_bytes(),&cwd)?;
    let mut options=OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)] {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW|libc::O_NONBLOCK);
    }
    let file=options.open(path)?;
    let metadata=file.metadata()?;
    ensure!(metadata.is_file(),"TLS secrets log must be a regular file");
    #[cfg(unix)] {
        use std::os::unix::fs::PermissionsExt;
        ensure!(metadata.permissions().mode()&0o077==0,"TLS secrets log must be private to its owner");
    }
    Ok(Arc::new(Log(Mutex::new(file))))
}

struct Log(Mutex<File>);
impl std::fmt::Debug for Log {
    fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result { f.write_str("ExplicitTlsSecretsLog") }
}
impl rustls::KeyLog for Log {
    fn log(&self,label:&str,client_random:&[u8],secret:&[u8]) {
        // All supported NSS labels are fixed ASCII tokens; secret material
        // never enters the application logger or an error's Display value.
        if label.len()>96||!label.bytes().all(|b|b.is_ascii_uppercase()||b.is_ascii_digit()||b==b'_')
            ||client_random.len()>64||secret.len()>128{return}
        let mut line=zeroize::Zeroizing::new([0u8;512]);let mut n=0;
        line[..label.len()].copy_from_slice(label.as_bytes());n+=label.len();
        const HEX:&[u8;16]=b"0123456789abcdef";
        for bytes in [client_random,secret] {
            line[n]=b' ';n+=1;
            for byte in bytes {line[n]=HEX[(byte>>4)as usize];line[n+1]=HEX[(byte&15)as usize];n+=2;}
        }
        line[n]=b'\n';n+=1;
        if let Ok(mut file)=self.0.lock() { let _=file.write_all(&line[..n]); }
    }
}

pub(crate) fn openssl_line(logger:&dyn rustls::KeyLog,line:&str) {
    let mut fields=line.split_ascii_whitespace();
    let(Some(label),Some(random),Some(secret))=(fields.next(),fields.next(),fields.next())else{return};
    if fields.next().is_some()||!logger.will_log(label){return}
    fn decode(input:&str,out:&mut[u8])->Option<usize>{
        if !input.len().is_multiple_of(2)||input.len()/2>out.len(){return None}
        for(i,pair)in input.as_bytes().chunks_exact(2).enumerate(){
            let a=(pair[0]as char).to_digit(16)?;let b=(pair[1]as char).to_digit(16)?;
            out[i]=(a*16+b)as u8;
        }Some(input.len()/2)
    }
    let mut random_bytes=zeroize::Zeroizing::new([0u8;64]);
    let mut secret_bytes=zeroize::Zeroizing::new([0u8;128]);
    let(Some(r),Some(s))=(decode(random,&mut*random_bytes),decode(secret,&mut*secret_bytes))else{return};
    logger.log(label,&random_bytes[..r],&secret_bytes[..s]);
}
