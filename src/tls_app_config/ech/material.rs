use anyhow::{Result,anyhow,ensure};
use std::sync::Arc;
use zeroize::Zeroizing;
use rustls::crypto::hpke::Hpke;
pub(crate)struct Key{
    pub(crate)config:Arc<[u8]>,
    private:Zeroizing<Vec<u8>>,
    pub(crate)public_name:Arc<str>,
    pub(crate)id:u8,
    pub(crate)created:i64,
    pub(crate)replaced:Option<i64>,
    pub(super)metadata:crate::cert_transient::Json,
    _memory:crate::acme_wire::chain_memory::Scratch,
}
impl Key{
    pub(crate)fn private_bytes(&self)->&[u8]{&self.private}
    pub(crate)fn send_as_retry(&self)->bool{self.replaced.is_none()}
    pub(super)fn parse(id:u8,config:Vec<u8>,private:Zeroizing<Vec<u8>>,metadata:crate::cert_transient::Json)->Result<Self>{
        let memory=crate::cert_transient::reserve(config.len().saturating_mul(4).saturating_add(private.len()*2).saturating_add(8192))?;
        ensure!(config.len()>=48&&config.len()<=4096&&private.len()==32,"invalid ECH material size");
        let mut reader=Reader(&config);ensure!(reader.u16()?==0xfe0d,"unsupported ECH version");
        ensure!(usize::from(reader.u16()?)==reader.0.len(),"invalid ECH content length");
        ensure!(reader.byte()?==id&&reader.u16()?==0x20,"invalid ECH key identity");
        let public=reader.bytes16()?;ensure!(public.len()==32,"invalid ECH public key size");
        let derived=aws_lc_rs::agreement::PrivateKey::from_private_key(&aws_lc_rs::agreement::X25519,&private).map_err(|_|anyhow!("invalid ECH private key"))?.compute_public_key().map_err(|_|anyhow!("invalid ECH public key"))?;
        ensure!(aws_lc_rs::constant_time::verify_slices_are_equal(public,derived.as_ref()).is_ok(),"ECH public and private keys differ");
        let suites=reader.bytes16()?;ensure!(!suites.is_empty()&&suites.len()%4==0&&suites.chunks_exact(4).all(|s|s[0..2]==[0,1]&&s[2]==0&&[1,2,3].contains(&s[3])),"unsupported ECH HPKE suite");
        let _max_name=reader.byte()?;let name=reader.bytes8()?;let name=std::str::from_utf8(name).map_err(|_|anyhow!("invalid ECH public name"))?;
        ensure!(super::config::valid_public_name(name),"invalid ECH public name");let name:Arc<str>=Arc::from(name);
        let _extensions=reader.bytes16()?;ensure!(reader.0.is_empty(),"invalid ECH config trailing bytes");
        let object=metadata.as_object().ok_or_else(||anyhow!("invalid ECH metadata"))?;
        let created=timestamp(object.get("created"))?.unwrap_or(-62_135_596_800);
        let replaced=timestamp(object.get("replaced"))?.filter(|t|*t!= -62_135_596_800);
        Ok(Self{config:config.into(),private,public_name:name,id,created,replaced,metadata,_memory:memory})
    }
    pub(super)fn generate(id:u8,name:&str,now:i64)->Result<Self>{
        ensure!(super::config::valid_public_name(name),"invalid ECH public name");
        let _scratch=crate::cert_transient::reserve(16384)?;
        let(public,private)=rustls::crypto::aws_lc_rs::hpke::DH_KEM_X25519_HKDF_SHA256_AES_128.generate_key_pair()?;
        let mut config=vec![0xfe,0x0d,0,0,id,0,0x20,0,32];config.extend_from_slice(&public.0);
        config.extend_from_slice(&[0,12,0,1,0,1,0,1,0,2,0,1,0,3,(name.len()+16).min(255)as u8,name.len()as u8]);config.extend_from_slice(name.as_bytes());config.extend_from_slice(&[0,0]);
        let length=u16::try_from(config.len()-4)?;config[2..4].copy_from_slice(&length.to_be_bytes());
        let metadata=crate::cert_transient::edited_json(&serde_json::Value::Null,1024,|value|{*value=serde_json::json!({"created":format_time(now)?,"publications":{}});Ok(())})?;
        Self::parse(id,config,Zeroizing::new(private.secret_bytes().to_vec()),metadata)
    }
    pub(super)fn mark_replaced(&self,now:i64)->Result<Self>{
        let _copy=crate::cert_transient::reserve(self.config.len().saturating_mul(2).saturating_add(4096))?;
        let metadata=crate::cert_transient::edited_json(&self.metadata,256,|metadata|{metadata.as_object_mut().ok_or_else(||anyhow!("invalid ECH metadata"))?.insert("replaced".into(),serde_json::Value::String(format_time(now)?));Ok(())})?;
        Self::parse(self.id,self.config.to_vec(),Zeroizing::new(self.private.to_vec()),metadata)
    }
}
fn timestamp(value:Option<&serde_json::Value>)->Result<Option<i64>>{
    match value.filter(|v|!v.is_null()){
        None=>Ok(None),Some(serde_json::Value::String(text))=>Ok(Some(chrono::DateTime::parse_from_rfc3339(text).map_err(|_|anyhow!("invalid ECH metadata timestamp"))?.timestamp())),_=>Err(anyhow!("invalid ECH metadata timestamp")),
    }
}
pub(super)fn format_time(now:i64)->Result<String>{Ok(chrono::DateTime::from_timestamp(now,0).ok_or_else(||anyhow!("ECH timestamp out of range"))?.to_rfc3339_opts(chrono::SecondsFormat::Secs,true))}
struct Reader<'a>(&'a[u8]);
impl<'a>Reader<'a>{
    fn take(&mut self,n:usize)->Result<&'a[u8]>{ensure!(n<=self.0.len(),"invalid ECH length");let(a,b)=self.0.split_at(n);self.0=b;Ok(a)}
    fn byte(&mut self)->Result<u8>{Ok(self.take(1)?[0])}
    fn u16(&mut self)->Result<u16>{let s=self.take(2)?;Ok(u16::from_be_bytes([s[0],s[1]]))}
    fn bytes8(&mut self)->Result<&'a[u8]>{let n=usize::from(self.byte()?);self.take(n)}
    fn bytes16(&mut self)->Result<&'a[u8]>{let n=usize::from(self.u16()?);self.take(n)}
}
