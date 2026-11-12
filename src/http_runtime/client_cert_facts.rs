//! Owned certificate facts shared by typed replacer consumers. Parsing happens
//! once per connection, on the runtime's bounded metadata worker lane.
use super::{ConnectionSnapshot, pkix_name::{Attribute, AttributeValue, Name, NativeValue}, resource_budget::Resources};
use std::sync::Arc;
use tokio::sync::{OnceCell, OwnedSemaphorePermit};
pub(super) const POOL_UNITS: usize = 64 * 1024;
const RESERVE_UNITS: u32 = 8 * 1024;
pub(crate) struct Cache {
    snapshot: Arc<ConnectionSnapshot>,
    value: OnceCell<Result<Option<Arc<Facts>>, String>>,
}
impl Cache {
    pub(crate) fn new(snapshot: Arc<ConnectionSnapshot>) -> Arc<Self> {
        Arc::new(Self { snapshot, value: OnceCell::new() })
    }
    pub(crate) async fn get(&self, resources: &Resources) -> Result<Option<Arc<Facts>>, String> {
        self.value.get_or_init(|| async {
            let meta = self.snapshot.metadata().map_err(|e| e.to_string())?;
            let Some(der) = meta.peer_certificates.first().cloned() else { return Ok(None) };
            if der.len() > 65536 { return Err("client certificate exceeds 64 KiB".into()) }
            // Admission precedes parsing, including its temporary name/ASN.1
            // containers. A cancelled waiter cannot release a running worker's lease.
            let credit = resources.client_cert_bytes.clone().try_acquire_many_owned(RESERVE_UNITS)
                .map_err(|_| "client certificate metadata pool exhausted".to_owned())?;
            resources.metadata.run(move || {
                let mut facts = parse(der)?;
                let units = facts.retained_upper().div_ceil(1024).max(1);
                if units > RESERVE_UNITS as usize { return Err("client certificate metadata limit".into()) }
                let mut credit = credit;
                drop(credit.split(RESERVE_UNITS as usize - units));
                facts.credit = Some(credit);
                Ok(Some(Arc::new(facts)))
            }).await.map_err(|_| "client certificate metadata worker unavailable".to_owned())?
        }).await.clone()
    }
}
pub(crate) struct Facts {
    pub der: Arc<[u8]>,
    pub subject: Name,
    pub issuer: Name,
    pub subject_display: Arc<str>,
    pub issuer_display: Arc<str>,
    pub serial: Vec<u8>,
    pub serial_decimal: String,
    pub dns: Vec<String>,
    pub emails: Vec<String>,
    pub ips: Vec<Vec<u8>>,
    /// Original Go url.Parse input; consumers retain URL identity, not strings.
    pub uris: Vec<String>,
    pub public_key: Option<Vec<u8>>,
    credit: Option<OwnedSemaphorePermit>,
}
impl Facts {
    fn retained_upper(&self) -> usize {
        // DER bounds every copied payload. 4096 attribute/SAN cap bounds owned
        // descriptors; this includes name lists, derived displays and Vec growth.
        let count = self.subject.names.len() + self.issuer.names.len() + self.dns.len()
            + self.emails.len() + self.ips.len() + self.uris.len();
        self.der.len().saturating_mul(32).saturating_add(count.saturating_mul(1024)).saturating_add(4096)
    }
}
pub(crate) fn parse(der: Arc<[u8]>) -> Result<Facts, String> {
    if der.len() > 65536 { return Err("client certificate exceeds 64 KiB".into()) }
    let (remaining, cert) = x509_parser::parse_x509_certificate(&der).map_err(|e| format!("client certificate: {e}"))?;
    if !remaining.is_empty() { return Err("client certificate trailing bytes".into()) }
    let subject = parse_name(cert.subject().as_raw())?;
    let issuer = parse_name(cert.issuer().as_raw())?;
    let serial = cert.raw_serial().to_vec();
    let serial_decimal = rsa::BigUint::from_bytes_be(&serial).to_str_radix(10);
    let (mut dns, mut emails, mut ips, mut uris) = (Vec::new(),Vec::new(),Vec::new(),Vec::new());
    let mut count = subject.names.len() + issuer.names.len();
    if let Some(san) = cert.subject_alternative_name().map_err(|e| format!("client SAN: {e}"))? {
        for name in &san.value.general_names {
            count += 1;
            if count > 4096 { return Err("client certificate attribute limit".into()) }
            use x509_parser::extensions::GeneralName as G;
            match name {
                G::DNSName(s) => dns.push((*s).to_owned()),
                G::RFC822Name(s) => emails.push((*s).to_owned()),
                G::URI(s) => uris.push((*s).to_owned()),
                G::IPAddress(b) if matches!(b.len(),4|16) => ips.push(b.to_vec()),
                G::IPAddress(_) => return Err("invalid client SAN IP".into()),
                _ => {},
            }
        }
    }
    let pki = cert.public_key();
    let raw = pki.subject_public_key.data.as_ref();
    let public_key = if pki.subject_public_key.unused_bits != 0 { None } else {
        match pki.algorithm.algorithm.to_id_string().as_str() {
            "1.2.840.113549.1.1.1" => Some(raw.to_vec()),
            "1.3.101.112" if raw.len() == 32 => Some(raw.to_vec()),
            "1.2.840.10045.2.1" => {
                let curve = pki.algorithm.parameters.as_ref().and_then(|p| p.as_oid().ok()).map(|p| p.to_id_string());
                let len = match curve.as_deref() { Some("1.2.840.10045.3.1.7") => 65, Some("1.3.132.0.34") => 97, Some("1.3.132.0.35") => 133, _ => 0 };
                (len != 0 && raw.len() == len && raw.first() == Some(&4)).then(|| raw.to_vec())
            },
            _ => None,
        }
    };
    let subject_display=subject.string().into(); let issuer_display=issuer.string().into();
    Ok(Facts { der,subject,issuer,subject_display,issuer_display,serial,serial_decimal,dns,emails,ips,uris,public_key,credit:None })
}

struct Element<'a> { class:u8, constructed:bool, tag:u32, data:&'a [u8], full:&'a [u8] }
fn element<'a>(input:&mut &'a [u8]) -> Result<Element<'a>,String> {
    let original = *input;
    let mut index = 0usize;
    let mut byte = || { let b = original.get(index).copied().ok_or("truncated ASN.1 element")?; index += 1; Ok::<_,String>(b) };
    let first = byte()?;
    let mut tag = u32::from(first & 31);
    if tag == 31 {
        tag = 0;
        let mut leading = true;
        loop { let b = byte()?; if leading && b == 128 { return Err("nonminimal ASN.1 tag".into()) }
            tag = tag.checked_mul(128).and_then(|n| n.checked_add(u32::from(b&127))).ok_or("ASN.1 tag overflow")?;
            leading = false; if b&128 == 0 { break }
        }
        if tag < 31 { return Err("nonminimal ASN.1 tag".into()) }
    }
    let length = byte()?;
    let length = if length < 128 { usize::from(length) } else {
        let count = length & 127;
        if count == 0 || count > 4 { return Err("invalid ASN.1 length".into()) }
        let mut n = 0usize;
        for i in 0..count { let b=byte()?; if i==0 && b==0 { return Err("nonminimal ASN.1 length".into()) }
            n=n.checked_mul(256).and_then(|n| n.checked_add(usize::from(b))).ok_or("ASN.1 length overflow")?;
        }
        if n<128 { return Err("nonminimal ASN.1 length".into()) } n
    };
    let end = index.checked_add(length).filter(|n| *n<=original.len()).ok_or("truncated ASN.1 value")?;
    *input=&original[end..];
    Ok(Element { class:first>>6,constructed:first&32!=0,tag,data:&original[index..end],full:&original[..end] })
}
fn tagged<'a>(input:&mut &'a[u8], tag:u32, constructed:bool)->Result<&'a[u8],String> {
    let e=element(input)?; if e.class!=0 || e.tag!=tag || e.constructed!=constructed { return Err("invalid X.509 name tag".into()) } Ok(e.data)
}
fn oid(input:&[u8])->Result<Vec<u32>,String> {
    let mut arcs=Vec::new(); let mut value=0u32; let mut leading=true;
    for &b in input {
        if leading && b==128 { return Err("nonminimal ASN.1 OID".into()) }
        value=value.checked_mul(128).and_then(|n|n.checked_add(u32::from(b&127))).ok_or("ASN.1 OID overflow")?;
        leading=false;
        if b&128==0 { if arcs.is_empty() { let first=(value/40).min(2);arcs.push(first);arcs.push(value-first*40); } else { arcs.push(value) } value=0;leading=true; }
    }
    if !leading || arcs.is_empty() { return Err("truncated ASN.1 OID".into()) } Ok(arcs)
}
pub(crate) fn parse_name(mut input:&[u8])->Result<Name,String> {
    let mut sequence=tagged(&mut input,16,true)?;
    if !input.is_empty() { return Err("X.509 name trailing bytes".into()) }
    let mut rdns=Vec::new(); let mut count=0usize;
    while !sequence.is_empty() {
        let mut set=tagged(&mut sequence,17,true)?; let mut rdn=Vec::new();
        while !set.is_empty() {
            count+=1; if count>4096 { return Err("X.509 name attribute limit".into()) }
            let mut atv=tagged(&mut set,16,true)?;
            let parts=oid(tagged(&mut atv,6,false)?)?;
            let oid=parts.iter().map(u32::to_string).collect::<Vec<_>>().join(".");
            let value=attribute(element(&mut atv)?)?;
            rdn.push(Attribute { oid,value });
        }
        rdns.push(rdn);
    }
    let mut name=Name::default();name.fill_from_rdns(&rdns);Ok(name)
}
fn decimal_bytes(input:&[u8])->String { format!("[{}]",input.iter().map(u8::to_string).collect::<Vec<_>>().join(" ")) }
fn attribute(e:Element<'_>)->Result<AttributeValue,String> {
    if e.class==0 && !e.constructed && matches!(e.tag,12|18|19|20|22|30) {
        let text=match e.tag {
            20=>e.data.iter().map(|&b| char::from(b)).collect(),
            30=>{
                if e.data.len()%2!=0 { return Err("invalid BMPString".into()) }
                let data=e.data.strip_suffix(&[0,0]).unwrap_or(e.data);
                let mut out=String::new();
                for pair in data.chunks_exact(2) { let n=u16::from_be_bytes([pair[0],pair[1]]);
                    if matches!(n,0xd800..=0xdfff|0xfdd0..=0xfdef|0xfffe|0xffff) { return Err("invalid BMPString".into()) }
                    out.push(char::from_u32(u32::from(n)).ok_or("invalid BMPString")?);
                } out
            },
            tag=>{
                if (tag==18 && !e.data.iter().all(|b| b.is_ascii_digit()||*b==b' '))
                    || (tag==22 && !e.data.is_ascii())
                    || (tag==19 && !e.data.iter().all(|b| b.is_ascii_alphanumeric()||b"'()+,-./ :=?*&".contains(b))) { return Err("invalid ASN.1 string".into()) }
                std::str::from_utf8(e.data).map_err(|_|"invalid UTF8String")?.to_owned()
            }
        }; return Ok(AttributeValue::Text(text));
    }
    let mut der=Some(e.full.to_vec());
    let (native,display)=if e.class==0 && !e.constructed { match e.tag {
        2=>{
            if e.data.is_empty()||e.data.len()>8||(e.data.len()>1 && ((e.data[0]==0 && e.data[1]&128==0)||(e.data[0]==255&&e.data[1]&128!=0))) { return Err("invalid ASN.1 int64".into()) }
            let mut n=if e.data[0]&128!=0 {-1i64} else {0}; for &b in e.data {n=(n<<8)|i64::from(b)}
            (NativeValue::Int(n),n.to_string())
        },
        1=>{ let b=match e.data {[0]=>false,[255]=>true,_=>return Err("invalid ASN.1 boolean".into())};(NativeValue::Bool(b),b.to_string()) },
        5=>{der=None;(NativeValue::Null,"<nil>".into())},
        4=>(NativeValue::Bytes(e.data.to_vec()),decimal_bytes(e.data)),
        3=>{ let Some((&pad,bytes))=e.data.split_first() else{return Err("invalid ASN.1 bits".into())};
            if pad>7||(pad>0&&(bytes.is_empty()||bytes.last().is_some_and(|b|b&((1<<pad)-1)!=0))) { return Err("invalid ASN.1 bits".into()) }
            let bit_length=bytes.len()*8-usize::from(pad);
            (NativeValue::BitString{bytes:bytes.to_vec(),bit_length},format!("{{{} {bit_length}}}",decimal_bytes(bytes)))
        },
        6=>{let arcs=oid(e.data)?;let display=arcs.iter().map(u32::to_string).collect::<Vec<_>>().join(".");(NativeValue::Oid(arcs),display)},
        23|24=>{
            let digits=if e.tag==23 {12} else {14};
            if e.data.len()!=digits+1||e.data[digits]!=b'Z'||!e.data[..digits].iter().all(u8::is_ascii_digit) {return Err("invalid ASN.1 time".into())}
            let number=|at:usize,n:usize|e.data[at..at+n].iter().fold(0u32,|v,b|v*10+u32::from(*b-b'0'));
            let (year,at)=if e.tag==23 {let y=number(0,2);(if y<50 {2000+y} else {1900+y},2)} else {(number(0,4),4)};
            use chrono::TimeZone;
            let time=chrono::Utc.with_ymd_and_hms(year as i32,number(at,2),number(at+2,2),number(at+4,2),number(at+6,2),number(at+8,2)).single().ok_or("invalid ASN.1 time")?;
            let canonical=if (1950..=2049).contains(&year) {(23,time.format("%y%m%d%H%M%SZ").to_string())} else {(24,time.format("%Y%m%d%H%M%SZ").to_string())};
            let mut bytes=vec![canonical.0,canonical.1.len() as u8];bytes.extend_from_slice(canonical.1.as_bytes());der=Some(bytes);
            (NativeValue::Time{unix_seconds:time.timestamp(),nanoseconds:0},time.format("%Y-%m-%d %H:%M:%S +0000 UTC").to_string())
        },
        _=>raw_value(&e),
    }}else{raw_value(&e)};
    Ok(AttributeValue::Encoded{der,display,native})
}
fn raw_value(e:&Element<'_>)->(NativeValue,String) {
    (NativeValue::Raw{class:e.class,tag:e.tag,constructed:e.constructed,bytes:e.data.to_vec(),full:e.full.to_vec()},
        format!("{{{} {} {} {} {}}}",e.class,e.tag,e.constructed,decimal_bytes(e.data),decimal_bytes(e.full)))
}
