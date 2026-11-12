//! Map paths from the actual verifier to owned, bounded connection observations.
use rustls::{ChainUnavailable as Missing,ClientChainObservation as Observation,
    VerifiedChainRef,VerifiedChainSet,pki_types::CertificateDer,server::ClientPathEnumeration};
use std::sync::Arc;

pub(super) fn observe(leaf:&CertificateDer<'_>, intermediates:&[CertificateDer<'_>],
    roots:&[CertificateDer<'static>], enumeration:ClientPathEnumeration,
    binding:[u8;32],platform:bool)->Observation {
    if platform { return Observation::Unavailable(Missing::PlatformVerifier); }
    match build(leaf,intermediates,roots,enumeration,binding) {
        Ok(set)=>Observation::Verified(set),Err(reason)=>Observation::Unavailable(reason),
    }
}
fn build(leaf:&CertificateDer<'_>,intermediates:&[CertificateDer<'_>],
    roots:&[CertificateDer<'static>], enumeration:ClientPathEnumeration,
    binding:[u8;32])->Result<VerifiedChainSet,Missing> {
    if !enumeration.complete || enumeration.paths.len()>16 {
        return Err(Missing::EnumerationLimit);
    }
    let peer_len=intermediates.len().checked_add(1).ok_or(Missing::EnumerationLimit)?;
    if roots.iter().any(|root|root.as_ref()==leaf.as_ref()) {
        return VerifiedChainSet::new(vec![VerifiedChainRef{intermediates:vec![],root:None}],
            Arc::from([]),binding,peer_len).map_err(|_|Missing::TooLargeForSession);
    }
    let mut used=enumeration.paths.iter().map(|path|path.anchor_index).collect::<Vec<_>>();
    used.sort_unstable();used.dedup();
    let total=used.iter().try_fold(0usize,|sum,&index|sum.checked_add(roots.get(index)?.len()))
        .ok_or(Missing::RootSourceUnknown)?;
    if total>16*1024 {return Err(Missing::TooLargeForSession);}
    let leaf_facts=Facts::parse(leaf).ok_or(Missing::RootSourceUnknown)?;
    let inter_facts=intermediates.iter().map(Facts::parse).collect::<Option<Vec<_>>>()
        .ok_or(Missing::RootSourceUnknown)?;
    let root_facts=used.iter().map(|&index|Facts::parse(&roots[index]))
        .collect::<Option<Vec<_>>>().ok_or(Missing::RootSourceUnknown)?;
    struct Candidate<'a>{der:Vec<&'a[u8]>,key:Vec<(u8,u8,usize)>,inter:Vec<u8>,root:u8}
    let mut candidates:Vec<Candidate<'_>>=Vec::new();
    for path in enumeration.paths {
        let root_index=used.iter().position(|index|*index==path.anchor_index)
            .ok_or(Missing::RootSourceUnknown)?;
        let mut facts=vec![&leaf_facts];let mut der=vec![leaf.as_ref()];
        let mut key=Vec::new();let mut inter=Vec::new();let mut child=&leaf_facts;
        for index in path.intermediate_indexes {
            let cert=intermediates.get(index).ok_or(Missing::RootSourceUnknown)?;
            let parent=inter_facts.get(index).ok_or(Missing::RootSourceUnknown)?;
            let ordinal=intermediates.iter().position(|actual|actual.as_ref()==cert.as_ref())
                .ok_or(Missing::RootSourceUnknown)?;
            key.push((1,rank(child,parent),ordinal));child=parent;facts.push(parent);der.push(cert.as_ref());
            inter.push(u8::try_from(index+1).map_err(|_|Missing::EnumerationLimit)?);
        }
        let root=&root_facts[root_index];key.push((0,rank(child,root),path.anchor_index));
        facts.push(root);der.push(roots[path.anchor_index].as_ref());
        let repeated=facts.iter().enumerate().any(|(index,cert)|facts[index+1..].iter()
            .any(|other|cert.subject==other.subject&&cert.spki==other.spki&&cert.san==other.san));
        if repeated || candidates.iter().any(|candidate|candidate.der==der) {continue;}
        candidates.push(Candidate{der,key,inter,root:u8::try_from(root_index)
            .map_err(|_|Missing::EnumerationLimit)?});
    }
    if candidates.is_empty(){return Err(Missing::PolicyDivergence);}
    candidates.sort_by(|left,right|left.key.cmp(&right.key));
    let paths=candidates.into_iter().map(|candidate|VerifiedChainRef{
        intermediates:candidate.inter,root:Some(candidate.root)}).collect();
    let selected:Arc<[CertificateDer<'static>]>=used.into_iter().map(|index|roots[index].clone())
        .collect::<Vec<_>>().into();
    VerifiedChainSet::new(paths,selected,binding,peer_len).map_err(|_|Missing::TooLargeForSession)
}
struct Facts{subject:Vec<u8>,spki:Vec<u8>,san:Option<Vec<u8>>,aki:Vec<u8>,ski:Vec<u8>}
impl Facts{
    fn parse(der:&CertificateDer<'_>)->Option<Self>{
        use x509_parser::extensions::ParsedExtension;
        let (tail,cert)=x509_parser::parse_x509_certificate(der.as_ref()).ok()?;
        if !tail.is_empty(){return None;}
        let mut facts=Self{subject:cert.subject().as_raw().to_vec(),spki:cert.public_key().raw.to_vec(),
            san:None,aki:Vec::new(),ski:Vec::new()};
        for extension in cert.extensions(){
            if extension.oid.to_id_string()=="2.5.29.17" {facts.san=Some(extension.value.to_vec());}
            match extension.parsed_extension(){
                ParsedExtension::AuthorityKeyIdentifier(value)=>facts.aki=value.key_identifier.as_ref()
                    .map_or_else(Vec::new,|key|key.0.to_vec()),
                ParsedExtension::SubjectKeyIdentifier(value)=>facts.ski=value.0.to_vec(),_=>{},
            }
        }
        Some(facts)
    }
}
fn rank(child:&Facts,parent:&Facts)->u8{
    if child.aki==parent.ski {0}else if child.aki.is_empty()||parent.ski.is_empty(){1}else{2}
}
