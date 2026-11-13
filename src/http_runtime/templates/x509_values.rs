//! Lazy, owned public crypto/x509.Certificate projection. DER is parsed only on
//! the bounded template worker, after the same request owner prepays its peak.
#[path = "x509_values_hostname.rs"]
mod hostname;
#[path = "x509_values_numbers.rs"]
mod numbers;
#[path = "x509_values_public_key.rs"]
mod public_key_methods;
#[path = "x509_values_types.rs"]
mod types;
#[path = "x509_values_url.rs"]
mod urls;
use super::{Factory, RenderResult, arity, error};
use crate::http_runtime::client_cert_facts;
use gotmpl::{Object, Value, ValueFunc};
use std::{
    collections::BTreeMap,
    sync::{Arc, OnceLock},
};
const FIELDS: &[&str] = &[
    "Raw",
    "RawTBSCertificate",
    "RawSubjectPublicKeyInfo",
    "RawSubject",
    "RawIssuer",
    "RawSignatureAlgorithm",
    "Signature",
    "SignatureAlgorithm",
    "PublicKeyAlgorithm",
    "PublicKey",
    "Version",
    "SerialNumber",
    "Issuer",
    "Subject",
    "NotBefore",
    "NotAfter",
    "KeyUsage",
    "Extensions",
    "ExtraExtensions",
    "UnhandledCriticalExtensions",
    "ExtKeyUsage",
    "UnknownExtKeyUsage",
    "BasicConstraintsValid",
    "IsCA",
    "MaxPathLen",
    "MaxPathLenZero",
    "SubjectKeyId",
    "AuthorityKeyId",
    "OCSPServer",
    "IssuingCertificateURL",
    "DNSNames",
    "EmailAddresses",
    "IPAddresses",
    "URIs",
    "PermittedDNSDomainsCritical",
    "PermittedDNSDomains",
    "ExcludedDNSDomains",
    "PermittedIPRanges",
    "ExcludedIPRanges",
    "PermittedEmailAddresses",
    "ExcludedEmailAddresses",
    "PermittedURIDomains",
    "ExcludedURIDomains",
    "CRLDistributionPoints",
    "PolicyIdentifiers",
    "Policies",
    "InhibitAnyPolicy",
    "InhibitAnyPolicyZero",
    "InhibitPolicyMapping",
    "InhibitPolicyMappingZero",
    "RequireExplicitPolicy",
    "RequireExplicitPolicyZero",
    "PolicyMappings",
];
pub(super) struct Certificate {
    der: Arc<[u8]>,
    raw: gotmpl::TypedSlice,
    fields: OnceLock<Result<Arc<BTreeMap<Arc<str>, Value>>, Arc<str>>>,
}
impl Certificate {
    pub(super) fn new(der: Arc<[u8]>) -> Arc<Self> {
        Arc::new(Self {
            raw: gotmpl::TypedSlice::bytes(Some(der.clone())),
            der,
            fields: OnceLock::new(),
        })
    }
    fn fields(&self, factory: &Arc<Factory>) -> RenderResult<Arc<BTreeMap<Arc<str>, Value>>> {
        self.fields
            .get_or_init(|| {
                parse(factory, self.der.clone(), &self.raw)
                    .map(Arc::new)
                    .map_err(|e| Arc::from(e.to_string()))
            })
            .clone()
            .map_err(|e| error(e.as_ref()))
    }
}
struct Receiver {
    factory: Arc<Factory>,
    certificate: Arc<Certificate>,
}
pub(super) fn value(factory: &Arc<Factory>, certificate: Arc<Certificate>) -> RenderResult<Value> {
    factory.reserve(8192)?;
    let receiver = Arc::new(Receiver {
        factory: factory.clone(),
        certificate,
    });
    let identity = Arc::as_ptr(&receiver.certificate) as usize;
    let dynamic = receiver.clone();
    let weak = factory.control.clone();
    let mut methods = BTreeMap::<Arc<str>, ValueFunc>::new();
    for name in [
        "Equal",
        "VerifyHostname",
        "CheckSignatureFrom",
        "CheckSignature",
    ] {
        let receiver = receiver.clone();
        methods.insert(
            name.into(),
            Arc::new(move |args| method(&receiver, name, args)),
        );
    }
    Ok(Value::Object(Arc::new(Object {
        fields: FIELDS
            .iter()
            .map(|name| (Arc::from(*name), Value::Nil))
            .collect(),
        field_order: Some(
            FIELDS
                .iter()
                .map(|name| Arc::from(*name))
                .collect::<Vec<_>>()
                .into(),
        ),
        go_type: Some("*x509.Certificate"),
        pointer_identity: Some(identity),
        lazy_fields: true,
        dynamic_fields: Some(Arc::new(move |name| {
            dynamic.factory.work(1)?;
            if name == "Raw" {
                return Ok(Some({
                    dynamic.factory.reserve(128)?;
                    Value::Slice(dynamic.certificate.raw.clone())
                }));
            }
            Ok(dynamic
                .certificate
                .fields(&dynamic.factory)?
                .get(name)
                .cloned())
        })),
        field_charge: Some(Arc::new(move |_| {
            weak.upgrade()
                .ok_or_else(|| error("certificate template owner retired"))?
                .check()
        })),
        method_signatures: BTreeMap::from([
            (
                "VerifyHostname".into(),
                gotmpl::Signature::from_static(&[gotmpl::ArgKind::String], None),
            ),
            (
                "CheckSignature".into(),
                gotmpl::Signature::new(
                    vec![
                        gotmpl::ArgKind::NamedInt64("x509.SignatureAlgorithm", |n| {
                            numbers::enumeration("x509.SignatureAlgorithm", n)
                        }),
                        gotmpl::ArgKind::Any,
                        gotmpl::ArgKind::Any,
                    ],
                    None,
                ),
            ),
        ]),
        methods,
        data: Some(receiver),
        data_bytes: 128,
        ..Object::default()
    })))
}

fn values(factory: &Arc<Factory>, name: &'static str, values: Vec<Value>) -> RenderResult<Value> {
    let nil = values.is_empty();
    factory.reserve(values.len() * (std::mem::size_of::<Value>() * 2 + 64) + 256)?;
    types::list(factory, name, values, nil)
}
fn parse(
    factory: &Arc<Factory>,
    der: Arc<[u8]>,
    backing: &gotmpl::TypedSlice,
) -> RenderResult<BTreeMap<Arc<str>, Value>> {
    let peak = der
        .len()
        .checked_mul(128)
        .and_then(|n| n.checked_add(65536))
        .ok_or_else(|| error("certificate parse budget overflow"))?;
    factory.reserve(peak)?;
    factory.work(
        der.len()
            .checked_mul(8)
            .ok_or_else(|| error("certificate parse work overflow"))?,
    )?;
    let (remaining, cert) = x509_parser::parse_x509_certificate(&der)
        .map_err(|e| error(format!("certificate projection: {e}")))?;
    if !remaining.is_empty() {
        return Err(error("certificate projection trailing DER"));
    }
    let raw = |factory: &Arc<Factory>, bytes: &[u8]| -> RenderResult<Value> {
        factory.reserve(128)?;
        let offset = (bytes.as_ptr() as usize)
            .checked_sub(der.as_ptr() as usize)
            .ok_or_else(|| error("DER view before certificate backing"))?;
        let end = offset
            .checked_add(bytes.len())
            .filter(|end| *end <= der.len())
            .ok_or_else(|| error("DER view outside certificate backing"))?;
        Ok(Value::Slice(backing.reslice(offset, end)?))
    };
    let mut result = BTreeMap::new();
    for (name, kind) in [
        ("ExtraExtensions", "[]pkix.Extension"),
        ("UnhandledCriticalExtensions", "[]asn1.ObjectIdentifier"),
        ("ExtKeyUsage", "[]x509.ExtKeyUsage"),
        ("UnknownExtKeyUsage", "[]asn1.ObjectIdentifier"),
        ("OCSPServer", "[]string"),
        ("IssuingCertificateURL", "[]string"),
        ("DNSNames", "[]string"),
        ("EmailAddresses", "[]string"),
        ("IPAddresses", "[]net.IP"),
        ("URIs", "[]*url.URL"),
        ("PermittedDNSDomains", "[]string"),
        ("ExcludedDNSDomains", "[]string"),
        ("PermittedIPRanges", "[]*net.IPNet"),
        ("ExcludedIPRanges", "[]*net.IPNet"),
        ("PermittedEmailAddresses", "[]string"),
        ("ExcludedEmailAddresses", "[]string"),
        ("PermittedURIDomains", "[]string"),
        ("ExcludedURIDomains", "[]string"),
        ("CRLDistributionPoints", "[]string"),
        ("PolicyIdentifiers", "[]asn1.ObjectIdentifier"),
        ("Policies", "[]x509.OID"),
        ("PolicyMappings", "[]x509.PolicyMapping"),
    ] {
        result.insert(Arc::from(name), Value::Slice(gotmpl::TypedSlice::nil(kind)));
    }
    for name in [
        "BasicConstraintsValid",
        "IsCA",
        "MaxPathLenZero",
        "PermittedDNSDomainsCritical",
        "InhibitAnyPolicyZero",
        "InhibitPolicyMappingZero",
        "RequireExplicitPolicyZero",
    ] {
        result.insert(name.into(), Value::Bool(false));
    }
    for name in [
        "MaxPathLen",
        "InhibitAnyPolicy",
        "InhibitPolicyMapping",
        "RequireExplicitPolicy",
    ] {
        result.insert(name.into(), Value::Int(0));
    }
    for name in ["SubjectKeyId", "AuthorityKeyId"] {
        result.insert(
            name.into(),
            Value::Slice(gotmpl::TypedSlice::nil("[]uint8")),
        );
    }
    let mut outer = der_element(&der)?.1;
    let (_, _, tbs) = take(&mut outer)?;
    let (_, outer_algorithm, _) = take(&mut outer)?;
    let mut tbs = tbs;
    let (tag, _, _) = take(&mut tbs)?;
    if tag == 0xa0 {
        let (tag, _, _) = take(&mut tbs)?;
        if tag != 2 {
            return Err(error("invalid certificate serial tag"));
        }
    } else if tag != 2 {
        return Err(error("invalid certificate serial tag"));
    }
    let (tag, signature_algorithm, _) = take(&mut tbs)?;
    if tag != 0x30 || signature_algorithm != outer_algorithm {
        return Err(error(
            "X.509 inner and outer signature algorithm identifiers differ",
        ));
    }
    for (name, bytes) in [
        ("Raw", der.as_ref()),
        ("RawTBSCertificate", cert.tbs_certificate.as_ref()),
        ("RawSubjectPublicKeyInfo", cert.public_key().raw),
        ("RawSubject", cert.subject().as_raw()),
        ("RawIssuer", cert.issuer().as_raw()),
        ("RawSignatureAlgorithm", signature_algorithm),
        ("Signature", cert.signature_value.data.as_ref()),
    ] {
        result.insert(name.into(), raw(factory, bytes)?);
    }
    result.insert(
        "Version".into(),
        Value::Int(i64::from(cert.version().0) + 1),
    );
    result.insert(
        "SerialNumber".into(),
        numbers::integer(factory, cert.raw_serial(), true)?,
    );
    result.insert(
        "Issuer".into(),
        types::name(
            factory,
            &client_cert_facts::parse_name(cert.issuer().as_raw()).map_err(error)?,
        )?,
    );
    result.insert(
        "Subject".into(),
        types::name(
            factory,
            &client_cert_facts::parse_name(cert.subject().as_raw()).map_err(error)?,
        )?,
    );
    let before = cert.validity().not_before.to_datetime();
    let after = cert.validity().not_after.to_datetime();
    result.insert(
        "NotBefore".into(),
        types::time_value(factory, before.unix_timestamp(), before.nanosecond())?,
    );
    result.insert(
        "NotAfter".into(),
        types::time_value(factory, after.unix_timestamp(), after.nanosecond())?,
    );
    let signature = signature_algorithm_id(&cert.signature_algorithm)?;
    result.insert(
        "SignatureAlgorithm".into(),
        numbers::enumeration("x509.SignatureAlgorithm", signature),
    );
    let pki = cert.public_key();
    let pki_oid = pki.algorithm.algorithm.to_id_string();
    let public_kind = match pki_oid.as_str() {
        "1.2.840.113549.1.1.1" => 1,
        "1.2.840.10040.4.1" => 2,
        "1.2.840.10045.2.1" => 3,
        "1.3.101.112" => 4,
        "2.16.840.1.101.3.4.3.17" | "2.16.840.1.101.3.4.3.18" | "2.16.840.1.101.3.4.3.19" => 5,
        _ => 0,
    };
    result.insert(
        "PublicKeyAlgorithm".into(),
        numbers::enumeration("x509.PublicKeyAlgorithm", public_kind),
    );
    let public = if public_kind == 4 {
        let Value::Slice(slice) = raw(factory, pki.subject_public_key.data.as_ref())? else {
            unreachable!()
        };
        types::bind(factory, slice.with_named_bytes(&ED25519_TYPE)?)?
    } else {
        public_key(factory, pki, public_kind)?
    };
    result.insert("PublicKey".into(), public);
    result.insert("KeyUsage".into(), numbers::enumeration("x509.KeyUsage", 0));
    let mut extensions = Vec::with_capacity(cert.extensions().len());
    let mut unhandled = Vec::new();
    for ext in cert.extensions() {
        factory.work(1)?;
        let oid = ext.oid.to_id_string();
        extensions.push(Value::Object(Arc::new(Object {
            fields: BTreeMap::from([
                ("Id".into(), types::oid(factory, &oid)?),
                ("Critical".into(), Value::Bool(ext.critical)),
                ("Value".into(), raw(factory, ext.value)?),
            ]),
            go_type: Some("pkix.Extension"),
            field_order: Some([Arc::from("Id"), Arc::from("Critical"), Arc::from("Value")].into()),
            ..Object::default()
        })));
        use x509_parser::extensions::{GeneralName as G, ParsedExtension as E};
        let mut handled = true;
        match oid.as_str() {
            "2.5.29.15" => {
                let E::KeyUsage(usage) = ext.parsed_extension() else {
                    return Err(error("invalid X.509 key usage"));
                };
                result.insert(
                    "KeyUsage".into(),
                    numbers::enumeration("x509.KeyUsage", i64::from(usage.flags)),
                );
            }
            "2.5.29.19" => {
                let E::BasicConstraints(b) = ext.parsed_extension() else {
                    return Err(error("invalid X.509 basic constraints"));
                };
                result.insert("BasicConstraintsValid".into(), Value::Bool(true));
                result.insert("IsCA".into(), Value::Bool(b.ca));
                result.insert(
                    "MaxPathLen".into(),
                    Value::Int(b.path_len_constraint.map_or(-1, i64::from)),
                );
                result.insert(
                    "MaxPathLenZero".into(),
                    Value::Bool(b.path_len_constraint == Some(0)),
                );
            }
            "2.5.29.14" => {
                let E::SubjectKeyIdentifier(k) = ext.parsed_extension() else {
                    return Err(error("invalid X.509 subject key identifier"));
                };
                result.insert("SubjectKeyId".into(), raw(factory, k.0)?);
            }
            "2.5.29.35" => {
                let E::AuthorityKeyIdentifier(k) = ext.parsed_extension() else {
                    return Err(error("invalid X.509 authority key identifier"));
                };
                if let Some(key) = &k.key_identifier {
                    result.insert("AuthorityKeyId".into(), raw(factory, key.0)?);
                }
            }
            "2.5.29.17" => {
                let E::SubjectAlternativeName(san) = ext.parsed_extension() else {
                    return Err(error("invalid X.509 subject alternate name"));
                };
                let (mut dns, mut emails, mut ips, mut uris) =
                    (Vec::new(), Vec::new(), Vec::new(), Vec::new());
                for name in &san.general_names {
                    match name {
                        G::DNSName(s) => dns.push((*s).to_owned()),
                        G::RFC822Name(s) => emails.push((*s).to_owned()),
                        G::IPAddress(bytes) => {
                            if !matches!(bytes.len(), 4 | 16)
                                || bytes.len() == 16
                                    && bytes[..10] == [0; 10]
                                    && bytes[10..12] == [255, 255]
                            {
                                return Err(error("invalid X.509 SAN IP"));
                            }
                            let Value::Slice(view) = raw(factory, bytes)? else {
                                return Err(error("invalid IP DER view"));
                            };
                            ips.push(types::ip_view(factory, view)?);
                        }
                        G::URI(s) => uris.push(urls::value(factory, s)?),
                        _ => {}
                    }
                }
                handled =
                    !dns.is_empty() || !emails.is_empty() || !ips.is_empty() || !uris.is_empty();
                result.insert("DNSNames".into(), types::strings(factory, &dns)?);
                result.insert("EmailAddresses".into(), types::strings(factory, &emails)?);
                result.insert("IPAddresses".into(), values(factory, "[]net.IP", ips)?);
                result.insert("URIs".into(), values(factory, "[]*url.URL", uris)?);
            }
            "2.5.29.37" => {
                let mut input = der_element(ext.value)?.1;
                let (mut known, mut unknown) = (Vec::new(), Vec::new());
                while !input.is_empty() {
                    let (tag, _, body) = take(&mut input)?;
                    if tag != 6 {
                        return Err(error("invalid X.509 extended key usage"));
                    }
                    let text = oid_text(body)?;
                    if let Some(value) = numbers::eku_oid(&text) {
                        known.push(numbers::enumeration("x509.ExtKeyUsage", value));
                    } else {
                        unknown.push(types::oid(factory, &text)?);
                    }
                }
                result.insert(
                    "ExtKeyUsage".into(),
                    values(factory, "[]x509.ExtKeyUsage", known)?,
                );
                result.insert(
                    "UnknownExtKeyUsage".into(),
                    values(factory, "[]asn1.ObjectIdentifier", unknown)?,
                );
            }
            "1.3.6.1.5.5.7.1.1" => {
                let E::AuthorityInfoAccess(aia) = ext.parsed_extension() else {
                    return Err(error("invalid X.509 authority information access"));
                };
                let (mut ocsp, mut issuers) = (Vec::new(), Vec::new());
                for entry in &aia.accessdescs {
                    if let G::URI(uri) = entry.access_location {
                        match entry.access_method.to_id_string().as_str() {
                            "1.3.6.1.5.5.7.48.1" => ocsp.push(uri.to_owned()),
                            "1.3.6.1.5.5.7.48.2" => issuers.push(uri.to_owned()),
                            _ => {}
                        }
                    }
                }
                result.insert("OCSPServer".into(), types::strings(factory, &ocsp)?);
                result.insert(
                    "IssuingCertificateURL".into(),
                    types::strings(factory, &issuers)?,
                );
            }
            "2.5.29.30" => {
                let E::NameConstraints(nc) = ext.parsed_extension() else {
                    return Err(error("invalid X.509 name constraints"));
                };
                result.insert(
                    "PermittedDNSDomainsCritical".into(),
                    Value::Bool(ext.critical),
                );
                let mut unknown = false;
                for (prefix, subtrees) in [
                    ("Permitted", &nc.permitted_subtrees),
                    ("Excluded", &nc.excluded_subtrees),
                ] {
                    let (mut dns, mut emails, mut uris, mut ips) =
                        (Vec::new(), Vec::new(), Vec::new(), Vec::new());
                    if let Some(subtrees) = subtrees {
                        for subtree in subtrees {
                            match &subtree.base {
                                G::DNSName(s) => dns.push((*s).to_owned()),
                                G::RFC822Name(s) => emails.push((*s).to_owned()),
                                G::URI(s) => uris.push((*s).to_owned()),
                                G::IPAddress(bytes) => {
                                    if !matches!(bytes.len(), 8 | 32) {
                                        return Err(error("invalid X.509 IP constraint"));
                                    }
                                    let Value::Slice(view) = raw(factory, bytes)? else {
                                        return Err(error("invalid constraint DER view"));
                                    };
                                    let n = bytes.len() / 2;
                                    let mask = &bytes[n..];
                                    let mut zero = false;
                                    for b in mask {
                                        for bit in (0..8).rev() {
                                            if b & (1 << bit) != 0 {
                                                if zero {
                                                    return Err(error(
                                                        "invalid X.509 IP constraint mask",
                                                    ));
                                                }
                                            } else {
                                                zero = true;
                                            }
                                        }
                                    }
                                    ips.push(types::ip_net_view(
                                        factory,
                                        view.reslice(0, n)?,
                                        view.reslice(n, bytes.len())?,
                                    )?);
                                }
                                _ => unknown = true,
                            }
                        }
                    }
                    result.insert(
                        format!("{prefix}DNSDomains").into(),
                        types::strings(factory, &dns)?,
                    );
                    result.insert(
                        format!("{prefix}EmailAddresses").into(),
                        types::strings(factory, &emails)?,
                    );
                    result.insert(
                        format!("{prefix}URIDomains").into(),
                        types::strings(factory, &uris)?,
                    );
                    result.insert(
                        format!("{prefix}IPRanges").into(),
                        values(factory, "[]*net.IPNet", ips)?,
                    );
                }
                handled = !unknown;
            }
            "2.5.29.31" => {
                let E::CRLDistributionPoints(points) = ext.parsed_extension() else {
                    return Err(error("invalid X.509 CRL distribution points"));
                };
                let mut urls = Vec::new();
                for point in &points.points {
                    if let Some(x509_parser::extensions::DistributionPointName::FullName(names)) =
                        &point.distribution_point
                    {
                        for name in names {
                            if let G::URI(uri) = name {
                                urls.push((*uri).to_owned());
                            }
                        }
                    }
                }
                result.insert(
                    "CRLDistributionPoints".into(),
                    types::strings(factory, &urls)?,
                );
            }
            "2.5.29.32" => {
                let mut seq = der_element(ext.value)?.1;
                let (mut policies, mut legacy) = (Vec::new(), Vec::new());
                while !seq.is_empty() {
                    let (_, _, body) = take(&mut seq)?;
                    let mut body = body;
                    let (tag, _, oid) = take(&mut body)?;
                    if tag != 6 {
                        return Err(error("invalid X.509 policy OID"));
                    }
                    let text = oid_text(oid)?;
                    policies.push(policy_oid(factory, &text, oid)?);
                    if text
                        .split('.')
                        .all(|arc| arc.parse::<u32>().is_ok_and(|v| v <= i32::MAX as u32))
                    {
                        legacy.push(types::oid(factory, &text)?);
                    }
                }
                result.insert("Policies".into(), values(factory, "[]x509.OID", policies)?);
                result.insert(
                    "PolicyIdentifiers".into(),
                    values(factory, "[]asn1.ObjectIdentifier", legacy)?,
                );
            }
            "2.5.29.33" => {
                let mut seq = der_element(ext.value)?.1;
                let mut mappings = Vec::new();
                while !seq.is_empty() {
                    let (_, _, body) = take(&mut seq)?;
                    let mut body = body;
                    let (tag, _, issuer) = take(&mut body)?;
                    let (tag2, _, subject) = take(&mut body)?;
                    if tag != 6 || tag2 != 6 || !body.is_empty() {
                        return Err(error("invalid X.509 policy mapping"));
                    }
                    mappings.push(Value::Object(Arc::new(Object {
                        fields: BTreeMap::from([
                            (
                                "IssuerDomainPolicy".into(),
                                policy_oid(factory, &oid_text(issuer)?, issuer)?,
                            ),
                            (
                                "SubjectDomainPolicy".into(),
                                policy_oid(factory, &oid_text(subject)?, subject)?,
                            ),
                        ]),
                        go_type: Some("x509.PolicyMapping"),
                        ..Object::default()
                    })));
                }
                result.insert(
                    "PolicyMappings".into(),
                    values(factory, "[]x509.PolicyMapping", mappings)?,
                );
            }
            "2.5.29.36" => {
                let mut body = der_element(ext.value)?.1;
                while !body.is_empty() {
                    let (tag, _, value) = take(&mut body)?;
                    let field = match tag {
                        0x80 => "RequireExplicitPolicy",
                        0x81 => "InhibitPolicyMapping",
                        _ => return Err(error("invalid X.509 policy constraint tag")),
                    };
                    let value = small_integer(value)?;
                    result.insert(field.into(), Value::Int(value));
                    result.insert(format!("{field}Zero").into(), Value::Bool(value == 0));
                }
            }
            "2.5.29.54" => {
                let (_, body, _) = der_element(ext.value)?;
                let value = small_integer(body)?;
                result.insert("InhibitAnyPolicy".into(), Value::Int(value));
                result.insert("InhibitAnyPolicyZero".into(), Value::Bool(value == 0));
            }
            _ => handled = false,
        }
        if ext.critical && !handled {
            unhandled.push(types::oid(factory, &oid)?);
        }
    }
    result.insert(
        "Extensions".into(),
        values(factory, "[]pkix.Extension", extensions)?,
    );
    result.insert(
        "UnhandledCriticalExtensions".into(),
        values(factory, "[]asn1.ObjectIdentifier", unhandled)?,
    );
    if result.len() != FIELDS.len() {
        return Err(error("incomplete X.509 public field projection"));
    }
    Ok(result)
}
// Strict, borrowed DER TLV access for original signed bytes and extension OIDs.
fn der_element(s: &[u8]) -> RenderResult<(u8, &[u8], &[u8])> {
    let tag = *s
        .first()
        .ok_or_else(|| error("truncated certificate DER"))?;
    let first = *s
        .get(1)
        .ok_or_else(|| error("truncated certificate DER length"))?;
    let (mut at, mut len) = (2, usize::from(first));
    if first & 128 != 0 {
        let n = usize::from(first & 127);
        if n == 0 || n > 8 {
            return Err(error("invalid certificate DER length"));
        }
        len = 0;
        for i in 0..n {
            let b = *s
                .get(at + i)
                .ok_or_else(|| error("truncated certificate DER length"))?;
            if i == 0 && b == 0 {
                return Err(error("nonminimal certificate DER length"));
            }
            len = len
                .checked_mul(256)
                .and_then(|v| v.checked_add(usize::from(b)))
                .ok_or_else(|| error("certificate DER length overflow"))?;
        }
        at += n;
        if len < 128 {
            return Err(error("nonminimal certificate DER length"));
        }
    }
    let end = at
        .checked_add(len)
        .filter(|n| *n <= s.len())
        .ok_or_else(|| error("truncated certificate DER value"))?;
    Ok((tag, &s[at..end], &s[end..]))
}
fn take<'a>(input: &mut &'a [u8]) -> RenderResult<(u8, &'a [u8], &'a [u8])> {
    let original = *input;
    let (tag, body, rest) = der_element(original)?;
    let full = &original[..original.len() - rest.len()];
    *input = rest;
    Ok((tag, full, body))
}
fn small_integer(bytes: &[u8]) -> RenderResult<i64> {
    if bytes.is_empty() || bytes.len() > 8 {
        return Err(error("X.509 integer outside Go int"));
    }
    let mut n = if bytes[0] & 128 != 0 { -1i64 } else { 0 };
    for b in bytes {
        n = (n << 8) | i64::from(*b);
    }
    Ok(n)
}
fn oid_text(bytes: &[u8]) -> RenderResult<String> {
    use bigdecimal::num_bigint::BigUint;
    let mut values = Vec::new();
    let mut n = BigUint::from(0u8);
    let mut end = true;
    for b in bytes {
        n = (n << 7usize) + BigUint::from(b & 127);
        end = b & 128 == 0;
        if end {
            if values.is_empty() {
                let forty = BigUint::from(40u8);
                let two = BigUint::from(2u8);
                let first = (&n / &forty).min(two);
                values.push(first.to_string());
                values.push((&n - &first * &forty).to_string());
            } else {
                values.push(n.to_string());
            }
            n = BigUint::from(0u8);
        }
    }
    if !end || values.is_empty() {
        return Err(error("invalid certificate OID"));
    }
    Ok(values.join("."))
}
fn signature_algorithm_id(ai: &x509_parser::x509::AlgorithmIdentifier<'_>) -> RenderResult<i64> {
    let oid = ai.algorithm.to_id_string();
    if oid == "1.3.101.112"
        || matches!(
            oid.as_str(),
            "2.16.840.1.101.3.4.3.17" | "2.16.840.1.101.3.4.3.18" | "2.16.840.1.101.3.4.3.19"
        )
    {
        if ai.parameters.is_some() {
            return Ok(0);
        }
    }
    if oid != "1.2.840.113549.1.1.10" {
        return Ok(numbers::signature_oid(&oid).unwrap_or(0));
    }
    let Some(params) = &ai.parameters else {
        return Ok(0);
    };
    let mut body = params.data;
    let (mut hash, mut mgf, mut salt, mut trailer) = (String::new(), String::new(), 20i64, 1i64);
    while !body.is_empty() {
        let (tag, _, value) = take(&mut body)?;
        match tag {
            0xa0 => {
                hash = algorithm_oid(value)?;
            }
            0xa1 => {
                let mut seq = der_element(value)?.1;
                let (tag, _, oid) = take(&mut seq)?;
                if tag != 6 || oid_text(oid)? != "1.2.840.113549.1.1.8" {
                    return Ok(0);
                }
                mgf = algorithm_oid(seq)?;
            }
            0xa2 => salt = small_integer(der_element(value)?.1)?,
            0xa3 => trailer = small_integer(der_element(value)?.1)?,
            _ => return Ok(0),
        }
    }
    if hash != mgf || trailer != 1 {
        return Ok(0);
    }
    Ok(match (hash.as_str(), salt) {
        ("2.16.840.1.101.3.4.2.1", 32) => 13,
        ("2.16.840.1.101.3.4.2.2", 48) => 14,
        ("2.16.840.1.101.3.4.2.3", 64) => 15,
        _ => 0,
    })
}
fn algorithm_oid(der: &[u8]) -> RenderResult<String> {
    let mut seq = der_element(der)?.1;
    let (tag, _, oid) = take(&mut seq)?;
    if tag != 6 || !seq.is_empty() && seq != [5, 0] {
        return Ok(String::new());
    }
    oid_text(oid)
}
#[derive(Clone)]
struct PolicyOid {
    der: Arc<[u8]>,
    text: Arc<str>,
}
fn policy_oid(factory: &Arc<Factory>, text: &str, der: &[u8]) -> RenderResult<Value> {
    factory.reserve(der.len() * 8 + text.len() * 4 + 4096)?;
    let data = Arc::new(PolicyOid {
        der: der.into(),
        text: text.into(),
    });
    let mut methods = BTreeMap::<Arc<str>, ValueFunc>::new();
    for name in [
        "String",
        "MarshalText",
        "MarshalBinary",
        "Equal",
        "EqualASN1OID",
        "AppendText",
        "AppendBinary",
    ] {
        let owner = Arc::downgrade(factory);
        let data = data.clone();
        methods.insert(
            name.into(),
            Arc::new(move |args| {
                arity(
                    args,
                    usize::from(matches!(
                        name,
                        "Equal" | "EqualASN1OID" | "AppendText" | "AppendBinary"
                    )),
                    usize::from(matches!(
                        name,
                        "Equal" | "EqualASN1OID" | "AppendText" | "AppendBinary"
                    )),
                )?;
                let f = owner
                    .upgrade()
                    .ok_or_else(|| error("certificate owner retired"))?;
                f.reserve((data.der.len() + data.text.len()) * 4 + 1024)?;
                match name {
                    "String" => Ok(Value::String(data.text.clone())),
                    "MarshalText" => f.byte_slice(Arc::from(data.text.as_bytes()), false),
                    "MarshalBinary" => f.byte_slice(data.der.clone(), false),
                    "Equal" => {
                        let Value::Object(other) = &args[0] else {
                            return Err(error("expected x509.OID"));
                        };
                        let other = other
                            .host_data::<PolicyOid>("x509.OID")
                            .ok_or_else(|| error("expected x509.OID"))?;
                        Ok(Value::Bool(data.der == other.der))
                    }
                    "EqualASN1OID" => {
                        if matches!(args[0], Value::Nil) {
                            return Ok(Value::Bool(false));
                        }
                        let Value::Slice(other) = &args[0] else {
                            return Err(error("expected asn1.ObjectIdentifier"));
                        };
                        if !matches!(other.go_type(), "asn1.ObjectIdentifier" | "[]int") {
                            return Err(error("expected asn1.ObjectIdentifier"));
                        }
                        f.reserve(
                            other
                                .len()
                                .checked_mul(64)
                                .and_then(|n| n.checked_add(512))
                                .ok_or_else(|| error("OID comparison budget overflow"))?,
                        )?;
                        let text = other
                            .iter()
                            .map(|v| {
                                v.as_int()
                                    .map(|n| n.to_string())
                                    .ok_or_else(|| error("expected OID integer"))
                            })
                            .collect::<RenderResult<Vec<_>>>()?
                            .join(".");
                        Ok(Value::Bool(data.text.as_ref() == text))
                    }
                    "AppendText" | "AppendBinary" => f.append_bytes(
                        &args[0],
                        if name == "AppendText" {
                            data.text.as_bytes()
                        } else {
                            data.der.as_ref()
                        },
                    ),
                    _ => Err(error("unknown X.509 OID method")),
                }
            }),
        );
    }
    Ok(Value::Object(Arc::new(Object {
        go_type: Some("x509.OID"),
        display: Some(text.into()),
        json: Some(Ok(serde_json::to_string(text)
            .map_err(|e| error(e.to_string()))?
            .into())),
        methods,
        data: Some(data),
        data_bytes: der.len() + text.len() + 128,
        ..Object::default()
    })))
}
#[derive(Clone)]
struct PublicKeyData {
    kind: i64,
    der: Arc<[u8]>,
}
fn public_key(
    factory: &Arc<Factory>,
    pki: &x509_parser::x509::SubjectPublicKeyInfo<'_>,
    kind: i64,
) -> RenderResult<Value> {
    factory.reserve(pki.raw.len() * 32 + 32768)?;
    if kind == 0 {
        return Ok(Value::Nil);
    }
    if kind == 4 {
        return ed25519(factory, pki.subject_public_key.data.as_ref());
    }
    let mut fields = BTreeMap::new();
    let go_type = match kind {
        1 => {
            let mut seq = der_element(pki.subject_public_key.data.as_ref())?.1;
            let (n_tag, _, n) = take(&mut seq)?;
            let (e_tag, _, e) = take(&mut seq)?;
            if n_tag != 2
                || e_tag != 2
                || !seq.is_empty()
                || n.is_empty()
                || n[0] & 128 != 0
                || n.iter().all(|b| *b == 0)
                || small_integer(e)? <= 0
            {
                return Err(error("invalid X.509 RSA public key"));
            }
            fields.insert("N".into(), numbers::integer(factory, n, false)?);
            fields.insert("E".into(), Value::Int(small_integer(e)?));
            "*rsa.PublicKey"
        }
        2 => {
            let params = pki
                .algorithm
                .parameters
                .as_ref()
                .ok_or_else(|| error("missing DSA parameters"))?;
            let mut seq = params.data;
            let mut parameters = BTreeMap::new();
            for name in ["P", "Q", "G"] {
                let (tag, _, bytes) = take(&mut seq)?;
                if tag != 2 {
                    return Err(error("invalid DSA parameter"));
                }
                parameters.insert(name.into(), numbers::integer(factory, bytes, false)?);
            }
            let (_, y, _) = der_element(pki.subject_public_key.data.as_ref())?;
            fields.insert(
                "Parameters".into(),
                Value::Object(Arc::new(Object {
                    fields: parameters.clone(),
                    go_type: Some("dsa.Parameters"),
                    field_order: Some(["P", "Q", "G"].map(Arc::from).into()),
                    ..Object::default()
                })),
            );
            for (name, value) in parameters {
                fields.insert(name, value);
            }
            fields.insert("Y".into(), numbers::integer(factory, y, false)?);
            "*dsa.PublicKey"
        }
        3 => {
            let key = openssl::pkey::PKey::public_key_from_der(pki.raw)
                .map_err(|e| error(e.to_string()))?
                .ec_key()
                .map_err(|e| error(e.to_string()))?;
            let group = key.group();
            let mut ctx = openssl::bn::BigNumContext::new().map_err(|e| error(e.to_string()))?;
            let (mut x, mut y) = (
                openssl::bn::BigNum::new().map_err(|e| error(e.to_string()))?,
                openssl::bn::BigNum::new().map_err(|e| error(e.to_string()))?,
            );
            key.public_key()
                .affine_coordinates_gfp(group, &mut x, &mut y, &mut ctx)
                .map_err(|e| error(e.to_string()))?;
            fields.insert("X".into(), numbers::coordinate_integer(factory,&x.to_vec(),usize::try_from(group.degree()).map_err(|_|error("curve size overflow"))?.div_ceil(8))?);
            fields.insert("Y".into(), numbers::coordinate_integer(factory,&y.to_vec(),usize::try_from(group.degree()).map_err(|_|error("curve size overflow"))?.div_ceil(8))?);
            fields.insert("Curve".into(), curve_value(factory, group)?);
            "*ecdsa.PublicKey"
        }
        5 => "*mldsa.PublicKey",
        _ => return Err(error("unsupported certificate public key projection")),
    };
    let data = Arc::new(PublicKeyData {
        kind,
        der: pki.raw.into(),
    });
    let own_fields = Arc::new(fields.clone());
    let mut methods = BTreeMap::<Arc<str>, ValueFunc>::new();
    if kind != 2 {
        let owner = Arc::downgrade(factory);
        let original = data.clone();
        let fields = own_fields.clone();
        methods.insert(
            "Equal".into(),
            Arc::new(move |args| {
                arity(args, 1, 1)?;
                let factory = owner
                    .upgrade()
                    .ok_or_else(|| error("certificate owner retired"))?;
                let Value::Object(other) = &args[0] else {
                    return Ok(Value::Bool(false));
                };
                Ok(Value::Bool(public_key_methods::equal(
                    &factory, kind, &fields, &original, other,
                )?))
            }),
        );
    }
    if kind == 1 {
        let fields = own_fields.clone();
        methods.insert(
            "Size".into(),
            Arc::new(move |args| {
                arity(args, 0, 0)?;
                Ok(Value::Int(public_key_methods::rsa_size(&fields)? as i64))
            }),
        );
    }
    if kind == 3 {
        let fields = own_fields.clone();
        let key_data = data.clone();
        let owner = Arc::downgrade(factory);
        methods.insert(
            "Bytes".into(),
            Arc::new(move |args| {
                arity(args, 0, 0)?;
                let factory = owner
                    .upgrade()
                    .ok_or_else(|| error("certificate owner retired"))?;
                factory.reserve(4096)?;
                let value = Value::Object(Arc::new(Object {
                    fields: fields.as_ref().clone(),
                    data: Some(key_data.clone()),
                    go_type: Some("*ecdsa.PublicKey"),
                    ..Object::default()
                }));
                public_key_methods::ec_bytes(&factory, &value)
            }),
        );
    }
    if kind == 5 {
        let bytes = Arc::<[u8]>::from(pki.subject_public_key.data.as_ref());
        let owner = Arc::downgrade(factory);
        methods.insert(
            "Bytes".into(),
            Arc::new(move |a| {
                arity(a, 0, 0)?;
                let f = owner
                    .upgrade()
                    .ok_or_else(|| error("certificate owner retired"))?;
                f.byte_slice(bytes.clone(), false)
            }),
        );
    }
    Ok(Value::Object(Arc::new(Object {
        fields,
        methods,
        field_order: Some(
            match kind {
                1 => vec!["N", "E"],
                2 => vec!["Parameters", "Y"],
                3 => vec!["Curve", "X", "Y"],
                _ => vec![],
            }
            .into_iter()
            .map(Arc::from)
            .collect::<Vec<_>>()
            .into(),
        ),
        json_fields: if kind == 2 {
            Some(
                ["P", "Q", "G", "Y"]
                    .into_iter()
                    .map(|name| gotmpl::JsonField {
                        source: name,
                        name,
                        omit_empty: false,
                    })
                    .collect::<Vec<_>>()
                    .into(),
            )
        } else {
            None
        },
        go_type: Some(go_type),
        pointer_identity: Some(Arc::as_ptr(&data) as usize),
        data: Some(data),
        data_bytes: pki.raw.len() + 128,
        ..Object::default()
    })))
}
static ED25519_TYPE: gotmpl::SliceType = gotmpl::SliceType {
    name: "ed25519.PublicKey",
    element: "uint8",
    stringer: None,
    methods: &[gotmpl::SliceMethod {
        name: "Equal",
        signature: None,
        invoke: |slice, args| {
            arity(args, 1, 1)?;
            slice.reserve_host_bytes(128)?;
            let Value::Slice(other) = &args[0] else {
                return Ok(Value::Bool(false));
            };
            Ok(Value::Bool(
                other.go_type() == "ed25519.PublicKey"
                    && slice.visible_bytes().as_deref() == other.visible_bytes().as_deref(),
            ))
        },
    }],
};
fn ed25519(factory: &Arc<Factory>, bytes: &[u8]) -> RenderResult<Value> {
    if bytes.len() != 32 {
        return Err(error("invalid Ed25519 public key length"));
    }
    types::bind(
        factory,
        gotmpl::TypedSlice::named_bytes(&ED25519_TYPE, Some(Arc::from(bytes)))?,
    )
}
static CURVE_IDENTITIES: [u8; 4] = [0; 4];
static CURVE_PARAM_IDENTITIES: [u8; 4] = [0; 4];
static CURVE_NUMBER_IDENTITIES: [u8; 20] = [0; 20];
fn curve_value(factory: &Arc<Factory>, group: &openssl::ec::EcGroupRef) -> RenderResult<Value> {
    use openssl::bn::{BigNum, BigNumContext};
    let mut ctx = BigNumContext::new().map_err(|e| error(e.to_string()))?;
    let (mut p, mut a, mut b) = (
        BigNum::new().map_err(|e| error(e.to_string()))?,
        BigNum::new().map_err(|e| error(e.to_string()))?,
        BigNum::new().map_err(|e| error(e.to_string()))?,
    );
    group
        .components_gfp(&mut p, &mut a, &mut b, &mut ctx)
        .map_err(|e| error(e.to_string()))?;
    let mut n = BigNum::new().map_err(|e| error(e.to_string()))?;
    group
        .order(&mut n, &mut ctx)
        .map_err(|e| error(e.to_string()))?;
    let (mut gx, mut gy) = (
        BigNum::new().map_err(|e| error(e.to_string()))?,
        BigNum::new().map_err(|e| error(e.to_string()))?,
    );
    group
        .generator_opt()
        .ok_or_else(|| error("elliptic group generator unavailable"))?
        .affine_coordinates_gfp(group, &mut gx, &mut gy, &mut ctx)
        .map_err(|e| error(e.to_string()))?;
    let name = match group.curve_name() {
        Some(openssl::nid::Nid::SECP224R1) => "P-224",
        Some(openssl::nid::Nid::X9_62_PRIME256V1) => "P-256",
        Some(openssl::nid::Nid::SECP384R1) => "P-384",
        Some(openssl::nid::Nid::SECP521R1) => "P-521",
        _ => return Err(error("unsupported Go elliptic curve")),
    };
    let curve_index = match name {
        "P-224" => 0,
        "P-256" => 1,
        "P-384" => 2,
        _ => 3,
    };
    let mut fields = BTreeMap::new();
    for (index, (name, n)) in [("P", p), ("N", n), ("B", b), ("Gx", gx), ("Gy", gy)]
        .into_iter()
        .enumerate()
    {
        let value = numbers::singleton_integer(
            factory,
            &n.to_vec(),
            &CURVE_NUMBER_IDENTITIES[curve_index * 5 + index] as *const u8 as usize,
            index < 2,
        )?;
        fields.insert(name.into(), value);
    }
    fields.insert("BitSize".into(), Value::Int(i64::from(group.degree())));
    fields.insert("Name".into(), Value::String(name.into()));
    let params = Value::Object(Arc::new(Object {
        fields,
        field_order: Some(
            ["P", "N", "B", "Gx", "Gy", "BitSize", "Name"]
                .map(Arc::from)
                .into(),
        ),
        pointer_identity: Some(&CURVE_PARAM_IDENTITIES[curve_index] as *const u8 as usize),
        go_type: Some("*elliptic.CurveParams"),
        ..Object::default()
    }));
    let result = params.clone();
    Ok(Value::Object(Arc::new(Object {
        pointer_identity: Some(&CURVE_IDENTITIES[curve_index] as *const u8 as usize),
        field_order: Some(Arc::from([])),
        go_type: Some(match name {
            "P-224" => "*elliptic.nistCurve[*crypto/internal/fips140/nistec.P224Point]",
            "P-256" => "*elliptic.nistCurve[*crypto/internal/fips140/nistec.P256Point]",
            "P-384" => "*elliptic.nistCurve[*crypto/internal/fips140/nistec.P384Point]",
            _ => "*elliptic.nistCurve[*crypto/internal/fips140/nistec.P521Point]",
        }),
        methods: BTreeMap::from([(
            "Params".into(),
            Arc::new(move |args: &[Value]| {
                arity(args, 0, 0)?;
                Ok(result.clone())
            }) as ValueFunc,
        )]),
        ..Object::default()
    })))
}
fn method(receiver: &Receiver, name: &str, args: &[Value]) -> RenderResult<Value> {
    let f = &receiver.factory;
    f.work(1)?;
    arity(
        args,
        if name == "CheckSignature" { 3 } else { 1 },
        if name == "CheckSignature" { 3 } else { 1 },
    )?;
    if name == "Equal" {
        let other = match &args[0] {
            Value::Nil => return Ok(Value::Bool(false)),
            Value::Object(other)
                if other.go_type == Some("*x509.Certificate") && other.is_nil_pointer() =>
            {
                return Ok(Value::Bool(false));
            }
            Value::Object(other) => other
                .host_data::<Receiver>("*x509.Certificate")
                .ok_or_else(|| error("expected *x509.Certificate"))?,
            _ => return Err(error("expected *x509.Certificate")),
        };
        return Ok(Value::Bool(
            receiver.certificate.raw.visible_bytes().as_deref()
                == other.certificate.raw.visible_bytes().as_deref(),
        ));
    }
    if name == "VerifyHostname" {
        let host = args[0]
            .as_go_bytes()
            .ok_or_else(|| error("expected string hostname"))?;
        let fields = receiver.certificate.fields(f)?;
        f.reserve(
            host.len()
                .checked_mul(8)
                .and_then(|n| n.checked_add(receiver.certificate.der.len() * 8 + 8192))
                .ok_or_else(|| error("hostname output overflow"))?,
        )?;
        let dns = match fields.get("DNSNames") {
            Some(Value::Slice(s)) => s
                .iter()
                .filter_map(|v| v.as_go_bytes().map(<[u8]>::to_vec))
                .collect::<Vec<_>>(),
            _ => return Err(error("invalid certificate DNS SAN projection")),
        };
        let ips = match fields.get("IPAddresses") {
            Some(Value::Slice(s)) => s
                .iter()
                .filter_map(|v| {
                    if let Value::Slice(s) = v {
                        s.visible_bytes().map(|b| b.to_vec())
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>(),
            _ => return Err(error("invalid certificate IP SAN projection")),
        };
        let common = match fields.get("Subject") {
            Some(Value::Object(s)) => s
                .fields
                .get("CommonName")
                .and_then(Value::as_go_bytes)
                .unwrap_or_default(),
            _ => return Err(error("invalid certificate subject projection")),
        };
        let (_, cert) = x509_parser::parse_x509_certificate(&receiver.certificate.der)
            .map_err(|e| error(e.to_string()))?;
        let has_san = cert
            .extensions()
            .iter()
            .any(|ext| ext.oid.to_id_string() == "2.5.29.17");
        return match hostname::verify(host, common, &dns, &ips, has_san) {
            Ok(()) => Ok(Value::NilError),
            Err((message, host)) => {
                let cert = value(f, receiver.certificate.clone())?;
                error_bytes(
                    f,
                    "x509.HostnameError",
                    message,
                    BTreeMap::from([
                        ("Certificate".into(), cert),
                        ("Host".into(), f.go_string(&host)?),
                    ]),
                    Some(["Certificate", "Host"].map(Arc::from).into()),
                )
            }
        };
    }

    f.reserve(receiver.certificate.der.len() * 128 + 65536)?;
    f.work(receiver.certificate.der.len() * 8 + 1)?;
    if name == "CheckSignature" {
        for arg in &args[1..] {
            if let Value::Slice(slice) = arg {
                f.reserve(
                    slice
                        .len()
                        .checked_mul(4)
                        .and_then(|n| n.checked_add(1024))
                        .ok_or_else(|| error("signature input size overflow"))?,
                )?;
                f.work(slice.len().div_ceil(64) + 1)?;
            }
        }
    }
    let (key, algo, message, signature) = if name == "CheckSignatureFrom" {
        let Value::Object(parent) = &args[0] else {
            return Err(error("expected *x509.Certificate"));
        };
        let parent = parent
            .host_data::<Receiver>("*x509.Certificate")
            .ok_or_else(|| error("expected *x509.Certificate"))?;
        let p = parent.certificate.fields(&parent.factory)?;
        if p.get("Version").and_then(Value::as_int) == Some(3)
            && p.get("BasicConstraintsValid")
                .is_some_and(|v| matches!(v, Value::Bool(false)))
            || p.get("BasicConstraintsValid")
                .is_some_and(|v| matches!(v, Value::Bool(true)))
                && p.get("IsCA")
                    .is_some_and(|v| matches!(v, Value::Bool(false)))
        {
            return Ok(error_value(
                "x509.ConstraintViolationError",
                "x509: invalid signature: parent certificate cannot sign this kind of certificate"
                    .into(),
            ));
        }
        if p.get("PublicKeyAlgorithm").and_then(Value::as_int) == Some(0) {
            return Ok(error_value(
                "*errors.errorString",
                "x509: cannot verify signature: algorithm unimplemented".into(),
            ));
        }
        let ku = p.get("KeyUsage").and_then(Value::as_int).unwrap_or(0);
        if ku != 0 && ku & 32 == 0 {
            return Ok(error_value(
                "x509.ConstraintViolationError",
                "x509: invalid signature: parent certificate cannot sign this kind of certificate"
                    .into(),
            ));
        }
        let own = receiver.certificate.fields(f)?;
        let bytes = |name| -> RenderResult<Vec<u8>> {
            let Some(Value::Slice(slice)) = own.get(name) else {
                return Err(error("missing certificate signature bytes"));
            };
            Ok(slice
                .visible_bytes()
                .as_deref()
                .unwrap_or_default()
                .to_vec())
        };
        let algo = own
            .get("SignatureAlgorithm")
            .and_then(Value::as_int)
            .ok_or_else(|| error("missing certificate signature algorithm"))?;
        (
            p.get("PublicKey")
                .cloned()
                .ok_or_else(|| error("missing parent public key"))?,
            algo,
            bytes("RawTBSCertificate")?,
            bytes("Signature")?,
        )
    } else {
        let algo = match &args[0] {
            Value::NamedInt64(n, t) if t.name == "x509.SignatureAlgorithm" => *n,
            _ => return Err(error("expected x509.SignatureAlgorithm")),
        };
        let bytes = |value: &Value| -> RenderResult<Vec<u8>> {
            if matches!(value, Value::Nil) {
                return Ok(Vec::new());
            }
            let Value::Slice(slice) = value else {
                return Err(error("expected []uint8"));
            };
            if !matches!(slice.go_type(), "[]uint8" | "[]byte")
                && !slice.named_type().is_some_and(|k| k.element == "uint8")
            {
                return Err(error("expected []uint8"));
            }
            Ok(slice
                .visible_bytes()
                .as_deref()
                .unwrap_or_default()
                .to_vec())
        };
        (
            receiver
                .certificate
                .fields(f)?
                .get("PublicKey")
                .cloned()
                .ok_or_else(|| error("missing public key"))?,
            algo,
            bytes(&args[1])?,
            bytes(&args[2])?,
        )
    };
    f.reserve((message.len() + signature.len()) * 32 + 65536)?;
    f.work((message.len() + signature.len()) * 16 + 1)?;
    if algo == 2 || name == "CheckSignatureFrom" && matches!(algo, 3 | 7 | 9) {
        return Ok(numbers::insecure_algorithm(algo));
    }
    let expected = match algo {
        2..=6 | 13..=15 => 1,
        7 | 8 => 2,
        9..=12 => 3,
        16 => 4,
        17..=19 => 5,
        _ => {
            return Ok(error_value(
                "*errors.errorString",
                "x509: cannot verify signature: algorithm unimplemented".into(),
            ));
        }
    };
    let (actual, actual_type) = public_key_methods::kind(&key);
    if actual == 0 {
        return Ok(error_value(
            "*errors.errorString",
            "x509: cannot verify signature: algorithm unimplemented".into(),
        ));
    }
    if actual != expected {
        let expected = match expected {
            1 => "RSA",
            2 => "DSA",
            3 => "ECDSA",
            4 => "Ed25519",
            _ => "ML-DSA",
        };
        return Ok(error_value(
            "*errors.errorString",
            format!(
                "x509: signature algorithm specifies an {expected} public key, but have public key of type {actual_type}"
            ),
        ));
    }
    if actual == 1 {
        let Value::Object(object) = &key else {
            unreachable!()
        };
        let n = numbers::current(
            object
                .fields
                .get("N")
                .ok_or_else(|| error("missing RSA modulus"))?,
        )?;
        if n.bits() < 1024 {
            return Ok(error_value(
                "*errors.errorString",
                format!(
                    "crypto/rsa: {}-bit keys are insecure (see https://go.dev/pkg/crypto/rsa#hdr-Minimum_key_size)",
                    n.bits()
                ),
            ));
        }
        if !n.bit(0) {
            return Ok(error_value(
                "*errors.errorString",
                "crypto/rsa: public modulus is even".into(),
            ));
        }
    }
    let native = public_key_methods::native(f, &key)?;
    let failure = match actual {
        1 => "crypto/rsa: verification error",
        3 => "x509: ECDSA verification failure",
        4 => "x509: Ed25519 verification failure",
        _ => "x509: cannot verify signature: algorithm unimplemented",
    };
    let Some(key) = native else {
        return Ok(error_value("*errors.errorString", failure.into()));
    };
    let result = (|| -> Result<bool, openssl::error::ErrorStack> {
        let digest = match algo {
            3 | 7 | 9 => Some(openssl::hash::MessageDigest::sha1()),
            4 | 8 | 10 | 13 => Some(openssl::hash::MessageDigest::sha256()),
            5 | 11 | 14 => Some(openssl::hash::MessageDigest::sha384()),
            6 | 12 | 15 => Some(openssl::hash::MessageDigest::sha512()),
            _ => None,
        };
        let mut verifier = if let Some(digest) = digest {
            openssl::sign::Verifier::new(digest, &key)
        } else {
            openssl::sign::Verifier::new_without_digest(&key)
        }?;
        if matches!(algo, 13..=15) {
            verifier.set_rsa_padding(openssl::rsa::Padding::PKCS1_PSS)?;
            verifier.set_rsa_pss_saltlen(openssl::sign::RsaPssSaltlen::DIGEST_LENGTH)?;
        }
        verifier.verify_oneshot(&signature, &message)
    })();
    Ok(if matches!(result, Ok(true)) {
        Value::NilError
    } else {
        error_value("*errors.errorString", failure.into())
    })
}

fn error_value(kind: &'static str, message: String) -> Value {
    let text = Arc::<str>::from(message);
    let value = text.clone();
    Value::Object(Arc::new(Object {
        go_type: Some(kind),
        display: Some(text),
        methods: BTreeMap::from([(
            "Error".into(),
            Arc::new(move |args: &[Value]| {
                arity(args, 0, 0)?;
                Ok(Value::String(value.clone()))
            }) as ValueFunc,
        )]),
        ..Object::default()
    }))
}

struct ErrorData {
    owner: std::sync::Weak<Factory>,
    message: Arc<[u8]>,
}
fn error_bytes(
    factory: &Arc<Factory>,
    kind: &'static str,
    message: Vec<u8>,
    fields: BTreeMap<Arc<str>, Value>,
    order: Option<Arc<[Arc<str>]>>,
) -> RenderResult<Value> {
    factory.reserve(message.len() * 2 + 4096)?;
    let data = Arc::new(ErrorData {
        owner: Arc::downgrade(factory),
        message: message.into(),
    });
    let returned = data.clone();
    Ok(Value::Object(Arc::new(Object {
        fields,
        field_order: order,
        go_type: Some(kind),
        methods: BTreeMap::from([(
            "Error".into(),
            Arc::new(move |a: &[Value]| {
                arity(a, 0, 0)?;
                let f = returned
                    .owner
                    .upgrade()
                    .ok_or_else(|| error("certificate owner retired"))?;
                f.reserve(returned.message.len() + 128)?;
                Ok(Value::from_go_bytes(returned.message.clone()))
            }) as ValueFunc,
        )]),
        data: Some(data),
        data_bytes: 128,
        formatter: Some(format_error),
        ..Object::default()
    })))
}
fn format_error(object: &Object, verb: char, format: &gotmpl::HostFormat) -> RenderResult<Value> {
    let data = object
        .data
        .as_ref()
        .and_then(|d| d.downcast_ref::<ErrorData>())
        .ok_or_else(|| error("invalid error receiver"))?;
    let f = data
        .owner
        .upgrade()
        .ok_or_else(|| error("certificate owner retired"))?;
    format_display(&f, object, verb, format, &data.message)
}
pub(super) fn format_display(
    factory: &Arc<Factory>,
    object: &Object,
    verb: char,
    format: &gotmpl::HostFormat,
    message: &[u8],
) -> RenderResult<Value> {
    let maximum = message
        .len()
        .max(format.width.unwrap_or(0))
        .max(format.precision.unwrap_or(0));
    if maximum > 1 << 20 {
        return Err(error("host string format limit"));
    }
    factory.reserve(maximum * 8 + 4096)?;
    let mut spec = String::from("%");
    for (flag, set) in [
        ('-', format.left_align),
        ('+', format.plus),
        (' ', format.space),
        ('#', format.hash),
        ('0', format.zero),
    ] {
        if set {
            spec.push(flag);
        }
    }
    if let Some(width) = format.width {
        spec.push_str(&width.to_string());
    }
    if let Some(precision) = format.precision {
        spec.push('.');
        spec.push_str(&precision.to_string());
    }
    spec.push(verb);
    let value = if verb == 'v' && format.hash {
        Value::Object(Arc::new(Object {
            fields: object.fields.clone(),
            field_order: object.field_order.clone(),
            go_type: object.go_type,
            ..Object::default()
        }))
    } else {
        Value::from_go_bytes(Arc::<[u8]>::from(message))
    };
    Ok(Value::from_go_bytes(Arc::<[u8]>::from(
        gotmpl::go_sprintf_bytes(spec.as_bytes(), &[value])?,
    )))
}

pub(super) fn word_reference_factory(value:&Value)->Option<std::sync::Weak<Factory>> { numbers::word_reference_factory(value) }
