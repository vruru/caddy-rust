// pkix_name.rs
//
// Behavior port from Go's crypto/x509/pkix package.
// Copyright (c) Go Authors. BSD License.

#[derive(Clone)]
pub(crate) enum AttributeValue {
    Text(String),
    Encoded { der: Option<Vec<u8>>, display: String, native: NativeValue },
}

#[derive(Clone)]
pub(crate) enum NativeValue {
    Int(i64), Bool(bool), Null, Bytes(Vec<u8>),
    BitString { bytes: Vec<u8>, bit_length: usize },
    Oid(Vec<u32>),
    Time { unix_seconds: i64, nanoseconds: u32 },
    Raw { class: u8, tag: u32, constructed: bool, bytes: Vec<u8>, full: Vec<u8> },
}

#[derive(Clone)]
pub(crate) struct Attribute {
    pub(crate) oid: String,
    pub(crate) value: AttributeValue,
}

#[derive(Clone, Default)]
pub(crate) struct Name {
    pub(crate) country: Vec<String>,
    pub(crate) organization: Vec<String>,
    pub(crate) organizational_unit: Vec<String>,
    pub(crate) locality: Vec<String>,
    pub(crate) province: Vec<String>,
    pub(crate) street_address: Vec<String>,
    pub(crate) postal_code: Vec<String>,
    pub(crate) common_name: String,
    pub(crate) serial_number: String,
    pub(crate) names: Vec<Attribute>,
    pub(crate) extra_names: Option<Vec<Attribute>>,
}

fn oid_map(oid: &str) -> Option<&'static str> {
    match oid {
        "2.5.4.3" => Some("CN"),
        "2.5.4.5" => Some("SERIALNUMBER"),
        "2.5.4.6" => Some("C"),
        "2.5.4.7" => Some("L"),
        "2.5.4.8" => Some("ST"),
        "2.5.4.9" => Some("STREET"),
        "2.5.4.10" => Some("O"),
        "2.5.4.11" => Some("OU"),
        "2.5.4.17" => Some("POSTALCODE"),
        _ => None,
    }
}

fn escape_value(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for (i, c) in s.char_indices() {
        match c {
            '\\' | '+' | '"' | ',' | ';' | '<' | '>' => {
                out.push('\\');
                out.push(c);
            }
            ' ' => {
                if i == 0 || i + c.len_utf8() == s.len() {
                    out.push('\\');
                }
                out.push(c);
            }
            '#' => {
                if i == 0 {
                    out.push('\\');
                }
                out.push(c);
            }
            _ => {
                out.push(c);
            }
        }
    }
    out
}

fn attr_to_string(atv: &Attribute) -> String {
    match oid_map(&atv.oid) {
        Some(name) => {
            let display = match &atv.value {
                AttributeValue::Text(s) => s.as_str(),
                AttributeValue::Encoded { display, .. } => display.as_str(),
            };
            format!("{}={}", name, escape_value(display))
        }
        None => match &atv.value {
            AttributeValue::Text(s) => {
                format!("{}={}", atv.oid, escape_value(s))
            }
            AttributeValue::Encoded { der: Some(der), .. } => {
                let mut hex = String::with_capacity(der.len() * 2);
                for b in der {
                    hex.push_str(&format!("{:02x}", b));
                }
                format!("{}=#{}", atv.oid, hex)
            }
            AttributeValue::Encoded { display, .. } => format!("{}={}", atv.oid, escape_value(display)),
        },
    }
}

pub(crate) fn rdns_string(rdns: &[Vec<Attribute>]) -> String {
    let mut parts: Vec<String> = Vec::new();
    for rdn in rdns.iter().rev() {
        let mut rdn_str = String::new();
        for (i, atv) in rdn.iter().enumerate() {
            if i > 0 {
                rdn_str.push('+');
            }
            rdn_str.push_str(&attr_to_string(atv));
        }
        parts.push(rdn_str);
    }
    parts.join(",")
}

impl Name {
    pub(crate) fn fill_from_rdns(&mut self, rdns: &[Vec<Attribute>]) {
        for rdn in rdns {
            for atv in rdn {
                self.names.push(atv.clone());
                match &atv.value {
                    AttributeValue::Text(s) => match atv.oid.as_str() {
                        "2.5.4.6" => self.country.push(s.clone()),
                        "2.5.4.10" => self.organization.push(s.clone()),
                        "2.5.4.11" => self.organizational_unit.push(s.clone()),
                        "2.5.4.7" => self.locality.push(s.clone()),
                        "2.5.4.8" => self.province.push(s.clone()),
                        "2.5.4.9" => self.street_address.push(s.clone()),
                        "2.5.4.17" => self.postal_code.push(s.clone()),
                        "2.5.4.3" => self.common_name = s.clone(),
                        "2.5.4.5" => self.serial_number = s.clone(),
                        _ => {}
                    },
                    _ => {}
                }
            }
        }
    }

    pub(crate) fn to_rdns(&self) -> Vec<Vec<Attribute>> {
        let mut ret: Vec<Vec<Attribute>> = Vec::new();
        let mut append_rdns = |vals: &[String], oid: &str| {
            if vals.is_empty()
                || self
                    .extra_names
                    .as_ref()
                    .is_some_and(|extras| extras.iter().any(|attribute| attribute.oid == oid))
            {
                return;
            }
            ret.push(
                vals.iter()
                    .map(|value| Attribute {
                        oid: oid.to_owned(),
                        value: AttributeValue::Text(value.clone()),
                    })
                    .collect(),
            );
        };
        append_rdns(&self.country, "2.5.4.6");
        append_rdns(&self.province, "2.5.4.8");
        append_rdns(&self.locality, "2.5.4.7");
        append_rdns(&self.street_address, "2.5.4.9");
        append_rdns(&self.postal_code, "2.5.4.17");
        append_rdns(&self.organization, "2.5.4.10");
        append_rdns(&self.organizational_unit, "2.5.4.11");
        if !self.common_name.is_empty() {
            append_rdns(&[self.common_name.clone()], "2.5.4.3");
        }
        if !self.serial_number.is_empty() {
            append_rdns(&[self.serial_number.clone()], "2.5.4.5");
        }
        if let Some(extras) = &self.extra_names {
            for atv in extras {
                ret.push(vec![atv.clone()]);
            }
        }
        ret
    }

    pub(crate) fn string(&self) -> String {
        let mut rdns: Vec<Vec<Attribute>> = Vec::new();
        if self.extra_names.is_none() {
            for atv in &self.names {
                if oid_map(&atv.oid).is_none() {
                    rdns.push(vec![atv.clone()]);
                }
            }
        }
        rdns.extend(self.to_rdns());
        rdns_string(&rdns)
    }
}
