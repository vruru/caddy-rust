//! Immutable criteria and X.509 leaf facts for explicit certificate selection.
use super::{
    MAX_ARRAY_LEN, MAX_STRING_LEN, check_len, check_unknown, require_array, require_object,
    require_string,
};
use anyhow::{Result, anyhow, bail, ensure};
use serde_json::Value;
use std::collections::HashSet;
use x509_parser::{certificate::X509Certificate, x509::AttributeTypeAndValue};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Serial {
    negative: bool,
    magnitude: Vec<u8>,
}

impl Serial {
    fn from_decimal(value: &Value) -> Result<Self> {
        let raw = if value.is_null() {
            "0"
        } else {
            require_string(value, "certificate selection serial number")?
        };
        check_len(raw, MAX_STRING_LEN, "certificate selection serial number")?;
        let (negative, digits) = if let Some(digits) = raw.strip_prefix('-') {
            (true, digits)
        } else {
            (false, raw.strip_prefix('+').unwrap_or(raw))
        };
        ensure!(
            !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit()),
            "certificate selection serial number is not a decimal integer"
        );
        let magnitude = rsa::BigUint::parse_bytes(digits.as_bytes(), 10)
            .ok_or_else(|| anyhow!("invalid certificate selection serial number"))?
            .to_bytes_be();
        Ok(Self::from_magnitude(negative, magnitude))
    }

    fn from_der(raw: &[u8]) -> Self {
        let negative = raw.first().is_some_and(|byte| byte & 0x80 != 0);
        let mut bytes = raw.to_vec();
        if negative {
            // Convert DER's signed two's complement INTEGER to magnitude.
            let mut carry = 1u16;
            for byte in bytes.iter_mut().rev() {
                let total = u16::from(!*byte) + carry;
                *byte = total as u8;
                carry = total >> 8;
            }
        }
        Self::from_magnitude(negative, bytes)
    }

    fn from_magnitude(negative: bool, mut magnitude: Vec<u8>) -> Self {
        let zeros = magnitude.iter().take_while(|byte| **byte == 0).count();
        magnitude.drain(..zeros);
        Self {
            negative: negative && !magnitude.is_empty(),
            magnitude,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Algorithm {
    Dsa,
    Ecdsa,
    Rsa,
}

impl Algorithm {
    fn from_value(value: &Value) -> Result<Self> {
        let name = require_string(value, "certificate selection public key algorithm")?;
        check_len(
            name,
            MAX_STRING_LEN,
            "certificate selection public key algorithm",
        )?;
        match name.to_ascii_lowercase().as_str() {
            "dsa" => Ok(Self::Dsa),
            "ecdsa" => Ok(Self::Ecdsa),
            "rsa" => Ok(Self::Rsa),
            _ => bail!("unknown certificate selection public key algorithm"),
        }
    }

    fn from_leaf(leaf: &X509Certificate<'_>) -> Option<Self> {
        match leaf
            .public_key()
            .algorithm
            .algorithm
            .to_id_string()
            .as_str()
        {
            "1.2.840.10040.4.1" => Some(Self::Dsa),
            "1.2.840.10045.2.1" => Some(Self::Ecdsa),
            "1.2.840.113549.1.1.1" => Some(Self::Rsa),
            _ => None,
        }
    }
}

pub(crate) fn attribute_string(attribute: &AttributeTypeAndValue<'_>) -> Option<String> {
    if let Ok(value) = attribute.as_str() {
        return Some(value.to_owned());
    }
    let bytes = attribute.as_slice();
    match attribute.attr_value().tag().0 {
        // Go decodes legacy TeletexString as Latin-1.
        20 => Some(bytes.iter().copied().map(char::from).collect()),
        30 if bytes.len() % 2 == 0 => {
            // BMPString uses UCS-2, not UTF-16 surrogate pairs.
            let bytes = bytes.strip_suffix(&[0, 0]).unwrap_or(bytes);
            bytes
                .chunks_exact(2)
                .map(|bytes| {
                    let value = u16::from_be_bytes([bytes[0], bytes[1]]);
                    if matches!(value, 0xfdd0..=0xfdef | 0xfffe | 0xffff) {
                        return None;
                    }
                    char::from_u32(u32::from(value))
                })
                .collect()
        }
        _ => None,
    }
}

pub(crate) struct CertificateFacts {
    serial: Serial,
    algorithm: Option<Algorithm>,
    organizations: Vec<String>,
}

impl CertificateFacts {
    pub(crate) fn from_leaf(leaf: &X509Certificate<'_>) -> Self {
        Self {
            serial: Serial::from_der(leaf.raw_serial()),
            algorithm: Algorithm::from_leaf(leaf),
            organizations: leaf
                .subject()
                .iter_organization()
                .filter_map(attribute_string)
                .collect(),
        }
    }

    pub(crate) fn retained_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            .saturating_add(self.serial.magnitude.capacity())
            .saturating_add(self.organizations.capacity() * std::mem::size_of::<String>())
            .saturating_add(
                self.organizations
                    .iter()
                    .map(String::capacity)
                    .sum::<usize>(),
            )
    }
}

#[derive(Clone, Debug)]
pub struct CertificateFilter {
    serials: HashSet<Serial>,
    organizations: HashSet<String>,
    algorithm: Option<Algorithm>,
    any_tag: HashSet<String>,
    all_tags: HashSet<String>,
}

impl CertificateFilter {
    pub(crate) fn requires_tags(&self) -> bool {
        !self.any_tag.is_empty() || !self.all_tags.is_empty()
    }

    pub(crate) fn allows_tag_names<'a>(&self, tags: impl Clone + Iterator<Item = &'a str>) -> bool {
        (self.any_tag.is_empty() || tags.clone().any(|tag| self.any_tag.contains(tag)))
            && self
                .all_tags
                .iter()
                .all(|tag| tags.clone().any(|value| value == tag))
    }
    pub(crate) fn allows_tags(&self, tags: &[String]) -> bool {
        (self.any_tag.is_empty() || tags.iter().any(|tag| self.any_tag.contains(tag)))
            && self.all_tags.iter().all(|tag| tags.contains(tag))
    }

    pub(crate) fn allows_facts(&self, facts: &CertificateFacts) -> bool {
        (self.serials.is_empty() || self.serials.contains(&facts.serial))
            && self
                .algorithm
                .is_none_or(|algorithm| facts.algorithm == Some(algorithm))
            && (self.organizations.is_empty()
                || facts
                    .organizations
                    .iter()
                    .any(|organization| self.organizations.contains(organization)))
    }
}

pub(super) fn parse(value: Option<&Value>) -> Result<Option<CertificateFilter>> {
    let Some(value) = value.filter(|value| !value.is_null()) else {
        return Ok(None);
    };
    let object = require_object(value)?;
    check_unknown(
        object,
        &[
            "serial_number",
            "subject_organization",
            "public_key_algorithm",
            "any_tag",
            "all_tags",
        ],
        "certificate selection",
    )?;
    let array = |field| -> Result<&[Value]> {
        let Some(value) = object.get(field).filter(|value| !value.is_null()) else {
            return Ok(&[]);
        };
        let values = require_array(value, field)?;
        ensure!(
            values.len() <= MAX_ARRAY_LEN,
            "too many certificate selection criteria"
        );
        Ok(values)
    };
    let strings = |field| -> Result<HashSet<String>> {
        array(field)?
            .iter()
            .map(|value| {
                let text = if value.is_null() {
                    ""
                } else {
                    require_string(value, field)?
                };
                check_len(text, MAX_STRING_LEN, field)?;
                Ok(text.to_owned())
            })
            .collect()
    };
    Ok(Some(CertificateFilter {
        serials: array("serial_number")?
            .iter()
            .map(Serial::from_decimal)
            .collect::<Result<_>>()?,
        organizations: strings("subject_organization")?,
        algorithm: object
            .get("public_key_algorithm")
            .map(Algorithm::from_value)
            .transpose()?,
        any_tag: strings("any_tag")?,
        all_tags: strings("all_tags")?,
    }))
}
