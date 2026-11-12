use std::cmp::Ordering;
use std::fmt;
use std::str::FromStr;
use regex::Regex;
use std::sync::LazyLock;

static LOOSE_VERSION_REGEX:LazyLock<Regex>=LazyLock::new(||Regex::new(
    r"^v?([0-9]+)(?:\.([0-9]+))?(?:\.([0-9]+))?(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
).expect("fixed semantic version grammar"));
const NUM:&str="0123456789";
const ALLOWED:&str="0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-";

#[derive(Clone, PartialEq, Eq)]
pub struct Version {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    pub pre: String,
    pub metadata: String,
    pub original: String,
}

fn contains_only(s: &str, comp: &str) -> bool {
    s.chars().all(|c| comp.contains(c))
}

fn validate_prerelease(p: &str) -> Result<(), String> {
    if p.is_empty() {
        return Ok(());
    }
    let eparts: Vec<&str> = p.split('.').collect();
    for part in eparts {
        if part.is_empty() {
            return Err("invalid prerelease identifier".to_string());
        }
        if contains_only(part, &NUM) {
            if part.len() > 1 && part.starts_with('0') {
                return Err("numeric identifier must not include leading zeroes".to_string());
            }
        } else if !contains_only(part, &ALLOWED) {
            return Err("invalid prerelease identifier".to_string());
        }
    }
    Ok(())
}

fn validate_metadata(m: &str) -> Result<(), String> {
    if m.is_empty() {
        return Ok(());
    }
    let eparts: Vec<&str> = m.split('.').collect();
    for part in eparts {
        if part.is_empty() {
            return Err("invalid metadata identifier".to_string());
        }
        if !contains_only(part, &ALLOWED) {
            return Err("invalid metadata identifier".to_string());
        }
    }
    Ok(())
}

fn compare_segment(v: u64, o: u64) -> Ordering {
    v.cmp(&o)
}

fn compare_pre_part(s: &str, o: &str) -> Ordering {
    if s == o {
        return Ordering::Equal;
    }

    // When s or o are empty
    if s.is_empty() {
        if !o.is_empty() {
            return Ordering::Less;
        }
        return Ordering::Greater;
    }

    if o.is_empty() {
        if !s.is_empty() {
            return Ordering::Greater;
        }
        return Ordering::Less;
    }

    // Parse as u64. Note: Go's strconv.ParseUint returns error if out of range for u64.
    // In Go, if parsing fails, it treats the string as alphanumeric.
    // We mimic this: if parsing to u64 fails, it's treated as a string (alphanumeric).
    let oi = o.parse::<u64>();
    let si = s.parse::<u64>();

    match (si, oi) {
        (Ok(si_val), Ok(oi_val)) => {
            // Both are valid u64 numbers
            si_val.cmp(&oi_val)
        }
        (Ok(_), Err(_)) => {
            // s is a number, o is not (string)
            Ordering::Less
        }
        (Err(_), Ok(_)) => {
            Ordering::Greater
        }
        (Err(_), Err(_)) => {
            // Both are strings (alphanumeric)
            // In Go: if s > o return 1, else return -1
            // Note: Go's string comparison is lexicographical byte-wise
            s.cmp(o)
        }
    }
}

fn compare_prerelease(v: &str, o: &str) -> Ordering {
    let sparts: Vec<&str> = v.split('.').collect();
    let oparts: Vec<&str> = o.split('.').collect();

    let slen = sparts.len();
    let olen = oparts.len();
    let l = if slen > olen { slen } else { olen };

    for i in 0..l {
        let stemp = if i < slen { sparts[i] } else { "" };
        let otemp = if i < olen { oparts[i] } else { "" };

        let d = compare_pre_part(stemp, otemp);
        if d != Ordering::Equal {
            return d;
        }
    }

    Ordering::Equal
}

impl Version {
    pub(super) fn parse(v_str: &str) -> Result<Self, String> {
        if v_str.len() > 256 {
            return Err("version string length exceeds 256 bytes".to_string());
        }

        let m = LOOSE_VERSION_REGEX.captures(v_str)
            .ok_or_else(|| "invalid semantic version".to_string())?;

        // Extract groups
        // Group 1: Major
        // Group 2: Minor (with optional leading dot)
        // Group 3: Patch (with optional leading dot)
        // Group 4: Prerelease
        // Group 5: Metadata

        let major_str = m.get(1).map(|m| m.as_str()).unwrap_or("0");

        let minor_str = m.get(2).map(|m| {
            let s = m.as_str();
            if s.starts_with('.') {
                &s[1..]
            } else {
                s
            }
        }).unwrap_or("0");

        let patch_str = m.get(3).map(|m| {
            let s = m.as_str();
            if s.starts_with('.') {
                &s[1..]
            } else {
                s
            }
        }).unwrap_or("0");

        let pre = m.get(4).map(|m| m.as_str()).unwrap_or("").to_string();
        let metadata = m.get(5).map(|m| m.as_str()).unwrap_or("").to_string();

        let major: u64 = major_str.parse().map_err(|_| "error parsing version segment: major")?;
        let minor: u64 = minor_str.parse().map_err(|_| "error parsing version segment: minor")?;
        let patch: u64 = patch_str.parse().map_err(|_| "error parsing version segment: patch")?;

        if !pre.is_empty() {
            validate_prerelease(&pre)?;
        }

        if !metadata.is_empty() {
            validate_metadata(&metadata)?;
        }

        Ok(Version {
            major,
            minor,
            patch,
            pre,
            metadata,
            original: v_str.to_string(),
        })
    }

    fn original_v_prefix(&self) -> &str {
        if !self.original.is_empty() && self.original.starts_with('v') {
            "v"
        } else {
            ""
        }
    }

    pub fn inc_patch(&self) -> Result<Self, String> {
        let mut v_next = self.clone();

        if !self.pre.is_empty() {
            v_next.metadata = "".to_string();
            v_next.pre = "".to_string();
        } else {
            v_next.metadata = "".to_string();
            v_next.pre = "".to_string();
            if self.patch == u64::MAX {
                return Err("patch version increment would overflow uint64".to_string());
            }
            v_next.patch = self.patch + 1;
        }

        v_next.original = format!("{}{}", self.original_v_prefix(), v_next.to_string());
        Ok(v_next)
    }

    pub fn inc_minor(&self) -> Result<Self, String> {
        let mut v_next = self.clone();

        v_next.metadata = "".to_string();
        v_next.pre = "".to_string();
        v_next.patch = 0;

        if self.minor == u64::MAX {
            return Err("minor version increment would overflow uint64".to_string());
        }
        v_next.minor = self.minor + 1;

        v_next.original = format!("{}{}", self.original_v_prefix(), v_next.to_string());
        Ok(v_next)
    }

    pub fn inc_major(&self) -> Result<Self, String> {
        let mut v_next = self.clone();

        v_next.metadata = "".to_string();
        v_next.pre = "".to_string();
        v_next.patch = 0;
        v_next.minor = 0;

        if self.major == u64::MAX {
            return Err("major version increment would overflow uint64".to_string());
        }
        v_next.major = self.major + 1;

        v_next.original = format!("{}{}", self.original_v_prefix(), v_next.to_string());
        Ok(v_next)
    }

    pub fn set_prerelease(&self, prerelease: &str) -> Result<Self, String> {
        let mut v_next = self.clone();

        if !prerelease.is_empty() {
            validate_prerelease(prerelease)?;
        }
        v_next.pre = prerelease.to_string();

        v_next.original = format!("{}{}", self.original_v_prefix(), v_next.to_string());
        Ok(v_next)
    }

    pub fn set_metadata(&self, metadata: &str) -> Result<Self, String> {
        let mut v_next = self.clone();

        if !metadata.is_empty() {
            validate_metadata(metadata)?;
        }
        v_next.metadata = metadata.to_string();

        v_next.original = format!("{}{}", self.original_v_prefix(), v_next.to_string());
        Ok(v_next)
    }

    pub fn compare(&self, other: &Self) -> Ordering {
        // Compare major, minor, patch
        let d = compare_segment(self.major, other.major);
        if d != Ordering::Equal {
            return d;
        }
        let d = compare_segment(self.minor, other.minor);
        if d != Ordering::Equal {
            return d;
        }
        let d = compare_segment(self.patch, other.patch);
        if d != Ordering::Equal {
            return d;
        }

        // At this point major, minor, patch are equal
        let ps = &self.pre;
        let po = &other.pre;

        if ps.is_empty() && po.is_empty() {
            return Ordering::Equal;
        }
        if ps.is_empty() {
            return Ordering::Greater;
        }
        if po.is_empty() {
            return Ordering::Less;
        }

        compare_prerelease(ps, po)
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)?;
        if !self.pre.is_empty() {
            write!(f, "-{}", self.pre)?;
        }
        if !self.metadata.is_empty() {
            write!(f, "+{}", self.metadata)?;
        }
        Ok(())
    }
}

impl FromStr for Version {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Version::parse(s)
    }
}
