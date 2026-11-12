// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! System configuration loading
//!
//! This module is responsible for parsing and returning the configuration from
//!  the host system. It will read from the default location on each operating
//!  system, e.g. most Unixes have this written to `/etc/resolv.conf`
#![allow(missing_docs)]

#[cfg(all(unix, not(any(target_os = "android", target_vendor = "apple"))))]
#[cfg(feature = "system-config")]
mod unix;

#[cfg(all(unix, not(any(target_os = "android", target_vendor = "apple"))))]
#[cfg(feature = "system-config")]
pub use self::unix::{parse_resolv_conf, read_system_conf};

#[cfg(windows)]
#[cfg(feature = "system-config")]
mod windows;

#[cfg(target_os = "windows")]
#[cfg(feature = "system-config")]
pub use self::windows::read_system_conf;

#[cfg(target_os = "android")]
#[cfg(feature = "system-config")]
mod android;

#[cfg(target_os = "android")]
#[cfg(feature = "system-config")]
pub use self::android::read_system_conf;

#[cfg(target_vendor = "apple")]
#[cfg(feature = "system-config")]
mod apple;

#[cfg(target_vendor = "apple")]
#[cfg(feature = "system-config")]
pub use self::apple::read_system_conf;

#[cfg(all(feature = "system-config", any(windows, target_vendor = "apple")))]
mod sanitize {
    use std::str::FromStr;

    use crate::proto::{ProtoError, rr::Name};

    pub(super) fn parse_search_domains(
        raw: &str,
    ) -> impl Iterator<Item = Result<Name, ProtoError>> + '_ {
        raw.split(|c: char| c.is_whitespace() || c == '\0')
            .filter(|domain| !domain.is_empty())
            .map(Name::from_str)
    }


}
