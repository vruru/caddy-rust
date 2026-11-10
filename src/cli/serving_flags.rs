use super::{
    COMMON,
    args::{Flag, Kind},
};

/// Construct a Flag with given name, optional short char (as byte), and kind.
fn flag(name: &'static str, short: Option<u8>, kind: Kind) -> Flag {
    Flag { name, short, kind }
}

pub(super) fn specs(command: &str) -> Option<Vec<Flag>> {
    let mut flags = COMMON.to_vec();

    // All commands share 'adapter'
    flags.push(flag("adapter", Some(b'a'), Kind::Text));

    match command {
        "run" => {
            flags.push(flag("envfile", None, Kind::List));
            flags.push(flag("environ", Some(b'e'), Kind::Bool));
            flags.push(flag("resume", Some(b'r'), Kind::Bool));
            flags.push(flag("watch", Some(b'w'), Kind::Bool));
            flags.push(flag("pidfile", None, Kind::Text));
            flags.push(flag("pingback", None, Kind::Text));
        }
        "start" => {
            flags.push(flag("envfile", None, Kind::List));
            flags.push(flag("watch", Some(b'w'), Kind::Bool));
            flags.push(flag("pidfile", None, Kind::Text));
        }
        "stop" => {
            flags.push(flag("address", None, Kind::Text));
        }
        "reload" => {
            flags.push(flag("address", None, Kind::Text));
            flags.push(flag("force", Some(b'f'), Kind::Bool));
        }
        _ => return None,
    }

    Some(flags)
}
