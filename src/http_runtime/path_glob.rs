//! Shared path-pattern matcher used by HTTP routing and configuration adaptation.
pub(crate) fn compile_go_path_glob(pattern: &str) -> Option<regex::Regex> {
    let mut regex = String::from("^");
    let mut chars = pattern.chars();
    while let Some(c) = chars.next() {
        match c {
            '*' => regex.push_str("[^/]*"),
            '?' => regex.push_str("[^/]"),
            '\\' => {
                let c = chars.next()?;
                regex.push_str(&regex::escape(&c.to_string()));
            }
            '[' => {
                regex.push('[');
                let mut first = true;
                let mut closed = false;
                let mut any = false;
                while let Some(c) = chars.next() {
                    if c == ']' {
                        closed = true;
                        break;
                    }
                    if first && c == '^' {
                        regex.push('^');
                        first = false;
                        continue;
                    }
                    if c == '\\' {
                        let c = chars.next()?;
                        regex.push_str(&regex::escape(&c.to_string()));
                    } else if c == '-' {
                        regex.push('-');
                    } else {
                        regex.push_str(&regex::escape(&c.to_string()));
                    }
                    first = false;
                    any = true;
                }
                if !closed || !any {
                    return None;
                }
                regex.push(']');
            }
            other => regex.push_str(&regex::escape(&other.to_string())),
        }
    }
    regex.push('$');
    regex::Regex::new(&regex).ok()
}

pub(crate) fn go_path_glob(pattern:&str,value:&str)->bool{compile_go_path_glob(pattern).is_some_and(|pattern|pattern.is_match(value))}
