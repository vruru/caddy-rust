//! Complete request-body admission before the next handler may run.
use anyhow::{Context, Result, ensure};
use serde_json::Value;

pub(crate) const MAX_SIZE: u64 = 50 * 1024 * 1024;

#[derive(Clone, Debug)]
pub(crate) struct Plan {
    pub(crate) max_size: u64,
}

pub(crate) fn parse(value: &Value, path: &str) -> Result<Plan> {
    let object = super::helpers::object(value, path)?;
    super::helpers::deny_unknown(object, &["handler", "max_size"], path)?;
    let max_size = object
        .get("max_size")
        .and_then(Value::as_number)
        .and_then(|number| number.as_go_i64())
        .with_context(|| format!("bounded_body integer required at {path}/max_size"))?;
    ensure!(
        (1..=MAX_SIZE as i64).contains(&max_size),
        "bounded_body max_size must be in [1, {MAX_SIZE}] at {path}/max_size"
    );
    Ok(Plan {
        max_size: max_size as u64,
    })
}
