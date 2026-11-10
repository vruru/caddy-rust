use anyhow::Result;
use serde_json::Value;

/// Mirror JSONModuleObject's module -> map[string]any -> JSON boundary.
/// This applies only to module objects, not typed top-level durations/ports.
pub(super) fn normalize(value: Value) -> Result<Value> {
    Ok(crate::admin_json::decoded(&serde_json::to_vec(&value)?)?)
}
