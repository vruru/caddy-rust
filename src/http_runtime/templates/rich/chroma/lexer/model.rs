use serde::Deserialize;
use serde_json::Value;
use std::sync::Arc;
fn arc_value<'de, D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Arc<Value>, D::Error> {
    Ok(Arc::new(Value::deserialize(d)?))
}
use std::collections::BTreeMap;
fn null_default<'de, D: serde::Deserializer<'de>, T: Deserialize<'de> + Default>(
    d: D,
) -> std::result::Result<T, D::Error> {
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Config {
    pub name: String,
    #[serde(deserialize_with = "null_default")]
    pub aliases: Vec<String>,
    #[serde(deserialize_with = "null_default")]
    pub filenames: Vec<String>,
    #[serde(deserialize_with = "null_default")]
    pub alias_filenames: Vec<String>,
    #[serde(deserialize_with = "null_default")]
    pub mime_types: Vec<String>,
    pub ensure_n_l: bool,
    pub priority: f32,
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Rule {
    pub program: String,
    #[serde(deserialize_with = "arc_value")]
    pub emitter: Arc<Value>,
    #[serde(deserialize_with = "arc_value")]
    pub mutator: Arc<Value>,
    #[serde(skip)]
    pub program_index: usize,
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Mapping {
    pub from: i32,
    pub to: i32,
    #[serde(deserialize_with = "null_default")]
    pub words: Vec<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Definition {
    pub config: Config,
    pub kind: String,
    pub children: Vec<usize>,
    #[serde(default, deserialize_with = "null_default")]
    pub mapping: Vec<Mapping>,
    #[serde(skip)]
    pub mapping_lookup: BTreeMap<i32, BTreeMap<String, i32>>,
    #[serde(deserialize_with = "null_default")]
    pub states: BTreeMap<String, Vec<Rule>>,
}
