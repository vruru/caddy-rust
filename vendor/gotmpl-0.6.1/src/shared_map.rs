#[path="map_retired.rs"]
mod retired;
use retired::{EntriesSlot,GenericNode,KeyedNode,Mutex};
#[path="generic_map.rs"]
mod generic;
pub use generic::{GenericMapCell,GenericMapSnapshot};
// Mutable map identity scoped to one render graph. Locks never span callbacks.
use crate::{Result, TemplateError, Value};
use std::{
    collections::BTreeMap,
    sync::Arc,
};
use crate::GoKey;

type Entries = BTreeMap<Arc<str>, Value>;
type KeyedEntries = BTreeMap<GoKey, Value>;

struct Graph {
    writes: Mutex<usize>,
}

#[derive(Clone)]
pub struct MapContext {
    graph: Arc<Graph>,
}

pub struct MapCell {
    entries: EntriesSlot<KeyedEntries>,
    graph: Arc<Graph>,
    is_nil:bool,
    retired:Option<Box<KeyedNode>>,
}

// The cell Arc, entries Arc and prepaid node fit the caller's 128-byte
// metadata reservation. Locks are inline; this is not an RSS guarantee.
const _: () = assert!(std::mem::size_of::<MapCell>() + std::mem::size_of::<KeyedEntries>() + 4*std::mem::size_of::<usize>() + std::mem::size_of::<KeyedNode>() <= 128);
impl Drop for MapCell {
    fn drop(&mut self) {
        let entries=self.entries.take();
        self.retired.take().expect("live map has retirement node").retire(entries);
    }
}

fn error(message: &str) -> TemplateError {
    TemplateError::Exec(message.into())
}

impl Default for MapContext {
    fn default() -> Self {
        Self::new()
    }
}

impl MapContext {
    pub fn new() -> Self {
        Self {
            graph: Arc::new(Graph {
                writes: Mutex::new(16_384),
            }),
        }
    }

    pub fn nil_map(&self)->Value{Value::SharedMap(Arc::new(MapCell{entries:EntriesSlot::new(KeyedEntries::new()),graph:self.graph.clone(),is_nil:true,retired:Some(KeyedNode::new())}))}
    pub fn map(&self,entries:Entries)->Result<Value>{self.map_go(entries.into_iter().map(|(key,value)|(GoKey::Utf8(key),value)).collect())}

    pub fn map_go(&self, entries: KeyedEntries) -> Result<Value> {
        let cell = Arc::new(MapCell {
            entries: EntriesSlot::new(entries),
            graph: self.graph.clone(),
            is_nil:false,
            retired:Some(KeyedNode::new()),
        });

        // Re-validate the provided entries to enforce budgets and inspect values.
        // The caller is expected to provide pre-validated entries, but we re-check
        // to maintain consistency with existing `map` behavior which validates on construction.
        let gate=self.graph.writes.lock().map_err(|_|error("map graph lock poisoned"))?;
        let mut nodes = 16_384usize;
        let mut bytes = 1024 * 1024usize;
        for (key, value) in cell.snapshot_go()? .iter() {
            bytes = bytes
                .checked_sub(key.len())
                .ok_or_else(|| error("map value byte limit exceeded"))?;
            cell.inspect(value, 1, &mut nodes, &mut bytes)?;
        }
        drop(gate);
        Ok(Value::SharedMap(cell))
    }
}

impl MapCell {
    /// Validate the current graph and wrappers; historical placement does not
    /// constrain later detached or shallower values.
    pub(crate) fn ensure_depth(&self, depth:usize)->Result<()> {
        let gate=self.graph.writes.lock().map_err(|_|error("map graph lock poisoned"))?;
        if depth>32{return Err(error("map value nesting limit exceeded"));}
        let base=depth+1;
        let(mut nodes,mut bytes)=(16_384usize,1024*1024usize);
        for(key,value)in self.snapshot_go()?.iter(){
            bytes=bytes.checked_sub(key.len()).ok_or_else(||error("map value byte limit exceeded"))?;
            self.inspect(value,base,&mut nodes,&mut bytes)?;
        }
        drop(gate);
        Ok(())
    }
    pub fn is_nil(&self)->bool{self.is_nil}
    /// UTF-8 compatibility view; O(n). Byte-aware consumers use snapshot_go().
    pub fn snapshot(&self) -> Result<Arc<Entries>> {
        let keyed = self.entries.lock().map(|m| m.clone()).map_err(|_| error("map lock poisoned"))?;
        let mut plain = Entries::new();
        for (key, value) in keyed.iter() {
            match key { GoKey::Utf8(key)=>{plain.insert(key.clone(),value.clone());},GoKey::Bytes(_)=>return Err(error("map contains non-UTF8 keys; use snapshot_go")) }
        }
        Ok(Arc::new(plain))
    }

    pub fn snapshot_go(&self) -> Result<Arc<KeyedEntries>> {
        self.entries
            .lock()
            .map(|m| m.clone())
            .map_err(|_| error("map lock poisoned"))
    }

    pub fn get(&self, key: &str) -> Result<Option<Value>> {
        self.get_bytes(key.as_bytes())
    }

    pub fn get_bytes(&self, key: &[u8]) -> Result<Option<Value>> {
        self.entries
            .lock()
            .map(|m| m.get(key).cloned())
            .map_err(|_| error("map lock poisoned"))
    }

    pub fn set(&self, key: Arc<str>, value: Value) -> Result<()> {
        self.set_key(GoKey::Utf8(key), value)
    }

    pub fn set_key(&self, key: GoKey, value: Value) -> Result<()> {
        if self.is_nil{return Err(error("assignment to entry in nil map"));}
        let mut writes = self
            .graph
            .writes
            .lock()
            .map_err(|_| error("map graph lock poisoned"))?;
        *writes = writes
            .checked_sub(1)
            .ok_or_else(|| error("map mutation budget exhausted"))?;

        let mut nodes = 16_384usize;
        let mut bytes = 1024 * 1024usize;
        let base=1;
        self.inspect(&value, base, &mut nodes, &mut bytes)?;

        let current = self.snapshot_go()?;
        if current.len() >= 16_384 && !current.contains_key(&key) {
            return Err(error("map entry limit exceeded"));
        }

        bytes = 1024 * 1024;
        nodes = 16_384;
        for (old_key, old_value) in current.iter().filter(|(old, _)| *old != &key) {
            bytes = bytes
                .checked_sub(old_key.len())
                .ok_or_else(|| error("map value byte limit exceeded"))?;
            self.inspect(old_value, base, &mut nodes, &mut bytes)?;
        }
        bytes = bytes
            .checked_sub(key.len())
            .ok_or_else(|| error("map value byte limit exceeded"))?;
        self.inspect(&value, base, &mut nodes, &mut bytes)?;

        let mut entries = self
            .entries
            .lock()
            .map_err(|_| error("map lock poisoned"))?;
        let retired=Arc::make_mut(&mut entries).insert(key, value);
        drop(entries);drop(writes);drop(retired);drop(current);
        Ok(())
    }

    pub fn remove(&self, key: &str) -> Result<()> {
        self.remove_bytes(key.as_bytes())
    }

    pub fn remove_bytes(&self, key: &[u8]) -> Result<()> {
        let mut writes = self
            .graph
            .writes
            .lock()
            .map_err(|_| error("map graph lock poisoned"))?;
        *writes = writes
            .checked_sub(1)
            .ok_or_else(|| error("map mutation budget exhausted"))?;

        let mut entries = self
            .entries
            .lock()
            .map_err(|_| error("map lock poisoned"))?;
        let retired=Arc::make_mut(&mut entries).remove(key);
        drop(entries);drop(writes);drop(retired);
        Ok(())
    }

    fn inspect(
        &self,
        value: &Value,
        depth: usize,
        nodes: &mut usize,
        bytes: &mut usize,
    ) -> Result<()> {
        if depth > 32 {
            return Err(error("map value nesting limit exceeded"));
        }
        *nodes = nodes
            .checked_sub(1)
            .ok_or_else(|| error("map value node limit exceeded"))?;
        *bytes = bytes
            .checked_sub(32)
            .ok_or_else(|| error("map value byte limit exceeded"))?;
        match value {
            Value::Field(_)=>return Err(error("map storage rejects retained field references")),
            Value::ByteString(s) => {
                *bytes = bytes
                    .checked_sub(s.as_bytes().len())
                    .ok_or_else(|| error("map value byte limit exceeded"))?
            }
            Value::String(s) => {
                *bytes = bytes
                    .checked_sub(s.as_bytes().len())
                    .ok_or_else(|| error("map value byte limit exceeded"))?
            }
            Value::Slice(slice)=>{if let Some(values)=slice.retained_values(){for value in values.iter(){self.inspect(value,depth+1,nodes,bytes)?;}}else{*bytes=bytes.checked_sub(slice.retained_len()).ok_or_else(||error("map value byte limit exceeded"))?;}},
            Value::List(values) => {
                for value in values.iter() {
                    self.inspect(value, depth + 1, nodes, bytes)?;
                }
            }
            Value::Map(values) => {
                for (key, value) in values.iter() {
                    *bytes = bytes
                        .checked_sub(key.len())
                        .ok_or_else(|| error("map value byte limit exceeded"))?;
                    self.inspect(value, depth + 1, nodes, bytes)?;
                }
            }
            Value::GenericMap(map)=>{
                if !Arc::ptr_eq(&self.graph,&map.graph){return Err(error("mutable template maps belong to different renders"));}
                for(key,value)in map.snapshot()?.iter(){self.inspect(key,depth+1,nodes,bytes)?;self.inspect(value,depth+1,nodes,bytes)?;}
            }
            Value::SharedMap(map) => {
                if std::ptr::eq(self, map.as_ref()) {
                    return Err(error("cyclic template map is not supported"));
                }
                if !Arc::ptr_eq(&self.graph, &map.graph) {
                    return Err(error("mutable template maps belong to different renders"));
                }
                let snapshot = map.snapshot_go()?;
                for (key, value) in snapshot.iter() {
                    *bytes = bytes
                        .checked_sub(key.len())
                        .ok_or_else(|| error("map value byte limit exceeded"))?;
                    self.inspect(value, depth + 1, nodes, bytes)?;
                }
            }
            Value::Object(object) => {
                for value in object.fields.values() {
                    self.inspect(value, depth + 1, nodes, bytes)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
}
