use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::ops::Deref;
use core::slice;

use crate::{Result, TemplateError, Value};

#[cfg(feature = "std")]
use std::sync::Mutex;

// ─── cell types ───────────────────────────────────────────────────────────────

#[cfg(feature = "std")]
type ByteCell = Arc<Mutex<Arc<[u8]>>>;
#[cfg(feature = "std")]
type ValueCell = Arc<Mutex<Arc<[Value]>>>;

#[cfg(not(feature = "std"))]
type ByteCell = Arc<[u8]>;
#[cfg(not(feature = "std"))]
type ValueCell = Arc<[Value]>;

// ─── storage ──────────────────────────────────────────────────────────────────

#[derive(Clone)]
enum SliceData {
    Bytes(ByteCell),
    Values(ValueCell),
}

// ─── view wrappers (Arc + span, no borrowed LockGuard) ────────────────────────

/// Immutable view over a byte backing.  Owns an `Arc<[u8]>` clone.
pub struct ByteView {
    data: Arc<[u8]>,
    start: usize,
    len: usize,
}

impl Deref for ByteView {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.data[self.start..self.start + self.len]
    }
}

/// Immutable view over a value backing.  Owns an `Arc<[Value]>` clone.
pub struct ValuesView {
    data: Arc<[Value]>,
    start: usize,
    len: usize,
}

impl Deref for ValuesView {
    type Target = [Value];
    fn deref(&self) -> &[Value] {
        &self.data[self.start..self.start + self.len]
    }
}

// ─── canonical element-type check ─────────────────────────────────────────────

fn canonical_elem_ok(v: &Value, elem: &str) -> bool {
    match elem {
        "interface {}" | "interface{}" => true,
        "string" => v.as_go_bytes().is_some(),
        "[]interface {}" | "[]interface{}" => {
            matches!(v, Value::List(_))
                || matches!(v, Value::Slice(s) if s.go_type() == "[]interface {}")
        }
        "map[string]interface {}" | "map[string]interface{}" => match v {
            Value::Map(_) => true,
            #[cfg(feature = "std")]
            Value::SharedMap(_) => true,
            _ => false,
        },
        _ => v.type_name() == elem,
    }
}

// These mutation entry points do not participate in MapContext graph retirement.
// Admit only payloads with no owned Value graph edges. Fn pointers carry no
// captured environment; NamedInt64 dyn method closures are deliberately denied.
#[cfg(feature="std")]
fn values_payload_has_no_edges(value:&Value)->bool {
    match value {
        Value::Nil|Value::NilError|Value::Bool(_)|Value::Int(_)|Value::Int64(_)|Value::Uint(_)|Value::Uint32(_)|Value::Uint8(_)|Value::Uint16(_)|Value::Float(_)|Value::String(_)|Value::ByteString(_)=>true,
        Value::NamedInt64(_,kind)=>kind.methods.is_empty(),
        #[cfg(feature="html")]
        Value::Safe{..}=>true,
        _=>false,
    }
}

// ─── TypedSlice ───────────────────────────────────────────────────────────────

/// Immutable Go named-slice metadata. Receivers are the current slice view,
/// including its offset/length, so slicing never captures stale contents.
pub struct SliceMethod {
    pub name: &'static str,
    pub invoke: fn(&TypedSlice, &[Value]) -> Result<Value>,
    pub signature: Option<&'static crate::Signature>,
}
pub struct SliceType {
    pub name: &'static str,
    pub element: &'static str,
    pub methods: &'static [SliceMethod],
    pub stringer: Option<fn(&TypedSlice) -> Result<Value>>,
}

#[derive(Clone)]
pub struct TypedSlice {
    go_type: &'static str,
    named: Option<&'static SliceType>,
    host_budget: Option<Arc<dyn Fn(usize) -> Result<()> + Send + Sync>>,
    storage: Option<SliceData>,
    start: usize,
    len: usize,
    cap: usize,
}

impl TypedSlice {
    /// Address of the first visible element, as used by Go fmt's %p. This
    /// reads the real backing (including a non-nil empty view); it does not
    /// expose writable pointers or manufacture a cell/zero-sized sentinel.
    pub(crate) fn data_address(&self) -> Result<usize> {
        match &self.storage {
            None => Ok(0),
            Some(SliceData::Bytes(cell)) => {
                #[cfg(feature="std")]
                let data = cell.lock().map_err(|_| TemplateError::Exec("byte slice lock poisoned".into()))?;
                #[cfg(not(feature="std"))]
                let data = cell;
                Ok(data.as_ptr().wrapping_add(self.start) as usize)
            }
            Some(SliceData::Values(cell)) => {
                #[cfg(feature="std")]
                let data = cell.lock().map_err(|_| TemplateError::Exec("value slice lock poisoned".into()))?;
                #[cfg(not(feature="std"))]
                let data = cell;
                Ok(data.as_ptr().wrapping_add(self.start) as usize)
            }
        }
    }

    // ── construction ──────────────────────────────────────────────────────────

    pub fn nil(go_type: &'static str) -> Self {
        TypedSlice {
            go_type,
            named: None,
            host_budget: None,
            storage: None,
            start: 0,
            len: 0,
            cap: 0,
        }
    }

    pub fn bytes(data: Option<Arc<[u8]>>) -> Self {
        let n = data.as_ref().map_or(0, |d| d.len());
        #[cfg(feature = "std")]
        let storage = data.map(|d| SliceData::Bytes(Arc::new(Mutex::new(d))));
        #[cfg(not(feature = "std"))]
        let storage = data.map(SliceData::Bytes);
        TypedSlice {
            go_type: "[]uint8",
            named: None,
            host_budget: None,
            storage,
            start: 0,
            len: n,
            cap: n,
        }
    }

    pub fn values(go_type: &'static str, data: Option<Arc<[Value]>>) -> Result<Self> {
        if go_type == "[]uint8" {
            return Err(TemplateError::Exec(
                "use bytes() for []uint8".into(),
            ));
        }
        let elem = go_type
            .strip_prefix("[]")
            .ok_or_else(|| TemplateError::Exec("invalid typed slice".into()))?;
        if let Some(values)=&data{crate::field_reference::check_storage_fields(values)?;}
        let n = data.as_ref().map_or(0, |d| d.len());
        if let Some(vals) = &data {
            for v in vals.iter() {
                if !canonical_elem_ok(v, elem) {
                    return Err(TemplateError::Exec("invalid typed slice".into()));
                }
            }
        }
        #[cfg(feature = "std")]
        let storage = data.map(|d| SliceData::Values(Arc::new(Mutex::new(d))));
        #[cfg(not(feature = "std"))]
        let storage = data.map(SliceData::Values);
        Ok(TypedSlice {
            go_type,
            named: None,
            host_budget: None,
            storage,
            start: 0,
            len: n,
            cap: n,
        })
    }

    pub fn named_bytes(kind: &'static SliceType, data: Option<Arc<[u8]>>) -> Result<Self> {
        Self::bytes(data).with_named_bytes(kind)
    }

    pub(crate) fn byte_parameter_compatible(&self)->bool {
        (self.go_type=="[]uint8"||self.go_type=="[]byte"||self.named.is_some_and(|kind|kind.element=="uint8"))&&!matches!(self.storage.as_ref(),Some(SliceData::Values(_)))
    }

    /// Change only a byte-slice type descriptor. The actual backing cell,
    /// window/capacity and original budget gate remain shared and unchanged.
    pub fn with_named_bytes(mut self, kind: &'static SliceType) -> Result<Self> {
        let byte_type=self.go_type=="[]uint8" || self.go_type=="[]byte" || self.named.is_some_and(|ty|ty.element=="uint8");
        if kind.name.is_empty() || kind.name.starts_with("[]") || kind.element!="uint8" || !byte_type || matches!(self.storage.as_ref(),Some(SliceData::Values(_))) {
            return Err(TemplateError::Exec("invalid named byte slice descriptor".into()));
        }
        self.go_type=kind.name; self.named=Some(kind); Ok(self)
    }

    /// Assign a byte slice to its unnamed Go type without copying its backing.
    /// Offset, length, capacity and the original request budget remain intact.
    pub fn into_plain_bytes(mut self) -> Result<Self> {
        if !self.byte_parameter_compatible() {
            return Err(TemplateError::Exec("invalid byte slice assignment".into()));
        }
        self.go_type = "[]uint8";
        self.named = None;
        Ok(self)
    }

    /// Capacity of a Go1.27 byte append, including noscan allocation-class
    /// rounding. This calculation allocates no backing and grants no writes;
    /// the caller must prepay the returned capacity before any allocation.
    /// Go Authors' runtime/slice.go/msize.go behavior (BSD-3-Clause).
    pub fn byte_append_capacity(&self, additional:usize)->Result<usize>{
        if !self.byte_parameter_compatible(){return Err(TemplateError::Exec("expected byte slice".into()));}
        let length=self.len.checked_add(additional).filter(|n|*n<=isize::MAX as usize).ok_or_else(||TemplateError::Exec("byte append length overflow".into()))?;
        if length<=self.cap{return Ok(self.cap);}
        let double=self.cap.checked_mul(2).filter(|n|*n<=isize::MAX as usize);
        let mut capacity=match double{Some(double)if length>double=>length,Some(double)if self.cap<256=>double,Some(_)=>self.cap,None=>length};
        if self.cap>=256&&double.is_some()&&length<=double.unwrap(){while capacity<length{capacity=match capacity.checked_add(768).map(|n|n>>2).and_then(|step|capacity.checked_add(step)).filter(|n|*n<=isize::MAX as usize){Some(n)=>n,None=>length};}}
        const CLASSES:&[usize]=&[0,8,16,24,32,48,64,80,96,112,128,144,160,176,192,208,224,240,256,288,320,352,384,416,448,480,512,576,640,704,768,896,1024,1152,1280,1408,1536,1792,2048,2304,2688,3072,3200,3456,4096,4864,5376,6144,6528,6784,6912,8192,9472,9728,10240,10880,12288,13568,14336,16384,18432,19072,20480,21760,24576,27264,28672,32768];
        let capacity=if capacity<=32760{CLASSES.iter().copied().find(|size|*size>=capacity).ok_or_else(||TemplateError::Exec("byte size class missing".into()))?}else{capacity.checked_add(8191).map(|n|n&!8191).ok_or_else(||TemplateError::Exec("byte append capacity overflow".into()))?};
        if capacity>isize::MAX as usize{return Err(TemplateError::Exec("byte append capacity overflow".into()));}Ok(capacity)
    }

    /// Full byte backing size, including portions outside this view. Does not
    /// clone the backing or invoke its budget; hosts can prepay a later COW.
    pub fn byte_backing_len(&self) -> Option<usize> {
        match &self.storage {
            Some(SliceData::Bytes(cell)) => {
                #[cfg(feature = "std")]
                { Some(cell.lock().unwrap_or_else(|p| p.into_inner()).len()) }
                #[cfg(not(feature = "std"))]
                { Some(cell.len()) }
            }
            None if self.go_type == "[]uint8" || self.go_type == "[]byte"
                || self.named.is_some_and(|kind| kind.element == "uint8") => Some(0),
            _ => None,
        }
    }

    /// Full Values backing size without cloning it or entering a host budget.
    /// A nil byte slice is not a Values backing, even though it has no cell.
    pub fn values_backing_len(&self) -> Option<usize> {
        match &self.storage {
            Some(SliceData::Values(cell)) => {
                #[cfg(feature="std")]
                { Some(cell.lock().unwrap_or_else(|p|p.into_inner()).len()) }
                #[cfg(not(feature="std"))]
                { Some(cell.len()) }
            }
            None if self.named.map(|kind|kind.element).or_else(||self.go_type.strip_prefix("[]"))
                .is_some_and(|elem|!matches!(elem,"byte"|"uint8")) => Some(0),
            _ => None,
        }
    }

    /// Copy into the visible Values window. The entire input is type-checked,
    /// including any part beyond the destination window. Views share one cell;
    /// existing immutable snapshots keep their old backing through COW.
    /// A COW allocation requires a host budget. Its callback runs outside the
    /// cell lock and reserves the full backing before it can be cloned.
    /// Copies only edge-free scalar payloads. Composite Value graphs require
    /// a graph-aware writer; dyn method-bearing named integers are rejected.
    /// COW caused by strong/weak observers or old callback-bearing values is
    /// prepaid. Old opaque values are retained until the cell lock is released.
    #[cfg(feature="std")]
    pub fn write_values_range(&self,offset:usize,buf:&[Value])->Result<usize>{
        if offset>self.len{return Err(TemplateError::Exec("slice index out of range".into()));}
        let elem=self.named.map(|kind|kind.element).or_else(||self.go_type.strip_prefix("[]"))
            .ok_or_else(||TemplateError::Exec("invalid Values slice type".into()))?;
        if buf.iter().any(|value|!canonical_elem_ok(value,elem)){
            return Err(TemplateError::Exec("slice element type mismatch".into()));
        }
        if buf.iter().any(|value|!values_payload_has_no_edges(value)){
            return Err(TemplateError::Exec("Values mutation accepts edge-free scalar payloads only".into()));
        }
        if matches!(self.storage.as_ref(),Some(SliceData::Bytes(_)))||self.values_backing_len().is_none(){
            return Err(TemplateError::Exec("write_values_range requires Values backing".into()));
        }
        if let Some(reserve)=&self.host_budget{reserve(0)?;}
        let n=buf.len().min(self.len-offset);
        if n==0{return Ok(0);}
        let Some(SliceData::Values(cell))=&self.storage else{return Err(TemplateError::Exec("nil Values slice write".into()));};
        let start=self.start.checked_add(offset).ok_or_else(||TemplateError::Exec("slice span overflow".into()))?;
        let end=start.checked_add(n).ok_or_else(||TemplateError::Exec("slice span overflow".into()))?;
        let mut paid=0;
        for _ in 0..8 {
            let mut current=cell.lock().unwrap_or_else(|p|p.into_inner());
            if end>current.len(){return Err(TemplateError::Exec("invalid Values slice span".into()));}
            let peak=current.len().checked_mul(core::mem::size_of::<Value>()).and_then(|n|n.checked_add(128)).and_then(|n|n.checked_mul(2))
                .ok_or_else(||TemplateError::Exec("Values COW size overflow".into()))?;
            let retire_old=current[start..end].iter().any(|value|!values_payload_has_no_edges(value));
            let can_in_place=Arc::strong_count(&current)==1&&Arc::weak_count(&current)==0&&!retire_old;
            if can_in_place||paid>=peak {
                // Keep a strong snapshot when old payloads can execute Drop.
                // This forces COW even if another observer concurrently exits.
                let retired=retire_old.then(||current.clone());
                Arc::make_mut(&mut current)[start..end].clone_from_slice(&buf[..n]);
                drop(current);
                drop(retired);
                return Ok(n);
            }
            drop(current);
            self.reserve_host_bytes(peak)?;
            paid=peak;
        }
        Err(TemplateError::Exec("Values backing changed during write admission".into()))
    }
    #[cfg(not(feature="std"))]
    pub fn write_values_range(&self,_offset:usize,_buf:&[Value])->Result<usize>{
        Err(TemplateError::Exec("mutation not available in no_std".into()))
    }

    pub fn named_values(kind: &'static SliceType, data: Option<Arc<[Value]>>) -> Result<Self> {
        if kind.name.is_empty() || kind.name.starts_with("[]") || kind.element == "uint8" || kind.element.is_empty() {
            return Err(TemplateError::Exec("invalid named value slice descriptor".into()));
        }
        if data.as_ref().is_some_and(|values| values.iter().any(|v| !canonical_elem_ok(v, kind.element))) {
            return Err(TemplateError::Exec("invalid named slice element".into()));
        }
        if let Some(values)=&data{crate::field_reference::check_storage_fields(values)?;}
        let n = data.as_ref().map_or(0, |values| values.len());
        #[cfg(feature = "std")]
        let storage = data.map(|d| SliceData::Values(Arc::new(Mutex::new(d))));
        #[cfg(not(feature = "std"))]
        let storage = data.map(SliceData::Values);
        Ok(Self { go_type: kind.name, named: Some(kind), host_budget: None, storage, start: 0, len: n, cap: n })
    }

    /// A host factory binds its request-owned budget, usually through a Weak
    /// control owner. Clones and reslices retain the same preallocation gate.
    pub fn with_host_budget(mut self, reserve: Arc<dyn Fn(usize) -> Result<()> + Send + Sync>) -> Self {
        self.host_budget = Some(reserve); self
    }
    /// Copy only the original budget gate, never a chain of receiver closures.
    pub fn host_budget(&self) -> Option<Arc<dyn Fn(usize) -> Result<()> + Send + Sync>> {
        self.host_budget.clone()
    }
    pub fn reserve_host_bytes(&self, bytes: usize) -> Result<()> {
        self.host_budget.as_ref().ok_or_else(|| TemplateError::Exec("named slice has no host budget".into()))?(bytes)
    }
    pub fn named_type(&self) -> Option<&'static SliceType> { self.named }
    pub(crate) fn method(&self, name: &str) -> Option<&'static SliceMethod> {
        self.named?.methods.iter().find(|method| method.name == name)
    }
    pub fn string_value(&self) -> Result<Option<Value>> {
        self.named.and_then(|kind| kind.stringer).map(|stringer| {
            let value = stringer(self)?;
            if value.as_go_bytes().is_none() { return Err(TemplateError::Exec("slice String method must return string".into())); }
            Ok(value)
        }).transpose()
    }

    /// Input backing must already be prepaid. The bounded structural scan rejects
    /// retained field lvalues; resolve them at an Interface boundary first.
    pub fn from_list(data: Arc<[Value]>) -> Result<Self> {
        crate::field_reference::check_storage_fields(&data)?;
        let n = data.len();
        #[cfg(feature = "std")]
        let storage = SliceData::Values(Arc::new(Mutex::new(data)));
        #[cfg(not(feature = "std"))]
        let storage = SliceData::Values(data);
        Ok(TypedSlice {
            go_type: "[]interface {}",
            named: None,
            host_budget: None,
            storage: Some(storage),
            start: 0,
            len: n,
            cap: n,
        })
    }

    pub fn with_len(mut self, n: usize) -> Result<Self> {
        if n > self.cap {
            return Err(TemplateError::Exec("invalid typed slice".into()));
        }
        self.len = n;
        Ok(self)
    }

    // ── basic accessors ───────────────────────────────────────────────────────

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn cap(&self) -> usize {
        self.cap
    }

    pub fn is_nil(&self) -> bool {
        self.storage.is_none()
    }

    pub fn go_type(&self) -> &'static str {
        self.go_type
    }

    /// Reads the *current* cell each call (Go semantics: sort-during-range).
    pub fn get(&self, index: usize) -> Option<Value> {
        if index >= self.len {
            return None;
        }
        let cell = self.storage.as_ref()?;
        match cell {
            SliceData::Bytes(bc) => {
                #[cfg(feature = "std")]
                {
                    let guard = bc.lock().unwrap_or_else(|p|p.into_inner());
                    let b: &[u8] = guard.as_ref();
                    Some(Value::Uint8(b[self.start + index]))
                }
                #[cfg(not(feature = "std"))]
                {
                    let b: &[u8] = bc.as_ref();
                    Some(Value::Uint8(b[self.start + index]))
                }
            }
            SliceData::Values(vc) => {
                #[cfg(feature = "std")]
                {
                    let guard = vc.lock().unwrap_or_else(|p|p.into_inner());
                    let v: &[Value] = guard.as_ref();
                    Some(v[self.start + index].clone())
                }
                #[cfg(not(feature = "std"))]
                {
                    let v: &[Value] = vc.as_ref();
                    Some(v[self.start + index].clone())
                }
            }
        }
    }

    // ── view helpers ──────────────────────────────────────────────────────────

    /// Visible bytes for `[]uint8`; nil `[]uint8` yields empty `Some`.
    pub fn visible_bytes(&self) -> Option<ByteView> {
        match &self.storage {
            Some(SliceData::Bytes(bc)) => {
                #[cfg(feature = "std")]
                let data = bc.lock().unwrap_or_else(|p|p.into_inner()).clone();
                #[cfg(not(feature = "std"))]
                let data = Arc::clone(bc);
                Some(ByteView {
                    data,
                    start: self.start,
                    len: self.len,
                })
            }
            None if self.go_type == "[]uint8" || self.named.is_some_and(|kind| kind.element == "uint8") => Some(ByteView {
                data: Arc::from(Vec::new().as_slice()),
                start: 0,
                len: 0,
            }),
            _ => None,
        }
    }

    /// Visible values for non-uint8 typed slices; nil yields empty `Some`.
    pub fn visible_values(&self) -> Option<ValuesView> {
        match &self.storage {
            Some(SliceData::Values(vc)) => {
                #[cfg(feature = "std")]
                let data = vc.lock().unwrap_or_else(|p|p.into_inner()).clone();
                #[cfg(not(feature = "std"))]
                let data = Arc::clone(vc);
                Some(ValuesView {
                    data,
                    start: self.start,
                    len: self.len,
                })
            }
            None if self.go_type != "[]uint8" && !self.named.is_some_and(|kind| kind.element == "uint8") => Some(ValuesView {
                data: Arc::from(Vec::new().as_slice()),
                start: 0,
                len: 0,
            }),
            _ => None,
        }
    }

    /// Entire backing Arc (budget API).
    pub fn retained_values(&self) -> Option<Arc<[Value]>> {
        match &self.storage {
            Some(SliceData::Values(vc)) => {
                #[cfg(feature = "std")]
                {
                    Some(vc.lock().unwrap_or_else(|p|p.into_inner()).clone())
                }
                #[cfg(not(feature = "std"))]
                {
                    Some(Arc::clone(vc))
                }
            }
            _ => None,
        }
    }

    pub fn retained_len(&self) -> usize {
        match &self.storage {
            Some(SliceData::Bytes(bc)) => {
                #[cfg(feature = "std")]
                {
                    bc.lock().unwrap_or_else(|p|p.into_inner()).len()
                }
                #[cfg(not(feature = "std"))]
                {
                    bc.len()
                }
            }
            Some(SliceData::Values(vc)) => {
                #[cfg(feature = "std")]
                {
                    vc.lock().unwrap_or_else(|p|p.into_inner()).len()
                }
                #[cfg(not(feature = "std"))]
                {
                    vc.len()
                }
            }
            None => 0,
        }
    }

    // ── reslicing ─────────────────────────────────────────────────────────────

    pub fn reslice(&self, lo: usize, hi: usize) -> Result<Self> {
        self.reslice3(lo, hi, self.cap)
    }

    pub fn reslice3(&self, lo: usize, hi: usize, max: usize) -> Result<Self> {
        if lo > hi || hi > max || max > self.cap {
            return Err(TemplateError::Exec("invalid typed slice".into()));
        }
        let new_start = self
            .start
            .checked_add(lo)
            .ok_or_else(|| TemplateError::Exec("invalid typed slice".into()))?;
        let mut out = self.clone();
        out.start = new_start;
        out.len = hi - lo;
        out.cap = max - lo;
        Ok(out)
    }

    // ── mutation: write_range (Bytes only) ────────────────────────────────────

    /// Go-compatible copy into the visible byte window.
    /// Validates `offset <= len`; writes `min(buf.len(), len - offset)` bytes.
    /// nil (len==0, offset==0): writes 0 bytes, returns Ok(0).
    /// One `make_mut` on the cell.
    #[cfg(feature = "std")]
    pub fn write_range(&self, offset: usize, buf: &[u8]) -> Result<usize> {
        if offset > self.len {
            return Err(TemplateError::Exec("slice index out of range".into()));
        }
        let writable = self.len - offset;
        let n = core::cmp::min(buf.len(), writable);
        if n == 0 {
            return Ok(0);
        }
        let cell = self
            .storage
            .as_ref()
            .ok_or_else(|| TemplateError::Exec("nil slice write_range".into()))?;
        match cell {
            SliceData::Bytes(bc) => {
                let mut guard=bc.lock().unwrap_or_else(|p|p.into_inner());
                let target = Arc::make_mut(&mut guard);
                target[self.start + offset..self.start + offset + n]
                    .copy_from_slice(&buf[..n]);
                Ok(n)
            }
            SliceData::Values(_) => Err(TemplateError::Exec(
                "write_range on non-bytes slice".into(),
            )),
        }
    }

    #[cfg(not(feature = "std"))]
    pub fn write_range(&self, _offset: usize, _buf: &[u8]) -> Result<usize> {
        Err(TemplateError::Exec("mutation not available in no_std".into()))
    }

    // ── mutation: sort_strings ([]string, stable raw-byte) ────────────────────

    /// Stable sort of visible elements by raw byte content.
    /// Only valid on `[]string`.  Snapshots visible Arc, drops guard,
    /// re-locks, verifies `Arc::ptr_eq`, then `make_mut` + sort in place.
    /// len/cap unchanged; no recursive lock-holding.
    #[cfg(feature="std")]
    pub fn sort_strings(&self)->Result<()>{
        if self.go_type!="[]string"{return Err(TemplateError::Exec("sort_strings requires []string".into()));}
        if self.len==0{return Ok(());}
        let Some(SliceData::Values(cell))=&self.storage else{return Err(TemplateError::Exec("invalid string slice".into()));};
        let snapshot=cell.lock().unwrap_or_else(|p|p.into_inner()).clone();
        let mut values=snapshot[self.start..self.start+self.len].to_vec();
        if values.iter().any(|v|v.as_go_bytes().is_none()){return Err(TemplateError::Exec("invalid string slice element".into()));}
        values.sort_by(|a,b|a.as_go_bytes().cmp(&b.as_go_bytes()));
        let mut current=cell.lock().unwrap_or_else(|p|p.into_inner());
        if !Arc::ptr_eq(&current,&snapshot){return Err(TemplateError::Exec("slice changed during sort".into()));}
        drop(snapshot);
        Arc::make_mut(&mut current)[self.start..self.start+self.len].clone_from_slice(&values);Ok(())
    }

    #[cfg(not(feature = "std"))]
    pub fn sort_strings(&self) -> Result<()> {
        Err(TemplateError::Exec("mutation not available in no_std".into()))
    }

    // ── iteration ─────────────────────────────────────────────────────────────

    pub fn iter(&self) -> TypedSliceIter<'_> {
        TypedSliceIter { s: self, idx: 0 }
    }

    pub fn to_vec(&self) -> Vec<Value> {
        self.iter().collect()
    }
}

// ─── TypedSliceIter ───────────────────────────────────────────────────────────

pub struct TypedSliceIter<'a> {
    s: &'a TypedSlice,
    idx: usize,
}

impl<'a> Iterator for TypedSliceIter<'a> {
    type Item = Value;
    fn next(&mut self) -> Option<Value> {
        if self.idx >= self.s.len {
            return None;
        }
        let v = self.s.get(self.idx);
        self.idx += 1;
        v
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        let rem = self.s.len - self.idx;
        (rem, Some(rem))
    }
}

impl<'a> ExactSizeIterator for TypedSliceIter<'a> {}

// ─── Debug ────────────────────────────────────────────────────────────────────

impl fmt::Debug for TypedSlice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TypedSlice")
            .field("go_type", &self.go_type)
            .field("len", &self.len)
            .field("cap", &self.cap)
            .field("nil", &self.is_nil())
            .finish()
    }
}

// ─── PartialEq ────────────────────────────────────────────────────────────────

impl PartialEq for TypedSlice {
    fn eq(&self, other: &Self) -> bool {
        self.go_type == other.go_type
            && self.is_nil() == other.is_nil()
            && self.iter().eq(other.iter())
    }
}

// ─── SliceRef ─────────────────────────────────────────────────────────────────

pub enum SliceRef<'a> {
    List(&'a Arc<[Value]>),
    Typed(&'a TypedSlice),
}

impl<'a> SliceRef<'a> {
    pub fn len(&self) -> usize {
        match self {
            Self::List(v) => v.len(),
            Self::Typed(t) => t.len(),
        }
    }

    pub fn cap(&self) -> usize {
        match self {
            Self::List(v) => v.len(),
            Self::Typed(t) => t.cap(),
        }
    }

    pub fn is_nil(&self) -> bool {
        match self {
            Self::List(_) => false,
            Self::Typed(t) => t.is_nil(),
        }
    }

    pub fn go_type(&self) -> &'static str {
        match self {
            Self::List(_) => "[]interface {}",
            Self::Typed(t) => t.go_type(),
        }
    }

    pub fn get(&self, index: usize) -> Option<Value> {
        match self {
            Self::List(v) => v.get(index).cloned(),
            Self::Typed(t) => t.get(index),
        }
    }

    pub fn iter(&self) -> SliceIter<'a> {
        match self {
            Self::List(v) => SliceIter::List(v.iter()),
            Self::Typed(t) => SliceIter::Typed(t.iter()),
        }
    }

    pub fn visible_bytes(&self) -> Option<ByteView> {
        match self {
            Self::List(_) => None,
            Self::Typed(t) => t.visible_bytes(),
        }
    }

    pub fn visible_values(&self) -> Option<ValuesView> {
        match self {
            Self::List(v) => Some(ValuesView {
                data: Arc::clone(v),
                start: 0,
                len: v.len(),
            }),
            Self::Typed(t) => t.visible_values(),
        }
    }
}

// ─── SliceIter ────────────────────────────────────────────────────────────────

pub enum SliceIter<'a> {
    List(slice::Iter<'a, Value>),
    Typed(TypedSliceIter<'a>),
}

impl<'a> Iterator for SliceIter<'a> {
    type Item = Value;
    fn next(&mut self) -> Option<Value> {
        match self {
            Self::List(it) => it.next().cloned(),
            Self::Typed(it) => it.next(),
        }
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        match self {
            Self::List(it) => it.size_hint(),
            Self::Typed(it) => it.size_hint(),
        }
    }
}

impl<'a> ExactSizeIterator for SliceIter<'a> {}

impl AsRef<[u8]> for ByteView{fn as_ref(&self)->&[u8]{self}}
impl From<ByteView> for Arc<[u8]>{fn from(view:ByteView)->Self{if view.start==0&&view.len==view.data.len(){view.data}else{Arc::from(&*view)}}}

#[path = "go_slice_atomic.rs"]
mod atomic;
pub use atomic::{PreparedValuesWrites, ValuesWrite, ValuesCommitError};
