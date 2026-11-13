// Portions derived from Go math/big. Copyright The Go Authors.
// BSD 3-Clause license retained in THIRD-PARTY-NOTICES.
//! Template-private nat headers over real, scoped, scalar Values cells.
use super::*;
use gotmpl::{Int64Type, TypedSlice, ValuesView};

static WORD: LazyLock<Arc<Int64Type>> = LazyLock::new(|| Arc::new(Int64Type {
    name: "big.Word", kind: "uint", stringer: None,
    methods: BTreeMap::new(), signatures: BTreeMap::new(),
}));
fn value(n: u64) -> Value { Value::NamedInt64(n as i64, WORD.clone()) }
fn decode(v: &Value) -> RenderResult<u64> {
    match v {
        Value::NamedInt64(n, kind) if Arc::ptr_eq(kind, &WORD) => Ok(*n as u64),
        _ => Err(error("invalid big.Word payload")),
    }
}
fn word_len(n: &BigInt) -> RenderResult<usize> {
    usize::try_from(n.bits().div_ceil(64)).map_err(|_| error("big.Word length overflow"))
}
fn capacity(n: usize) -> RenderResult<usize> {
    if n <= 1 { Ok(n) } else { n.checked_add(4).ok_or_else(|| error("big.Word capacity overflow")) }
}
#[derive(Clone)]
pub(super) struct Words { slice: TypedSlice }
pub(super) struct Staged {
    pub(super) next: Words,
    pub(super) target: Option<TypedSlice>,
    pub(super) values: Vec<Value>,
}
struct Element { slice: TypedSlice, index: usize, owner: Weak<Factory> }
impl gotmpl::FieldSource for Element {
    fn read_field(&self, name: &'static str) -> RenderResult<Value> {
        if name != "word" { return Err(error("unknown big.Word element field")); }
        let owner = self.owner.upgrade().ok_or_else(||error("big.Word field owner retired"))?;
        owner.work(0)?;
        let value = self.slice.try_get(self.index)?.ok_or_else(||error("big.Word field index out of range"))?;
        decode(&value)?;
        Ok(value)
    }
}
fn element(slice:&TypedSlice,index:usize,owner:Arc<dyn std::any::Any+Send+Sync>)->RenderResult<Value> {
    let owner = owner.downcast::<Factory>().map_err(|_|error("invalid big.Word field owner"))?;
    owner.reserve(std::mem::size_of::<Element>() + std::mem::size_of::<gotmpl::FieldReference>() + 128)?;
    owner.work(1)?;
    if index >= slice.len() { return Err(error("big.Word field index out of range")); }
    let source = Arc::new(Element { slice: slice.clone(), index, owner: Arc::downgrade(&owner) });
    Ok(Value::Field(Arc::new(gotmpl::FieldReference::new(source,"word",gotmpl::FieldKind::NamedUint("big.Word")))))
}
pub(super) fn reference_factory(value:&Value)->Option<Weak<Factory>> {
    let Value::Field(reference)=value else{return None;};
    Some(reference.source::<Element>()?.owner.clone())
}
impl Words {
    pub(super) fn nil() -> Self { Self { slice: TypedSlice::nil("[]big.Word") } }
    pub(super) fn len(&self) -> usize { self.slice.len() }
    pub(super) fn cap(&self) -> usize { self.slice.cap() }
    pub(super) fn value(&self) -> Value { Value::Slice(self.slice.clone()) }
    pub(super) fn span(&self) -> Option<(usize, usize, usize, usize)> { self.slice.values_span() }
    pub(super) fn snapshot(&self) -> Option<ValuesView> {
        if self.len() == 0 { None } else { self.slice.visible_values() }
    }
    /// The caller prepays the byte Vec and BigInt conversion before obtaining
    /// this immutable snapshot. No host callback or numeric conversion under a
    /// Number/cell lock occurs here.
    pub(super) fn unsigned(factory: &Factory, snapshot: &[Value]) -> RenderResult<BigInt> {
        let len = snapshot.len().checked_mul(8).ok_or_else(|| error("big.Word byte size overflow"))?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(len).map_err(|_| error("big.Word byte allocation failed"))?;
        for (i, item) in snapshot.iter().enumerate() {
            if i % 256 == 0 { factory.work(0)?; }
            bytes.extend_from_slice(&decode(item)?.to_le_bytes());
        }
        Ok(BigInt::from_bytes_le(Sign::Plus, &bytes))
    }
    fn values(factory: &Arc<Factory>, n: &BigInt, len: usize) -> RenderResult<Vec<Value>> {
        if word_len(n)? > len { return Err(error("big.Word result exceeds write length")); }
        let mut values = Vec::new();
        values.try_reserve_exact(len).map_err(|_| error("big.Word allocation failed"))?;
        let mut digits = n.iter_u64_digits();
        for i in 0..len {
            if i % 256 == 0 { factory.work(0)?; }
            values.push(value(digits.next().unwrap_or(0)));
        }
        Ok(values)
    }
    pub(super) fn with_capacity(factory: &Arc<Factory>, n: &BigInt, cap: usize) -> RenderResult<Self> {
        factory.work(0)?;
        let len = word_len(n)?;
        if len > cap { return Err(error("big.Word result exceeds capacity")); }
        if cap == 0 { return Ok(Self::nil()); }
        factory.reserve(cap.checked_mul(std::mem::size_of::<Value>()).and_then(|n|n.checked_mul(4)).and_then(|n|n.checked_add(2048)).ok_or_else(|| error("big.Word allocation budget overflow"))?)?;
        factory.work(cap.checked_add(1).ok_or_else(|| error("big.Word work overflow"))?)?;
        let values = Self::values(factory, n, cap)?;
        let weak = Arc::downgrade(factory);
        let erased: Weak<dyn std::any::Any+Send+Sync> = Arc::downgrade(factory) as Weak<dyn std::any::Any+Send+Sync>;
        let full = TypedSlice::values_scalars("[]big.Word", Some(values.into()))?.with_index_fields(erased,element).with_host_budget(Arc::new(move |bytes| {
            weak.upgrade().ok_or_else(|| error("big.Word owner retired"))?.reserve(bytes)
        }));
        let id = full.values_span().ok_or_else(|| error("big.Word backing missing"))?.0;
        let slice = full.reslice(0, len)?;
        // These registered headers keep real cells alive, preventing stale
        // address reuse. Their budget callbacks contain only Weak<Factory>.
        // Full backing/entry credit was prepaid and is retained for this scope.
        {
            let mut entries = factory.word_values.lock().map_err(|_| error("big.Word registry poisoned"))?;
            if entries.contains_key(&id) { return Err(error("duplicate big.Word backing identity")); }
            entries.insert(id, full);
        }
        Ok(Self { slice })
    }
    pub(super) fn make(factory: &Arc<Factory>, n: &BigInt, requested: usize) -> RenderResult<Self> {
        if word_len(n)? > requested { return Err(error("big.Word result exceeds requested length")); }
        Self::with_capacity(factory, n, capacity(requested)?)
    }
    /// ASN.1 INTEGER preserves its actual encoded byte length for SetBytes.
    /// Negative parsing complements, adds one using nat.add, then changes sign.
    /// Reproduce the pinned named-curve constants' actual SetString origins.
    /// Decimal scanning uses grouped mulAddWW; hex scanning appends words.
    pub(super) fn scanned(factory:&Arc<Factory>,number:&BigInt,decimal:bool)->RenderResult<Self> {
        if number.sign()==Sign::Minus || number.bits()>521 {return Err(error("invalid named-curve integer initializer"));}
        let bits=usize::try_from(number.bits()).map_err(|_|error("curve integer size overflow"))?;
        if !decimal {
            let cap=word_len(number)?.max(1).checked_next_power_of_two().ok_or_else(||error("curve integer capacity overflow"))?;
            factory.work(1)?;
            return Self::with_capacity(factory,number,cap);
        }
        factory.reserve(bits.checked_mul(16).and_then(|n|n.checked_add(4096)).ok_or_else(||error("curve integer scanner budget overflow"))?)?;
        let limbs=word_len(number)?;
        factory.work(limbs.checked_mul(limbs).and_then(|n|n.checked_add(1)).ok_or_else(||error("curve integer scanner work overflow"))?)?;
        let text=number.to_str_radix(10);
        let mut prefix=BigInt::from(0);
        let mut cap=0;
        for chunk in text.as_bytes().chunks(19) {
            let limbs=word_len(&prefix)?;
            factory.work(limbs.checked_mul(limbs).and_then(|n|n.checked_add(1)).ok_or_else(||error("curve integer scanner work overflow"))?)?;
            let mut word=0u64;
            for digit in chunk {word=word.checked_mul(10).and_then(|n|n.checked_add(u64::from(*digit-b'0'))).ok_or_else(||error("curve integer digit overflow"))?;}
            let requested=if prefix.sign()==Sign::NoSign {usize::from(word!=0)} else {limbs.checked_add(1).ok_or_else(||error("curve integer capacity overflow"))?};
            if requested>cap {cap=capacity(requested)?;}
            let base=10u64.checked_pow(chunk.len() as u32).ok_or_else(||error("curve integer base overflow"))?;
            prefix=prefix*base+word;
        }
        Self::with_capacity(factory,number,cap)
    }
    pub(super) fn initial(factory: &Arc<Factory>, bytes: &[u8], signed: bool, n: &BigInt) -> RenderResult<Self> {
        factory.work(bytes.len().div_ceil(8).checked_add(1).ok_or_else(|| error("big.Word initial work overflow"))?)?;
        let mut cap = capacity(bytes.len().div_ceil(8))?;
        if signed && bytes.first().is_some_and(|b| b & 0x80 != 0) {
            let mut first = bytes.len();
            for (i, b) in bytes.iter().enumerate() {
                if i % 256 == 0 { factory.work(0)?; }
                if *b != 0xff { first = i; break; }
            }
            let complement_len = (bytes.len() - first).div_ceil(8);
            let request = if complement_len == 0 { 1 } else { complement_len.checked_add(1).ok_or_else(|| error("big.Word initial capacity overflow"))? };
            if request > cap { cap = capacity(request)?; }
        }
        Self::with_capacity(factory, n, cap)
    }
    pub(super) fn check_owner(&self,factory:&Arc<Factory>)->RenderResult<()> {
        factory.work(0)?;
        let Some((id,_,_,_))=self.span()else{return Ok(());};
        let known={let entries=factory.word_values.lock().map_err(|_|error("big.Word registry poisoned"))?;entries.contains_key(&id)};
        if !known{return Err(error("foreign big.Word backing owner"));}
        self.slice.reserve_host_bytes(0)?;
        Ok(())
    }
    pub(super) fn source(factory: &Arc<Factory>, input: &Value) -> RenderResult<Self> {
        factory.reserve(128)?;
        factory.work(0)?;
        let slice = match input {
            Value::Nil => return Ok(Self::nil()),
            Value::Slice(slice) if slice.go_type() == "[]big.Word" => slice,
            _ => return Err(error("expected []big.Word")),
        };
        if slice.is_nil() { return Ok(Self::nil()); }
        let id = slice.values_span().ok_or_else(|| error("invalid big.Word backing"))?.0;
        {
            let entries = factory.word_values.lock().map_err(|_| error("big.Word registry poisoned"))?;
            if !entries.contains_key(&id) { return Err(error("foreign big.Word backing owner")); }
        }
        factory.work(slice.len().checked_add(1).ok_or_else(|| error("big.Word input work overflow"))?)?;
        slice.reserve_host_bytes(0)?;
        if slice.len() == 0 { return Ok(Self { slice: slice.clone() }); }
        let snapshot = slice.visible_values().ok_or_else(|| error("invalid big.Word backing"))?;
        let mut normalized = 0;
        for (i, item) in snapshot.iter().enumerate() {
            if i % 256 == 0 { factory.work(0)?; }
            if decode(item)? != 0 { normalized = i + 1; }
        }
        Ok(Self { slice: slice.reslice(0, normalized)? })
    }
    pub(super) fn stage(&self, factory: &Arc<Factory>, n: &BigInt, requested: usize, written: usize, force_new: bool, preserve_header: bool) -> RenderResult<Staged> {
        factory.work(0)?;
        if preserve_header {
            if requested != 0 || written != 0 { return Err(error("invalid preserved big.Word write")); }
            return Ok(Staged { next: self.clone(), target: None, values: Vec::new() });
        }
        let len = word_len(n)?;
        if len > written || written > requested { return Err(error("invalid big.Word staged write length")); }
        if force_new || requested > self.cap() {
            return Ok(Staged { next: Self::make(factory, n, requested)?, target: None, values: Vec::new() });
        }
        let next = Self { slice: self.slice.reslice(0, len)? };
        if written == 0 { return Ok(Staged { next, target: None, values: Vec::new() }); }
        factory.reserve(written.checked_mul(std::mem::size_of::<Value>()).and_then(|n|n.checked_mul(2)).and_then(|n|n.checked_add(256)).ok_or_else(|| error("big.Word stage budget overflow"))?)?;
        factory.work(written.checked_add(1).ok_or_else(|| error("big.Word stage work overflow"))?)?;
        let values = Self::values(factory, n, written)?;
        Ok(Staged { next, target: Some(self.slice.reslice(0, written)?), values })
    }
}
