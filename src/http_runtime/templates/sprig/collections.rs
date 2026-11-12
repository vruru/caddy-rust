use super::*;
use gotmpl::{MapContext, GoKey, GoMapSnapshot, GoMapKeyRef,TypedSlice,SliceRef};

type Entries = BTreeMap<GoKey, V>;

fn gokey_from_ref(key: GoMapKeyRef<'_>) -> GoKey {
    match key {
        GoMapKeyRef::Utf8(value) => GoKey::Utf8(value.clone()),
        GoMapKeyRef::Keyed(value) => value.clone(),
    }
}

pub(super) fn add(m: &mut M, context: &MapContext) {
    for name in [
        "list", "tuple", "dict", "get", "set", "unset", "hasKey", "pluck", "keys",
        "pick", "omit", "values", "merge", "mergeOverwrite", "mustMerge",
        "mustMergeOverwrite", "dig", "deepCopy", "mustDeepCopy", "default", "empty",
        "coalesce", "all", "any", "ternary", "fail", "append", "push", "mustAppend",
        "mustPush", "prepend", "mustPrepend", "first", "mustFirst", "last", "mustLast",
        "rest", "mustRest", "initial", "mustInitial", "reverse", "mustReverse",
        "compact", "mustCompact", "uniq", "mustUniq", "without", "mustWithout", "has",
        "mustHas", "slice", "mustSlice", "concat", "chunk", "mustChunk", "deepEqual",
        "kindOf", "kindIs", "typeOf", "typeIs", "typeIsLike",
    ] {
        let context = context.clone();
        put(m, name, move |args| call(name, args, &context));
    }
}

fn entries(value: &V) -> gotmpl::Result<GoMapSnapshot> {
    match value {
        V::Nil => Ok(GoMapSnapshot::Keyed(Arc::new(Entries::new()))),
        V::Map(_) | V::SharedMap(_) => value
            .map_snapshot()?
            .ok_or_else(|| err("expected a map")),
        _ => Err(err("expected map[string]interface {}")),
    }
}

fn values(value: &V) -> gotmpl::Result<SliceRef<'_>> {
    value
        .as_sequence()
        .ok_or_else(|| err("expected a list"))
}

fn kind(value: &V) -> &'static str {
    match value {
        V::NamedInt64(_, kind) => kind.kind,
        V::Nil => "invalid",
        V::List(_) | V::Slice(_) => "slice",
        V::Object(object) => {
            if object.map_view.is_some() {
                "map"
            } else if object.go_type.is_some_and(|name| name.starts_with('*')) {
                "ptr"
            } else {
                "struct"
            }
        }
        v => v.type_name(),
    }
}

fn type_name(value: &V) -> &'static str {
    match value {
        V::Nil => "<nil>",
        V::List(_) => "[]interface {}",
        V::Slice(ts) => ts.go_type(),
        V::Map(_) | V::SharedMap(_) => "map[string]interface {}",
        V::GenericMap(_)=>"map[interface {}]interface {}",
        V::Object(object) => object.go_type.unwrap_or_else(|| {
            object
                .map_view
                .as_ref()
                .map_or_else(|| kind(value), |view| view.type_name)
        }),
        v => v.type_name(),
    }
}

fn seq_types_compatible(a_type: &str, b_type: &str) -> bool {
    // List normalizes to "[]interface {}"; Slice[interface{}] is the same.
    // []string, []int, etc. must match exactly; cross-type is not equal.
    a_type == b_type
}

fn equal(a: &V, b: &V) -> gotmpl::Result<bool> {
    match(a,b){
        (V::GenericMap(a),V::GenericMap(b))=>{
            if Arc::ptr_eq(a,b){return Ok(true);}
            let(sa,sb)=(a.snapshot()?,b.snapshot()?);if sa.len()!=sb.len(){return Ok(false);}
            for(key,value)in sa.iter(){let Some(other)=b.get(key)?else{return Ok(false);};if !equal(value,&other)?{return Ok(false);}}return Ok(true);
        }
        (V::GenericMap(_),_)|(_,V::GenericMap(_))=>return Ok(false),
        (V::Object(a),V::Object(b))if a.go_type==b.go_type&&a.map_view.is_none()&&b.map_view.is_none()=>{if let Some(equal)=a.deep_equal.or(a.equal){return Ok(equal(a,b));}},
        _=>{}
    }

    match (a.map_snapshot()?, b.map_snapshot()?) {
        (Some(a_snap), Some(b_snap)) => {
            if type_name(a)!=type_name(b)||a.is_go_nil()!=b.is_go_nil(){return Ok(false);}
            if a_snap.len() != b_snap.len() {
                return Ok(false);
            }
            for (key, value) in a_snap.iter() {
                let Some(other) = b_snap.get(key.as_bytes()) else {
                    return Ok(false);
                };
                if !equal(value, other)? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        (Some(_), None) | (None, Some(_)) => Ok(false),
        (None, None) => {
            // Sequence path: check type + nil + len, then deep compare elements.
            let a_seq = a.as_sequence();
            let b_seq = b.as_sequence();
            match (a_seq, b_seq) {
                (Some(a_s), Some(b_s)) => {
                    // nil slice != non-nil slice
                    if a_s.is_nil() != b_s.is_nil() {
                        return Ok(false);
                    }
                    // length must match
                    if a_s.len() != b_s.len() {
                        return Ok(false);
                    }
                    // type gate: []string vs []interface{} are NOT equal
                    let at = match a { V::List(_) => "[]interface {}", _ => a_s.go_type() };
                    let bt = match b { V::List(_) => "[]interface {}", _ => b_s.go_type() };
                    if !seq_types_compatible(at, bt) {
                        return Ok(false);
                    }
                    // element-wise deep compare via get (indexed, Go-l2.Index)
                    for i in 0..a_s.len() {
                        let ai = a_s
                            .get(i)
                            .ok_or_else(|| err("index out of range in equal"))?;
                        let bi = b_s
                            .get(i)
                            .ok_or_else(|| err("index out of range in equal"))?;
                        if !equal(&ai, &bi)? {
                            return Ok(false);
                        }
                    }
                    Ok(true)
                }
                (Some(_), None) | (None, Some(_)) => Ok(false),
                (None, None) => Ok(a == b),
            }
        }
    }
}

fn copy(value: &V, context: &MapContext, depth: usize) -> R {
    if depth > 32 {
        return Err(err("deep copy exceeds nesting limit"));
    }
    if let V::GenericMap(map)=value{
        let snapshot=map.snapshot()?;let account=map.budget_account();account.reserve(snapshot.len().checked_mul(2*std::mem::size_of::<(V,V)>()).and_then(|n|n.checked_add(64)).ok_or_else(||err("generic map copy size overflow"))?)?;
        let mut entries=Vec::new();entries.try_reserve_exact(snapshot.len()).map_err(|_|err("generic map copy allocation failed"))?;
        for(key,value)in snapshot.iter(){entries.push((key.clone(),copy(value,context,depth+1)?));}return context.generic_map(entries,&account);
    }
    if let Some(snap) = value.map_snapshot()? {
        if value.is_go_nil(){return Ok(context.nil_map());}
        let mut result = Entries::new();
        for (key, value) in snap.iter() {
            result.insert(gokey_from_ref(key), copy(value, context, depth + 1)?);
        }
        context.map_go(result)
    } else if let Some(seq) = value.as_sequence() {
        // Preserve element type, nil state, visible len.
        // Go copystructure: cap = len (make+copy). No source deepCopy can
        // preserve the original cap beyond visible len, so we reproduce that
        // behaviour: the copied slice has cap == len.
        if seq.is_nil() {
            // nil typed slice → nil typed slice of same element type
            return Ok(V::Slice(TypedSlice::nil(seq.go_type())));
        }
        if let Some(bytes)=seq.visible_bytes(){return Ok(V::Slice(TypedSlice::bytes(Some(Arc::from(&*bytes)))));}
        let n = seq.len();
        check_budget(n)?;
        let mut items = Vec::with_capacity(n);
        for i in 0..n {
            let v = seq
                .get(i)
                .ok_or_else(|| err("index out of range in copy"))?;
            items.push(copy(&v, context, depth + 1)?);
        }
        Ok(V::Slice(TypedSlice::values(seq.go_type(),Some(items.into()))?))
    } else {
        Ok(value.clone())
    }
}

fn merge(dst: &V, src: &V, overwrite: bool, depth: usize) -> gotmpl::Result<()> {
    if depth > 32 {
        return Err(err("map merge exceeds nesting limit"));
    }
    if let(V::GenericMap(dst),V::GenericMap(src))=(dst,src){
        if Arc::ptr_eq(dst,src){return Ok(());}
        for(key,value)in src.snapshot()?.iter(){
            match dst.get(key)?{
                Some(ref current @ V::GenericMap(_))if matches!(value,V::GenericMap(_))=>merge(current,value,overwrite,depth+1)?,
                Some(ref current @ V::SharedMap(_))if value.map_snapshot()?.is_some()=>merge(current,value,overwrite,depth+1)?,
                Some(current)if !overwrite&&current.is_truthy()=>{},_=>dst.set(key.clone(),value.clone())?,
            }
        }return Ok(());
    }
    let V::SharedMap(dst_cell) = dst else {
        return Err(err("destination map is immutable"));
    };
    for (key, value) in entries(src)?.iter() {
        let gokey = gokey_from_ref(key);
        let current = dst_cell.get_bytes(gokey.as_bytes())?;
        match current {
            Some(ref current @ V::GenericMap(_)) if matches!(value,V::GenericMap(_))=>merge(current,value,overwrite,depth+1)?,
            Some(ref current @ V::SharedMap(_)) if value.map_snapshot()?.is_some() => {
                merge(current, value, overwrite, depth + 1)?
            }
            Some(current) if !overwrite && current.is_truthy() => {}
            _ => {
                dst_cell.set_key(gokey, value.clone())?;
            }
        }
    }
    Ok(())
}

fn list(items: Vec<V>) -> R {
    check_budget(items.len())?;
    Ok(V::List(items.into()))
}

fn check_budget(count: usize) -> gotmpl::Result<()> {
    if count > MAX_ITEMS {
        return Err(err("too many items"));
    }
    // []interface{} element = 16 bytes (two pointer-words) + slice header
    if count.saturating_mul(std::mem::size_of::<V>()) > MAX_BYTES {
        return Err(err("too many bytes"));
    }
    Ok(())
}

fn typed_nil_list()->V{V::Slice(TypedSlice::nil("[]interface {}"))}
fn finish_list(mut values:Vec<V>,cap:usize,nil:bool)->R{
    check_budget(cap)?;let len=values.len();if nil&&len==0{return Ok(typed_nil_list());}
    values.resize_with(cap,||V::Nil);Ok(V::Slice(TypedSlice::from_list(values.into()).with_len(len)?))
}
fn go_append(s:&[V],item:V)->R{
    let len=s.len()+1;let cap=gotmpl::go_slice_capacity(s.len(),len,16,true).ok_or_else(||err("slice capacity overflow"))?;check_budget(cap)?;
    let mut values=Vec::with_capacity(cap);values.extend_from_slice(s);values.push(item);finish_list(values,cap,false)
}
fn go_prepend(s:&[V],item:V)->R{
    let len=s.len()+1;let cap=if len<=1{1}else{gotmpl::go_slice_capacity(1,len,16,true).ok_or_else(||err("slice capacity overflow"))?};check_budget(cap)?;
    let mut values=Vec::with_capacity(cap);values.push(item);values.extend_from_slice(s);finish_list(values,cap,false)
}
fn go_grow_append(values:&mut Vec<V>,cap:&mut usize,item:V)->gotmpl::Result<()>{
    let len=values.len()+1;if len>*cap{*cap=gotmpl::go_slice_capacity(*cap,len,16,true).ok_or_else(||err("slice capacity overflow"))?;check_budget(*cap)?;values.try_reserve_exact(cap.saturating_sub(values.len())).map_err(|_|err("slice allocation failed"))?;}values.push(item);Ok(())
}

fn call(name: &str, a: &[V], context: &MapContext) -> R {
    match name {
        // ── map / dict / scalar ops (unchanged from supplied source) ──
        "list" | "tuple" => list(a.to_vec()),
        "dict" => {
            let mut map = Entries::new();
            for pair in a.chunks(2) {
                let key = match &pair[0] {
                    V::String(_) | V::ByteString(_) => GoKey::from_value(&pair[0])?,
                    _ => GoKey::from_bytes(gotmpl::go_sprint_bytes(&pair[..1], false)?),
                };
                map.insert(key, pair.get(1).cloned().unwrap_or_else(|| V::from("")));
            }
            context.map_go(map)
        }
        "get" | "hasKey" => {
            arity(a, 2, 2)?;
            let map = entries(&a[0])?;
            let key_bytes = a[1].as_go_bytes().ok_or_else(|| err("expected string key"))?;
            if name == "get" {
                Ok(map.get(key_bytes).cloned().unwrap_or_else(|| V::from("")))
            } else {
                Ok(V::Bool(map.get(key_bytes).is_some()))
            }
        }
        "set" | "unset" => {
            let n = if name == "set" { 3 } else { 2 };
            arity(a, n, n)?;
            if name == "unset" && matches!(a[0], V::Nil) {
                return Ok(context.nil_map());
            }
            let V::SharedMap(map) = &a[0] else {
                return Err(err("destination map is immutable"));
            };
            let key = GoKey::from_value(&a[1])?;
            if name == "set" {
                map.set_key(key, a[2].clone())?;
            } else {
                map.remove_bytes(key.as_bytes())?;
            }
            Ok(a[0].clone())
        }
        "pluck" => {
            arity(a, 1, usize::MAX)?;
            let key = a[0].as_go_bytes().ok_or_else(|| err("expected string key"))?;
            let mut out = Vec::new();
            for map in &a[1..] {
                if let Some(value) = entries(map)?.get(key) {
                    out.push(value.clone());
                }
            }
            list(out)
        }
        "keys" | "values" => {
            let (min, max) = if name == "values" { (1, 1) } else { (0, usize::MAX) };
            arity(a, min, max)?;
            let mut out = Vec::new();
            for map in a {
                for (key, value) in entries(map)?.iter() {
                    out.push(if name == "keys" { key.to_value() } else { value.clone() });
                    if out.len() > MAX_ITEMS {
                        return Err(err("too many map values"));
                    }
                }
            }
            list(out)
        }
        "pick" | "omit" => {
            arity(a, 1, usize::MAX)?;
            let map = entries(&a[0])?;
            let keys: Vec<&[u8]> = a[1..]
                .iter()
                .map(|v| v.as_go_bytes().ok_or_else(|| err("expected a string key")))
                .collect::<gotmpl::Result<_>>()?;
            let out: gotmpl::Result<Entries> = map
                .iter()
                .filter(|(key, _)| keys.contains(&key.as_bytes()) == (name == "pick"))
                .map(|(key, value)| {
                    Ok((GoKey::from_value(&key.to_value())?, value.clone()))
                })
                .collect();
            context.map_go(out?)
        }
        "merge" | "mergeOverwrite" | "mustMerge" | "mustMergeOverwrite" => {
            arity(a, 1, usize::MAX)?;
            for source in &a[1..] {
                if let Err(error) =
                    merge(&a[0], source, name.ends_with("Overwrite"), 0)
                {
                    if name.starts_with("must") {
                        return Err(error);
                    }
                    return output("");
                }
            }
            Ok(a[0].clone())
        }
        "dig" => {
            arity(a, 3, usize::MAX)?;
            let fallback = &a[a.len() - 2];
            let mut current = a[a.len() - 1].clone();
            for key in &a[..a.len() - 2] {
                let key_bytes = key.as_go_bytes().ok_or_else(|| err("dig key must be string"))?;
                let map = entries(&current)?;
                let Some(value) = map.get(key_bytes) else {
                    return Ok(fallback.clone());
                };
                current = value.clone();
            }
            Ok(current)
        }
        "deepCopy" | "mustDeepCopy" => {
            arity(a, 1, 1)?;
            copy(&a[0], context, 0)
        }
        "default" => {
            arity(a, 1, usize::MAX)?;
            Ok(if a.get(1).is_none_or(|v| !v.is_truthy()) {
                a[0].clone()
            } else {
                a[1].clone()
            })
        }
        "empty" => {
            arity(a, 1, 1)?;
            Ok(V::Bool(!a[0].is_truthy()))
        }
        "coalesce" => Ok(a.iter().find(|v| v.is_truthy()).cloned().unwrap_or(V::Nil)),
        "all" => Ok(V::Bool(a.iter().all(V::is_truthy))),
        "any" => Ok(V::Bool(a.iter().any(V::is_truthy))),
        "ternary" => {
            arity(a, 3, 3)?;
            let V::Bool(test) = a[2] else {
                return Err(err("ternary requires a bool"));
            };
            Ok(a[usize::from(!test)].clone())
        }
        "fail" => {
            arity(a, 1, 1)?;
            Err(err(arg_text(a, 0)?))
        }
        "deepEqual" => {
            arity(a, 2, 2)?;
            Ok(V::Bool(equal(&a[0], &a[1])?))
        }
        "kindOf" | "typeOf" => {
            arity(a, 1, 1)?;
            output(if name == "kindOf" {
                kind(&a[0])
            } else {
                type_name(&a[0])
            })
        }
        "kindIs" | "typeIs" | "typeIsLike" => {
            arity(a, 2, 2)?;
            Ok(V::Bool(
                arg_text(a, 0)?
                    == if name == "kindIs" {
                        kind(&a[1])
                    } else {
                        type_name(&a[1])
                    },
            ))
        }

        // ── chunk: [][]interface{} typed slice, indexed via get ──
        "chunk" | "mustChunk" => {
            arity(a, 2, 2)?;
            let size = usize::try_from(arg_int(a, 0)?)
                .ok()
                .filter(|n| *n > 0)
                .ok_or_else(|| err("chunk size must be positive"))?;
            let seq = values(&a[1])?;
            let l = seq.len();
            if l == 0 {
                // Go: (0-1)/size underflows; guard → empty [][]interface{}
                let rows: Vec<V> = Vec::new();
                check_budget(0)?;
                return Ok(V::Slice(TypedSlice::values(
                    "[][]interface {}",
                    Some(rows.into()),
                )?));
            }
            // Go: cs = floor((l-1)/size) + 1
            let cs = (l - 1) / size + 1;
            check_budget(cs)?;
            let mut rows: Vec<V> = Vec::with_capacity(cs);
            for i in 0..cs {
                let mut clen = size;
                if i == cs - 1 {
                    clen = l % size;
                    if clen == 0 {
                        clen = size;
                    }
                }
                check_budget(clen)?;
                let mut row = Vec::with_capacity(clen);
                for j in 0..clen {
                    let v = seq
                        .get(i * size + j)
                        .ok_or_else(|| err("chunk index out of range"))?;
                    row.push(v);
                }
                rows.push(V::Slice(TypedSlice::from_list(row.into())));
            }
            Ok(V::Slice(TypedSlice::values(
                "[][]interface {}",
                Some(rows.into()),
            )?))
        }

        // ── concat: var res []interface{} (nil start), append grows via go_slice_capacity ──
        "concat" => {
            let mut result: Vec<V> = Vec::new();let mut capacity=0usize; // nil in Go: len=0, cap=0
            for value in a {
                let seq = values(value)?;
                check_budget(result.len() + seq.len())?;
                for v in seq.iter() {
                    go_grow_append(&mut result,&mut capacity,v)?;
                }
            }
            finish_list(result,capacity,true)
        }

        // ── has / mustHas ──
        "has" | "mustHas" => {
            arity(a, 2, 2)?;
            if matches!(a[1], V::Nil) {
                return Ok(V::Bool(false));
            }
            let seq = values(&a[1])?;
            for v in seq.iter() {
                if equal(&a[0], &v)? {
                    return Ok(V::Bool(true));
                }
            }
            Ok(V::Bool(false))
        }

        // ── slice / mustSlice: (Any, ...Any) – first arg list, rest indices ──
        // len0 → untypedNil, don't read indices.
        // Non-empty: first 2 indices → int(), extra ignored.
        // Result: shared backing view via Value.slice.
        "slice" | "mustSlice" => {
            arity(a, 1, usize::MAX)?;
            let seq = values(&a[0])?;
            if seq.len() == 0 {
                return Ok(V::Nil);
            }
            let start=a.get(1).map(int).unwrap_or(0);let end=a.get(2).map(int).unwrap_or(seq.len()as i64);a[0].slice(Some(start),Some(end))
        }

        // ── canonical list helpers (first/last/rest/initial/append/prepend/
        //    reverse/compact/uniq/without) ──
        _ => {
            let canonical = name
                .strip_prefix("must")
                .map(|s| {
                    let mut s = s.to_owned();
                    if let Some(c) = s.get_mut(..1) {
                        c.make_ascii_lowercase();
                    }
                    s
                })
                .unwrap_or_else(|| name.to_owned());
            let canonical = if canonical == "push" {
                "append"
            } else {
                canonical.as_str()
            };
            arity(a, 1, usize::MAX)?;
            let seq = values(&a[0])?;
            match canonical {
                "first" | "last" => {
                    arity(a, 1, 1)?;
                    Ok(if canonical == "first" {
                        seq.get(0).unwrap_or(V::Nil)
                    } else {
                        if seq.len() == 0 {
                            return Ok(V::Nil);
                        }
                        seq.get(seq.len() - 1).unwrap_or(V::Nil)
                    })
                }
                "rest" | "initial" => {
                    arity(a, 1, 1)?;
                    let l = seq.len();
                    if l == 0 {
                        return Ok(typed_nil_list());
                    }
                    let n = l - 1;
                    check_budget(n)?;
                    let mut out = Vec::with_capacity(n);
                    if canonical == "rest" {
                        for i in 1..l {
                            out.push(
                                seq.get(i)
                                    .ok_or_else(|| err("index out of range in rest"))?,
                            );
                        }
                    } else {
                        for i in 0..n {
                            out.push(
                                seq.get(i)
                                    .ok_or_else(|| err("index out of range in initial"))?,
                            );
                        }
                    }
                    Ok(V::Slice(TypedSlice::from_list(out.into())))
                }
                "append" | "prepend" => {
                    arity(a, 2, 2)?;
                    if seq.len() >= MAX_ITEMS {
                        return Err(err("list exceeds item limit"));
                    }
                    let l = seq.len();
                    check_budget(l + 1)?;
                    let mut items = Vec::with_capacity(l);
                    for v in seq.iter() {
                        items.push(v);
                    }
                    return if canonical == "append" {
                        go_append(&items, a[1].clone())
                    } else {
                        go_prepend(&items, a[1].clone())
                    };
                }
                "reverse" => {
                    arity(a, 1, 1)?;
                    let l = seq.len();
                    check_budget(l)?;
                    // Go: make([]interface{}, l) → non-nil even for l==0
                    let mut out = Vec::with_capacity(l);
                    for i in 0..l {
                        out.push(
                            seq.get(l - 1 - i)
                                .ok_or_else(|| err("index out of range in reverse"))?,
                        );
                    }
                    Ok(V::Slice(TypedSlice::from_list(out.into())))
                }
                "compact" => {
                    arity(a, 1, 1)?;
                    // Go: nl := []interface{}{} (non-nil, cap=0)
                    let mut result: Vec<V> = Vec::new();let mut capacity=0usize;
                    check_budget(seq.len())?;
                    for v in seq.iter() {
                        if v.is_truthy() {
                            go_grow_append(&mut result,&mut capacity,v)?;
                        }
                    }
                    finish_list(result,capacity,false)
                }
                "uniq" => {
                    arity(a, 1, 1)?;
                    // Go: dest := []interface{}{} (non-nil, cap=0)
                    let mut result: Vec<V> = Vec::new();let mut capacity=0usize;
                    check_budget(seq.len())?;
                    for v in seq.iter() {
                        let mut seen = false;
                        for old in &result {
                            if equal(old, &v)? {
                                seen = true;
                                break;
                            }
                        }
                        if !seen {
                            go_grow_append(&mut result,&mut capacity,v)?;
                        }
                    }
                    finish_list(result,capacity,false)
                }
                "without" => {
                    // Go: res := []interface{}{} (non-nil, cap=0)
                    let mut result: Vec<V> = Vec::new();let mut capacity=0usize;
                    check_budget(seq.len())?;
                    for v in seq.iter() {
                        let mut excluded = false;
                        for omit in &a[1..] {
                            if equal(omit, &v)? {
                                excluded = true;
                                break;
                            }
                        }
                        if !excluded {
                            go_grow_append(&mut result,&mut capacity,v)?;
                        }
                    }
                    finish_list(result,capacity,false)
                }
                _ => Err(err("unregistered list helper")),
            }
        }
    }
}
