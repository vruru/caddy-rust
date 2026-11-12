//! First-document YAML arena and scanner share one precharged budget account.
use std::{borrow::Cow, collections::BTreeMap, mem::size_of};
use gotmpl::{BudgetAccount, Result, TemplateError};
use super::libyaml::parser::{Anchor, Event, Parser, ScalarStyle};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kind { Scalar, Sequence, Mapping, Alias(usize) }
pub(super) struct Node {
    pub kind: Kind,
    pub tag: Option<Vec<u8>>,
    pub value: Vec<u8>,
    pub style: Option<ScalarStyle>,
    pub children: Vec<usize>,
    pub line: u64,
    pub column: u64,
}
pub(super) struct Arena { pub nodes: Vec<Node>, pub root: usize }
fn error(message: impl Into<String>) -> TemplateError { TemplateError::Exec(message.into()) }

// Prepay the complete new allocation while the old allocation is still live.
// Rust may grow to a larger capacity; reject that exceptional allocator result
// rather than pretending only the final-capacity difference was live.
fn room<T>(values: &mut Vec<T>, account: &BudgetAccount) -> Result<()> {
    if values.len() < values.capacity() { return Ok(()); }
    let old = values.capacity();
    let next = old.max(4).checked_mul(2).ok_or_else(|| error("YAML allocation overflow"))?;
    let bytes = next.checked_mul(size_of::<T>()).ok_or_else(|| error("YAML allocation overflow"))?;
    account.reserve(bytes)?;
    values.try_reserve_exact(next-values.len()).map_err(|_| error("YAML allocation failed"))?;
    if values.capacity() > next { return Err(error("YAML allocation capacity exceeded reservation")); }
    account.release(old*size_of::<T>())?;
    Ok(())
}
fn add(nodes: &mut Vec<Node>, stack: &[usize], root: &mut Option<usize>, node: Node, account: &BudgetAccount) -> Result<usize> {
    if nodes.len() >= 16_384 { return Err(error("YAML node limit exceeded")); }
    if stack.is_empty() && root.is_some() { return Err(error("multiple YAML root nodes")); }
    room(nodes, account)?;
    let id = nodes.len();
    if let Some(&parent) = stack.last() {
        room(&mut nodes[parent].children, account)?;
        nodes[parent].children.push(id);
    } else { *root = Some(id); }
    nodes.push(node);
    Ok(id)
}
fn anchor(anchors: &mut BTreeMap<Anchor, usize>, name: Option<Anchor>, id: usize, account: &BudgetAccount) -> Result<()> {
    if let Some(name) = name {
        // The parser already owns this anchor. A new map entry is prepaid;
        // replacing an anchor retains no second key allocation.
        if !anchors.contains_key(&name) {
            super::allocation::btree_insert::<Anchor,usize>(anchors.is_empty(),account)?;
            account.reserve(name.as_bytes().len())?;
        }
        anchors.insert(name, id);
    }
    Ok(())
}
pub(super) fn parse(input: &[u8], account: &BudgetAccount) -> Result<Option<Arena>> {
    if input.len() > 1<<20 { return Err(error("YAML input byte limit exceeded")); }
    struct Context<'a>{account:&'a BudgetAccount,refund_failed:std::cell::Cell<bool>}
    unsafe fn reserve(data:*mut (),bytes:usize){
        let context=unsafe{&*(data as *const Context<'_>)};
        if let Err(error)=context.account.reserve(bytes){std::panic::resume_unwind(Box::new(error));}
    }
    unsafe fn release(data:*mut (),bytes:usize){
        let context=unsafe{&*(data as *const Context<'_>)};
        if context.account.release(bytes).is_err(){context.refund_failed.set(true);}
    }
    let mut context=Context{account,refund_failed:std::cell::Cell::new(false)};
    let callbacks=unsafe_libyaml::allocation_scope::Callbacks{data:(&mut context as *mut Context<'_>).cast(),reserve,release};
    // SAFETY: parse_inner keeps all raw parser/event storage inside the call;
    // all ABI boundaries are Rust. Parser destruction is skipped on unwind,
    // and the intrusive allocator scope then frees even unattached buffers.
    let result=std::panic::catch_unwind(std::panic::AssertUnwindSafe(||unsafe{
        unsafe_libyaml::allocation_scope::with_allocator(callbacks,||parse_inner(input,account))
    }));
    if context.refund_failed.get(){return Err(error("YAML allocation accounting invariant failed"));}
    match result{Ok(result)=>result,Err(payload)=>match payload.downcast::<TemplateError>(){Ok(error)=>Err(*error),Err(payload)=>std::panic::resume_unwind(payload)}}
}
fn parse_inner(input:&[u8],account:&BudgetAccount)->Result<Option<Arena>>{
    let mut parser = Parser::new(Cow::Borrowed(input),account).map_err(|e| error(e.to_string()))?;
    let (mut nodes, mut stack, mut anchors) = (Vec::<Node>::new(), Vec::<usize>::new(), BTreeMap::new());
    let (mut root, mut started, mut in_document, mut retained) = (None, false, false, 0usize);
    for _ in 0..32_772 {
        account.charge_work(1)?;
        let (event, mark) = parser.next().map_err(|e| error(e.to_string()))?;
        match event {
            Event::StreamStart if !started => { started = true; continue; }
            Event::DocumentStart if started && !in_document => { in_document = true; continue; }
            Event::StreamEnd if started && !in_document => return Ok(None),
            Event::DocumentEnd if in_document && stack.is_empty() => {
                let root = root.ok_or_else(|| error("YAML document has no root"))?;
                return Ok(Some(Arena {nodes, root}));
            }
            Event::SequenceEnd | Event::MappingEnd => {
                let id = stack.pop().ok_or_else(|| error("unbalanced YAML collection"))?;
                let want = if matches!(event, Event::SequenceEnd) { Kind::Sequence } else { Kind::Mapping };
                if nodes[id].kind != want || (want == Kind::Mapping && nodes[id].children.len()%2 != 0) {
                    return Err(error("unbalanced YAML collection"));
                }
                continue;
            }
            Event::Scalar(_) | Event::SequenceStart(_) | Event::MappingStart(_) | Event::Alias(_) if in_document => {}
            _ => return Err(error("unexpected YAML event")),
        }
        let is_container=matches!(event,Event::SequenceStart(_)|Event::MappingStart(_));
        if is_container && stack.len()>=32 { return Err(error("YAML collection depth limit exceeded")); }
        let mut node = Node {kind:Kind::Scalar,tag:None,value:Vec::new(),style:None,children:Vec::new(),line:mark.line()+1,column:mark.column()+1};
        let (name, container) = match event {
            Event::Scalar(s) => {
                node.style = Some(s.style);
                let size = s.value.len().checked_add(s.tag.as_ref().map_or(0, |t| t.len())).ok_or_else(|| error("YAML size overflow"))?;
                retained = retained.checked_add(size).filter(|n| *n<=1<<20).ok_or_else(|| error("YAML retained byte limit exceeded"))?;
                account.reserve(size)?;
                node.value = s.value.into_vec();
                node.tag = s.tag.map(|t| t.to_vec());
                (s.anchor, false)
            }
            Event::SequenceStart(s) => { node.kind=Kind::Sequence; let n=s.tag.as_ref().map_or(0, |t|t.len()); account.reserve(n)?;retained=retained.checked_add(n).filter(|n|*n<=1<<20).ok_or_else(||error("YAML retained byte limit exceeded"))?;node.tag=s.tag.map(|t|t.to_vec()); (s.anchor,true) }
            Event::MappingStart(s) => { node.kind=Kind::Mapping; let n=s.tag.as_ref().map_or(0, |t|t.len()); account.reserve(n)?;retained=retained.checked_add(n).filter(|n|*n<=1<<20).ok_or_else(||error("YAML retained byte limit exceeded"))?;node.tag=s.tag.map(|t|t.to_vec()); (s.anchor,true) }
            Event::Alias(name) => {
                node.kind=Kind::Alias(*anchors.get(&name).ok_or_else(||error("unknown YAML anchor"))?);
                account.reserve(name.as_bytes().len())?;
                node.value=name.as_bytes().to_vec();
                (None,false)
            }
            _ => return Err(error("unexpected YAML node")),
        };
        let id = add(&mut nodes, &stack, &mut root, node, account)?;
        anchor(&mut anchors,name,id,account)?;
        if container { room(&mut stack,account)?;stack.push(id); }
    }
    Err(error("YAML event limit exceeded"))
}
