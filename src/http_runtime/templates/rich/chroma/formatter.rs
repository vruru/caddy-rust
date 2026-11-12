use super::code_info::CodeBlockAttrs;
pub use super::lexer::Token;
use super::vm::{Budget,Error,Result};
use std::mem::size_of;
fn allocate<T>(capacity:usize,budget:&mut Budget)->Result<Vec<T>> {
    let bytes=capacity.checked_mul(size_of::<T>()).ok_or(Error::TotalLimit)?;
    budget.charge(1,bytes)?;
    let mut out=Vec::new();out.try_reserve_exact(capacity).map_err(|_|Error::TotalLimit)?;
    let actual=out.capacity().checked_mul(size_of::<T>()).ok_or(Error::TotalLimit)?;
    if actual>bytes { budget.charge(0,actual-bytes)?; }
    Ok(out)
}
struct Output<'a> { data:Vec<u8>, budget:&'a mut Budget }
impl Output<'_> {
    fn put(&mut self,data:&[u8])->Result<()> {
        self.budget.charge(1,0)?;
        let needed=self.data.len().checked_add(data.len()).ok_or(Error::TotalLimit)?;
        if needed>self.data.capacity() {
            let new=needed.max(self.data.capacity().checked_mul(2).ok_or(Error::TotalLimit)?).max(64);
            let mut buffer=allocate(new,self.budget)?;
            buffer.extend_from_slice(&self.data);
            let old=std::mem::replace(&mut self.data,buffer);let old_capacity=old.capacity();
            drop(old);self.budget.release(old_capacity)?;
        }
        self.data.extend_from_slice(data);Ok(())
    }
    fn escaped(&mut self,data:&[u8])->Result<()> {
        self.budget.charge(data.len().div_ceil(16) as u64+1,0)?;
        let mut start=0;
        for (i,b) in data.iter().enumerate(){
            let replacement:&[u8]=match b{
                b'&'=>b"&amp;",b'<'=>b"&lt;",b'>'=>b"&gt;",b'"'=>b"&#34;",39=>b"&#39;",_=>continue,
            };
            self.put(&data[start..i])?;self.put(replacement)?;start=i+1;
        }
        self.put(&data[start..])
    }
}
fn parent(t:i32)->i32 {if t%100!=0{t/100*100}else if t%1000!=0{t/1000*1000}else{0}}
fn class(mut t:i32)->&'static str{
    loop {
        if let Some((_,c))=super::classes::CLASSES.iter().find(|(k,_)|*k==t){return c;}
        if t==0{return "";}t=parent(t);
    }
}
fn highlighted(ranges:&[(i64,i64)],cursor:&mut usize,line:i64)->bool{
    let mut index=*cursor;
    while index<ranges.len() && line>ranges[index].1{index+=1;}
    // The upstream formatter increments its cursor once, even if the local scan skipped several.
    if index!=*cursor{*cursor+=1;}
    ranges.get(index).is_some_and(|r|line>=r.0 && line<=r.1)
}
type Part<'a>=(i32,&'a[u8]);
struct Lines<'a> { parts:Vec<Part<'a>>,ends:Vec<usize> }
impl Lines<'_> {
 fn len(&self)->usize { self.ends.len() }
 fn iter(&self)->impl Iterator<Item=&[Part<'_>]> {
  self.ends.iter().scan(0,|start,&end|{let line=&self.parts[*start..end];*start=end;Some(line)})
 }
}
fn split<'a>(tokens:&'a[Token],budget:&mut Budget)->Result<Lines<'a>> {
 let bytes=tokens.iter().try_fold(0usize,|n,t|n.checked_add(t.text.len()).ok_or(Error::TotalLimit))?;
 budget.charge((bytes.div_ceil(16)+tokens.len()) as u64,0)?;
 let count=tokens.iter().try_fold(0usize,|n,t|n.checked_add(1+t.text.iter().filter(|b|**b==b'\n').count()).ok_or(Error::TotalLimit))?;
 let mut parts=allocate(count,budget)?;let mut ends=allocate(count,budget)?;
 for token in tokens {
  let mut data=token.text.as_slice();let mut ended=false;
  while let Some(n)=data.iter().position(|b|*b==b'\n') {
   parts.push((token.kind,&data[..=n]));ends.push(parts.len());data=&data[n+1..];ended=data.is_empty();if ended{break;}
  }
  if !ended{parts.push((token.kind,data));}
 }
 if parts.len()>ends.last().copied().unwrap_or(0){ends.push(parts.len());}
 let start=if ends.len()>1{ends[ends.len()-2]}else{0};
 if ends.last().is_some_and(|end|*end==start+1&&parts[start].1.is_empty()){ends.pop();parts.pop();}
 Ok(Lines{parts,ends})
}
fn number(out:&mut Output<'_>,kind:&str,base:i64,index:usize,width:usize,highlight:bool,table:bool)->Result<()>{
    if table && highlight{out.put(b"<span class=\"hl\">")?;}
    out.put(b"<span class=\"")?;out.put(kind.as_bytes())?;out.put(b"\">")?;
    let n=base.wrapping_add(index as i64);
    out.budget.charge(0,48)?;
    let n=n.to_string();
    for _ in n.len()..width {out.put(b" ")?;}
    out.put(n.as_bytes())?;
    if table{out.put(b"\n")?;}
    out.put(b"</span>")?;
    if table && highlight{out.put(b"</span>")?;}
    Ok(())
}
pub fn format(tokens:&[Token],attrs:&CodeBlockAttrs,budget:&mut Budget)->Result<gotmpl::BudgetedBytes>{
    let lines=split(tokens,budget)?;
    let base=attrs.base_line_number.unwrap_or(1);
    let linenos=attrs.line_numbers.unwrap_or(false);
    let table=linenos && attrs.line_numbers_in_table.unwrap_or(false);
    budget.charge((attrs.highlight_lines.len().checked_mul(attrs.highlight_lines.len().max(1).ilog2() as usize+1).ok_or(Error::TotalLimit)?) as u64,48)?;
    let mut ranges=allocate(attrs.highlight_lines.len(),budget)?;
    ranges.extend_from_slice(&attrs.highlight_lines);
    ranges.sort_unstable_by_key(|r|r.0);
    let width=base.wrapping_add(lines.len() as i64).wrapping_sub(1).to_string().len();
    let mut out=Output{data:Vec::new(),budget};
    if table{
        out.put(b"<div class=\"chroma\">\n<table class=\"lntable\"><tr><td class=\"lntd\">\n<pre class=\"chroma\">")?;
        let mut cursor=0;
        for i in 0..lines.len(){
            let hl=highlighted(&ranges,&mut cursor,base.wrapping_add(i as i64));
            number(&mut out,"lnt",base,i,width,hl,true)?;
        }
        out.put(b"</pre></td>\n<td class=\"lntd\">\n")?;
    }
    out.put(b"<pre class=\"chroma\"><code>")?;
    let mut cursor=0;
    for (i,line) in lines.iter().enumerate(){
        let hl=highlighted(&ranges,&mut cursor,base.wrapping_add(i as i64));
        out.put(if hl{b"<span class=\"line hl\">"}else{b"<span class=\"line\">"})?;
        if linenos && !table{number(&mut out,"ln",base,i,width,false,false)?;}
        out.put(b"<span class=\"cl\">")?;
        for (kind,text) in line{
            let c=class(*kind);
            if !c.is_empty(){out.put(b"<span class=\"")?;out.put(c.as_bytes())?;out.put(b"\">")?;}
            out.escaped(text)?;
            if !c.is_empty(){out.put(b"</span>")?;}
        }
        out.put(b"</span></span>")?;
    }
    out.put(b"</code></pre>")?;
    if table{out.put(b"</td></tr></table>\n</div>\n")?;}
    let Output{data,budget}=out;
    budget.transfer_output(data)
}
