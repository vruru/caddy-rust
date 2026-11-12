// Goldmark 1.8.6 attribute parser behavioral port; MIT upstream attribution in THIRD-PARTY-NOTICES.
#[derive(Clone, Debug)]
pub enum AttrValue {
    Bytes(Vec<u8>),
    Number(f64),
    Bool(bool),
    Null,
    Array(Vec<AttrValue>),
    Attrs(Vec<(Vec<u8>, AttrValue)>),
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
    nodes: usize,
    resource_limited: bool,
}

fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | b'\r' | b'\x0B' | b'\x0C')
}

fn is_ascii_punct(c: u8) -> bool {
    (c >= b'!' && c <= b'/') || (c >= b':' && c <= b'@') || (c >= b'[' && c <= b'`') || (c >= b'{' && c <= b'~')
}

fn is_numeric(c: u8) -> bool {
    c >= b'0' && c <= b'9'
}

fn is_alpha(c: u8) -> bool {
    (c >= b'a' && c <= b'z') || (c >= b'A' && c <= b'Z')
}

fn is_name_char(c: u8) -> bool {
    is_alpha(c) || is_numeric(c) || c == b'_' || c == b':' || c == b'.' || c == b'-'
}

fn is_id_char(c: u8) -> bool {
    !is_space(c) && (!is_ascii_punct(c) || c == b'_' || c == b'-' || c == b':' || c == b'.')
}

pub fn parse_attributes(input: &[u8]) -> Option<Vec<(Vec<u8>, AttrValue)>> {
    let mut p = Parser { bytes: input, pos: 0, nodes: 0, resource_limited:false };
    p.attrs(1)
}

fn parse_attributes_checked(input:&[u8])->Result<Option<Vec<(Vec<u8>,AttrValue)>>,&'static str>{
    let mut p=Parser{bytes:input,pos:0,nodes:0,resource_limited:false};
    let result=p.attrs(1);
    if p.resource_limited{Err("markdown code attributes exceed parser resource limit")}else{Ok(result)}
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn advance(&mut self, n: usize) {
        self.pos += n;
    }

    fn spaces(&mut self) {
        while let Some(c) = self.peek() {
            if is_space(c) {
                self.advance(1);
            } else {
                break;
            }
        }
    }

    fn consume_node(&mut self) -> bool {
        self.nodes += 1;
        if self.nodes>16384{self.resource_limited=true;false}else{true}
    }

    fn attrs(&mut self, depth: usize) -> Option<Vec<(Vec<u8>, AttrValue)>> {
        if depth > 32 {
            self.resource_limited=true;
            return None;
        }
        self.spaces();
        if self.peek() != Some(b'{') {
            return None;
        }
        self.advance(1);
        let mut result: Vec<(Vec<u8>, AttrValue)> = Vec::new();
        loop {
            match self.peek() {
                Some(b'}') => {
                    self.advance(1);
                    return Some(result);
                }
                _ => {}
            }
            let (name, value) = self.attribute(depth)?;
            if name == b"class" {
                if let AttrValue::Bytes(v) = &value {
                    if let Some(entry) = result.iter_mut().find(|(n, _)| n == &name) {
                        if let AttrValue::Bytes(ref mut s) = entry.1 {
                            s.push(b' ');
                            s.extend_from_slice(v);
                        }
                    } else {
                        result.push((name, value));
                    }
                } else {
                    return None;
                }
            } else {
                result.push((name, value));
            }
            self.spaces();
            if self.peek() == Some(b',') {
                self.advance(1);
                self.spaces();
            }
        }
    }

    fn attribute(&mut self, depth: usize) -> Option<(Vec<u8>, AttrValue)> {
        if depth > 32 {
            self.resource_limited=true;
            return None;
        }
        if !self.consume_node(){return None;}
        self.spaces();
        let c = self.peek()?;
        if c == b'#' || c == b'.' {
            self.advance(1);
            let start = self.pos;
            let mut i = 0;
            while start + i < self.bytes.len() && is_id_char(self.bytes[start + i]) {
                i += 1;
            }
            let val = self.bytes[start..start + i].to_vec();
            self.advance(i);
            let name = if c == b'#' { b"id".to_vec() } else { b"class".to_vec() };
            return Some((name, AttrValue::Bytes(val)));
        }
        let start = self.pos;
        if start >= self.bytes.len() {
            return None;
        }
        let c = self.bytes[start];
        if !is_alpha(c) && c != b'_' && c != b':' {
            return None;
        }
        let mut i = 0;
        while start + i < self.bytes.len() && is_name_char(self.bytes[start + i]) {
            i += 1;
        }
        if i == 0 {
            return None;
        }
        let name = self.bytes[start..start + i].to_vec();
        self.advance(i);
        self.spaces();
        if self.peek() != Some(b'=') {
            return None;
        }
        self.advance(1);
        self.spaces();
        let value = self.value(depth)?;
        if name == b"class" && !matches!(value, AttrValue::Bytes(_)) {
            return None;
        }
        Some((name, value))
    }

    fn value(&mut self, depth: usize) -> Option<AttrValue> {
        if depth > 32 {
            self.resource_limited=true;
            return None;
        }
        self.spaces();
        let c = self.peek()?;
        match c {
            b'{' => self.attrs(depth + 1).map(AttrValue::Attrs),
            b'[' => self.array(depth + 1).map(AttrValue::Array),
            b'"' => self.string().map(AttrValue::Bytes),
            b'-' | b'+' if is_numeric(self.bytes.get(self.pos + 1).copied().unwrap_or(0)) => self.number(),
            c if is_numeric(c) => self.number(),
            c if is_alpha(c) || c == b'_' || c == b':' => self.others(),
            _ => None,
        }
    }

    fn array(&mut self, depth: usize) -> Option<Vec<AttrValue>> {
        if depth > 32 {
            self.resource_limited=true;
            return None;
        }
        self.advance(1); // skip [
        let mut ret: Vec<AttrValue> = Vec::new();
        let mut i = 0;
        loop {
            let c = self.peek()?;
            let mut comma = false;
            if i != 0 && c == b',' {
                self.advance(1);
                comma = true;
            }
            if c == b']' {
                if !comma {
                    self.advance(1);
                    return Some(ret);
                }
                return None;
            }
            self.spaces();
            if !self.consume_node() {
                return None;
            }
            let v = self.value(depth)?;
            ret.push(v);
            self.spaces();
            i += 1;
        }
    }

    fn string(&mut self) -> Option<Vec<u8>> {
        self.advance(1); // skip "
        let mut buf: Vec<u8> = Vec::new();
        while self.pos < self.bytes.len() {
            let c = self.bytes[self.pos];
            if c == b'\\' && self.pos + 1 < self.bytes.len() {
                let n = self.bytes[self.pos + 1];
                match n {
                    b'"' | b'/' | b'\\' => {
                        buf.push(n);
                        self.advance(2);
                    }
                    b'b' => {
                        buf.push(b'\x08');
                        self.advance(2);
                    }
                    b'f' => {
                        buf.push(b'\x0C');
                        self.advance(2);
                    }
                    b'n' => {
                        buf.push(b'\n');
                        self.advance(2);
                    }
                    b'r' => {
                        buf.push(b'\r');
                        self.advance(2);
                    }
                    b't' => {
                        buf.push(b'\t');
                        self.advance(2);
                    }
                    _ => {
                        buf.push(b'\\');
                        self.advance(1);
                    }
                }
                continue;
            }
            if c == b'"' {
                self.advance(1);
                return Some(buf);
            }
            buf.push(c);
            self.advance(1);
        }
        None
    }

    fn number(&mut self) -> Option<AttrValue> {
        let mut sign = 1.0f64;
        let c = self.peek()?;
        if c == b'-' {
            sign = -1.0;
            self.advance(1);
        } else if c == b'+' {
            self.advance(1);
        }
        if !is_numeric(self.peek()?) {
            return None;
        }
        let start = self.pos;
        let mut digits = Vec::new();
        while let Some(c) = self.peek() {
            if is_numeric(c) {
                digits.push(c);
                self.advance(1);
            } else {
                break;
            }
        }
        if digits.is_empty() {
            self.pos = start;
            return None;
        }
        if self.peek() == Some(b'.') {
            digits.push(b'.');
            self.advance(1);
            while let Some(c) = self.peek() {
                if is_numeric(c) {
                    digits.push(c);
                    self.advance(1);
                } else {
                    break;
                }
            }
        }
        let c = self.peek()?;
        if c == b'e' || c == b'E' {
            digits.push(c);
            self.advance(1);
            let c2 = self.peek()?;
            if c2 == b'-' || c2 == b'+' {
                digits.push(c2);
                self.advance(1);
            }
            while let Some(c3) = self.peek() {
                if is_numeric(c3) {
                    digits.push(c3);
                    self.advance(1);
                } else {
                    break;
                }
            }
        }
        let s = std::str::from_utf8(&digits).ok()?;
        let f = s.parse::<f64>().ok()?;
        if !f.is_finite() {
            return None;
        }
        Some(AttrValue::Number(sign * f))
    }

    fn others(&mut self) -> Option<AttrValue> {
        self.spaces();
        let start = self.pos;
        if start >= self.bytes.len() {
            return None;
        }
        let c = self.bytes[start];
        if !is_alpha(c) && c != b'_' && c != b':' {
            return None;
        }
        let mut i = 0;
        while start + i < self.bytes.len() && is_name_char(self.bytes[start + i]) {
            i += 1;
        }
        let value = &self.bytes[start..start + i];
        self.advance(i);
        if value == b"true" {
            return Some(AttrValue::Bool(true));
        }
        if value == b"false" {
            return Some(AttrValue::Bool(false));
        }
        if value == b"null" {
            return Some(AttrValue::Null);
        }
        Some(AttrValue::Bytes(value.to_vec()))
    }
}


#[derive(Clone,Debug,Default,PartialEq,Eq)]
pub(crate) struct CodeBlockAttrs {
    pub base_line_number:Option<i64>,pub highlight_lines:Vec<(i64,i64)>,pub style:Option<Vec<u8>>,
    pub no_highlight:bool,pub line_numbers:Option<bool>,pub line_numbers_in_table:Option<bool>,
}
pub(crate) struct CodeInfo<'a>{pub lang:Option<&'a[u8]>,pub attrs:CodeBlockAttrs,pub raw:&'a[u8]}
pub(crate) fn parse(raw:&[u8])->Result<CodeInfo<'_>,&'static str>{
    if raw.len()>1<<20{return Err("markdown code info exceeds byte limit");}
    let lang=if raw.is_empty(){None}else{Some(&raw[..raw.iter().position(|b|*b==b' ').unwrap_or(raw.len())])};
    let mut attrs=CodeBlockAttrs::default();
    let parsed=if let Some(position)=raw.iter().position(|b|*b==b'{').filter(|position|*position>0){parse_attributes_checked(&raw[position..])?}else{None};
    if let Some(parsed)=parsed{
        let mut unique=std::collections::BTreeMap::new();for(name,value)in parsed{unique.insert(name,value);}
        let base=match unique.get(b"linenostart".as_slice()){Some(AttrValue::Number(number))=>{let base=gotmpl::float_to_go_i64(*number);attrs.base_line_number=Some(base);base},_=>1};
        if let Some(AttrValue::Array(lines))=unique.get(b"hl_lines".as_slice()){
            for line in lines{
                let range=match line{
                    AttrValue::Number(number)=>Some((gotmpl::float_to_go_i64(*number),gotmpl::float_to_go_i64(*number))),
                    AttrValue::Bytes(bytes)=>{
                        let mut parts=bytes.split(|b|*b==b'-');let start=parts.next().and_then(atoi);
                        match(start,parts.next()){(Some(start),None)=>Some((start,start)),(Some(start),Some(end))=>atoi(end).map(|end|(start,end)),_=>None}
                    }
                    _=>None,
                };
                if let Some((start,end))=range{let shift=base.wrapping_sub(1);attrs.highlight_lines.push((start.wrapping_add(shift),end.wrapping_add(shift)));}
            }
        }
        if let Some(AttrValue::Bytes(style))=unique.get(b"style".as_slice()){attrs.style=Some(style.clone());}
        attrs.no_highlight=unique.contains_key(b"nohl".as_slice());
        match unique.get(b"linenos".as_slice()){
            Some(AttrValue::Bool(value))=>attrs.line_numbers=Some(*value),
            Some(AttrValue::Bytes(value))=>{
                if !value.is_empty(){attrs.line_numbers=Some(true);}
                if value==b"table"{attrs.line_numbers_in_table=Some(true);}else if value==b"inline"{attrs.line_numbers_in_table=Some(false);}
            }
            _=>{},
        }
    }
    Ok(CodeInfo{lang,attrs,raw})
}
fn atoi(bytes:&[u8])->Option<i64>{
    let digits=bytes.strip_prefix(b"+").or_else(||bytes.strip_prefix(b"-")).unwrap_or(bytes);
    if digits.is_empty()||!digits.iter().all(u8::is_ascii_digit){return None;}
    std::str::from_utf8(bytes).ok()?.parse().ok()
}
#[path="html_entities.rs"] mod entities;
fn push(out:&mut Vec<u8>,bytes:&[u8])->Result<(),&'static str>{if bytes.len()>(1usize<<20).saturating_sub(out.len()){return Err("markdown fallback output exceeds byte limit");}out.extend_from_slice(bytes);Ok(())}
fn raw_write(out:&mut Vec<u8>,bytes:&[u8])->Result<(),&'static str>{
    for byte in bytes{push(out,match byte{0=>b"\xef\xbf\xbd",b'"'=>b"&quot;",b'&'=>b"&amp;",b'<'=>b"&lt;",b'>'=>b"&gt;",_=>std::slice::from_ref(byte)})?;}Ok(())
}
fn escape_rune(out:&mut Vec<u8>,number:u32)->Result<(),&'static str>{
    let rune=char::from_u32(number).filter(|c|*c!='\0').unwrap_or('\u{fffd}');let mut bytes=[0u8;4];raw_write(out,rune.encode_utf8(&mut bytes).as_bytes())
}
fn writer_write(out:&mut Vec<u8>,source:&[u8])->Result<(),&'static str>{
    let(mut escaped,mut start,mut i)=(false,0,0);
    while i<source.len(){let c=source[i];
        if escaped&&c.is_ascii_punctuation(){raw_write(out,&source[start..i-1])?;start=i;escaped=false;i+=1;continue;}
        if c==0{raw_write(out,&source[start..i])?;raw_write(out,b"\xef\xbf\xbd")?;start=i+1;escaped=false;i+=1;continue;}
        if c==b'&'{
            let next=i+1;let mut end=next;
            if source.get(next)==Some(&b'#'){
                let first=next+1;let hex=matches!(source.get(first),Some(b'x'|b'X'));let number_start=first+usize::from(hex);end=number_start;
                while source.get(end).is_some_and(|b|if hex{b.is_ascii_hexdigit()}else{b.is_ascii_digit()}){end+=1;}
                let digits=end-number_start;
                if digits>0&&digits<if hex{7}else{8}&&source.get(end)==Some(&b';'){
                    let number=u32::from_str_radix(std::str::from_utf8(&source[number_start..end]).unwrap_or(""),if hex{16}else{10}).unwrap_or(0);
                    raw_write(out,&source[start..i])?;escape_rune(out,number)?;start=end+1;escaped=false;i=end+1;continue;
                }
            }else{
                while source.get(end).is_some_and(u8::is_ascii_alphanumeric){end+=1;}
                if end>next&&source.get(end)==Some(&b';'){if let Some(entity)=entities::lookup(&source[next..end]){raw_write(out,&source[start..i])?;raw_write(out,entity)?;start=end+1;escaped=false;i=end+1;continue;}}
            }
        }
        escaped=c==b'\\';i+=1;
    }raw_write(out,&source[start..])
}
/// Goldmark-highlighting's unchanged non-highlighted fallback, for NoLexer or LexError.
/// Aggregate cancellation/budget errors must be propagated by the caller.
pub(crate) fn fallback(language:Option<&[u8]>,code:&[u8])->Result<Vec<u8>,&'static str>{
    let mut out=Vec::new();push(&mut out,b"<pre><code")?;
    if let Some(language)=language{push(&mut out,b" class=\"language-")?;writer_write(&mut out,language)?;push(&mut out,b"\"")?;}
    push(&mut out,b">")?;raw_write(&mut out,code)?;push(&mut out,b"</code></pre>\n")?;Ok(out)
}

/// The legacy attribute grammar is bounded to 32 levels and 16,384 nodes.
/// Prepay a conservative allocation *peak* before invoking it: each syntax
/// byte can belong to at most one string/name leaf, with simultaneous string
/// copies/growth covered by 32 bytes per input byte. Per-node Vec headers,
/// old/new backing slots, the deduplication BTree and final range list fit
/// within 1024 bytes per syntactic node. The lease remains live through the
/// caller's use of the owned attributes and drops after those attributes.
/// This bridge preserves the existing public unmetered inspection API while
/// making the request-path entry use the owning Markdown account.
pub(crate) struct BudgetedCodeInfo<'a>{info:CodeInfo<'a>,_lease:gotmpl::ByteLease}
impl<'a> std::ops::Deref for BudgetedCodeInfo<'a>{type Target=CodeInfo<'a>;fn deref(&self)->&Self::Target{&self.info}}
pub(crate) fn parse_with_account<'a>(raw:&'a[u8],account:&gotmpl::BudgetAccount)->gotmpl::Result<BudgetedCodeInfo<'a>>{
    if raw.len()>1<<20{return Err(gotmpl::TemplateError::Exec("markdown code info exceeds byte limit".into()));}
    let attributes=raw.iter().position(|b|*b==b'{').filter(|position|*position>0).map(|position|&raw[position..]);
    let (peak,work)=if let Some(bytes)=attributes{
        // Every attribute and array item consumes at least one input byte.
        let nodes=attribute_node_upper(bytes).min(16_384);
        (bytes.len().checked_mul(32).and_then(|n|nodes.checked_mul(1024).and_then(|m|n.checked_add(m))).and_then(|n|n.checked_add(4096)).ok_or_else(||gotmpl::TemplateError::Exec("Markdown attribute budget overflow".into()))?,bytes.len().checked_mul(nodes+1).ok_or_else(||gotmpl::TemplateError::Exec("Markdown attribute work overflow".into()))?)
    }else{(0,raw.len())};
    account.charge_work(work)?;account.reserve(peak)?;let lease=account.transfer(peak)?;
    let info=parse(raw).map_err(|message|gotmpl::TemplateError::Exec(message.into()))?;
    Ok(BudgetedCodeInfo{info,_lease:lease})
}

/// Allocation-free lexical upper bound: every attribute/array node begins
/// with a distinct token. Quoted payload and whitespace cannot begin nodes.
fn attribute_node_upper(bytes:&[u8])->usize{
    let(mut i,mut nodes)=(0,0usize);
    while i<bytes.len(){let b=bytes[i];
        if is_space(b)||matches!(b,b','|b'='|b']'|b'}'){i+=1;continue;}
        nodes+=1;
        if b==b'"'{i+=1;while i<bytes.len(){if bytes[i]==b'\\'&&i+1<bytes.len(){i+=2;continue;}if bytes[i]==b'"'{i+=1;break;}i+=1;}continue;}
        if is_alpha(b)||matches!(b,b'_'|b':'){i+=1;while i<bytes.len()&&is_name_char(bytes[i]){i+=1;}continue;}
        if is_numeric(b){i+=1;while i<bytes.len()&&is_numeric(bytes[i]){i+=1;}continue;}
        i+=1;
    }nodes
}
