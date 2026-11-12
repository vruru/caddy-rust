// Byte reader ported from Goldmark 1.8.6 text/reader.go (MIT).
use super::segment::{Segment, Bytes};
use gotmpl::{BudgetAccount, Result, TemplateError};
fn exec_error(msg: impl Into<String>) -> TemplateError {
    TemplateError::Exec(msg.into())
}
pub(super) const EOF:u8=0xff;
pub(super) struct Reader<'a> {
    source: &'a [u8],
    pos: Segment,
    line: isize,
    head: usize,
    line_offset: Option<isize>,
    account: BudgetAccount,
}
impl<'a> Reader<'a> {
    pub fn new(source:&'a[u8],account:BudgetAccount)->Result<Self>{
        let mut reader=Self{source,pos:Segment::default(),line:-1,head:0,line_offset:None,account};
        reader.reset_position()?;Ok(reader)
    }
    pub fn reset_position(&mut self)->Result<()>{
        self.line=-1;self.head=0;self.line_offset=None;self.advance_line()
    }
    pub fn source(&self) -> &'a [u8] {
        self.source
    }
    pub fn value(&self, seg: Segment) -> Result<Bytes<'a>> {
        seg.value(self.source, &self.account)
    }
    pub fn peek(&self) -> u8 {
        let source_len = self.source.len();
        if self.pos.start < source_len {
            if self.pos.padding != 0 {
                return b' ';
            }
            return self.source[self.pos.start];
        }
        EOF
    }
    pub fn peek_line(&self) -> Result<Option<(Bytes<'a>, Segment)>> {
        let source_len = self.source.len();
        if self.pos.start < source_len {
            let bytes = self.pos.value(self.source, &self.account)?;
            return Ok(Some((bytes, self.pos)));
        }
        Ok(None)
    }
    pub fn line_offset(&mut self)->Result<isize>{
        if self.line_offset.is_none(){
            let mut width=0usize;
            if self.head<self.pos.start{
                for byte in self.source.get(self.head..self.pos.start).ok_or_else(||exec_error("invalid Markdown position"))?{
                    width=width.checked_add(if *byte==b'\t'{4-width%4}else{1}).ok_or_else(||exec_error("Markdown column overflow"))?;
                }
            }
            let width=isize::try_from(width).map_err(|_|exec_error("Markdown column overflow"))?;
            let padding=isize::try_from(self.pos.padding).map_err(|_|exec_error("Markdown padding overflow"))?;
            self.line_offset=Some(width.checked_sub(padding).ok_or_else(||exec_error("Markdown column overflow"))?);
        }
        Ok(self.line_offset.unwrap())
    }
    pub fn preceding_character(&self)->Result<char>{
        if self.pos.start==0{return Ok(if self.pos.padding!=0{' '}else{'\n'});}
        let mut index=self.pos.start-1;
        loop{
            let byte=*self.source.get(index).ok_or_else(||exec_error("invalid Markdown preceding position"))?;
            if byte&0xc0!=0x80{break;}
            // Goldmark indexes -1 for an initial run of continuation bytes.
            // Decode that malformed prefix as RuneError instead of preserving
            // its process-level panic; the original source bytes stay intact.
            let Some(previous)=index.checked_sub(1)else{return Ok('\u{fffd}');};index=previous;
        }
        gotmpl::go_runes(&self.source[index..]).next().map(|(ch,_)|ch).ok_or_else(||exec_error("missing Markdown preceding rune"))
    }
    pub fn advance(&mut self, n: usize) -> Result<()> {
        self.line_offset = None;
        let source_len = self.source.len();
        let mut remaining = n;
        while remaining > 0 && self.pos.start < source_len {
            if self.pos.padding != 0 {
                self.pos.padding -= 1;
                remaining -= 1;
                continue;
            }
            if self.source.get(self.pos.start as usize) == Some(&b'\n') {
                self.advance_line()?;
                remaining -= 1;
                continue;
            }
            self.pos.start += 1;
            remaining -= 1;
        }
        Ok(())
    }
    pub fn advance_and_set_padding(&mut self, n: usize, padding: usize) -> Result<()> {
        self.advance(n)?;
        if padding > self.pos.padding {
            self.set_padding(padding);
        }
        Ok(())
    }
    pub fn advance_to_eol(&mut self) -> Result<()> {
        let source_len = self.source.len();
        if self.pos.start >= source_len {
            return Ok(());
        }
        self.line_offset = None;
        let mut i = self.pos.start as usize;
        let mut found_newline_index = None;
        while i < source_len {
            if self.source[i] == b'\n' {
                found_newline_index = Some(i);
                break;
            }
            i += 1;
        }
        if let Some(newline_idx) = found_newline_index {
            self.pos.start = newline_idx;
        } else {
            self.pos.start = source_len;
        }
        self.pos.padding = 0;
        Ok(())
    }
    pub fn advance_line(&mut self)->Result<()>{
        self.line_offset=None;self.pos.start=self.pos.stop;self.head=self.pos.start;
        if self.pos.start>=self.source.len(){return Ok(());}
        self.pos.stop=match self.source[self.pos.start..].iter().position(|byte|*byte==b'\n'){
            Some(offset)=>self.pos.start+offset+1,None=>self.source.len()
        };
        self.line=self.line.checked_add(1).ok_or_else(||exec_error("Markdown line overflow"))?;
        self.pos.padding=0;Ok(())
    }
    pub fn position(&self) -> (isize, Segment) {
        (self.line, self.pos)
    }
    pub fn set_position(&mut self, line: isize, pos: Segment) {
        self.line_offset = None;
        self.line = line;
        self.pos = pos;
    }
    pub fn set_padding(&mut self, v: usize) {
        self.pos.padding = v;
    }
    pub fn read_rune(&mut self)->Result<Option<(char,usize)>>{
        let Some((bytes,_))=self.peek_line()? else{return Ok(None);};
        let Some((ch,width))=gotmpl::go_runes(&bytes).next() else{return Ok(None);};
        // Goldmark's regexp io.RuneReader stops at RuneError, including the
        // valid replacement character. It does not advance that position.
        if ch=='\u{fffd}'{return Ok(None);}
        drop(bytes);self.advance(width)?;Ok(Some((ch,width)))
    }
}
