//! Segmented byte reader ported from Goldmark 1.8.6 text/reader.go (MIT).
use super::segment::{Bytes,Segment};
use gotmpl::{BudgetAccount,BudgetedBytes,Result,TemplateError};
fn error()->TemplateError{TemplateError::Exec("invalid Markdown block reader position or allocation".into())}
pub(super) struct BlockReader<'a,'s>{
    source:&'a[u8],segments:&'s[Segment],line:isize,pos:Option<Segment>,
    head:usize,last:usize,line_offset:Option<isize>,account:BudgetAccount,
}
impl<'a,'s> BlockReader<'a,'s>{
    pub fn new(source:&'a[u8],segments:&'s[Segment],account:&BudgetAccount)->Result<Self>{
        let mut reader=Self{source,segments:&[],line:-1,pos:None,head:0,last:0,line_offset:None,account:account.clone()};
        reader.reset(segments)?;Ok(reader)
    }
    pub fn reset(&mut self,segments:&'s[Segment])->Result<()>{
        self.account.charge_work(segments.len())?;
        for segment in segments{self.source.get(segment.start..segment.stop).ok_or_else(error)?;}
        self.segments=segments;self.reset_position()
    }
    pub fn reset_position(&mut self)->Result<()>{
        self.line=-1;self.head=0;self.last=self.segments.last().map_or(0,|s|s.stop);self.pos=None;self.line_offset=None;self.advance_line()
    }
    pub fn source(&self)->&'a[u8]{self.source}
    pub fn value(&self,segment:Segment)->Result<BudgetedBytes>{block_value(self.source,self.segments,segment,&self.account)}
    fn visible(&self)->Option<Segment>{
        self.pos.filter(|pos|self.line>=0&&(self.line as usize)<self.segments.len()&&pos.start<self.last)
    }
    pub fn peek(&self)->u8{self.visible().map_or(0xff,|pos|if pos.padding!=0{b' '}else{self.source.get(pos.start).copied().unwrap_or(0xff)})}
    pub fn peek_line(&self)->Result<Option<(Bytes<'a>,Segment)>>{
        self.visible().map(|pos|Ok((pos.value(self.source,&self.account)?,pos))).transpose()
    }
    pub fn preceding_character(&self)->Result<char>{
        let Some(pos)=self.pos else{return Ok('\n');};
        if pos.padding!=0{return Ok(' ');}
        let Some(first)=self.segments.first()else{return Ok('\n');};
        if self.line==0&&pos.start<=first.start{return Ok('\n');}
        let Some(mut index)=pos.start.checked_sub(1)else{return Ok('\n');};
        loop{
            let Some(byte)=self.source.get(index)else{return Ok('\n');};
            if byte&0xc0!=0x80{break;}
            let Some(previous)=index.checked_sub(1)else{return Ok('\n');};index=previous;
        }
        Ok(gotmpl::go_runes(&self.source[index..]).next().map_or('\n',|(ch,_)|ch))
    }
    pub fn line_offset(&mut self)->Result<isize>{
        if let Some(offset)=self.line_offset{return Ok(offset);}
        let Some(pos)=self.pos else{return Ok(0);};let mut width=0usize;
        if self.head<pos.start{for byte in self.source.get(self.head..pos.start).ok_or_else(error)?{
            width=width.checked_add(if *byte==b'\t'{4-width%4}else{1}).ok_or_else(error)?;
        }}
        let width=isize::try_from(width).map_err(|_|error())?;let padding=isize::try_from(pos.padding).map_err(|_|error())?;
        let offset=width.checked_sub(padding).ok_or_else(error)?;self.line_offset=Some(offset);Ok(offset)
    }
    pub fn advance(&mut self,n:usize)->Result<()>{
        self.account.charge_work(n)?;self.line_offset=None;
        for _ in 0..n{
            let Some(pos)=self.pos.as_mut()else{self.advance_line()?;continue;};
            if pos.padding!=0{pos.padding-=1;continue;}
            if pos.start>=pos.stop.saturating_sub(1)&&pos.stop<self.last{self.advance_line()?;continue;}
            pos.start=pos.start.checked_add(1).ok_or_else(error)?;
        }Ok(())
    }
    pub fn advance_and_set_padding(&mut self,n:usize,padding:usize)->Result<()>{
        self.advance(n)?;if self.pos.as_ref().is_some_and(|pos|padding>pos.padding){self.set_padding(padding);}Ok(())
    }
    pub fn advance_to_eol(&mut self)->Result<()>{
        self.line_offset=None;let Some(pos)=self.pos.as_mut()else{return Ok(());};pos.padding=0;
        let Some(last)=pos.stop.checked_sub(1)else{return Ok(());};
        let byte=self.source.get(last).ok_or_else(error)?;pos.start=if *byte==b'\n'{last}else{pos.stop};Ok(())
    }
    pub fn advance_line(&mut self)->Result<()>{
        self.set_position(self.line.checked_add(1).ok_or_else(error)?,None)?;
        self.head=self.pos.map_or(0,|pos|pos.start);Ok(())
    }
    pub fn position(&self)->(isize,Option<Segment>){(self.line,self.pos)}
    pub fn set_position(&mut self,line:isize,pos:Option<Segment>)->Result<()>{
        let index=usize::try_from(line).map_err(|_|error())?;self.line_offset=None;self.line=line;
        if let Some(pos)=pos{self.pos=Some(pos);}else if let Some(segment)=self.segments.get(index){self.pos=Some(*segment);}
        if let Some(segment)=self.segments.get(index){self.head=segment.start;}Ok(())
    }
    pub fn set_padding(&mut self,padding:usize){self.line_offset=None;if let Some(pos)=&mut self.pos{pos.padding=padding;}}
    pub fn read_rune(&mut self)->Result<Option<(char,usize)>>{
        let Some((bytes,_))=self.peek_line()?else{return Ok(None);};
        let Some((ch,width))=gotmpl::go_runes(&bytes).next()else{return Ok(None);};
        if ch=='\u{fffd}'{return Ok(None);}drop(bytes);self.advance(width)?;Ok(Some((ch,width)))
    }
}
fn block_value(source:&[u8],segments:&[Segment],requested:Segment,account:&BudgetAccount)->Result<BudgetedBytes>{
    source.get(requested.start..requested.stop).ok_or_else(error)?;
    let first=segments.iter().rposition(|segment|segment.start<=requested.start).ok_or_else(error)?;
    let mut count=0usize;let mut steps=0usize;
    for(index,segment)in segments.iter().enumerate().skip(first){
        source.get(segment.start..segment.stop).ok_or_else(error)?;
        let start=if index==first{requested.start}else{segment.start};let end=requested.stop.min(segment.stop);
        count=count.checked_add(segment.padding).and_then(|n|n.checked_add(end.saturating_sub(start))).ok_or_else(error)?;
        steps+=1;if segment.stop>requested.stop{break;}
    }
    account.charge_work(count.checked_add(steps).ok_or_else(error)?)?;account.reserve(count)?;
    let mut bytes=Vec::new();if bytes.try_reserve_exact(count).is_err(){account.release(count)?;return Err(error());}
    if bytes.capacity()!=count{drop(bytes);account.release(count)?;return Err(error());}
    for(index,segment)in segments.iter().enumerate().skip(first){
        bytes.resize(bytes.len()+segment.padding,b' ');
        let start=if index==first{requested.start}else{segment.start};let end=requested.stop.min(segment.stop);
        if start<end{bytes.extend_from_slice(source.get(start..end).ok_or_else(error)?);}
        if segment.stop>requested.stop{break;}
    }
    BudgetedBytes::from_account(bytes,account)
}
