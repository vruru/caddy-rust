//! Shared Goldmark reader contract. Returned bytes borrow the source, never a
//! reader cursor, so parsers can advance while retaining the current line.
use super::{segment::{Bytes,Segment},reader::Reader,block_reader::BlockReader};
use gotmpl::{Result,TemplateError};
pub(super) type Position=(isize,Option<Segment>);
pub(super) trait Read<'a>{
    fn source(&self)->&'a[u8];
    fn value(&self,segment:Segment)->Result<Bytes<'a>>;
    fn peek(&self)->u8;
    fn peek_line(&self)->Result<Option<(Bytes<'a>,Segment)>>;
    fn line_offset(&mut self)->Result<isize>;
    fn preceding_character(&self)->Result<char>;
    fn advance(&mut self,n:usize)->Result<()>;
    fn advance_and_set_padding(&mut self,n:usize,padding:usize)->Result<()>;
    fn advance_to_eol(&mut self)->Result<()>;
    fn advance_line(&mut self)->Result<()>;
    fn position(&self)->Position;
    fn set_position(&mut self,line:isize,position:Option<Segment>)->Result<()>;
    fn set_padding(&mut self,padding:usize);
    fn read_rune(&mut self)->Result<Option<(char,usize)>>{
        let Some((line,_))=self.peek_line()?else{return Ok(None);};
        let Some((ch,width))=gotmpl::decode_go_rune(&line)else{return Ok(None);};
        if ch=='\u{fffd}'{return Ok(None);}drop(line);self.advance(width)?;Ok(Some((ch,width)))
    }
}
impl<'a> Read<'a> for Reader<'a>{
    fn source(&self)->&'a[u8]{Reader::source(self)}
    fn value(&self,segment:Segment)->Result<Bytes<'a>>{Reader::value(self,segment)}
    fn peek(&self)->u8{Reader::peek(self)}
    fn peek_line(&self)->Result<Option<(Bytes<'a>,Segment)>>{Reader::peek_line(self)}
    fn line_offset(&mut self)->Result<isize>{Reader::line_offset(self)}
    fn preceding_character(&self)->Result<char>{Reader::preceding_character(self)}
    fn advance(&mut self,n:usize)->Result<()>{Reader::advance(self,n)}
    fn advance_and_set_padding(&mut self,n:usize,padding:usize)->Result<()>{Reader::advance_and_set_padding(self,n,padding)}
    fn advance_to_eol(&mut self)->Result<()>{Reader::advance_to_eol(self)}
    fn advance_line(&mut self)->Result<()>{Reader::advance_line(self)}
    fn position(&self)->Position{let(line,segment)=Reader::position(self);(line,Some(segment))}
    fn set_position(&mut self,line:isize,position:Option<Segment>)->Result<()>{
        let position=position.ok_or_else(||TemplateError::Exec("missing raw Markdown cursor".into()))?;
        Reader::set_position(self,line,position);Ok(())
    }
    fn set_padding(&mut self,padding:usize){Reader::set_padding(self,padding)}
}
impl<'a,'s> Read<'a> for BlockReader<'a,'s>{
    fn source(&self)->&'a[u8]{BlockReader::source(self)}
    fn value(&self,segment:Segment)->Result<Bytes<'a>>{BlockReader::value(self,segment).map(Bytes::Owned)}
    fn peek(&self)->u8{BlockReader::peek(self)}
    fn peek_line(&self)->Result<Option<(Bytes<'a>,Segment)>>{BlockReader::peek_line(self)}
    fn line_offset(&mut self)->Result<isize>{BlockReader::line_offset(self)}
    fn preceding_character(&self)->Result<char>{BlockReader::preceding_character(self)}
    fn advance(&mut self,n:usize)->Result<()>{BlockReader::advance(self,n)}
    fn advance_and_set_padding(&mut self,n:usize,padding:usize)->Result<()>{BlockReader::advance_and_set_padding(self,n,padding)}
    fn advance_to_eol(&mut self)->Result<()>{BlockReader::advance_to_eol(self)}
    fn advance_line(&mut self)->Result<()>{BlockReader::advance_line(self)}
    fn position(&self)->Position{BlockReader::position(self)}
    fn set_position(&mut self,line:isize,position:Option<Segment>)->Result<()>{BlockReader::set_position(self,line,position)}
    fn set_padding(&mut self,padding:usize){BlockReader::set_padding(self,padding)}
}
