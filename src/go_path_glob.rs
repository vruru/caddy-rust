// Copyright 2010 The Go Authors. All rights reserved.
// BSD-3-Clause; the full license is retained in THIRD-PARTY-NOTICES.
//! Go path.Match compares literal bytes and decodes runes only for '?' and
//! classes. A star may advance one byte into a valid multibyte rune. A UTF-8
//! regexp therefore cannot faithfully replace this matcher.
use std::time::Instant;
#[derive(Debug)]pub(crate) struct GlobLimit;
struct Budget{deadline:Option<Instant>,ticks:usize}
impl Budget{fn step(&mut self)->Result<(),GlobLimit>{self.ticks=self.ticks.wrapping_add(1);if self.ticks.is_multiple_of(512)&&self.deadline.is_some_and(|at|Instant::now()>=at){Err(GlobLimit)}else{Ok(())}}}
#[derive(Clone,Debug)]pub(crate) struct CompiledGoGlob{pattern:Box<str>}
impl CompiledGoGlob{pub(crate) fn is_match(&self,value:&str)->bool{run(self.pattern.as_bytes(),value.as_bytes(),&mut Budget{deadline:None,ticks:0}).unwrap_or(false)}}
pub(crate) fn compile_go_path_glob(pattern:&str)->Option<CompiledGoGlob>{validate(pattern.as_bytes(),&mut Budget{deadline:None,ticks:0}).ok()?.then(||CompiledGoGlob{pattern:pattern.into()})}
pub(crate) fn go_path_glob(pattern:&str,value:&str)->bool{go_path_glob_deadline(pattern,value,None).unwrap_or(false)}
pub(crate) fn go_path_glob_deadline(pattern:&str,value:&str,deadline:Option<Instant>)->Result<bool,GlobLimit>{
    let mut budget=Budget{deadline,ticks:0};if !validate(pattern.as_bytes(),&mut budget)?{return Ok(false)}run(pattern.as_bytes(),value.as_bytes(),&mut budget)
}
fn esc(mut pattern:&[u8])->Option<(char,&[u8])>{
    if pattern.is_empty()||matches!(pattern[0],b'-'|b']'){return None}
    if pattern[0]==b'\\'{pattern=&pattern[1..];}
    let(rune,width)=gotmpl::decode_go_rune(pattern)?;
    if rune=='\u{fffd}'&&width==1{return None}
    let rest=&pattern[width..];if rest.is_empty(){return None}Some((rune,rest))
}
fn validate(mut pattern:&[u8],budget:&mut Budget)->Result<bool,GlobLimit>{
    while !pattern.is_empty(){budget.step()?;
        match pattern[0]{
            b'\\'=>{if pattern.len()<2{return Ok(false)}pattern=&pattern[2..];},
            b'['=>{
                pattern=&pattern[1..];if pattern.first()==Some(&b'^'){pattern=&pattern[1..];}
                let mut ranges=0;
                loop{budget.step()?;if pattern.first()==Some(&b']')&&ranges>0{pattern=&pattern[1..];break}
                    let Some((_,rest))=esc(pattern)else{return Ok(false)};pattern=rest;
                    if pattern.first()==Some(&b'-'){let Some((_,rest))=esc(&pattern[1..])else{return Ok(false)};pattern=rest;}
                    ranges+=1;
                }
            },_=>pattern=&pattern[1..],
        }
    }Ok(true)
}
fn scan(mut pattern:&[u8])->(bool,&[u8],&[u8]){
    let mut star=false;while pattern.first()==Some(&b'*'){star=true;pattern=&pattern[1..];}
    let(mut range,mut i)=(false,0usize);
    while i<pattern.len(){match pattern[i]{b'\\'=>{if i+1<pattern.len(){i+=1;}},b'['=>range=true,b']'=>range=false,b'*' if !range=>return(star,&pattern[..i],&pattern[i..]),_=>{}}i+=1;}
    (star,pattern,&[])
}
fn chunk<'a>(mut pattern:&[u8],mut name:&'a[u8],budget:&mut Budget)->Result<Option<&'a[u8]>,GlobLimit>{
    // Syntax was checked once before matching. Stop failed candidates early;
    // do not repeatedly parse the tail merely to recheck known-valid syntax.
    while !pattern.is_empty(){budget.step()?;if name.is_empty(){return Ok(None)}
        match pattern[0]{
            b'['=>{
                let(rune,width)=gotmpl::decode_go_rune(name).expect("nonempty Go rune");name=&name[width..];pattern=&pattern[1..];
                let negated=pattern.first()==Some(&b'^');if negated{pattern=&pattern[1..];}
                let(mut matched,mut ranges)=(false,0);
                loop{budget.step()?;if pattern.first()==Some(&b']')&&ranges>0{pattern=&pattern[1..];break}
                    let Some((lo,rest))=esc(pattern)else{return Ok(None)};pattern=rest;let mut hi=lo;
                    if pattern.first()==Some(&b'-'){let Some((end,rest))=esc(&pattern[1..])else{return Ok(None)};hi=end;pattern=rest;}
                    matched|=lo<=rune&&rune<=hi;ranges+=1;
                }
                if matched==negated{return Ok(None)}
            },
            b'?'=>{if name[0]==b'/'{return Ok(None)}let(_,width)=gotmpl::decode_go_rune(name).expect("nonempty Go rune");name=&name[width..];pattern=&pattern[1..];},
            _=>{
                if pattern[0]==b'\\'{pattern=&pattern[1..];}
                if pattern.first()!=name.first(){return Ok(None)}pattern=&pattern[1..];name=&name[1..];
            }
        }
    }Ok(Some(name))
}
fn run(mut pattern:&[u8],mut name:&[u8],budget:&mut Budget)->Result<bool,GlobLimit>{
    'pattern:while !pattern.is_empty(){budget.step()?;let(star,current,rest)=scan(pattern);pattern=rest;
        if star&&current.is_empty(){return Ok(!name.contains(&b'/'))}
        if let Some(tail)=chunk(current,name,budget)?{if tail.is_empty()||!pattern.is_empty(){name=tail;continue}}
        if star{for i in 0..name.len(){budget.step()?;if name[i]==b'/'{break}if let Some(tail)=chunk(current,&name[i+1..],budget)?{if pattern.is_empty()&&!tail.is_empty(){continue}name=tail;continue 'pattern}}}
        return Ok(false)
    }Ok(name.is_empty())
}

/// Raw filesystem names use the same byte/rune rules as HTTP path patterns.
/// The caller distinguishes invalid syntax from a valid non-match.
pub(crate) fn go_path_glob_bytes(pattern:&str,name:&[u8])->Option<bool>{
    let mut budget=Budget{deadline:None,ticks:0};
    if !validate(pattern.as_bytes(),&mut budget).ok()?{return None}
    run(pattern.as_bytes(),name,&mut budget).ok()
}
