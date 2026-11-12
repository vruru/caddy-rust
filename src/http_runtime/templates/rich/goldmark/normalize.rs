//! Pinned Goldmark link-label normalization, without UTF-8 replacement.
use super::{case_folding,output::Output,segment::is_space};
use gotmpl::{BudgetAccount,BudgetedBytes,Result};
pub(super) fn reference(source:&[u8],account:&BudgetAccount)->Result<BudgetedBytes>{
    let start=source.iter().take_while(|byte|is_space(**byte)).count();
    let end=source.len()-source[start..].iter().rev().take_while(|byte|is_space(**byte)).count();
    let source=&source[start..end];let mut output=Output::new(account,1<<20);let mut index=0;let mut space=false;
    while index<source.len(){
        let byte=source[index];
        if is_space(byte){if !space{output.byte(b' ')?;}space=true;index+=1;continue;}
        space=false;
        if byte.is_ascii_uppercase(){output.byte(byte+32)?;index+=1;continue;}
        if byte>=0xb5&&byte&0xc0!=0x80{
            if let Some((ch,width))=gotmpl::decode_go_rune(&source[index..]){
                if ch!='\u{fffd}'{if let Some(folded)=case_folding::lookup(ch){output.write(folded)?;index+=width;continue;}}
            }
        }
        output.byte(byte)?;index+=1;
    }
    output.into_bytes()
}
