//! Flat, owned AST for Caddy's enabled Goldmark 1.8.6 nodes (MIT).
//! Links are indices, so deep Markdown trees do not recursively destroy nodes.
use super::segment::{Bytes,Segment,Segments};
use gotmpl::{BudgetAccount,Result,TemplateError};
pub(super) type Id=usize;
pub(super) const SOFT_BREAK:u8=1;
pub(super) const HARD_BREAK:u8=2;
pub(super) const RAW:u8=4;
pub(super) const CODE:u8=8;
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub(super) enum Alignment{Left,Right,Center,None}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]pub(super) enum ReferenceType{Full,Collapsed,Shortcut}
pub(super) struct LinkReference<'a>{pub kind:ReferenceType,pub label:Bytes<'a>}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]pub(super) enum DelimiterProcessor{Emphasis,Strikethrough}
pub(super) enum Kind<'a>{
    Document,TextBlock,Paragraph,Heading{level:u8},ThematicBreak,CodeBlock,
    FencedCode{info:Option<Segment>},Blockquote,List{marker:u8,tight:bool,start:usize},ListItem{offset:isize},
    HtmlBlock{kind:u8,closure:Option<Segment>},ReferenceDefinition{label:Bytes<'a>,destination:Bytes<'a>,title:Option<Bytes<'a>>},
    Text{segment:Segment,flags:u8},String{value:Bytes<'a>,flags:u8},CodeSpan,Emphasis{level:usize},
    Link{destination:Bytes<'a>,title:Option<Bytes<'a>>,reference:Option<LinkReference<'a>>},Image{destination:Bytes<'a>,title:Option<Bytes<'a>>,reference:Option<LinkReference<'a>>},
    AutoLink{email:bool,protocol:Option<&'static[u8]>,value:Segment},RawHtml,Strikethrough,TaskCheckBox{checked:bool},
    Table{alignments:Vec<Alignment>},TableHeader,TableRow,TableCell{alignment:Alignment},
    Footnote{reference:Bytes<'a>,index:Option<usize>},FootnoteList{count:usize},
    FootnoteLink{index:usize,ref_count:usize,ref_index:usize},FootnoteBacklink{index:usize,ref_count:usize,ref_index:usize},
    LinkLabel{segment:Segment,is_image:bool},
    Delimiter{segment:Segment,character:u8,length:usize,original_length:usize,can_open:bool,can_close:bool,
        previous:Option<Id>,next:Option<Id>,processor:DelimiterProcessor},
}
pub(super) struct Attribute<'a>{pub name:Bytes<'a>,pub value:Bytes<'a>}
pub(super) struct Node<'a>{
    pub kind:Kind<'a>,pub parent:Option<Id>,pub first:Option<Id>,pub last:Option<Id>,pub prev:Option<Id>,pub next:Option<Id>,
    pub child_count:usize,pub lines:Segments,pub blank_previous:bool,pub attributes:Vec<Attribute<'a>>,pub pos:Option<usize>,
}
impl<'a> Node<'a>{
    fn new(kind:Kind<'a>,account:&BudgetAccount)->Self{
        Self{kind,parent:None,first:None,last:None,prev:None,next:None,child_count:0,lines:Segments::new(account),blank_previous:false,attributes:Vec::new(),pos:None}
    }
}
fn error()->TemplateError{TemplateError::Exec("invalid Markdown AST state or allocation".into())}
/// Reallocation prepays both blocks, moves elements without cloning payloads,
/// and refunds the old capacity only after its allocation has been destroyed.
pub(super) fn room<T>(values:&mut Vec<T>,additional:usize,account:&BudgetAccount)->Result<()>{
    let length=values.len().checked_add(additional).ok_or_else(error)?;
    if length<=values.capacity(){return Ok(());}
    let size=std::mem::size_of::<T>();if size==0{return Err(error());}
    let capacity=values.capacity().checked_mul(2).ok_or_else(error)?.max(4).max(length);
    let bytes=capacity.checked_mul(size).ok_or_else(error)?;account.reserve(bytes)?;
    let mut next=Vec::new();if next.try_reserve_exact(capacity).is_err(){account.release(bytes)?;return Err(error());}
    if next.capacity()!=capacity{drop(next);account.release(bytes)?;return Err(error());}
    let retired=values.capacity().checked_mul(size).ok_or_else(error)?;
    next.append(values);drop(std::mem::replace(values,next));account.release(retired)?;Ok(())
}
pub(super) struct Arena<'a>{nodes:Vec<Node<'a>>,account:BudgetAccount}
impl<'a> Arena<'a>{
    pub fn new(account:&BudgetAccount)->Self{Self{nodes:Vec::new(),account:account.clone()}}
    pub fn account(&self)->&BudgetAccount{&self.account}
    pub fn get(&self,id:Id)->Result<&Node<'a>>{self.nodes.get(id).ok_or_else(error)}
    pub fn get_mut(&mut self,id:Id)->Result<&mut Node<'a>>{self.nodes.get_mut(id).ok_or_else(error)}
    pub fn add(&mut self,kind:Kind<'a>)->Result<Id>{
        self.account.charge_work(1)?;room(&mut self.nodes,1,&self.account)?;
        let id=self.nodes.len();self.nodes.push(Node::new(kind,&self.account));Ok(id)
    }
    fn may_attach(&self,parent:Id,child:Id)->Result<()>{
        let empty=self.get(child)?.first.is_none();self.get(parent)?;
        if parent==child{return Err(error());}
        // A leaf cannot contain its new parent. Normal block construction
        // appends new leaves, so nested Markdown keeps O(1) insertion here.
        if empty{return Ok(());}
        let mut current=Some(parent);
        while let Some(id)=current{self.account.charge_work(1)?;if id==child{return Err(error());}current=self.get(id)?.parent;}
        Ok(())
    }
    pub fn detach(&mut self,id:Id)->Result<()>{
        let node=self.get(id)?;let(parent,previous,next)=(node.parent,node.prev,node.next);
        let Some(parent)=parent else{return Ok(());};
        let count=self.get(parent)?.child_count.checked_sub(1).ok_or_else(error)?;
        if let Some(previous)=previous{self.get_mut(previous)?.next=next;}else{self.get_mut(parent)?.first=next;}
        if let Some(next)=next{self.get_mut(next)?.prev=previous;}else{self.get_mut(parent)?.last=previous;}
        self.get_mut(parent)?.child_count=count;let node=self.get_mut(id)?;node.parent=None;node.prev=None;node.next=None;Ok(())
    }
    pub fn append(&mut self,parent:Id,child:Id)->Result<()>{
        self.may_attach(parent,child)?;self.detach(child)?;
        let previous=self.get(parent)?.last;let count=self.get(parent)?.child_count.checked_add(1).ok_or_else(error)?;
        if let Some(previous)=previous{self.get_mut(previous)?.next=Some(child);}else{self.get_mut(parent)?.first=Some(child);}
        let node=self.get_mut(child)?;node.parent=Some(parent);node.prev=previous;node.next=None;
        let node=self.get_mut(parent)?;node.last=Some(child);node.child_count=count;Ok(())
    }
    pub fn insert_before(&mut self,parent:Id,reference:Option<Id>,child:Id)->Result<()>{
        self.may_attach(parent,child)?;
        if let Some(reference)=reference{if self.get(reference)?.parent!=Some(parent){return Err(error());}}
        if reference==Some(child){return Ok(());}
        let Some(reference)=reference else{return self.append(parent,child);};
        self.detach(child)?;
        let count=self.get(parent)?.child_count.checked_add(1).ok_or_else(error)?;
        let previous=self.get(reference)?.prev;
        if let Some(previous)=previous{self.get_mut(previous)?.next=Some(child);}else{self.get_mut(parent)?.first=Some(child);}
        let node=self.get_mut(child)?;node.parent=Some(parent);node.prev=previous;node.next=Some(reference);
        self.get_mut(reference)?.prev=Some(child);self.get_mut(parent)?.child_count=count;Ok(())
    }
    pub fn insert_after(&mut self,parent:Id,reference:Id,child:Id)->Result<()>{
        if self.get(reference)?.parent!=Some(parent){return Err(error());}
        let next=self.get(reference)?.next;self.insert_before(parent,next,child)
    }
    pub fn replace(&mut self,parent:Id,previous:Id,child:Id)->Result<()>{
        if self.get(previous)?.parent!=Some(parent){return Err(error());}
        if previous==child{return Ok(());}self.insert_before(parent,Some(previous),child)?;self.detach(previous)
    }
    pub fn remove_children(&mut self,parent:Id)->Result<()>{
        let mut child=self.get(parent)?.first;
        while let Some(id)=child{self.account.charge_work(1)?;let node=self.get_mut(id)?;child=node.next;node.parent=None;node.prev=None;node.next=None;}
        let node=self.get_mut(parent)?;node.first=None;node.last=None;node.child_count=0;Ok(())
    }
    pub fn attribute(&self,id:Id,name:&[u8])->Result<Option<&[u8]>>{
        Ok(self.get(id)?.attributes.iter().find(|attribute|&*attribute.name==name).map(|attribute|&*attribute.value))
    }
    pub fn set_attribute(&mut self,id:Id,name:Bytes<'a>,value:Bytes<'a>)->Result<()>{
        let account=self.account.clone();let node=self.get_mut(id)?;
        if let Some(attribute)=node.attributes.iter_mut().find(|attribute|&*attribute.name==&*name){attribute.value=value;return Ok(());}
        room(&mut node.attributes,1,&account)?;node.attributes.push(Attribute{name,value});Ok(())
    }
    pub fn append_text_segment(&mut self,parent:Id,segment:Segment)->Result<Id>{
        if let Some(last)=self.get(parent)?.last{
            if let Kind::Text{segment:old,flags}=&mut self.get_mut(last)?.kind{
                if old.stop==segment.start&&*flags&SOFT_BREAK==0{*old=old.with_stop(segment.stop);return Ok(last);}
            }
        }
        let id=self.add(Kind::Text{segment,flags:0})?;self.append(parent,id)?;Ok(id)
    }
    pub fn walk(&mut self,root:Id,mut visitor:impl FnMut(&mut Self,Id,bool)->Result<Walk>)->Result<()>{
        self.get(root)?;let account=self.account.clone();let mut frames=Vec::new();room(&mut frames,1,&account)?;
        frames.push(Frame{id:root,stage:Stage::Enter});
        let result:Result<()>=(||{
            while let Some(frame)=frames.last().copied(){
                account.charge_work(1)?;
                match frame.stage{
                    Stage::Enter=>{let status=visitor(self,frame.id,true)?;if status==Walk::Stop{return Ok(());}frames.last_mut().unwrap().stage=if status==Walk::SkipChildren{Stage::Exit}else{Stage::Children(None)};}
                    Stage::Children(previous)=>{
                        let next=match previous{Some(previous)=>self.get(previous)?.next,None=>self.get(frame.id)?.first};
                        if let Some(next)=next{frames.last_mut().unwrap().stage=Stage::Children(Some(next));room(&mut frames,1,&account)?;frames.push(Frame{id:next,stage:Stage::Enter});}
                        else{frames.last_mut().unwrap().stage=Stage::Exit;}
                    }
                    Stage::Exit=>{if visitor(self,frame.id,false)?==Walk::Stop{return Ok(());}frames.pop();}
                }
            }Ok(())
        })();
        let bytes=frames.capacity()*std::mem::size_of::<Frame>();drop(frames);let refund=account.release(bytes);result?;refund
    }
}
#[derive(Clone,Copy,PartialEq,Eq)]pub(super) enum Walk{Continue,SkipChildren,Stop}
#[derive(Clone,Copy)]enum Stage{Enter,Children(Option<Id>),Exit}
#[derive(Clone,Copy)]struct Frame{id:Id,stage:Stage}
