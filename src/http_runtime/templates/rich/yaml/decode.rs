// Native behavioral port of yaml.v3 v3.0.1.
// Copyright (c) 2011-2019 Canonical Ltd; Apache-2.0.
// See LICENSES/yaml-v3.0.1-LICENSE and THIRD-PARTY-NOTICES.
use super::{reader::{Arena,Kind,Node},resolve::{self,Tag},libyaml::parser::ScalarStyle};
use gotmpl::{BudgetAccount,MapContext,Result,TemplateError,Value,GoKey};
use std::{collections::{BTreeMap,BTreeSet},sync::Arc,mem::size_of,cell::RefCell};
use super::super::super::sprig::dates;
#[derive(Clone,Copy,Default)]
struct ScalarCache {tag:Option<Tag>,time:Option<Option<dates::YamlTimeParts>>}
fn error(message:&str)->TemplateError{TemplateError::Exec(message.into())}
pub(super) fn convert(arena:&Arena,maps:&MapContext,account:&BudgetAccount)->Result<Value>{
    account.reserve(arena.nodes.len().checked_mul(1+size_of::<ScalarCache>()).ok_or_else(||error("YAML cache size overflow"))?)?;
    let mut active=Vec::new();active.try_reserve_exact(arena.nodes.len()).map_err(|_|error("YAML alias allocation failed"))?;active.resize(arena.nodes.len(),false);
    let mut cache=Vec::new();cache.try_reserve_exact(arena.nodes.len()).map_err(|_|error("YAML scalar cache allocation failed"))?;cache.resize(arena.nodes.len(),ScalarCache::default());
    let mut decoder=Decoder{arena,maps,account,active,cache:RefCell::new(cache),decoded:0,aliases:0,alias_depth:0};
    match arena.nodes[arena.root].kind{
        Kind::Mapping|Kind::Alias(_)=>{let entries=decoder.mapping(arena.root,true,0,None,true)?;decoder.finish(entries,true)},
        Kind::Scalar=>{let resolved=decoder.scalar(arena.root)?;if resolved.tag==Tag::Null{Ok(maps.nil_map())}else{Err(error("front matter requires a mapping"))}},
        _=>Err(error("front matter requires a mapping")),
    }
}
struct Decoder<'a>{arena:&'a Arena,maps:&'a MapContext,account:&'a BudgetAccount,active:Vec<bool>,cache:RefCell<Vec<ScalarCache>>,decoded:usize,aliases:usize,alias_depth:usize}
impl Decoder<'_>{
    fn touch(&mut self,depth:usize)->Result<()>{
        if depth>32{return Err(error("YAML expanded nesting limit exceeded"));}
        self.account.charge_work(1)?;self.decoded+=1;if self.alias_depth>0{self.aliases+=1;}
        if self.decoded>16_384{return Err(error("YAML expanded node limit exceeded"));}
        let ratio=if self.decoded<=400_000{0.99}else if self.decoded>=4_000_000{0.10}else{0.99-0.89*(self.decoded-400_000)as f64/3_600_000.0};
        if self.aliases>100&&self.decoded>1000&&self.aliases as f64/self.decoded as f64>ratio{return Err(error("document contains excessive aliasing"));}Ok(())
    }
    fn time_parts(&self,id:usize,text:&str)->Result<Option<dates::YamlTimeParts>>{
        if let Some(cached)=self.cache.borrow()[id].time{return Ok(cached);}
        self.account.reserve(dates::YAML_TIME_PARSE_SCRATCH)?;
        let result=dates::parse_yaml_timestamp(text);
        self.account.release(dates::YAML_TIME_PARSE_SCRATCH)?;
        let parts=result?;self.cache.borrow_mut()[id].time=Some(parts);Ok(parts)
    }
    fn scalar(&self,id:usize)->Result<resolve::Resolved>{
        let node=&self.arena.nodes[id];
        resolve::resolve(&node.value,node.tag.as_deref(),node.style!=Some(ScalarStyle::Plain),self.account,|text|{
            let Some(parts)=self.time_parts(id,text)?else{return Ok(None);};
            let total=dates::YAML_TIME_BUILD_SCRATCH+dates::yaml_time_retained_bound();self.account.reserve(total)?;
            let value=dates::yaml_time_value(parts)?;let retained=dates::yaml_time_retained(&value)?;
            self.account.release(total.checked_sub(retained).ok_or_else(||error("YAML timestamp exceeds precharged layout"))?)?;
            Ok(Some(value))
        })
    }
    fn target(&self,mut id:usize)->Result<usize>{
        for _ in 0..=32{match self.arena.nodes[id].kind{Kind::Alias(next)=>id=next,_=>return Ok(id)}}Err(error("YAML alias target nesting limit exceeded"))
    }
    fn short_tag(&self,id:usize)->Result<Tag>{
        let id=self.target(id)?;if let Some(tag)=self.cache.borrow()[id].tag{return Ok(tag);}
        let node=&self.arena.nodes[id];if node.kind!=Kind::Scalar{return Ok(Tag::Other);}
        let out=resolve::resolve(&node.value,node.tag.as_deref(),node.style!=Some(ScalarStyle::Plain),self.account,|text|Ok(self.time_parts(id,text)?.map(|_|Value::Nil)))?;
        self.cache.borrow_mut()[id].tag=Some(out.tag);Ok(out.tag)
    }
    fn is_merge(&self,id:usize)->Result<bool>{let node=&self.arena.nodes[id];Ok(node.kind==Kind::Scalar&&node.value==b"<<"&&self.short_tag(id)?==Tag::Merge)}
    fn decode(&mut self,id:usize,depth:usize)->Result<Value>{
        self.touch(depth)?;let arena=self.arena;let node=&arena.nodes[id];
        match node.kind{
            Kind::Alias(target)=>{
                if self.active[id]{return Err(error("YAML anchor value contains itself"));}
                self.active[id]=true;self.alias_depth+=1;let out=self.decode(target,depth+1);self.alias_depth-=1;self.active[id]=false;out
            }
            Kind::Scalar=>Ok(self.scalar(id)?.value),
            Kind::Sequence=>{
                self.account.reserve(node.children.len().checked_mul(2*size_of::<Value>()).and_then(|n|n.checked_add(32)).ok_or_else(||error("YAML sequence size overflow"))?)?;
                let mut items=Vec::new();items.try_reserve_exact(node.children.len()).map_err(|_|error("YAML sequence allocation failed"))?;
                for &child in &node.children{items.push(self.decode(child,depth+1)?);}Ok(Value::List(items.into()))
            }
            Kind::Mapping=>{
                let mut string_map=true;for pair in node.children.chunks_exact(2){if !matches!(self.short_tag(pair[0])?,Tag::Str|Tag::Merge){string_map=false;break;}}
                let entries=self.mapping(id,string_map,depth,None,false)?;self.finish(entries,string_map)
            }
        }
    }
    fn key(&mut self,id:usize,string_map:bool,depth:usize)->Result<Option<Value>>{
        if !string_map{return self.decode(id,depth).map(Some);}
        self.touch(depth)?;
        if let Kind::Alias(target)=self.arena.nodes[id].kind{
            if self.active[id]{return Err(error("YAML anchor value contains itself"));}
            self.active[id]=true;self.alias_depth+=1;let result=self.key(target,true,depth+1);self.alias_depth-=1;self.active[id]=false;return result;
        }
        let node=&self.arena.nodes[id];
        if node.kind!=Kind::Scalar{return Err(error("YAML map key cannot decode as string"));}
        let tag=self.short_tag(id)?;
        if tag==Tag::Null{return Ok(None);}
        if tag==Tag::Binary{return Ok(Some(self.scalar(id)?.value));}
        self.account.reserve(node.value.len().checked_mul(3).and_then(|n|n.checked_add(64)).ok_or_else(||error("YAML map key size overflow"))?)?;
        Ok(Some(Value::from_go_bytes(Arc::<[u8]>::from(node.value.as_slice()))))
    }
    fn seen(&self,seen:&mut Vec<Value>,key:&Value)->Result<bool>{
        // The normal decoder never accepts collection keys.
        for old in seen.iter(){self.account.charge_work(1)?;if key_equal(old,key)?{return Ok(true);}}
        if seen.len()==seen.capacity(){let next=seen.capacity().max(4).checked_mul(2).ok_or_else(||error("YAML merge key size overflow"))?;self.account.reserve(next*size_of::<Value>())?;seen.try_reserve_exact(next-seen.len()).map_err(|_|error("YAML merge key allocation failed"))?;}
        seen.push(key.clone());Ok(false)
    }
    fn mapping(&mut self,id:usize,string_map:bool,depth:usize,mut seen:Option<&mut Vec<Value>>,count:bool)->Result<Vec<(Value,Value)>>{
        if count{self.touch(depth)?;}
        let arena=self.arena;let node=&arena.nodes[id];
        if let Kind::Alias(target)=node.kind{
            if self.active[id]{return Err(error("YAML anchor value contains itself"));}
            if self.arena.nodes[target].kind!=Kind::Mapping{return Err(error("map merge requires map or sequence of maps"));}
            self.active[id]=true;self.alias_depth+=1;let result=self.mapping(target,string_map,depth+1,seen,true);self.alias_depth-=1;self.active[id]=false;return result;
        }
        if node.kind!=Kind::Mapping{return Err(error("map merge requires map or sequence of maps"));}
        {
        super::allocation::btree::<(u8,&[u8]),()>(node.children.len()/2,self.account)?;
        let mut duplicate=BTreeSet::new();
        for pair in node.children.chunks_exact(2){
            let key=&arena.nodes[pair[0]];let kind=match key.kind{Kind::Scalar=>0,Kind::Sequence=>1,Kind::Mapping=>2,Kind::Alias(_)=>3};
            if !duplicate.insert((kind,key.value.as_slice())){return Err(TemplateError::Exec(format!("line {}: mapping key already defined",key.line)));}
        }
        }
        self.account.reserve(node.children.len().checked_mul(size_of::<(Value,Value)>()).and_then(|n|n.checked_add(32)).ok_or_else(||error("YAML mapping size overflow"))?)?;
        let mut out=Vec::new();out.try_reserve_exact(node.children.len()/2).map_err(|_|error("YAML mapping allocation failed"))?;
        let mut merge=None;
        for pair in node.children.chunks_exact(2){
            if self.is_merge(pair[0])?{merge=Some(pair[1]);continue;}
            let Some(key)=self.key(pair[0],string_map,depth+1)?else{continue;};
            // Validate generic hashability before recursively expanding value.
            key_valid(&key)?;
            if let Some(seen)=seen.as_deref_mut(){if self.seen(seen,&key)?{continue;}}
            out.push((key,self.decode(pair[1],depth+1)?));
        }
        if let Some(merge)=merge{
            let mut own_seen=Vec::new();
            let seen=if let Some(seen)=seen{seen}else{
                self.account.reserve(node.children.len()*size_of::<Value>())?;own_seen.try_reserve_exact(node.children.len()/2).map_err(|_|error("YAML merge key allocation failed"))?;
                for pair in node.children.chunks_exact(2){let key=self.decode(pair[0],depth+1)?;self.seen(&mut own_seen,&key)?;}&mut own_seen
            };
            let targets=if arena.nodes[merge].kind==Kind::Sequence{arena.nodes[merge].children.as_slice()}else{std::slice::from_ref(&merge)};
            for &target in targets{
                let incoming=self.mapping(target,string_map,depth+1,Some(&mut *seen),true)?;
                if out.len().saturating_add(incoming.len())>out.capacity(){self.account.reserve(out.len().checked_add(incoming.len()).and_then(|n|n.checked_mul(size_of::<(Value,Value)>())).ok_or_else(||error("YAML merged mapping size overflow"))?)?;out.try_reserve_exact(incoming.len()).map_err(|_|error("YAML merged mapping allocation failed"))?;}
                out.extend(incoming);
            }
        }Ok(out)
    }
    fn finish(&self,entries:Vec<(Value,Value)>,string_map:bool)->Result<Value>{
        if string_map{
            super::allocation::btree::<GoKey,Value>(entries.len(),self.account)?;self.account.reserve(128)?;
            let mut map=BTreeMap::new();for(key,value)in entries{map.insert(GoKey::from_value(&key)?,value);}self.maps.map_go(map)
        }else{self.maps.generic_map(entries,self.account)}
    }
}
fn key_valid(key:&Value)->Result<()>{
    match key{Value::List(_)|Value::Slice(_)|Value::Map(_)|Value::SharedMap(_)|Value::GenericMap(_)|Value::Function(_)=>Err(error("invalid YAML map key")),_=>Ok(())}
}
fn key_equal(a:&Value,b:&Value)->Result<bool>{
    gotmpl::generic_key_equal(a,b)
}
