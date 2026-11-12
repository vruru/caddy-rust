// Copyright 2015 Matthew Holt and The Caddy Authors
// SPDX-License-Identifier: Apache-2.0
//! Directory-specific fields, backed by plain owned listing data. A file's
//! Tpl accessor wraps the same listing identity without storing Value cycles.
use super::{Control, Fields, RenderResult, error, arity};
use crate::http_runtime::browse::{Listing, human_size};
use gotmpl::{Value, Object, TypedSlice, HostType, HostMethod, Signature, ArgKind, JsonField};
use std::{sync::{Arc,Weak},collections::BTreeMap};

struct Browse {listing:Listing, owner:Weak<Control>}
struct Entry {browse:Arc<Browse>,index:Option<usize>}
fn item(e:&Entry)->&crate::http_runtime::browse::Item {
    static ZERO:std::sync::LazyLock<crate::http_runtime::browse::Item>=std::sync::LazyLock::new(||crate::http_runtime::browse::Item::zero());
    e.index.and_then(|index|e.browse.listing.items.get(index)).unwrap_or(&ZERO)
}
const NAMES:&[&str]=&["Name","Path","CanGoUp","Items","Offset","Limit","NumDirs","NumFiles","TotalFileSize","TotalFileSizeFollowingSymlinks","Sort","Order","Layout"];
const ITEM_NAMES:&[&str]=&["Name","Size","URL","ModTime","Mode","IsDir","IsSymlink","SymlinkPath","Tpl"];
fn owner(b:&Browse)->RenderResult<Arc<Control>>{let c=b.owner.upgrade().ok_or_else(||error("browse template owner retired"))?;c.check()?;Ok(c)}
fn text(raw:&[u8])->Value{Value::from_go_bytes(raw.to_vec())}
fn json(names:&[&'static str],keys:&[&'static str])->Arc<[JsonField]>{names.iter().zip(keys).map(|(&source,&name)|JsonField{source,name,omit_empty:matches!(source,"Items"|"Offset"|"Limit"|"Sort"|"Order"|"Layout"|"SymlinkPath")}).collect()}

pub(super) fn fields(listing:Listing,control:&Arc<Control>)->RenderResult<Fields>{
    control.reserve_host_bytes(4096)?;
    let b=Arc::new(Browse{listing,owner:Arc::downgrade(control)});
    let mut fields=Fields::new();
    for &n in NAMES {fields.insert(n.into(),listing_field(&b,n)?.ok_or_else(||error("missing browse field"))?);}
    fields.insert("Breadcrumbs".into(),breadcrumbs(&b)?);
    fields.insert("HumanTotalFileSize".into(),Value::String(human_size(b.listing.total_size as u64).into()));
    fields.insert("HumanTotalFileSizeFollowingSymlinks".into(),Value::String(human_size(b.listing.total_following_size as u64).into()));
    Ok(fields)
}
fn listing_field(b:&Arc<Browse>,name:&str)->RenderResult<Option<Value>>{
    let c=owner(b)?;c.charge(1)?;
    let l=&b.listing;
    Ok(Some(match name {
        "Name"=>{c.reserve_host_bytes(l.title.len()+64)?;Value::String(l.title.clone().into())},
        "Path"=>{c.reserve_host_bytes(l.path.len()+64)?;Value::String(l.path.clone().into())},
        "CanGoUp"=>Value::Bool(l.can_go_up),
        "NumDirs"=>Value::Int(l.num_dirs),"NumFiles"=>Value::Int(l.num_files),
        "TotalFileSize"=>Value::Int64(l.total_size),"TotalFileSizeFollowingSymlinks"=>Value::Int64(l.total_following_size),
        "Offset"=>Value::Int(l.offset as i64),"Limit"=>Value::Int(l.limit as i64),
        "Sort"|"Order"|"Layout"=>{let v=match name {"Sort"=>&l.sort,"Order"=>&l.order,_=>&l.layout};c.reserve_host_bytes(v.len()+64)?;Value::from_go_bytes(v.clone())},
        "Items"=>{
            let size=l.backing_capacity.checked_mul(std::mem::size_of::<Value>()+2048).ok_or_else(||error("browse items size overflow"))?;
            c.reserve_host_bytes(size+1024)?;c.charge(l.backing_capacity)?;
            let values=(0..l.backing_capacity).map(|index|entry(Arc::new(Entry{browse:b.clone(),index:(index<l.items.len()).then_some(index)}))).collect::<RenderResult<Vec<_>>>()?;
            let length=if l.limit>0{l.limit}else{l.items.len().saturating_sub(l.offset)};
            Value::Slice(TypedSlice::values("[]fileserver.fileInfo",Some(values.into()))?.reslice(l.offset,l.offset+length)?)
        },
        _=>return Ok(None)
    }))
}
fn listing_object(b:Arc<Browse>)->RenderResult<Value>{
    let c=owner(&b)?;c.reserve_host_bytes(4096)?;
    let fields=NAMES.iter().map(|&n|(Arc::from(n),Value::Nil)).collect();
    let mut methods=BTreeMap::<Arc<str>,gotmpl::ValueFunc>::new();
    for name in ["Breadcrumbs","HumanTotalFileSize","HumanTotalFileSizeFollowingSymlinks"] {let b=b.clone();methods.insert(name.into(),Arc::new(move|args|{arity(args,0,0)?;let c=owner(&b)?;c.reserve_host_bytes(512)?;match name {"Breadcrumbs"=>breadcrumbs(&b),"HumanTotalFileSize"=>Ok(Value::String(human_size(b.listing.total_size as u64).into())),_=>Ok(Value::String(human_size(b.listing.total_following_size as u64).into()))}}));}
    let identity=Arc::as_ptr(&b) as usize;let data=b.clone();let weak=b.owner.clone();
    Ok(Value::Object(Arc::new(Object{fields,methods,lazy_fields:true,
        dynamic_fields:Some(Arc::new(move|n|listing_field(&b,n))),
        field_charge:Some(Arc::new(move|_|weak.upgrade().ok_or_else(||error("browse owner retired"))?.check())),
        go_type:Some("*fileserver.browseTemplateContext"),pointer_identity:Some(identity),data:Some(data),
        field_order:Some(NAMES.iter().map(|&n|Arc::from(n)).collect()),
        json_fields:Some(json(NAMES,&["name","path","can_go_up","items","offset","limit","num_dirs","num_files","total_file_size","total_file_size_following_symlinks","sort","order","layout"])),..Object::default()})))
}
static EXT:Signature=Signature::from_static(&[],Some(ArgKind::String));
static LAYOUT:Signature=Signature::from_static(&[ArgKind::String],None);
static METHODS:HostType=HostType{methods:&[
    HostMethod{name:"HasExt",invoke:|o,a|method(o,"HasExt",a),signature:Some(&EXT)},
    HostMethod{name:"HumanSize",invoke:|o,a|method(o,"HumanSize",a),signature:None},
    HostMethod{name:"HumanModTime",invoke:|o,a|method(o,"HumanModTime",a),signature:Some(&LAYOUT)},
]};
fn entry(e:Arc<Entry>)->RenderResult<Value>{
    let c=owner(&e.browse)?;c.check()?;
    let field=e.clone();let weak=e.browse.owner.clone();
    Ok(Value::Object(Arc::new(Object{
        fields:ITEM_NAMES.iter().map(|&n|(Arc::from(n),Value::Nil)).collect(),lazy_fields:true,
        dynamic_fields:Some(Arc::new(move|n|entry_field(&field,n))),
        field_charge:Some(Arc::new(move|_|weak.upgrade().ok_or_else(||error("browse owner retired"))?.check())),
        host_type:Some(&METHODS),go_type:Some("fileserver.fileInfo"),data:Some(e),data_bytes:std::mem::size_of::<Entry>(),
        equal:Some(|a,b|match(a.host_data::<Entry>("fileserver.fileInfo"),b.host_data::<Entry>("fileserver.fileInfo")){(Some(a),Some(b))=>(a.index.is_none()&&b.index.is_none())||(Arc::ptr_eq(&a.browse,&b.browse)&&a.index==b.index),_=>false}),
        field_order:Some(ITEM_NAMES.iter().map(|&n|Arc::from(n)).collect()),
        json_fields:Some(json(&ITEM_NAMES[..8],&["name","size","url","mod_time","mode","is_dir","is_symlink","symlink_path"])),..Object::default()})))
}
fn entry_field(e:&Entry,name:&str)->RenderResult<Option<Value>>{
    let c=owner(&e.browse)?;c.charge(1)?;
    let i=item(e);
    Ok(Some(match name {
        "Name"=>{c.reserve_host_bytes(i.raw_name.len()+64)?;text(&i.raw_name)},
        "URL"=>{c.reserve_host_bytes(i.url.len()+64)?;Value::String(i.url.clone().into())},
        "SymlinkPath"=>{c.reserve_host_bytes(i.raw_symlink_path.len()+64)?;text(&i.raw_symlink_path)},
        "Size"=>Value::Int64(i.size as i64),"Mode"=>{c.reserve_host_bytes(256)?;super::data::mode_value(i.mode)},
        "IsDir"=>Value::Bool(i.is_dir),"IsSymlink"=>Value::Bool(i.is_symlink),
        "ModTime"=>{c.reserve_host_bytes(16384)?;utc_mod_time(i.modified.into())?},
        "Tpl"=>if e.index.is_some(){listing_object(e.browse.clone())?}else{Value::Object(Arc::new(Object{go_type:Some("*fileserver.browseTemplateContext"),nil_pointer:Some(Arc::new(||true)),..Object::default()}))},_=>return Ok(None)
    }))
}
fn utc_mod_time(time:std::time::SystemTime)->RenderResult<Value>{
    // Caddy directoryListing stores ModTime.UTC(), independent of process TZ.
    // Reuse the existing Go time UTC method, leaving ordinary local-time APIs
    // unchanged, including the zero-valued backing slot's year-one timestamp.
    let Value::Object(value)=super::sprig::dates::system_time(time)?else{return Err(error("invalid browse time"));};
    let utc=value.host_type.and_then(|host|host.methods.iter().find(|method|method.name=="UTC")).ok_or_else(||error("browse time UTC unavailable"))?;
    (utc.invoke)(&value,&[])
}
fn method(o:&Object,name:&str,args:&[Value])->RenderResult<Value>{
    let e=o.host_data::<Entry>("fileserver.fileInfo").ok_or_else(||error("invalid browse entry"))?;
    let c=owner(&e.browse)?;c.charge(1)?;
    let i=item(e);
    match name {
        "HasExt"=>{
            c.reserve_host_bytes(i.raw_name.len().checked_mul(6).and_then(|x|x.checked_add(64)).ok_or_else(||error("browse name size overflow"))?)?;
            let lower=gotmpl::go_utf8_text(&i.raw_name).chars().map(|c|c.to_lowercase().next().unwrap_or(c)).collect::<String>();
            for a in args {let raw=a.as_go_bytes().ok_or_else(||error("HasExt requires string"))?;c.charge(raw.len()+lower.len()+1)?;c.reserve_host_bytes(raw.len().saturating_mul(6)+64)?;let suffix=gotmpl::go_utf8_text(raw).chars().map(|c|c.to_lowercase().next().unwrap_or(c)).collect::<String>();if lower.ends_with(&suffix){return Ok(Value::Bool(true));}}
            Ok(Value::Bool(false))
        },
        "HumanSize"=>{arity(args,0,0)?;c.reserve_host_bytes(256)?;Ok(Value::String(human_size(i.size).into()))},
        "HumanModTime"=>{
            arity(args,1,1)?;c.reserve_host_bytes(16384)?;
            let Value::Object(t)=utc_mod_time(i.modified.into())? else{return Err(error("invalid browse time"));};
            let format=t.host_type.and_then(|h|h.methods.iter().find(|m|m.name=="Format")).ok_or_else(||error("browse time Format unavailable"))?;(format.invoke)(&t,args)
        },_=>Err(error("unknown browse method"))
    }
}
fn breadcrumbs(b:&Arc<Browse>)->RenderResult<Value>{
    let c=owner(b)?;let path=&b.listing.path;c.reserve_host_bytes(path.len().saturating_mul(8)+4096)?;c.charge(path.len()+1)?;
    let p=path.strip_suffix('/').unwrap_or(path);
    let parts=p.split('/').collect::<Vec<_>>();let count=parts.len();
    c.reserve_host_bytes(count.checked_mul(1024).ok_or_else(||error("breadcrumb size overflow"))?)?;
    let mut out=Vec::with_capacity(count);
    for (index,part) in parts.into_iter().enumerate(){
        let len=(count-index-1).checked_mul(3).ok_or_else(||error("breadcrumb size overflow"))?;c.reserve_host_bytes(len+part.len()+128)?;let link="../".repeat(count-index-1);
        let text=if index==0&&part.is_empty(){b"/".to_vec()}else{percent_encoding::percent_decode_str(part).collect()};
        out.push(Value::Object(Arc::new(Object{fields:BTreeMap::from([("Link".into(),Value::String(link.into())),("Text".into(),Value::from_go_bytes(text))]),field_order:Some([Arc::from("Link"),Arc::from("Text")].into()),go_type:Some("fileserver.crumb"),equal:Some(|a,b|a.fields.get("Link")==b.fields.get("Link")&&a.fields.get("Text")==b.fields.get("Text")),..Object::default()})));
    }
    Ok(Value::Slice(TypedSlice::values("[]fileserver.crumb",Some(out.into()))?))
}
