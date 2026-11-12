use super::cstr::{self, CStr};
use super::error::{Error, Mark, Result};
use super::tag::Tag;
use super::util::Owned;
use std::borrow::Cow;
use std::fmt::{self, Debug};
use std::mem::MaybeUninit;
use std::ptr::{addr_of_mut, NonNull};
use std::slice;
use unsafe_libyaml as sys;

pub(crate) struct Parser<'input> {
    pin: Owned<ParserPinned<'input>>,
    scratch: Scratch,
}

struct Scratch {account:gotmpl::BudgetAccount,bytes:usize}
impl Scratch{
    fn reserve(&mut self,n:usize){
        let bytes=self.bytes.checked_add(n).expect("YAML wrapper allocation overflow");
        if let Err(error)=self.account.reserve(n){std::panic::resume_unwind(Box::new(error));}
        self.bytes=bytes;
    }
}
impl Drop for Scratch{fn drop(&mut self){let result=self.account.release(self.bytes);debug_assert!(result.is_ok());}}

struct ParserPinned<'input> {
    sys: sys::yaml_parser_t,
    input: Cow<'input, [u8]>,
}

#[derive(Debug)]
pub(crate) enum Event<'input> {
    StreamStart,
    StreamEnd,
    DocumentStart,
    DocumentEnd,
    Alias(Anchor),
    Scalar(Scalar<'input>),
    SequenceStart(SequenceStart),
    SequenceEnd,
    MappingStart(MappingStart),
    MappingEnd,
}

pub(crate) struct Scalar<'input> {
    pub anchor: Option<Anchor>,
    pub tag: Option<Tag>,
    pub value: Box<[u8]>,
    pub style: ScalarStyle,
    pub repr: Option<&'input [u8]>,
}

#[derive(Debug)]
pub(crate) struct SequenceStart {
    pub anchor: Option<Anchor>,
    pub tag: Option<Tag>,
}

#[derive(Debug)]
pub(crate) struct MappingStart {
    pub anchor: Option<Anchor>,
    pub tag: Option<Tag>,
}

#[derive(Ord, PartialOrd, Eq, PartialEq)]
pub(crate) struct Anchor(Box<[u8]>);
impl Anchor {
    pub(crate) fn as_bytes(&self)->&[u8]{&self.0}
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(crate) enum ScalarStyle {
    Plain,
    SingleQuoted,
    DoubleQuoted,
    Literal,
    Folded,
}

impl<'input> Parser<'input> {
    pub fn new(input: Cow<'input, [u8]>,account:&gotmpl::BudgetAccount) -> Result<Parser<'input>> {
        let mut scratch=Scratch{account:account.clone(),bytes:0};
        scratch.reserve(std::mem::size_of::<ParserPinned>());
        let owned = Owned::<ParserPinned>::new_uninit();
        let pin = unsafe {
            let parser = addr_of_mut!((*owned.ptr).sys);
            if sys::yaml_parser_initialize(parser).fail {
                return Err(Error::parse_error(parser));
            }
            sys::yaml_parser_set_encoding(parser, sys::YAML_UTF8_ENCODING);
            sys::yaml_parser_set_input_string(parser, input.as_ptr(), input.len() as u64);
            addr_of_mut!((*owned.ptr).input).write(input);
            Owned::assume_init(owned)
        };
        Ok(Parser { pin,scratch })
    }

    pub fn next(&mut self) -> Result<(Event<'input>, Mark)> {
        let mut event = MaybeUninit::<sys::yaml_event_t>::uninit();
        unsafe {
            let parser = addr_of_mut!((*self.pin.ptr).sys);
            if (&*parser).error != sys::YAML_NO_ERROR {
                return Err(Error::parse_error(parser));
            }
            let event = event.as_mut_ptr();
            if sys::yaml_parser_parse(parser, event).fail {
                return Err(Error::parse_error(parser));
            }
            let ret = convert_event(&*event, &(*self.pin.ptr).input,&mut self.scratch);
            let mark = Mark {
                sys: (*event).start_mark,
            };
            sys::yaml_event_delete(event);
            Ok((ret?, mark))
        }
    }
}

unsafe fn convert_event<'input>(
    sys: &sys::yaml_event_t,
    input: &Cow<'input, [u8]>,
    scratch:&mut Scratch,
) -> Result<Event<'input>> {
    // All wrapper-owned copies are prepaid before Box allocation. They stay
    // conservatively charged until Parser drops; the arena independently
    // charges any data moved or copied out of an event before that refund.
    let mut bytes=0usize;
    let mut count_cstr=|pointer:*const u8|{if !pointer.is_null(){let cstr=unsafe{CStr::from_ptr(NonNull::new_unchecked(pointer as *mut i8))};bytes=bytes.checked_add(cstr.to_bytes().len()).expect("YAML event size overflow");}};
    // SAFETY: the discriminant selects the initialized libyaml event union.
    unsafe{match sys.type_{
        sys::YAML_ALIAS_EVENT=>count_cstr(sys.data.alias.anchor),
        sys::YAML_SCALAR_EVENT=>{count_cstr(sys.data.scalar.anchor);count_cstr(sys.data.scalar.tag);bytes=bytes.checked_add(sys.data.scalar.length as usize).expect("YAML event size overflow");},
        sys::YAML_SEQUENCE_START_EVENT=>{count_cstr(sys.data.sequence_start.anchor);count_cstr(sys.data.sequence_start.tag);},
        sys::YAML_MAPPING_START_EVENT=>{count_cstr(sys.data.mapping_start.anchor);count_cstr(sys.data.mapping_start.tag);},
        _=>{}
    }}
    scratch.reserve(bytes);
    Ok(match sys.type_ {
        sys::YAML_STREAM_START_EVENT => Event::StreamStart,
        sys::YAML_STREAM_END_EVENT => Event::StreamEnd,
        sys::YAML_DOCUMENT_START_EVENT => Event::DocumentStart,
        sys::YAML_DOCUMENT_END_EVENT => Event::DocumentEnd,
        sys::YAML_ALIAS_EVENT => {
            Event::Alias(unsafe { optional_anchor(sys.data.alias.anchor) }.ok_or_else(Error::invalid_event)?)
        }
        sys::YAML_SCALAR_EVENT => Event::Scalar(Scalar {
            anchor: unsafe { optional_anchor(sys.data.scalar.anchor) },
            tag: unsafe { optional_tag(sys.data.scalar.tag) },
            value: Box::from(unsafe {
                slice::from_raw_parts(sys.data.scalar.value, sys.data.scalar.length as usize)
            }),
            style: match unsafe { sys.data.scalar.style } {
                sys::YAML_PLAIN_SCALAR_STYLE => ScalarStyle::Plain,
                sys::YAML_SINGLE_QUOTED_SCALAR_STYLE => ScalarStyle::SingleQuoted,
                sys::YAML_DOUBLE_QUOTED_SCALAR_STYLE => ScalarStyle::DoubleQuoted,
                sys::YAML_LITERAL_SCALAR_STYLE => ScalarStyle::Literal,
                sys::YAML_FOLDED_SCALAR_STYLE => ScalarStyle::Folded,
                _ => return Err(Error::invalid_event()),
            },
            repr: if let Cow::Borrowed(input) = input {
                Some(input.get(sys.start_mark.index as usize..sys.end_mark.index as usize).ok_or_else(Error::invalid_event)?)
            } else {
                None
            },
        }),
        sys::YAML_SEQUENCE_START_EVENT => Event::SequenceStart(SequenceStart {
            anchor: unsafe { optional_anchor(sys.data.sequence_start.anchor) },
            tag: unsafe { optional_tag(sys.data.sequence_start.tag) },
        }),
        sys::YAML_SEQUENCE_END_EVENT => Event::SequenceEnd,
        sys::YAML_MAPPING_START_EVENT => Event::MappingStart(MappingStart {
            anchor: unsafe { optional_anchor(sys.data.mapping_start.anchor) },
            tag: unsafe { optional_tag(sys.data.mapping_start.tag) },
        }),
        sys::YAML_MAPPING_END_EVENT => Event::MappingEnd,
        _ => return Err(Error::invalid_event()),
    })
}

unsafe fn optional_anchor(anchor: *const u8) -> Option<Anchor> {
    let ptr = NonNull::new(anchor as *mut i8)?;
    let cstr = unsafe { CStr::from_ptr(ptr) };
    Some(Anchor(Box::from(cstr.to_bytes())))
}

unsafe fn optional_tag(tag: *const u8) -> Option<Tag> {
    let ptr = NonNull::new(tag as *mut i8)?;
    let cstr = unsafe { CStr::from_ptr(ptr) };
    Some(Tag(Box::from(cstr.to_bytes())))
}

impl<'input> Debug for Scalar<'input> {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        let Scalar {
            anchor,
            tag,
            value,
            style,
            repr: _,
        } = self;

        struct LossySlice<'a>(&'a [u8]);

        impl<'a> Debug for LossySlice<'a> {
            fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                cstr::debug_lossy(self.0, formatter)
            }
        }

        formatter
            .debug_struct("Scalar")
            .field("anchor", anchor)
            .field("tag", tag)
            .field("value", &LossySlice(value))
            .field("style", style)
            .finish()
    }
}

impl Debug for Anchor {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        cstr::debug_lossy(&self.0, formatter)
    }
}

impl<'input> Drop for ParserPinned<'input> {
    fn drop(&mut self) {
        // A reservation can unwind between raw pointer updates in transpiled
        // libyaml. Its scoped allocator owns every raw allocation and reclaims
        // them without traversing that potentially partial parser state.
        if std::thread::panicking(){return;}
        unsafe { sys::yaml_parser_delete(&mut self.sys) }
    }
}
