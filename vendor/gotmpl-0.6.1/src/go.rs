//! Go-compatible formatting, escaping, and number parsing.
//!
//! Holds the adaptations needed to match Go's `fmt` package and `text/template`
//! output conventions. Used by the built-in template functions
//! ([`print`](crate::funcs), [`printf`](crate::funcs), etc.) and by the lexer
//! for number literal parsing.
//!
//! # What lives here
//!
//! | Category | Functions | Go equivalent |
//! |----------|-----------|---------------|
//! | sprintf | [`sprintf`] | `fmt.Sprintf` |
//! | Sprint spacing | [`needs_space`] | `fmt.Sprint` inter-arg spacing rule |
//! | Quoting | [`go_quote_into`], [`try_backquote_into`] | `strconv.Quote`, `%#q` |
//! | Sci-notation | [`write_normalized_sci`] | Exponent `e+00` format |
//! | `%g` formatting | [`write_g_default`], [`write_g_with_precision`] | `%g` / `%.Ng` |
//! | Integer bases | [`format_int_base_into`] | `%x`, `%o`, `%b` with sign handling |
//! | HTML escape | [`html_escape`] | `template.HTMLEscapeString` |
//! | JS escape | [`js_escape`] | `template.JSEscapeString` |
//! | URL encode | [`url_encode`] | `template.URLQueryEscaper` |
//! | Hex float parse | [`parse_hex_float`] | Hex float literal `0x1.Fp10` |

use alloc::sync::Arc;
use alloc::string::String;
use core::fmt::Write;

use crate::error::{Result, TemplateError};
use crate::value::Value;
use crate::go_buffer::{ByteBuffer,FmtCursor,FormatBuffer};

// fmt.Sprint spacing
/// Returns `true` when Go's `fmt.Sprint` would insert a space between two
/// adjacent arguments (i.e. neither is a string).
pub(crate) fn needs_space(prev: &Value, next: &Value) -> bool {
    // Trusted content (`Value::Safe`) is string-kind, so — like a plain string —
    // it does not get a surrounding space in `print`.
    fn is_stringish(v: &Value) -> bool {
        match v {
            Value::String(_) | Value::ByteString(_) => true,
            #[cfg(feature = "html")]
            Value::Safe { .. } => true,
            _ => false,
        }
    }
    !is_stringish(prev) && !is_stringish(next)
}

/// `fmt.Sprint`: render every argument, inserting a space between two adjacent
/// args exactly when [`needs_space`] says so.
pub(crate) fn sprint(args: &[Value]) -> String {
    let mut out = String::new();
    for (i, arg) in args.iter().enumerate() {
        if i > 0 && needs_space(&args[i - 1], arg) {
            out.push(' ');
        }
        let _ = write!(out, "{arg}");
    }
    out
}

pub fn sprint_bytes(args:&[Value],newline:bool)->Result<alloc::vec::Vec<u8>>{
    let mut output=ByteBuffer::new();
    for(index,arg)in args.iter().enumerate(){
        output.check()?;
        if index>0&&(newline||needs_space(&args[index-1],arg)){output.push(' ');}
        let result=crate::go_write::write_value(&mut output,arg,0);output.check()?;result?;
    }
    if newline{output.push('\n');}output.check()?;Ok(output.into_vec())
}

// sprintf
/// Maximum allowed printf width or precision. Larger values are clamped to
/// this cap to prevent attacker-controlled format strings from triggering
/// multi-gigabyte padding allocations. Also stays below Rust's internal
/// formatter count limit (u16::MAX), which panics on larger widths.
pub(crate) const PRINTF_MAX_LEN: usize = 1_000_000;

fn clamp_fmt_len(n:usize)->usize{n}

/// Parsed printf format specifier (`flags`, `width`, `precision`).
///
/// Mirrors the subset of Go's `fmt` format grammar that `text/template` uses.
#[derive(Default,Clone,Copy)]
pub struct FmtSpec {
    pub left_align: bool,
    pub plus: bool,
    pub space: bool,
    pub hash: bool,
    pub zero: bool,
    pub width: Option<usize>,
    pub precision: Option<usize>,
}

impl FmtSpec {
    fn from_flags(chars: &mut FmtCursor<'_>) -> Self {
        let mut spec = FmtSpec::default();
        loop {
            match chars.peek() {
                Some('-') => {
                    spec.left_align = true;
                    chars.next();
                }
                Some('+') => {
                    spec.plus = true;
                    chars.next();
                }
                Some(' ') => {
                    spec.space = true;
                    chars.next();
                }
                Some('#') => {
                    spec.hash = true;
                    chars.next();
                }
                Some('0') => {
                    spec.zero = true;
                    chars.next();
                }
                _ => break,
            }
        }
        spec
    }

    /// Pad `out[start..]` to the configured width in place.
    ///
    /// Width is measured in Unicode scalars (chars) to match Rust's formatter
    /// semantics and Go parity on the verbs we support. Padding is inserted
    /// only when the already-written content is shorter than `width`.
    ///
    /// `start` must sit on a char boundary in `out`. Callers always invoke
    /// at `out.len()` taken before the verb's content was pushed, which
    /// trivially satisfies that requirement.
    fn pad_in_place(&self, out: &mut dyn FormatBuffer, start: usize, is_numeric: bool) {
        let Some(width) = self.width else {
            return;
        };
        let written = crate::go_runes(&out.as_bytes()[start..]).count();
        if written >= width {
            return;
        }
        let pad_count = width - written;

        if self.left_align {
            out.repeat_ascii(out.len(),b' ',pad_count);
        } else if self.zero && is_numeric {
            // Zero-pad after a leading sign so `-042` / `+042` / ` 042` stay
            // sign-first. The space flag synthesizes a leading ' ' that, like
            // '+'/'-', occupies the sign slot (Go's `% 08d` of 5 is " 0000005").
            let sign_off = match out.as_bytes().get(start) {
                Some(&b'-') | Some(&b'+') | Some(&b' ') => 1,
                _ => 0,
            };
            insert_repeated(out, start + sign_off, '0', pad_count);
        } else {
            insert_repeated(out, start, ' ', pad_count);
        }
    }

    /// Write a signed integer with sign flags (`+`, ` `) applied into `out`.
    fn write_signed(&self, out: &mut dyn FormatBuffer, n: i64) {
        if n >= 0 {
            if self.plus {
                out.push('+');
            } else if self.space {
                out.push(' ');
            }
        }
        let _ = write!(out, "{}", n);
    }

    /// Write an unsigned integer (a [`Value::Uint`]) with sign flags applied.
    ///
    /// Unsigned values are always non-negative, so a `-` is never emitted; Go
    /// still honors the `+` / space flags, prepending the requested sign.
    fn write_unsigned(&self, out: &mut dyn FormatBuffer, n: u64) {
        if self.plus {
            out.push('+');
        } else if self.space {
            out.push(' ');
        }
        let _ = write!(out, "{}", n);
    }
}

/// Insert `count` copies of `ch` at byte position `pos` in `out`.
///
/// One allocation for the pad buffer (via `str::repeat`), then a single
/// `insert_str` memmove. Callers pass ASCII characters, so `pos` is
/// guaranteed to sit on a char boundary.
fn insert_repeated(out:&mut dyn FormatBuffer,pos:usize,ch:char,count:usize){
    debug_assert!(ch.is_ascii());out.repeat_ascii(pos,ch as u8,count);
}

/// Go-compatible `fmt.Sprintf` implementation.
///
/// Supports the format verbs used by `text/template`:
/// `%s`, `%d`, `%f`, `%e`/`%E`, `%g`/`%G`, `%v`, `%q` (incl. `%#q`),
/// `%t`, `%x`/`%X`, `%o`, `%b`, `%c`, and `%%`.
///
/// Flags: `-` (left-align), `+` (sign), ` ` (space sign), `#` (alternate),
/// `0` (zero-pad). Width and precision (`.N`) are supported.
pub(crate) fn sprintf(fmt_str:&str,args:&[Value])->Result<String>{
    String::from_utf8(sprintf_bytes(fmt_str.as_bytes(),args)?).map_err(|_|TemplateError::NonUtf8Output)
}
/// Go-compatible byte formatter with the same bounded output as `printf`.
/// Host callers remain responsible for admission before formatting and for the
/// returned Vec's lifetime; no independent allocation budget is created here.
pub fn sprintf_bytes(fmt_str:&[u8],args:&[Value])->Result<alloc::vec::Vec<u8>>{
    let mut out=ByteBuffer::with_capacity(fmt_str.len().saturating_add(16usize.saturating_mul(args.len())));
    let result=sprintf_into(&mut out,fmt_str,args);out.check()?;result?;Ok(out.into_vec())
}

/// Budgeted printf output for an explicitly owned rendering scope. The caller
/// retains the scope/Tree for all use of the resulting registered Values.
#[cfg(feature="std")]
pub fn sprintf_with_scope(fmt_str:&[u8],args:&[Value],scope:alloc::sync::Arc<crate::FormatterScope>)->Result<crate::BudgetedBytes>{
    let account=scope.account()?;
    let mut out=ByteBuffer::bounded(account,scope,fmt_str.len().saturating_add(16usize.saturating_mul(args.len())));
    let result=sprintf_into(&mut out,fmt_str,args);out.check()?;result?;out.into_budgeted_bytes()
}

/// Read a run of ASCII digits as a `usize` (saturating on overflow).
///
/// Returns `None` if no digits were consumed.
fn parse_uint_digits(chars:&mut FmtCursor<'_>)->Option<usize>{
    let(mut number,mut any)=(0usize,false);
    while let Some(rune)=chars.peek().filter(|rune|rune.is_ascii_digit()){
        if number>PRINTF_MAX_LEN{while chars.next().is_some(){}return None;}
        chars.next();number=number*10+(rune as u8-b'0')as usize;any=true;
    }any.then_some(number)
}

enum ParsedIndex {
    Absent,
    /// 1-based; caller validates `N` against `args.len()`.
    Found(usize),
    Bad,
}

enum IndexOutcome {
    None,
    Applied,
    /// Marker was malformed/out-of-range; BADINDEX has been written and the
    /// caller must `continue`.
    Bad,
}

/// Try to parse a `[N]` argument-index marker at the current position.
///
/// On a malformed bracket: if a `]` exists later in the format, consume up
/// to and past it; otherwise consume only the `[` so the remaining chars
/// (digits, verb) flow back through the regular parse path — `%[1d` ends
/// up as `%!d(BADINDEX)` rather than a swallowed directive.
fn try_parse_index(chars: &mut FmtCursor<'_>) -> ParsedIndex {
    if chars.peek() != Some('[') {
        return ParsedIndex::Absent;
    }
    let mut probe = chars.clone();
    probe.next(); // consume '['
    if let Some(n) = parse_uint_digits(&mut probe)
        && probe.peek() == Some(']')
    {
        probe.next(); // consume ']'
        *chars = probe;
        return ParsedIndex::Found(n);
    }
    chars.next(); // consume '['
    // Only the malformed path needs to know whether a `]` exists later, so
    // we do the scan here rather than up front.
    if chars.clone().any(|c| c == ']') {
        for c in chars.by_ref() {
            if c == ']' {
                break;
            }
        }
    }
    ParsedIndex::Bad
}

/// Parse an optional `[N]` argument-index marker and apply its effect.
///
/// On a valid in-range index, updates `arg_idx`/`reordered` and returns
/// `Applied`. On out-of-range or malformed `[…]`, writes the BADINDEX marker
/// into `out`, sets `reordered` (so a trailing `%!(EXTRA …)` doesn't fire
/// over an unconsumed arg), and returns `Bad` for the caller to `continue`.
fn consume_index(
    chars: &mut FmtCursor<'_>,
    out: &mut dyn FormatBuffer,
    arg_idx: &mut usize,
    reordered: &mut bool,
    args_len: usize,
) -> IndexOutcome {
    match try_parse_index(chars) {
        ParsedIndex::Absent => IndexOutcome::None,
        ParsedIndex::Found(n) if n >= 1 && n <= args_len => {
            *arg_idx = n - 1;
            *reordered = true;
            IndexOutcome::Applied
        }
        ParsedIndex::Found(_) | ParsedIndex::Bad => {
            let verb = skip_to_verb(chars);
            let _ = write!(out, "%!{}(BADINDEX)", verb);
            *reordered = true;
            IndexOutcome::Bad
        }
    }
}

/// Read `args[*arg_idx]` for `*` width / `.*` precision.
///
/// A wrong-type arg is still considered "consumed" (the cursor advances and
/// `Err(())` is returned); a missing arg does not advance the cursor. This
/// asymmetry matches Go's behavior so a trailing `MISSING` marker still
/// fires for the verb when no width arg was actually present.
fn take_int_arg(args:&[Value],index:&mut usize)->core::result::Result<i64,()>{
    let value=args.get(*index).ok_or(())?;*index+=1;
    let number=match value{Value::Int(n)|Value::Int64(n)|Value::NamedInt64(n,_)=>*n,Value::Uint32(n)=>i64::from(*n),Value::Uint8(n)=>i64::from(*n),Value::Uint16(n)=>i64::from(*n),Value::Uint(n)=>i64::try_from(*n).map_err(|_|())?,_=>return Err(())};
    if number.unsigned_abs()>PRINTF_MAX_LEN as u64{return Err(());}Ok(number)
}

/// Skip ahead to the verb char (the next non-flag/digit/dot/star/bracket).
/// Used after a BADINDEX to drain the rest of the directive.
fn skip_to_verb(chars: &mut FmtCursor<'_>) -> char {
    let mut in_brackets = false;
    while let Some(c) = chars.peek() {
        if in_brackets {
            chars.next();
            if c == ']' {
                in_brackets = false;
            }
            continue;
        }
        match c {
            '-' | '+' | ' ' | '#' | '0' | '.' | '*' => {
                chars.next();
            }
            '[' => {
                chars.next();
                in_brackets = true;
            }
            c if c.is_ascii_digit() => {
                chars.next();
            }
            _ => {
                chars.next();
                return c;
            }
        }
    }
    '?'
}

/// Format directly into `out`. Each verb writes its value at `out.len()`,
/// then pads in place. Supports Go's `[N]` argument indexing and `*` /
/// `.*` dynamic width/precision.
fn sprintf_into(out: &mut dyn FormatBuffer, fmt_str: &[u8], args: &[Value]) -> Result<()> {
    let mut chars = FmtCursor::new(fmt_str);
    let mut arg_idx: usize = 0;
    let mut reordered = false;

    loop {
        let literal_start=chars.position();
        let Some(ch)=chars.next()else{break;};
        out.check()?;
        if ch != '%' {
            out.push_bytes(&fmt_str[literal_start..chars.position()]);
            continue;
        }

        let mut spec = FmtSpec::from_flags(&mut chars);

        // Optional `[N]` after flags (the grammar puts the index *after*
        // flags, not before — so `%[1]-d` parses `-` as the verb, not as
        // a left-align flag).
        let first_index = consume_index(&mut chars, out, &mut arg_idx, &mut reordered, args.len());
        if matches!(first_index, IndexOutcome::Bad) {
            continue;
        }
        let had_index_marker = !matches!(first_index, IndexOutcome::None);

        let mut bad_width = false;
        if chars.peek() == Some('*') {
            chars.next();
            // `*` accepts only `int` (float64, string, etc. all yield
            // BADWIDTH) — matched on `Value::Int` directly so floats don't
            // silently truncate via `as_int`.
            match take_int_arg(args, &mut arg_idx) {
                Ok(n) if n >= 0 => spec.width = Some(clamp_fmt_len(n as usize)),
                Ok(n) => {
                    // Negative width → left-align with magnitude as width.
                    // `as usize` may truncate on 32-bit targets for very
                    // large magnitudes, but `clamp_fmt_len` caps the final
                    // width at u16::MAX regardless, so the bound holds.
                    spec.left_align = true;
                    let mag = n.unsigned_abs() as usize;
                    spec.width = Some(clamp_fmt_len(mag));
                }
                Err(()) => bad_width = true,
            }
        } else if let Some(w) = parse_uint_digits(&mut chars) {
            spec.width = Some(clamp_fmt_len(w));
        }

        let mut bad_prec = false;
        if chars.peek() == Some('.') {
            chars.next();
            if chars.peek() == Some('*') {
                chars.next();
                // Same int-only rule as `*` width; negative precision is bad.
                match take_int_arg(args, &mut arg_idx) {
                    Ok(n) if n >= 0 => spec.precision = Some(clamp_fmt_len(n as usize)),
                    _ => bad_prec = true,
                }
            } else {
                // Empty digits (`%.f`) → precision 0.
                let p = parse_uint_digits(&mut chars).unwrap_or(0);
                spec.precision = Some(clamp_fmt_len(p));
            }
        }

        // Optional `[N]` immediately before the verb. Skipped if a prior
        // `[N]` already fired in this directive, to avoid double-reorder
        // on `%[1][2]d`.
        if !had_index_marker
            && matches!(
                consume_index(&mut chars, out, &mut arg_idx, &mut reordered, args.len()),
                IndexOutcome::Bad
            )
        {
            continue;
        }

        let verb = match chars.next() {
            Some(v) => v,
            None => {
                out.push_str("%!(NOVERB)");
                break;
            }
        };

        if verb == '%' {
            out.push('%');
            continue;
        }

        if bad_width {
            out.push_str("%!(BADWIDTH)");
        }
        if bad_prec {
            out.push_str("%!(BADPREC)");
        }

        let arg = if arg_idx < args.len() {
            arg_idx += 1;
            &args[arg_idx - 1]
        } else {
            let _ = write!(out, "%!{}(MISSING)", verb);
            continue;
        };

        format_value(out,arg,verb,spec,0)?;
    }

    // Trailing %!(EXTRA …) marker for unconsumed args.
    //
    // Go suppresses EXTRA when any [N] indexing was used in the directive —
    // tracking which args got read in that case is too expensive and not
    // unambiguous anyway.
    if !reordered && arg_idx < args.len() {
        out.push_str("%!(EXTRA ");
        for (i, v) in args[arg_idx..].iter().enumerate() {
            if i > 0 {
                out.push_str(", ");
            }
            write_bad_arg(out, v,false)?;
        }
        out.push(')');
    }

    out.check()
}

fn format_value(out:&mut dyn FormatBuffer,arg:&Value,verb:char,spec:FmtSpec,depth:usize)->Result<()>{
    format_value_inner(out,arg,verb,spec,depth,false)
}
fn format_value_inner(out:&mut dyn FormatBuffer,arg:&Value,verb:char,mut spec:FmtSpec,depth:usize,erroring:bool)->Result<()>{
    if matches!(arg,Value::Field(_)){let resolved=arg.resolve_field_with(|value|out.host(value))?;return format_value_inner(out,&resolved,verb,spec,depth,erroring);}
    out.check()?;if depth>32{return Err(TemplateError::Exec("formatted value exceeds nesting limit".into()));}
    if erroring && verb=='v' {
        // badVerb prints the underlying value with the original flags; it
        // does not apply ordinary %v's plusV/sharpV conversion or Stringer.
        let start=out.len();
        if let Some(bytes)=arg.as_go_bytes(){
            out.push_bytes(truncate_runes(bytes,spec.precision));
            pad_error_text(out,start,&spec);return out.check();
        }
        if let Value::Bool(value)=arg {out.push_str(if *value{"true"}else{"false"});pad_error_text(out,start,&spec);return out.check();}
        if let Some(number)=arg.as_go_integer() {
            let negative=number<0;
            let magnitude=if negative{(-number) as u64}else{number as u64};
            let sign=if negative{Some('-')}else if spec.plus{Some('+')}else if spec.space{Some(' ')}else{None};
            spec.hash=false;format_magnitude_base_into(out,magnitude,sign,'d',&spec);spec.pad_in_place(out,start,false);return out.check();
        }
        if matches!(arg,Value::Float(_)){return format_value_inner(out,arg,'g',spec,depth,true);}
    }
    if verb=='p' {return format_pointer(out,arg,spec,depth);}
    if !erroring && !matches!(verb,'T'|'p') && let Value::Object(object)=arg && let Some(formatter)=object.formatter {
        let _host_guard=out.host(arg)?;let formatted=formatter(object,verb,&spec)?;
        let bytes=formatted.as_go_bytes().ok_or_else(||TemplateError::Exec("host formatter must return string".into()))?;
        crate::go_write::GoWrite::write_bytes(out,bytes)?;return out.check();
    }
    if !erroring && (matches!(verb,'s'|'q'|'x'|'X')||(verb=='v'&&!spec.hash)) && let Value::Object(object)=arg && let Some(stringer)=object.dynamic_stringer {
        let _guard=out.host(arg)?;let text=stringer(object)?;
        let bytes=text.as_go_bytes().ok_or_else(||TemplateError::Exec("host Stringer must return a Go string".into()))?;
        let start=out.len();let mut unpadded=spec;unpadded.width=None;
        format_bytes_value(out,bytes,if verb=='v'{'s'}else{verb},&unpadded)?;
        pad_error_text(out,start,&spec);return out.check();
    }
    if depth>0&&matches!(arg,Value::Nil|Value::NilError){out.push_str(if verb=='v'&&spec.hash&&!erroring{"interface {}(nil)"}else{"<nil>"});return out.check();}
    if !erroring && (matches!(verb,'s'|'q'|'x'|'X') || (verb=='v'&&!spec.hash)) && let Value::Slice(slice)=arg {
        let _host_guard=if slice.named_type().is_some_and(|kind|kind.stringer.is_some()){out.host(arg)?}else{None};
        if let Some(display)=slice.string_value()? { return format_value_inner(out,&display,verb,spec,depth+1,erroring); }
    }
    if verb!='T'{
        #[cfg(feature="std")] if let Value::GenericMap(map)=arg{
            let sharp=verb=='v'&&spec.hash&&!erroring;
            if sharp{out.push_str("map[interface {}]interface {}{");}else{out.push_str("map[");}
            for(index,(key,value))in map.snapshot()?.iter().enumerate(){out.check()?;if index>0{out.push_str(if sharp{", "}else{" "});}format_value_inner(out,key,verb,spec,depth+1,erroring)?;out.push(':');format_value_inner(out,value,verb,spec,depth+1,erroring)?;}
            out.push(if sharp{'}'}else{']'});return out.check();
        }
        let _map_host=if matches!(arg,Value::Object(o)if o.map_view.is_some()){out.host(arg)?}else{None};
        if let Some(map)=arg.map_snapshot()?{
            let sharp=verb=='v'&&spec.hash&&!erroring;
            if sharp{out.push_str(arg.type_name());out.push('{');}else{out.push_str("map[");}
            for(index,(key,value))in map.iter().enumerate(){
                out.check()?;if index>0{out.push_str(if sharp{", "}else{" "});}
                format_value_inner(out,&key.to_value(),verb,spec,depth+1,erroring)?;out.push(':');format_value_inner(out,value,verb,spec,depth+1,erroring)?;
            }out.push(if sharp{'}'}else{']'});return out.check();
        }
        if let Some(values)=arg.as_sequence(){
            if matches!(verb,'s'|'q'|'x'|'X'){if let Some(bytes)=values.visible_bytes(){return format_bytes_value(out,&bytes,verb,&spec);}}
            let sharp=verb=='v'&&spec.hash&&!erroring;
            // fmt's direct []byte type switch uses the alias spelling, while
            // nested reflection and %T retain []uint8 (Go fmt.printArg).
            let sequence_type=if depth==0&&matches!(arg,Value::Slice(slice)if slice.named_type().is_none()&&matches!(slice.go_type(),"[]uint8"|"[]byte")){"[]byte"}else{values.go_type()};
            if sharp && values.is_nil(){out.push_str(sequence_type);out.push_str("(nil)");return out.check();}
            if sharp{out.push_str(sequence_type);out.push('{');}else{out.push('[');}
            for(index,value)in values.iter().enumerate(){out.check()?;if index>0{out.push_str(if sharp{", "}else{" "});}format_value_inner(out,&value,verb,spec,depth+1,erroring)?;}
            out.push(if sharp{'}'}else{']'});return out.check();
        }
        if verb=='v'&&spec.hash&&!erroring{if let Some(bytes)=arg.as_go_bytes(){let start=out.len();quote_bytes(out,bytes,false);spec.pad_in_place(out,start,false);return out.check();}}
    }
        let _named_host=if (matches!(verb,'s'|'q'|'x'|'X')||(verb=='v'&&!spec.hash))&&matches!(arg,Value::NamedInt64(_,kind)if kind.stringer.is_some()){out.host(arg)?}else{None};
        let displayed=match arg {
            Value::NamedInt64(n,kind)if !erroring&&kind.stringer.is_some()&&(matches!(verb,'s'|'q'|'x'|'X')||(verb=='v'&&!spec.hash))=>kind.stringer.map(|stringer|Value::String(stringer(*n).into())),
            Value::NamedInt64(n,kind)if kind.kind.starts_with("uint")&&matches!(verb,'v'|'b'|'c'|'d'|'o'|'O'|'q'|'x'|'X'|'U')=>Some(Value::Uint(*n as u64)),
            Value::NamedInt64(n,kind)if verb=='v'&&spec.hash=>Some(if matches!(kind.kind,"uint"|"uint8"|"uint16"|"uint32"|"uint64"|"uintptr"){Value::Uint(*n as u64)}else{Value::Int64(*n)}),
            Value::Object(object) if !erroring&&(matches!(verb,'s'|'q'|'x'|'X')||(verb=='v'&&!spec.hash))=>object.display.as_ref().map(|text|Value::String(text.clone())),
            Value::NamedInt64(n,kind)if erroring=>Some(if kind.kind.starts_with("uint"){Value::Uint(*n as u64)}else{Value::Int64(*n)}),
            _=>None,
        };
        let arg=displayed.as_ref().unwrap_or(arg);
        if verb=='v'&&spec.hash{if let Some(number)=match arg{Value::Uint(n)=>Some(*n),Value::Uint8(n)=>Some(u64::from(*n)),Value::Uint16(n)=>Some(u64::from(*n)),Value::Uint32(n)=>Some(u64::from(*n)),_=>None}{let start=out.len();format_uint_base_into(out,number,'x',&spec);spec.pad_in_place(out,start,false);return out.check();}}
        if let Value::Float(value)=arg{
            if verb=='v'{spec.plus=false;spec.hash=false;}
            if !value.is_finite()&&matches!(verb,'g'|'G'|'v'|'e'|'E'|'f'|'F'){
                write_float_binary_hex(out,*value,verb,&spec);return out.check();
            }
        }
        // Struct formatting is not Sprint: %+v includes field names and %#v
        // includes the Go type. Preserve actual field order and recurse with
        // the current flags instead of discarding them in the plain printer.
        if verb=='v' && let Value::Object(object)=arg {
            let _nil_guard=if object.nil_pointer.is_some(){out.host(arg)?}else{None};
            if object.is_nil_pointer(){
                if spec.hash && let Some(ty)=object.go_type {let _=write!(out,"({ty})(nil)");}
                else{out.push_str("<nil>");}
                return out.check();
            }
            let pointer=object.go_type.is_some_and(|ty|ty.starts_with('*'));
            if pointer && depth>0 {
                    let address=object.pointer_identity.unwrap_or(object.as_ref() as *const crate::Object as usize);
                    if spec.hash {let _=write!(out,"({})(0x{address:x})",object.go_type.unwrap());}
                    else{let _=write!(out,"0x{address:x}");}
                    return out.check();
            }
            if let Some(fields)=&object.field_order {
                if pointer{out.push('&');}
                if spec.hash&&!erroring{out.push_str(object.go_type.ok_or_else(||TemplateError::Exec("host struct has no Go type".into()))?.trim_start_matches('*'));}
                out.push('{');
                for(index,name)in fields.iter().enumerate(){
                    out.check()?;
                    if index>0{out.push_str(if spec.hash&&!erroring{", "}else{" "});}
                    if !erroring&&(spec.plus||spec.hash){out.push_str(name);out.push(':');}
                    let _field_host=if object.dynamic_fields.is_some(){out.host(arg)?}else{None};let value=object.field_value(name)?.ok_or_else(||TemplateError::Exec("host struct field unavailable".into()))?;
                    format_value_inner(out,&value,verb,spec,depth+1,erroring)?;
                }
                out.push('}');return out.check();
            }
            if erroring{return Err(TemplateError::Exec("host underlying representation unavailable for invalid %p".into()));}
        }
        if matches!(verb,'s'|'q'|'x'|'X'){if let Some(bytes)=arg.as_go_bytes(){return format_bytes_value(out,bytes,verb,&spec);}}
        let start = out.len();
        match verb {
            'T' => out.push_str(match arg {Value::Nil|Value::NilError=>"<nil>",Value::List(_)=>"[]interface {}",Value::Map(_)=>"map[string]interface {}",#[cfg(feature="std")]Value::SharedMap(_)=>"map[string]interface {}",#[cfg(feature="std")]Value::GenericMap(_)=>"map[interface {}]interface {}",value=>value.type_name()}),
            's' => {
                if let Some(bytes)=arg.as_go_bytes(){out.push_bytes(truncate_runes(bytes,spec.precision));spec.pad_in_place(out,start,false);}
                else{write_bad_verb(out,verb,arg)?;}
            },
            'd' => match arg {
                // Match Uint before the as_int() path: a u64 above i64::MAX
                // must print its true magnitude, not the wrapped signed value.
                Value::Uint(u) => {
                    spec.write_unsigned(out, *u);
                    spec.pad_in_place(out, start, true);
                }
                _ => match arg.as_go_integer().and_then(|n|i64::try_from(n).ok()) {
                    Some(n) => {
                        spec.write_signed(out, n);
                        spec.pad_in_place(out, start, true);
                    }
                    None => write_bad_verb(out, verb, arg)?,
                },
            },
            'f' | 'F' => match match arg { Value::Float(f)=>Some(*f),_=>None } {
                Some(f) => {
                    let prec = spec.precision.unwrap_or(6);
                    if !f.is_sign_negative() && !f.is_nan() {
                        if spec.plus {
                            out.push('+');
                        } else if spec.space {
                            out.push(' ');
                        }
                    }
                    let base=prec.min(1074);let _=write!(out,"{:.base$}",f);out.repeat_ascii(out.len(),b'0',prec.saturating_sub(base));
                    if spec.hash&&prec==0{out.push('.');}
                    spec.pad_in_place(out, start, true);
                }
                None => write_bad_verb(out, verb, arg)?,
            },
            'e' | 'E' => match match arg { Value::Float(f)=>Some(*f),_=>None } {
                Some(f) => {
                    let prec = spec.precision.unwrap_or(6);
                    let base=prec.min(1074);let mut raw=out.temporary(32);if verb=='e'{let _=write!(raw,"{:.base$e}",f);}else{let _=write!(raw,"{:.base$E}",f);}
                    if spec.hash&&prec==0{if let Some(exponent)=raw.as_bytes().iter().position(|b|matches!(*b,b'e'|b'E')){raw.insert(exponent,'.');}}
                    out.fail_scratch(&*raw);if let Ok(text)=core::str::from_utf8(raw.as_bytes()){write_normalized_sci(out,text,verb=='E',false);}else{out.reject_size();}
                    if prec>base{let exponent=out.as_bytes()[start..].iter().position(|byte|matches!(*byte,b'e'|b'E')).map_or(out.len(),|index|start+index);out.repeat_ascii(exponent,b'0',prec-base);}
                    apply_float_sign_in_place(out, start, f, &spec);
                    spec.pad_in_place(out, start, true);
                }
                None => write_bad_verb(out, verb, arg)?,
            },
            'g' | 'G' => match match arg { Value::Float(f)=>Some(*f),_=>None } {
                Some(f) => {
                    if spec.hash {
                        let precision=spec.precision.unwrap_or(6).max(1);
                        if spec.precision.is_some(){write_g_with_precision(out,f,precision,verb=='G');}else{write_g_default(out,f,verb=='G');}
                        retain_g_zeros(out,start,precision);
                    } else if let Some(prec) = spec.precision {
                        write_g_with_precision(out, f, prec.max(1), verb == 'G');
                    } else {
                        write_g_default(out, f, verb == 'G');
                    };
                    apply_float_sign_in_place(out, start, f, &spec);
                    spec.pad_in_place(out, start, true);
                }
                None => write_bad_verb(out, verb, arg)?,
            },
            'v' => {
                if let Value::Float(value)=arg{write_g_default(out,*value,false);apply_float_sign_in_place(out,start,*value,&spec);spec.pad_in_place(out,start,true);}
                else{crate::go_write::write_value(out,arg,0)?;spec.pad_in_place(out, start, false);}
            }
            'U' => {
                // Go casts the int to uint64 and prints as hex with min 4 digits,
                // so negative ints wrap (`-1` → `U+FFFFFFFFFFFFFFFF`) and values
                // outside the Unicode range still format as bare hex. A Uint is
                // used as-is. (`as_int() as u64` would round-trip but also accept
                // floats, which Go rejects — so match the integer kinds directly.)
                let code = match arg {
                    Value::Int(n) | Value::Int64(n) | Value::NamedInt64(n,_) => Some(*n as u64),
                    Value::Uint(n) => Some(*n),
                    Value::Uint32(n) => Some(u64::from(*n)),
                    Value::Uint8(n) => Some(u64::from(*n)),Value::Uint16(n) => Some(u64::from(*n)),
                    _ => None,
                };
                match code {
                    Some(u) => {
                        let _ = write!(out, "U+{:04X}", u);
                        if spec.hash {
                            // Only quote when the value is a valid, non-control rune.
                            // Surrogates, > U+10FFFF, and control chars get no quote —
                            // matching Go's `strconv.IsPrint` gate (close enough for
                            // ASCII; full Unicode-graphic parity would need a table).
                            if let Some(c) = u32::try_from(u)
                                .ok()
                                .and_then(char::from_u32)
                                .filter(|c| !c.is_control())
                            {
                                let _ = write!(out, " '{}'", c);
                            }
                        }
                        spec.pad_in_place(out, start, false);
                    }
                    None => write_bad_verb(out, verb, arg)?,
                }
            }
            'q' => match arg {
                value if value.as_go_bytes().is_some() => {
                    let bytes=truncate_runes(value.as_go_bytes().unwrap_or_default(),spec.precision);
                    if !(spec.hash&&core::str::from_utf8(bytes).is_ok_and(|s|try_backquote_into(out,s))){quote_bytes(out,bytes,spec.plus);}
                    spec.pad_in_place(out,start,false);
                }
                // Go's %q on an integer emits a single-quoted rune literal,
                // signed and unsigned alike. Either fits a rune only if it
                // round-trips through u32.
                Value::Int(_) | Value::Int64(_) | Value::NamedInt64(_,_) | Value::Uint(_) | Value::Uint32(_) | Value::Uint8(_) | Value::Uint16(_) => {
                    let rune=arg.as_go_integer().and_then(|n|u32::try_from(n).ok()).and_then(char::from_u32).unwrap_or('\u{fffd}');
                    let mut buffer=[0u8;4];quote_with_delimiter(out,rune.encode_utf8(&mut buffer).as_bytes(),spec.plus,'\'');spec.pad_in_place(out,start,false);
                }
                _ => write_bad_verb(out, verb, arg)?,
            },
            't' => match arg {
                Value::Bool(b) => {
                    out.push_str(if *b { "true" } else { "false" });
                    spec.pad_in_place(out, start, false);
                }
                _ => write_bad_verb(out, verb, arg)?,
            },
            'x' | 'X' | 'o' | 'O' | 'b' => match arg {
                Value::Float(value)if !matches!(verb,'o'|'O')=>write_float_binary_hex(out,*value,verb,&spec),
                value if value.as_go_bytes().is_some()&&(verb=='x'||verb=='X') => {
                    format_string_hex_into(out,value.as_go_bytes().unwrap_or_default(),verb=='X',&spec);
                    spec.pad_in_place(out, start, false);
                }
                // Unsigned magnitude: route around as_int() (which would wrap a
                // u64 above i64::MAX to a negative i64 and emit a spurious `-`).
                Value::Uint(u) => {
                    format_uint_base_into(out, *u, verb, &spec);
                    spec.pad_in_place(out, start, false);
                }
                _ => match arg.as_go_integer().and_then(|n|i64::try_from(n).ok()) {
                    Some(n) => {
                        format_int_base_into(out, n, verb, &spec);
                        // Zero-padding is already baked into the digit string
                        // (Go's scheme: pad digits, then prepend prefix), so
                        // only space-pad the overall field here.
                        spec.pad_in_place(out, start, false);
                    }
                    None => write_bad_verb(out, verb, arg)?,
                },
            },
            'c' => match arg.as_go_integer() {
                Some(n) => {match u32::try_from(n).ok().and_then(char::from_u32) {
                    Some(c) => out.push(c),
                    None => out.push('\u{FFFD}'),
                }if spec.zero&&!spec.left_align{if let Some(width)=spec.width{insert_repeated(out,start,'0',width.saturating_sub(1));}}else{spec.pad_in_place(out,start,false);}},
                None => write_bad_verb(out, verb, arg)?,
            },
            _ => write_bad_verb(out, verb, arg)?,
        }
    out.check()
}

/// Prepend a `+` or space sign to a formatted float at `out[start..]`
/// when the sign flag demands it and the number isn't already negative.
fn format_bytes_value(out:&mut dyn FormatBuffer,bytes:&[u8],verb:char,spec:&FmtSpec)->Result<()>{
    let start=out.len();match verb{
        's'=>out.push_bytes(truncate_runes(bytes,spec.precision)),
        'q'=>{let bytes=truncate_runes(bytes,spec.precision);if !(spec.hash&&core::str::from_utf8(bytes).is_ok_and(|s|try_backquote_into(out,s))){quote_bytes(out,bytes,spec.plus);}},
        'x'|'X'=>format_string_hex_into(out,bytes,verb=='X',spec),_=>return Err(TemplateError::Exec("invalid internal bytes format".into())),
    }spec.pad_in_place(out,start,false);out.check()
}

fn apply_float_sign_in_place(out: &mut dyn FormatBuffer, start: usize, f: f64, spec: &FmtSpec) {
    // `f >= 0.0` is false for NaN, matching the semantics of the previous
    // allocating `apply_float_sign` helper (NaN never gets a synthesized sign).
    if f < 0.0 || f.is_nan() {
        return;
    }
    if matches!(out.as_bytes().get(start), Some(&b'-')) {
        return;
    }
    if spec.plus {
        out.insert(start, '+');
    } else if spec.space {
        out.insert(start, ' ');
    }
}


fn pad_error_text(out:&mut dyn FormatBuffer,start:usize,spec:&FmtSpec){
    if let Some(width)=spec.width {
        let count=width.saturating_sub(crate::go_runes(&out.as_bytes()[start..]).count());
        out.repeat_ascii(if spec.left_align{out.len()}else{start},if spec.zero&&!spec.left_align{b'0'}else{b' '},count);
    }
}

// %p and %T precede method dispatch in Go. A pointer is the actual pointee,
// maps use their stable cell identity, and slices use the visible backing.
fn format_pointer(out:&mut dyn FormatBuffer,arg:&Value,mut spec:FmtSpec,depth:usize)->Result<()> {
    let address=match arg {
        Value::Map(map)=>Some(Arc::as_ptr(map) as usize),
        #[cfg(feature="std")]
        Value::SharedMap(map)=>Some(if map.is_nil(){0}else{Arc::as_ptr(map) as usize}),
        #[cfg(feature="std")]
        Value::GenericMap(map)=>Some(Arc::as_ptr(map) as usize),
        Value::List(values)=>Some(values.as_ptr() as usize),
        Value::Slice(slice)=>Some(slice.data_address()?),
        Value::Object(object) if object.map_view.is_some()=>{
            let _guard=out.host(arg)?;
            let view=object.map_view.as_ref().unwrap();
            Some(if (view.is_nil)(){0}else{object.pointer_identity.unwrap_or_else(||object.data.as_ref().map_or(Arc::as_ptr(object) as usize,|data|Arc::as_ptr(data) as *const () as usize))})
        }
        Value::Object(object) if object.go_type.is_some_and(|ty|ty.starts_with('*'))=>{
            let _guard=if object.nil_pointer.is_some(){out.host(arg)?}else{None};
            Some(if object.is_nil_pointer(){0}else{object.pointer_identity.unwrap_or(Arc::as_ptr(object) as usize)})
        }
        // Rust's dyn Fn data pointer is not a function code pointer. The host
        // Value API has no code-address descriptor, so do not invent one.
        Value::Function(_)=>return Err(TemplateError::Exec("Go function code pointer unavailable for native closure".into())),
        _=>None,
    };
    if let Some(address)=address {
        let start=out.len();spec.hash=!spec.hash;
        format_uint_base_into(out,address as u64,'x',&spec);
        spec.pad_in_place(out,start,false);
    }else{
        out.push_str("%!p(");
        if matches!(arg,Value::Nil|Value::NilError){out.push_str("<nil>");}
        else{out.push_str(arg.type_name());out.push('=');format_value_inner(out,arg,'v',spec,depth+1,true)?;}
        out.push(')');
    }
    out.check()
}

/// Emit Go's `%!verb(type=value)` marker for a type-mismatched or unknown verb.
///
/// Nil is a special case: Go emits `%!verb(<nil>)` without the `nil=` prefix.
fn write_bad_verb(out: &mut dyn FormatBuffer, verb: char, arg: &Value)->Result<()> {
    out.push_str("%!");
    out.push(verb);
    out.push('(');
    write_bad_arg(out, arg,true)?;
    out.push(')');
    out.check()
}

/// Emit the `type=value` (or bare `<nil>`) form used inside `%!verb(...)`
/// and `%!(EXTRA …)` markers.
fn write_bad_arg(out: &mut dyn FormatBuffer, arg: &Value,erroring:bool)->Result<()> {
    if matches!(arg, Value::Nil) {
        out.push_str("<nil>");
        return Ok(());
    }
    out.push_str(arg.type_name());out.push('=');
    match arg {
        value if value.as_go_bytes().is_some()=>out.push_bytes(value.as_go_bytes().unwrap_or_default()),
        Value::Object(object)if erroring&&object.dynamic_stringer.is_some()=>{format_value_inner(out,arg,'v',FmtSpec::default(),0,true)?;}
        other=>{crate::go_write::write_value(out,other,0)?;}
    }
    out.check()
}

/// `%x` / `%X` on strings: hex-encode each byte into `out`.
///
/// Go's precision on `%.Nx` for strings limits the number of *input bytes*
/// consumed, yielding `2 * N` hex characters, not `N`.
fn format_string_hex_into(out: &mut dyn FormatBuffer, bytes: &[u8], upper: bool, spec: &FmtSpec) {
    let take = spec
        .precision
        .map(|p| p.min(bytes.len()))
        .unwrap_or(bytes.len());
    for(index,b)in bytes[..take].iter().enumerate(){
        if index>0&&spec.space{out.push(' ');}
        if spec.hash&&(index==0||spec.space){out.push_str(if upper{"0X"}else{"0x"});}
        let _=if upper{write!(out,"{:02X}",b)}else{write!(out,"{:02x}",b)};
    }
}

// Quoting
/// Write a Go-syntax double-quoted string literal (like `strconv.Quote`) into `out`.
///
/// Escapes backslash, double-quote, newline, tab, carriage-return, bell,
/// backspace, form-feed, vertical-tab, and all control characters.
/// Try to write a Go-syntax backtick-quoted string (for `%#q`) into `out`.
///
/// Returns `false` if the string contains backticks or non-printable
/// characters; in that case `out` is left unchanged and the caller should
/// fall back to [`go_quote_into`].
fn try_backquote_into(out: &mut dyn FormatBuffer, s: &str) -> bool {
    if s.contains('`') {
        return false;
    }
    for ch in s.chars() {
        // Mirrors Go's strconv.CanBackquote: reject ASCII control chars
        // (U+0000..U+001F plus DEL) except tab, which is allowed inside
        // backticks. Non-ASCII chars pass through — Rust's &str already
        // guarantees valid UTF-8, which is the other half of Go's rule.
        if ch=='\u{feff}'||(ch != '\t' && (ch < ' ' || ch == '\x7F')) {
            return false;
        }
    }
    out.reserve(s.len() + 2);
    out.push('`');
    out.push_str(s);
    out.push('`');
    true
}

// Scientific notation normalization
/// Write Rust's scientific notation `raw` into `out` in Go's format.
///
/// Go's format requires:
/// - Explicit `+` sign on positive exponents.
/// - At least 2-digit exponent (`e+02`, not `e+2`).
/// - The exponent character is taken from `upper` (`'E'` if true, else `'e'`),
///   regardless of which case `raw` happens to contain. Callers that already
///   produced uppercase `raw` (e.g. `format!("{:E}", f)`) must pass
///   `upper = true` to preserve case.
/// - When `strip_zeros` is set, trailing zeros (and a dangling `.`) are
///   removed from the mantissa before emission.
///
/// Writes directly into `out`: no intermediate `String` allocation, in
/// contrast to the previous `go_normalize_sci` + `replace` + `strip` chain.
fn write_normalized_sci(out: &mut dyn FormatBuffer, raw: &str, upper: bool, strip_zeros: bool) {
    let e_pos = raw.bytes().position(|b| b == b'e' || b == b'E');
    let Some(e_pos) = e_pos else {
        // No exponent: emit the mantissa-only form, optionally stripped.
        out.push_str(if strip_zeros {
            trim_trailing_zeros_view(raw)
        } else {
            raw
        });
        return;
    };
    let mut mantissa = &raw[..e_pos];
    if strip_zeros && mantissa.contains('.') {
        mantissa = mantissa.trim_end_matches('0').trim_end_matches('.');
    }
    out.push_str(mantissa);
    out.push(if upper { 'E' } else { 'e' });

    let exp_str = &raw[e_pos + 1..];
    let (sign, digits) = if let Some(d) = exp_str.strip_prefix('-') {
        ('-', d)
    } else if let Some(d) = exp_str.strip_prefix('+') {
        ('+', d)
    } else {
        ('+', exp_str)
    };
    out.push(sign);
    if digits.len() < 2 {
        out.push('0');
    }
    out.push_str(digits);
}

/// Borrowing view of `s` with trailing zeros (and a dangling `.`) stripped.
/// Zero-allocation alternative to the old `strip_trailing_zeros` String
/// helper.
fn trim_trailing_zeros_view(s: &str) -> &str {
    if !s.contains('.') {
        return s;
    }
    s.trim_end_matches('0').trim_end_matches('.')
}

// %g formatting
/// Decimal exponent of `f` as reported by its shortest scientific form.
///
/// Avoids the `log10().floor()` round-off that misclassifies values right at
/// a power-of-ten boundary (e.g. `999999.999…` rounding up to `1e6`).
fn decimal_exp(out:&mut dyn FormatBuffer,f:f64)->i32{
    let mut raw=out.temporary(32);let _=write!(raw,"{:e}",f.abs());out.fail_scratch(&*raw);
    let Ok(text)=core::str::from_utf8(raw.as_bytes())else{out.reject_size();return 0;};
    text.find('e').and_then(|i|text[i+1..].parse::<i32>().ok()).unwrap_or(0)
}

/// Conversion used by the pinned Go amd64 reference for runtime float-to-int64.
/// Go leaves out-of-range conversions implementation dependent; preserve this
/// reference explicitly instead of Rust's saturating cast.
pub fn float_to_go_i64(value:f64)->i64{
    if !value.is_finite()||!(-9223372036854775808.0..9223372036854775808.0).contains(&value){i64::MIN}else{value as i64}
}

/// Go fmt.Sprintf("%g", value): shortest digits and Go exponent/special spellings.
/// The result needs at most 24 bytes for any binary64 value.
pub fn format_float_shortest(value:f64)->String{
    let mut output=ByteBuffer::with_capacity(24);
    if value.is_nan(){output.push_str("NaN");}
    else if value.is_infinite(){output.push_str(if value.is_sign_negative(){"-Inf"}else{"+Inf"});}
    else{write_g_default(&mut output,value,false);}
    let bytes=output.into_vec();debug_assert!(bytes.is_ascii());bytes.into_iter().map(char::from).collect()
}

/// Go shortest g/G notation uses an exponent below -4 or at least 6.
fn write_g_default(out: &mut dyn FormatBuffer, f: f64, upper: bool) {
    if f == 0.0 {
        out.push_str(if f.is_sign_negative() { "-0" } else { "0" });
        return;
    }
    let exp = decimal_exp(out,f);
    if !(-4..6).contains(&exp) {
        let mut raw=out.temporary(32);let _=write!(raw,"{:e}",f);out.fail_scratch(&*raw);
        if let Ok(text)=core::str::from_utf8(raw.as_bytes()){write_normalized_sci(out,text,upper,false);}else{out.reject_size();}
    } else {
        let _ = write!(out, "{}", f);
    }
}

/// Write a float into `out` using Go's `%g` with an explicit precision
/// (significant digits). Uses `%e` notation when the exponent is < −4 or
/// ≥ `prec`, then strips trailing zeros.
fn write_g_with_precision(out: &mut dyn FormatBuffer, f: f64, prec: usize, upper: bool) {
    let prec=prec.min(1074);
    if f == 0.0 {
        out.push_str(if f.is_sign_negative() { "-0" } else { "0" });
        return;
    }
    let exp = decimal_exp(out,f);
    if exp < -4 || exp >= prec as i32 {
        let e_prec = prec.saturating_sub(1);
        let mut raw=out.temporary(32);let _=write!(raw,"{:.prec$e}",f,prec=e_prec);out.fail_scratch(&*raw);
        if let Ok(text)=core::str::from_utf8(raw.as_bytes()){write_normalized_sci(out,text,upper,true);}else{out.reject_size();}
    } else {
        let f_prec = if prec as i32 > exp + 1 {
            (prec as i32 - exp - 1) as usize
        } else {
            0
        };
        let mut raw=out.temporary(32);let _=write!(raw,"{:.prec$}",f,prec=f_prec);out.fail_scratch(&*raw);
        if let Ok(text)=core::str::from_utf8(raw.as_bytes()){out.push_str(trim_trailing_zeros_view(text));}else{out.reject_size();}
    }
}

// The sharp g/G form retains precision significant digits and a decimal point.
fn retain_g_zeros(out:&mut dyn FormatBuffer,start:usize,precision:usize){
    let end=out.as_bytes()[start..].iter().copied().position(|byte|matches!(byte,b'e'|b'E')).map_or(out.len(),|offset|start+offset);
    let mut significant=0usize;let mut nonzero=false;
    for byte in out.as_bytes()[start..end].iter().copied(){if byte.is_ascii_digit(){if byte!=b'0'{nonzero=true;}if nonzero{significant+=1;}}}
    if significant==0{significant=1;}
    let mut insertion=end;
    if !out.as_bytes()[start..end].contains(&b'.') {out.insert(insertion,'.');insertion+=1;}
    insert_repeated(out,insertion,'0',precision.saturating_sub(significant));
}

// Integer base formatting
/// Write a signed integer in a non-decimal base into `out`, using Go's
/// conventions (sign separate from magnitude; `#` inserts `0x`/`0X`/`0b`/`0`).
///
/// Zero-padding is applied to the digits themselves — matching Go, whose
/// integer formatter builds the digit string, pads it up to
/// `width − sign_len`, then prepends the `#` prefix. As a result `%#08x` of
/// 255 yields `0x000000ff` (the `0x` sits outside the padded digit count),
/// and `%#08o` of 255 yields `00000377` (Go's formatter omits the bare-`0`
/// octal prefix when the padded digits already start with `0`).
fn format_int_base_into(out: &mut dyn FormatBuffer, n: i64, base: char, spec: &FmtSpec) {
    let sign = if n < 0 {
        Some('-')
    } else if spec.plus {
        Some('+')
    } else if spec.space {
        Some(' ')
    } else {
        None
    };
    format_magnitude_base_into(out, n.unsigned_abs(), sign, base, spec);
}

/// Write an unsigned integer (a [`Value::Uint`]) in a non-decimal base into
/// `out`.
///
/// Identical to [`format_int_base_into`] except the value has no inherent
/// sign: only the `+` / space flags can introduce a leading sign character,
/// never `-`. Go applies the `+` / space flags to unsigned values too.
fn format_uint_base_into(out: &mut dyn FormatBuffer, u: u64, base: char, spec: &FmtSpec) {
    let sign = if spec.plus {
        Some('+')
    } else if spec.space {
        Some(' ')
    } else {
        None
    };
    format_magnitude_base_into(out, u, sign, base, spec);
}

/// Shared core for the signed and unsigned base formatters: writes `mag`'s
/// digits in `base` with `sign` prepended, applying Go's zero-pad / precision /
/// `#`-prefix rules described on [`format_int_base_into`].
fn format_magnitude_base_into(out:&mut dyn FormatBuffer,mag:u64,sign:Option<char>,base:char,spec:&FmtSpec){
    let mut digits=out.temporary(64);
    let _=match base{'x'=>write!(digits,"{:x}",mag),'X'=>write!(digits,"{:X}",mag),'o'|'O'=>write!(digits,"{:o}",mag),'b'=>write!(digits,"{:b}",mag),'d'=>write!(digits,"{}",mag),_=>return};
    out.fail_scratch(&*digits);if mag==0&&spec.precision==Some(0){return;}
    let target=match spec.precision{Some(p)=>p,None if spec.zero&&!spec.left_align=>spec.width.map(|w|w.saturating_sub(usize::from(sign.is_some()))).unwrap_or(0),None=>0};
    if target>(1<<20){out.reject_size();return;}let padding=target.saturating_sub(digits.len());
    if let Some(sign)=sign{out.push(sign);}if base=='O'{out.push_str("0o");}
    if spec.hash{match base{'x'=>out.push_str("0x"),'X'=>out.push_str("0X"),'b'=>out.push_str("0b"),'o'|'O'=>{if padding==0&&!digits.as_bytes().starts_with(b"0"){out.push('0');}},_=>{}}}
    out.repeat_ascii(out.len(),b'0',padding);out.push_bytes(digits.as_bytes());
}

// Escaping functions
/// HTML-escape a string, replacing `&`, `<`, `>`, `"`, `'`, and NUL bytes.
///
/// Matches Go's `template.HTMLEscapeString`. NUL bytes are replaced with the
/// Unicode replacement character (U+FFFD). Quotes use numeric entities
/// (`&#34;`, `&#39;`) for brevity, matching Go's choice.
pub fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\0' => out.push('\u{FFFD}'), // Go replaces NUL with Unicode replacement char
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&#34;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

/// JavaScript-escape a string for safe embedding in JS string literals.
///
/// Matches Go's `template.JSEscapeString`. Escapes backslash, quotes,
/// angle brackets (`<`, `>`), ampersand, equals sign, all control
/// characters below U+0020, and the JSON-in-HTML-hostile line/paragraph
/// separators U+2028 / U+2029 — all as `\uXXXX`.
pub fn js_escape(s: &str) -> String {
    let mut out = String::new();
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\'' => out.push_str("\\'"),
            // Go's JSEscape uses \uXXXX (uppercase hex) for all control
            // characters, including \t, \n, \r (no shorthand escapes).
            '<' => out.push_str("\\u003C"),
            '>' => out.push_str("\\u003E"),
            '&' => out.push_str("\\u0026"),
            '=' => out.push_str("\\u003D"),
            // U+2028 LINE SEPARATOR / U+2029 PARAGRAPH SEPARATOR — valid
            // in JSON but illegal mid-string in JavaScript pre-ES2019.
            // Go escapes both to keep `<script>` payloads safe.
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            _ if (ch as u32) < 0x20 => {
                write!(out, "\\u{:04X}", ch as u32).ok();
            }
            _ => out.push(ch),
        }
    }
    out
}

/// Percent-encode a string for use in URL query parameters (form-encoding).
///
/// Matches Go's `template.URLQueryEscaper` / `url.QueryEscape`: unreserved
/// characters (`A-Z`, `a-z`, `0-9`, `-`, `_`, `.`, `~`) pass through, space
/// becomes `+`, and everything else is `%XX`-encoded.
pub fn url_encode(s: &str) -> String {
    let mut out = String::new();
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            b' ' => out.push('+'),
            _ => {
                write!(out, "%{:02X}", byte).ok();
            }
        }
    }
    out
}

// Hex float parsing
/// Parse a hex float literal like `0x1.Fp10` or `-0x1p-2`.
///
/// Used by the lexer to convert Go's hex-float syntax into an `f64`.
pub(crate) fn parse_hex_float(s: &str) -> Option<f64> {
    let negative = s.starts_with('-');
    let s = s.trim_start_matches('+').trim_start_matches('-');
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X"))?;

    let (mantissa_str, exp_str) = if let Some(p) = s.find(['p', 'P']) {
        (&s[..p], &s[p + 1..])
    } else {
        (s, "0")
    };

    let mantissa = if let Some(dot) = mantissa_str.find('.') {
        let int_part = &mantissa_str[..dot];
        let frac_part = &mantissa_str[dot + 1..];
        let int_val = if int_part.is_empty() {
            0u64
        } else {
            u64::from_str_radix(int_part, 16).ok()?
        };
        let frac_val = if frac_part.is_empty() {
            0u64
        } else {
            u64::from_str_radix(frac_part, 16).ok()?
        };
        let frac_bits = frac_part.len() as i32 * 4;
        int_val as f64 + frac_val as f64 / (2f64).powi(frac_bits)
    } else {
        u64::from_str_radix(mantissa_str, 16).ok()? as f64
    };

    let exp: i32 = exp_str.parse().ok()?;
    let result = mantissa * (2.0_f64).powi(exp);
    Some(if negative { -result } else { result })
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

// Derived from Go internal/strconv fmtB/fmtX (BSD-3-Clause, Go Authors).
fn write_float_binary_hex(out:&mut dyn FormatBuffer,value:f64,verb:char,spec:&FmtSpec){
    let start=out.len();
    if !value.is_finite(){
        if value.is_nan(){if spec.plus{out.push('+');}else if spec.space{out.push(' ');}out.push_str("NaN");}
        else{out.push_str(if value.is_sign_negative(){"-Inf"}else if spec.space&&!spec.plus{" Inf"}else{"+Inf"});}
        spec.pad_in_place(out,start,false);return;
    }
    if spec.precision.is_some_and(|precision|precision>=(1<<20)){out.reject_size();return;}
    let bits=value.to_bits();let negative=bits>>63!=0;
    let mut exponent=((bits>>52)&0x7ff)as i32;let mut mantissa=bits&((1u64<<52)-1);
    if exponent==0{exponent=1;}else{mantissa|=1<<52;}exponent-=1023;
    let mut text=out.temporary(32);text.push(if negative{'-'}else{'+'});
    if verb=='b'{let _=write!(text,"{mantissa}p{:+}",exponent-52);}
    else{
        if mantissa==0{exponent=0;}mantissa<<=8;
        while mantissa!=0&&mantissa&(1<<60)==0{mantissa<<=1;exponent-=1;}
        if let Some(precision)=spec.precision.filter(|p|*p<15){
            let shift=(precision*4)as u32;let extra=mantissa.wrapping_shl(shift)&((1<<60)-1);mantissa>>=60-shift;
            if (extra|(mantissa&1))>1<<59{mantissa+=1;}mantissa<<=60-shift;
            if mantissa&(1<<61)!=0{mantissa>>=1;exponent+=1;}
        }
        let upper=verb=='X';let hex=if upper{b"0123456789ABCDEF"}else{b"0123456789abcdef"};
        text.push('0');text.push(verb);text.push(char::from(b'0'+((mantissa>>60)&1)as u8));mantissa<<=4;
        match spec.precision{
            None if mantissa!=0=>{text.push('.');while mantissa!=0{text.push(hex[((mantissa>>60)&15)as usize]as char);mantissa<<=4;}},
            Some(precision)if precision>0=>{text.push('.');for _ in 0..precision{text.push(hex[((mantissa>>60)&15)as usize]as char);mantissa<<=4;}},_=>{},
        }
        let _=write!(text,"{}{:+03}",if upper{'P'}else{'p'},exponent);
        if spec.hash{
            let split=text.as_bytes().iter().position(|b|matches!(*b,b'p'|b'P')).unwrap_or(text.len());let mut tail=[0u8;8];let tail_len=text.len()-split;
            if tail_len>tail.len(){out.reject_size();return;}tail[..tail_len].copy_from_slice(&text.as_bytes()[split..]);text.truncate(split);let(mut point,mut nonzero)=(false,false);
            let mut digits=if verb=='x'{spec.precision.unwrap_or(6)as isize}else{0};
            for byte in text.as_bytes().iter().skip(1){if *byte==b'.'{point=true;}else{if *byte!=b'0'{nonzero=true;}if nonzero{digits-=1;}}}
            if !point{text.push('.');}while digits>0{text.push('0');digits-=1;}text.push_bytes(&tail[..tail_len]);
        }
    }
    out.fail_scratch(&*text);if text.check().is_err(){return;}
    if negative||spec.plus{out.push_bytes(text.as_bytes());}else if spec.space{out.push(' ');out.push_bytes(&text.as_bytes()[1..]);}else{out.push_bytes(&text.as_bytes()[1..]);}
    spec.pad_in_place(out,start,true);
}

fn truncate_runes(bytes:&[u8],precision:Option<usize>)->&[u8]{
    let Some(precision)=precision else{return bytes;};
    let end=crate::go_runes(bytes).take(precision).map(|(_,width)|width).sum();&bytes[..end]
}
fn quote_bytes(out:&mut dyn FormatBuffer,bytes:&[u8],ascii:bool){quote_with_delimiter(out,bytes,ascii,'"')}
fn quote_with_delimiter(out:&mut dyn FormatBuffer,bytes:&[u8],ascii:bool,delimiter:char){
    out.push(delimiter);let mut offset=0;
    for(rune,width)in crate::go_runes(bytes){
        if rune=='\u{fffd}'&&width==1{let _=write!(out,"\\x{:02x}",bytes[offset]);}
        else{match rune{
            c if c==delimiter=>{out.push('\\');out.push(c);},'\\'=>out.push_str("\\\\"),'\n'=>out.push_str("\\n"),'\r'=>out.push_str("\\r"),'\t'=>out.push_str("\\t"),'\x07'=>out.push_str("\\a"),'\x08'=>out.push_str("\\b"),'\x0b'=>out.push_str("\\v"),'\x0c'=>out.push_str("\\f"),
            c if c<' '||c=='\x7f'=>{let _=write!(out,"\\x{:02x}",c as u32);},
            c if !crate::go_print::is_print(c)||(ascii&&!c.is_ascii())=>{if(c as u32)<0x10000{let _=write!(out,"\\u{:04x}",c as u32);}else{let _=write!(out,"\\U{:08x}",c as u32);}},
            c=>out.push(c),
        }}offset+=width;
    }out.push(delimiter);
}

/// strconv.Quote / QuoteToASCII, preserving each malformed byte as a hex escape.
pub fn quote_go_string(bytes:&[u8],ascii:bool)->Result<String>{
    let mut output=ByteBuffer::with_capacity(bytes.len().saturating_add(2));quote_bytes(&mut output,bytes,ascii);output.check()?;
    String::from_utf8(output.into_vec()).map_err(|_|TemplateError::Exec("Go quoting UTF-8 invariant".into()))
}
