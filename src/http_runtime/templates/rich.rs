#[path="rich/chroma.rs"]
pub(crate) mod chroma;
#[path="rich/code_info.rs"]
pub(crate) mod code_info;
pub(crate) use code_info::CodeBlockAttrs;
#[path="rich/yaml/mod.rs"]
mod yaml;
#[path="rich/allocation.rs"]mod allocation;
#[path="rich/goldmark/mod.rs"]mod goldmark;
use super::{Fields,RenderResult,arity,error,string,text};
use gotmpl::{MapContext,Object,Value};
use std::sync::Arc;
pub(super) fn front_matter(input: &[u8], maps: &MapContext, meter:Arc<gotmpl::BudgetMeter>) -> RenderResult<Value> {
    if input.len() > 1 << 20 {
        return Err(error("front matter exceeds byte limit"));
    }
    // Replicate Go `for i, r := range s` with rune/width accumulation.
    let (mut start, mut end, mut empty) = (0usize, 0usize, true);
    let mut byteoffset = 0usize;
    for (ch, width) in gotmpl::go_runes(input) {
        if ch == '\n' {
            start = end;
            if start > 0 {
                start += 1;
            }
            end = byteoffset;
            if !empty {
                break;
            }
            byteoffset += width;
            continue;
        }
        empty = empty && ch.is_whitespace();
        byteoffset += width;
    }
    // Trim first line leading/trailing whitespace by rune, keep raw middle.
    let raw = &input[start..end];
    let (mut trim_start, mut trim_end, mut offset)=(None,0usize,0usize);
    for (ch,width) in gotmpl::go_runes(raw){if !ch.is_whitespace(){trim_start.get_or_insert(offset);trim_end=offset+width;}offset+=width;}
    let first=&raw[trim_start.unwrap_or(0)..trim_end];
    // Fence list matched against raw bytes.
    let fences: &[&[u8]] = match first {
        b"---" => &[b"---", b"..."],
        b"+++" => &[b"+++"],
        b"{" => &[b"}"],
        _ => &[],
    };
    let (meta, body): (Value, &[u8]) = if fences.is_empty() {
        (Value::Nil, input)
    } else {
        let (fence, position) = fences
            .iter()
            .find_map(|fence| {
                let mut pattern = Vec::with_capacity(1 + fence.len());
                pattern.push(b'\n');
                pattern.extend_from_slice(fence);
                memchr::memmem::find(&input[end..], &pattern).map(|i| (*fence, end + i + 1))
            })
            .ok_or_else(|| error("unterminated front matter"))?;
        let source = &input[end..position];
        let meta = match first {
            b"---" => {
                yaml::front_matter(source,maps,meter)?
            }
            b"+++" => {
                let s = std::str::from_utf8(source).map_err(|e| error(e.to_string()))?;
                toml_value(toml::from_str(s).map_err(|e| error(e.to_string()))?, maps, 0)?
            }
            _ => {
                let mut bytes = Vec::with_capacity(source.len() + 2);
                bytes.push(b'{');
                bytes.extend_from_slice(source);
                bytes.push(b'}');
                let json = crate::admin_json::decoded_go_bounded(&bytes, 32, 4 * 16384)
                    .map_err(|e| error(e.to_string()))?;
                super::sprig::json_value(&json, maps)?
            }
        };
        // Allow nil (YAML empty → Value::Nil); non-nil must be a mapping.
        if !matches!(meta, Value::Nil) && meta.as_map_view()?.is_none() {
            return Err(error("front matter requires a mapping"));
        }
        (meta, &input[position + fence.len()..])
    };
    let meta=if matches!(meta,Value::Nil){maps.nil_map()}else{meta};
    Ok(Value::Object(Arc::new(Object {
        go_type: Some("templates.parsedMarkdownDoc"),
        field_order: Some([Arc::from("Meta"), Arc::from("Body")].into()),
        json_fields: Some(
            [
                gotmpl::JsonField { source: "Meta", name: "meta", omit_empty: true },
                gotmpl::JsonField { source: "Body", name: "body", omit_empty: true },
            ]
            .into(),
        ),
        fields: Fields::from([
            ("Meta".into(), meta),
            ("Body".into(), Value::from_go_bytes(Arc::<[u8]>::from(body))),
        ]),
        ..Object::default()
    })))
}

fn toml_value(value:toml::Value,maps:&MapContext,depth:usize)->RenderResult<Value>{
    if depth>32{return Err(error("TOML front matter nesting limit exceeded"));}
    Ok(match value{
        toml::Value::String(value)=>string(value),toml::Value::Integer(value)=>Value::Int(value),toml::Value::Float(value)=>Value::Float(value),toml::Value::Boolean(value)=>Value::Bool(value),
        toml::Value::Datetime(value)=>string(value.to_string()),
        toml::Value::Array(values)=>{if values.len()>16_384{return Err(error("TOML front matter item limit exceeded"));}Value::List(values.into_iter().map(|v|toml_value(v,maps,depth+1)).collect::<RenderResult<Vec<_>>>()?.into())},
        toml::Value::Table(values)=>maps.map(values.into_iter().map(|(k,v)|Ok((k.into(),toml_value(v,maps,depth+1)?))).collect::<RenderResult<_>>()?)?,
    })
}
/// Caddy's pinned Goldmark pipeline preserves arbitrary Go string bytes.
pub(super) fn markdown(input:&[u8],meter:Arc<gotmpl::BudgetMeter>)->RenderResult<Value>{
    if input.len()>1<<20{return Err(error("markdown input exceeds byte limit"));}
    let account=gotmpl::BudgetAccount::new(meter)?;
    let output=goldmark::convert(input,&account,|info,code|{
        let parsed=code_info::parse_with_account(info,&account)?;
        let registry=chroma::prepared()?;
        match chroma::render_with_account(registry,parsed.lang.unwrap_or_default(),code,&parsed.attrs,&account)?{
            chroma::Rendered::Html(html)=>Ok(Some(html)),chroma::Rendered::Fallback=>Ok(None),
        }
    })?;
    output.into_value(1<<20)
}
pub(super) fn humanize(args:&[Value])->RenderResult<Value>{
    arity(args,2,2)?;
    let format=text(args,0)?.split(':').next().unwrap_or_default();let input=text(args,1)?;
    match format{
        "size"=>{let size=input.parse::<u64>().map_err(|_|error("humanize: size cannot be parsed"))?;let unit=["B","kB","MB","GB","TB","PB","EB"];if size<10{return Ok(string(format!("{size} B")));}let exponent=((size as f64).ln()/1000f64.ln()).floor().clamp(0.0,6.0)as usize;let mut value=size as f64/1000f64.powi(exponent as i32);let integer_digits=(value as u64).to_string().len();let mut digits=2usize.saturating_sub(integer_digits);let scale=10f64.powi(digits as i32);value=(value*scale+0.5).floor()/scale;let new_digits=(value as u64).to_string().len();digits=digits.saturating_sub(new_digits.saturating_sub(integer_digits));Ok(string(format!("{value:.digits$} {}",unit[exponent])))},
        "time"=>{let layout=text(args,0)?.split(':').nth(1).unwrap_or("Mon, 02 Jan 2006 15:04:05 -0700");Ok(string(super::sprig::dates::humanize_time(layout,input)?))},
        _=>Err(error("unsupported humanize format")),
    }
}
