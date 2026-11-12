// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0
use opentelemetry::Context;
use opentelemetry::propagation::{
    Extractor, Injector, TextMapPropagator, text_map_propagator::FieldIter,
};
use opentelemetry::trace::{SpanContext, SpanId, TraceContextExt, TraceFlags, TraceId, TraceState};

const B3_HEADER: &str = "b3";
const B3_DEBUG_FLAG_HEADER: &str = "x-b3-flags";
const B3_TRACE_ID_HEADER: &str = "x-b3-traceid";
const B3_SPAN_ID_HEADER: &str = "x-b3-spanid";
const B3_SAMPLED_HEADER: &str = "x-b3-sampled";
const B3_PARENT_SPAN_ID_HEADER: &str = "x-b3-parentspanid";
const B3_TRACE_ID_PADDING: &str = "0000000000000000";

#[derive(Debug, Clone, Copy, PartialEq)]
struct DebugFlag(bool);

#[derive(Debug, Clone, Copy, PartialEq)]
struct DeferredFlag(bool);

#[derive(Debug, Clone)]
pub struct B3Propagator {
    multi: bool,
    fields: Vec<String>,
}

impl B3Propagator {
    pub fn new(multi: bool) -> Self {
        let fields = if multi {
            vec![
                B3_TRACE_ID_HEADER.to_string(),
                B3_SPAN_ID_HEADER.to_string(),
                B3_SAMPLED_HEADER.to_string(),
                B3_DEBUG_FLAG_HEADER.to_string(),
            ]
        } else {
            vec![B3_HEADER.to_string()]
        };
        Self { multi, fields }
    }
}

impl TextMapPropagator for B3Propagator {
    fn inject_context(&self, cx: &Context, injector: &mut dyn Injector) {
        let sc = get_sc_from_context(cx);

        if self.multi {
            if sc.is_valid() {
                injector.set(B3_TRACE_ID_HEADER, sc.trace_id().to_string());
                injector.set(B3_SPAN_ID_HEADER, sc.span_id().to_string());
            }
            let debug = cx.get::<DebugFlag>().map(|v| v.0).unwrap_or(false);
            let deferred = cx.get::<DeferredFlag>().map(|v| v.0).unwrap_or(false);

            if debug {
                injector.set(B3_DEBUG_FLAG_HEADER, "1".into());
            } else if !deferred {
                let sampled = if sc.is_sampled() { "1" } else { "0" };
                injector.set(B3_SAMPLED_HEADER, sampled.into());
            }
        } else {
            let debug = cx.get::<DebugFlag>().map(|v| v.0).unwrap_or(false);
            let deferred = cx.get::<DeferredFlag>().map(|v| v.0).unwrap_or(false);

            let mut header_parts: Vec<String> = Vec::new();
            if sc.is_valid() {
                header_parts.push(sc.trace_id().to_string());
                header_parts.push(sc.span_id().to_string());
            }

            if debug {
                header_parts.push("d".to_string());
            } else if !deferred {
                let sampled = if sc.is_sampled() { "1" } else { "0" };
                header_parts.push(sampled.to_string());
            }

            injector.set(B3_HEADER, header_parts.join("-"));
        }
    }

    fn extract_with_context(&self, cx: &Context, extractor: &dyn Extractor) -> Context {
        let mut current_cx = cx.clone();

        {
            if let Some(h) = extractor.get(B3_HEADER) {
                if !h.is_empty() {
                    let (new_cx, sc, is_valid) = extract_single(&current_cx, h);
                    current_cx = new_cx;
                    if is_valid {
                        return set_sc_in_context(current_cx, sc);
                    }
                }
            }
        }

        let trace_id = extractor.get(B3_TRACE_ID_HEADER).unwrap_or("");
        let span_id = extractor.get(B3_SPAN_ID_HEADER).unwrap_or("");
        let parent_span_id = extractor.get(B3_PARENT_SPAN_ID_HEADER).unwrap_or("");
        let sampled = extractor.get(B3_SAMPLED_HEADER).unwrap_or("");
        let debug_flag = extractor.get(B3_DEBUG_FLAG_HEADER).unwrap_or("");

        let (new_cx, sc, is_valid) = extract_multiple(
            &current_cx,
            trace_id,
            span_id,
            parent_span_id,
            sampled,
            debug_flag,
        );
        current_cx = new_cx;

        if is_valid {
            set_sc_in_context(current_cx, sc)
        } else {
            // Clear deferred flag if invalid
            current_cx.with_value(DeferredFlag(false))
        }
    }

    fn fields(&self) -> FieldIter<'_> {
        FieldIter::new(&self.fields)
    }
}

fn extract_single(cx: &Context, h: &str) -> (Context, SpanContext, bool) {
    if !h.is_ascii() {
        return (cx.clone(), SpanContext::empty_context(), false);
    }
    let bytes = h.as_bytes();
    let len = bytes.len();

    let mut scc = SpanContextConfig::default();
    let mut sampling = "";

    if len == 1 {
        sampling = h;
    } else if len == 16 || len == 32 {
        return (cx.clone(), SpanContext::empty_context(), false);
    } else if len >= 16 + 16 + 1 {
        let mut pos = 0;
        let trace_id_str;

        // Check separator position
        if bytes.get(16).map(|&b| b == b'-').unwrap_or(false) {
            pos = 16;
            trace_id_str = format!("{}{}", B3_TRACE_ID_PADDING, &h[0..pos]);
        } else if bytes.get(32).map(|&b| b == b'-').unwrap_or(false) {
            pos = 32;
            trace_id_str = h[0..pos].to_string();
        } else {
            return (cx.clone(), SpanContext::empty_context(), false);
        }

        scc.trace_id = match parse_trace_id(&trace_id_str) {
            Some(id) => id,
            None => return (cx.clone(), SpanContext::empty_context(), false),
        };

        pos += 1; // Skip separator

        if len < pos + 16 {
            return (cx.clone(), SpanContext::empty_context(), false);
        }

        let span_str = &h[pos..pos + 16];
        scc.span_id = match parse_span_id(span_str) {
            Some(id) => id,
            None => return (cx.clone(), SpanContext::empty_context(), false),
        };

        pos += 16;

        if len > pos {
            if len == pos + 1 {
                return (cx.clone(), SpanContext::empty_context(), false);
            }
            pos += 1; // Skip separator

            if len == pos + 1 {
                sampling = &h[pos..pos + 1];
            } else if len == pos + 16 {
                return (cx.clone(), SpanContext::empty_context(), false);
            } else if len == pos + 1 + 1 + 16 {
                sampling = &h[pos..pos + 1];
                pos += 2;
                if parse_span_id(&h[pos..]).is_none() {
                    return (cx.clone(), SpanContext::empty_context(), false);
                }
            } else {
                return (cx.clone(), SpanContext::empty_context(), false);
            }
        }
    } else {
        return (cx.clone(), SpanContext::empty_context(), false);
    }

    let mut new_cx = cx.clone();
    match sampling {
        "" => {
            new_cx = new_cx.with_value(DeferredFlag(true));
        }
        "d" => {
            new_cx = new_cx.with_value(DebugFlag(true));
            scc.trace_flags = TraceFlags::SAMPLED;
        }
        "1" => {
            scc.trace_flags = TraceFlags::SAMPLED;
        }
        "0" => {}
        _ => return (new_cx, SpanContext::empty_context(), false),
    }

    let sc = SpanContext::new(
        scc.trace_id,
        scc.span_id,
        scc.trace_flags,
        true,
        TraceState::default(),
    );
    {
        let valid = sc.is_valid();
        (new_cx, sc, valid)
    }
}

fn extract_multiple(
    cx: &Context,
    trace_id: &str,
    span_id: &str,
    parent_span_id: &str,
    sampled: &str,
    flags: &str,
) -> (Context, SpanContext, bool) {
    let mut new_cx = cx.clone();
    let mut scc = SpanContextConfig::default();

    match sampled.to_lowercase().as_str() {
        "0" | "false" => {}
        "1" | "true" => {
            scc.trace_flags = TraceFlags::SAMPLED;
        }
        "" => {
            new_cx = new_cx.with_value(DeferredFlag(true));
        }
        _ => {
            return (new_cx, SpanContext::empty_context(), false);
        }
    }

    if flags == "1" {
        new_cx = new_cx.with_value(DeferredFlag(false));
        new_cx = new_cx.with_value(DebugFlag(true));
        scc.trace_flags = TraceFlags::SAMPLED;
    }

    if !trace_id.is_empty() {
        let tid = if trace_id.len() == 16 {
            format!("{}{}", B3_TRACE_ID_PADDING, trace_id)
        } else {
            trace_id.to_string()
        };
        if let Some(id) = parse_trace_id(&tid) {
            scc.trace_id = id;
        } else {
            return (new_cx, SpanContext::empty_context(), false);
        }
    }

    if !span_id.is_empty() {
        if let Some(id) = parse_span_id(span_id) {
            scc.span_id = id;
        } else {
            return (new_cx, SpanContext::empty_context(), false);
        }
    }

    if !parent_span_id.is_empty() {
        if scc.trace_id == TraceId::INVALID || scc.span_id == SpanId::INVALID {
            return (new_cx, SpanContext::empty_context(), false);
        }
        if parse_span_id(parent_span_id).is_none() {
            return (new_cx, SpanContext::empty_context(), false);
        }
    }

    let sc = SpanContext::new(
        scc.trace_id,
        scc.span_id,
        scc.trace_flags,
        true,
        TraceState::default(),
    );
    {
        let valid = sc.is_valid();
        (new_cx, sc, valid)
    }
}

#[derive(Clone)]
struct SpanContextConfig {
    trace_id: TraceId,
    span_id: SpanId,
    trace_flags: TraceFlags,
}

pub(super) fn parse_trace_id(s: &str) -> Option<TraceId> {
    if s.len() != 32
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    TraceId::from_hex(s)
        .ok()
        .filter(|id| *id != TraceId::INVALID)
}

pub(super) fn parse_span_id(s: &str) -> Option<SpanId> {
    if s.len() != 16
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    SpanId::from_hex(s).ok().filter(|id| *id != SpanId::INVALID)
}

fn get_sc_from_context(cx: &Context) -> SpanContext {
    cx.span().span_context().clone()
}
fn set_sc_in_context(cx: Context, sc: SpanContext) -> Context {
    cx.with_remote_span_context(sc)
}

impl Default for SpanContextConfig {
    fn default() -> Self {
        Self {
            trace_id: TraceId::INVALID,
            span_id: SpanId::INVALID,
            trace_flags: TraceFlags::default(),
        }
    }
}
