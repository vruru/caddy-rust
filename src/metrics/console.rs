//! Stream borrowed SDK snapshots into the prepaid bounded output. Attribute
//! sorting stores references only; no whole JSON Value tree is constructed.
use anyhow::{Result, bail, ensure};
use opentelemetry::Array;
use opentelemetry::KeyValue;
use opentelemetry::Value as OValue;
use opentelemetry_sdk::metrics::Temporality;
use opentelemetry_sdk::metrics::data::{AggregatedMetrics, MetricData, ResourceMetrics};
use std::time::SystemTime;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

pub(super) fn write(rm: &ResourceMetrics, out: &mut impl std::io::Write) -> Result<()> {
    out.write_all(b"{\"Resource\":[")?;

    // Resource Attributes
    let mut res_attrs = rm.resource().iter().collect::<Vec<_>>();
    res_attrs.sort_unstable_by(|a, b| a.0.as_str().cmp(b.0.as_str()));
    let mut first = true;
    for (key, value) in res_attrs {
        if !first {
            out.write_all(b",")?;
        }
        first = false;
        out.write_all(b"{\"Key\":")?;
        serde_json::to_writer(&mut *out, key.as_str())?;
        out.write_all(b",\"Value\":")?;
        write_otlp_value(out, value)?;
        out.write_all(b"}")?;
    }
    out.write_all(b"],\"ScopeMetrics\":")?;

    // Scope Metrics
    let mut sm_list = rm.scope_metrics().peekable();
    if sm_list.peek().is_none() {
        out.write_all(b"null")?;
    } else {
        out.write_all(b"[")?;
        let mut first_sm = true;
        for sm in sm_list {
            if !first_sm {
                out.write_all(b",")?;
            }
            first_sm = false;
            write_scope_metric(out, sm)?;
        }
        out.write_all(b"]")?;
    }

    out.write_all(b"}")?;
    out.flush()?;
    Ok(())
}

fn write_scope_metric<W: std::io::Write>(
    out: &mut W,
    sm: &opentelemetry_sdk::metrics::data::ScopeMetrics,
) -> Result<()> {
    let scope = sm.scope();
    out.write_all(b"{\"Scope\":{\"Name\":")?;
    serde_json::to_writer(&mut *out, scope.name())?;
    out.write_all(b",\"Version\":")?;
    serde_json::to_writer(&mut *out, scope.version().unwrap_or(""))?;
    out.write_all(b",\"SchemaURL\":")?;
    serde_json::to_writer(&mut *out, scope.schema_url().unwrap_or(""))?;
    out.write_all(b",\"Attributes\":")?;

    // Scope Attributes
    let mut scope_attrs: Vec<&KeyValue> = scope.attributes().collect();
    scope_attrs.sort_by_key(|kv| kv.key.as_str());

    if scope_attrs.is_empty() {
        out.write_all(b"null")?;
    } else {
        out.write_all(b"[")?;
        let mut first = true;
        for kv in scope_attrs {
            if !first {
                out.write_all(b",")?;
            }
            first = false;
            write_key_value_pair(out, kv)?;
        }
        out.write_all(b"]")?;
    }

    out.write_all(b"},\"Metrics\":[")?;
    let mut first_m = true;
    for m in sm.metrics() {
        if !first_m {
            out.write_all(b",")?;
        }
        first_m = false;
        out.write_all(b"{\"Name\":")?;
        serde_json::to_writer(&mut *out, m.name())?;
        out.write_all(b",\"Description\":")?;
        serde_json::to_writer(&mut *out, m.description())?;
        out.write_all(b",\"Unit\":")?;
        serde_json::to_writer(&mut *out, m.unit())?;
        out.write_all(b",\"Data\":")?;
        write_aggregated_metrics(out, m.data())?;
        out.write_all(b"}")?;
    }
    out.write_all(b"]}").map_err(Into::into)
}

fn write_key_value_pair<W: std::io::Write>(out: &mut W, kv: &KeyValue) -> Result<()> {
    out.write_all(b"{\"Key\":")?;
    serde_json::to_writer(&mut *out, kv.key.as_str())?;
    out.write_all(b",\"Value\":")?;
    write_otlp_value(out, &kv.value)?;
    out.write_all(b"}").map_err(Into::into)
}

fn write_otlp_value<W: std::io::Write>(out: &mut W, v: &OValue) -> Result<()> {
    match v {
        OValue::String(s) => {
            out.write_all(b"{\"Type\":\"STRING\",\"Value\":")?;
            serde_json::to_writer(&mut *out, s.as_str())?;
        }
        OValue::Bool(b) => {
            out.write_all(b"{\"Type\":\"BOOL\",\"Value\":")?;
            serde_json::to_writer(&mut *out, b)?;
        }
        OValue::I64(i) => {
            out.write_all(b"{\"Type\":\"INT64\",\"Value\":")?;
            serde_json::to_writer(&mut *out, i)?;
        }
        OValue::F64(f) => {
            ensure!(f.is_finite(), "invalid metric attribute");
            out.write_all(b"{\"Type\":\"FLOAT64\",\"Value\":")?;
            serde_json::to_writer(&mut *out, f)?;
        }
        OValue::Array(arr) => match arr {
            Array::Bool(values) => {
                out.write_all(b"{\"Type\":\"BOOLSLICE\",\"Value\":")?;
                serde_json::to_writer(&mut *out, values)?;
            }
            Array::I64(values) => {
                out.write_all(b"{\"Type\":\"INT64SLICE\",\"Value\":")?;
                serde_json::to_writer(&mut *out, values)?;
            }
            Array::F64(values) => {
                ensure!(
                    values.iter().all(|v| v.is_finite()),
                    "invalid metric attribute"
                );
                out.write_all(b"{\"Type\":\"FLOAT64SLICE\",\"Value\":")?;
                serde_json::to_writer(&mut *out, values)?;
            }
            Array::String(values) => {
                out.write_all(b"{\"Type\":\"STRINGSLICE\",\"Value\":[")?;
                for (i, value) in values.iter().enumerate() {
                    if i != 0 {
                        out.write_all(b",")?;
                    }
                    serde_json::to_writer(&mut *out, value.as_str())?;
                }
                out.write_all(b"]")?;
            }
            _ => bail!("Unsupported array type"),
        },
        _ => bail!("Unsupported value type"),
    }
    out.write_all(b"}").map_err(Into::into)
}

fn write_time<W: std::io::Write>(out: &mut W, t: Option<SystemTime>) -> Result<()> {
    match t {
        Some(t) => serde_json::to_writer(out, &OffsetDateTime::from(t).format(&Rfc3339)?)?,
        None => serde_json::to_writer(out, "0001-01-01T00:00:00Z")?,
    };
    Ok(())
}
fn attributes<'a>(
    out: &mut impl std::io::Write,
    attrs: impl Iterator<Item = &'a KeyValue>,
    null_empty: bool,
) -> Result<()> {
    let mut attrs = attrs.collect::<Vec<_>>();
    attrs.sort_unstable_by(|a, b| a.key.as_str().cmp(b.key.as_str()));
    if attrs.is_empty() && null_empty {
        out.write_all(b"null")?;
        return Ok(());
    }
    out.write_all(b"[")?;
    for (i, attr) in attrs.iter().enumerate() {
        if i != 0 {
            out.write_all(b",")?;
        }
        write_key_value_pair(out, attr)?;
    }
    out.write_all(b"]")?;
    Ok(())
}
fn iterator_array<T: serde::Serialize>(
    out: &mut impl std::io::Write,
    values: impl Iterator<Item = T>,
) -> Result<()> {
    out.write_all(b"[")?;
    for (i, value) in values.enumerate() {
        if i != 0 {
            out.write_all(b",")?;
        }
        serde_json::to_writer(&mut *out, &value)?;
    }
    out.write_all(b"]")?;
    Ok(())
}
trait Number: Copy + serde::Serialize {
    fn finite(self) -> bool;
}
impl Number for f64 {
    fn finite(self) -> bool {
        self.is_finite()
    }
}
impl Number for i64 {
    fn finite(self) -> bool {
        true
    }
}
impl Number for u64 {
    fn finite(self) -> bool {
        true
    }
}

fn write_aggregated_metrics<W: std::io::Write>(out: &mut W, m: &AggregatedMetrics) -> Result<()> {
    match m {
        AggregatedMetrics::F64(d) => write_metric_data(out, d),
        AggregatedMetrics::U64(d) => write_metric_data(out, d),
        AggregatedMetrics::I64(d) => write_metric_data(out, d),
    }
}

fn write_metric_data<W: std::io::Write, T: Number>(out: &mut W, d: &MetricData<T>) -> Result<()> {
    match d {
        MetricData::Gauge(g) => {
            out.write_all(b"{\"DataPoints\":[")?;
            for (i, pt) in g.data_points().enumerate() {
                ensure!(pt.value().finite(), "invalid metric value");
                if i != 0 {
                    out.write_all(b",")?;
                }
                out.write_all(b"{\"Attributes\":")?;
                attributes(out, pt.attributes(), false)?;
                out.write_all(b",\"StartTime\":")?;
                write_time(out, g.start_time())?;
                out.write_all(b",\"Time\":")?;
                write_time(out, Some(g.time()))?;
                out.write_all(b",\"Value\":")?;
                serde_json::to_writer(&mut *out, &pt.value())?;
                out.write_all(b"}")?;
            }
            out.write_all(b"]}")?;
        }
        MetricData::Sum(sum) => {
            out.write_all(b"{\"DataPoints\":[")?;
            for (i, pt) in sum.data_points().enumerate() {
                ensure!(pt.value().finite(), "invalid metric value");
                if i != 0 {
                    out.write_all(b",")?;
                }
                out.write_all(b"{\"Attributes\":")?;
                attributes(out, pt.attributes(), false)?;
                out.write_all(b",\"StartTime\":")?;
                write_time(out, Some(sum.start_time()))?;
                out.write_all(b",\"Time\":")?;
                write_time(out, Some(sum.time()))?;
                out.write_all(b",\"Value\":")?;
                serde_json::to_writer(&mut *out, &pt.value())?;
                out.write_all(b"}")?;
            }
            out.write_all(b"],\"Temporality\":")?;
            serde_json::to_writer(&mut *out, temporality_str(sum.temporality()))?;
            out.write_all(b",\"IsMonotonic\":")?;
            serde_json::to_writer(&mut *out, &sum.is_monotonic())?;
            out.write_all(b"}")?;
        }
        MetricData::Histogram(hist) => {
            out.write_all(b"{\"DataPoints\":[")?;
            for (i, pt) in hist.data_points().enumerate() {
                ensure!(
                    pt.sum().finite()
                        && pt.min().is_none_or(Number::finite)
                        && pt.max().is_none_or(Number::finite),
                    "invalid histogram value"
                );
                if i != 0 {
                    out.write_all(b",")?;
                }
                out.write_all(b"{\"Attributes\":")?;
                attributes(out, pt.attributes(), false)?;
                out.write_all(b",\"StartTime\":")?;
                write_time(out, Some(hist.start_time()))?;
                out.write_all(b",\"Time\":")?;
                write_time(out, Some(hist.time()))?;
                out.write_all(b",\"Count\":")?;
                serde_json::to_writer(&mut *out, &pt.count())?;
                out.write_all(b",\"Bounds\":")?;
                iterator_array(out, pt.bounds())?;
                out.write_all(b",\"BucketCounts\":")?;
                iterator_array(out, pt.bucket_counts())?;
                out.write_all(b",\"Min\":")?;
                serde_json::to_writer(&mut *out, &pt.min())?;
                out.write_all(b",\"Max\":")?;
                serde_json::to_writer(&mut *out, &pt.max())?;
                out.write_all(b",\"Sum\":")?;
                serde_json::to_writer(&mut *out, &pt.sum())?;
                out.write_all(b"}")?;
            }
            out.write_all(b"],\"Temporality\":")?;
            serde_json::to_writer(&mut *out, temporality_str(hist.temporality()))?;
            out.write_all(b"}")?;
        }
        MetricData::ExponentialHistogram(_) => bail!("Unsupported exponential histogram"),
    }
    Ok(())
}

fn temporality_str(t: Temporality) -> &'static str {
    match t {
        Temporality::Cumulative => "CumulativeTemporality",
        Temporality::Delta => "DeltaTemporality",
        Temporality::LowMemory => "DeltaTemporality",
        _ => "UnknownTemporality",
    }
}
