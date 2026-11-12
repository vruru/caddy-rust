use super::negotiation::{Compression, Format};
use anyhow::Result;
use prometheus::{
    Encoder, ProtobufEncoder,
    proto::{Metric, MetricFamily, MetricType},
};
use std::io::{self, Write};
pub(super) const MAX_BYTES: usize = 64 << 20;
pub(super) struct Output(Vec<u8>);
impl Write for Output {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let end = self
            .0
            .len()
            .checked_add(data.len())
            .filter(|n| *n <= MAX_BYTES)
            .ok_or_else(|| io::Error::other("metrics output limit exceeded"))?;
        if end > self.0.capacity() {
            let capacity = end.max(self.0.capacity().saturating_mul(2)).min(MAX_BYTES);
            self.0
                .try_reserve_exact(capacity - self.0.len())
                .map_err(io::Error::other)?;
        }
        self.0.extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
pub(super) fn encode(
    families: &[MetricFamily],
    format: Format,
    compression: Compression,
) -> Result<Vec<u8>> {
    let mut out = Output(Vec::new());
    match compression {
        Compression::Identity => write(families, format, &mut out)?,
        Compression::Gzip => {
            let mut encoder =
                flate2::write::GzEncoder::new(&mut out, flate2::Compression::default());
            write(families, format, &mut encoder)?;
            encoder.finish()?;
        }
        Compression::Zstd => {
            let mut encoder = zstd::stream::write::Encoder::new(&mut out, 3)?;
            write(families, format, &mut encoder)?;
            encoder.finish()?;
        }
    }
    Ok(out.0)
}
fn write(families: &[MetricFamily], format: Format, out: &mut impl Write) -> Result<()> {
    match format {
        Format::ProtoDelimited => ProtobufEncoder::new().encode(families, out)?,
        Format::ProtoText => {
            for family in families {
                writeln!(out, "{family:#}")?;
            }
        }
        Format::ProtoCompact => {
            for family in families {
                writeln!(out, "{family}")?;
            }
        }
        Format::Text | Format::OpenMetrics | Format::OpenMetricsOld => {
            let open = format != Format::Text;
            for family in families {
                let name = family.name();
                let counter = family.get_field_type() == MetricType::COUNTER;
                let base = if open && counter {
                    name.strip_suffix("_total").unwrap_or(name)
                } else {
                    name
                };
                write!(out, "# HELP {base} ")?;
                escape(out, family.help(), false)?;
                writeln!(out)?;
                let kind = match family.get_field_type() {
                    MetricType::COUNTER => "counter",
                    MetricType::GAUGE => "gauge",
                    MetricType::HISTOGRAM => "histogram",
                    _ => anyhow::bail!("unsupported metrics family"),
                };
                writeln!(out, "# TYPE {base} {kind}")?;
                for metric in family.get_metric() {
                    match family.get_field_type() {
                        MetricType::COUNTER => sample(
                            out,
                            name,
                            "",
                            metric,
                            None,
                            metric.get_counter().as_ref().map_or(0., |c| c.value()),
                            open,
                            open,
                        )?,
                        MetricType::GAUGE => sample(
                            out,
                            name,
                            "",
                            metric,
                            None,
                            metric.get_gauge().as_ref().map_or(0., |g| g.value()),
                            open,
                            open,
                        )?,
                        MetricType::HISTOGRAM => {
                            let histogram = metric.get_histogram();
                            for bucket in histogram.get_bucket() {
                                sample(
                                    out,
                                    name,
                                    "_bucket",
                                    metric,
                                    Some(bucket.upper_bound()),
                                    bucket.cumulative_count() as f64,
                                    open,
                                    false,
                                )?;
                            }
                            sample(
                                out,
                                name,
                                "_bucket",
                                metric,
                                Some(f64::INFINITY),
                                histogram.get_sample_count() as f64,
                                open,
                                false,
                            )?;
                            sample(
                                out,
                                name,
                                "_sum",
                                metric,
                                None,
                                histogram.get_sample_sum(),
                                open,
                                open,
                            )?;
                            sample(
                                out,
                                name,
                                "_count",
                                metric,
                                None,
                                histogram.get_sample_count() as f64,
                                open,
                                false,
                            )?;
                        }
                        _ => unreachable!(),
                    }
                }
            }
            if open {
                writeln!(out, "# EOF")?;
            }
        }
    }
    Ok(())
}
fn escape(out: &mut impl Write, value: &str, quotes: bool) -> io::Result<()> {
    for b in value.as_bytes() {
        match b {
            b'\\' => out.write_all(b"\\\\")?,
            b'\n' => out.write_all(b"\\n")?,
            b'"' if quotes => out.write_all(b"\\\"")?,
            _ => out.write_all(&[*b])?,
        }
    }
    Ok(())
}
fn number(out: &mut impl Write, n: f64, float: bool) -> io::Result<()> {
    if n.is_nan() {
        out.write_all(b"NaN")
    } else if n == f64::INFINITY {
        out.write_all(b"+Inf")
    } else if n == f64::NEG_INFINITY {
        out.write_all(b"-Inf")
    } else if n != 0. && (n.abs() < 1e-4 || n.abs() >= 1e6) {
        let raw = format!("{n:e}");
        let (mantissa, exponent) = raw.split_once('e').expect("scientific notation");
        let exponent = exponent.parse::<i32>().expect("scientific exponent");
        write!(
            out,
            "{mantissa}e{}{:02}",
            if exponent < 0 { "-" } else { "+" },
            exponent.unsigned_abs()
        )
    } else {
        write!(out, "{n}")?;
        if float && n.fract() == 0. {
            out.write_all(b".0")?;
        }
        Ok(())
    }
}
fn sample(
    out: &mut impl Write,
    name: &str,
    suffix: &str,
    metric: &Metric,
    bound: Option<f64>,
    value: f64,
    open: bool,
    float: bool,
) -> io::Result<()> {
    write!(out, "{name}{suffix}")?;
    if !metric.get_label().is_empty() || bound.is_some() {
        write!(out, "{{")?;
        let mut comma = false;
        for label in metric.get_label() {
            if comma {
                out.write_all(b",")?;
            }
            write!(out, "{}=\"", label.name())?;
            escape(out, label.value(), true)?;
            out.write_all(b"\"")?;
            comma = true;
        }
        if let Some(bound) = bound {
            if comma {
                out.write_all(b",")?;
            }
            out.write_all(b"le=\"")?;
            number(out, bound, open)?;
            out.write_all(b"\"")?;
        }
        out.write_all(b"}")?;
    }
    out.write_all(b" ")?;
    number(out, value, float)?;
    out.write_all(b"\n")
}

pub(super) fn console(data: &opentelemetry_sdk::metrics::data::ResourceMetrics) -> Result<Vec<u8>> {
    let mut output = Output(Vec::new());
    super::console::write(data, &mut output)?;
    output.write_all(b"\n")?;
    Ok(output.0)
}
