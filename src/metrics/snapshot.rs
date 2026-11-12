use anyhow::{Result, bail};
use opentelemetry::KeyValue;
use opentelemetry_sdk::metrics::Temporality;
use opentelemetry_sdk::metrics::data::{AggregatedMetrics, MetricData, ResourceMetrics};
use prometheus::proto::{
    Bucket, Counter, Gauge as PromGauge, Histogram as PromHistogram, LabelPair, Metric,
    MetricFamily, MetricType,
};
use std::collections::BTreeMap;

/// Unifies f64 / i64 / u64 into a single conversion surface.
trait Num: Copy {
    fn to_f64(self) -> f64;
}
impl Num for f64 {
    #[inline]
    fn to_f64(self) -> f64 {
        self
    }
}
impl Num for i64 {
    #[inline]
    fn to_f64(self) -> f64 {
        self as f64
    }
}
impl Num for u64 {
    #[inline]
    fn to_f64(self) -> f64 {
        self as f64
    }
}

pub(super) fn families(rm: &ResourceMetrics) -> Result<Vec<MetricFamily>> {
    let mut map: BTreeMap<String, MetricFamily> = BTreeMap::new();

    for sm in rm.scope_metrics() {
        for m in sm.metrics() {
            let name = m.name().to_string();
            let help = m.description().to_string();
            match m.data() {
                AggregatedMetrics::F64(d) => process(&name, &help, d, &mut map)?,
                AggregatedMetrics::U64(d) => process(&name, &help, d, &mut map)?,
                AggregatedMetrics::I64(d) => process(&name, &help, d, &mut map)?,
            }
        }
    }

    Ok(map
        .into_values()
        .filter(|f| !f.get_metric().is_empty())
        .collect())
}

fn process<T: Num>(
    name: &str,
    help: &str,
    md: &MetricData<T>,
    map: &mut BTreeMap<String, MetricFamily>,
) -> Result<()> {
    match md {
        MetricData::Gauge(g) => {
            let pts: Vec<Metric> = g
                .data_points()
                .map(|pt| {
                    let mut m = Metric::new();
                    m.set_label(sorted_labels(pt.attributes()));
                    let mut ga = PromGauge::new();
                    ga.set_value(pt.value().to_f64());
                    m.set_gauge(ga);
                    m
                })
                .collect();
            merge(map, name, help, MetricType::GAUGE, pts)?;
        }
        MetricData::Sum(s) => {
            if s.temporality() != Temporality::Cumulative {
                bail!("Delta temporality Sum rejected for Prometheus exposition");
            }
            let monotonic = s.is_monotonic();
            let mt = if monotonic {
                MetricType::COUNTER
            } else {
                MetricType::GAUGE
            };
            let pts: Vec<Metric> = s
                .data_points()
                .map(|pt| {
                    let mut m = Metric::new();
                    m.set_label(sorted_labels(pt.attributes()));
                    let val = pt.value().to_f64();
                    if monotonic {
                        let mut c = Counter::new();
                        c.set_value(val);
                        m.set_counter(c);
                    } else {
                        let mut ga = PromGauge::new();
                        ga.set_value(val);
                        m.set_gauge(ga);
                    }
                    m
                })
                .collect();
            merge(map, name, help, mt, pts)?;
        }
        MetricData::Histogram(h) => {
            if h.temporality() != Temporality::Cumulative {
                bail!("Delta temporality Histogram rejected for Prometheus exposition");
            }
            let pts: Vec<Metric> = h
                .data_points()
                .map(|pt| {
                    let mut m = Metric::new();
                    m.set_label(sorted_labels(pt.attributes()));
                    let mut hist = PromHistogram::new();
                    hist.set_sample_count(pt.count());
                    hist.set_sample_sum(pt.sum().to_f64());

                    let bounds: Vec<f64> = pt.bounds().collect();
                    let raw_counts: Vec<u64> = pt.bucket_counts().collect();
                    // bounds.len()==N, counts.len()==N+1 (last = overflow/+Inf).
                    // Zip the first N entries → cumulative buckets; +Inf omitted
                    // because Prometheus TextEncoder appends it automatically.
                    let mut cum: u64 = 0;
                    let buckets: Vec<Bucket> = bounds
                        .iter()
                        .zip(raw_counts.iter())
                        .map(|(&ub, &c)| {
                            cum = cum.saturating_add(c);
                            let mut b = Bucket::new();
                            b.set_upper_bound(ub);
                            b.set_cumulative_count(cum);
                            b
                        })
                        .collect();
                    hist.set_bucket(buckets);
                    m.set_histogram(hist);
                    m
                })
                .collect();
            merge(map, name, help, MetricType::HISTOGRAM, pts)?;
        }
        MetricData::ExponentialHistogram(_) => {
            bail!("ExponentialHistogram has no Prometheus exposition mapping");
        }
    }
    Ok(())
}

fn sorted_labels<'a>(attrs: impl Iterator<Item = &'a KeyValue>) -> Vec<LabelPair> {
    let mut pairs: Vec<(String, String)> = attrs
        .map(|kv| (kv.key.as_str().to_string(), kv.value.as_str().into_owned()))
        .collect();
    pairs.sort_by(|a, b| a.0.cmp(&b.0));
    pairs
        .into_iter()
        .map(|(k, v)| {
            let mut lp = LabelPair::new();
            lp.set_name(k);
            lp.set_value(v);
            lp
        })
        .collect()
}

fn merge(
    map: &mut BTreeMap<String, MetricFamily>,
    name: &str,
    help: &str,
    kind: MetricType,
    points: Vec<Metric>,
) -> Result<()> {
    if points.is_empty() {
        return Ok(());
    }
    let family = map.entry(name.to_owned()).or_insert_with(|| {
        let mut family = MetricFamily::new();
        family.set_name(name.to_owned());
        family.set_help(help.to_owned());
        family.set_field_type(kind);
        family
    });
    anyhow::ensure!(
        family.get_field_type() == kind && family.help() == help,
        "conflicting metrics descriptor for {name}"
    );
    family.mut_metric().extend(points);
    Ok(())
}

pub(super) fn automatic(
    resource: &opentelemetry_sdk::Resource,
    errors: [u64; 2],
) -> Vec<MetricFamily> {
    let mut labels = BTreeMap::new();
    for (key, value) in resource.iter() {
        let mut name = String::new();
        for (index, character) in key.as_str().chars().enumerate() {
            if index == 0 && character.is_ascii_digit() {
                name.push('_');
            }
            name.push(if character.is_ascii_alphanumeric() || character == '_' {
                character
            } else {
                '_'
            });
        }
        if !name.is_empty() {
            labels.insert(name, value.as_str().into_owned());
        }
    }
    let mut metric = Metric::new();
    metric.set_label(
        labels
            .into_iter()
            .map(|(key, value)| {
                let mut label = LabelPair::new();
                label.set_name(key);
                label.set_value(value);
                label
            })
            .collect(),
    );
    let mut gauge = PromGauge::new();
    gauge.set_value(1.);
    metric.set_gauge(gauge);
    let mut target = MetricFamily::new();
    target.set_name("target_info".into());
    target.set_help("Target metadata".into());
    target.set_field_type(MetricType::GAUGE);
    target.set_metric(vec![metric]);
    let mut family = MetricFamily::new();
    family.set_name("promhttp_metric_handler_errors_total".into());
    family.set_help(
        "Total number of internal errors encountered by the promhttp metric handler.".into(),
    );
    family.set_field_type(MetricType::COUNTER);
    family.set_metric(
        ["gathering", "encoding"]
            .into_iter()
            .zip(errors)
            .map(|(cause, count)| {
                let mut metric = Metric::new();
                let mut label = LabelPair::new();
                label.set_name("cause".into());
                label.set_value(cause.into());
                metric.set_label(vec![label]);
                let mut counter = Counter::new();
                counter.set_value(count as f64);
                metric.set_counter(counter);
                metric
            })
            .collect(),
    );
    vec![target, family]
}
