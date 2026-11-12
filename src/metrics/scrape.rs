use super::{
    Registry, encode,
    negotiation::{self, Compression},
    snapshot,
};
use opentelemetry::{
    KeyValue,
    metrics::{Meter, ObservableCounter, ObservableGauge},
};
use std::sync::{
    Arc,
    atomic::{AtomicI64, AtomicU64, Ordering},
};
use tokio::sync::OwnedSemaphorePermit;
#[derive(Default)]
pub(super) struct Stats {
    inflight: AtomicI64,
    requests: [AtomicU64; 3],
    instruments: std::sync::OnceLock<(ObservableGauge<i64>, ObservableCounter<u64>)>,
}
impl Stats {
    pub fn attach(meter: &Meter) -> Arc<Self> {
        let result = Arc::new(Self::default());
        let weak = Arc::downgrade(&result);
        let gauge = meter
            .i64_observable_gauge("promhttp_metric_handler_requests_in_flight")
            .with_description("Current number of scrapes being served.")
            .with_callback(move |observer| {
                if let Some(stats) = weak.upgrade() {
                    observer.observe(stats.inflight.load(Ordering::Relaxed), &[]);
                }
            })
            .build();
        let weak = Arc::downgrade(&result);
        let count = meter
            .u64_observable_counter("promhttp_metric_handler_requests_total")
            .with_description("Total number of scrapes by HTTP status code.")
            .with_callback(move |observer| {
                if let Some(stats) = weak.upgrade() {
                    for (index, code) in ["200", "500", "503"].iter().enumerate() {
                        observer.observe(
                            stats.requests[index].load(Ordering::Relaxed),
                            &[KeyValue::new("code", *code)],
                        );
                    }
                }
            })
            .build();
        let _ = result.instruments.set((gauge, count));
        result
    }
}
struct Active {
    stats: Arc<Stats>,
    code: usize,
}
impl Drop for Active {
    fn drop(&mut self) {
        self.stats.inflight.fetch_sub(1, Ordering::Relaxed);
        self.stats.requests[self.code].fetch_add(1, Ordering::Relaxed);
    }
}
struct OwnedOutput {
    bytes: Vec<u8>,
    _credit: OwnedSemaphorePermit,
    _stats: Option<Active>,
}
impl AsRef<[u8]> for OwnedOutput {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}
impl Registry {
    pub(crate) async fn scrape(
        self: &Arc<Self>,
        headers: &http::HeaderMap,
        openmetrics: bool,
    ) -> http::Response<crate::http_runtime::Body> {
        self.scrape_mode(headers, openmetrics, false).await
    }
    pub(crate) async fn scrape_auto(
        self: &Arc<Self>,
        headers: &http::HeaderMap,
    ) -> http::Response<crate::http_runtime::Body> {
        self.scrape_mode(headers, false, true).await
    }
    async fn scrape_mode(
        self: &Arc<Self>,
        headers: &http::HeaderMap,
        openmetrics: bool,
        automatic: bool,
    ) -> http::Response<crate::http_runtime::Body> {
        let mut active = if automatic {
            None
        } else {
            Some(Active {
                stats: self.scrape_stats.clone(),
                code: 2,
            })
        };
        if let Some(active) = &active {
            active.stats.inflight.fetch_add(1, Ordering::Relaxed);
        }
        let format = negotiation::choose(
            headers
                .get(http::header::ACCEPT)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default(),
            openmetrics,
        );
        let compression = negotiation::compression(
            headers
                .get(http::header::ACCEPT_ENCODING)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default(),
        );
        let (Ok(scratch), Ok(output)) = (
            self.process
                .scratch
                .clone()
                .try_acquire_many_owned(256 << 20),
            self.process.output.clone().try_acquire_many_owned(64 << 20),
        ) else {
            if automatic {
                self.automatic_errors[0].fetch_add(1, Ordering::Relaxed);
            }
            return response(503, "metrics collection busy\n");
        };
        let registry = self.clone();
        // The running and memory permits move into the owned worker. Caller
        // cancellation cannot return them while collection/encoding continues.
        let result = self
            .process
            .collection
            .run(move || {
                let _scratch = scratch;
                let data = if automatic {
                    registry.automatic_snapshot()?
                } else {
                    Some(registry.snapshot()?)
                };
                let mut families = if let Some(data) = &data {
                    snapshot::families(data)?
                } else {
                    Vec::new()
                };
                if automatic {
                    families.extend(snapshot::automatic(
                        &registry.resource,
                        [
                            registry.automatic_errors[0].load(Ordering::Relaxed),
                            registry.automatic_errors[1].load(Ordering::Relaxed),
                        ],
                    ));
                    families.sort_by(|a, b| a.name().cmp(b.name()));
                }
                let bytes = encode::encode(&families, format, compression)?;
                Ok::<_, anyhow::Error>(OwnedOutput {
                    bytes,
                    _credit: output,
                    _stats: None,
                })
            })
            .await;
        let mut owned = match result {
            Ok(Ok(owned)) => owned,
            Ok(Err(_)) => {
                if let Some(active) = &mut active {
                    active.code = 1;
                }
                if automatic {
                    self.automatic_errors[1].fetch_add(1, Ordering::Relaxed);
                }
                return response(500, "metrics collection failed\n");
            }
            Err(_) => return response(503, "metrics collection busy\n"),
        };
        if let Some(active) = &mut active {
            active.code = 0;
        }
        owned._stats = active.take();
        use http_body_util::BodyExt;
        let bytes = bytes::Bytes::from_owner(owned);
        let mut result = http::Response::new(
            http_body_util::Full::new(bytes)
                .map_err(|never| match never {})
                .boxed_unsync(),
        );
        result.headers_mut().insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static(format.content_type()),
        );
        result.headers_mut().insert(
            http::header::VARY,
            http::HeaderValue::from_static("Accept-Encoding"),
        );
        match compression {
            Compression::Gzip => {
                result.headers_mut().insert(
                    http::header::CONTENT_ENCODING,
                    http::HeaderValue::from_static("gzip"),
                );
            }
            Compression::Zstd => {
                result.headers_mut().insert(
                    http::header::CONTENT_ENCODING,
                    http::HeaderValue::from_static("zstd"),
                );
            }
            _ => {}
        }
        result
    }
}
fn response(code: u16, message: &'static str) -> http::Response<crate::http_runtime::Body> {
    use http_body_util::BodyExt;
    let mut response = http::Response::new(
        http_body_util::Full::new(bytes::Bytes::from_static(message.as_bytes()))
            .map_err(|never| match never {})
            .boxed_unsync(),
    );
    *response.status_mut() = http::StatusCode::from_u16(code).expect("fixed status");
    response.headers_mut().insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
}
