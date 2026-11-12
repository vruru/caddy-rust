//! Official generated OTLP client, with native DATA-owner transport.
use super::transport::{Credit, Transport};
use std::sync::Arc;
pub(super) struct Grpc {
    transport: Arc<Transport>,
    origin: http::Uri,
    headers: tonic::metadata::MetadataMap,
    gzip: bool,
    timeout: std::time::Duration,
}
impl Grpc {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn prepare(
        endpoint: String,
        headers: Option<String>,
        compression: Option<String>,
        ca: Option<&[u8]>,
        identity: Option<(&[u8], &[u8])>,
        timeout: std::time::Duration,
        credit: Arc<super::budget::Metadata>,
    ) -> anyhow::Result<Self> {
        let uri: http::Uri = endpoint.parse()?;
        anyhow::ensure!(
            matches!(uri.scheme_str(), Some("http" | "https")) && uri.host().is_some(),
            "invalid OTLP gRPC endpoint"
        );
        let gzip = match compression.as_deref() {
            None | Some("none") => false,
            Some("gzip") => true,
            _ => anyhow::bail!("unsupported OTLP gRPC compression"),
        };
        let mut map = http::HeaderMap::new();
        if let Some(headers) = headers {
            for entry in headers.split(',').map(str::trim) {
                let Some((key, value)) = entry.split_once('=') else {
                    continue;
                };
                let key = key.trim();
                let value = value.trim();
                if key.is_empty() || value.is_empty() {
                    continue;
                }
                let decoded = percent_encoding::percent_decode_str(value)
                    .decode_utf8()
                    .map(|v| v.into_owned())
                    .unwrap_or_else(|_| value.to_owned());
                if let (Ok(key), Ok(value)) = (
                    http::HeaderName::from_bytes(key.as_bytes()),
                    http::HeaderValue::from_str(&decoded),
                ) {
                    map.insert(key, value);
                }
            }
        }

        let connector = crate::http_runtime::metrics_client::Connector::prepare(
            uri.clone(),
            ca,
            identity,
            timeout,
            tokio_util::sync::CancellationToken::new(),
            credit,
            true,
        )?;
        let origin = http::Uri::builder()
            .scheme(uri.scheme_str().expect("validated scheme"))
            .authority(uri.authority().expect("validated host").clone())
            .path_and_query("/")
            .build()?;
        Ok(Self {
            transport: Transport::new(connector, timeout, true),
            origin,
            headers: tonic::metadata::MetadataMap::from_headers(map),
            gzip,
            timeout,
        })
    }
    pub(super) async fn export(
        &self,
        data: &opentelemetry_sdk::metrics::data::ResourceMetrics,
        credit: Arc<Credit>,
    ) -> anyhow::Result<()> {
        use opentelemetry_proto::tonic::collector::metrics::v1::{
            ExportMetricsServiceRequest, metrics_service_client::MetricsServiceClient,
        };
        use prost::Message;
        use tonic_types::StatusExt;
        let owners = Arc::strong_count(&credit);
        let mut delay = std::time::Duration::from_millis(100);
        let mut cap = std::time::Duration::from_millis(1600);
        for attempt in 0..4 {
            let service = Service {
                transport: self.transport.clone(),
                credit: credit.clone(),
            };
            let mut client = MetricsServiceClient::with_origin(service, self.origin.clone())
                .max_encoding_message_size(32 << 20);
            if self.gzip {
                client = client
                    .send_compressed(tonic::codec::CompressionEncoding::Gzip)
                    .accept_compressed(tonic::codec::CompressionEncoding::Gzip);
            }
            let message = ExportMetricsServiceRequest::from(data);
            anyhow::ensure!(
                message.encoded_len() <= 32 << 20,
                "OTLP protobuf message exceeds 32 MiB"
            );
            let mut request = tonic::Request::new(message);
            *request.metadata_mut() = self.headers.clone();
            request.set_timeout(self.timeout);
            let result = client.export(request).await;
            drop(client);
            let error = match result {
                Ok(_) => return Ok(()),
                Err(error) => error,
            };
            let hint = error.get_details_retry_info().and_then(|v| v.retry_delay);
            let retry = match error.code() {
                tonic::Code::ResourceExhausted => hint.is_some(),
                tonic::Code::Unavailable
                | tonic::Code::Cancelled
                | tonic::Code::DeadlineExceeded
                | tonic::Code::Aborted
                | tonic::Code::OutOfRange
                | tonic::Code::DataLoss => true,
                _ => false,
            };
            // A peer may finish the control response while its request DATA is
            // still queued. Do not accumulate retries behind that real owner.
            if !retry || attempt == 3 || Arc::strong_count(&credit) > owners {
                return Err(error.into());
            }
            if let Some(hint) = hint {
                let hint = hint.min(std::time::Duration::from_secs(30));
                if hint > cap {
                    cap = std::time::Duration::from_secs(30);
                }
                delay = delay.max(hint);
            }
            let jitter = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .subsec_nanos() as u64
                % 101;
            let sleep = delay
                .saturating_add(std::time::Duration::from_millis(jitter))
                .min(cap);
            if sleep >= self.timeout.saturating_sub(credit.created.elapsed()) {
                return Err(error.into());
            }
            tokio::time::sleep(sleep).await;
            delay = delay.saturating_mul(2).min(cap);
        }
        unreachable!("bounded retry loop returns on its final attempt")
    }

pub(super) async fn export_traces(
    &self,
    data: &[opentelemetry_sdk::trace::SpanData],
    resource: &opentelemetry_sdk::Resource,
    credit: Arc<Credit>,
) -> anyhow::Result<()> {
    use opentelemetry_proto::tonic::collector::trace::v1::{
        ExportTraceServiceRequest, trace_service_client::TraceServiceClient,
    };
    use opentelemetry_proto::transform::common::tonic::ResourceAttributesWithSchema;
    use opentelemetry_proto::transform::trace::tonic::group_spans_by_resource_and_scope;
    use prost::Message;
    use tonic_types::StatusExt;
    let owners = Arc::strong_count(&credit);
    let mut delay = std::time::Duration::from_millis(100);
    let mut cap = std::time::Duration::from_millis(1600);
    for attempt in 0..4 {
        let service = Service {
            transport: self.transport.clone(),
            credit: credit.clone(),
        };
        let mut client = TraceServiceClient::with_origin(service, self.origin.clone())
            .max_encoding_message_size(32 << 20);
        if self.gzip {
            client = client
                .send_compressed(tonic::codec::CompressionEncoding::Gzip)
                .accept_compressed(tonic::codec::CompressionEncoding::Gzip);
        }
        let message = ExportTraceServiceRequest {
            resource_spans: group_spans_by_resource_and_scope(
                data.to_vec(),
                &ResourceAttributesWithSchema::from(resource),
            ),
        };
        anyhow::ensure!(
            message.encoded_len() <= 32 << 20,
            "OTLP protobuf message exceeds 32 MiB"
        );
        let mut request = tonic::Request::new(message);
        *request.metadata_mut() = self.headers.clone();
        request.set_timeout(self.timeout);
        let result = client.export(request).await;
        drop(client);
        let error = match result {
            Ok(_) => return Ok(()),
            Err(error) => error,
        };
        let hint = error.get_details_retry_info().and_then(|v| v.retry_delay);
        let retry = match error.code() {
            tonic::Code::ResourceExhausted => hint.is_some(),
            tonic::Code::Unavailable
            | tonic::Code::Cancelled
            | tonic::Code::DeadlineExceeded
            | tonic::Code::Aborted
            | tonic::Code::OutOfRange
            | tonic::Code::DataLoss => true,
            _ => false,
        };
        // A peer may finish the control response while its request DATA is
        // still queued. Do not accumulate retries behind that real owner.
        if !retry || attempt == 3 || Arc::strong_count(&credit) > owners {
            return Err(error.into());
        }
        if let Some(hint) = hint {
            let hint = hint.min(std::time::Duration::from_secs(30));
            if hint > cap {
                cap = std::time::Duration::from_secs(30);
            }
            delay = delay.max(hint);
        }
        let jitter = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos() as u64
            % 101;
        let sleep = delay
            .saturating_add(std::time::Duration::from_millis(jitter))
            .min(cap);
        if sleep >= self.timeout.saturating_sub(credit.created.elapsed()) {
            return Err(error.into());
        }
        tokio::time::sleep(sleep).await;
        delay = delay.saturating_mul(2).min(cap);
    }
    unreachable!("bounded retry loop returns on its final attempt")
}

    pub(super) async fn shutdown(&self) {
        self.transport.shutdown().await;
    }
}
#[derive(Clone)]
struct Service {
    transport: Arc<Transport>,
    credit: Arc<Credit>,
}
impl tower_service::Service<http::Request<tonic::body::Body>> for Service {
    type Response = http::Response<hyper::body::Incoming>;
    type Error = Box<dyn std::error::Error + Send + Sync>;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;
    fn poll_ready(
        &mut self,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }
    fn call(&mut self, request: http::Request<tonic::body::Body>) -> Self::Future {
        let transport = self.transport.clone();
        let credit = self.credit.clone();
        Box::pin(async move { transport.send(request, credit).await })
    }
}
