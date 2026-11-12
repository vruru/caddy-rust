use opentelemetry_sdk::{
    error::OTelSdkResult,
    metrics::{
        InstrumentKind, ManualReader, Pipeline, Temporality, data::ResourceMetrics,
        reader::MetricReader,
    },
};
use std::{
    sync::{Arc, Weak},
    time::Duration,
};
/// Shared ownership lets the generation collect without a global meter provider.
/// Manual readers create no background export thread during preparation.
#[derive(Clone, Debug)]
pub(super) struct Reader(pub Arc<ManualReader>);
impl Reader {
    pub fn cumulative() -> Self {
        Self(Arc::new(
            ManualReader::builder()
                .with_temporality(Temporality::Cumulative)
                .build(),
        ))
    }
    pub fn snapshot(&self) -> OTelSdkResultSnapshot {
        let mut data = ResourceMetrics::default();
        self.0.collect(&mut data)?;
        Ok(data)
    }
}
type OTelSdkResultSnapshot = Result<ResourceMetrics, opentelemetry_sdk::error::OTelSdkError>;
impl MetricReader for Reader {
    fn register_pipeline(&self, pipeline: Weak<Pipeline>) {
        self.0.register_pipeline(pipeline)
    }
    fn collect(&self, data: &mut ResourceMetrics) -> OTelSdkResult {
        self.0.collect(data)
    }
    fn force_flush(&self) -> OTelSdkResult {
        self.0.force_flush()
    }
    fn shutdown_with_timeout(&self, timeout: Duration) -> OTelSdkResult {
        self.0.shutdown_with_timeout(timeout)
    }
    fn temporality(&self, kind: InstrumentKind) -> Temporality {
        self.0.temporality(kind)
    }
}
