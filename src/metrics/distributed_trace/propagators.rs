#[path="propagators/b3.rs"]pub(crate) mod b3;
#[path="propagators/jaeger.rs"]pub(crate) mod jaeger;
#[path="propagators/xray.rs"]pub(crate) mod xray;
#[path="propagators/ot.rs"]pub(crate) mod ot;
#[path="propagators/baggage.rs"]pub(crate) mod baggage;

pub(crate) fn compose(names:&[super::config::Propagator])->opentelemetry::propagation::TextMapCompositePropagator{
 use super::config::Propagator as P;
 use opentelemetry::propagation::TextMapPropagator;
 let props:Vec<Box<dyn TextMapPropagator+Send+Sync>>=names.iter().map(|name|match name{
  P::TraceContext=>Box::new(opentelemetry_sdk::propagation::TraceContextPropagator::new())as Box<dyn TextMapPropagator+Send+Sync>,
  P::Baggage=>Box::new(baggage::Baggage::new()),
  P::B3=>Box::new(b3::B3Propagator::new(false)),P::B3Multi=>Box::new(b3::B3Propagator::new(true)),
  P::Jaeger=>Box::new(jaeger::Jaeger::new()),P::Xray=>Box::new(xray::Xray::new()),P::OtTrace=>Box::new(ot::Ot::new()),
 }).collect();opentelemetry::propagation::TextMapCompositePropagator::new(props)
}
