# Tracing

Native tracing instruments the request chain following a configured `tracing` handler, using Caddy 2.11.7 as its behavioral reference. It accepts the existing Caddyfile directive or a JSON handler with `span` and `span_attributes`. It does not instrument every handler merely because a provider exists. The default span name is "handler". Span attributes are mapped to string values. A configured JSON null attribute value is decoded as the empty string, matching Go reference behavior.

## Configuration and Providers

Tracing providers are managed per committed generation. In-flight requests and active tunnels retain the provider instance from the generation at the time of their initiation. There is no global thread-local context that persists across asynchronous boundaries. This ensures that tracing context is scoped strictly to the request lifecycle.

The exported span ends at the point of actual stream or tunnel retirement. Cancelled streams are marked with an `Error` status code. Note that the reference Go implementation may leave cancelled spans with an `Unset` status; this Rust implementation explicitly sets `Error` to aid debugging.

## Export Configuration

Exporters are configured via the `OTEL_TRACES_EXPORTER` environment variable. This variable is case-sensitive and accepts exactly one of the following values: `otlp`, `console`, or `none`. An empty value defaults to `otlp`.

The `otlp` exporter supports HTTP/protobuf and gRPC protocols. Optional gzip is available for either transport. TLS and mTLS configurations follow standard OTLP settings. The `console` exporter serializes reference-shaped span records through the bounded stdout writer. Use `none` to suppress export; an unset exporter selects `otlp`.

Supported propagators include: `tracecontext`, `baggage`, `b3`, `b3multi`, `jaeger`, `xray`, `ottrace`, and `none`. The `xray` propagator integrates with AWS Distributed Tracing (X-Ray), not the proxy/X-ray-core tool. Propagator values are matched exactly, with no trimming. Duplicate propagators are deduplicated. Unknown propagator values generate a bounded numeric warning.

Setting `OTEL_SDK_DISABLED=true` suppresses native span export and exporter setup. Trace-context propagation can continue. This differs from the inspected Go implementation, which ignored this setting.

## Limits and Resource Management

The configured span name is limited to 16 KiB. The configured attribute map is capped at 128 entries and 128 KiB of combined key/value text. These are configuration bounds, separate from SDK span limits and export budgets.

Exporters use queueing and batching mechanisms. The default queue size is 2048 spans. The batch size is 512 spans. The scheduled export interval is 5000 milliseconds. The export timeout is 30000 milliseconds. Configured queue and batch counts may each be at most 65,536; the batch count is clamped to the queue count. These counts are not a 65,536-byte encoded payload limit. Malformed or non-positive configuration values revert to defaults.

Recording admission uses separate 128 MiB source credit and 4,096 span-owner slots retained through recording and export retirement. The workspace has an independent 512 MiB budget and 128 MiB for encoded output. Exporters operate on bounded 1–4 lanes. Recording and export pressure result in dropped telemetry, not dropped business logic. There is no whole-process RSS cap. Console exporters share a serialized, bounded writer; preparing a candidate cannot start exporting its spans.

## Data Collection Scope

The system tracks actual consumed request bytes. Response data is tracked logically. For HTTP/1.1 opaque WebSockets, no fictitious HTTP body count is recorded. For HTTP/2 and HTTP/3, logical DATA frames are counted.

The standard resource identity remains the actual Rust SDK. The logical instrumentation scope follows the reference implementation for collector routing compatibility.

## Status

This documentation covers implemented tracing paths. The project remains a development candidate. Full module/field acceptance, performance comparisons, browser business flows and the authorized canary remain release gates.
