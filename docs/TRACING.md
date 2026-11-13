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

### Trace encoding, IO and CPU retirement

Trace actors poll the closed SDK exporter future on the existing bounded trace
CPU lane. Each Pending step returns its running permit before socket readiness,
retry delay, or console IO is awaited. The actual owned future and source batch
remain registry-pinned; the async driver receives only a small outcome. The
pinned generated gRPC unary codec is preencoded on that same lane before Hyper
polls request DATA. Its separate small supervisor avoids nested single-slot CPU
wait cycles. This is a closed unary seam, with explicit errors for unexpected
Pending, multiple DATA frames or request trailers; arbitrary body callbacks are
not a new supported encoding API.

CPU admission failure, idle deadline, caller cancellation and unconsumed output
leave large batch/future/body data with the same registry. One retirement thread
per metrics Process takes the same running semaphore before actual destruction.
It is prepared before provider ingress and fails preparation explicitly if it
cannot start. It is neither an additional encoder pool nor a thread per batch.
Prepaid intrusive cells and their weak/control metadata use the existing trace
source budget; no unbounded cleanup queue or new count allowance is introduced.
The existing source, workspace, output, actor, queue, retry and absolute-deadline
limits remain in force. In particular, four retained 128MiB workspaces can fill
the existing 512MiB pool: CPU independence does not waive memory admission.

Immutable encoded bytes have a registry primary pin plus a concrete shared Bytes
reader owner. Slices share that reader. The reader releases its actual backing
reference before reporting reader0; only then can CPU retirement destroy the
last primary data owner and return its memory/output loans. Trace BatchMemory
contains the memory lifetime separately from the original logical IO Credit.
Byte pins do not extend Credit.done, change its creation time, postpone an old
batch deadline, or add a strong Credit reference to the existing retry test.
A concrete previous-pin receipt bounds successive encoded attempts. Actual
retained HTTP/2 DATA still prohibits replay; reader0 alone is not IO success.
Console retains its original single physical writer, order, deadline and
kill-and-wait behavior; its trace output loan follows actual byte destruction.
Ordinary metrics keep their existing direct scratch/metadata representation.

Driver/source tokens and transferred byte pins have separate completion layers.
Actor stop preserves the existing 30-second queue drain, retires its future on
CPU, and closes its own Plan transport before the Driver finishes. This permits
actual IO readers to end; final Process shutdown then drains byte retirement and
awaits the real thread join. A byte pin owns neither a Plan nor the Process or
Driver. The resident export future does strongly own its actual Plan during
consumption, while the Plan/context has only weak retirement links. Pending
receiver disposal and expired queued input use a pre-registered CPU retirement
cell instead of dropping the whole receiver on the reactor.

Normal explicit shutdown holds the requested 2MiB stack reservation through the
actual OS thread join. Last-owner Drop without a usable runtime can signal the
preexisting retirement thread and retire business data without that runtime; it
does not claim an async join or prove that OS TLS/TCB/stack mappings have already
been reclaimed merely because the thread function ended. Allocator/provider and
whole-process RSS remain outside these declared source/workspace/layout loans.

This boundary covers admitted trace-driver batches and the closed local encoder
and byte handoffs above. The SDK Processor::on_end's preexisting queue-full or
closed direct SpanData destruction is outside it. Ordinary metrics
ExportPlan::once still has its separate CPU-lane block_on of network work; this
trace change does not claim all observability callers are split. Standalone SDK
bodies and Windows runtime behavior have no new universal acceptance claim.
