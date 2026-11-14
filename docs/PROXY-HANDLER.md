# Reverse-proxy handler controls

These JSON fields belong to the `reverse_proxy` handler, independently of its
HTTP transport. Existing request buffering, flushing, rewrite, response routes,
load balancing, retries, health checks and TLS material preparation remain in
place.

| Field | Default | Behavior |
| --- | --- | --- |
| `trusted_proxies` | empty | Legacy IP addresses or CIDR ranges trusted for inherited `X-Forwarded-*` values. This combines with trust established by the server and does not change the server's client-IP result. |
| `response_buffers` | `0` | Zero streams without this prefix buffer; a positive value reads up to that prefix before forwarding the rest; a negative value buffers to EOF within the existing resource limits. |
| `proxy_status_name` | empty | Optional deployment identifier for RFC 9209 `Proxy-Status` when Incremental forwarding is refused. It is literal data, not a replacer template. |
| `stream_timeout` | `0` | Positive duration limits the total lifetime of an upgraded bidirectional stream after its handshake. Zero and negative values add no stream deadline. |
| `stream_buffer_size` | `0` | Zero selects 32 KiB per direction. A positive value selects the actual upgraded-stream buffers; ordinary HTTP bodies are unaffected. |
| `verbose_logs` | `false` | Enables additional DEBUG events for proxy progress, retries and response transfer. It does not lower the logger's configured level. |

Null fields retain their defaults. Invalid types, malformed IP ranges and
invalid durations reject the candidate configuration. Negative stream buffer
sizes are rejected safely during preparation; the reference can panic when
allocating a negative buffer at request time.

Handler-level forwarding trust retains existing `X-Forwarded-For` bytes and
appends the peer IP. `X-Forwarded-Proto` and `X-Forwarded-Host` use the last
received value when trusted, falling back to the connection's values when that
last value is empty. Handler-level trust does not promote a client-IP variable
or alter server trust decisions.

Configured buffering refuses messages with content marked `Incremental: ?1`
with HTTP 501. The checks cover original requests, request-header changes and
response-header changes, including removal of an original Incremental flag.
HEAD and responses without representation content are exempt. A configured
`proxy_status_name` appends `error=incremental_refused` to valid upstream
Proxy-Status string/token members. Invalid upstream lists are discarded.
Names are encoded as a token where possible and otherwise as an RFC string;
unrepresentable names do not produce the optional header. Valid upstream field
syntax is preserved, whereas the reference normalizes its serialization.

Response prefixes use the existing memory/spool admission and retain body and
trailer ordering. Complete buffered responses with trailers keep a streaming
size hint so HTTP/1 cannot replace their framing with Content-Length and lose
the trailers. A failed upstream body read preserves the prefix and its error,
without retrying the application request or counting a local admission failure
as an unhealthy upstream. This deliberately avoids the reference's negative-
limit read-error suppression, which can otherwise disguise a truncated prefix
as a complete response.

Upgraded HTTP/1 and HTTP/2 streams use the selected size in both copy directions.
HTTP/3 extended WebSockets use the selected upload reader and download buffer.
Their existing transfer allowance is acquired before buffer construction and
retained by the stream owners. Stream deadlines remain active after an upload
half-close and are independent of `stream_close_delay` during reload. Admission
failure uses the existing local resource error path.

Verbose events use the existing bounded logging app and numeric progress facts.
The added events do not include request headers, credentials or body content.
The pinned Go reference does not advertise HTTP/2 extended CONNECT by default;
its existing `GODEBUG=http2xconnect=1` opt-in is used for that differential
control. Native's existing HTTP/2 extended-CONNECT behavior remains enabled.

This field group has local differential coverage. It does not establish full
release compatibility; combined regression with the other feature groups is a
separate acceptance step.
