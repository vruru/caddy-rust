# Timeouts

The timeout subsystem enforces strict deadline management for HTTP servers and route handlers. Timeouts are configured via JSON fields in the server and route configurations. The controls are scoped to the actual request, response and transport owners.

## Server-Level Timeouts

Server timeouts apply to the entire request-response lifecycle. The `read_timeout` field defines a hard deadline spanning the header and body of the original request, anchored to the request epoch. The `read_header_timeout` is effective as the minimum of its value and the hard `read_timeout`. Additional server-side controls include `read_idle_timeout` and `read_min_rate` for incoming data, and `write_timeout` for the hard response deadline. The `write_idle_timeout` and `write_min_rate` monitor physical transport progress, excluding pauses from upstream sources. The default `write_idle_timeout` is 60 seconds. Negative values disable the timeout. Hard non-positive values also disable the timeout. JSON server durations accept existing duration strings and integer nanoseconds.

## Route-Level Timeouts

A route uses a JSON handler such as `{"handler":"timeouts","read_timeout":100000000,"write_timeout":200000000}`. Duration fields use signed integer nanoseconds, not duration strings. `read_min_rate` and `write_min_rate` use integer bytes per second; `max_write_chunk` is an integer byte count. Non-positive route timeout values disable that route policy. Route read/write limits are progress/idle policies, distinct from an overall server hard deadline. The default chunk is 64 KiB. There are at most 64 active clauses, including an installed server clause. These examples describe the route JSON module; they do not introduce a new route Caddyfile directive.

## Behavior and Scope Management

Timeout scopes are restored upon unwind, including during error conditions. The original server hard deadline is preserved. For H1, H2, and H3, physical output receipts are isolated by stream. Local write, flush, and UDP transmission events are recorded; peer ACKs are not considered. Allocated memory is retained until the last owner is released. This integration keeps its observation callbacks and foreign payload destructors outside codec locks.

## Reload and Shutdown

During a failed reload, the old configuration remains active. Accepted old requests retain their generation-specific timeouts. Normal shutdown is graceful, with a declared hard stop to prevent indefinite hangs. CPU detection occurs automatically at startup. There is no fixed production CPU count assumption.

## Release scope

These are implemented native transport paths against the Caddy 2.11.7 reference. The project remains a development candidate. Other certificate, ACME, CBC and standard module gaps and the full release gates remain; this document does not establish production readiness.
