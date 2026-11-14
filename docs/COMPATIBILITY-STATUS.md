# Compatibility status and release boundaries

The behavioral baseline is Caddy 2.11.7 and CertMagic 0.25.6. This is an
independent native Rust implementation, **not yet a production-ready complete
replacement**. See the README for implemented feature families and
COMPATIBILITY.md for their detailed contracts. A feature accepting syntax,
a component passing, and the complete executable passing are distinct states.

## Cross-cutting remediation

The concentrated audit identified three shared defects: adapter output without
runtime consumers, incomplete retention of accepted TLS trust/identity across
failed-reload compensation, and errors being confused with absent name matches.
These are different from capabilities which have not yet been implemented.

The following grouped remediation passed its targeted normal-program and
component acceptance on macOS and Linux, including all-CPU and single-CPU Linux
business regressions. This closes the workflows described here; it does not
complete the full release gates or the missing capabilities listed below:

- Retain accepted business incoming/outgoing trust and static client identity;
  reconstruct new-generation clients without reopening the accepted sources.
- Prepare explicit ACME roots once per configured issuer, with custom-only
  trust. Retain the original live consumption phase for default system roots
  used by permission checks, external certificate retrieval and admin polling.
- Supply the existing trust installer through the normal CLI. Explicit
  disabling still prevents installation; installation failure stays nonfatal.
- Preserve typed errors and output ownership through chain selection and
  Map/DNS dispatch, while preserving legitimate remote no-match behavior.

This does not promise that configuration activation has no external effects.
In particular, a later configuration compensation cannot undo an already
started system trust installation. Validation and rejection before activation
must not start that installation.

## Explicit standard capability gaps

These are finite known gaps, not a claim that every existing configuration uses
or is broken by these fields. Rejected fields must not be made superficially
compatible by ignoring them. The adapter, typed plan and real runtime consumer
must all implement their behavior.

| Area | Missing fields or legal branches |
| --- | --- |
| HTTP transport | `resolver`, `keep_alive`, `max_conns_per_host`, outgoing `proxy_protocol` |
| Forward proxy | `network_proxy`, legacy `forward_proxy_url`, including normal reverse-proxy environment consumption |
| Dialing | `dial_fallback_delay`, `local_address` |
| HTTP transport buffering | `expect_continue_timeout`, `max_response_header_size`, `write_buffer_size`, `read_buffer_size` |
| Upstream protocols | HTTP/3 upstream transport; existing frontend HTTP/3 is a separate implementation |
| Reverse proxy | Handler-level legacy `trusted_proxies`, `response_buffers`, `proxy_status_name`, `stream_timeout`, `stream_buffer_size`, `verbose_logs` |
| Server sockets | `keepalive_interval`, `keepalive_idle`, `keepalive_count` |
| Server HTTP | `max_header_bytes`, `enable_full_duplex`, `trusted_proxies_unix`, `listen_protocols`, `allow_0rtt` |
| Listener addresses | Remaining non-TCP HTTP listener network/address forms, including Unix sockets |
| Certificate issuers | Complete ZeroSSL REST issuer lifecycle; REST primitives alone are not an issuer. Default ACME OS-root parity is also incomplete: the current reqwest build uses built-in WebPKI roots |
| Leaf verification | Folder and storage leaf loaders |
| Other standard capabilities | Standard ECH lifecycle, filesystem app and file-server `fs` selection, explicit `insecure_secrets_log` |
| Providers and byte strings | Non-scalar TLS providers in ordinary text consumers; raw non-UTF-8 form/query values; percent-bearing non-IPv6 absolute HTTP target hosts |
| Template methods | Remaining time/location mutable decode/append and private-reflection behavior documented in COMPATIBILITY.md |
| CLI | `list-modules`, `build-info`, standalone `environ`, storage import/export, explicit PKI trust/untrust commands |
| Platforms | Windows CLI/service/native trust and other unverified OS branches; macOS/Linux verification does not establish all-platform readiness |

Existing similarly named features do not satisfy a missing consumer. Incoming
PROXY protocol does not implement outgoing PROXY protocol; server-level trusted
proxies do not implement the legacy handler-level setting. Server and route
stream deadlines do not by themselves implement proxy `stream_timeout`.
Likewise, a transport connection count is not an HTTP/2 stream or CPU work cap.

Standard module behavior and the actual required third-party plugin behavior
must be inventoried separately. This project does not promise a Go plugin
binary ABI. Correct useful native extensions may remain supported even where
the baseline rejects them.

## Integrated release gates

A single final source, lockfile and official stable toolchain must produce the
candidate used for all applicable acceptance. Historical results for different
executables cannot collectively establish current whole-program readiness.

1. Configuration parser, typed plan and actual runtime contract.
2. Certificate issue, renewal, revocation and restart recovery with persistent
   state and the certificate actually served agreeing.
3. H1/H2/H3 transfers, concurrent large bodies, Range/conditional/HEAD behavior,
   gzip negotiation, WebSocket and streaming proxy workflows.
4. Failed reload and compensation, checking real TLS authentication and proxy
   traffic as well as restored raw configuration and admin availability.
5. Concurrency, cancellation, actual in-flight work retirement and shutdown;
   an independent slow or failed task must not block unrelated traffic.
6. Admin Host/origin/remote authorization, permissions and private material
   exposure boundaries.
7. Combined regression and performance with all available CPUs and one CPU.

Resource limits and correct ownership remain in place. Full-process RSS
accounting is not promised, and theoretical allocation accounting must not
substitute for closing these actual workflows. A reproduced leak, unsafe
replay, trust substitution or shutdown failure still requires repair.

Verification scripts, fixtures and operational evidence remain outside this
source repository. No GitHub Actions are introduced by this process. Passing
an isolated subset does not grant a general production release or change the
separately authorized deployment scope.
