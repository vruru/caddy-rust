# Compatibility status and release boundaries

The behavioral baseline is Caddy 2.11.7 and CertMagic 0.25.6. This is an
independent native Rust implementation with combined acceptance of the fixed
standard capability suite and a guarded Linux deployment. This is **not a
blanket all-platform or arbitrary-plugin compatibility claim**. See the README for implemented feature families and
COMPATIBILITY.md for their detailed contracts. A feature accepting syntax,
a component passing, and the complete executable passing are distinct states.

## Combined acceptance, 2026-11-15

The release executables were built from the same frozen functional source
`352ca2b`, lockfile and official stable Rust 1.100.0 toolchain. The combined
checks covered the enumerated feature gaps together with proxy/template/CEL,
certificate issue and recovery, incoming/outgoing trust, ticket rotation,
listener/ECH, metrics/tracing, server/route deadlines, CLI and real trust tools.
Failed test setup attempts remain separate from the corrected results; a
different executable's historical success is not counted for this release.

macOS and Linux ARM checks included applicable full-CPU and single-CPU profiles.
The local Linux x86 protocol matrix used emulation; native x86 Linux separately
verified certificate compensation, concurrent transfers, offset recovery,
large Range positions and reload during active transfers. Throughput, CPU,
latency and memory were recorded separately: Rust was not faster than the
reference in every profile. These workloads do not establish universal
capacity or full TUS conformance.

One Linux installation then passed a guarded live trial, with executable
identity verification, browser cold/warm loads and business-page checks,
configuration reload retaining a real HTTPS connection, private loopback
administration, and actual bounded log rotation. The original executable and
configuration remain available for manual rollback. Initial process replacement
is distinct from retaining connections across an in-process reload. Further
deployments still require their own authorization and site acceptance.

## Cross-cutting remediation

The concentrated audit identified three shared defects: adapter output without
runtime consumers, incomplete retention of accepted TLS trust/identity across
failed-reload compensation, and errors being confused with absent name matches.
These are different from capabilities which have not yet been implemented.

The following grouped remediation passed its targeted normal-program and
component acceptance on macOS and Linux, including all-CPU and single-CPU Linux
business regressions. These workflows were also included in the combined
release acceptance above; they do not remove the remaining boundaries below:

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

## Capability and verification boundaries

The enumerated standard feature gaps now have typed plans and actual native
runtime consumers. The frozen candidate completed the applicable combined
release gates below. Unsupported extension inputs remain explicit errors; accepting or
ignoring a field is not evidence of compatibility.

| Area | Missing fields or legal branches |
| --- | --- |
| Edge-case verification | Fixed template and certificate contracts passed combined regression; unenumerated combinations and private Go reflection/layout equivalence are not promised |
| Optional providers | DNS publication/validation and non-default filesystem backends require actual provider implementations; the inspected standard inventory contains none of those plugins |
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

## Integrated capability groups

The reverse-proxy handler now consumes its legacy trust, response buffering,
Proxy-Status, stream timeout/buffer and verbose-log settings. HTTP transport
controls include actual outgoing HTTP/3. These are separate from incoming
protocol support and server-level proxy trust; their contracts are described
in `PROXY-HANDLER.md` and COMPATIBILITY.md.

Ordinary request replacers, headers, Map and file templates expose the supported
client-certificate fingerprint, public key/hash, issuer, serial, subject,
PEM/DER and SAN values through the existing TLS authentication boundary.
Query, form and multipart names, filenames, content and MIME parameters retain
their byte sequences. Time append/format methods return typed bytes;
addressable X509 time fields support mutating decoders without adding pointer
methods to ordinary returned Time values.

Folder and storage leaf loaders prepare accepted certificate snapshots before
handshakes. Configured ACME clients use system trust by default;
`trusted_roots_pem_files` remains custom-only, and the public wire SDK retains
its additive-extra-root contract. `insecure_secrets_log` is explicit, uses a
private regular file, and supports the ordinary and CBC TLS engines.
`SSLKEYLOGFILE` alone does not enable it.

The filesystem app and `file_server.fs` select the real default OS filesystem;
unknown backends are not mapped to it. Information commands, offline tar storage
import/export, and explicit PKI trust/removal have actual CLI consumers. Linux
system, Java and NSS trust installation/removal have real-backend coverage;
this does not establish macOS Keychain or Windows trust acceptance.

Server ECH includes key generation, compatible storage, restart, rotation and
retention of cached configurations. Both implementations can read the stored
key format. The original standard module set has no `dns.providers.*`; default
ECH publication without a provider is a no-op, and an explicit publisher without
a usable provider is rejected. Listing a module name does not establish DNS
record publication. Native treats `dns:null` as unconfigured, a deliberate
no-op extension to the reference's rejection of that input.

## ZeroSSL and shared cancellation boundaries

The REST issuer owns its typed backend, prepared credential, fixed endpoint,
shared CSR/key, persistent create intent, known-ID recovery, HTTP proof,
validation/download and publication CAS. An uncertain create is not replayed.
Only demonstrably uncreated or closed ZeroSSL attempts permit a corrected
credential configuration to replace the old attempt. Shared proof readers select
the first matching accepted policy and stop with their generation. Providerless
CNAME-validation metadata retains the HTTP validation path; an explicit provider
RawMessage remains a rejected extension dependency, including provider:null.

Revocation binds to the stored backend and exact leaf rather than current issuer
order. Authenticated API confirmations are stored only in instance-private state;
they are not signed OCSP and cannot be introduced by public storage import.
Already-revoked results confirm the leaf, not a newly requested reason. A local
key-compromise veto in that case remains explicitly conservative. Accepted
issuance tasks retain scoped storage/network ownership for bounded cleanup before
the generation closes its outgoing TLS scope. A failed renewal preserves the
previous working leaf.

Template multipart Read/ReadAt mutate the existing typed-byte COW view. Request
Body Read/Close and form parsing share the actual asynchronous body owner and
consumption position; ordinary Read does not collect an entire slow upload. Unread DATA prefixes remain owned by the actual request Body through nested
renders, template failures and cancellation. Each actual render installs one
narrow prefix wrapper without a request-extension identity shortcut. The bridge
has capacity one and uses the existing template work/memory budget. Close
retires the read half promptly instead of adding an extra compatibility drain of
an unknown slow source. Memory, disk/section, EOF, alias and concurrent-upload
checks belong to the same combined candidate gates.

## Server/listener layer

Server socket keepalive, header limits, H1 full duplex, Unix proxy trust and
per-listener protocol sets have real runtime consumers. Unix/unixpacket/fd and
UDP/fdgram listeners retain concrete kernel identities and existing reload
ownership. Stateful HTTP/3 early dispatch observes unfinished versus completed
TLS honestly and returns 425 for IP matchers before Finished. Stateless STEK
continues resumption while Rustls rejects early data. See COMPATIBILITY.md for
platform limits, body-drain behavior and listener filesystem side effects.
These targeted contracts do not replace the combined release gates below.

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

## Rewrite allocation admission

Literal arguments, identity rewrites and path-prefix/suffix stripping reserve
workspace from the actual request and argument sizes. Short rewrites do not
prepay the maximum URI size or a fixed multi-megabyte transformation buffer.
The shared 128 MiB pool, URI limits, work deadlines and parallel admission remain
in force. Complex substring, regexp and query transformations retain their
conservative workspace guards; this is not a claim of exact accounting for
every placeholder provider or all process allocations.

Reservations precede copies and transformation work. Retained projections cover
physical buffer capacities and URI handoff, and a blocking producer retains the
previous projection's allocation lease after its awaiting request is cancelled.
Completed simple transformations transfer their workspace lease to their
retained result instead of briefly charging the same result twice.

## Reverse-proxy HTTP transport

The HTTP transport consumes resolver addresses, TCP keepalive probes, HTTP idle
pool limits, total connections per host, local TCP/Unix binding, dial fallback,
outgoing PROXY v1/v2, explicit HTTP/HTTPS/SOCKS5 proxies and the legacy proxy URL.
When no proxy source is configured, HTTP_PROXY/HTTPS_PROXY/NO_PROXY are consumed;
`network_proxy` with `from: none` disables that environment path. Proxy routing,
authentication, and TLS are performed by the native connector. Origin and proxy
handshakes retain the existing trust, client-identity and compatibility policies.
The connection limit covers dialing, active and idle sockets rather than HTTP/2
streams or TLS CPU slots. Outgoing PROXY pooling includes the actual source
identity; Unix peers cannot supply a fabricated IP prefix.

HTTP/1 read chunks and write-buffer batching are configurable independently of
the total response-header limit. HTTP/2 applies its decoded header-list limit.
The 100-continue interval starts at actual request-head flush; a 100 response
releases the upload immediately and a final response can finish without reading
or replaying the held body. Existing response-header and socket read/write
limits remain separate controls. Buffer controls do not establish a bound on
all ingress, HeaderMap, HPACK or process allocations.

Exclusive `versions: ["3"]` with an explicit TLS configuration uses native QUIC
and HTTP/3, including concurrent request streams, streaming uploads/responses,
trailers, cancellation and pooled connections. It reuses the prepared verifier
and managed-client certificate binding. TCP socket probes, TCP read/write buffer
controls, outgoing PROXY and HTTP/SOCKS forward proxies are TCP-transport controls;
they are not CONNECT-UDP/MASQUE support. Upstream HTTP/3 does not support the
HTTP/1 Upgrade bridge. Its configured response-header timer starts after the
upload's FIN is accepted by QUIC, and is not a claim of peer acknowledgment or
physical UDP flush. The existing frontend HTTP/3 implementation is independent.

The upstream QUIC cache and DNS/upload/driver ownership use the existing runtime
resources and task tracker. Request-derived dial metadata retains its existing
Map/optional-client-cache ownership. No new process-wide resource pool or CPU
limit is introduced by these transport settings.

## Absolute HTTP/1 target host bytes

The Native HTTP/1 receiver accepts the Go URL host escape set in absolute HTTP(S)
request targets: percent itself and escaped bytes at or above 0x80. Other escaped
ASCII, controls and malformed escapes remain rejected. The ordinary http/Hyper
URI parsers retain their strict default behavior; this is an explicit Native H1
server opt-in, not a global relaxation of Authority or its UTF-8 representation.
The literal on-wire Host header retains the ASCII HTTP host-character gate.

The logical request authority is byte-valued and decoded exactly once. Template
Request.Host/URL.Host, byte replacers, Map inputs, header matching, HostHash and
CGI preserve those bytes. The raw request target is retained separately from
URL.String, so an absolute target's scheme spelling and percent-escape case are
not replaced by a normalized path/query. Access logs use the existing Go-style
byte-string JSON serialization. Unrepresentable optional UTF-8-only metrics or
trace host observations are omitted; that representation boundary does not alter
the authority used for matching, authorization or forwarding.

The outgoing Host is normalized independently: valid Unicode becomes IDNA,
IPv6 routing zones are removed, and invalid UTF-8 produces a typed local 502
before sending an upstream application request. X-Forwarded-Host retains the
logical incoming byte fact. New Unicode conversion uses the existing bounded
metadata lane and header pool, with the input/work/output loan following the
actual worker and the final owned HeaderValue bytes. This does not claim that
all HPACK/QUIC or process heap allocation is charged by that loan. ASCII keeps
the existing path. Certificate URI SAN validation, TLS identity and trust rules
are unchanged.
