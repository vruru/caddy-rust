# Compatibility contract and current gaps

Baseline: Caddy v2.11.7, CertMagic v0.25.6, acmez/v3 v3.1.7. The three inspected
production binaries expose the same 135 standard modules and no additional
third-party modules. The live configuration uses a subset; that observation does
not authorize removing capabilities from the requested replacement.

Current integration stage: the native process serves supported HTTP/Admin and
certificate configurations with `native-run`. Formatting, adaptation,
provisioning validation, transactional reload, stop/start and autosave recovery
are connected to that process. Serving and library paths do not invoke Go.
This is a development candidate; full module/field acceptance, performance,
production traffic validation and retained rollback remain release gates.
Unknown capabilities are rejected before replacing an active configuration.

Current integrated coverage includes HTTP/1, HTTP/2 and HTTP/3 streaming,
reverse proxy and FastCGI, dynamic upstreams and health checks, content coding,
static ranges and conditions, request/response middleware and matchers, logging
and handler trace. Templates, Goldmark and CEL have differential coverage, but
remaining host methods and field combinations are not claimed complete.

TLS 1.2/1.3, manual and managed material, automatic HTTP redirects, local PKI,
on-demand permission checks, HTTP-01/TLS-ALPN-01 issuance, renewal/ARI and OCSP
are connected to the native lifecycle. HTTP and Tailscale external managers
have actual handshake, fallback, reload/cancellation and revocation coverage.
The Admin PKI/public-certificate and reverse-proxy upstream status routes use
normal authorization and bounded snapshots. None of this establishes support
for every issuer, trust loader or connection-policy combination.

Required feature families:

- Caddyfile and JSON configuration, environment/placeholder rules, imports,
  CLI run/validate/adapt/reload/resume semantics, autosave, managed endpoint and
  conditional Admin API writes with their original path/array/ETag semantics.
- Transactional configuration replacement, retained accepted requests and long
  streams, listener ownership, failed-candidate rollback, graceful shutdown.
- HTTP/1, HTTP/2, HTTP/3, TLS/SNI/ALPN, reverse proxy, HTTP and FastCGI upstreams,
  WebSocket/SSE, timeouts, stream flushing, load balancing, health behavior.
- Handler/matcher/module namespaces, routes and subroutes, rewrites, headers,
  authentication, maps/variables, file serving, range/conditional/compressed
  responses, original client-IP trust boundaries, logging and metrics.
- Automatic HTTPS planning, implicit challenge listeners and redirects; existing
  ACME account identity; HTTP-01/TLS-ALPN-01 and applicable DNS provider behavior;
  issuer fallback; EC/RSA/Ed25519 key-format compatibility; early renewal/ARI,
  retry/backoff; OCSP; atomic certificate publication and TLS hot replacement.
- CertMagic file-storage namespaces, metadata preservation and compatible locks.
  Multi-file key/cert/metadata publication needs explicit recovery; three renames
  do not constitute an atomic group. A Rust process and the original Caddy must
  read each other's validated state in an isolated CA interoperability test.
- Standard local PKI, on-demand TLS, storage providers, and other registered
  capabilities remain explicit migration work; unsupported configuration must
  fail before it changes a working listener or published snapshot.

Current production inputs and all authentication material remain exclusively in
LocalOps. The live service names, ports, certificate storage, domain routing and
other applications' loopback backends must be preserved during eventual rollout.
No new official installation/self-upgrade workflow is introduced.

Concurrency and response acceptance
-----------------------------------

Requests, individual upstream operations and independent certificate jobs must
make progress concurrently. Storage, JSON parsing, certificate parsing and
signature work use bounded workers; an async function alone is not evidence of
nonblocking execution. Limits and overload behavior must be explicit, with no
unbounded task spawning, buffered file bodies or queues hidden behind a mutex.

Configuration publication is ordered and transactional. Per-certificate storage
generations and account identity changes also require scoped ordering. These
short consistency boundaries must not hold a global request lock during network
or disk waits. Accepted writes retain ownership after a client disconnect;
cancellation must not release an I/O gate while a detached writer can still
publish. A failed certificate or configuration candidate preserves its working
predecessor.

HTTP acceptance includes simultaneous uploads/downloads, slow readers and
upstreams, stream backpressure, ranges and conditional responses, interrupted
transfers, retries of non-idempotent bodies, HTTP-version/trailer behavior,
compression, connection reuse, reload and graceful drain. Fault and overload
cases must verify unrelated requests still complete. Performance comparisons
record workload, architecture, CPU, memory, descriptors, first-byte latency and
tail response latency against the pinned original executable. A short local
benchmark is not a production capacity or long-duration leak guarantee.

TLS handshakes select already validated in-memory material. Certificate issuance,
OCSP retrieval and verification run independently in bounded background work.
OCSP updates bind to the exact loaded certificate instance and chain, and expired
staples must not be sent to new handshakes. Required certificate material and optional OCSP data have separate budgets
(64 MiB and 16 MiB currently). A full optional cache cannot reject a new
certificate or renewal. Exact-chain reload can inherit an unexpired verified
staple while changing the instance generation; policy changes must explicitly
clear it or use a fresh resolver/manager. These active snapshot budgets do not
imply a hard total-process RSS limit while old users retain Arcs.

Remaining acceptance includes complete Caddyfile/import and application-lifecycle
combinations, all registered module behaviors and fields, transport policies,
certificate policies and rollback under simultaneous failures. Implemented
paths still need the final combined regression and production gates. Isolated
component success cannot waive these gates or establish that all 135 modules
are complete.

The Rust JSON configuration decoder rejects more than 400,000 opening
brackets, opening braces, commas and colons outside JSON strings before
allocating the configuration tree. Unlike upstream, HTTP writes that hit
this safety limit return `413 configuration_materialization_limit`. The
existing configuration stays active. The raw JSON `/adapt` endpoint does
not construct a tree and retains its separate input and output limits.


Compatibility policy and current boundaries
-------------------------------------------

The reference executable is an oracle, not a requirement to reproduce defects.
A useful native extension is retained when it executes correctly and has its
own validation. Unimplemented semantics are never represented by silently
accepting their module name. Go plugins have no cross-language binary ABI;
their configuration and behavior require native implementations.

Known development gaps still include remaining listener/address combinations,
metrics/OTLP and distributed tracing, the ACME server handler, push and timeout
handlers, remaining template receiver methods and custom directory templates,
TLS 1.0/1.1, full Go PKIX edge semantics and remaining issuer/trust-loader
capabilities. This list is not a claim that all other field combinations are
fully verified. The 135-module baseline is an inventory, not a support registry.

Automatic redirects preserve explicit Host-route precedence and an existing
HTTP catch-all when no new certificate names are managed. They retain all bind
addresses at the chosen canonical HTTPS port, prefer exact domains to wildcard
routes, and provide the baseline catch-all redirect for unknown hosts. Loaded
manual certificates, custom application ports and TLS-only catch-alls have
actual CLI differential coverage. Challenge-port application defaults do not
override explicitly configured issuer ports.

HTTP Basic Auth supports bcrypt and Argon2id v19, including the legacy outer
Base64 hash representation. Per-generation cache keys include the algorithm;
concurrent equal credentials share one owned comparison. Missing users use the
corresponding reference fake hash, and plaintext buffers are zeroized. Argon2
scratch is reserved before allocation from a separate 512 MiB aggregate pool,
with at most 256 MiB requested memory per record, requested/physical minimum
memory times iterations at most 4,194,304 KiB-iterations, a 16 KiB hash record
and 1..1024-byte derived key. Go-compatible short salts, positive short outputs
and sub-minimum requested memory preserve the original Argon2 initial hash.
Invalid or over-budget candidates fail before publication; transient scratch
pressure rejects authentication work without holding unrelated HTTP workers.
These are explicit resource boundaries, not whole-process RSS guarantees.

On macOS only the protected, root-owned /var, /tmp and /etc aliases may map to
their exact /private counterparts, accepting either the system's relative or
absolute link target. Every resulting path component still receives descriptor
and ownership validation. Arbitrary user symlinks are not trusted. Actual save,
reload and `run --resume` preserve 0600 autosave files through these aliases.

Private fixtures, comparison scripts, certificates, operation logs, screenshots
and build products stay outside this source repository. Tests and GitHub Actions
are not added as part of publishing functional source. Passing local checks is
reported separately from GitHub synchronization and production deployment.

### Corrected modular exponentiation of negative bases

The native template `*big.Int.Exp` repairs an upstream double-sign defect for a negative base and an odd negative exponent with a nonzero modulus. It computes the signed modular inverse once, then raises that inverse to the absolute exponent modulo the absolute modulus. For example, `Exp(-2, -1, 5)` returns `2`; the pinned Go baseline returns `3` because it applies the original base's sign again after inversion. Positive exponents retain the baseline behavior. A non-invertible negative exponent returns typed nil and leaves its receiver unchanged. With no modulus, nonpositive exponents retain the baseline result `1`.

This is an intentional mathematical correction, separately checked against an independent integer modular-power oracle. The observed Go outputs remain recorded as known differences rather than normalized away or counted as matching results. Template number mutation is private to one render context and cannot modify authenticated TLS snapshots or trust/signature facts. GCD rejects outputs from foreign or retired render owners and commits aliased outputs only after all target cells have been locked and validated.

Password generation and certificate key policy
---------------------------------------------

The startup-only `hash-password` utility supports bcrypt and Argon2id with
CSPRNG salts. A real terminal hides and confirms input and restores its settings
on mismatch and SIGINT. Piped input is bounded and may end at EOF without a final
newline; accepting that valid input is an intentional extension. Bcrypt accepts
72 password bytes and rejects longer input before hashing. The reusable native
hash API shares the authentication Argon2 scratch limits; async callers must use
a bounded blocking lane. Hashes generated by either implementation have been
verified by actual HTTP authentication in the other implementation.

TLS automation `must_staple` adds TLS Feature status_request to signed PKCS#10
requests and internal-issuer certificates. `reuse_private_keys` preserves the
existing validated private-key bytes on ordinary renewals and admits an exact,
validated key-only initial generation through a separately scoped capability.
Certificate, key and metadata publication retains leased, recoverable journal
semantics. This does not make arbitrary partial resources acceptable. A known
compromised key is archived and replaced even when reuse is requested, and
subsequent ordinary renewals may reuse that replacement. Active ACME checkpoints
bind both options; a policy change cannot silently resume a differently scoped
order. These behaviors have isolated CA, restart, fault and real TLS coverage;
final combined release acceptance remains required.

ACME network proxy
------------------

An ACME issuer supports `network_proxy` modules `{"from":"url","url":"http://proxy.example:3128"}` and `{"from":"none"}`. Omitting the field preserves environment proxy selection and `NO_PROXY`; an explicit URL overrides environment selection, and explicit `none` disables it. HTTP and HTTPS CONNECT, HTTP Basic authentication, and SOCKS5 username/password authentication are supported. Both `socks5` and `socks5h` resolve destination names at the proxy, matching Go's transport behavior. Scheme-less network-path URLs (`//proxy.example:3128`) use HTTP.

Explicit proxy policy remains effective when the HTTP app fills in ACME challenge defaults. Caddy 2.11.7 can lose its already-loaded proxy module during that second provisioning; Native preserves the configured policy. Native also makes `none` actually disable environment proxies instead of copying the upstream nil-callback fallback. These are deliberate repairs, rather than removal of the proxy capability.

Proxy URL global placeholders are resolved once, on the existing bounded CPU lane, when each independent ACME HTTP client is constructed. Business-request placeholders have no ACME request context. The expanded URL must retain a valid host; errors cannot silently select a direct connection. URLs are limited to 64 KiB, shared across cloned issuer configurations, and credentials are not included in proxy validation diagnostics. Existing ACME request/body limits, CA concurrency budgets, storage leases, certificate/key revocation gates and generation cancellation continue to apply. Proxy routing covers account, order, authorization, certificate and ARI requests, plus the same client's automatic ZeroSSL EAB request; it does not replace the separate OCSP transport policy.


ACME requested validity and profiles
-----------------------------------

ACME issuers apply `certificate_lifetime` as a signed nanosecond offset from
order creation time. Zero omits the requested expiry; nonzero values become an
absolute RFC 3339 `notAfter`, truncated to whole seconds. A CA remains free to
adjust requested validity. Invalid or expired issued material is not published.
Explicit `profile` values are literal strings and must be advertised by the CA
before a new order is sent; the empty value selects the CA default. Profile
names are bounded to 1024 UTF-8 bytes.

The absolute expiry, profile, key and CSR are retained in the durable order
checkpoint. Unknown new-order outcomes are reconciled with authenticated
POST-as-GET and require matching explicit profile/expiry observations; absence
or a mismatch never authorizes a second order. Known order URLs continue with
the original request parameters. Changing an active issuer policy leaves its
order blocked until the original parameters are restored or the order is
explicitly resolved. A definitively rejected prepared request and a completed
stored certificate do not lock future requests to obsolete parameters. This
preserves existing lease, scope, publication-CAS and compromised-key checks.


Prepaid Values mutation
----------------------

The template host's new Values mutation entry points accept edge-free scalar
payloads. Composite slices remain constructible and readable, but writing
Slice, Object, Map, List, Function or named values with captured dynamic methods
requires a graph-aware writer and is not exposed by these entry points. This
prevents safe host APIs from creating unreclaimable reference cycles. Existing
strong or weak read snapshots require prepaid copy-on-write; replacing an old
opaque value also retains its snapshot until the backing lock has been released,
so arbitrary destructors cannot reenter that locked backing.

A prepared atomic ticket supports at most 256 writes and 1,048,576 supplied
values. Preparation checks complete inputs, prepays metadata and replacement
backings, and executes admission callbacks outside backing locks. Commit locks
distinct cells in stable identity order, checks every original snapshot, then
swaps all replacements or changes none. Its one bounded guard-vector allocation
is prepaid and happens before acquiring any backing-cell lock. Tickets are
single-use and retain old snapshots after either result. Hosts recheck their
receiver ownership, commit and update metadata, unlock all receiver guards, and
only then drop the ticket or convert its allocation-free error. Nonempty atomic
writes without std are explicitly unsupported. These host primitives do not
establish completion of the remaining template methods or composite copy.


Ordered PROXY listener transport
--------------------------------

`proxy_protocol` listener wrappers execute in their configured order on each
side of the TLS marker. Native reads PROXY v1 and v2 IPv4/IPv6 TCP/UDP and Unix
stream/datagram addresses. IGNORE consumes a valid header without adopting its
addresses; USE adopts them; REJECT rejects a supplied valid header; REQUIRE
rejects absence or timeout; SKIP performs no header I/O. Deny CIDRs precede
allow CIDRs, then the fallback applies. Zero or omitted wrapper timeout uses the
pinned implementation's actual ten-second default; negative values disable only
that wrapper timer, not the server's outer classification deadline. Stacks are
bounded to 64 entries and each CIDR list to 1024 entries.

The incremental reader permits 107-byte v1 headers and the full uint16 v2
payload. Its independent 32 MiB prepaid staging pool retains consumed partial
bytes until replay drains or the connection is dropped. Exhaustion affects the
individual connection. Empty wrapper groups add no boxed stream. Proof listener
leases preserve the same configured transport: an uncommitted candidate serves
only challenge proofs, and conflicting candidates cannot replace a transport
still used by a challenge lease. Unchanged stacks retain keepalive connections
through route reload; a changed stack rejects new operations on an older
connection while already admitted transfers retain their original scope.

Addresses retain their declared family and raw path bytes rather than borrowing
the physical proxy's IP. Direct response/header placeholders, templates and
FastCGI preserve byte-valued Unix names. Access logs retain host/port fallback
semantics and per-invalid-byte JSON diagnostics. The external certificate HTTP
manager percent-encodes raw local-host bytes and preserves the original query
when the connection has no nonempty, structurally split host.
HTTP remote-IP matching, trusted-proxy
client-IP extraction and TLS matching use their respective parsing rules;
non-IP addresses cannot satisfy an IP matcher merely because its positive
range list is empty. IP-shaped Unix names and scoped IPv6 have separate parsing
coverage. No-SNI lookup uses the local host (including a bare IP or DNS-shaped
Unix name) before a configured default, while separate raw address bytes scope
sessions and IP-hash selection without lossy UTF-8 collisions. This does not
establish every address, mapping or module combination.

Two observed upstream defects are deliberately repaired. An after-TLS PROXY
wrapper does not erase real TLS state or relabel an encrypted request as HTTP.
An empty/unparseable untrusted source host cannot preserve client-supplied
forwarding headers. Native removes X-Forwarded-For/Host/Proto in that case,
instead of inventing a source IP or forwarding unauthenticated assertions. An
explicit leading TLS marker is also accepted: it has the same valid meaning as
the implicit marker, despite the pinned baseline rejecting the redundant form.

### Numerical zero after noncanonical integer decoding

The integer byte codecs retain Go's observable raw sign and partial scanner state for Gob and formatting roundtrips. Numerical methods treat a decoded negative-zero representation as integer zero. Comparisons return equality with zero; zero is representable as uint64; sqrt, shifts and bit operations compute their ordinary zero results instead of propagating Go's internal-sign underflow/panic defects. Arithmetic results are canonical, while copying may preserve raw sign for encoding fidelity. A zero exponent is evaluated as zero even if its raw codec sign was negative, so modular exponentiation does not incorrectly require an inverse.

These are intentional correctness repairs, independently checked with integer arithmetic and modular-power/square oracles. Actual Go error/result bytes remain recorded as known differences, not counted as matching behavior. The repairs affect template-private number state and do not modify authenticated TLS snapshots or trust facts.

### Integer codecs, modular roots and primality

Template-private integers support Gob/text/JSON decoding, byte-faithful codec
round trips and modular square roots. Decoder failures preserve the observable
partial scanner state where the Go API does so; JSON `null` leaves an existing
integer unchanged. Modular roots use bounded Jacobi, exponentiation and
Tonelli–Shanks steps rather than an uninterruptible search. This does not add
the entire Go `math/big` API or complete shared `Bits`/`SetBits` backing semantics.

`ProbablyPrime` uses the Go-compatible deterministic Miller–Rabin base sequence
and extra-strong Lucas test. Its local seeded RNG is used only to reproduce
those primality bases, never for keys, salts or security tokens. Odd operands
are limited to 65,536 bits. Each modular multiply/reduction prepays work from
the existing one-million-unit render allowance, at 2,048 conceptual 64-bit
limb products per unit; linear work and RNG setup are charged separately.
Absurd round counts fail before computation. The existing 30-second deadline
and allocation allowance remain in force. These are explicit resource bounds,
not a hard CPU-time or whole-process RSS guarantee.

Primality computation uses a separate admission stage, bounded by the actual
available CPU count up to eight concurrent jobs. It validates arguments and
render ownership before admission, rejects overload without waiting, and
temporarily returns the ordinary template CPU permit while computing on the
same renderer thread. Only that overloaded request receives 503. Normal
continuation fairly reacquires ordinary capacity outside state locks. Memory,
request-tree admission and worker ownership remain held until the actual
worker exits; cancellation, completed trees and shutdown stop continuation.
The control backlink is weak and a foreign or unbound worker cannot bypass
admission. This revision isolates `ProbablyPrime`; other arithmetic retains
its previous execution stage and work fees. It adds no production CPU quota
or affinity and does not change the runtime's use of available CPUs.
