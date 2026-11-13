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

Demand-driven Map reads, their CPU/ownership boundaries, retained native regexp
extensions and remaining provider scope are described in
[`docs/MAP-REPLACER.md`](docs/MAP-REPLACER.md). This does not waive the remaining
provider and full-runtime acceptance gates.

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
remaining header-operation/push combinations and
remaining template receiver methods,
full Go PKIX edge semantics and remaining issuer/trust-loader
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
the entire Go `math/big` API. Template-private `Bits`/`SetBits` now share actual
word backings, including addressable index/range views and atomic multi-output
updates; their resource, capacity and request-isolation boundaries are described
in [Template integer word views](docs/TEMPLATE-INTEGER-WORDS.md).

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


Response templates, content coding, and bodyless messages
--------------------------------------------------------

Only an existing private StaticHeadLength marker from a prepared static entity
allows the templates layer to consume HEAD source bytes. Arbitrary body size
hints do not establish that provenance, and unknown/streaming HEAD bodies are
not read to discover a length. Finite inner output stays available to enclosing
templates, including empty output.

The actual HEAD method remains visible and its template side effects execute.
A separate marker records that HEAD rendering occurred. Such a response omits
Content-Length at finalization, including after deferred headers, and cannot
use the HTTP/3 exact-size fallback to invent zero. It is not re-executed as GET:
that could repeat side effects. This intentionally repairs a baseline defect.
For `{{.Req.Method}}-BODY`, GET has eight bytes while HEAD evaluation produces
nine. Go's CL9 does not establish the selected GET representation length required
by RFC 9110 section 8.6; native HEAD transmits no body and omits optional CL.
Plain static responses, MIME bypass and opaque encoded files retain their
existing trusted representation metadata.

A non-identity Content-Encoding makes the entity opaque at the template layer.
Its bytes, validators and representation metadata pass through unchanged. There
is no automatic decompression, recompression or middleware reordering. Identity
retains ordinary template handling. This repairs the baseline's possible rewrite
of literal template syntax in gzip STORE or raw zstd blocks without updating
codec lengths/checksums. Native preserves the original valid encoded entity.
Compression bytes, streaming framing and omitted optional encoded HEAD lengths
remain observable differences, even when both bodies independently decode.

The shared finalizer clears CL/TE for 1xx, 204 and successful CONNECT. It also
conservatively omits optional 304 length metadata because it has no trusted
selected-200 representation length provenance. A suppressed body does not prove
that length. Legal 304 Content-Type metadata is retained. The request consumer
supplies a genuinely empty body for these bodyless messages before any transport:
H2 otherwise sends handler data and synthesizes a new CL after header cleanup.
The informational writer uses the same centralized header rules.

RFC 9110 reference: https://www.rfc-editor.org/rfc/rfc9110.html#section-8.6
Default native browse UI differs intentionally. Prepared listing HEAD metadata
is handled by the browse layer described below. Single native 100/102 interim
responses are retained despite a baseline fixture emitting duplicates. These
response fixes do not establish complete HTTP or production acceptance.

Successful CONNECT cleanup here applies to the currently supported static
response path. It does not establish CONNECT tunnel forwarding. DATA on an
established H2/H3 CONNECT tunnel belongs to the tunnel transport, not an HTTP
message body; future tunnel support requires an explicit transport owner and
must not route tunnel data through this ordinary bodyless finalizer.


Custom directory templates and prepared browse HEAD
---------------------------------------------------

file_server browse.template_file is executed natively with the same bounded
renderer worker tree, current request/header context, include/import namespace,
virtual request bridge and TLS factory as ordinary templates. Browse uses
text/template semantics, preserving literal bytes and caller-selected HTML.
All public browse/item fields and directory helpers are projected. A file's Tpl
points to the browse-only context. Pagination retains its original slice backing,
including zero-valued unused slots after hidden entries; legitimate reslicing
can recover values outside the visible length.

JSON and text Accept selections take priority and bypass the custom template.
The existing native default HTML UI is retained. Fully prepared native listing
bytes supply trusted HEAD representation lengths for HTML, JSON and text;
custom template HEAD executes its actual method and side effects while omitting
an unproved GET representation length, using the existing HEADc4 marker.

Directory scanning reserves its existing 32MiB work credit before option-owned
buffers. The metadata worker measures retained listing capacities. On a genuine
renderer worker, its Control first charges these bytes, the source moves into
the owned host view, then the directory permit is retired outside locks. The
source wrapper drops listing data before its permit on errors. A custom root
uses immediate CPU admission: it cannot hold unrelated directory credit while
waiting in the ordinary two-second CPU queue. Overload returns 503. The ordinary
admission queue is unchanged. Custom output is wrapped in the existing owned
Vec+Tree byte owner on the worker before crossing the result channel, so delayed
responses, aliases and cancellation retain the actual Tree credit to the last
owner; future completion alone cannot refund it.

Native bounds include at most 100000 directory entries, 8MiB listing/custom
output, 1MiB custom source, one million template work units, thirty-second
cooperative execution checks, bounded header/options input and existing worker
queues. Detailed host/source charges can reject earlier than those individual
ceilings. These are bounded admission/accounting policies, not a proof of a
64MiB hard engine memory cap or full process RSS bound. A retained-local-string
counterexample in the generic engine remains separate work; no counter increase
or post-result length charge repairs that defect. Full TemplateContext/Go stdlib
object methods, complete feature combinations and production gates remain explicit.

Directory-entry ModTime and HumanModTime are always UTC, independently of the
process timezone. This preserves the directory listing contract without changing
general template Date/Time local-time behavior, including the year-one zero
time in unused slice-backing entries.

Plaintext browse preserves raw invalid UTF-8 filename bytes while keeping normal
column alignment. The Go tabwriter reserves byte 0xff as Escape; feeding a real
filename containing that byte into it can make later TAB/LF delimiters lose their
table meaning. Native treats the filename as data and retains alignment. This is
an intentional repair, distinct from the native default HTML UI, and is not
represented as byte equality with the baseline. See the
[upstream tabwriter implementation](https://github.com/golang/go/blob/go1.27.3/src/text/tabwriter/tabwriter.go).


### Preferred ACME chains and certificate data ownership

ACME issuer `preferred_chains` supports `smallest` (ascending or descending
encoded-chain size), `any_common_name`, and `root_common_name`. Selection keeps
stable candidate order for ties; an unmatched preference falls back to the
first size-ranked candidate. A preference chooses a chain rather than adding
trust. Certificate-download capabilities originate in authenticated ACME order
or certificate responses, are limited to HTTP(S), and cannot authorize account,
order, challenge, or arbitrary application requests. Cross-origin certificate
links retain normal server verification and the configured proxy policy, reject
redirects, credentials, fragments and HTTPS downgrades, and must yield the same
leaf DER. Malformed optional alternatives preserve a valid primary chain.

The default runtime shares a 32 MiB live certificate/input payload allowance,
8 MiB network reallocation staging allowance, and 64 MiB decoding/serialization
scratch allowance across issuers, configuration generations and default
standalone wire clients. A separate shared 64 MiB preparation-output allowance
covers unpublished native certificate material until actual resolver/cache
acceptance or destruction. These are admission limits for the named Rust data
and transformations, not a whole-process RSS or crypto-provider heap bound.
Existing resident/manual/status capacities remain separate; accepted snapshots
and independently retained legacy cache values retain their existing accounting
boundaries.

Downloaded checkpoint bodies share their complete data/credit owner when
cloned. Raw reads reserve before allocation; bounded typed checkpoint restoration
transfers its output credit before the IO worker returns. For example, the
checkpoint directory String is parsed under the raw/decode credit and then
transferred to its payload owner, with the old decode credit retained until that
transfer completes. Cancelled callers and completed but unconsumed worker
results retain the actual data owner. Per-object DER shape admission covers the
pinned parser's supported extension structures, and native SAN/JSON working
copies use their own prepayments. Resource exhaustion is treated as a transient
failure, without classifying valid stored material as corrupt or issuing a
replacement merely because inspection lacked resources.

The Rust `CachedProbe::Material` handoff now uses read-only
`OwnedCertificateBundle`; clones share the complete owner. The three public
`CertificateBundle` fields remain unchanged. This is a Rust library API shape
adjustment, not a promise of source or binary ABI compatibility. Key binding
compares the complete original SPKI after strict X.509/duplicate-extension
checks, avoiding an unrelated WebPKI whole-certificate size limit while still
rejecting mismatched keys and malformed DER.

Certificate-chain graphs fetch independent branches concurrently, with at
most four certificate HTTP requests in flight. The slot covers HTTP send and
body collection, not signing, parsing or recursion. Raw URL results share one
fetch within a graph; recursion uses branch-local paths. Candidate order follows
link declaration order regardless of completion timing, and size ranking keeps
stable ties. Existing bounds remain 32 distinct endpoint retrievals, 128 visits,
16 candidates and depth eight. Each endpoint retains the wire's bounded three
badNonce attempts, so certificate POSTs can reach 96; nonce and order control
requests are separate from that endpoint count.

Two intentional native improvements are retained: a complete primary chain
with no configured preference skips optional alternatives, and a failed mandatory
primary `up` path can recover through a complete, verified same-leaf alternative.
A bad optional branch cannot discard an intact primary. Delegated URL, signature,
leaf identity, proxy and memory-admission checks apply equally to concurrent
branches. Waiting for shared input credit requires an already-admitted operation
in the same graph that can progress; otherwise admission returns a transient
resource error instead of waiting indefinitely.

Active graphs and abandoned-task joins register with both their manager's local
tracker and the native certificate group's existing tracker. Outer cancellation
and cancellation during final joins transfer real task ownership before active
graph registration is released; native group retirement waits for those tasks.
Standalone library callers cancel and join their issuance calls before awaiting
`CertificateManager::drain_chain_cleanup`. Running CPU workers and their actual
input/scratch owners remain charged until those workers and results are destroyed.
These named limits retain the memory scope described above, not a whole-process
RSS guarantee.


## Internal physical-output deadline plumbing

Native response controls now distinguish payload production, protocol buffering,
local transport output and actual allocation ownership. HTTP/1 retains encoding
credit through the real reusable connection buffer, observes interim and automatic
100 responses, and defers a ready final response until that earlier boundary has
flushed. HTTP/2 tracks bounded wire spans through HEADERS/CONTINUATION and DATA;
progress on one stream does not extend another stream's deadline. HTTP/3 observes
successful local UDP output, rather than treating QUIC queue acceptance or FIN
submission as transmission. This is local output, not peer acknowledgement.

The internal `native-write-policy` crate preserves the minimum of independently
anchored server/route constraints, including rate/grace clauses whose deadlines
cross. Concrete prepaid policy ownership follows the actual protocol boundary;
logical completion, cancellation and the last allocation owner are separate facts.
The pool accounts for its named Rust policy allocations, not whole-process RSS,
existing HTTP headers, payload producers or QUIC retransmission storage. Native
HTTP/1 and HTTP/2 metadata allowances are exposed separately; callers supplying
retention guards must not make them refer back to their response control.

These transport primitives are opt-in. Native server and route timeout
configuration is now integrated as described in [TIMEOUTS.md](docs/TIMEOUTS.md),
including interim responses, admission, reload and unwind behavior. The named
transport-allocation contracts above remain distinct from full release gates.


## Scoped builtin formatter ownership

Builtin printf now uses an explicitly owned rendering scope. Its shared formatter buffer and temporary numeric buffers reserve capacity before allocation, including old/new growth and Vec-to-Arc conversion peaks. Formatted string/byte results retain refundable loans while any real Arc alias remains. A pressure sweep drops dead Weak backing allocations before refunding their loans, reuses registration slots and charges bounded traversal work.

The actual admitted Tree owns the scope before its Control and memory token fields. Child Frames and httpInclude share that scope. Final response bytes retain Tree ownership through the actual transport owner; cancellation does not retire scope or memory credits while the OS renderer still runs. Dedicated meter callbacks capture only Weak<Control>, with no strong cycle; refunds do nothing after Control destruction. Scope and registration metadata have explicit loans; no permanent-debit orphan strategy is used.

Public bounded formatting scopes reject unknown callback-based hosts by default. The online Frame uses its closed native factory/function set (CustomFuncs remains nil); existing TLS/BigInt/network factories retain their own prepayment contracts. Header map snapshots receive a scoped temporary peak reservation before both execution-argument measurement and formatting. Their preflight reuses the original HeaderMap Arc without allocating another metadata tag. Header snapshots and Values return actual []string (including typed nil missing values), and header byte strings preserve invalid UTF-8.

This is a formatter allocation boundary, not a 64 MiB whole-engine heap guarantee. Parser/AST, namespace and arbitrary host-function allocations, Sprig transformations, container constructors/copies, final Template output and external host retention require independent gates. Allocating a new substring/copy is a new allocation family, not a tracked alias. Arbitrary Rust callbacks that store raw Values beyond the admitted graph are unsupported by this owner contract. The new registry is std-only; old no_std formatting APIs still compile and run, without an implicit unbudgeted online fallback.

`%p` uses actual map identity, pointer pointees and the visible slice backing,
including nil and non-nil empty slices. It bypasses Formatter/Stringer dispatch,
as does Go. Width, precision and flags apply to pointer and invalid-verb output.
A Rust closure's data pointer cannot establish a Go function code address; that
public-library case is explicitly unsupported. Opaque host values without a
native underlying representation also fail explicitly instead of invoking a
formatter to invent an invalid-verb diagnostic. These boundaries and remaining
Go fmt edge cases are not covered by old-formatter regression equality.


## Optional request-header deadlines

`read_header_timeout` accepts signed durations: missing, null and zero retain
60 seconds; a positive duration sets that limit and a negative duration disables
it. No zero-duration Tokio timeout substitutes for the disabled state. HTTP/1
head parsing, initial protocol detection and before/after TLS listener wrappers
propagate that option. PROXY wrappers retain their independently configured
limits; proof listeners retain their separate admission deadlines. TLS admission
still uses its existing CPU, queue, proof, pressure and connection budgets.

HTTP/3 retains its independent handshake/control setup limits while allowing the
request-header resolver limit to be disabled. Pending resolver futures also end
on the actual generation's cancellation signals. Native continues to enforce a
positive HTTP/3 header limit even though the pinned original ignores that setting
there. The existing native negative-PROXY disable behavior is also retained;
the original's immediate rejection is not copied. A genuinely removed listener
cancels admitted non-proof connections that have not entered their first HTTP
service call, including partial PROXY/TLS wrappers. The service-entry decision
and removal cancellation serialize under the admission state lock; cancellation
wakes outside that lock, and descriptor credit remains owned until actual IO
destruction. Existing active requests/bodies and same-endpoint generation reuse
retain their original retirement paths. This does not shorten a later keepalive
request's disabled header timer.


Template response-header bytes
------------------------------

Template RespHeader.Set/Add validate the actual string bytes before mutating
the header map. Valid non-UTF-8 bytes and HTAB are preserved, including Add order.
CR, LF and NUL are rejected without partial mutation. This intentionally differs
from the baseline's H1 CR/LF rewriting and invalid NUL emission; accepting a
malformed response field is not treated as additional useful compatibility.


Request URL templates now retain decoded Go-string bytes for Path/User/Host facts and expose Redacted and MarshalBinary alongside the existing read methods. RawPath, empty absolute paths, ForceQuery, IPv6 zones and numeric port text (including values greater than65535) are retained; request hosts use ordinary URL rules rather than X.509 SAN restrictions. Mutable receiver operations and their ownership boundaries are described below. The shared HTTP Uri parser still rejects percent-encoded DNS host bytes which Go can accept in an absolute-form target; this remains a separate pre-factory transport gap. Other unrepresented request-target forms and full net/url standard-library compatibility remain pending.

Construction and method outputs are prepaid on the existing request Control before temporary vectors, field maps and byte-slice outputs allocate, with cancellation/retired-owner checks. The factory retains only a weak Control backlink and owns its private URL facts; it does not modify authenticated TLS facts. This host prepayment does not establish full-engine heap coverage or replace the narrower refundable printf allocation scope.


Scoped HTTP/3 interim output and metadata
----------------------------------------

An installed native HTTP/3 write control is claimed once and shared from
informational responses through the final response. Interim acknowledgements
wait for actual local UDP transmission, and a hard ceiling remains active while
the producer is paused. A different later control is rejected. A peer header
size rejection before encoding acceptance can withdraw only its unchanged,
unsealed zero-payload boundary; it earns no progress or rate credit.

When a scoped allocation pool is installed, HTTP/3 prepays two fixed sorted Vec
layouts and each actual scalar observation cell before allocation, plus its one
native timer Box. Neither packet progress nor later registration grows these
buffers. Strong observers and weak cached entries retain the same concrete cell
loan through actual destruction; the table buffers retire before their table
loan. A pool cannot replace one already bound to the connection. Legacy unscoped
observation remains available without claiming a prepaid allocation contract.
These named metadata limits exclude existing task/header/payload storage, QUIC
retransmission storage and whole-process RSS. Configuration activation uses the
separately integrated server/route path described in the timeout contract.


Startup-selected directory aliases
----------------------------------

The CLI resolves protected current-user-owned aliases when selecting its trusted
XDG/HOME/cwd application directories at startup. FD-relative metadata/readlink
checks validate source namespace and target identity before returning a physical
root path. The existing store and admin capability walks then apply their own
NOFOLLOW, inode, type, ownership, private-anchor and file checks. API paths never
use this startup resolver; child and terminal symlinks remain rejected.

Resolution permits at most40 links,64 directories and16KiB of path input. It
selects a root without creating directories or claiming a permanently pinned
inode; the real file operations retain their descriptor-based authorization.
This repairs autosave/reload/resume through a legitimate process-configured
external-disk alias without allowing arbitrary API symlink traversal.


HTTP request-target userinfo remains rejected with400, independently of the
URL template factory. This follows RFC9110 section4.2.4's recipient guidance
and retains the existing authority boundary; the baseline's acceptance of such
a target is not used to weaken that check. Redacted/userinfo object operations
are validated separately from accepting userinfo on an actual HTTP target.


Bare-asterisk request targets
----------------------------

A bare `*` URL retains an empty RawPath, unlike `/*`. General `OPTIONS *`
returns an empty200 with Content-Length0 outside application routes, preserving
authority validation and the configured strict SNI/Host boundary. An unfinished
HTTP/1 request body makes that one connection close after the response rather
than waiting in an unbounded post-handler drain. Bodyless requests retain
keepalive, while H2/H3 streams remain independently handled. Invalid star-query
targets retain parser rejection.


ACME JSON `account_key` selects an already existing account using a literal PEM
or a global environment/file placeholder. Preparation runs once per configured
issuer and generation on the blocking CPU lane. P-256, P-384, RSA and Ed25519
keys use the native signer; the CA may independently reject an algorithm (the
stock isolated Pebble policy rejects EdDSA despite a verified valid JWS).
Unknown or empty placeholder expansion rejects provisioning. A malformed PEM
is an issuer-local failure, allowing an independent fallback issuer to run.
An empty literal retains the ordinary automatic-account behavior.

The explicit key path uses `onlyReturnExisting`; it cannot register an unknown
key or fall back to an unrelated email-selected account. A fenced public
metadata sidecar is keyed by canonical directory URL and RFC 7638 signer
identity, contains no PEM, and shares lookup results across concurrent groups.
Native leaves the historical email account files intact, avoiding the original
implementation's same-email overwrite. Pending orders still require the same
authenticated account URL: switching credentials cannot take over an active
order, and restoring the original credentials resumes the original URL. A
forced reload rereads a file placeholder even if its path and configuration
text are unchanged; the current certificate continues serving until a new
certificate is published. Existing CSR, lease, CAS, key-veto, OCSP and storage
publication gates continue to apply.

Rust library callers gain `AcmeIssuerConfig::account_key` with type
`Option<Arc<ConfiguredAccountKey>>`; struct-literal callers must supply that
field. This is a Rust source interface extension, not a cross-language plugin
ABI. Signing-key/control input residency is distinct from certificate-chain
payload pools; this feature does not claim a whole-process heap or RSS bound.
`test_ca`, the independent ZeroSSL API issuer and DNS solver/resolver/ECH
options remain explicitly unfinished. HTTP CA sources are described below.

Controlled HTTP/2 informational output
------------------------------------

Opt-in physical-output controls can bind before an automatic `100 Continue`
without sending a header or starting an idle clock. Interim and final headers
share one uniquely claimed stream owner. Controlled informational acknowledgments
wait for actual HEADERS/CONTINUATION flush; socket acceptance alone is insufficient.
A stalled stream is reset independently, while a hard ceiling also applies
while its application source is pending. Completed physical boundaries preserve
their actual completion before timer checks.

One bounded ready-final slot retains the response while an interim is pending.
Callers prepay its generic body size with the native H2 allowance; existing
header/payload storage and connection tables retain separate actual owners.
Replacing route clauses between acknowledged boundaries requires the same pool,
no pending output and no final payload progress, preserving all outer clauses.
Controlled HTTP/2 CONNECT tunnel handoff and route/server timeout configuration
are now integrated; their ownership and physical-progress semantics are
specified in the CONNECT and timeout sections below.


Server client-authentication CA pools now resolve native `pki_root` and
`pki_intermediate` providers, including nested `combined` sources, during the
tracked configuration preparation transaction. They reuse the current
generation's native PKI authorities and storage; no CA lookup or I/O occurs
in a handshake. `pki_root` exports the single root certificate, while
`pki_intermediate` exports the complete configured intermediate chain. The
raw published/admin configuration retains its original provider definitions.
The existing client-certificate modes, proof-of-possession checks and PKIX
path validation still apply to the resolved anchors.

The PKI app must be configured or already provisioned by the generation's
internal issuer. The local authority may then be provisioned lazily, and an
unknown non-local authority fails preparation. Independent authorities use
at most four concurrent provisioning futures. Provider nesting, authority
references and prepared trust material are bounded; short transformation
scratch uses the existing shared pool and is released by the actual CPU
worker. Persistent prepared configuration/trust outputs retain their existing
control/output ownership boundary; this is not a whole-process heap bound.
A failed reload keeps the previous working TLS configuration. This entry
covers server client-authentication pools; upstream consumers and HTTP CA
providers are described below.


Server client-authentication storage CA sources
---------------------------------------------

The storage trust provider resolves configured PEM keys from the selected
FileStorage or the generation’s global storage before TLS activation. Nested
combined providers and key order are preserved. Independent providers and
independent key reads each use at most four concurrent futures; certificate
decoding and config transformation run on the bounded CPU lane. The existing
FD-relative NOFOLLOW, ownership, stable-read, regular-file and size checks also
apply to CA reads. No filesystem or network operation is added to handshakes.

An explicitly empty pool does not inherit old or system trust. A forced reload
rereads the same key, and a failed candidate preserves its working predecessor.
Provider depth, key count, aggregate PEM/DER bytes and certificate count have
explicit limits. Actual input and transformation scratch retain their shared
credits until the real worker releases them. Prepared trust output then enters
the existing configuration ownership boundary; this is not a whole-process RSS
bound. System-root scanning propagates resource exhaustion instead of silently
skipping a valid root. HTTP providers are described below.


Reverse-proxy TLS trust-provider consumers
-----------------------------------------

The upstream TLS `ca` provider now follows the same generation preparation
transaction as server client-authentication providers. PKI and storage inputs
resolve before transport provisioning; inline, file, system and combined pools
compile on the existing bounded provisioning lane. The typed traversal includes
main, error, named, nested subroute and intercepted/proxy-response route trees.
Active upstream health checks use that prepared transport; handshakes perform no
CA-provider I/O. An explicitly empty pool trusts no roots, and cannot silently
fall back to system trust or a previous generation. Conflicting legacy root-CA
fields are rejected before publication. A failed candidate retains the working
configuration. Unknown/unprepared providers still fail explicitly. Remaining issuer/PKIX behavior remains separate work; this addition does not claim complete TLS compatibility.


Mutable template request URL views
---------------------------------

Within an admitted render graph, URL Parse/JoinPath/ResolveReference return
new private views and UnmarshalBinary atomically replaces its receiver's facts.
String, fmt.Stringer, JSON, query helpers and supported URI placeholders read
that state. Current and original URL views stay separate. A first form parse
observes the current query; parsed form values retain their cache. include
shares its graph, while httpInclude captures an independent request. Transport
URI/routing and authenticated TLS facts are not rewritten by these views.

Addressable URL fields remain references across template variable assignment,
and/or and with. Interface/function arguments resolve after all argument
expressions finish; list and include arguments retain snapshots. Template dot
can still carry a field reference. This new Value::Field ABI is registered only
for the URL factory's string/bool/User fields. A closed host gate checks actual
source identity and the same Weak<Control>, and 32 retained Arc identities bound
resolution and detect cycles without allocator-address reuse mistakes. Owner
retirement, cancellation, incompatible values and resource failure are errors.

Object gains a guarded dynamic_stringer callback, ArgKind gains ByteSlice and
GoPointer, and TypedSlice::from_list now returns Result. Existing Rust callers
must propagate that result. Values constructors reject direct or nested retained
field references before creating mutable backing, using a callback-free scan
bounded to 16,384 nodes and depth32. Existing Arc snapshots release each cell
lock before inspecting children. Map and scalar-only Values writes also reject
references. This preserves the existing trusted-host boundary for opaque Rust
captures rather than claiming that arbitrary captures are acyclic or prepaid.

AppendBinary preserves byte backing/view aliases when capacity permits, and
uses Go byte-slice growth when a new backing is required. Nil []byte, non-nil
empty slices and typed nil non-byte slices stay distinct. URL has Stringer,
not a fabricated fmt.Formatter. Struct formatting with an actual supplied
layout now recurses with the original verb and flags. Userinfo supplies an
immutable formatter-only layout of its real private fields; this does not make
those fields accessible to template field lookup or JSON. The optional HTML
feature retains its separately recorded baseline build errors. GoStringer and
private layouts which have not been provided for other host types, including
time.Time/time.Location, remain separate gaps.

URL host allocation/work is conservatively prepaid from the same Control;
this does not expand refundable printf coverage to every allocation family or
promise a whole-engine heap/RSS cap. Online results retain their real Tree until
the last response owner or worker retires. Future field reads fail after render
completion. Arbitrary raw host Value escape is outside that owner contract.
The existing raw-query form UTF-8 materialization limitation, HTTP request-target
userinfo rejection and percent-host HTTP parser gap remain separate boundaries.


HTTP/3 automatic continuation and early control binding
------------------------------------------------------

On the first actual read of a nonempty or unknown request body with
Expect:100-continue, the native H3 driver sends and acknowledges100 before
allowing body reads to proceed. Unread and known-empty bodies do not trigger
an automatic head. Explicit and automatic100 for the same exchange are
suppressed after the first acknowledged continuation; unrelated streams
continue independently. This is a verified extension: the pinned Go H3
implementation does not generate that automatic continuation.

A concrete shared Flow carries first-read demand and optional write-control
metadata through the existing request task. It adds no per-frame task or
unbounded queue. Prebinding emits no head and starts no pending-write idle
clock; the same actual control governs informational and final output. Waker
clone, wake, replacement destruction and retained-control destruction occur
outside the Flow mutex. An independent process-wide2MiB metadata quota prepays
1024bytes per admitted Flow before allocation. A full quota rejects only a new
request stream with H3_REQUEST_REJECTED; existing owners retain their credits
until their actual last reference retires. Other protocol, task, header,
payload and Quinn allocations keep their separate ownership boundaries.

Template request URLs also distinguish transport provenance: H2/H3 pseudo-field
reconstruction does not expose an artificial scheme/authority in the ordinary
server URL. Request.Host retains the independently validated authority. H1
absolute-form targets, CONNECT authority-form and virtual include targets keep
their own representations. Implemented server/route timeout activation and the
remaining full release gates are tracked independently.


Formatter reflection and static layouts
---------------------------------------

Object.reflected_fields is a producer-prepaid immutable layout for formatting,
separate from public fields and JSON. Its strong values and names participate
in execution measurement and bounded structural/graph checks; collection
constructors and writes cannot hide field references or a self-reference in
this layout. The current Userinfo layout contains only its actual immutable
username, password and passwordSet scalars. Formatting can reveal that private
password just as Go does; String/Redacted and JSON retain their own rules.
Other TLS/BigInt factories are not given invented private layouts.

Static, dynamic and named Stringers preserve width, precision and zero padding;
T/p/sharp-v and bad-verb reflection do not call Stringer. Bad-verb diagnostics
format the underlying value with the original flags, and decimal/default integer
precision and boolean zero padding follow Go. Reflected pointers use their
actual native pointee identity. Addresses vary across processes and engines;
no portable address literal is promised. Native output bytes remain intact.

The existing scoped printf account, callback admission, work/cancellation and
last-result/Tree lifetime remain in force. Static layouts do not establish a
whole-engine heap cap or cover arbitrary opaque Rust captures. Host values
without their real reflection/GoStringer representation remain explicit gaps
rather than being replaced with a Stringer fallback for unsupported reflection.


Configuration-time HTTP CA sources
----------------------------------

HTTP CA modules now perform configuration-time HTTP(S) GETs for both server
client authentication and the typed upstream CA consumers above. Successful
2xx PEM bodies ignore non-certificate blocks; gzip, URL Basic authentication,
HTTP proxy environment settings and bounded redirects are supported. Relative
URL references preserve configured userinfo, while absolute redirects without
userinfo do not inherit those URL credentials, including across ports on the
same host. Explicit HTTP endpoints are allowed; HTTPS redirects cannot downgrade
to HTTP. HTTPS fetch trust can itself use the supported CA modules, including
nested HTTP, PKI and storage sources. Custom server names and handshake deadlines
apply only to origin TLS, preserving the dial/CONNECT target, HTTP Host and an
HTTPS proxy's own TLS name. This retains correct Native behavior where the
pinned Go implementation drops the configured server name and does not wire
its handshake timeout.

Four HTTP CA network slots and existing external byte credits are shared across
generations. Each body reserves input credit before network allocation and
output credit before conversion; general certificate scratch is borrowed only
inside bounded CPU decoding, never across network waits. Limits include 4 MiB
raw and inflated bodies, 16 MiB each of aggregate raw/decoded/DER data, 4096
certificates, 256 endpoints/logical GETs, depth eight, ten requests per redirect
chain, a 30-second fetch deadline and a 120-second preparation deadline.
Independent endpoints progress concurrently and preserve configured order.
Failure or cancellation cancels and drains started sibling work through the
owned service task before returning. A failed candidate keeps the old site;
handshakes and health probes use the published pool without source I/O.
Persistent prepared trust retains its existing output accounting boundary;
these temporary credits are not a whole-process/RSS limit. Explicit TLS
renegotiation uses the prepared compatibility transport described below.

### Native request URL provenance and rewrite path components

Template URL projections retain scheme and host from the actual original
transport target, independently of later method and path rewrites. HTTP/2 and
HTTP/3 pseudo-field authorities remain Request.Host facts; origin-form requests
and extended CONNECT expose an origin-form URL. Authority-form CONNECT retains
its separate URL authority. Virtual template requests retain their own target.

A method-only rewrite no longer changes the path. URI setters update a path and
query component without interpreting a literal scheme-looking path as a new
origin, or cleaning dot segments with a generic URL parser. Percent escapes are
decoded and re-encoded using the Go setter's path behavior. An explicit bounded
component constructor supports relative and empty rewrite paths without widening
the normal wire request-target parser. Other rewrite modifiers and fragment
projection are separate compatibility work; controlled CONNECT body/upgrade
acceptance is not established by these URL changes.

Reverse-proxy HTTP transport `tls.curves` now selects real outgoing key exchange
groups through the same mapping as incoming TLS policies: X25519, P-256,
P-384, P-521 and X25519MLKEM768. It applies to every typed proxy consumer and
active health checks, including Caddyfile `tls_curves`. Native preserves the
configured first-occurrence order and removes duplicates; the pinned Go TLS
implementation instead reorders its allowed set by its own preferences. This
Native ordering enhancement is retained. Empty/null fields retain the current
provider defaults. Invalid groups or invalid field types reject the candidate
and keep the old working site. The outgoing default group profile remains a
separate compatibility item; this stage covers explicit curve configuration.


Default outgoing TLS groups
---------------------------

Outgoing TLS clients use an independent provider with the pinned Go default
groups: X25519MLKEM768, P256MLKEM768, P384MLKEM1024, X25519, P-256, P-384 and
P-521. Incoming Rustls and QUIC defaults remain unchanged; explicitly configured
upstream groups preserve their first-occurrence order. P384MLKEM1024 reuses the
existing AWS-LC components and hybrid exchange layout with RFC 10024 wire sizes.
The same outgoing profile covers configured upstreams, HTTPS CA sources and
other native HTTP clients, without replacing the process-wide server provider.
Real independent single-group peers, strict HTTP traffic, public ClientHello
facts and shared-client issuance/trust regressions cover this behavior.

The pinned baseline only recognizes TLS1.2/TLS1.3 as server protocols. Legacy
TLS1.0/TLS1.1 names fall back to modern defaults and do not enable those wire
versions; they are not an unimplemented baseline feature.
Remaining issuer features are separate unfinished work. PKI KeyPair formats other
than empty/pem_file are likewise not implemented by the pinned baseline.

CONNECT and WebSocket ownership
------------------------------

Ordinary successful CONNECT responses retain their handler body. HTTP/1 omits
Content-Length/Transfer-Encoding and closes the opaque response at EOF instead
of accepting another HTTP request on that connection. Application-requested
upgrades remain distinct from these ordinary handler responses.

HTTP/2 and HTTP/3 extended WebSocket CONNECT requests are translated to an
upstream HTTP/1 GET/Upgrade handshake. The translated 200 is published only
after validating the single matching upstream Accept against this actual
attempt's final Key, including configured request-header replacements. Retries
receive independent generated challenges. Invalid upstream handshakes fail the
request with 502 before a raw bridge is started; unrelated streams continue.
This validation repairs a pinned-reference defect and is not error-page parity.
Ordinary HTTP/1 upgrades preserve transparent proxy behavior.

The raw bridges retain per-session, DATA and concrete protocol-table allocation
owners through cancellation and the real last IO owner. No-rule controls add no
idle/rate/hard timeout. Completion means local transport write/flush (or UDP send
for HTTP/3 source DATA), not remote acknowledgment or successful application
consumption. Separately bounded QUIC transport/retransmission state is not
represented as already-freed source payload or as a whole-process memory cap.
These integrated paths still require the final combined release gates above.

Tracing and transfer policies
-----------------------------

Native tracing is connected to committed provider generations, ordinary response
bodies and actual detached upgrade owners. HTTP/protobuf, gRPC, optional gzip,
TLS/mTLS and console export use independent bounded transport/work lanes.
Telemetry pressure drops recording/export work without rejecting business
requests. Stream cancellation records Error where the inspected reference can
leave Unset. OTEL_SDK_DISABLED suppresses native export while propagation can
continue. See docs/TRACING.md for configuration,
resource bounds and reference differences.

Server hard read/write deadlines and progress/rate controls are active in the
normal runtime. Original HTTP/1 header/body epochs are preserved; HTTP/2 and
HTTP/3 scopes remain per stream. Route error unwind restores prior clauses
without erasing an outer server hard deadline. Requests and upgrade actors
retain their concrete generation and allocation owners through reload and stop.
See docs/TIMEOUTS.md for units, defaults and scope bounds. These paths do not
waive any outstanding full-project acceptance gate.

### Explicit outgoing TLS renegotiation

Upstream HTTP transports and HTTPS CA sources accept `never`, `once` and
`freely`. Default/`never` retains Rustls; explicit `once`/`freely` selects the
complete OpenSSL SSL transport with the same prepared native trust verifier,
configured client identity and outgoing key-exchange profile. Direct, Unix,
SOCKS and CONNECT paths preserve their transport identity. HTTPS proxy TLS
uses its own hostname; origin overrides do not replace that hostname. HTTP/1
upgrade clears ALPN, and HTTP/2 renegotiation is rejected. Each completed
renegotiation must retain the exact initial leaf DER, including when a new
leaf uses the same trusted signing key. Count limits use actual Finished
messages; an abbreviated or ignored request is not counted as a full exchange.

Initial certificate path/name/time validation uses OpenSSL's public retry-verify
boundary and the original native verifier on a bounded CPU worker. Network
readiness remains asynchronous and OpenSSL's path verifier is replaced, rather
than evaluating the untrusted chain twice. Verification CPU/queue admission is
shared across clients (running: available CPUs capped at 32; waiting: eight
per CPU, bounded to 32..256). Runtime/service scopes close admission and wait
for real workers and abandoned results. The CPU permit is released when the
completed worker's result is taken; a separate handshake entry token spans
the returned result until the handshake exits. Established streams retain their
certificate observations independently. Closing the scope fences admission
under its mutex, then wakes cancellation/task waiters outside that mutex.
Exact-wire certificate observations
have a separate aggregate 64 MiB credit pool, a 1 MiB message limit and at most
64 certificates. This is not a whole-process/OpenSSL heap limit.

Protocol, suite, ALPN, peer certificates, stapled OCSP bytes, session reuse and
exporter values exposed by this outgoing transport come from its live SSL
connection; this does not add OCSP-revocation policy to native upstream trust.
The outgoing connector does not replace incoming TLS snapshots or the default
server/HTTP3 provider. Managed client identities are covered below.
The generic configuration still rejects invalid renegotiation levels
before publication, and a failed HTTPS CA preparation retains the old site.


### URI rewrite modifiers and upstream request views

The rewrite handler and `reverse_proxy.rewrite` execute method/URI setters,
prefix/suffix removal, ordered substring and Go-regexp path replacements and
query rename/set/add/replace/delete operations. Query operations use the pinned
reference order, including repeated values and old-query placeholder snapshots.
URI components retain literal scheme-looking paths and decode/re-encode path
escapes once. Fragment and alternate RawPath facts remain available to native
URL projections; fragments are not transmitted upstream.

Upstream rewriting uses an independent attempt request. Its direct matcher and
transport see the changed method/URI; its replacer continues to see inbound
facts. Exclusively borrowed values/providers move into that view and return on
normal completion or cancellation, avoiding a full metadata-table clone.
Retries reuse the prepared rewrite while recalculating per-attempt headers.
A rewritten GET/HEAD may omit its outgoing body without consuming the inbound
body needed by later handlers. Extended WebSocket upload owners remain separate
from the HTTP handshake body, including when its method is explicitly GET.

A shared 128 MiB rewrite allocation pool spans generations. It covers live
component projections, admitted arguments, bounded-worker workspace and attempt
metadata through their actual last owner. Individual component/expanded-argument
and encoded-URI limits are 4 MiB, arrays admit at most 65,536 operations, and
regexp/query work has an independent 150 ms bound (query value scanning also
has a 64 MiB work allowance). These are resource admission bounds, not CPU
thread counts or a whole-process RSS cap. Expensive transforms run on the
existing bounded regexp CPU lane. Exhaustion fails the affected rewrite before
unfunded growth; other requests and the committed configuration remain active.

Documented repairs/extensions include no-op empty path-regexp rules, preserving
unknown-length GET/CONNECT uploads when forwarding to HTTP/1, correct zero
outgoing FastCGI body length, and removing a HEAD representation length from a
response sent to an original non-HEAD client. Native ordinary CONNECT forwarding
retains the handler response body and authority/path request target; generic
Hyper tunnel upgrades remain the default unless its native opt-in is selected.
Raw Go-string query facts are retained internally; octets illegal in an HTTP URI
are percent-encoded only in mechanical transport storage. General raw-byte path
matching and additional nonstandard CONNECT wire forms remain separate bounds.


Byte-preserving request routing and push
---------------------------------------

HTTP path matching uses the pinned Go simple Unicode lower table and byte/rune
path.Match rules, including escaped slash patterns, invalid UTF-8 rune errors,
character classes and stars which can advance into a multibyte rune. Filename
selection and Caddyfile import matching reuse the same primitive. The adapter's
existing one-wildcard import safety restriction is retained; this does not claim
support for arbitrary filesystem encodings or all Windows path rules.

Path-regexp matching cleans decoded path bytes on the existing bounded CPU lane.
The regexp search interprets each invalid UTF-8 byte as one RuneError while
capture offsets map back to exact original bytes. Named, numeric, unmatched and
zero-width captures preserve reference behavior. Raw captures reach byte-aware
response, header, template and CEL consumers without lossy text conversion.
Capture input, temporary normalization/search workspace and retained results are
admitted separately; the retained credits move with exclusive upstream views
and retire with the actual request owner. A per-request cumulative capture cap
and the shared rewrite workspace bound return overload rather than an unbounded
allocation. These bounds do not establish a whole-process memory ceiling.

Native explicit/Link push and its bounded protocol ownership are documented in
`docs/PUSH.md`. Combined acceptance includes actual parent completion/reset,
interim heads, target/header behavior, backpressure and old/new generation
separation through reload. Shared HeaderOps replacement is described in
[HEADERS.md](docs/HEADERS.md). Remaining replacer/provider scheduling and other
release gates stay separate; accepting a handler name is not full compatibility.


Native ACME server
------------------

The native `acme_server` handler provides account/order/authorization lifecycle,
three real challenge types, verified CSR issuance through the existing PKI,
certificate download, persistent revocation and dual-signature key rollover.
It reads and writes the original Bolt representation with checked snapshots,
same-descriptor cooperative locking and bounded COW publication; no Go runtime
or unchecked bbolt-rs backend is used. Existing unknown tables and record fields
are retained. File/record/operation capacities, retained worker/output credits,
correctness repairs and the distinction from Smallstep's non-Caddy APIs are
described in [ACME-SERVER.md](docs/ACME-SERVER.md). Global defaults have the separate ACME DNS scope documented below; this does
not establish every TLS DNS consumer, all PKIX edge semantics or full-project acceptance.


Process-manager state
---------------------

Linux serving processes now publish bounded native readiness, reload and stop
notifications for `Type=notify`. The inherited endpoint is captured only by
`run`; short-lived control clients and ordinary library use do not announce
readiness. Failed initial preparation never claims readiness, and notifications
cannot return to ready after stopping begins. See
[PROCESS-NOTIFY.md](docs/PROCESS-NOTIFY.md) for scope and failure behavior. Final
acceptance under the target machine's real service manager remains a deployment
gate, separate from datagram/credential validation.


Numeric TCP listener ranges
---------------------------

JSON HTTP listeners now expand inclusive numeric-IP TCP port ranges through
the existing staged socket ownership, reload and failed-candidate rollback
path. Bare numeric IPs and omitted ports retain the reference's ephemeral-port
semantics. IPv4, IPv6, wildcard addresses and the optional TCP network prefix
are supported. The existing per-server limit applies to expanded endpoints:
at most 1024, checked before allocating the expanded range. Unknown listener
networks and Unix HTTP listeners remain explicit gaps;
this does not claim every NetworkAddress or Caddyfile site-address combination.


### Explicit incoming TLS1.2 CBC policies

Explicit policies support ECDHE-ECDSA and ECDHE-RSA with AES128-CBC-SHA and AES256-CBC-SHA. These TLS1.2 connections use the complete pinned OpenSSL SSL record/session engine; Native does not implement CBC record padding, MAC verification or encryption in Rust. Default server policies, TLS1.3 and HTTP3 retain Rustls. Configured suites are an allow-set: available AEAD suites stay ahead of CBC and AES128 ahead of AES256. CBC negotiates HTTP/1.1; mixed policies can negotiate HTTP2 with an allowed AEAD suite.

The original resolver selection, selector/SNI policy, on-demand permission/manager path and live leaf/SPKI veto authorize the same credential. There is no certificate-source I/O inside SSL. Client authentication runs the original Native path/pin/purpose verifier once on the owned crypto worker; SSL separately authenticates CertificateVerify and Finished. Require/request modes retain proof of private-key possession. Snapshot peer DER, verified paths, negotiated group, TLSUnique, resumption and owned binary-label exporters reflect the actual completed handshake. Original stateful cache and standard/distributed ticket ownership stay bound to selected chain, policy and name. A live key-compromise veto prevents application I/O and resumption.

The SSL object moves through bounded CPU steps; socket I/O stays asynchronous. Process-shared Rust temporary pools limit engine/output buffers to32MiB, input/queued writes to16MiB and session serialization staging to4MiB. Raw peer certificates retain the existing shared64MiB admission. These named temporary limits do not bound provider/FFI heap, persistent cache/snapshot owners or whole-process RSS. Cancelled waiters cannot refund data still held by real workers. Listener/request admission closes before graceful drain; record-worker admission stays open for existing HTTP tasks, then closes and joins after HTTP connections and upgrades finish. Hard-stop still terminates blocked connections at the grace limit.

The small native-openssl-src builder obtains unchanged OpenSSL C sources from exact openssl-src400.0.2+4.0.3. Its tls-deprecated-ec build feature makes legacy certificate curves such as P224 available without adding them to configured/default key-exchange groups or enabling TLS1.0/1.1. P224 certificates work when the peer explicitly advertises that curve. Native retains RFC8422's requirement that EC certificate curves respect the peer's supported groups. The pinned Go pair accepted P224 without advertising it; that observed difference is recorded separately and does not cause weaker SSL verification. Security policy is local to the explicit compatibility context; no global security level is changed.

Isolated actual-main checks cover four suites, selection/preference, modern and TLS1.3 controls, Caddyfile, P224/P256/P384/P521/Ed25519 and RSA1024 through RSA8192, leaves above64KiB, same-connection exporters, mTLS and invalid CertificateVerify, modified CBC ciphertext, session/ticket rotation, real reason1 plus restart, real ACME TLS-ALPN-01 proof, parallel large keys, reload, graceful drain and hard-stop. Evidence and fixtures stay local. Issuer and PKIX residuals remain separate; this addition does not claim complete TLS compatibility.


Graceful in-flight resource retirement
-------------------------------------

Closing incoming HTTP admission no longer cancels the shared DNS or template
resources needed by requests already executing. Their cancellation-bearing
fences, proxy cleanup admission and crypto admission close after HTTP connection
and upgrade owners have joined, then real workers and detached results retire.
An in-flight dynamic-upstream DNS query or template include may finish within
the configured grace period. New external requests remain fenced; a finite
grace deadline still forces blocked requests to stop. Resource retirement does
not substitute an artificial timeout for a configured unlimited drain.
Explicit force shutdown and runtime drop close cancellation-bearing resources
immediately, independently of whether the caller subsequently waits for joins.

Local PKI admission and shutdown
-------------------------------

Local CA work is registered under a closed-state fence before it is submitted
to its executor. Cancellation notifications, tracker-close notifications and
executor-side payload destruction run outside that fence, including shutdown
and maintenance-future cancellation. Already accepted work keeps its task and
queue ownership until the actual worker or payload has retired; abandoning a
caller does not release capacity early. No trust installation or issuance
authorization is added by this lifecycle change.

## Global TLS resolver defaults

`apps.tls.resolvers` is retained as configuration and supplies ACME server
DNS-01 TXT defaults when a handler has no nonempty local list. Unused/shadowed
defaults are not eagerly dialed; actual lookups reuse the bounded owned DNS
engine. UDP/TCP, IPv4/IPv6, null/empty fallback and true endpoint selection have
local differential coverage. Unsupported resolver networks are rejected during
staging instead of deferred dial failure. This does not enable DNS-provider
certificate issuance or redirect HTTP/TLS proofs and unrelated clients. See
[global resolver scope](docs/GLOBAL-TLS-RESOLVERS.md).

Accepted ACME issuance across HTTP retirement
--------------------------------------------

ACME handlers distinguish admission-drain notification from their business
owner's hard-stop signal. An already accepted proof or CSR-finalize request
may complete within the configured grace period; grace expiry or explicit
force still cancels that request. A separate business-drained receipt keeps
old certificate services available until that generation finishes or is
forced. Publication completion still observes acceptance closure, so loading
a new generation does not wait for old requests to finish.

At process stop, HTTP owners from all generations join before root certificate
cancellation and CA shutdown. Detached CPU/storage work still has its own
supervised owners and join phase; a business-drained receipt alone does not
claim those workers have retired. These dependencies do not serialize ordinary
requests, separate generations or independent authority jobs, and do not add
an artificial timeout to an unlimited grace period.

Shutdown receipts also terminate when their owning executor disappears before
the stop actor runs. Task registration occurs under lifecycle admission, while
executor submission and possible synchronous payload destruction run outside
that mutex. An aborted stop actor fences the runtime and completes both the
admission and business-drain receipts as forced. Starting a new stop without
an executor returns an error without publishing a half-started stop; existing
receipts remain readable without an executor.

ACME configuration validation scheduling
----------------------------------------

Large resolver lists and ACME route-reference validation run on existing bounded
CPU workers instead of HTTP executor threads. Certificate-service validation
remains generation-owned and completes before CA material is loaded or
provisioned. HTTP capability validation preserves its original ordering and
errors, including duplicate route references; it does not skip invalid inputs
or substitute successful configuration parsing for actual ACME execution.
Cancellation does not release CPU capacity while an accepted worker still owns
its configuration. Route traversal cooperatively yields between handlers.

Numeric TCP address families
----------------------------

Numeric `tcp4/` and `tcp6/` listener addresses retain their kernel address-family
semantics, including wildcard and inclusive port ranges. TCP4 normalizes IPv4
mapped literals and the unspecified IPv6 wildcard to IPv4; TCP6 rejects IPv4
and mapped literals and sets IPv6-only on both TCP and HTTP/3 UDP sockets.
Unqualified TCP keeps its existing dual-stack wildcard behavior. IPv6 scope IDs
and duplicate/ephemeral declaration behavior are retained.

Shared-socket ownership includes IPv6-only mode. A reload cannot silently reuse
a descriptor with a different mode. A distinct declaration may acquire its own
real descriptor when the operating system permits, without changing the old
socket mode; failed candidates leave the existing generation intact. An IPv6-only wildcard does not count as an IPv4 challenge
capability. A default dual-family challenge lease reuses the actual IPv6
listener and acquires a separate IPv4 listener, retaining/releasing each real
descriptor independently, including listeners initially bound with port zero.
Hostname TCP listeners are described below; Unix and file-descriptor HTTP listeners remain separate gaps.

Template HTTP header accessors
------------------------------

`http.Header.Clone` is exposed on request headers, trailers, response headers
and the Caddy response-header wrapper. It copies the current field table and
values, retains the `http.Header` type and nil-map semantics, and does not add a
Clone method to the separate `textproto.MIMEHeader` adapter. Copies prepay
through the existing template-tree allowance before allocating; retained table
capacity is included and resource failures remain errors. Control callbacks
and budget admission run outside the header mutex. This named copy allowance
is not a claim about total allocator or process memory.

UserAgent and Referer accessors retain the actual wire bytes, including strings
that are not UTF-8. Cookie lookup reuses the existing byte-oriented selection
parser: an invalid cookie pair does not discard a later valid pair in the same
header field. Nil typed maps use `type(nil)` for sharp Go formatting. Direct
request-header Set/Add/Del calls remain rejected by templates, as in the
baseline whose methods have zero return values; the Caddy RespHeader wrapper's
supported mutation methods remain available.

Template response-header mutations prepay their host allocations before
constructing names or values. Set/Add check the existing 128KiB template field
allowance on the resulting map under its mutex; Set removes the replaced
field's full prior value count from that calculation, and Del remains able to
remove a field. The allowance includes per-field metadata as well as name and
value bytes. It is enforced during mutation rather than relying on an initial
header check or emitting an oversized error response. This is an explicit
resource boundary; ordinary within-limit wrapper behavior is unchanged.

Certificate-service executor admission
--------------------------------------

Service construction and owned preparation require a current Tokio executor.
They return an explicit error before creating/admitting task ownership when no
executor is present, rather than panicking during task submission. An owned
preparation rejected at that boundary does not initialize inventory or poison
the service; preparation on a live executor remains available. Task registration
and possible executor-side synchronous payload destruction remain separated
from service admission locks.


### Managed outbound client certificates

The HTTP transport supports `client_certificate_automate`, including the Caddyfile single-name `tls_client_auth` form. Names are always registered with the existing certificate services for acquisition, status maintenance and renewal, even when a valid manual certificate is already cached. The actual CertificateRequest selects a valid cached credential using its DER issuer names, signature schemes and negotiated TLS version; a missing compatible credential fails the requested authentication. A server that does not request a client certificate receives none. In the last valid encoded UTC second of a manual leaf, a compatible cached managed successor with strictly later expiry can take over early, provided it is also outside its own last valid second. This avoids the observed millisecond-scale expiry race without relaxing verification or retrying application requests; it does not guarantee against arbitrary network delay or clock skew. Callback selection performs no network or storage I/O. When static client certificate files and automated identity are both configured, the static pair is still validated during provisioning, but the automated resolver takes precedence during authentication. An automated-selection mismatch does not silently fall back to the static pair.

Default Rustls client handshakes use one lazily provisioned runtime per shared resource owner, created on the provisioning CPU lane. The existing OpenSSL once/freely engine performs its operations in the owned SSL CPU lane. Cancellation and forced stop close admission without waking callers under its fence; graceful shutdown joins HTTP owners before joining the client runtime. Deadline errors retain their timeout category. Selected client credentials retain leaf/SPKI vetoes through signing and application I/O, including reload and durable restart.

Isolated actual-main evidence covers Internal and dual-purpose Native ACME issuance, ordinary renewal, manual-leaf expiry followed by managed takeover and another renewal, real CRI selection, live signed reason1, same-key sibling leaves, reload/drain/hard-stop, large-RSA CPU progress, Caddyfile, nested/error/response/named consumers and health probes. Frontend HTTP/1, HTTP/2 and HTTP/3 compose with the existing HTTP/1 and HTTP/2 upstream transports. Outgoing HTTP/3 and remaining issuer/PKIX capabilities are separate inventory items; this entry does not claim whole TLS compatibility or a process RSS bound. A serverAuth-only ACME certificate is not reinterpreted as clientAuth: the upstream's normal purpose and trust validation still applies.


HTTP/3 TLS metadata consumers
-----------------------------

HTTP/3 requests carry the completed QUIC connection snapshot into the same
access-log and FastCGI TLS extensions used by TCP TLS. Access logs report actual
negotiated version, cipher, ALPN, SNI and resumption facts; FastCGI receives
`HTTPS`, `SSL_PROTOCOL` and `SSL_CIPHER` from that snapshot. Request headers do
not synthesize TLS facts, and reduced access-log capture retains its existing
omission policy. Isolated real HTTP/2 and HTTP/3 TLS 1.3 mutual-authentication
checks cover sequential and overlapping streams, including FastCGI backend
environment observation, on macOS and Linux with automatic and single-CPU
runtimes. This does not claim coverage of every cipher or resumed-session case.


### Reverse-proxy outgoing TLS1.2 CBC compatibility

The reverse-proxy transport supports the four Go-default ECDHE AES128/256 CBC-SHA suites with RSA or ECDSA authentication. Modern default connections still start with Rustls. A single compatibility attempt is eligible only after the exact typed handshake_failure error and a complete seven-byte plaintext fatal alert as the first peer record, before any ServerHello or Certificate. The failed TCP connection is dropped before a fresh TLS1.2-only CBC connection is attempted. This alert does not reveal the server's private failure reason; successful CBC negotiation confirms a compatible CBC peer. DNS, I/O, EOF, certificate/name/signature failures, timeout, cancellation and resource errors do not qualify. Hyper receives a usable connector result only after authentication succeeds; this mechanism never replays an application request. Dial attempts share one aggregate dial-time allowance, and both TLS attempts plus the compatibility redial share the original TLS deadline. Explicit no-timeout settings remain no-timeout.

The configured once/freely engines offer AEAD before this same finite CBC subset. Static and absent client identities now use the complete owned SSL engine, as managed identities already do; the older public ClientConfig/Stream interface remains available. SSL construction, key exchange, signatures and records run in the bounded CPU lane, retaining the existing staged verifier, actual CertificateRequest selection, credential veto, handshake identity and shutdown ownership. No TLS record, padding or MAC implementation is added. Configured trust, groups, session-cache policy and HTTP/1 upgrade ALPN semantics remain intact.

Go-valid CBC+HTTP/2 upstreams are supported. This is a legacy-peer compatibility choice: [RFC9113 section9.2.2](https://www.rfc-editor.org/rfc/rfc9113.html#section-9.2.2) discourages these suites and permits a peer to reject them. TLS renegotiation after the HTTP/2 preface remains forbidden under [section9.2.1](https://www.rfc-editor.org/rfc/rfc9113.html#section-9.2.1); allowing CBC does not loosen that guard. Incoming server CBC policy is separate.

Local actual-main verification covers HTTP/1 and HTTP/2, all four suites, static/managed authentication, non-idempotent POST bodies processed once, strict verification failures, pre/post-negotiation alerts, shared TLS and real cumulative TCP-dial budgets, IPv6, signed reason1 across pooled connections/reload/restart, renegotiation, large RSA keys and one-MiB records with ordinary-request progress, cancellation and process stop. Direct engine verification compares same-connection exporter bytes, actual negotiated facts and disabled resumption, and confirms observed input/output/certificate credits return after the actual owners stop. These bounds do not claim process RSS or OpenSSL heap accounting.

This layer applies to reverse-proxy consumers, including nested routes and health checks through their shared connector. HTTP CA-loader, ACME and other HTTPS-client CBC behavior remain separate caller work; adding these constructors does not claim universal outgoing TLS compatibility or complete issuer/PKIX support.

The reverse-proxy CBC-only retry sends TLS_FALLBACK_SCSV through the public SSL mode. A TLS1.3-capable peer can therefore reject a forced TLS1.2 fallback; direct modern TLS remains unchanged and a genuine TLS1.2-only CBC peer can still connect. This protects protocol-version fallback, not suite-only selection within TLS1.2, and does not reveal the server's private early-alert reason. The finite Go-default CBC subset remains the explicit legacy-peer compatibility policy.

Default reverse-proxy Rustls client handshakes, with or without a managed identity, use the shared bounded client TLS executor. Provisioning creates that executor on the configuration CPU lane; its runtime derives workers from the CPUs available to the process. Native static/absent and managed identity paths use the complete owned SSL engine. CA-loader, ACME, metrics and other HTTPS callers remain separate work; this does not claim every outgoing TLS handshake is off reactor.


Certificate URI SAN template URL methods
---------------------------------------

Certificate `URIs` now use the same guarded `*url.URL` view as request URLs.
`Parse`, `ResolveReference`, `JoinPath`, `AppendBinary`, `UnmarshalBinary`, and
`Clone` are reachable with their typed arguments. Clone copies the URL and its
Userinfo; Parse, ResolveReference and JoinPath return independent URL receivers.
A certificate URL and request URL may resolve against each other within the
same admitted render. Repeated certificate field/index/range reads share the
same private URL identity within that render. A later render starts from the
original signed certificate; mutable views never update DER, trust, routing or
TLS authentication facts. This intentionally avoids the baseline's observable
sharing of mutated certificate URLs across requests on one connection.

Initial certificate projection retains IA5 admission and its decoded ASCII
domain checks. ASCII controls in the fragment follow the baseline URL parser:
string output escapes them, and RequestURI omits the fragment. The preceding
URL components retain the existing control-character checks. Later ordinary
URL methods are not subjected to certificate-SAN admission again. Decoded Go
string bytes and RawPath/RawFragment remain distinct, including escaped invalid
UTF-8 path bytes. Construction and copying are prepaid on the existing render
Control; no separate allowance or general host-value provenance bypass is added.

A shared [certificate URI SAN admission guard](docs/URI-SAN-ADMISSION.md) now
rejects invalid URI syntax during material and peer-certificate admission rather
than waiting for template projection. It preserves the existing verifier and raw
DER, including strict/skip-trust distinctions and source-specific root-bundle
contracts. Client-authenticated session resumption remains independently disabled
by native server policy; the syntax hook does not enable it. Full PKIX equivalence
is not established by this finite guard.

### Explicit native TLS in HTTP CA fetching

Reqwest's explicitly prepared native TLS origin and HTTPS-proxy paths use the complete owned SSL engine. SSL construction, handshake crypto and authenticated records use its bounded CPU lane; socket IO remains asynchronous. Origin SNI, the HTTPS proxy's own SNI and empty CONNECT ALPN, verifier and client identity, renegotiation policy, timeout and connection facts are retained. Direct TlsInfo visits exact authenticated peer DER through the same Guard evidence outside its mutex; existing CONNECT TlsInfo=None behavior is unchanged. The older public ClientConfig/Stream API remains available. This does not move default Rustls CA/ACME/metrics handshakes or add CBC compatibility to these callers.

Completed SSL CPU work returns its running permit from the real worker. Actual data, the existing admission ticket and tracker remain with an unconsumed result, preventing a single-slot nested-TLS wait cycle without returning data credit early. The process-shared admission limit (32..256, derived from available CPUs) now counts waiting, running and completed-unconsumed jobs together; it previously bounded only waiting jobs in addition to separately retained running slots. Full admission still returns an explicit WouldBlock error and recovers when an actual result owner drops. Worker cancellation does not return active CPU capacity early; spawn and payload/ticket destruction occur outside the scope admission mutex. These are bounded ownership/scheduling claims, not OpenSSL heap or process-RSS accounting.


TCP hostname listener snapshots
------------------------------

HTTP `tcp`, `tcp4` and `tcp6` listener declarations accept hostnames without
performing DNS in the parser or provision-only validation. Candidate preparation
resolves each name once on its own bounded blocking lane, then seals the selected
IPv4/IPv6 answers. Like Go's TCP listen selection, unqualified TCP selects the
first IPv4 answer when one exists; family-qualified declarations select their
corresponding family. This is one selected endpoint, not all-answer fanout.
Independent names use a rolling set of at most the lane's admitted concurrency;
a slow name does not prevent sibling lookups from starting. The complete
snapshot is required before publication. On failure the batch cancels its
bounded async waiters while actual libc jobs retain their own lifetime.
Automatic redirects, configured ACME challenge binds and TCP/HTTP3 UDP pairing
use that same immutable candidate snapshot. Reload performs fresh resolution;
failed resolution or binding does not replace a working generation or its proof
leases. A port-zero TCP/UDP pair uses the actual port from its own TCP socket.

Original expanded network, original host spelling and individual port form the
logical declaration identity. Repeated identical declarations are rejected;
different aliases use distinct real `SO_REUSEPORT` owners even when DNS chooses
the same physical address. Different port-zero aliases bind independently.
Connection distribution is the operating system's behavior: Linux and macOS
need not choose the same distribution. A connection stays with its accepted
binding. Established H1/H2 connections under compatible policy look up current routes
by stable declaration while retaining the actual old local address, including
when DNS moves.
Fresh candidate resolution and this DNS-move handoff are verified native
behavior, not a claim of Go reload equivalence. HTTP/3 keeps its existing
transport retirement policy. The existing TLS identity/client-authentication
policy checks still reject
incompatible old connections; a changed declaration follows normal retirement.

`StagedAddress::only_v6` is an additive public Rust source field. Bound capability
records read the actual `IPV6_V6ONLY` socket option; IPv6 family alone is not a
dual-stack claim. Dormant provision-only planning has no bound socket and cannot establish a
live dual-stack claim. An IPv6-only wildcard cannot satisfy a
configured IPv4 challenge bind: the broker acquires a real IPv4 proof owner and
retains/releases that descriptor independently. Empty wildcard binds combine
actual capabilities from both families: an existing single-family wildcard is
borrowed and only the missing family is rented, without changing the original
socket mode. Selected IPv6 scope IDs participate in proof coverage, so a
link-local address on another interface cannot satisfy the requested scope.
Existing provider implementers
retain a conservative snapshot-only default for the new `resolve_bind_host`
method: empty/numeric hosts work, and absent hostname snapshots fail without a
second DNS lookup. Rust clients using `StagedAddress` literals must provide the
new field.

The listener lookup lane has at most min(available CPUs, 8) running calls and
32 waiting calls, allocated from the common blocking headroom with compression
headroom retained. This is bounded admission, not physical thread isolation.
Known native lookup payloads are prepaid (16 KiB per lookup) and known immutable
plan metadata shares a 64 MiB pool; the original input configuration, existing
HTTP engine allocations and opaque libc/NSS allocations are not a whole-process
RSS guarantee. A waiter has a 30-second resolution deadline and cancellation;
an already-started libc call cannot be interrupted, so its actual worker keeps
its slot, tracker and concrete credit until it returns. Shutdown joins that real
work. `listener_resolution_diagnostics()` exposes only read-only lane, tracked
job and retained-credit observations. Plan/result graphs keep their allowances
until their actual final owner retires, not merely until an await completes.

This layer does not implement Unix, unixpacket, inherited-fd or large-range HTTP
listeners, and does not add a configuration-level custom resolver plugin API. The existing
1024-entry per-server range capacity remains explicit. Current native hostname
runtime validation covers macOS and Linux ARM64; unsupported system resolver
platforms return an explicit error. Private acceptance includes strict H1/H2/H3
with IPv4/IPv6/port-zero aliases, same-policy DNS-move continuity, incompatible
client-auth policy rejection, real HTTP-01/TLS-ALPN-01 signing through an isolated
Go ACME CA, and cancellation while actual lookup workers remain blocked. Private
fixtures, keys, helper programs and output do not belong in this repository.


HTTP/3 request receive retirement
--------------------------------

A handler that finishes without consuming its HTTP/3 request body retires the
receive half with H3_NO_ERROR, including when the adapter has moved its actual
receive handle into a pending read future. This does not cancel a valid response
or turn a real request/response cancellation into success. Content-length
violations retain H3_MESSAGE_ERROR, and explicit protocol errors retain their
original codes. Reader cancellation remains distinct from malformed framing.

The real receive handle, pending future and connection references drop before
the final per-request Flow metadata credit. Its fixed scalar allowance includes
the added Incoming layout, but does not bound every channel, packet buffer or
provider allocation. No synthetic receive stream or detached cleanup task is
created. The opt-in Quinn receive-stop operation and generic RecvStream
destructor release the connection mutex before invoking or destroying removed
reader/driver wakers. Other Quinn polling and waker paths are not claimed to
have been converted by this change.

Ordinary TLS scalar placeholders
--------------------------------

The seven snapshot-backed TLS scalars (`version`, `cipher_suite`, `resumed`,
`proto`, `proto_mutual`, `server_name`, and `ech`) under `http.request.tls.`
are available to ordinary text, headers, URI rewrites, demand-driven Maps and
template `ph`/`placeholder`. They use the same negotiated metadata and scalar
formatting as the typed provider; typed booleans and plain-HTTP nulls retain
their existing types. Plain HTTP renders an empty string and health probes
provide no request TLS value. ALPN remains raw bytes in byte consumers.

Missing or failed TLS metadata is an error in fallible expansion and Map
consumers, rather than an invented empty/false value. The existing Option-only
lookup compatibility API reports absence; its String form also cannot represent
non-UTF-8 ALPN, while byte lookup preserves it. Variable/capture/global provider
precedence is retained. Ordinary `client.*` and unknown TLS suffixes remain
rejected before configuration publication; certificate-derived providers are
not enabled by this scalar change. ASCII case-insensitive scalar suffixes
retain the native typed provider's existing extension.

Fallible direct scalar String lookups reject non-UTF-8 ALPN even when Maps are
configured. Generic Map-output Option decoding retains its prior absence
behavior for byte values that cannot be represented as UTF-8.


### Root-managed default Rustls CA and ACME connection scheduling

Root-managed HTTP CA loaders and ACME managers run default Rustls connection establishment on one lazily prepared client TLS executor per CertificateResources. Configuration CPU preparation creates the executor; workers follow the CPUs available to the process. The owned connector clone is polled for readiness and called on that executor, covering DNS/TCP, HTTPS-proxy TLS, CONNECT and origin TLS while retaining the original roots, verifier, proxy/environment policy, SNI, client identity, ALPN and timeouts. HTTP/JWS construction, application requests and response-body processing keep their existing execution paths. This layer adds no CBC retry and does not move default Rustls authenticated-record processing to a different runtime. Explicit native SSL connections retain their existing complete owned-engine path.

A generation has an independent external scope owner. Actual queued/running futures, completed but unconsumed results, errors and returned connection IO retain concrete scope and metadata owners; IO keeps no handshake running/queue permit. The optional reqwest IO mapping preserves proxy flags, Connection, ALPN/TlsInfo and vectored IO delegation. Idle connections remain cancellable even while they retain the runtime. Services close only their generation after accepted business work drains; final Root drain then joins the shared executor. The last external NativeBackend handle reuses the existing owned graceful stop, including configured delay/grace, with an explicit force fallback when no usable runtime can start that stop. Internal tasks and IO do not retain this external handle.

New connection/scope wrapper layouts borrow from an 8MiB subtype limit and the existing 256MiB certificate external-byte pool simultaneously. These are two limits on the same allocation, not two physical payloads. Full admission explicitly fails new work, existing pooled destinations can continue, and raw CA downloads keep the remaining aggregate budget. Future/result/IO owners hold byte loans and tracker tokens through their actual destruction. Parent cancellation-tree Vec high-water capacity is separately reserved before construction, including old/new growth overlap and temporary grandchild adoption during cancellation, and is not refunded with a destroyed child. Bounds derive from the current layout and minimum prepaid connection frame; current 64-bit examples reserve 100440B per scope and 106616B per master and admit 82 otherwise-empty scopes. These are layout examples, not configured limits or claims about provider heaps, runtime internals in general, TLS backing data, or whole-process RSS.

Standalone public CertificateServices::new and AcmeWire constructors preserve their prior unscoped behavior. Metrics/tracing exporters and other HTTPS callers remain separate scheduling work. CBC compatibility in default HTTP CA/ACME clients remains separate caller work. Scope completion includes all its actual IO and cannot serve as a receipt for one issuer leg; an error retaining that scope must not wait on its own generation tracker.

ACME send and response-chunk failures preserve their real reqwest source beneath the existing ProtocolError context. Only an explicit wire cancellation check/select adds the typed AcmeRequestCancelled context, retaining ProtocolError status, uncertainty and display. A coincident cancellation flag on a signing failure does not receive that marker or discard the original failure. Confirmed local connection admission/stopped/scheduling failures retain typed local control and resource sources. Cancellation evidence alone does not prove actual TLS-worker retirement or authorize issuer fallback: that decision also requires the independent parent/deadline state and a genuine single-leg retirement receipt.

Explicit client authentication and session resumption
----------------------------------------------------

A non-null `client_authentication` object, including `{}`, disables session
tickets and runtime session-cache resumption across native TCP Rustls, explicit
TLS 1.2 CBC and HTTP/3. This matches Caddy 2.11.7's intentional protection
against authentication privilege escalation across virtual hosts. An empty
object does not request a client certificate. Omitting the object retains the
existing ordinary session-ticket behavior. Authenticated resumption is not a
missing baseline capability; enabling it safely would be a separate native
enhancement, rather than removing the existing gates.

The existing full-handshake client modes, proof of private-key possession,
DER/URI syntax checks, configured trust and leaf verifiers remain unchanged.
In particular, `request` and `require` do not acquire chain trust/time validation
just because resumption is disabled. Library-only restoration of parsed
certificate metadata does not establish new authorization or enable runtime
resumption. See [`docs/SESSION-TICKETS.md`](docs/SESSION-TICKETS.md).
