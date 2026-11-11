# Native compatibility implementation

Standalone Rust implementation in progress for the existing Caddy deployment.
This is a separate project from GoEdge. The default build provides configuration
utilities and migration inspection. The opt-in `native-run` build can serve
supported configurations in development. Production replacement requires
the remaining compatibility and rollout gates.

The user requires original functionality and module behavior to remain available,
especially automatic certificate issuance and renewal. See COMPATIBILITY.md for
the full baseline and the current incomplete status. Compilation and parsing
success are not evidence that a proxy, plugin, or certificate issuer is complete.

Current commands:

- `fmt [FLAGS] [FILE]`: format, preview differences or overwrite a Caddyfile.
- `adapt [FLAGS]`: adapt implemented Caddyfile directives, with compatible env-file
  and flag behavior; `--validate` provisions supported runtime modules when built
  with the opt-in `native-run` development feature.
- `validate [FLAGS]`: load the original config source/env/adapter path, remove raw
  metadata and provision supported modules without starting listeners or issuing
  ACME certificates. This also requires `native-run`.
- `inspect-config FILE`: extract a privacy-safe configuration feature inventory.
- `inspect-storage ROOT`: inspect CertMagic certificate/account layout and validate
  supported certificate/key pairs without writing or registering an ACME account.

Provisioning validation may initialize local storage or PKI material, while the
inspection commands remain read-only. Formatting can overwrite the explicit input
file. These configuration and inspection commands do not serve traffic, renew
certificates or reload a running process. Inspection reports must not contain private keys, account email,
account URLs, domain names, or credential values. Schema pointers use documented
redaction for dynamic map keys; they are not Admin API mutation paths.

The library also includes the Caddy v2.11.7 lexical tokenizer and token helpers,
including quoted strings, heredocs, source line tracking and import-chain line
boundaries. A source-preserving parser now handles server blocks, imports,
snippets, arguments, environment expansion and the compatible scalar helpers.
Its synchronous parsing and filesystem work require a bounded blocking worker.
The HTTP configuration adapter and its product integration remain incomplete.

The library also contains bounded HTTP-01/TLS-ALPN-01 challenge ownership and a
validated TLS certificate snapshot resolver. These are integration primitives,
not an automatic-certificate service. Challenge leases are scoped by registration
generation, and challenge certificates must never serve ordinary TLS handshakes.
Failed certificate candidates retain the previously published snapshot. The
caller still needs to provide listeners, ACME account/order handling, persistence,
renewal scheduling, issuer selection, OCSP and transactional configuration reload.
Certificate `upsert` uses bounded optimistic publication. A competing full reload
or another publisher can exhaust its eight attempts and return `retry required`.
The future certificate manager must retain the validated candidate and retry with
bounded backoff outside handshake and publication locks; it must not treat that
result as a successful renewal or re-register an ACME account because of it.

The TLS provider retains ring cipher suites and key exchange, uses AWS-LC for
RSA private signing keys larger than 4096 and up to 8192 bits, and restricts
OpenSSL 4.0.3 to the additional key/signature compatibility backend.
Certificate/private-key matching remains mandatory before publication. The
native certificate resolver also prepares separate TLS 1.2 generic EC-signature
and TLS 1.3 curve-bound profiles at load time. The negotiated protocol controls
the final choice; a TLS 1.2-only certificate cannot authorize a TLS 1.3 handshake.
Full certificate-path, name, time and purpose validation remain required.
HTTP handshakes now choose a final profile only after protocol negotiation and
bind session admission to the certificate actually selected. Preselection never
authorizes a TLS 1.2-only profile for TLS 1.3. Upstream client-certificate profile
integration and complete transport policies remain separate compatibility gates. The
process installs this explicit provider before constructing implicit TLS clients;
an incompatible existing default is an error. This key compatibility primitive
does not implement a production TLS listener or certificate lifecycle.

The `admin_json` library provides configuration traversal, mutation, Go-style
JSON number/Unicode encoding and raw-path ETags. Reads can borrow the immutable
configuration snapshot instead of cloning the full document. This is a DOM
primitive, not an exposed Admin endpoint or a configuration transaction backend.
Input and mutation paths currently have a 256-level resource limit, below the
original decoder's 10000-level limit; that difference remains a migration gap.
Raw JSON adaptation response encoding has a separate path that preserves number
lexemes, duplicate keys and existing escapes. Its measured raw depth limit is
9999, and its output budget includes the response wrapper and newline. This
codec does not change configuration-map normalization or ETag encoding.

The `certstore` library preserves CertMagic account/certificate layout, with a
separate private transaction journal, bounded blocking I/O and canonical group
gates retained through cancelled writes. A recovery report isolates unresolved
groups; it is not permission to ignore their blockers or reissue certificates.
Scoped recovery remains mandatory before an issuance operation. Use one stable
native-state directory for each data root, one active issuer implementation and
a local filesystem. Recover all outstanding transactions before returning the
store to the original server. This does not provide distributed fencing with Go
writers or establish NFS or physical power-loss guarantees.

Certificate snapshots also expose an OCSP attachment primitive. The caller must
authenticate the response before attachment. Updates bind to the exact DER
chain and loaded instance, and expired responses are excluded from new
handshakes without I/O or certificate parsing. Required certificate material
and optional staples use independent budgets; optional cache pressure cannot
prevent certificate publication. Byte-identical reloads can inherit unexpired
verified status while rejecting stale publishers. A policy change must use a
fresh resolver or explicitly clear inherited status. Conflict, capacity and
expiry errors are distinct types. This primitive is not an OCSP fetcher or a
complete certificate-policy service.

The official Caddy v2.11.7 and CertMagic v0.25.6 implementation provide the pinned
behavioral reference. The original Go plugins have no native cross-language ABI:
module configuration and behavior require individual Rust implementations.
Unimplemented modules must remain explicit gaps, never silently ignored or
advertised as supported. No Go runtime is permitted in the replacement's normal
request or certificate path.

The library now includes isolated HTTP and Admin runtimes. HTTP request and
response bodies stream with backpressure, including long transfers and upgrades;
configuration snapshots keep accepted requests independent of later publication.
The Admin runtime bounds connections, requests and queued configuration writes,
retains accepted writes after client disconnection, and separates parallel reads
from serialized publication. Management requests have a 16 MiB default
per-request body limit. Uploads and raw JSON adaptation responses use separate
64 MiB aggregate budgets; a busy body lane returns 503 and reserves capacity
for reads and shutdown. Ordinary configuration reads have their own 64 MiB
response budget; slow reads keep the charge until their output is released.
Queued JSON writes keep bounded input bytes and parse at the serialized write
worker, after conditional validation. These budgets do not cap the entire
expanded configuration tree. HTTP custom adaptation and warning responses
reserve output capacity before encoding; a failed reservation cannot publish a
candidate. A queued adapted configuration owns its bounded canonical bytes.
An external adapter's own allocations before returning its value remain outside
this endpoint budget. Native serving remains
opt-in while full production compatibility is being validated.
Unsupported modules and transport options fail validation instead of being
silently ignored. The vendored HTTP crates contain opt-in compatibility changes;
see vendor/VENDOR.md and THIRD-PARTY-NOTICES.

ACME library work now includes bounded signed protocol requests, persistent
account/order checkpoints, isolated issuer fallback, scoped recovery and renewal
scheduling. Cached certificate publication emits a discovery hint as well as
new issuance; consumers must rescan after a missed hint or a full replacement.
The automatic-HTTPS product lifecycle, certificate-policy integration and the
remaining issuer/module behaviors are still migration work. Library checks and
isolated CA interoperability do not make the inspector a production server.

The OCSP library authenticates cached and fetched status, performs bounded
background retrieval and refresh, and preserves the original cache format.
Independent responders have separate concurrency limits. Missing `nextUpdate`
uses an explicit configurable freshness limit (24 hours by default), which is
stricter than the original unlimited cache lifetime. Verified negative status
clears staples and produces notices even when bookkeeping fails. Notices alone
do not implement managed-certificate renewal or withdrawal: root lifecycle,
startup restoration and shared leaf-policy integration remain incomplete.

Certificate resolvers now require an explicitly shared, bounded leaf-status
guard. Verified revocation facts survive newer Unknown responses and certificate
reloads; a matching failed renewal can withdraw the leaf without interrupting
existing connections. Selection reads one atomic policy snapshot and separately
checks certificate/staple expiry. Loader registrations bind immutable certificate
validity, and inactive expired records can be reclaimed. Diagnostic latest-status
exports are not persistence. Authenticated OCSP producers now update a pinned leaf state before cache
ownership, cancellation and diagnostic bookkeeping checks. External inventory
readers use immutable getters so the response and shared state stay bound. The
root still must create the shared guard, restore authenticated cache before
acceptance, and implement renewal ownership and bounded retries; these lifecycle
gates remain incomplete.

Build with the current official stable Rust, pinned to 1.99.1 for this phase.
Keep all QA, fixtures, private configuration, keys, logs, and build output in the
current LocalOps task. Do not create GitHub Actions. The public source repository
is [vruru/caddy-rust](https://github.com/vruru/caddy-rust). Publication covers this
project's reusable source, necessary documentation, and licenses only. Private
deployment data and other projects are outside its scope. This standalone project
must not be published into another repository.

HTTP upstream TLS now loads explicit trust material during preparation, validates
client identities, derives supported dynamic server names per request, and bounds
connect/handshake/read/write waits. HTTP-only ALPN follows the original absence
of an ALPN extension. Static and managed leaves share revocation policy. This
is isolated transport support; transactional listener integration remains work.

The shared duration parser preserves the original day-unit float conversion and
rounding while rejecting integer overflow instead of wrapping. JSON integer
durations retain nanosecond semantics. Callers keep their own negative-value
policy and error context; this helper does not provision a runtime.

HTTP file descriptors, disk reads, metadata and password verification have
separate bounded admission. A slow download does not hold a disk-read worker.
The per-handler bcrypt cache follows the configuration's optional `hash_cache`;
omitting it keeps verification uncached. These limits and cache ownership are
library behavior, with remaining transport and product integration tracked in
COMPATIBILITY.md. The process explicitly bounds Tokio's blocking pool while
choosing async worker threads from every CPU available to the process.

Production runtime construction detects this process's available CPUs on every
startup rather than hard-coding a worker count. Test cgroup CPU limits remain
confined to isolated QA containers and must not enter production service units.
The runtime constructor is a product-integration primitive; the current
inspection CLI does not create it.

The public Caddyfile adapter entry point now assembles the implemented global
options, handlers, named matchers, routes, certificate loaders and TLS policies.
It preserves issuer/policy alias behavior while enforcing aggregate work,
materialization, source and output budgets. `format_caddyfile` exposes the bounded
source formatter. Unsupported directives remain explicit errors; the remaining
adapter directives and their runtime integration are still migration gates.
Go map-order ambiguities use deterministic input order, with compatible observed
outputs rather than an attempt to reproduce randomized iteration.

HTTP listener staging now reserves a non-cloneable publication ticket; graceful
stop waits for its owner and forced stop discards late publication. Compatible
TLS connections can reuse current routes after reload; rotated or withdrawn
identities receive a complete response and graceful connection drain. Existing
streams retain their accepted lifetime unless an explicit close delay applies.
Session resumption checks the actual stored leaf and current ClientHello policy.
These HTTP lifecycle components do not complete the root backend or module set.

New Ed25519 account keys retain the existing PEM label and use PKCS8 integer
version zero for generic-reader interoperability. The outer structure uses the
pkcs8 encoder; the inner CurvePrivateKey octet string has a fixed two-byte prefix.
Existing account-key files are imported without rewriting their identity.

Known revocation now vetoes cached and terminal-checkpoint readiness without
changing issuer/winner selection. A stored revoked leaf starts a fresh-key cycle.
This does not implement root force-renew failure evidence, withdrawal, rescan,
compromised-key archival or startup OCSP restoration; those remain migration gates.

The local PKI library preserves existing CA files, journals certificate/key pair
updates and signs authorized CSRs through independent authority workers. Optional
trust installation is explicit and supervised, including atomic Java-store
updates. The caller must authorize names, own leaf keys and integrate generation
lifecycle and rollback recovery. Native CA interoperability was verified in
isolation; RootBackend, CLI, admin endpoints and automatic-HTTPS integration
remain incomplete. Mac Keychain writes and legacy NSS dbm execution are unverified.

Admin configuration writes now stage candidate identities and listeners before
publishing the actual root generation. Normal rejection keeps the predecessor;
post-publication failure either restores retained application state or fences
the runtime. Unix socket permission changes preserve inode ownership, delay
broader admission until publication, and recheck queued writes and stops. Linux
uses connection-bound supplementary groups; macOS exports positive group hints
without treating absent hints as authoritative non-membership. After a started
mode transaction, subjects relying on ACLs, capabilities or unusual filesystem
credentials can be conservatively rejected; those OS-specific compatibility
boundaries remain explicit. These library contracts do not complete the native
RootBackend, CLI or certificate lifecycle integration.

Grouped certificate/account reads now keep the actual file descriptors pinned
through pending-journal, path-identity and final descriptor checks. They reject
concurrent generation changes without waiting for an issuance lease; individual
key reads retain their existing old-inode snapshot behavior during replacement.
Private read buffers have a fixed validated size and a zeroized EOF probe, so
file growth cannot leave a reallocated secret buffer. This contract relies on
atomic replacement of published material and does not establish protection from
a same-user adversary, in-place external writers or physical power loss.

Manual certificate inventories now share one resolver with serving and OCSP for
each generation. Per-server tag filters apply to complete chain identities
before selection, and tagged servers cannot fall back to managed certificates.
The HTTP runtime validates inventory identities, counts, names and shared leaf
guard before publication. Unknown tags are rejected before publication, stricter
than accepting an unusable configuration. Challenge listeners use scoped shared
leases; releasing one owner cannot close a listener retained by a staged or
active generation. These contracts do not complete the remaining modules,
remaining product lifecycle or production integration.

The certificate application library now owns generation-scoped preparation,
manual inventories, policy/store resources, business cache probes and dormant
maintenance. Business acquisition starts after explicit activation; Admin
identities retain synchronous acquisition. Rollback accepts an authenticated
in-memory predecessor, and shutdown joins owned work. Uncertain ACME requests
retain their intent across caller cancellation and storage-lease loss. This
component still has explicit feature and CPU-offload gaps; it does not enable
the inspection CLI to serve production traffic.

Caddyfile adaptation now also preserves named-route reachability, error-route
assembly, URLPattern configuration, authentication/tracing/map directives and
the implemented storage/metrics options. Nested bind/TLS directives retain the
original parsing side effects and sorting behavior, including shared manual
certificate tags. Map matrix expansion is prepaid against the same adaptation
budget. Adapter JSON equivalence does not establish execution of every emitted
module: named routes, tracing, URLPattern and remaining server/module options
still have explicit runtime gates. The remaining proxy/directive families and
complete runtime behavior continue to block production replacement.

Certificate preparation, material publication, ACME signing and OCSP certificate
inspection now dispatch their CPU work through owned bounded blocking admission.
The actual worker retains its permit through caller cancellation. Immutable
material caches validated keys, certificate times, purposes and issuer names;
current time and shared revocation policy still apply at use. This removes those
CPU operations from async request workers without starting business issuance
before activation. TLS handshake CPU isolation and remaining lifecycle/module
compatibility are separate integration gates; the CLI remains an inspector.

The Caddyfile adapter now assembles the reverse_proxy, forward_auth, php_fastcgi,
intercept and response-copy directive families, including HTTP/FastCGI transport
options, response matchers, dynamic upstream sources and selection policies.
Range expansion and recursive source/fallback trees share the adapter's prepaid
resource ledger. `formatting_difference` exposes the original formatter comparison
for command-line use. These are adaptation contracts; executing every emitted
transport, policy and handler remains a separate production gate.

CLI environment files are applied at single-threaded executable startup before
crypto/runtime construction. Existing process variables are preserved, repeated
files use the original CSV semantics, and a file named `-` remains an ordinary
environment file even when configuration is read from stdin. Formatting supports
original overwrite/diff precedence and preserves existing file modes and symlinks.
The diff implementation has explicit work/output budgets. Serving, validation
provisioning and the remaining lifecycle commands are still migration gates.

The HTTP library now retains generation-owned shutdown delays and request/body/
upgrade activity. Removed bindings keep their original role during delay; current
bindings win immediately. Positive grace forces only its own generation, while
zero or omitted grace drains without a default timer. Old and current delays run
concurrently, and global stop preserves every generation's remaining admission
window. Read-only retirement receipts distinguish business admission from shared
socket ownership. Force still reaches older upgraded streams after admission
closes. Root certificate/CLI integration and full production acceptance remain
separate gates.

Scoped certificate cache removal now requires an opaque owner and an exact
publication receipt, including resolver, loaded generation, complete alias set
and full chain identity. Stale work cannot evict a renewed or replaced instance;
metadata-only OCSP updates preserve valid ownership. Cache eviction does not
create a global revocation fact, and accepted TLS streams retain their owned
keys. On-demand permission, renewal and HTTP request integration remain separate
compatibility gates.

The configuration adapter now translates global/site logging, access-log host
association, built-in log writers/encoders/filters, per-listener server settings
and metrics options, and the ACME-server directive with its explicit PKI CA
configuration. Server selection preserves the original Go unstable sorting
behavior for overlapping listener settings. These are configuration conversion
capabilities; the corresponding runtime modules remain separate implementation
and acceptance gates. Logging output, ACME-server signing, server protocols and
metrics must not be advertised as operational from adaptation success alone.

The native Admin library can capture an exact candidate's read-only publication
completion signal. Waiting for a delayed predecessor to stop accepting business
requests happens outside the ordered configuration write worker, with bounded
response ownership. A disconnected caller releases only its response wait;
accepted publication and retirement cleanup remain owned by the backend. Stop
admission bypasses the pending-response budget, and shutdown joins those response
tasks. A response interrupted after publication has a distinct error category.
Normal backend shutdown also has an explicit unbounded-drain facade; a caller's
wait deadline must not cancel the backend's owned drain. The application Root
and serving-command integration remain separate development gates.

The opt-in `native-run` library feature now exposes a native application backend
that stages HTTP listeners, prepares manual/managed certificate services and
candidate-specific Admin identities, then publishes one configuration generation.
Failed candidates preserve their predecessor; compensation uses retained verified
material rather than fetching or issuing certificates. Owned shutdown survives
caller timeout/drop and retains delayed predecessor services until their actual
HTTP admission closes. Provision-only validation uses the same server path
without binding listeners or activating certificate jobs. The opt-in serving
CLI uses this backend. Remaining module and CLI acceptance gates still apply.

OCSP restoration and CPU verification now use distinct admission budgets. The
same certificate CPU budget is shared across default application policies and
configuration generations, while standalone OCSP managers keep their own bounded
CPU budget. A full set of cache-restoration candidates cannot deadlock by each
holding one restore slot and waiting for another to inspect its certificate.
Actual blocking verification owns its CPU permit through completion, and no CPU
permit spans responder network or storage I/O. Signature checks, certificate
identity, revocation/guard policy and cache freshness remain mandatory.

CLI typed decoding preserves integral fields instead of applying the Admin map's
float64 normalization. Application digests likewise preserve distinct integral
configuration values when fencing retained rollback material. Literal null in
validation is rejected with a controlled error instead of reproducing the pinned
Go command's nil-configuration panic. The existing depth/resource bounds and
unsupported-module gates remain explicit; this is not full serving acceptance.
Caddyfile adaptation uses deterministic JSON object ordering, which can differ
from Go's typed-struct field order while retaining the same JSON configuration.
The shared JSON writer also provides bounded non-HTML-escaped typed output for
reflected log values. It retains Go float formatting, sorted map keys and escaped
U+2028/U+2029; ordinary Admin encoding, raw adaptation and ETags remain HTML-safe.

The HTTP and logging libraries share one warmed local-timezone lookup for the
platform UTC offset and abbreviation. It runs only during blocking preparation
or bounded encoding work; the existing placeholder fallback is preserved.

OCSP groups can now select their own immutable certificate inventory before
copying DER chains. Complete aliases and distinct loaded generations remain
authoritative, including multiple instances of one chain. Already authenticated
negative status still reaches every matching instance. Normal cancellation joins
owned work before returning without reporting a spurious maintenance failure.

Direct typed JSON and inline module decoding retain their separate number
semantics. A signed integer field accepts a literal negative-zero integer,
while arbitrary values retain floating negative zero and unsigned fields keep
their original rejection behavior. Inline modules apply the same float64
roundtrip as the reference before strict decoding; a nested route reuses its
already normalized subtree. This includes issuer and HTTP configuration
loaders. Configuration acceptance does not establish support for provisional
HTTP responses; runtime handling of 100 and 103 remains a separate gate.

The configuration DOM has explicit depth and byte limits. Compact arrays can
still expand considerably in memory; aggregate concurrent configuration work
requires separate memory admission and load acceptance before rollout.

With `native-run`, `run`, `start`, `reload` and `stop` expose the native
development lifecycle. Initial and accepted configuration can be saved to the
original autosave location; `run --resume` uses it when present. Background
start reports readiness only after publication and authenticates its local
child handshake. An interrupted start owns the child through shutdown. The
process uses every CPU available at startup and raises only its own descriptor
limit where possible. Signals provide graceful drain, and a forced shutdown
has a bounded wait for owned cleanup.

File monitoring survives temporary read failures and retries transient
configuration admission failures. A successful external load preserves
monitoring only when the source marker matches the original absolute lexical
path and adapter. Different directories, unresolved aliases, and absent or
different source markers revoke monitoring. HTTP markers never provide a new
path for the process to open. TCP, filesystem Unix sockets, and Linux abstract
Unix sockets are supported by the administrative commands; the server can
capture declared inherited TCP descriptors before runtime construction.
This is not the complete Caddy command or module surface.

TLS certificate acquisition uses the active listener's policy and exact
certificate scope. Already authenticated requests can finish during a
configured retirement delay. Admission and handshake work is bounded by
the host's actual CPU and descriptor resources. ACME proof traffic retains
independent capacity on a shared port: when a proof replacement is needed,
it can cancel an older incomplete connection and wait for its actual
release. Expired or unrelated requests do not evict other connections.
These limits protect runtime capacity; they do not establish complete
automatic HTTPS or on-demand TLS compatibility.

On-demand TLS is connected to the native serving generation. A certificate
miss uses that generation's permission policy. Concurrent requests for the
same name share an acquisition, and an already verified compatible certificate
can remain usable across a reload without another permission lookup. Storage
imports, renewal and eviction remain fenced to their owning generation.
The permission client preserves the escaped request path and Go query
normalization on HTTP/1 and HTTP/2; it leaves the configured origin, proxy,
certificate verification, and ordinary inbound URI limits unchanged. Long
targets still require a permission server whose own limit permits them.
Full production automatic-HTTPS acceptance remains a separate gate.

Native FastCGI supports dedicated TCP and Unix socket exchanges, request
streaming, and the standard PHP front-controller route. Large configured
request buffers can use anonymous temporary files under separate memory,
file and disk budgets. Per-target socket admission leaves capacity for
unrelated upstreams. An interrupted upstream response is not reported as
complete; conflicting Content-Length fields are rejected. An already
consumed request is not replayed as an empty request through error routes.
General proxy retry and response buffering remain separate gates.

The native root stages a logging generation with its server configuration.
An already admitted request retains that generation through body delivery;
a failed candidate does not retire existing log writers. The logging registry
drains accepted work during owned shutdown. HTTP access logging supports
host selection and omits credentials by default. Captured FastCGI stderr
uses the same generation's nonblocking logger. Bounded tail processing
does not delay a completed response. The capture marks truncated data and
limits stderr to 16 KiB. Under pressure the separate reduced access-log
budget retains status and a shortened request without its headers. The regexp and multi_regexp log filters preserve original replacement and
truncation semantics within explicit work and memory limits. A failed filter
never sends the unfiltered record. Handler tracing and full module-level log
integration remain separate compatibility work.

Before dispatch, business requests drop ambiguous underscore and dot header
spellings by default. Per-server exact and prefix allowlists preserve the
chosen spelling, remove competing hyphenated variants, and reject repeated
values for an allowed alias. Mixed underscore/dot spellings require an exact
entry. This applies before proxying to HTTP or FastCGI backends.

The native TLS cache honors the default 10,000-entry capacity and explicit
positive capacities up to 16,384. Eager loads, exact shared imports, and
on-demand acquisitions use the same generation-owned capacity. Manual
certificate entries are never eviction targets; a full manual inventory
can still serve one managed certificate. Count limits do not replace the
separate certificate-material byte limits. Exact rollback history includes
only displaced, configured entries from the retained generation.

Native HTTP/1.1, HTTP/2 and HTTP/3 can forward upstream informational
responses and emit configured responses such as 103 Early Hints. Per-stream
bounds preserve order without buffering or replaying the request. FastCGI
interim responses remain a separate compatibility item.

The native HTTP/3 listener provisions UDP transactionally, uses TLS 1.3,
and advertises its live port over HTTPS. It streams requests and responses
under flow control and drains active streams when a generation retires.
A cold on-demand handshake validates the peer's address with QUIC Retry
before requesting a certificate. ClientHello inspection and issuance run
outside the endpoint lock, with separate capacity for fragmented flights
and issuance so ordinary connections can continue. This covers server
HTTP/3 with the currently supported TLS policies. Outgoing HTTP/3,
extended CONNECT/datagrams, early data and full production compatibility
are separate work.

The native `encode` handler negotiates gzip and Zstandard for HTTP/1.1,
HTTP/2 and HTTP/3, preserves eligible response trailers, and flushes SSE as
events become available. Encoders use a separate bounded worker and codec
budget. If no codec is available before the response starts, the server
can send identity; a stream already compressed must finish correctly or
fail. The response matcher is also available for deferred header rules.
For an upstream response without a declared length, the minimum-length
decision can differ when the first data chunk is split differently by the
transport. Precompressed file sidecars remain separate work.

The `strict_sni_host` server option checks each HTTPS authority against the
actual TLS SNI, including on existing HTTP/1.1 and HTTP/2 connections after a
configuration reload. A mismatch uses the configured 421 error route; clear
HTTP remains unaffected. HTTP/3 applies the same check per request.

A negative server `read_idle_timeout` disables the per-read upload idle
timer, as in Caddy. Omitted or zero values retain the one-minute default.
