# Native compatibility implementation

Standalone Rust implementation in progress for the existing Caddy deployment.
This is a separate project from GoEdge. The current build is a **read-only
migration inspector**, not a traffic-serving replacement. Existing production
Caddy remains unchanged until the replacement passes the applicable contracts.

The user requires original functionality and module behavior to remain available,
especially automatic certificate issuance and renewal. See COMPATIBILITY.md for
the full baseline and the current incomplete status. Compilation and parsing
success are not evidence that a proxy, plugin, or certificate issuer is complete.

Current commands:

- `inspect-config FILE`: extract a privacy-safe configuration feature inventory.
- `inspect-storage ROOT`: inspect CertMagic certificate/account layout and validate
  supported certificate/key pairs without writing or registering an ACME account.

Neither command serves traffic, renews a certificate, reloads a running process,
or replaces existing state. Reports must not contain private keys, account email,
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

The TLS key provider preserves the ring cipher and verification policy, using
AWS-LC only for RSA private signing keys larger than 4096 and up to 8192 bits.
Certificate/private-key matching remains mandatory before publication. The
process installs this explicit provider before constructing implicit TLS clients;
an incompatible existing default is an error. This key compatibility primitive
does not implement a production TLS listener or certificate lifecycle.

The `admin_json` library provides configuration traversal, mutation, Go-style
JSON number/Unicode encoding and raw-path ETags. Reads can borrow the immutable
configuration snapshot instead of cloning the full document. This is a DOM
primitive, not an exposed Admin endpoint or a configuration transaction backend.
Input and mutation paths currently have a 256-level resource limit, below the
original decoder's 10000-level limit; that difference remains a migration gap.

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
from serialized publication. Its backend contract requires real candidate
provisioning, identity acquisition and rollback. Those product-level connections
are still incomplete: the CLI remains the read-only inspector described above.
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
current LocalOps task. Do not create GitHub Actions. The authorized source
repository is the private `vruru/caddy-rust` repository; do not publish this
standalone project into another repository.

HTTP upstream TLS now loads explicit trust material during preparation, validates
client identities, derives supported dynamic server names per request, and bounds
connect/handshake/read/write waits. HTTP-only ALPN follows the original absence
of an ALPN extension. Static and managed leaves share revocation policy. This
is isolated transport support; transactional listener integration remains work.

The shared duration parser preserves the original day-unit float conversion and
rounding while rejecting integer overflow instead of wrapping. JSON integer
durations retain nanosecond semantics. Callers keep their own negative-value
policy and error context; this helper does not provision a runtime.

Production runtime construction detects this process's available CPUs on every
startup rather than hard-coding a worker count. Test cgroup CPU limits remain
confined to isolated QA containers and must not enter production service units.
The runtime constructor is a product-integration primitive; the current
inspection CLI does not create it.

Configuration-adapter primitives now include source formatting, directive order,
route sorting, named matchers and a subset of global options and handlers. They
are not yet exposed through a complete adapter entry point. Aggregate resource
budgeting, remaining directives and runtime integration remain explicit gaps.

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
