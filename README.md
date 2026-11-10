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
boundaries. This is not yet a Caddyfile parser or configuration adapter.

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

Build with the current official stable Rust, pinned to 1.99.1 for this phase.
Keep all QA, fixtures, private configuration, keys, logs, and build output in the
current LocalOps task. Do not create GitHub Actions. The authorized source
repository is the private `vruru/caddy-rust` repository; do not publish this
standalone project into another repository.
