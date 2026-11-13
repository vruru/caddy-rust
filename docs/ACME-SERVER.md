# Native ACME server

The `acme_server` handler uses the existing PKI and CertificateServices signing
path. Serving, validation and storage execute in Rust, without a Go process or a
second CA implementation. Its compatibility baseline is Caddy 2.11.7 and
Smallstep certificates 0.30.2/nosql 0.8.0. The inspected Caddy reference actually
links bbolt 1.5.0; the older 1.4.3 module declaration is not its runtime version.

## Protocol and configuration

The handler provides directory and nonce endpoints, account creation, lookup,
contact updates, deactivation and order listing; DNS/IP orders, authorizations,
HTTP-01, DNS-01 and TLS-ALPN-01; CSR finalization, certificate-chain download and
persisted revocation. CSR signatures, public keys and authorized SANs are checked
before signing. A failed proof does not create an issuable certificate. Nonces
are consumed transactionally and cannot be replayed.

JWS verification supports RS256/384/512, PS256/384/512, ES256/384/512 and EdDSA.
RSA keys are bounded to 2048–8192 bits. The observed client short-R/S ECDSA
compatibility still requires successful verification of the actual signature.
Optional JWK certificate metadata is parsed and checked, including leaf public
key equality and certificate thumbprints; `x5u` is not dereferenced.

| JSON field | Behavior |
| --- | --- |
| `ca` | Selects a PKI authority, default `local`; provisioning uses the normal PKI lifecycle. |
| `lifetime` | Defaults to 12 hours; accepted range is 5 minutes–365 days. Managed intermediate lifetime must exceed the requested default leaf lifetime. Issued validity does not extend past its signer. |
| `host` | Fallback for requests without a Host authority. An explicit request Host takes precedence. Bare IPv6 fallback addresses are normalized. |
| `path_prefix` | Selects the handler namespace, default `/acme/`. |
| `sign_with_root` | Selects the authority's root instead of its intermediate as signer. |
| `resolvers` | A nonempty list overrides DNS-01 TXT lookup resolvers. Empty, null or absent lists use `apps.tls.resolvers`, then system defaults. It does not override HTTP/TLS challenge or issuer-wide DNS resolution. |
| `challenges` | Filters the supported `http-01`, `dns-01` and `tls-alpn-01` challenges. |
| `policy` | Domain/IP allow and deny rules, with deny precedence, and `allow_wildcard_names`. |

The existing Caddyfile adapter exposes the original directive's subdirectives;
JSON-only fields are not silently added to that grammar. Unsupported fields fail
before publishing a replacement configuration. The pinned Caddy provisioner
fixes RequireEAB to false: optional EAB wire shape is checked, while its binding
content is ignored as in the reference. This does not implement Smallstep's
separate EAB administration, Wire, attestation or permanent-identifier platform.

## Existing state and transactions

The database remains Bolt format under the default application-storage
directory, at `acme_server/<sanitized-CA>/db`. A Unicode-only CA identifier can
sanitize to empty, producing the original `acme_server/db` layout. A raw authority
identity record in a native metadata table prevents colliding identifiers from
silently adopting each other's state. Legacy accounts are checked before adding
that marker; existing tables are not deleted.

The checked codec preserves unknown raw tables, nested buckets and sequences,
as well as account, nonce, index, order, certificate and revocation records.
Unknown record JSON fields are retained. Certificate downloads parse stored
certificate bundles and emit canonical LF PEM, rather than expose arbitrary
stored bytes or depend on their newline style.

Storage uses checked positional snapshots, not an unchecked memory map or the
bbolt-rs implementation. A lifetime cooperative advisory lock is acquired on
the same descriptor with a one-second deadline. Commits write COW pages using
the currently committed free list, synchronize data, then publish and
synchronize the alternate checksummed meta page. Previous live pages become
reusable only through the new committed state. An uncertain failed commit
poisons that descriptor until a later admitted operation revalidates its actual
snapshot; it neither initializes a replacement database nor switches descriptors.
Cancellation after publication must not be mistaken for rollback.

Current limits are 64 MiB per file, 4 MiB per record, traversal depth 64 and
little-endian Bolt v2 page sizes of 1–64 KiB. Compound allocation pressure can
refuse an operation earlier. Free-page reuse limits repeated-write growth;
capacity refusal does not delete old certificates. Back up and stop the current
writer before switching implementations. Advisory locking cannot protect against
an unrelated writer that deliberately ignores it. Process-crash recovery has
been exercised; that is not a physical power-loss guarantee or unlimited-format
compatibility claim.

## Resource ownership

Each database has an owned serial actor and an eight-command queue. ACME CPU and
network lanes are independent, each bounded to `min(available CPUs, 8)`. Shared
admission bounds 64 requests, 64 database identities and 256 MiB of ACME credits.
An operation has a 192 MiB cumulative allocation allowance, 32 million work
units, cancellation and a 30-second deadline. These are component admissions,
not a CPU affinity restriction or a whole-process RSS ceiling.

Admission precedes the controlled allocations. Credits follow actual blocking
closures, DNS futures, I/O streams, issuance results, DER/PEM copies and the last
response byte owner. Dropping a waiter does not retire a still-running worker or
its output. Configuration retirement and shutdown join that work. Capacity and
cancelled service admission produce 503 responses; ordinary template and health
routes do not enter the ACME heavy queues. Existing unretained DNS callers keep
their previous path.

## Deliberate differences

RFC keyChange performs real dual-signature verification and atomic key-index
replacement where the reference returns 501. Authorization deactivation and
revocation by an account holding current authorizations are also implemented.

Invalid provisioner settings fail during staging instead of validating
successfully and leaving a disabled endpoint. An active deny-only policy still
honors disabled wildcard issuance. TLS-ALPN proofs require exactly one authorized
SAN, including rejection of extra URI SANs; TLS 1.2/1.3 CertificateVerify remains
mandatory. Canonical mapped IPv4 addresses repair the reference's HTTP proof URL
construction, and mapped proof SANs can be verified without skipping possession.
An HTTP/1.0 request with neither request nor configured authority receives 400
instead of an unusable directory that promotes a path segment into a hostname.

Raw route keys retain byte identity; only JSON diagnostics use Go's invalid-UTF8
replacement convention. Generated values, pointer-independent protocol facts,
error details and Go PKIX edge behavior are not all claimed byte-identical.
Differences are retained explicitly, without normalizing failures into passes.
Remaining DNS provider issuance and other unsupported modules remain
tracked in the main compatibility contract. Component acceptance does not
establish full Caddy compatibility or authorize a production replacement.
