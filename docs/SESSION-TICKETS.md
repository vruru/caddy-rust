# TCP TLS session tickets

The native TLS app accepts the standard and filesystem-backed distributed STEK
configuration for ordinary unauthenticated TCP HTTPS. This integration is
separate from QUIC ticket handling and administrative client authentication.

An omitted session ticket service, or explicit disable_rotation, preserves
same-generation runtime resumption. Reload starts a fresh runtime session cache.
Explicit standard rotation preserves its process-owned key ring over equivalent
reloads. Distributed rotation uses the configured filesystem storage or the
global/default storage; the data file and lock names remain stek/stek.bin and
stek_check. Provider and storage module fields are checked before disable flags.
In these raw module fields, explicit JSON null is an error rather than an omitted
provider. The disabled flag prevents both ticket and session-ID resumption.

Defaults are a 12-hour rotation interval and four keys. Nonpositive max_keys uses
the original default; positive values above 64 and active rotation intervals
below 10 ms are explicit resource limits. A missing distributed key file is
initialized only after the configuration is committed. The short initial window
supports full verified TLS without issuing a ticket. Bad or partial stored
material is never treated as an empty namespace. Candidate validation and
discarded configuration do not rotate or replace shared keys.

Each ordinary handshake owns its own ticket wrapper. Its authenticated context
contains the real negotiated protocol, normalized SNI, complete selected chain,
and stable configured storage/HTTPS realm. The final certificate and live
withdrawal guard remain authoritative for both full and resumed handshakes.
Administrative client authentication and TLS-ALPN certificate proofs do not
install this wrapper. Early data is disabled, and rotating mode has no
session-ID fallback. Up to five offered tickets are attempted, with bounded
untrusted data and no I/O or lazy key-schedule lock on a handshake.

TLS 1.2 rewrapped master secrets retain their original ticket creation time.
TLS 1.3 creates a newly dated PSK. Runtime session-cache entries and native opaque
tickets have a seven-day age limit; stale cache entries are removed on lookup
and insertion. Accepted HTTP connections retain their existing connection
lifetime independently of this new-handshake limit.

A configured namespace and authenticated matching key material are both
necessary for distributed resumption. A matching pathname alone does not grant
access. Equivalent verified aliases of one real local directory use one owner.
Copying a key file to a different canonical namespace does not automatically
share its resumption realm. Path migration, unknown formats, missing/stale keys,
identity changes, or a binary rollback may safely require a full handshake.
The original Go and native payload formats differ even though their persisted
seed file can be exchanged; native code does not decode a Go session as a
Rustls session.

Root prepares an immutable view before committing it at HTTP generation
publication. Only committed workers may persist rotation. Failed candidates
leave the preceding mode intact. Workers follow actual delayed TCP admission:
a removed old binding may continue its old service until its acceptance receipt
closes. Rollback uses authenticated retained certificate material. Distributed
rollback initially performs full handshakes, then the committed worker reads the
current namespace rather than resurrecting a previous on-disk key generation.

Storage coordination has been exercised on supported local POSIX filesystems
with the original Go lock protocol. Cross-host/NFS fencing and every third-party
storage plugin are not implied. Expired ring data is unusable even if a blocked
storage operation is still draining; forced kernel I/O completion or immediate
memory erasure during such a block cannot be promised.

References: [Caddy session service](https://github.com/caddyserver/caddy/blob/v2.11.7/modules/caddytls/sessiontickets.go),
[distributed provider](https://github.com/caddyserver/caddy/blob/v2.11.7/modules/caddytls/distributedstek/distributedstek.go),
[Go TLS 1.2 age handling](https://github.com/golang/go/blob/go1.27.3/src/crypto/tls/handshake_server.go).
