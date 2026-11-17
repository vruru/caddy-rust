# Native HTTP cache and policy extensions

These extensions run in Rust. They do not load Go plugins or provide a Go plugin
ABI. Their behavior was derived from cache-handler 0.17.0, Souin 1.7.9 and Otter
storage 0.0.22, together with the explicit policy contracts below. Unknown
configuration fields and unsupported options fail validation before activation.

## Cache application

`apps.cache` provides the state consumed by `http.handlers.cache`. A bare route
handler `{"handler":"cache"}` inherits that application; per-handler overrides
are not implemented. `storages.cache.otter` denotes the native in-memory
storage behavior, not an external service or a dynamic Go plugin.

```json
{
  "cache_name": "ExampleCache",
  "allowed_http_verbs": ["GET", "HEAD"],
  "default_cache_control": "no-store",
  "key": {"hash": true, "hide": true},
  "max_cacheable_body_bytes": 4194304,
  "otter": {"found": true, "configuration": {"size": 1024}},
  "storers": ["OTTER"],
  "ttl": "1h",
  "stale": "0s",
  "log_level": "error"
}
```

The example is the value of `apps.cache`. The default TTL is 120 seconds; an
explicit TTL overrides it. Only GET/HEAD and OTTER are supported. Nonzero stale
serving and other backend/options are rejected. The body limit defaults to
4 MiB and accepts 1..16 MiB. The Otter size defaults to 10,000, is limited to
1,000,000, and conservatively charges two slots per response variant.

A process-wide 128 MiB budget covers retained cache data, in-flight captures,
entry metadata, response metadata and evicted data still held by clients. This
is not a bound on total process RSS. Same-capacity reloads share the existing
store. A capacity change creates a fresh store under the same process budget.
Entries retain copied bytes, not request/generation guards or upload spools.
This backend uses uncompressed native bytes and bounded approximate rotation,
rather than reproducing Otter's internal compression/eviction algorithm.
Same-capacity force reload retention is a deliberate improvement over reference
cleanup paths that can discard entries while processing a policy-only reload.
Lookups use a key index and bounded expiry maintenance; payload destruction is
outside the shared metadata lock. Concurrent misses for one key share a bounded
flight: at most 128 in-flight keys, 32 waiters per key and 512 waiters process-wide.
A waiter rechecks its own Vary headers after waking; cancellation and failures
release the flight, and a 10-second wait limit permits normal origin fallback.

Captures publish only after actual end-of-stream and abandon storage on error,
cancellation, oversized bodies or exhausted credits. Storage failure continues
the original response. HEAD metadata and complete GET representations support
HEAD hits. Vary values match exactly; `Vary: *` is not stored. Fresh hits apply
Age and representation conditions. Known complete representations support
single, suffix and bounded multipart ranges.

Intentional safety differences from the older backend:

- Authorization/Cookie requests bypass caching; Set-Cookie and private/no-store
  responses are not stored. Request no-store also prevents reading an old entry.
- SSE, upgrades, non-GET/HEAD requests and partial responses are not stored.
- Cold requests retain the origin Range header. A 200 response of known length
  can be sliced without buffering the whole representation; an ignored Range
  with unknown length can remain 200. A 206 origin response passes through.
- Higher-priority Souin/Surrogate/CDN cache controls are recognized, while an
  ordinary private/no-store instruction still prevents unsafe storage.
- Streams are bounded captures rather than an unbounded whole-body buffer.

## Scoped trusted proxies

A server's `trusted_proxies` can use:

```json
{"source":"scoped_policy","hosts":{"www.example.test":["192.0.2.0/24"]}}
```

The source selects canonical CIDRs by the current exact request authority,
including a valid optional port and case/trailing-dot normalization. Unknown or
malformed authorities trust no forwarded address. Both direct-peer admission
and strict forwarded-chain traversal use the selected scope. Static trusted
proxy configuration remains available.

The configuration allows at most 256 canonical hosts and 10,000 CIDRs per host.
Noncanonical prefixes, default /0 ranges and IPv4-mapped IPv6 are rejected.
Lookups perform no network requests or mutable policy fetching. A newly
validated configuration publishes its immutable policy transactionally.

## Bounded request bodies

`{"handler":"bounded_body","max_size":52428800}` waits for the complete
request body, including actual end-of-stream, before the next handler runs.
The explicit size must be 1..50 MiB. Existing replay storage keeps a bounded
memory prefix and spills to anonymous files; retry owners retain the storage
until the real upload finishes.

Declared or observed oversized bodies fail with 413, malformed or failed bodies
with 400, and storage/resource admission failures with 503. A failed body cannot
be replayed by an error route. Normal reload drains accepted uploads; only a hard
stop aborts their body admission. Extended WebSocket CONNECT bypasses body capture;
ordinary HTTP/1 upgrade bodies still receive size validation.

Validate each target's complete configuration and actual request paths before
cutover. Module registration and a successful `validate` alone are not runtime
acceptance. Certificate storage and automatic certificate behavior continue to
use the existing native TLS lifecycle.


## Filesystem storage and native runtime state

The native certificate store keeps runtime identity and coordination state under
`<configuration directory>/native-state`. On Linux, `XDG_CONFIG_HOME` selects the
configuration directory as `$XDG_CONFIG_HOME/caddy`; otherwise it defaults to
`$HOME/.config/caddy`. This state is required even when admin configuration
persistence is disabled.

Each certificate data root and its native state root must be absolute, separate,
non-nested directories. An explicit file-system storage root that contains the
home directory's default configuration path therefore needs an external
configuration directory. For example, with certificate storage at
`/var/lib/caddy`, use `XDG_CONFIG_HOME=/var/lib/caddy-native-config`. Keep the
existing certificate data and ACME accounts in their original storage root;
changing the configuration directory does not require moving those files.

The directory must be owned and writable by the service account. Sandboxed
systemd units with `ProtectSystem=strict` also need an explicit
`ReadWritePaths=/var/lib/caddy-native-config` addition. Apply the same environment
and filesystem permissions to pre-start validation, normal startup, and reload.
Preserve unrelated service limits and capabilities.

Deployment validation must preserve the target's storage/state path relationships,
service identity, mount permissions, and listener capabilities. Mapping storage
and configuration paths to unrelated writable temporary directories can hide a
real startup failure. Check actual isolated startup and normal stop/restart as
well as `validate`; preserve production certificate files and keep any copied
store identity state isolated from the live store.
