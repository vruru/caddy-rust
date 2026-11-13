# Demand-driven Map placeholders

A `map` handler registers an immutable definition graph for the request. It does
not choose a mapping or expand an output at registration. Each subsequent read
uses the current request metadata and variables. Results are not cached across
handlers or upstream attempts. Registration order is preserved: the first Map
which owns a destination also owns its missing/default result.

Literal and default outputs expand placeholders when selected. A regexp output
expands capture references once; the resulting bytes are not scanned again for
placeholders. A missing default remains a typed null for CEL, distinct from an
explicit empty string. String-only consumers retain their normal Caddy string
conversion. Raw capture bytes remain bytes where the receiving API supports
bytes; this does not add raw filesystem-path support to string-only APIs.

Go-valid regexp syntax uses the native Go-compatible engine, including its
ASCII shorthand classes and capture expansion. Existing useful Rust-regexp Map
extensions such as explicit Unicode, extended-whitespace, CRLF and set syntax
remain available when the Go syntax parser rejects the expression. Resource
admission failure does not trigger a second compiler attempt.

## Scheduling and live receivers

The service task resolves only the requested name. Map regexp and formatting
work uses a bounded CPU lane, distinct from the ordinary HTTP regexp lane.
Header replacement expressions which may read a Map also enter that lane,
including short expressions. Template reads execute in the existing bounded
renderer worker and consult the current controlled URL receiver. Asynchronous
consumers use immutable metadata views rather than temporarily rewriting the
real request method or URI.

Map work is demand-driven in response/status expansion, variables, matchers,
rewrites, file/template roots, FastCGI environment, proxy headers/dial/SNI,
dynamic upstream sources, Push targets/headers, and logging/tracing. This
scheduling work covers the primitive providers currently implemented by those
consumers; it does not establish every Caddy host method or provider, including
remaining request-body/provider combinations.

## Resource ownership

| Resource | Native boundary |
| --- | --- |
| Runtime Map buffers, work and retained string copies | 128 MiB shared across overlapping generations |
| Optional proxy client metadata cache | Independent 32 MiB shared pool; 4 MiB current index per proxy; at most 1024 entries |
| Expansion input / output | 1 MiB / 4 MiB |
| Recursive Map/provider reads | 64 levels |
| One lookup/expansion | 5 seconds, shared by its nested reads |
| Header Map dependency metadata | 4096 keys; bounded CPU preparation |
| Map CPU work | CPU-derived running limit, at most 16, with a bounded queue and wait |
| Map-derived proxy NSS work | Its own CPU-derived bounded lane and queue, separate from FastCGI DNS |
| Owned mapped NSS address copies | At most 4096 resolver addresses inspected; two complete copies prepaid before the worker; excess rejects rather than truncates |

Existing stricter consumer limits still apply, including the Push target/head,
Header operation, FastCGI parameter and template budgets. Header Map expansion
also observes the Header operation deadline; template reads observe the
renderer cancellation/deadline. These are operation bounds rather than a new
whole-request timeout or a fixed production worker count. Physical service
workers still follow the CPUs available at process startup. Independent queues
do not promise physical CPU or blocking-pool isolation under arbitrary load.

Buffer growth, regexp construction/search, copied metadata and cache-table
allocation are prepaid. Hash-table accounting includes its retained capacity
and old/new tables during growth or tombstone rehash. A full optional cache
uses an uncached client; it does not consume the runtime Map pool indefinitely
or reject a request solely because caching is unavailable.

Owned inputs and unconsumed worker results retain their credit after a waiting
future is cancelled. File/template metadata handoff returns only to the same
request retention arena. Proxy cache keys, connector inputs, real NSS closures
and successful upstream I/O retain their specific owners. The original TLS
implementation remains responsible for TLS behavior; the Map I/O wrapper
forwards the original connection/read/write operations. An I/O completion or a
cancelled future is not itself proof that its final memory owner has retired.

Mapped TLS attempts keep concrete atomic lease capsules through their actual
handshake worker, unconsumed result, native SSL factory/verification/record
jobs, returned errors and connection I/O. Adapter boxes and result metadata are
admitted before allocation. Cancelling a waiting HTTP request does not refund
credits still held by those owners. Unmapped traffic creates no capsule and
acquires no Map allowance. The connector wrapper forwards vectored-write
capabilities as well as the original read/write and connection facts.

Only a credited native SSL error gains a source wrapper: its kind, display and
original error chain remain available, including an underlying OS error. The
top-level `raw_os_error` is then absent because the standard I/O error cannot
also carry the lease capsule in its inline OS representation. Uncredited errors
retain their original representation. This does not change the finite CBC
eligibility checks or permit replaying an application request.

The NSS adapter uses the same synchronous system `ToSocketAddrs` call and family
filter as before. It bounds its own admission and retains the actual name/result;
it does not claim to meter every libc/NSS/TLS allocation or to bound process RSS. The adapter bounds its own copied Vec before allocation; a standard resolver iterator's size hint cannot cause an unadmitted reserve.
Resource exhaustion rejects the affected required operation. Optional log or
trace capture can omit the affected observation while the business request
continues.
