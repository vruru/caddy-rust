# HTTP, proxy and certificate lifecycle remediation

These contracts describe the concentrated remediation after the initial
combined release. They are behavioral requirements, not a claim that every
plugin, platform or configuration combination has been verified. Release
verification and deployment remain separate gates.

## HTTP and logging

| Path | Corrected behavior |
| --- | --- |
| `file_server` in error routes | An ordinary internal error establishes an error context even without a structured status placeholder. The file error page defaults to 500 and accepts the original request method. Explicit statuses and `static_response` keep their own rules. |
| Byte ranges | Empty range lists are ignored; ASCII whitespace around range members is accepted. A zero suffix alone remains unsatisfiable (416); it is skipped when mixed with a satisfiable member. This deliberately differs from the reference's empty 206 response for `bytes=-0`. |
| Canonical file redirects | Slash changes use the original escaped path. Encoded reserved characters and query bytes survive; raw spaces/non-ASCII bytes are escaped. `Location` and the HTML link represent the same target, with HTML escaping applied separately. |
| Header regular expressions | Invalid UTF-8 is interpreted one invalid byte at a time while captures preserve source bytes. Header inputs do not receive path normalization. Existing worker and capture budgets remain in force. |
| Rolling log sizes | With rolling enabled, negative sizes and signed-byte multiplication overflow are rejected before activation. Zero still selects the default; a disabled rolling writer retains its ignored-size behavior. |

Reverse-proxy terminal diagnostics contain a fixed category, response status,
elapsed time, actual attempts and retries. They use the existing bounded log
queue and do not include request URLs, credentials, bodies or raw error text.
Response-header timeouts retain a typed cause rather than being guessed from
status 504. Diagnostic failure does not change the response or retry decision.

## Independent proxy progress

An HTTP/3 fetch transfers cancellation responsibility to its real response
body. Returning early response headers no longer cancels an upload which is
still making progress. Error and caller-drop paths still cancel owned work.

Active health checks reset the opposite counter on every observation. Passing
and failing thresholds therefore mean consecutive observations. Retry matcher
evaluation errors preserve their actual status, including request-body limits,
rather than returning the preceding upstream error.

FastCGI STDIN writing and response reading make progress concurrently using the
existing admitted socket and task tracker. Source buffers, spool workers,
socket halves and request ownership remain attached to their actual work.
Response parsing observes upload failure; dropping a response cancels the
tracked upload. Record headers, payload and padding are offered together through
a borrowed vectored cursor when the writer supports it. Partial writes advance
the same cursor; no complete request copy or extra upload queue is introduced. A started non-idempotent exchange is not replayed merely because
the input was buffered. A connection failure before transmission retains the
ordinary retry rules.

Known-length responses retain at most their last record while required upload
and protocol completion is established. Parsing continues during that wait to
avoid a stdout-first responder blocking STDIN consumption. A diagnostic storage
limit is not an END_REQUEST receipt. Truncating captured diagnostics does not
pretend a pending upload succeeded. The existing short diagnostic-tail budget
applies only after upload completion; ordinary transport deadlines and forced
generation cancellation remain distinct controls.

## Certificate client lifetimes

Native Unix ACME issuance uses a concrete client scope for each issuer leg. Its
deadline includes setup, directory and account work. A read-only timeout can
permit the next issuer only after the real operation, connection/DNS work and
owned cleanup have retired. Unknown remote writes, active durable orders,
produced material, local resource failures and parent cancellation do not gain
fallback permission from that timeout. A storage lease remains valid through
fenced cleanup; explicit release joins its heartbeat worker.

The configured test-CA probe and production phases retain their separate
journals and existing ordering. Per-leg cleanup does not retire an unrelated
client or the whole accepted generation. Standalone SDK managers retain their
caller-owned lifetime; the native Unix retirement receipt is not a blanket
cross-platform promise.

The authenticated account's concrete client is used through download, optional
renewal-information lookup and certificate publication. A scoped leg does not
depend on the legacy generation client's lazy initialization at commit time.

Permission checks, external HTTP/Tailscale certificate retrieval and OCSP/AIA
clients use the existing native generation's DNS/TLS scope. Client construction
and root parsing use the existing bounded certificate CPU lane. Their original
trust, proxy, redirects, timeouts, cache identities and live default-root
consumption phases remain distinct. The public OCSP constructor stays
synchronous; manager limit validation does not construct a throwaway client.

Certificate client metadata prepays its existing process-local 8 MiB ceiling
once from the existing certificate total pool. Descendants divide that local
credit instead of recursively requesting small amounts from the fair total
queue while holding a large certificate-material reservation. Every metadata
loan retains the same prepaid owner, including CPU metadata which can outlive
the client master. The global credit returns only after its last real owner;
the independent observability pool remains separate. Neither quota is enlarged.

Some repairs intentionally correct defects also present in the reference Go
implementation. This project ports behavior and does not support the Go plugin
binary ABI. Optional providers and unverified platforms retain the boundaries
listed in [COMPATIBILITY-STATUS.md](COMPATIBILITY-STATUS.md).
