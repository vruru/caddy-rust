# Header operations

The native `headers` handler, reverse-proxy `header_up`/`header_down`, FastCGI
and HTTP/2 Push share HeaderOps compilation and byte-preserving replacement.
Literal `search` and regular-expression `search_regexp` are mutually exclusive.
Rules on a field execute in array order after clear-all, add, set and delete.
`*` selects all fields; other replacement selectors are exact field names.
Set keys that differ only by canonical header spelling merge in sorted raw-key
order. Set-Cookie values remain separate. Overlapping configured map entries
have unspecified iteration relationships in the Go reference; native configured
field keys follow their compiled map order.

A static regexp is compiled while preparing the candidate. A regexp with the
reference's placeholder marker is expanded and compiled for each actual value;
invalid dynamic syntax skips that rule. Native resource or compiler-invariant
failures are errors rather than successful skips. `$` capture expansion,
zero-width matches, empty literal searches and invalid UTF-8 values retain Go
byte/rune semantics. Unknown replacer names remain literal.

Request operations read their current temporary HeaderMap, including Host;
Host is copied back to request authority after the operations complete. Proxy,
response and Push operations use the original request replacer facts. An
immutable borrowed replacer view excludes the request body and does not change
request method, URI, projections, variables or captures. Capture/field/rule
scans yield cooperatively. Large replacement programs use the existing bounded
CPU lane, with an owned prepaid copy of only the needed current-header overlay.
Expensive legacy lazy Map evaluation is a separate remaining scheduler gate.

Replacement data uses a 128 MiB pool shared by the runtime across generations.
An operation admits at most 65,536 configured entries/values/rules and 65,536
needed replacer names. Captured data and the resulting header map have a 4 MiB
limit, including conservative per-value header overhead. Push retains its
64 KiB promise-header limit. Expanded expression input is at most 1 MiB. Match
and rule work checks a 150 ms budget; CPU compilation cannot be interrupted by
cancelling the awaiting future, and its actual owners keep their credits until
that work and any unconsumed result retire.

A separate process-wide 128 MiB pool admits HeaderOps static-regexp constructor
scratch. It is not the runtime output pool. Both static and dynamic compilation
prepay Go syntax translation and then native AST/HIR construction before those
phases allocate, using translated nodes/empty branches, ranges, bytes and capture
counts. Static scratch retires after construction/handoff; compiled objects keep
the existing 2 MiB individual and 64 MiB HTTP-configuration accounting limits.
These limits do not promise a whole-process RSS bound or cover other matcher
constructors. Constructor pressure rejects a candidate; existing generations
continue. Mandatory runtime replacement pressure fails that request. Push
pressure omits the optional promise and preserves the ordinary response.

Actual output HeaderValue owners retain their credits through clones and final
source retirement. Input batches, expansion overlays and completed worker
results retain their own data credits independently. Protocol encoding buffers
have their separate transport budgets; source retirement is not proof that a
peer consumed bytes. Existing original-input syntax, invalid-name/value and
transport limits remain in force.

The native proxy keeps its existing useful retry-placeholder behavior: header
operations can see the current native attempt count. The pinned reference can
leave that name literal in header_up. This is recorded as an extension, not
reported as zero differential behavior.
