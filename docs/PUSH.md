# Native HTTP/2 resource push

The `push` handler dispatches explicit resources and eligible response `Link`
headers through the native HTTP/2 connection. HTTP/1, HTTP/3, disabled peer push,
and a request already carrying `Caddy-Push` do not execute synthetic requests.
This is native request execution, not a Go subprocess or an upstream fetch shim.

A promised request retains its accepted server, business generation, addresses,
and immutable TLS facts. Reload cannot attach it to a newer configuration.
Once accepted, the child survives the parent's normal completion or reset, as
in the pinned Go implementation. The generation's hard stop can still cancel it.
The response source and actual protocol writer have independent cancellation;
failed sources, write deadlines and backpressure do not stop sibling streams.

Each connection admits at most eight pending promises and 32 live children.
Each source has a one-frame mailbox; DATA is split into at most 16 KiB pieces.
Promise, header, data and trailer metadata retain their prepaid allocation
ownership through actual local flush or retirement. Local flush is not evidence
that the remote application consumed a response. A reserved push stream also
counts as activity for idle timeout; the idle timeout resumes after its last
child retires. This fixes an early close when a parent finished before a slow
child produced its response.

Explicit resources run before the following handler. Response links run at the
first response head, including an informational head. Resource methods are GET
or HEAD. A resource error stops that handler's remaining pushes and preserves
the ordinary response. Target parsing preserves escaped paths, empty queries,
fragments and arbitrary Go-string bytes; unsafe protocol/framing headers are
rejected. The copied header allowlist and recursion marker follow the reference;
configured header operations apply afterward. No implicit cookie or authorization
copy is added.

This implementation shares HeaderOps compilation and literal/regular-expression
replacement with ordinary and proxy headers; see `HEADERS.md`. Unknown operations
are rejected at configuration preparation rather than silently ignored.
Resource limits are implementation safety bounds, not a process RSS promise.
Full combined certificate, lifecycle and production acceptance remains required.
