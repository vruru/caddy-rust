# HTTP dependency source provenance

These are functional source copies of the versions locked by this project:

| Crate | Registry version | Registry package SHA-256 |
| --- | --- | --- |
| hyper | 1.12.0 | `2c3e324da4c95177d6291d4c8730197c0d1822f8a9766814a4a44fa5ab797c9c` |
| hyper-util | 0.1.21 | `ddc03d96684f9226b8a787cdb71488417b53ab5ea8fdb1dac946cb9431cc8bff` |

The original MIT licenses are retained in each crate. The trailer continuation
normalizer follows Go 1.27.3 `src/net/textproto/reader.go`; its copyright notice
and the original BSD license are retained in `hyper-1.12.0/GO-LICENSE`.

There are two separate change layers. First, a local `syn` AST visitor removes
only nodes whose `cfg` predicate is definitely false with `test=false`, and
test-only `cfg_attr` attributes. Mixed predicates with a functional feature branch
remain intact. The two files referenced exclusively by removed test modules
(`hyper/src/mock.rs` and `hyper/src/client/tests.rs`) and development-only Cargo
target/dependency declarations are omitted. Original complete sources, per-file
checksums, AST removal reports, test-removal diffs, test programs and test results
are retained outside this repository.

Second, the functional patch adds opt-in HTTP/1 trailer encoder support and
diagnostic counters, a separate inclusive received-trailer byte budget, and
opt-in bounded obsolete CRLF continuation normalization. Both connection
builders and the hyper-util forwarding builders expose those controls. All new
controls retain the original Hyper behavior when unset. Initial request/response
header budgets are separate from the received-trailer budget. The encoder's
compatibility path rejects invalid wire values and blocks beyond 1 MiB or 32,768
values instead of emitting a successful chunk terminator.

The Caddy HTTP runtime enables dynamic response trailers, sets the received
HTTP/1 trailer block budget to 4,096 raw encoded bytes, and enables bounded
CRLF+SP/HTAB continuation normalization. It applies its request and response
trailer policy before either HTTP version serializes frames. Requests reproduce
the pinned Caddy request-clone behavior and do not forward later trailer values;
HTTP/1 non-chunked declarations are ignored. Invalid HTTP/2 declaration keys
fail the outgoing proxy request with an empty 502 response. Forbidden actual
HTTP/2 trailer fields cause a stream protocol error when a non-ignored
declaration exists and the body is consumed; they do not preempt a completed
response or require reading an otherwise unread request body.

Dangerous response fields are deliberately filtered in both protocols. The
filter is the union of Go `httpguts.ValidTrailerHeader` and Hyper's original
trailer filter: `Authorization`, `Cache-Control`, `Connection`,
`Content-Encoding`, `Content-Length`, `Content-Range`, `Content-Type`, `Expect`,
`Host`, `Keep-Alive`, `Max-Forwards`, `Pragma`, `Proxy-Authenticate`,
`Proxy-Authorization`, `Proxy-Connection`, `Range`, `Realm`, `TE`, `Trailer`,
`Transfer-Encoding`, `WWW-Authenticate`, `Set-Cookie`, and the `If-` prefix.
Names are case insensitive; `If` and `Ifx-Foo` are not prefix matches. Values
and user-specific labels are not stored in diagnostic counters.

This is a documented security difference from Go's HTTP/1 forwarding of those
fields and its HTTP/2 forwarding of `Set-Cookie`. Bare-LF folding is also
deliberately rejected. Valid CRLF folding is normalized before the existing
header-name and header-value parser checks; it cannot manufacture a folded name
or turn CR/LF into an injected value. These dependency changes do not establish
full Caddy or module compatibility. Remaining capability and validation gates
continue to apply; no production replacement is authorized by vendoring alone.
