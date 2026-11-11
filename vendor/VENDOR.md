# HTTP dependency source provenance

These are functional source copies of the versions locked by this project:

| Crate | Registry version | Registry package SHA-256 |
| --- | --- | --- |
| hyper | 1.12.0 | `2c3e324da4c95177d6291d4c8730197c0d1822f8a9766814a4a44fa5ab797c9c` |
| hyper-util | 0.1.21 | `ddc03d96684f9226b8a787cdb71488417b53ab5ea8fdb1dac946cb9431cc8bff` |
| h2 | 0.4.20 | `7d29020232d6aa3fb1daca64c1127cf662cf97f254ae16c18c05b8ab635fc118` |

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

## Transport write completion

The h2 copy retains the original MIT license. Its development targets and
test-only code are omitted. The functional patch adds opt-in observation of
the successful write flush of a request or final response head. An observer
moves with its own stream until its frame reaches the codec. A dropped write
resolves as abandoned. This does not change HTTP/2 stream state, encoding, or
retry policy. Hyper observes the corresponding request completion on HTTP/1.
A nonzero response-header timeout registers an upstream observer. The
response-header clock begins at the successful flush and ends when final
headers arrive. Negative values are disabled on HTTP/1 and already expired
after the request flush on HTTP/2, matching the negotiated transport's
behavior in the reference implementation.

## Typed JSON parser

The functional serde_json source is version 1.0.154. Its registry package
SHA-256 is `e7e9cc8b1b85264074fbcc02a88680c4096b1e47df8f739dceb03bf482f04bd6`.
The original MIT and Apache-2.0 license texts are retained in
`serde_json-1.0.154`. Development-only dependency and target declarations and
their files are omitted.

An explicit opt-in DOM parser marks a literal integer negative zero. Only
signed-integer consumers of that DOM use the mark. Normal JSON parsing,
float values, equality, hashing, serialization and unsigned decoding retain
their existing behavior. The application selects this parser only after its
own Unicode and depth checks. The alternate arbitrary-precision Number
representation is not enabled or supported in this patched copy.

## On-demand HTTP permission targets

The opt-in permission transport uses patched http 1.5.0 and reqwest 0.12.28.
See their VENDOR.md files for exact release hashes, scope, and licenses.

## HTTP/3 initial flight inspection

Quinn 0.11.12 and quinn-proto 0.11.19 retain their original MIT and
Apache-2.0 licenses. The upstream registry SHA-256 hashes are
`4051e23e9185c255a7e33ef59cdbca87a22d359052eecd22fc6b901fb37d9d11` and
`0e750cca55fe4f0439a15d0bb529da9651e79993e8e72c61a899a36d462befbe`,
respectively. Their opt-in Initial snapshot copies a bounded amount of pending
packet data without consuming it. The caller decrypts and validates outside
the endpoint lock, and uses QUIC address validation before doing certificate
work. Ordinary Quinn acceptance and transport limits are unchanged. External
upstream test modules are omitted.
