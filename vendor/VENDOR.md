# HTTP dependency source provenance

These are functional source copies of the versions locked by this project:

| Crate | Registry version | Registry package SHA-256 |
| --- | --- | --- |
| hyper | 1.12.0 | `2c3e324da4c95177d6291d4c8730197c0d1822f8a9766814a4a44fa5ab797c9c` |
| hyper-util | 0.1.21 | `ddc03d96684f9226b8a787cdb71488417b53ab5ea8fdb1dac946cb9431cc8bff` |
| h2 | 0.4.20 | `7d29020232d6aa3fb1daca64c1127cf662cf97f254ae16c18c05b8ab635fc118` |
| h3 | 0.0.8 | `10872b55cfb02a821b69dc7cf8dc6a71d6af25eb9a79662bec4a9d016056b3be` |

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

## Password hashing

The Argon2id backend is a functional copy of RustCrypto argon2 0.5.3.
Its original licenses, exact package checksum, omitted development targets and
opt-in Go-compatible parameter handling are documented in
[argon2-0.5.3/VENDOR.md](argon2-0.5.3/VENDOR.md). The host reserves scratch
memory before block allocation and uses the existing bounded authentication
worker and per-generation HMAC/single-flight cache.


`native-write-policy` is an Apache-2.0 component maintained in this repository.
It contains checked write-deadline arithmetic and concrete atomic allocation
ownership shared by the native Hyper, h2 and Quinn extensions; it is not an
upstream third-party crate release. Configuration activation is tracked in
COMPATIBILITY.md separately from these opt-in protocol primitives.


The existing http 1.5.0 source retains its upstream license and original public URI behavior. PathAndQuery now preserves an implicit-slash provenance bit when parsing an absolute URI whose source has no path. The read-only raw_path accessor distinguishes that source from an explicit slash; path/as_str/Display/equality/hashing retain the normalized data and prior behavior. Clones and Parts transfers retain provenance. This does not widen accepted authorities, add a dependency or change normal URI parser limits.

The native rewrite path uses an explicit bounded PathAndQuery constructor that accepts relative URL.Path values, including a colon in the first segment and the empty path. It rejects fragments and invalid path/query bytes and retains the existing 4 MiB explicit-component bound. The normal URI/request-target parser remains unchanged. This avoids reinterpreting a rewrite path as a scheme or authority; connection authorities remain independently validated.

## Extended CONNECT and WebSocket translation

The h3 0.0.8 copy retains its original MIT license. Its functional change adds recognition and serialization of the `websocket` extended-CONNECT protocol. Test-only Rust items and external test modules, development-only dependencies and package-cache metadata are omitted from the published functional copy; mixed functional feature conditions and upstream licenses remain intact. The h3-quinn adapter is not locally modified by this change.

The native HTTP/2 and HTTP/3 listeners advertise extended CONNECT. The HTTP runtime translates an extended WebSocket request into an upstream HTTP/1 GET/Upgrade handshake, and a verified upstream 101 into a frontend 200. The final actual upstream Key and single matching Accept are bound to one attempt; normal HTTP/1 proxy upgrades remain transparent. Failed upstream handshake verification is a native correctness enhancement, since the pinned Go reference accepts the tested invalid responses.

Hyper distinguishes an application-requested upgrade from an ordinary successful CONNECT handler response. Ordinary CONNECT responses keep their body; HTTP/1 uses an opaque close-delimited response without Content-Length or Transfer-Encoding. Requested HTTP/2 upgrades transfer the same control owner only after physical HEADERS/CONTINUATION completion. A bounded raw actor serializes DATA/flush/FIN receipts and cancels only its own stream. Unconsumed upgrade results, completed futures and codec tails retain their actual owned allocations until their last owner drops.

The HTTP/2 bridge reuses the existing locally modified h2 per-stream frame-span progress, completion/deadline and concrete allocation-credit interfaces; this WebSocket/Accept change does not add another h2 source patch or a new upstream h2 version. Progress is local transport write/flush, not peer acknowledgment, and one stream's progress does not credit its neighbors. Timeout configuration activation remains separately documented in COMPATIBILITY.md.

Native WebSocket session admission has a 64 MiB metadata pool with 256 KiB reservations; its HTTP/3 source payload pool is a separate 64 MiB budget. Concrete protocol-table credit follows the shared transfer allocation pool through the real table/weak-owner lifetime. Without configured write rules a neutral control uses no idle/rate/hard deadline and only retains actual output ownership. HTTP/3 source-byte credit covers local UDP transmission, not the separately bounded Quinn acknowledgment/retransmission copies.


The HTTP/3 application upload keeps its actual request body and write half in
one owner whose session hold is dropped last. Cancellation does not refund that
admission while the captured upload IO can still exist.

## Promised HEAD responses

The h2 receiver marks a validated promised HEAD request with the same body
semantics as a locally initiated HEAD. Content-Length describes its selected
representation and does not require response DATA. Nonempty HEAD DATA,
conflicting Content-Length fields, and truncated ordinary GET responses still
fail their own stream without resetting a valid parent response. This client
correctness fix does not by itself implement the native HTTP/2 push handler.

The opt-in h2 promise-observation API retains concrete caller metadata through
PUSH_PROMISE/CONTINUATION encoding and actual local flush. Its cancellation
target is the promised child, although the promise frame belongs to its parent.
A failed reservation does not reset the parent. Request validation precedes
child-table allocation, so rejected methods do not leave unreachable reserved
streams. The existing bounded retirement table retains its first allocation
credit until the real connection owner retires. These are transport building
blocks used by the native route-level push handler; full combined release
acceptance remains required.

## Explicit outgoing SSL transport

`native-ssl-tls` is first-party Apache-2.0 functional source. It uses the complete
OpenSSL SSL record/session engine through the existing pinned OpenSSL bindings
and `tokio-openssl` 0.6.5; it does not implement cryptographic record protection.
The reqwest copy adds an opt-in prepared SSL connector for explicit outgoing
renegotiation, retaining separate HTTPS-proxy and origin names and ALPN. Default
Rustls paths are preserved. Native trust validation uses exact-wire certificate
bytes and the public retry-verification boundary on a bounded CPU lane; raw
observations, abandoned worker results and service shutdown retain their actual
owners. See COMPATIBILITY.md for limits and unfinished server/client-identity
capabilities.


Hyper exposes an opt-in, bounded HTTP/2 server-push command bridge. A request
extension admits promises without adding Clone/Send bounds to unrelated
Services or generic response data. Accepted children retain independent output
owners after normal parent completion or parent RST; a child cancellation,
failed control identity, expired write deadline or admission denial affects
that child only. Their one-item output mailboxes wait for actual local
HEADERS/DATA/trailer flush receipts, including flow-control and continuation
boundaries; this is not proof of remote application consumption. Unique interim
writers preserve 1xx/final ordering. The h2 pushed-response client exposes the
same informational polling as an ordinary response future.

One concrete shared allocation pool prepays parent queues, child storage and
writer/interim metadata. Retained request/frame credit survives actual protocol
owners, while DATA carries its own source ownership. A separate per-connection
accepted-child activity guard prevents idle-close while reserved pushes are
still generating responses; RFC concurrent-stream counters omit reserved
states and cannot replace this guard. Last-child retirement wakes the idle
poller outside h2 and activity-state locks. Listeners without a native push route leave this
extension disabled. Native route-level dispatch explicitly enables it; generic
transport consumers retain their existing default behavior.


Native ordinary CONNECT body handling adds an opt-in Hyper client request
extension preserving the actual authority/path target and ordinary response
framing. Hyper HTTP/2 server and hyper-util automatic-server builders add a
native opt-in for ordinary CONNECT request DATA; extended CONNECT and generic
raw upgrades retain their existing default behavior. These changes carry no
application callbacks and do not add background actors or protocol queues.


Incoming explicit TLS1.2 CBC uses complete OpenSSL SSL records/sessions via native-ssl-tls server_* modules, owned CPU steps and asynchronous socket I/O. Rustls exposes a read-only client-chain observation and an owned TLS1.2 PRF exporter for exact snapshots. native-openssl-src derives from the pinned openssl-src400.0.2+4.0.3 builder (MIT/Apache-2.0): source_dir/version forward to the original pinned source package; tls-deprecated-ec adds OpenSSL Configure enable-tls-deprecated-ec. openssl-sys uses that named feature for its vendored builder. OpenSSL C sources remain unchanged. Default Native Rustls/H3 groups, versions and verification are unchanged.
