# Fixed rustls source and negotiated-version accessor

Source: official crates.io `rustls` 0.23.46, registry package SHA-256
`48e13bd8c0e9365c43cfa5c9e8f9ad49d3c8444926c9aac819e0e4dc503c8fdf`.
The upstream Apache-2.0, ISC and MIT license texts are retained.

The initial negotiated-version layer changes two functional source files. `server/server_conn.rs` adds a private
`Option<ProtocolVersion>` to `ClientHello` and a read-only
`negotiated_version()` accessor. `Accepted::client_hello()` sets it to `None`
because no server configuration has been selected. `server/hs.rs` populates it
with the version already selected by the unchanged negotiation logic before
calling the actual certificate resolver. It does not infer a version from cipher
suites, change protocol preferences, or force a TLS downgrade.

The normalized manifest omits independent example/benchmark targets and
development dependencies. Their directories, Actions, upstream lockfile and
registry bookkeeping are not copied. Upstream inline `cfg(test)` sections in
functional source are unchanged. New project tests, generated fixtures,
upstream-file checksums, exact diffs and verification outputs remain in LocalOps.

Application resolvers must distinguish preselection (`None`) from the real
handshake (`Some`). Protocol-specific signatures may be authorized only against
the real negotiated version. The accessor does not itself implement legacy
signers, certificate selection, certificate validation or application policy.

The AWS-LC provider exposes SecP384r1MLKEM1024 using its existing P-384 and
ML-KEM-1024 implementations and generic hybrid combiner. The group codepoint
and classical-first share/secret layout follow RFC 10024. This adds the group
to ALL_KX_GROUPS but does not change DEFAULT_KX_GROUPS. Native outgoing client
profiles select the complete pinned-Go capability set independently of server
and QUIC defaults.

Certificate URI admission adds a read-only `DangerousClientConfig` verifier Arc
getter and an optional, default-success client-certificate syntax hook for saved
nonempty client chains. The latter declines resumption on rejection before the
existing chain-binding checks; it neither changes the generic certificate codec
nor creates a verified-chain observation. The original raw-public-key contract is
unchanged.


The listener early-dispatch layer exposes a separate QUIC phase exporter getter.
It delegates only to a state which actually owns the exporter secret, including
ExpectFinished/ExpectEarlyData, and leaves the existing completed-only getter and
is_handshaking unchanged. Quinn's owned handshake data uses this phase getter;
HTTP snapshots retain their actual completion/authentication facts. The pending
key schedule exports from the already-derived TLS1.3 secret, retaining no stream
or packet keys. Stateless early-data rejection remains unchanged.
