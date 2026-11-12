# Fixed rustls source and negotiated-version accessor

Source: official crates.io `rustls` 0.23.46, registry package SHA-256
`48e13bd8c0e9365c43cfa5c9e8f9ad49d3c8444926c9aac819e0e4dc503c8fdf`.
The upstream Apache-2.0, ISC and MIT license texts are retained.

Only two functional source files differ. `server/server_conn.rs` adds a private
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
