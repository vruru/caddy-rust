# Vendored reqwest 0.12.28

Source: the official crates.io distribution of reqwest 0.12.28.
Registry checksum: `eddd3ca559203180a307f12d114c268abf583f59b03cb906fd0b3ff8646c1147`.
The original Apache-2.0 and MIT licenses are included.

The asynchronous client exposes one opt-in method,
`Client::execute_with_raw_target`, to send an already escaped origin-form
path and query without URL normalization. Only a client configured with
`redirect::Policy::none()` may call it. The original request URL remains
authoritative for scheme and authority; replacing the path does not change
proxy selection, the network destination, TLS verification, or timeout
behavior. CONNECT is rejected before dialing. Ordinary requests keep the original implementation and semantics.

The asynchronous `ClientBuilder` also has opt-in Rustls methods
`tls_server_name_override` and `tls_handshake_timeout`. These configure only
origin SNI/name verification and the origin TLS handshake deadline. The URL,
HTTP Host, dial target, HTTP proxy CONNECT target and HTTPS proxy's own TLS name
remain unchanged. They apply to direct TCP/Unix, CONNECT and SOCKS connections;
an unset override retains the upstream connector path. Selecting another TLS
backend with origin overrides returns a builder error rather than ignoring them.
Dial, proxy setup and whole-request deadlines remain independent.

Only `src/async_impl/client.rs`, `src/connect.rs` and `src/redirect.rs` differ from
the distribution's runtime source.

The optional `ClientBuilder::tls_crypto_provider` selects a provider for a newly
built Rustls client without installing a process-wide default. Combining it
with another backend or preconfigured TLS is rejected. Unset behavior is the
upstream provider selection. Native outgoing HTTP clients opt into their
client-only profile while incoming server/QUIC defaults remain independent.

An optional fixed, fallible Rustls verifier-wrapper function can wrap the original
verifier after TLS configuration, before connector/HTTP3 clones, in both normal
and preconfigured Rustls branches. It defaults to absent and preserves existing
root, identity, CRL, provider, proxy and verification settings. The API does not
force certificate policy on generic callers or replace the native TLS backend.


The optional `native-tls-scope` feature exposes the existing sealed connection as a hidden IO-mapping seam plus its existing IO/TlsInfo traits and a borrowed URI view. `Conn::map_io` preserves the original proxy and TlsInfo flags; the host supplies its concrete bounded connection-lifetime wrapper. The host connector layer runs its actual owned service clone's readiness and call on its existing TLS executor, not in reqwest's general HTTP request path. No arbitrary Any/Drop credit hook, global executor, trust-store reconstruction, application retry or CBC fallback is added by this seam. The original default builder behavior remains unchanged unless the host explicitly installs that layer.
