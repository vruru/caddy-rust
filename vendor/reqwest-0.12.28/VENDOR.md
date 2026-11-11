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

Only `src/async_impl/client.rs` and `src/redirect.rs` differ from the
distribution's runtime source.
