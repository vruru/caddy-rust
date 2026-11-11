# http 1.5.0 provenance

Source: [crates.io release](https://crates.io/crates/http/1.5.0), upstream [hyperium/http](https://github.com/hyperium/http). The official release archive SHA-256 is `918d3568bebf352712bc2ef3d46a8bcf1a75b373be6539de198e9105cbbf9ce0`. MIT and Apache-2.0 license notices are kept. The upstream runtime source and published Cargo manifests are preserved, except for the patch described here and the removal of manifest entries for standalone upstream tests that are omitted from this copy.

The only functionality change is in the URI path and query constructor. `PathAndQuery::from_bounded_origin_form(Bytes)` accepts a validated origin-form outbound request target up to 4 MiB without normalizing or reparsing the authority. It requires a leading slash and rejects fragments, disallowed bytes, and invalid UTF-8. It uses the existing path/query scanner with a wider private offset so a query after 64 KiB is preserved. Callers must separately validate the trusted connection origin and never use this API to loosen a parser for untrusted inbound targets. The existing string, byte, static and full-URI parsers retain their existing 65,534-byte limit and behavior. HTTP request line, frame and field limits, proxy routing, redirects and TLS policy do not change here.

This API is for a configured on-demand TLS permission endpoint whose path and query must reach the same server exactly. Caddy's permission configuration bounds literal endpoint size separately. An HTTP server or intermediary may accept less than the outbound limit; the client does not relax any peer or ingress limit.

Standalone upstream test targets are omitted from this copy.
