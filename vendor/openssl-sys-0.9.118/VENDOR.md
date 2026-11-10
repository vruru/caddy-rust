# Fixed openssl-sys and patched-source vendoring

Source: official crates.io `openssl-sys` 0.9.118, registry package SHA-256
`19c413d6ec9ebaf5e1c829d355cb3e9f783778d700f135be0921d52fce3c60ae`.
Its original MIT license and all functional FFI/build source are unchanged.

The single manifest change replaces the optional `openssl-src` build dependency
range `300.2.0` with `=400.0.2`. The existing `legacy` feature is retained.
The registry release `openssl-src` 400.0.2+4.0.3 has SHA-256
`d2093956673b8dbda85c87fa4fb78e70698ce6c5978a2837d1613f661d3bef76`.
This supplies the security-patched OpenSSL 4.0.3 sources, rather than the older
3.6.3 selected by the unmodified range. The official 0.9.118 binding/build code
already supports OpenSSL 4.x; no FFI code or version-detection logic is patched.
Builds use `openssl` =0.10.82 with its `vendored` feature and the checked lockfile.
Do not set `OPENSSL_NO_VENDOR` or substitute an implicit host OpenSSL installation.

OpenSSL is used only as an additional restricted key/signature backend. TLS
transport, ciphersuites, KX groups and full certificate/path/name/purpose/time
validation remain in rustls/WebPKI and the project's existing policy. This
dependency change alone is not evidence of completed legacy TLS compatibility.

The upstream lockfile and registry bookkeeping are omitted. Original manifest,
per-file provenance, package/lock checksums, static-link evidence, runtime
`OpenSSL 4.0.3` diagnostics and new isolated QA are retained in LocalOps only.
