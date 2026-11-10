# Compatibility contract and current gaps

Baseline: Caddy v2.11.7, CertMagic v0.25.6, acmez/v3 v3.1.7. The three inspected
production binaries expose the same 135 standard modules and no additional
third-party modules. The live configuration uses a subset; that observation does
not authorize removing capabilities from the requested replacement.

Current CLI stage: read-only feature/storage inspection only. The library adds
bounded in-memory challenge leases and validated certificate snapshot selection;
these primitives are not connected to a production listener or ACME issuer.
All traffic serving,
Caddyfile adaptation, Admin API mutation, automatic issuance/renewal, and standard
module behavior remain unimplemented until their respective code and differential
tests are complete. This document must track implementation and verification
separately. No production migration is authorized by this inspection build.

Required feature families:

- Caddyfile and JSON configuration, environment/placeholder rules, imports,
  CLI run/validate/adapt/reload/resume semantics, autosave, managed endpoint and
  conditional Admin API writes with their original path/array/ETag semantics.
- Transactional configuration replacement, retained accepted requests and long
  streams, listener ownership, failed-candidate rollback, graceful shutdown.
- HTTP/1, HTTP/2, HTTP/3, TLS/SNI/ALPN, reverse proxy, HTTP and FastCGI upstreams,
  WebSocket/SSE, timeouts, stream flushing, load balancing, health behavior.
- Handler/matcher/module namespaces, routes and subroutes, rewrites, headers,
  authentication, maps/variables, file serving, range/conditional/compressed
  responses, original client-IP trust boundaries, logging and metrics.
- Automatic HTTPS planning, implicit challenge listeners and redirects; existing
  ACME account identity; HTTP-01/TLS-ALPN-01 and applicable DNS provider behavior;
  issuer fallback; EC/RSA/Ed25519 key-format compatibility; early renewal/ARI,
  retry/backoff; OCSP; atomic certificate publication and TLS hot replacement.
- CertMagic file-storage namespaces, metadata preservation and compatible locks.
  Multi-file key/cert/metadata publication needs explicit recovery; three renames
  do not constitute an atomic group. A Rust process and the original Caddy must
  read each other's validated state in an isolated CA interoperability test.
- Standard local PKI, on-demand TLS, storage providers, and other registered
  capabilities remain explicit migration work; unsupported configuration must
  fail before it changes a working listener or published snapshot.

Current production inputs and all authentication material remain exclusively in
LocalOps. The live service names, ports, certificate storage, domain routing and
other applications' loopback backends must be preserved during eventual rollout.
No new official installation/self-upgrade workflow is introduced.
