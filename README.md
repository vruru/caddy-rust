# Caddy-Rust

`vruru/caddy-rust` is an independent, native Rust implementation whose behavioral baseline is Caddy 2.11.7 and CertMagic 0.25.6. It is licensed under Apache 2.0. The fixed standard capability suite has completed combined acceptance, followed by a guarded Linux deployment. The project remains in active development; this establishes the tested contracts, not universal compatibility with every plugin, field combination or platform. Application control and network I/O run natively in Rust and invoke no Go processes. Cryptography and explicit TLS compatibility use the pinned providers documented below.

## Current Status

The project currently covers a specific subset of functionalities:
*   **CLI**: `fmt`, `adapt`, `validate`, `run`, `start`, `reload`, `stop`, `hash-password` (bcrypt and Argon2id), recovery with `run --resume`, module/build/environment information, offline storage import/export, and explicit PKI `trust`/`untrust`.
*   **Process Lifecycle**: Linux `Type=notify` readiness/reload/stop datagrams, bounded notification delivery, Unix signal handling and graceful drain.
*   **HTTP/Admin**: Transactional endpoints, Host/origin/remote authorization, conditional configurations, and ETag support.
*   **Transports**: H1, H2, and H3 streaming uploads and downloads, range-conditional responses, compression, reverse proxying (including FastCGI and WebSocket), and load balancing with dynamic upstream health checks.
*   **TLS & Certificates**: TLS 1.2/1.3, managed and manual certificate support, native ZeroSSL REST issuance/recovery/revocation, on-demand ACME (HTTP-01, TLS-ALPN-01), local PKI, OCSP, session tickets, external certificate retrieval (HTTP, Tailscale), generation-scoped Must-Staple requests and private-key reuse.
*   **ACME Server**: Native account/order lifecycle, HTTP-01/DNS-01/TLS-ALPN-01 validation, CSR signing, persistent revocation and key rollover with checked Bolt-format state interoperability.
*   **Explicit CBC Policies**: Complete native SSL record/session processing for configured TLS 1.2 ECDHE AES-CBC suites, retaining the existing resolver, client-authentication and revocation policy.
*   **Metrics**: Generation-scoped Prometheus/OpenMetrics scraping, HTTP/protobuf and gRPC OTLP, console export, real runtime facts, and bounded observation/export lifetimes, with Process-owned client handshake scheduling and tested macOS/Linux DNS retirement.
*   **Resource Push & Rewrites**: Native bounded HTTP/2 push, independent child stream lifetimes, and ordered byte-preserving URI/query and upstream rewrites.
*   **Tracing & Timeouts**: Generation-scoped OpenTelemetry tracing and actual stream/tunnel lifetimes; native server hard deadlines and scoped route progress limits across H1/H2/H3.
*   **Templates & Logic**: Native Go-template, Goldmark and CEL behavior has differential coverage; remaining host methods and edge cases are tracked explicitly.
*   **Listener & ECH Controls**: Unix and inherited descriptors, per-listener protocols, socket keepalive, header limits, full duplex, and server ECH over TCP and HTTP/3. ECH keys use compatible storage, rotation and retained snapshots; DNS publication requires a separate provider plugin.

**Runtime Characteristics**:
*   CPU: Auto-detects and utilizes all available CPUs at startup.
*   Resource Management: Network, disk, password, and issuance operations run in independent bounded lanes. A full-process RSS limit is not promised.
*   **Compatibility**: Correct useful extensions remain supported even where the baseline rejects them. Resource bounds and repairs to upstream bugs are documented differences; accepting a configuration alone does not establish correct execution.

**Known Gaps**:
The known finite standard capability gaps have native runtime consumers. The completed combined acceptance, deployment boundaries, remaining edge-case verification, optional provider bindings and unverified platforms are tracked in `docs/COMPATIBILITY-STATUS.md`. A passing deployment does not remove the need to validate another site's configuration and traffic.

## Build

Use the official stable Rust toolchain (currently pinned to 1.100.0). GitHub Actions are not currently configured for this project.

```bash
cargo build --locked --release --features native-run
```

For compatibility details, refer to:
*   `COMPATIBILITY.md`
*   `docs/COMPATIBILITY-STATUS.md`
*   `docs/BEHAVIOR-REMEDIATION.md`
*   `docs/PROCESS-NOTIFY.md`
*   `docs/ACME-SERVER.md`
*   `docs/SESSION-TICKETS.md`
*   `docs/METRICS.md`
*   `docs/TRACING.md`
*   `docs/TIMEOUTS.md`
*   `docs/PUSH.md`
*   `vendor/VENDOR.md`
*   `THIRD-PARTY-NOTICES`

**Testing & Release Protocol**:
Before production deployment, the project must pass:
1.  Full feature comparison against baseline.
2.  Fault, cancellation, reload, and multi-user large transfer tests.
3.  Performance validation on all-CPU and single-CPU configurations.
4.  Key business flow acceptance via real browsers.
5.  Machine-by-machine rollout with rollback capabilities.

**Privacy & Exclusions**:
Do not upload private operational paths, other personal projects, server addresses, tests, real configurations, keys, databases, logs, screenshots, or build artifacts.
