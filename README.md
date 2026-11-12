# Caddy-Rust

`vruru/caddy-rust` is an independent, native Rust implementation whose behavioral baseline is Caddy 2.11.7 and CertMagic 0.25.6. It is licensed under Apache 2.0. The project is currently in active development. It has not undergone full feature acceptance testing nor is it validated as a production-ready replacement. The runtime executes entirely in Rust, invoking no Go processes.

## Current Status

The project currently covers a specific subset of functionalities:
*   **CLI**: `fmt`, `adapt`, `validate`, `run`, `start`, `reload`, `stop`, `hash-password` (bcrypt and Argon2id), and recovery with `run --resume`.
*   **HTTP/Admin**: Transactional endpoints, Host/origin/remote authorization, conditional configurations, and ETag support.
*   **Transports**: H1, H2, and H3 streaming uploads and downloads, range-conditional responses, compression, reverse proxying (including FastCGI and WebSocket), and load balancing with dynamic upstream health checks.
*   **TLS & Certificates**: TLS 1.2/1.3, managed and manual certificate support, on-demand ACME (HTTP-01, TLS-ALPN-01), local PKI, OCSP, session tickets, external certificate retrieval (HTTP, Tailscale), generation-scoped Must-Staple requests and private-key reuse.
*   **Metrics**: Generation-scoped Prometheus/OpenMetrics scraping, HTTP/protobuf and gRPC OTLP, console export, real runtime facts, and bounded observation/export lifetimes.
*   **Tracing & Timeouts**: Generation-scoped OpenTelemetry tracing and actual stream/tunnel lifetimes; native server hard deadlines and scoped route progress limits across H1/H2/H3.
*   **Templates & Logic**: Native Go-template, Goldmark and CEL behavior has differential coverage; remaining host methods and edge cases are tracked explicitly.

**Runtime Characteristics**:
*   CPU: Auto-detects and utilizes all available CPUs at startup.
*   Resource Management: Network, disk, password, and issuance operations run in independent bounded lanes. A full-process RSS limit is not promised.
*   **Compatibility**: Correct useful extensions remain supported even where the baseline rejects them. Resource bounds and repairs to upstream bugs are documented differences; accepting a configuration alone does not establish correct execution.

**Known Gaps**:
Remaining standard modules/fields, remaining listener/address combinations, ACME server, push, complete template mutability and remaining host methods, TLS 1.2 CBC suites, client renegotiation, Go PKIX edge cases, and full issuer/CA-loader capabilities are not yet implemented.

## Build

Use the official stable Rust toolchain (currently pinned to 1.100.0). GitHub Actions are not currently configured for this project.

```bash
cargo build --locked --release --features native-run
```

For compatibility details, refer to:
*   `COMPATIBILITY.md`
*   `docs/SESSION-TICKETS.md`
*   `docs/METRICS.md`
*   `docs/TRACING.md`
*   `docs/TIMEOUTS.md`
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
